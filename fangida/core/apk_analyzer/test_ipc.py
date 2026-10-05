"""Process-boundary tests for worker reuse, paging, cancellation and recovery."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path

from fangida.core.apk_analyzer.ipc import IPCClient, INLINE_RESULT_BYTES
from fangida.core.apk_analyzer.test_analyzer import sample_calling_class, sample_dex
from fangida.models import AnalysisTask


class WorkerIPCTests(unittest.TestCase):
    def test_reuses_worker_and_pages_large_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "many.jar"
            with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
                for index in range(180):
                    archive.writestr(f"C{index}.class", sample_calling_class())
            client = IPCClient()
            try:
                events: list[dict[str, object]] = []
                first = client.analyze(AnalysisTask(str(path), "jar"), on_progress=events.append)
                self.assertEqual(len(first.functions), 180)
                self.assertGreater(len(json.dumps(first.to_dict())), INLINE_RESULT_BYTES)
                self.assertEqual(events[0]["stage"], "opening")
                self.assertEqual(events[-1]["stage"], "complete")
                pid = client.pid
                self.assertIsNotNone(pid)
                second = client.analyze(AnalysisTask(str(path), "jar"))
                self.assertEqual(len(second.functions), 180)
                self.assertEqual(client.pid, pid)
            finally:
                client.close()
            self.assertIsNone(client.pid)

    def test_restarts_if_child_crashes_during_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "example.dex"
            path.write_bytes(sample_dex())
            marker = Path(directory) / "first-worker-started"
            # The tiny DEX can finish before a POSIX signal or Windows process
            # termination is observed. The first worker must stay alive after
            # its opening event so this actually verifies crash recovery.
            first_worker = """
import json, pathlib, sys, time
marker = pathlib.Path(sys.argv[1])
if marker.exists():
    from fangida.core.apk_analyzer.worker import main
    main()
else:
    marker.write_text('started', encoding='utf-8')
    request = json.loads(sys.stdin.readline())
    print(json.dumps({'jsonrpc': '2.0', 'method': '$/progress',
        'params': {'request_id': request['id'], 'stage': 'opening'}}), flush=True)
    time.sleep(30)
"""
            client = IPCClient([sys.executable, "-c", first_worker, str(marker)])
            killed: list[int] = []
            try:
                def kill_first_worker(event: dict[str, object]) -> None:
                    if not killed and event.get("stage") == "opening":
                        assert client.pid is not None
                        killed.append(client.pid)
                        assert client._process is not None
                        client._process.kill()

                result = client.analyze(AnalysisTask(str(path), "dex"), on_progress=kill_first_worker)
                self.assertEqual(result.metadata["class_count"], 1)
                self.assertEqual(len(killed), 1)
                self.assertIsNotNone(client.pid)
                self.assertNotEqual(client.pid, killed[0])
            finally:
                client.close()

    def test_cancellation_and_timeout_reap_worker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "example.dex"
            path.write_bytes(sample_dex())
            client = IPCClient()
            try:
                timed_out = client.analyze(AnalysisTask(str(path), "dex", worker_timeout_seconds=0.00001))
                self.assertEqual(timed_out.status, "error")
                self.assertTrue(any("TimedOut" in warning for warning in timed_out.warnings))
                self.assertIsNone(client.pid)

                cancelled = threading.Event()
                cancelled.set()
                # A pre-cancelled token can race a tiny DEX parse. Use an
                # archive with many members to guarantee a checkpoint.
                archive = Path(directory) / "many.jar"
                with zipfile.ZipFile(archive, "w") as stream:
                    for index in range(1000):
                        stream.writestr(f"C{index}.class", sample_calling_class())
                outcome = client.analyze(AnalysisTask(str(archive), "jar"), cancel=cancelled)
                self.assertEqual(outcome.status, "error")
                self.assertTrue(any("cancelled" in warning for warning in outcome.warnings))
                recovered = client.analyze(AnalysisTask(str(path), "dex"))
                self.assertEqual(recovered.metadata["class_count"], 1)
            finally:
                client.close()

    def test_legacy_one_shot_json_rpc_over_stdio(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "example.dex"
            path.write_bytes(sample_dex())
            request = {"jsonrpc": "2.0", "id": 17, "method": "analyze",
                       "params": {"path": str(path), "kind": "dex"}}
            output = subprocess.run([sys.executable, "-m", "fangida.core.apk_analyzer.worker"],
                                    input=json.dumps(request) + "\n", capture_output=True, text=True,
                                    timeout=10, check=True).stdout
            messages = [json.loads(line) for line in output.splitlines()]
            self.assertEqual(len(messages), 1)
            response = next(message for message in messages if message.get("id") == 17)
            self.assertEqual(response["result"]["metadata"]["class_count"], 1)


if __name__ == "__main__":
    unittest.main()
