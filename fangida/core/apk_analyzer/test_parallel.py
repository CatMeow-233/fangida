"""Cross-file Android request concurrency and worker-pool limits."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from tempfile import TemporaryDirectory
import unittest

from fangida.models import AnalysisTask

from . import PluginImpl
from .test_analyzer import sample_dex


class AndroidParallelTests(unittest.TestCase):
    def test_two_files_use_two_workers_with_isolated_progress(self) -> None:
        with TemporaryDirectory() as directory:
            first_path = Path(directory) / "first.dex"
            second_path = Path(directory) / "second.dex"
            first_path.write_bytes(sample_dex())
            second_path.write_bytes(sample_dex())
            plugin = PluginImpl()
            entered = Event()
            release = Event()
            first_events: list[str] = []
            second_events: list[str] = []

            def observe_first(event: dict[str, object]) -> None:
                first_events.append(str(event["stage"]))
                if event["stage"] == "opening":
                    entered.set()
                    if not release.wait(timeout=5):
                        raise AssertionError("first request was not released")

            try:
                with ThreadPoolExecutor(max_workers=2) as executor:
                    first = executor.submit(plugin.analyze_with_control,
                                            AnalysisTask(str(first_path), "dex", parse_threads=2),
                                            observe_first)
                    try:
                        self.assertTrue(entered.wait(timeout=5))
                        second = executor.submit(plugin.analyze_with_control,
                                                 AnalysisTask(str(second_path), "dex", parse_threads=2),
                                                 lambda event: second_events.append(str(event["stage"])))
                        # A single shared IPC client cannot deliver the
                        # second result until observe_first is released.
                        self.assertEqual(second.result(timeout=5).metadata["class_count"], 1)
                        self.assertEqual(len(plugin._clients), 2)
                    finally:
                        release.set()
                    self.assertEqual(first.result(timeout=5).metadata["class_count"], 1)
                    self.assertEqual(len({client.pid for client in plugin._clients}), 2)
                self.assertEqual(first_events, ["opening", "dex", "complete"])
                self.assertEqual(second_events, ["opening", "dex", "complete"])
            finally:
                release.set()
                plugin.teardown()
            self.assertTrue(all(client.pid is None for client in plugin._clients))

    def test_one_worker_quota_and_cancel_while_queued(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "example.dex"
            path.write_bytes(sample_dex())
            plugin = PluginImpl()
            entered = Event()
            release = Event()
            cancelled = Event()

            def hold(event: dict[str, object]) -> None:
                if event["stage"] == "opening":
                    entered.set()
                    release.wait(timeout=5)

            try:
                with ThreadPoolExecutor(max_workers=2) as executor:
                    first = executor.submit(plugin.analyze_with_control,
                                            AnalysisTask(str(path), "dex", parse_threads=1), hold)
                    try:
                        self.assertTrue(entered.wait(timeout=5))
                        second = executor.submit(plugin.analyze_with_control,
                                                 AnalysisTask(str(path), "dex", parse_threads=1),
                                                 None, cancelled)
                        cancelled.set()
                        outcome = second.result(timeout=5)
                        self.assertEqual(outcome.status, "error")
                        self.assertTrue(any("cancelled" in warning for warning in outcome.warnings))
                        self.assertEqual(len(plugin._clients), 1)
                    finally:
                        release.set()
                    self.assertEqual(first.result(timeout=5).metadata["class_count"], 1)
            finally:
                release.set()
                plugin.teardown()


if __name__ == "__main__":
    unittest.main()
