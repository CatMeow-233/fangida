"""Public service controls reach the separate Android worker."""
from __future__ import annotations

import tempfile
import threading
import unittest
import zipfile
from pathlib import Path

from fangida.core.apk_analyzer.test_analyzer import sample_calling_class, sample_dex
from fangida.core.kkagent.test_semantic import DECODER_AVAILABLE, _sample
from fangida.dispatcher import AnalysisService, analyze
from fangida.models import AnalysisResult, AnalysisTask
from fangida.plugins.manager import PluginManager


class AnalysisControlTests(unittest.TestCase):
    @unittest.skipUnless(DECODER_AVAILABLE, "Capstone or GNU objdump required")
    def test_native_progress_and_cancel_retain_partial_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.elf"
            path.write_bytes(_sample())
            cancel = threading.Event()
            events: list[dict[str, object]] = []

            def observe(event: dict[str, object]) -> None:
                events.append(event)
                if event.get("event") == "function":
                    cancel.set()

            with AnalysisService(project_path=Path(directory) / "project.db") as service:
                result = service.analyze(path, on_progress=observe, cancel=cancel)
                self.assertIsNone(service.project.load_analysis(path))
            self.assertTrue(result.stats["cancelled"])
            self.assertTrue(result.stats["semantic_cancelled"])
            self.assertTrue(result.functions)
            self.assertTrue(any(event.get("event") == "function" for event in events))
            self.assertTrue(any("cancelled" in warning for warning in result.warnings))

    def test_service_reports_progress_and_reuses_worker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "example.dex"
            path.write_bytes(sample_dex())
            events: list[dict[str, object]] = []
            with AnalysisService() as service:
                first = service.analyze(path, on_progress=events.append)
                plugin = service.manager.load("apk_analyzer")
                pid = plugin._client.pid
                second = service.analyze(path)
                self.assertEqual(plugin._client.pid, pid)
            self.assertEqual(first.metadata["class_count"], 1)
            self.assertEqual(second.metadata["class_count"], 1)
            self.assertEqual(events[0]["stage"], "opening")
            self.assertEqual(events[-1]["stage"], "complete")
            self.assertEqual(events[-1]["percent"], 100)

    def test_in_flight_cancel_through_service_skips_project_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "many.jar"
            with zipfile.ZipFile(path, "w") as archive:
                for index in range(1000):
                    archive.writestr(f"C{index}.class", sample_calling_class())
            cancel = threading.Event()
            events: list[dict[str, object]] = []

            def observe(event: dict[str, object]) -> None:
                events.append(event)
                if event["stage"] == "opening":
                    cancel.set()

            with AnalysisService(project_path=Path(directory) / "project.db") as service:
                result = service.analyze(path, on_progress=observe, cancel=cancel)
                self.assertEqual(result.status, "error")
                self.assertTrue(any("cancelled" in warning for warning in result.warnings))
                self.assertIsNone(service.project.load_analysis(path))
                cancel.clear()
                followup = service.analyze(path, max_bytes=1024)
                self.assertEqual(followup.status, "partial")
                self.assertIn("project_snapshot_id", followup.metadata)
            self.assertEqual(events[0]["stage"], "opening")

    def test_convenience_and_legacy_plugins_keep_their_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "example.dex"
            path.write_bytes(sample_dex())
            events: list[dict[str, object]] = []
            self.assertEqual(analyze(path, on_progress=events.append).metadata["class_count"], 1)
            self.assertTrue(events)

            class LegacyPlugin:
                def analyze(self, task: AnalysisTask) -> AnalysisResult:
                    return AnalysisResult(task.path, task.kind, "legacy", "partial")

            manager = PluginManager()
            manager._loaded["kkagent"] = LegacyPlugin()
            result = manager.analyze("kkagent", AnalysisTask(str(path), "elf"),
                                     on_progress=events.append, cancel=threading.Event())
            self.assertEqual(result.analyzer, "legacy")


if __name__ == "__main__":
    unittest.main()
