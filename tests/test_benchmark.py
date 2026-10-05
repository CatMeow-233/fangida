"""Benchmarks must distinguish genuine output changes from timing variation."""
from __future__ import annotations

import importlib.util
from contextlib import redirect_stdout
from dataclasses import replace
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
import weakref

from fangida.benchmark import _coverage, _evidence_digest, benchmark, compare_threads, main
from fangida.core.kkagent.test_semantic import _sample
from fangida.gui import main as gui_main
from fangida.gui import _prepare as gui_prepare, summary_text
from fangida.api import AnalysisView
from fangida.models import AnalysisResult
from fangida.settings import Settings
from fangida.ui import main as ui_main


DECODER_AVAILABLE = bool(importlib.util.find_spec("capstone") or shutil.which("objdump"))


@unittest.skipUnless(DECODER_AVAILABLE, "Capstone or GNU objdump required")
class BenchmarkTests(unittest.TestCase):
    def test_single_and_multi_thread_evidence_matches(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.elf"
            path.write_bytes(_sample())
            result = compare_threads(path, runs=2, semantic_threads=2)
        self.assertTrue(result["same_evidence_and_scope"])
        self.assertEqual(result["single_thread"]["output_digest"],
                         result["multi_thread"]["output_digest"])
        self.assertEqual(result["single_thread"]["coverage"]["semantic_instructions"], 4)
        self.assertEqual(result["multi_thread"]["coverage"]["semantic_parallel_functions"], 2)
        self.assertTrue(result["single_thread"]["stable_output"])
        self.assertTrue(result["multi_thread"]["stable_output"])
        self.assertEqual(len(result["single_thread"]["seconds"]), 2)
        self.assertEqual(len(result["multi_thread"]["seconds"]), 2)
        self.assertIsNotNone(result["local_median_ratio"])

    def test_single_mode_records_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.elf"
            path.write_bytes(_sample())
            result = benchmark(path, runs=1, semantic_threads=1)
        self.assertEqual(result["semantic_threads"], 1)
        self.assertEqual(result["coverage"]["semantic_functions"], 2)
        self.assertEqual(result["coverage"]["semantic_instructions"], 4)
        self.assertTrue(result["stable_output"])
        self.assertIn("bounded", result["scope"])
        self.assertGreaterEqual(result["cold_total_seconds"], result["cold_measurement"]["analysis_wall_seconds"])
        self.assertEqual(len(result["cpu_seconds"]), 1)
        self.assertEqual(len(result["postprocess_seconds"]), 1)

    def test_invalid_or_non_native_comparison_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.jar"
            path.write_bytes(b"PK\x03\x04junk")
            with self.assertRaisesRegex(ValueError, "ELF, PE, or Mach-O"):
                compare_threads(path, runs=1)
            with self.assertRaisesRegex(ValueError, "between 1 and 16"):
                benchmark(path, runs=1, semantic_threads=0)
            with self.assertRaisesRegex(ValueError, "at least 2"):
                compare_threads(path, runs=1, semantic_threads=1)

    def test_full_mode_reports_coverage_and_same_scope_without_ghidra(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.elf"
            path.write_bytes(_sample())
            result = compare_threads(path, runs=1, semantic_threads=2, full_analysis=True)
        self.assertTrue(result["full_analysis"])
        self.assertTrue(result["same_evidence_and_scope"])
        for mode in ("single_thread", "multi_thread"):
            coverage = result[mode]["coverage"]
            self.assertTrue(coverage["full_analysis"])
            self.assertEqual(coverage["full_executable_bytes"], coverage["full_decoded_bytes"])
            self.assertTrue(coverage["full_decode_complete"])
            self.assertGreaterEqual(coverage["cfg_functions"], 2)
            self.assertGreater(result[mode]["cold_total_seconds"], 0)
            self.assertEqual(len(result[mode]["measurements"]), 1)
            self.assertIn("phase_seconds", result[mode]["measurements"][0])


class BenchmarkAccountingTests(unittest.TestCase):
    def test_phase_timing_is_excluded_from_evidence_but_coverage_gaps_are_not(self) -> None:
        result = AnalysisResult("sample", "elf", "kkagent", "partial",
                                metadata={"full_analysis": {"enabled": True, "decoded_bytes": 4,
                                                            "regions": [{"complete": True}]}},
                                stats={"full_analysis": True, "full_instructions": 4,
                                       "full_decode_complete": True,
                                       "phase_seconds": {"disassembly": 1.0}})
        before = _evidence_digest(result)
        result.stats["phase_seconds"] = {"disassembly": 20.0, "cfg": 10.0}
        self.assertEqual(_evidence_digest(result), before)
        self.assertTrue(_coverage(result)["full_decode_complete"])
        result.metadata["full_analysis"]["regions"][0]["complete"] = False
        self.assertNotEqual(_evidence_digest(result), before)

    def test_samples_release_complete_results_and_mark_unavailable_memory(self) -> None:
        previous: list[weakref.ReferenceType] = []
        test = self

        class FakeService:
            def __init__(self, settings):
                self.settings = settings

            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def analyze(self, path):
                if previous:
                    test.assertIsNone(previous[-1](), "benchmark retained the prior full result")
                result = AnalysisResult(str(path), "elf", "kkagent", "partial",
                                        metadata={"full_analysis": {"enabled": True, "instruction_count": 1},
                                                  "full_disassembly": [{"addr": 1, "mnemonic": "ret"}]},
                                        stats={"full_analysis": True, "full_instructions": 1,
                                               "phase_seconds": {"disassembly": 0.00001}})
                previous.append(weakref.ref(result))
                return result

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.elf"
            path.write_bytes(b"\x7fELF")
            settings = lambda path, count, full: Settings(semantic_threads=count or 1, analyze_threads=4)
            with patch("fangida.benchmark._settings", side_effect=settings), \
                 patch("fangida.benchmark.AnalysisService", FakeService), \
                 patch("fangida.benchmark._peak_rss", return_value=None), \
                 patch("fangida.benchmark._child_cpu", return_value=None):
                result = benchmark(path, runs=3, semantic_threads=1, full_analysis=True)
                self.assertEqual(len(result["seconds"]), 3)
                self.assertTrue(result["stable_output"])
                self.assertIsNone(result["peak_rss_bytes"])
                self.assertTrue(all(item["child_cpu_seconds"] is None for item in result["measurements"]))
                self.assertIsNone(previous[-1]())
                compared = compare_threads(path, runs=2, semantic_threads=2, full_analysis=True)
                self.assertTrue(compared["same_evidence_and_scope"])
                self.assertEqual(len(compared["multi_thread"]["seconds"]), 2)
                self.assertIsNone(previous[-1]())

    def test_benchmark_cli_saves_same_json_and_forwards_full_option(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "测速结果.json"
            output = io.StringIO()
            with patch("sys.argv", ["fangida-bench", "sample.elf", "--full", "--runs", "1",
                                     "--output", str(destination)]), \
                 patch("fangida.benchmark.benchmark", return_value={"full_analysis": True}) as run, \
                 redirect_stdout(output):
                self.assertEqual(main(), 0)
            run.assert_called_once_with(Path("sample.elf"), 1, None, True)
            self.assertEqual(json.loads(destination.read_text(encoding="utf-8")), json.loads(output.getvalue()))

    def test_cli_and_gui_full_options_keep_fast_mutually_exclusive(self) -> None:
        with patch("fangida.gui.launch", return_value=0) as launch:
            self.assertEqual(gui_main(["sample.elf", "--full"]), 0)
        self.assertTrue(launch.call_args.kwargs["full_analysis"])
        with patch("fangida.ui.AnalysisService") as service, \
             patch("fangida.ui.load_settings", return_value=Settings()), \
             patch("sys.argv", ["fangida", "sample.elf", "--full", "--threads", "2"]), \
             redirect_stdout(io.StringIO()):
            service.return_value.__enter__.return_value.analyze.return_value = AnalysisResult(
                "sample.elf", "elf", "kkagent", "partial")
            self.assertEqual(ui_main(), 0)
            self.assertTrue(service.return_value.__enter__.return_value.analyze.call_args.kwargs["full_analysis"])
            self.assertGreaterEqual(service.call_args.args[0].analyze_threads, 3)
        with redirect_stdout(io.StringIO()), patch("sys.stderr", io.StringIO()):
            with self.assertRaises(SystemExit):
                gui_main(["sample.elf", "--full", "--fast"])

    def test_decoder_budget_includes_xref_reservation(self) -> None:
        from fangida.benchmark import _settings
        with patch("fangida.benchmark.load_settings", return_value=replace(Settings(), analyze_threads=2)):
            with self.assertRaisesRegex(ValueError, "reserving the xref thread"):
                _settings(Path("sample.elf"), 2)

    def test_full_cli_output_streams_result_and_prints_only_summary(self) -> None:
        result = AnalysisResult("sample.elf", "elf", "kkagent", "partial",
                                metadata={"full_analysis": {"enabled": True},
                                          "full_disassembly": [{"addr": 1, "mnemonic": "ret"}]},
                                functions=[{"name": "函数", "start": 1}],
                                stats={"full_analysis": True})
        expected = json.loads(json.dumps(result.to_dict(), ensure_ascii=False))
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "分析结果.json"
            console = io.StringIO()
            with patch("fangida.ui.AnalysisService") as service, \
                 patch("fangida.ui.load_settings", return_value=Settings()), \
                 patch("sys.argv", ["fangida", "sample.elf", "--full", "--output", str(destination)]), \
                 patch.object(result, "to_dict", side_effect=AssertionError("copied full graph")), \
                 patch("fangida.ui.AnalysisView", side_effect=AssertionError("copied full snapshot")), \
                 redirect_stdout(console):
                service.return_value.__enter__.return_value.analyze.return_value = result
                self.assertEqual(ui_main(), 0)
            self.assertEqual(json.loads(destination.read_text(encoding="utf-8")), expected)
            summary = json.loads(console.getvalue())
            self.assertEqual(summary["output"], str(destination.resolve()))
            self.assertNotIn("functions", summary)
            self.assertNotIn("full_disassembly", summary)

    def test_full_gui_prepares_one_snapshot_and_keeps_summary_bounded(self) -> None:
        instructions = [{"addr": index, "mnemonic": "nop"} for index in range(1200)]
        view = AnalysisView(AnalysisResult("sample.elf", "elf", "kkagent", "partial",
                                          metadata={"full_disassembly": instructions},
                                          functions=[{"name": "original", "start": 0,
                                                      "blocks": [{"start": 0, "instructions": instructions}],
                                                      "cfg": {"complete": True}}],
                                          stats={"full_analysis": True}))
        with patch.object(view, "snapshot", side_effect=AssertionError("copied for summary")):
            summary = json.loads(summary_text(view))
        self.assertEqual(summary["metadata"]["full_disassembly_count"], 1200)
        self.assertNotIn("full_disassembly", summary["metadata"])
        with patch.object(view, "snapshot", wraps=view.snapshot) as snapshot, \
             patch.object(view, "functions", side_effect=AssertionError("copied functions twice")), \
             patch.object(view, "disassembly", side_effect=AssertionError("indexed full disassembly for preview")):
            loaded = gui_prepare(view)
            self.assertEqual(snapshot.call_count, 1)
            self.assertEqual(len(loaded.tables["Disassembly"]), 1000)
        loaded.tables["Functions"][0]["name"] = "changed"
        loaded.tables["Disassembly"][0]["mnemonic"] = "changed"
        self.assertEqual(view.functions()[0]["name"], "original")
        self.assertEqual(view.disassembly(0, 1)[0]["mnemonic"], "nop")


if __name__ == "__main__":
    unittest.main()
