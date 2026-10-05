"""Display-free checks for the desktop browser's result adapters."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fangida.api import AnalysisView
from fangida.gui import (_display, cfg_block_rows, cfg_graphs, hex_page, main,
                         parse_seek_offset, summary_text, table_data)
from fangida.models import AnalysisResult


class GuiDataTests(unittest.TestCase):
    def test_native_result_tables_and_summary(self) -> None:
        view = AnalysisView(AnalysisResult(
            path="sample.elf", kind="elf", analyzer="kkagent", status="partial",
            metadata={"architecture": "x86_64", "sections": [{"name": ".text", "address": 0x401000}],
                      "disassembly": [{"addr": 0x401000, "mnemonic": "ret", "operands": []}]},
            functions=[{"name": "main", "start": 0x401000}],
            strings=[{"offset": 3, "value": "hello", "length": 5}],
            xrefs=[{"src": 0x401000, "dst": 0x401010, "kind": "jmp"}],
            warnings=["Entry window only"],
        ))
        tables = table_data(view)
        self.assertEqual(tables["Sections"][0]["name"], ".text")
        self.assertEqual(tables["Functions"][0]["location"], 0x401000)
        self.assertEqual(tables["Disassembly"][0]["mnemonic"], "ret")
        self.assertEqual(tables["Strings"][0]["value"], "hello")
        self.assertEqual(tables["Xrefs"][0]["dst"], 0x401010)
        self.assertIn("Entry window only", summary_text(view))
        self.assertNotIn('"disassembly"', summary_text(view))
        self.assertEqual(_display(0x401000, "location"), "0x401000")
        self.assertEqual(_display([0x401000, 0x501000], "address"), "0x401000, 0x501000")

    def test_dex_method_uses_code_offset(self) -> None:
        view = AnalysisView(AnalysisResult(
            path="sample.dex", kind="dex", analyzer="apk_analyzer", status="partial",
            functions=[{"name": "Lx;->main", "descriptor": "()V", "code_offset": 128}],
        ))
        self.assertEqual(table_data(view)["Functions"][0]["location"], 128)
        self.assertEqual(_display("line\nnext", "value"), "line\\nnext")

    def test_gui_entrypoint_options(self) -> None:
        with patch("fangida.gui.launch", return_value=0) as launch:
            self.assertEqual(main(["sample.elf", "--max-bytes", "4096", "--ghidra", "--fast",
                                   "--threads", "3"]), 0)
        launch.assert_called_once_with("sample.elf", max_bytes=4096, use_ghidra=True,
                                       deep_analysis=False, semantic_threads=3)

    def test_hex_seek_and_bounded_pages(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "sample.bin"
            source.write_bytes(bytes(range(256)) * 9)
            first = hex_page(source, 0, rows=2)
            self.assertIn("00000000  00 01 02 03", first["text"])
            self.assertIn("|................|", first["text"])
            self.assertIsNone(first["previous_offset"])
            self.assertEqual(first["next_offset"], 32)
            second = hex_page(source, parse_seek_offset("0x23"), rows=2)
            self.assertEqual(second["start"], 32)
            self.assertEqual(second["previous_offset"], 0)
            self.assertIn("00000020", second["text"])
            last = hex_page(source, len(source.read_bytes()), rows=2)
            self.assertIsNone(last["next_offset"])
            with self.assertRaises(ValueError):
                hex_page(source, 2_305)
            with self.assertRaises(ValueError):
                hex_page(source, 0, rows=257)
            with self.assertRaises(ValueError):
                hex_page(source, True)
            source.unlink()
            with self.assertRaises(FileNotFoundError):
                hex_page(source, 0)
        self.assertEqual(parse_seek_offset("008"), 8)
        with self.assertRaises(ValueError):
            parse_seek_offset("-0x1")

    def test_cfg_graphs_and_block_detail(self) -> None:
        graph = {"entry": 0x1000, "complete": False,
                 "edges": [{"src": 0x1002, "dst": 0x1010, "kind": "branch"}],
                 "frontier": [{"from": 0x1002, "to": 0x2000, "reason": "outside_window"}],
                 "blocks": [{"start": 0x1000,
                             "instructions": [{"addr": 0x1000, "mnemonic": "cmp"},
                                              {"addr": 0x1002, "mnemonic": "jne"}],
                             "successors": [0x1010]},
                            {"start": 0x1010, "instructions": [{"addr": 0x1010,
                                                                  "mnemonic": "ret"}]}]}
        view = AnalysisView(AnalysisResult(
            "sample", "elf", "kkagent", "partial", metadata={"entry_cfg": graph},
            functions=[{"start": 0x1000, "name": "start", "blocks": graph["blocks"],
                        "cfg": {key: value for key, value in graph.items() if key != "blocks"}}]))
        graphs = cfg_graphs(view)
        self.assertEqual(len(graphs), 1)  # entry metadata does not create a duplicate
        rows = cfg_block_rows(graphs[0]["graph"])
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["successors"], [0x1010])
        self.assertEqual(rows[0]["frontier"][0]["reason"], "outside_window")
        self.assertEqual(cfg_block_rows({"blocks": "invalid"}), [])


if __name__ == "__main__":
    unittest.main()
