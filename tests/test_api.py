import json
import tempfile
import unittest
from pathlib import Path
from fangida.api import AnalysisView
from fangida.models import AnalysisResult

class ApiTests(unittest.TestCase):
    def test_disassembly_includes_semantic_functions_beyond_entry(self) -> None:
        result = AnalysisResult("sample", "elf", "kkagent", "partial",
                                metadata={"disassembly": [{"addr": 0x100, "mnemonic": "call"}]},
                                functions=[{"start": 0x100, "blocks": [{"instructions": [
                                    {"addr": 0x100, "mnemonic": "call", "reads": ["rax"]}]}]},
                                           {"start": 0x200, "blocks": [{"instructions": [
                                               {"addr": 0x200, "mnemonic": "ret"}]}]}])
        view = AnalysisView(result)
        self.assertEqual([item["addr"] for item in view.disassembly(0)], [0x100, 0x200])
        self.assertEqual(view.disassembly(0)[0]["reads"], ["rax"])
        self.assertEqual(view.disassembly(0x200)[0]["mnemonic"], "ret")

    def test_snapshot_isolation_and_export(self) -> None:
        result = AnalysisResult("sample", "elf", "kkagent", "partial", strings=[{"value": "hello"}])
        view = AnalysisView(result)
        result.strings[0]["value"] = "changed"
        view.strings()[0]["value"] = "mutated"
        self.assertEqual(view.strings()[0]["value"], "hello")
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "out.json"
            view.export_json(destination)
            self.assertEqual(json.loads(destination.read_text())["strings"][0]["value"], "hello")
