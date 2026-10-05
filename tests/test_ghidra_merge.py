import unittest
from types import SimpleNamespace
from fangida.core.kkagent import _merge_ghidra
from fangida.models import AnalysisResult

class GhidraMergeTests(unittest.TestCase):
    def test_supplement_deduplicates_local_evidence(self) -> None:
        result = AnalysisResult("sample", "elf", "kkagent", "partial",
                                functions=[{"start": 0x100, "name": "original", "source": "symtab"}],
                                xrefs=[{"src": 0x100, "dst": 0x200, "kind": "call", "confidence": 1.0}])
        supplement = SimpleNamespace(
            functions=[{"start": 0x100, "name": "gh_name", "address_space": "ram"},
                       {"start": 0x200, "name": "helper", "address_space": "ram"}],
            xrefs=[{"src": 0x100, "dst": 0x200, "kind": "call", "src_space": "ram", "dst_space": "ram"}],
            pcode=[{"addr": 0x100, "ops": []}],
            decompiled_functions=[{"start": 0x100, "address_space": "ram", "pseudoc": "int main() {}",
                                   "producer": "ghidra", "truncated": False}],
            stats={"function_count": 2}, warnings=[])
        _merge_ghidra(result, supplement)
        self.assertEqual(len(result.functions), 2)
        self.assertEqual(result.functions[0]["name"], "original")
        self.assertEqual(result.functions[0]["ghidra_name"], "gh_name")
        self.assertEqual(len(result.xrefs), 1)
        self.assertEqual(result.metadata["ghidra"]["pcode"][0]["addr"], 0x100)
        self.assertEqual(result.functions[0]["pseudoc"], "int main() {}")
