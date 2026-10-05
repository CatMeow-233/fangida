import unittest
from fangida.mcp_server import McpServer
from fangida.settings import Settings

class ExtendedMcpTests(unittest.TestCase):
    def test_pseudocode_can_select_android_method_by_code_offset(self) -> None:
        server = McpServer(settings=Settings())
        try:
            server._snapshots["s"] = {"status": "partial", "functions": [
                {"name": "first", "code_offset": 0x40, "pseudoc": "first() {}",
                 "pseudoc_producer": "fangida_bytecode_outline"},
                {"name": "second", "code_offset": 0x80, "pseudoc": "second() {}",
                 "pseudoc_producer": "fangida_bytecode_outline"}],
                "metadata": {}, "xrefs": [], "strings": [], "imports": [], "exports": []}
            result = server.call_tool("get_pseudoc", {"handle": "s", "address": "0x80"})
            self.assertEqual(result["structuredContent"]["pseudoc"], "second() {}")
            self.assertEqual(result["structuredContent"]["address"], 0x80)
        finally:
            server.close()

    def test_bytecode_source_filter_and_api_evidence(self) -> None:
        server = McpServer(settings=Settings())
        try:
            server._snapshots["s"] = {
                "status": "partial", "metadata": {"api_calls": [
                    {"source": "classes.dex", "addr": 0x80, "target": "Landroid/os/Bundle;->get"}]},
                "functions": [
                    {"source": "classes.dex", "disassembly": [{"addr": 0x80, "mnemonic": "invoke"}]},
                    {"source": "classes2.dex", "disassembly": [{"addr": 0x80, "mnemonic": "return"}]},
                ], "xrefs": [], "strings": [], "imports": [], "exports": [], "warnings": [],
            }
            data = server.call_tool("get_disasm", {"handle": "s", "source": "classes.dex"})
            self.assertEqual([item["mnemonic"] for item in data["structuredContent"]["items"]], ["invoke"])
            calls = server.call_tool("list_api_calls", {"handle": "s"})
            self.assertEqual(calls["structuredContent"]["total"], 1)
        finally:
            server.close()
