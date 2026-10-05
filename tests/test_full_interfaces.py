"""Full disassembly stays accessible through existing script/project/MCP APIs."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fangida.api import AnalysisView
from fangida.mcp_server import McpServer
from fangida.models import AnalysisResult
from fangida.project import ProjectStore
from fangida.scripts import ScriptContext
from fangida.settings import Settings


def result(path="sample"):
    records = [{"addr": 0x1000 + n, "size": 1, "mnemonic": "nop"} for n in range(3)]
    return AnalysisResult(path, "elf", "kkagent", "partial",
                          metadata={"disassembly": records[:1], "full_disassembly": records},
                          stats={"full_analysis": True})


class FullInterfaceTests(unittest.TestCase):
    def test_snapshot_and_scripts_can_read_unassigned_full_instructions(self):
        raw = result()
        view, script = AnalysisView(raw), ScriptContext(raw)
        raw.metadata["full_disassembly"][1]["mnemonic"] = "changed"
        for interface in (view, script):
            page = interface.disassembly(0x1001)
            self.assertEqual([item["addr"] for item in page], [0x1001, 0x1002])
            self.assertEqual(page[0]["mnemonic"], "nop")

    def test_project_disassembly_page_retains_full_region_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample"
            path.write_bytes(b"abc")
            store = ProjectStore(Path(directory) / "project.db")
            snapshot_id = store.save_analysis(path, result(str(path)))
            page = store.page(snapshot_id, "disassembly", limit=10)
            self.assertEqual(page["total"], 3)
            self.assertEqual(page["items"][-1]["addr"], 0x1002)

    def test_mcp_full_omitted_scan_limit_reaches_service_and_pages_all_records(self):
        server = McpServer(settings=Settings())
        try:
            raw = result()
            with patch.object(server.service, "analyze", return_value=raw) as analyze:
                opened = server.call_tool("open_file", {"path": "sample", "full_analysis": True})
            self.assertFalse(opened.get("isError"), opened)
            self.assertIsNone(analyze.call_args.kwargs["max_bytes"])
            self.assertTrue(analyze.call_args.kwargs["full_analysis"])
            handle = opened["structuredContent"]["handle"]
            raw.metadata["full_disassembly"][1]["mnemonic"] = "changed"
            page = server.call_tool("get_disasm", {"handle": handle, "address": 0x1001})
            self.assertEqual(page["structuredContent"]["total"], 2)
            self.assertEqual(page["structuredContent"]["items"][0]["mnemonic"], "nop")
        finally:
            server.close()


if __name__ == "__main__":
    unittest.main()
