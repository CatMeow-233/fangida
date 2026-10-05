"""存储插件的 CLI/MCP 离线读取、写权限和旧工具兼容。"""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from fangida.database_cli import main as database_main
from fangida.mcp_server import MAX_OPEN_DATABASES, McpServer, _tools
from fangida.models import AnalysisResult
from fangida.settings import Settings


READ_DATABASE_TOOLS = {
    "open_database", "close_database", "database_history", "database_page",
    "database_annotations", "open_database_snapshot",
}
WRITE_DATABASE_TOOLS = {
    "create_database", "save_to_database", "database_rename_symbol", "database_set_comment",
}


def value(server: McpServer, tool_name: str, **arguments: object) -> dict:
    response = server.call_tool(tool_name, arguments)
    if response.get("isError"):
        raise AssertionError(response["content"][0]["text"])
    return response["structuredContent"]


class StorageAccessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / "sample.elf"
        self.source.write_bytes(b"\x7fELF" + b"\0" * 60 + b"original")
        self.database = Path(self.temp.name) / "sample.fdb"
        self.result = AnalysisResult(str(self.source), "elf", "kkagent", "partial",
            metadata={"full_disassembly": [
                {"addr": 0x1000, "size": 1, "mnemonic": "nop"},
                {"addr": 0x1001, "size": 1, "mnemonic": "ret"}]},
            functions=[{"start": 0x1000, "name": "original_function"}],
            xrefs=[{"src": 0x1000, "dst": 0x2000, "kind": "call"}])

    def create_saved(self) -> tuple[int, McpServer, str]:
        server = McpServer(allow_writes=True, settings=Settings())
        self.addCleanup(server.close)
        database = value(server, "create_database", path=str(self.database))["database"]
        with patch.object(server.service, "analyze", return_value=self.result):
            handle = value(server, "open_file", path=str(self.source))["handle"]
        with patch.object(server.service, "analyze", side_effect=AssertionError("必须复用快照")):
            snapshot_id = value(server, "save_to_database", database=database, handle=handle)["snapshot_id"]
        return snapshot_id, server, database

    def test_tool_surface_keeps_legacy_and_enforces_write_opt_in(self):
        read = {item["name"]: item for item in _tools(False)}
        write = {item["name"]: item for item in _tools(True)}
        self.assertTrue(READ_DATABASE_TOOLS <= read.keys())
        self.assertFalse(WRITE_DATABASE_TOOLS & read.keys())
        self.assertTrue(WRITE_DATABASE_TOOLS <= write.keys())
        self.assertTrue({"open_file", "close_file", "open_project", "project_history",
                         "list_functions", "get_disasm", "xref_query"} <= read.keys())
        self.assertTrue(read["open_database"]["inputSchema"]["properties"]["read_only"]["default"])
        for name in WRITE_DATABASE_TOOLS:
            self.assertFalse(write[name]["annotations"]["readOnlyHint"])

    def test_default_read_only_cannot_create_open_write_or_save(self):
        reader = McpServer(settings=Settings())
        self.addCleanup(reader.close)
        for tool, arguments in (("open_database", {"path": str(self.database)}),
                                ("create_database", {"path": str(self.database)}),
                                ("open_database", {"path": str(self.database), "read_only": False})):
            self.assertTrue(reader.call_tool(tool, arguments)["isError"])
            self.assertFalse(self.database.exists())

    def test_rpc_handshake_exposes_database_reads_and_rejects_hidden_writes(self):
        _, writer, database = self.create_saved()
        value(writer, "close_database", database=database)
        reader = McpServer(settings=Settings())
        self.addCleanup(reader.close)
        reader.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"protocolVersion": "2025-03-26"}})
        reader.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
        listed = reader.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = {tool["name"] for tool in listed["result"]["tools"]}
        self.assertTrue(READ_DATABASE_TOOLS <= names)
        self.assertFalse(WRITE_DATABASE_TOOLS & names)
        denied = reader.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "database_set_comment", "arguments": {}}})
        self.assertEqual(denied["error"]["code"], -32602)
        opened = reader.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "open_database", "arguments": {"path": str(self.database)}}})
        self.assertTrue(opened["result"]["structuredContent"]["read_only"])

    def test_database_close_failure_still_releases_other_handles_and_service(self):
        server = McpServer(settings=Settings())
        first = Mock()
        first.close.side_effect = RuntimeError("close failed")
        second = Mock()
        server._databases.update({"first": first, "second": second})
        with patch.object(server.service, "close") as close:
            with self.assertRaisesRegex(RuntimeError, "close failed"):
                server.close()
        second.close.assert_called_once_with()
        close.assert_called_once_with()
        self.assertFalse(server._databases)

    def test_offline_snapshot_annotations_and_original_analysis_tools(self):
        snapshot_id, writer, database = self.create_saved()
        self.source.unlink()
        value(writer, "database_rename_symbol", database=database, snapshot_id=snapshot_id,
              address="0x1000", name="renamed_function")
        value(writer, "database_set_comment", database=database, snapshot_id=snapshot_id,
              address=0x1000, text="离线审查")
        value(writer, "close_database", database=database)
        writer.close()
        original = self.database.read_bytes(), self.database.stat().st_mtime_ns
        reader = McpServer(settings=Settings())
        self.addCleanup(reader.close)
        database = value(reader, "open_database", path=str(self.database))["database"]
        self.assertTrue(reader._databases[database].read_only)
        history = value(reader, "database_history", database=database, path=str(self.source))
        self.assertEqual(history["total"], 1)
        annotations = value(reader, "database_annotations", database=database, snapshot_id=snapshot_id)
        self.assertEqual({(item["kind"], item["value"]) for item in annotations["items"]},
                         {("rename", "renamed_function"), ("comment", "离线审查")})
        self.assertEqual(value(reader, "database_page", database=database,
                               snapshot_id=snapshot_id, collection="disassembly")["total"], 2)
        handle = value(reader, "open_database_snapshot", database=database)["handle"]
        self.assertEqual(value(reader, "list_functions", handle=handle)["items"][0]["name"], "renamed_function")
        self.assertEqual(value(reader, "get_disasm", handle=handle)["total"], 2)
        self.assertEqual(value(reader, "xref_query", handle=handle, address="0x2000")["total"], 1)
        self.assertTrue(reader.call_tool("database_set_comment", {
            "database": database, "snapshot_id": snapshot_id, "address": 0x1000, "text": "禁止"})["isError"])
        value(reader, "close_database", database=database)
        # 读取到会话中的快照属于独立副本，数据库关闭不丢失会话结果。
        self.assertEqual(value(reader, "list_functions", handle=handle)["total"], 1)
        reader.close()
        self.assertEqual((self.database.read_bytes(), self.database.stat().st_mtime_ns), original)

    def test_changed_source_cannot_be_bound_to_old_result(self):
        writer = McpServer(allow_writes=True, settings=Settings())
        self.addCleanup(writer.close)
        database = value(writer, "create_database", path=str(self.database))["database"]
        with patch.object(writer.service, "analyze", return_value=self.result):
            handle = value(writer, "open_file", path=str(self.source))["handle"]
        self.source.write_bytes(b"changed source")
        denied = writer.call_tool("save_to_database", {"database": database, "handle": handle})
        self.assertTrue(denied["isError"])
        self.assertIn("Source changed", denied["content"][0]["text"])
        self.assertEqual(value(writer, "database_history", database=database)["total"], 0)

    def test_write_enabled_server_defaults_existing_database_to_read_only(self):
        snapshot_id, writer, database = self.create_saved()
        value(writer, "close_database", database=database)
        database = value(writer, "open_database", path=str(self.database))["database"]
        self.assertTrue(writer.call_tool("database_set_comment", {
            "database": database, "snapshot_id": snapshot_id, "address": 0x1000, "text": "禁止"})["isError"])
        value(writer, "close_database", database=database)
        database = value(writer, "open_database", path=str(self.database), read_only=False)["database"]
        value(writer, "database_set_comment", database=database, snapshot_id=snapshot_id,
              address=0x1000, text="允许")

    def test_database_handles_are_bounded_and_separate_from_project_handles(self):
        _, writer, database = self.create_saved()
        value(writer, "close_database", database=database)
        handles = [value(writer, "open_database", path=str(self.database))["database"]
                   for _ in range(MAX_OPEN_DATABASES)]
        self.assertTrue(writer.call_tool("open_database", {"path": str(self.database)})["isError"])
        self.assertTrue(writer.call_tool("project_history", {"project": handles[0]})["isError"])
        self.assertTrue(writer.call_tool("database_history", {"database": "missing"})["isError"])
        value(writer, "close_database", database=handles[0])
        value(writer, "open_database", path=str(self.database))

    def cli(self, *arguments: str) -> tuple[int, dict]:
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            status = database_main([str(self.database), *arguments])
        return status, json.loads(output.getvalue() if status == 0 else error.getvalue())

    def test_database_cli_reads_and_writes_without_original_binary(self):
        snapshot_id, writer, database = self.create_saved()
        value(writer, "close_database", database=database)
        self.source.unlink()
        original = self.database.read_bytes(), self.database.stat().st_mtime_ns
        self.assertEqual(self.cli("history")[1]["total"], 1)
        self.assertEqual(self.cli("page", str(snapshot_id), "functions")[1]["total"], 1)
        self.assertEqual(self.cli("show")[1]["functions"][0]["name"], "original_function")
        self.assertEqual((self.database.read_bytes(), self.database.stat().st_mtime_ns), original)
        self.assertEqual(self.cli("rename", str(snapshot_id), "0x1000", "cli_name")[0], 0)
        self.assertEqual(self.cli("comment", str(snapshot_id), "0x1000", "注释")[0], 0)
        self.assertEqual(self.cli("show", str(snapshot_id))[1]["functions"][0]["name"], "cli_name")
        self.assertEqual(self.cli("annotations", str(snapshot_id))[1]["comments"]["4096"], "注释")

    def test_cli_missing_database_reads_do_not_create(self):
        status, result = self.cli("history")
        self.assertEqual(status, 2)
        self.assertEqual(result["status"], "error")
        self.assertFalse(self.database.exists())


if __name__ == "__main__":
    unittest.main()
