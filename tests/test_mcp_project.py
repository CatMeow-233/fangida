"""Persistent project tools share the MCP session and enforce write opt-in."""
from __future__ import annotations

from contextlib import closing
import tempfile
import sqlite3
import unittest
from pathlib import Path

from fangida.mcp_server import McpServer
from fangida.project import ProjectStore
from fangida.settings import Settings


def value(server: McpServer, tool_name: str, **arguments: object) -> dict:
    response = server.call_tool(tool_name, arguments)
    if response.get("isError"):
        raise AssertionError(response["content"][0]["text"])
    return response["structuredContent"]


class McpProjectTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / "sample.elf"
        self.source.write_bytes(b"\x7fELF" + b"\x00" * 60 + b"test string\x00")
        self.database = Path(self.temp.name) / "project.fangida"

    def test_persistent_snapshot_and_annotations_across_sessions(self) -> None:
        writer = McpServer(allow_writes=True, settings=Settings())
        try:
            project = value(writer, "create_project", path=str(self.database))["project"]
            saved = value(writer, "analyze_to_project", project=project,
                          path=str(self.source), max_bytes=4096)
            snapshot_id = saved["snapshot_id"]
            self.assertGreater(snapshot_id, 0)
            value(writer, "project_rename_symbol", project=project,
                  path=str(self.source), address="0x1000", name="entry")
            value(writer, "project_set_comment", project=project,
                  path=str(self.source), address=0x1000, text="reviewed")
            self.assertEqual(value(writer, "project_history", project=project)["total"], 1)
            self.assertEqual(value(writer, "project_page", project=project,
                                   snapshot_id=snapshot_id, collection="strings",
                                   offset=0, limit=1)["items"][0]["value"], "test string")
            self.assertEqual(value(writer, "project_annotations", project=project,
                                   path=str(self.source), limit=1)["total"], 2)
            self.assertTrue(value(writer, "close_project", project=project)["closed"])
        finally:
            writer.close()

        original_bytes = self.database.read_bytes()
        original_mtime = self.database.stat().st_mtime_ns
        reader = McpServer(settings=Settings())
        try:
            init = reader.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                  "params": {"protocolVersion": "2025-11-25"}})
            self.assertEqual(init["result"]["capabilities"], {"tools": {}})
            reader.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
            listed = reader.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            tool_names = {tool["name"] for tool in listed["result"]["tools"]}
            self.assertIn("open_project", tool_names)
            self.assertIn("project_annotations", tool_names)
            self.assertNotIn("create_project", tool_names)
            self.assertNotIn("project_rename_symbol", tool_names)
            opened = value(reader, "open_project", path=str(self.database))["project"]
            history = value(reader, "project_history", project=opened,
                            path=str(self.source), limit=1)
            self.assertEqual(history["items"][0]["id"], snapshot_id)
            handle = value(reader, "open_project_snapshot", project=opened,
                           snapshot_id=snapshot_id)["handle"]
            export = value(reader, "export_result", handle=handle)
            self.assertEqual(export["kind"], "elf")
            annotations = value(reader, "project_annotations", project=opened,
                                path=str(self.source))
            self.assertEqual({(item["kind"], item["value"]) for item in annotations["items"]},
                             {("rename", "entry"), ("comment", "reviewed")})
            self.assertTrue(reader.call_tool("project_set_comment", {
                "project": opened, "path": str(self.source), "address": 1,
                "text": "denied"})["isError"])
        finally:
            reader.close()
        self.assertEqual(self.database.read_bytes(), original_bytes)
        self.assertEqual(self.database.stat().st_mtime_ns, original_mtime)

    def test_default_read_only_cannot_create_or_migrate(self) -> None:
        reader = McpServer(settings=Settings())
        try:
            missing = reader.call_tool("open_project", {"path": str(self.database)})
            self.assertTrue(missing["isError"])
            self.assertFalse(self.database.exists())
            denied = reader.call_tool("create_project", {"path": str(self.database)})
            self.assertTrue(denied["isError"])
            self.assertFalse(self.database.exists())
            denied = reader.call_tool("analyze_to_project", {"project": "missing",
                          "path": str(self.source)})
            self.assertTrue(denied["isError"])
        finally:
            reader.close()
        with closing(sqlite3.connect(self.database)) as connection, connection:
            ProjectStore._create_v1(connection)
            connection.execute("PRAGMA user_version=1")
        reader = McpServer(settings=Settings())
        try:
            self.assertTrue(reader.call_tool("open_project", {
                "path": str(self.database)})["isError"])
        finally:
            reader.close()
        with closing(sqlite3.connect(self.database)) as connection, connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)
        writer = McpServer(allow_writes=True, settings=Settings())
        try:
            opened = value(writer, "open_project", path=str(self.database))["project"]
            self.assertEqual(value(writer, "project_history", project=opened)["total"], 0)
        finally:
            writer.close()
        with closing(sqlite3.connect(self.database)) as connection, connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 2)

    def test_content_scoped_read_only_annotations(self) -> None:
        writer = McpServer(allow_writes=True, settings=Settings())
        try:
            project = value(writer, "create_project", path=str(self.database))["project"]
            value(writer, "project_rename_symbol", project=project,
                  path=str(self.source), address=4096, name="original")
        finally:
            writer.close()
        self.source.write_bytes(b"\x7fELF" + b"\x00" * 60 + b"other string\x00")
        original_bytes = self.database.read_bytes()
        original_mtime = self.database.stat().st_mtime_ns
        reader = McpServer(settings=Settings())
        try:
            project = value(reader, "open_project", path=str(self.database))["project"]
            self.assertEqual(value(reader, "project_annotations", project=project,
                                   path=str(self.source))["total"], 0)
        finally:
            reader.close()
        self.assertEqual(self.database.read_bytes(), original_bytes)
        self.assertEqual(self.database.stat().st_mtime_ns, original_mtime)


if __name__ == "__main__":
    unittest.main()
