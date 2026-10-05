"""Protocol and snapshot behavior of the dependency-free MCP stdio server."""
from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from fangida.mcp_server import McpServer, serve
from fangida.settings import Settings

PROJECT = Path(__file__).resolve().parents[1]


class McpTests(unittest.TestCase):
    def test_stdio_session_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory) / "sample.elf"
            sample.write_bytes(b"\x7fELF" + b"\x00" * 60 + b"test string\x00")
            with subprocess.Popen([sys.executable, "-m", "fangida.mcp_server"], cwd=PROJECT,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE) as process:
                assert process.stdin is not None and process.stdout is not None

                def request(identifier: int, method: str, params: dict | None = None) -> dict:
                    payload = {"jsonrpc": "2.0", "id": identifier, "method": method,
                               "params": params or {}}
                    process.stdin.write(json.dumps(payload).encode() + b"\n")
                    process.stdin.flush()
                    line = process.stdout.readline()
                    self.assertTrue(line.endswith(b"\n"), "MCP stdio uses JSON line framing")
                    return json.loads(line)

                self.assertEqual(request(1, "initialize", {
                    "protocolVersion": "2025-11-25", "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1.0"},
                })["result"]["protocolVersion"], "2025-11-25")
                process.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
                process.stdin.flush()
                tools = request(2, "tools/list")["result"]["tools"]
                self.assertNotIn("rename_symbol", {tool["name"] for tool in tools})
                opened = request(3, "tools/call", {"name": "open_file", "arguments": {"path": str(sample)}})
                self.assertNotIn("error", opened)
                handle = opened["result"]["structuredContent"]["handle"]
                self.assertEqual(opened["result"]["structuredContent"]["kind"], "elf")
                exported = request(4, "tools/call", {"name": "export_result", "arguments": {
                    "handle": handle, "limit": 1}})["result"]["structuredContent"]
                self.assertEqual(exported["schema_version"], "1.0")
                self.assertEqual(exported["pages"]["strings"]["items"][0]["value"], "test string")
                self.assertTrue(request(5, "tools/call", {"name": "get_pseudoc", "arguments": {
                    "handle": handle}})["result"]["isError"])
                self.assertEqual(request(6, "tools/call", {"name": "rename_symbol", "arguments": {
                    "handle": handle, "address": 0, "name": "foo"}})["error"]["code"], -32602)
                self.assertTrue(request(7, "tools/call", {"name": "close_file", "arguments": {
                    "handle": handle}})["result"]["structuredContent"]["closed"])
                self.assertTrue(request(8, "tools/call", {"name": "list_functions", "arguments": {
                    "handle": handle}})["result"]["isError"])
                process.stdin.close()
                self.assertEqual(process.wait(timeout=10), 0)

    def test_parse_error_notification_and_handshake(self) -> None:
        lines = [b"not json\n", b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n',
                 b'{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}\n',
                 b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n',
                 b'{"jsonrpc":"2.0","id":3,"method":"ping"}\n']
        output = io.BytesIO()
        serve(io.BytesIO(b"".join(lines)), output)
        responses = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual([response["id"] for response in responses], [None, 1, 2, 3])
        self.assertEqual(responses[0]["error"]["code"], -32700)
        self.assertEqual(responses[1]["error"]["code"], -32000)
        self.assertEqual(responses[-1]["result"], {})

    def test_enabled_rename_only_changes_snapshot(self) -> None:
        server = McpServer(allow_writes=True, settings=Settings())
        try:
            server._snapshots["test"] = {"status": "partial", "metadata": {},
                                         "functions": [{"start": 0x1000, "name": "old"}],
                                         "xrefs": [{"src": 0x1000, "dst": 0x2000, "kind": "call"}]}
            result = server.call_tool("rename_symbol", {"handle": "test", "address": "0x1000", "name": "new"})
            self.assertEqual(result["structuredContent"]["scope"], "session_snapshot")
            self.assertEqual(server._snapshots["test"]["functions"][0]["name"], "new")
            xrefs = server.call_tool("xref_query", {"handle": "test", "address": "0x2000", "direction": "to"})
            self.assertEqual(xrefs["structuredContent"]["total"], 1)
            server._snapshots["test"]["metadata"]["disassembly"] = [
                {"addr": 0x1000, "mnemonic": "nop"}, {"addr": 0x1001, "mnemonic": "ret"}]
            disasm = server.call_tool("get_disasm", {"handle": "test", "address": "0x1001"})
            self.assertEqual([item["mnemonic"] for item in disasm["structuredContent"]["items"]], ["ret"])
        finally:
            server.close()


if __name__ == "__main__":
    unittest.main()
