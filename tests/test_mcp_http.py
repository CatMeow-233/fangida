"""Wire-level tests of the Streamable HTTP MCP request/response transport."""
from __future__ import annotations

from http.client import HTTPConnection
import json
from pathlib import Path
from threading import Thread
import tempfile
import unittest

from fangida.mcp_http import McpHttpServer


def _rpc(identifier: int, method: str, params: dict | None = None) -> dict:
    return {"jsonrpc": "2.0", "id": identifier, "method": method, "params": params or {}}


class HttpMcpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = McpHttpServer(("127.0.0.1", 0))
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def request(self, method: str, payload: dict | bytes | None = None, *,
                headers: dict[str, str] | None = None,
                host: str | None = None) -> tuple[int, dict[str, str], bytes]:
        conn = HTTPConnection("127.0.0.1", self.port, timeout=4)
        body = (json.dumps(payload).encode("utf-8") if isinstance(payload, dict)
                else payload)
        sent = {"Host": host or f"127.0.0.1:{self.port}", **(headers or {})}
        if method == "POST":
            sent.setdefault("Content-Type", "application/json")
            sent.setdefault("Accept", "application/json, text/event-stream")
        conn.putrequest(method, "/mcp", skip_host=True)
        for name, value in sent.items():
            conn.putheader(name, value)
        if body is not None:
            conn.putheader("Content-Length", str(len(body)))
        conn.endheaders(body)
        response = conn.getresponse()
        status = response.status
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        data = response.read()
        conn.close()
        return status, response_headers, data

    def initialize(self) -> str:
        status, headers, body = self.request("POST", _rpc(1, "initialize", {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"}}))
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["result"]["protocolVersion"], "2025-11-25")
        return headers["mcp-session-id"]

    def test_lifecycle_tools_and_independent_sessions(self) -> None:
        first, second = self.initialize(), self.initialize()
        self.assertNotEqual(first, second)
        session_headers = {"Mcp-Session-Id": first, "Mcp-Protocol-Version": "2025-11-25"}
        status, _, body = self.request("POST", {"jsonrpc": "2.0", "method":
                                                 "notifications/initialized"},
                                       headers=session_headers)
        self.assertEqual((status, body), (202, b""))
        status, headers, body = self.request("POST", _rpc(2, "tools/list"), headers=session_headers)
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/json; charset=utf-8")
        self.assertIn("open_file", {tool["name"] for tool in json.loads(body)["result"]["tools"]})
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory) / "sample.elf"
            sample.write_bytes(b"\x7fELF" + b"\x00" * 60 + b"test string\x00")
            status, _, body = self.request("POST", _rpc(3, "tools/call", {
                "name": "open_file", "arguments": {"path": str(sample)}}), headers=session_headers)
            self.assertEqual(status, 200)
            handle = json.loads(body)["result"]["structuredContent"]["handle"]
            status, _, body = self.request("POST", _rpc(4, "tools/call", {
                "name": "export_result", "arguments": {"handle": handle}}), headers=session_headers)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)["result"]["structuredContent"]["kind"], "elf")
            self.request("POST", {"jsonrpc": "2.0", "method": "notifications/initialized"},
                         headers={"Mcp-Session-Id": second})
            status, _, body = self.request("POST", _rpc(5, "tools/call", {
                "name": "export_result", "arguments": {"handle": handle}}),
                                          headers={"Mcp-Session-Id": second})
            self.assertEqual(status, 200)
            self.assertTrue(json.loads(body)["result"]["isError"])
        status, _, body = self.request("DELETE", headers=session_headers)
        self.assertEqual((status, body), (204, b""))
        self.assertEqual(self.request("POST", _rpc(6, "tools/list"), headers=session_headers)[0], 404)

    def test_security_host_origin_version_and_token(self) -> None:
        payload = _rpc(1, "initialize", {"protocolVersion": "2025-11-25"})
        self.assertEqual(self.request("POST", payload, host=f"evil.example:{self.port}")[0], 403)
        self.assertEqual(self.request("POST", payload,
                                      headers={"Origin": "http://evil.example"})[0], 403)
        self.assertEqual(self.request("POST", payload,
                                      headers={"Origin": f"http://localhost:{self.port}"})[0], 200)
        session = self.initialize()
        self.assertEqual(self.request("POST", _rpc(2, "ping"),
                                      headers={"Mcp-Session-Id": session,
                                               "Mcp-Protocol-Version": "2099-01-01"})[0], 400)
        self.assertEqual(self.request("POST", _rpc(2, "ping"))[0], 400)
        self.assertEqual(self.request("POST", _rpc(2, "ping"),
                                      headers={"Mcp-Session-Id": "unknown"})[0], 404)

    def test_content_negotiation_errors_and_get(self) -> None:
        payload = _rpc(1, "initialize", {"protocolVersion": "2025-11-25"})
        self.assertEqual(self.request("POST", payload,
                                      headers={"Accept": "application/json"})[0], 406)
        self.assertEqual(self.request("POST", payload,
                                      headers={"Content-Type": "text/plain"})[0], 415)
        status, _, body = self.request("POST", b"{invalid")
        self.assertEqual((status, json.loads(body)["error"]["code"]), (400, -32700))
        self.assertEqual(self.request("POST", b"[]")[0], 400)
        self.assertEqual(self.request("GET", headers={"Accept": "text/event-stream"})[0], 405)
        self.assertEqual(self.request("GET", headers={"Accept": "application/json"})[0], 406)

    def test_bearer_requirement_and_session_limit(self) -> None:
        with self.assertRaisesRegex(ValueError, "bearer token"):
            McpHttpServer(("0.0.0.0", 0), allowed_hosts=["example.com"])
        with self.assertRaisesRegex(ValueError, "allowed_hosts"):
            McpHttpServer(("0.0.0.0", 0), bearer_token="secret")
        self.server.bearer_token = "secret"
        self.server.max_sessions = 1
        payload = _rpc(1, "initialize", {"protocolVersion": "2025-11-25"})
        self.assertEqual(self.request("POST", payload)[0], 401)
        headers = {"Authorization": "Bearer secret"}
        status, response_headers, _ = self.request("POST", payload, headers=headers)
        self.assertEqual(status, 200)
        self.assertEqual(self.request("POST", payload, headers=headers)[0], 503)
        self.assertEqual(self.request("DELETE", headers={**headers,
                          "Mcp-Session-Id": response_headers["mcp-session-id"]})[0], 204)
        self.assertEqual(self.request("POST", payload, headers=headers)[0], 200)


if __name__ == "__main__":
    unittest.main()
