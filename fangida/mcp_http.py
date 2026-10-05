"""Stateful MCP Streamable HTTP transport for Fangida.

Implements the request/response portion of the 2025-11-25 transport. Fangida
does not initiate server-to-client messages, so GET advertises no SSE stream.
The analysis tools and JSON-RPC lifecycle are shared with the stdio server.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
import re
import secrets
import ssl
import sys
from threading import Lock, RLock
from typing import Any, Iterable
from urllib.parse import urlsplit

from .mcp_server import MAX_MESSAGE_BYTES, McpServer, PROTOCOL_VERSION
from .settings import Settings

DEFAULT_PATH = "/mcp"
MAX_SESSIONS = 16


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _authority(value: str) -> tuple[str, int | None] | None:
    """Parse one Host authority without accepting credentials, paths or lists."""
    if not value or any(char.isspace() for char in value) or "," in value:
        return None
    try:
        parsed = urlsplit("http://" + value)
        host, port = parsed.hostname, parsed.port
    except ValueError:
        return None
    if (not host or parsed.username is not None or parsed.password is not None or
            parsed.path or parsed.query or parsed.fragment or
            not re.fullmatch(r"[A-Za-z0-9.:-]+", host)):
        return None
    return host.lower().rstrip("."), port


def _origin(value: str) -> tuple[str, str, int] | None:
    if not value or any(char.isspace() for char in value) or "," in value:
        return None
    try:
        parsed = urlsplit(value)
        host, port = parsed.hostname, parsed.port
    except ValueError:
        return None
    if (parsed.scheme not in ("http", "https") or not host or
            parsed.username is not None or parsed.password is not None or
            parsed.path or parsed.query or parsed.fragment or
            not re.fullmatch(r"[A-Za-z0-9.:-]+", host)):
        return None
    return parsed.scheme, host.lower().rstrip("."), port or (443 if parsed.scheme == "https" else 80)


@dataclass
class _Session:
    mcp: McpServer
    version: str
    lock: Lock = field(default_factory=Lock)


class McpHttpServer(ThreadingHTTPServer):
    """An HTTP listener whose randomly generated sessions own independent tool state.

    On a non-loopback bind an explicit allowed-host list and bearer token are
    mandatory. Put a TLS proxy in front or wrap the socket with TLS before
    exposing this listener outside a trusted network.
    """

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], *, allow_writes: bool = False,
                 settings: Settings | None = None, bearer_token: str | None = None,
                 allowed_hosts: Iterable[str] = (), allowed_origins: Iterable[str] = (),
                 path: str = DEFAULT_PATH, max_sessions: int = MAX_SESSIONS) -> None:
        host = address[0]
        self.local = _is_loopback(host)
        if not self.local and not bearer_token:
            raise ValueError("a bearer token is required for a non-loopback bind")
        explicit_hosts = {entry.lower().rstrip(".") for entry in allowed_hosts}
        if any(_authority(entry) != (entry, None) for entry in explicit_hosts):
            raise ValueError("allowed_hosts must contain plain DNS names or IP addresses")
        if not self.local and not explicit_hosts:
            raise ValueError("allowed_hosts is required for a non-loopback bind")
        if max_sessions < 1 or max_sessions > 1024:
            raise ValueError("max_sessions must be between 1 and 1024")
        if not path.startswith("/") or "?" in path or "#" in path:
            raise ValueError("path must be an absolute HTTP path")
        self.allowed_hosts = explicit_hosts | ({"127.0.0.1", "localhost"} if self.local else set())
        if self.local:
            self.allowed_hosts.add(host.lower().rstrip("."))
        self.allowed_origins_input = tuple(allowed_origins)
        self.allowed_origins: set[tuple[str, str, int]] = set()
        for value in self.allowed_origins_input:
            parsed = _origin(value)
            if parsed is None:
                raise ValueError(f"invalid allowed origin: {value!r}")
            self.allowed_origins.add(parsed)
        self.bearer_token = bearer_token
        self.allow_writes = allow_writes
        self.settings = settings
        self.path = path
        self.max_sessions = max_sessions
        self.sessions: dict[str, _Session] = {}
        self.sessions_lock = RLock()
        super().__init__(address, _McpHandler)
        if self.local:
            port = self.server_address[1]
            self.allowed_origins.update({("http", hostname, port)
                                         for hostname in self.allowed_hosts})

    def server_close(self) -> None:
        with self.sessions_lock:
            sessions = list(self.sessions.values())
            self.sessions.clear()
        for session in sessions:
            with session.lock:
                session.mcp.close()
        super().server_close()


class _McpHandler(BaseHTTPRequestHandler):
    server: McpHttpServer
    protocol_version = "HTTP/1.1"

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(30)

    def log_message(self, format: str, *args: Any) -> None:
        print("fangida-mcp-http: " + format % args, file=sys.stderr)

    def _send(self, status: int, body: dict[str, Any] | None = None,
              *, session_id: str | None = None) -> None:
        raw = (json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
               if body is not None else b"")
        self.send_response(status)
        if body is not None:
            self.send_header("Content-Type", "application/json; charset=utf-8")
        if session_id is not None:
            self.send_header("Mcp-Session-Id", session_id)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        if raw:
            self.wfile.write(raw)

    def _reject(self, status: int, message: str) -> None:
        # A rejection may occur before the POST body is consumed. Do not parse
        # the remaining bytes as another request on this keep-alive connection.
        self.close_connection = True
        self._send(status, {"jsonrpc": "2.0", "id": None,
                            "error": {"code": -32600, "message": message}})

    def _guard(self) -> bool:
        if self.path != self.server.path:
            self._reject(404, "Unknown endpoint")
            return False
        hosts = self.headers.get_all("Host", [])
        authority = _authority(hosts[0]) if len(hosts) == 1 else None
        if (authority is None or authority[0] not in self.server.allowed_hosts or
                (authority[1] or 80) != self.server.server_address[1]):
            self._reject(403, "Invalid Host")
            return False
        origins = self.headers.get_all("Origin", [])
        if origins and (len(origins) != 1 or _origin(origins[0]) not in self.server.allowed_origins):
            self._reject(403, "Invalid Origin")
            return False
        token = self.server.bearer_token
        if token is not None:
            auth = self.headers.get_all("Authorization", [])
            supplied = auth[0] if len(auth) == 1 else ""
            if (not supplied.startswith("Bearer ") or
                    not hmac.compare_digest(supplied[7:], token)):
                self._reject(401, "Bearer authentication required")
                return False
        return True

    @staticmethod
    def _accepts(header: str, media_type: str) -> bool:
        return any(part.split(";", 1)[0].strip().lower() == media_type
                   and not re.search(r"(?:^|;)\s*q\s*=\s*0(?:\.0*)?\s*(?:;|$)", part, re.I)
                   for part in header.split(","))

    def _session(self) -> tuple[str, _Session] | None:
        tokens = self.headers.get_all("Mcp-Session-Id", [])
        if len(tokens) != 1 or not tokens[0]:
            self._reject(400, "Mcp-Session-Id is required")
            return None
        session_id = tokens[0]
        with self.server.sessions_lock:
            session = self.server.sessions.get(session_id)
        if session is None:
            self._reject(404, "Unknown MCP session")
            return None
        versions = self.headers.get_all("Mcp-Protocol-Version", [])
        if len(versions) > 1 or (versions and versions[0] != session.version):
            self._reject(400, "Invalid MCP protocol version")
            return None
        return session_id, session

    def do_POST(self) -> None:
        if not self._guard():
            return
        accept = self.headers.get("Accept", "")
        if not (self._accepts(accept, "application/json") and
                self._accepts(accept, "text/event-stream")):
            self._reject(406, "Accept must include application/json and text/event-stream")
            return
        content_type = self.headers.get("Content-Type", "").lower().split(";", 1)[0].strip()
        if content_type != "application/json":
            self._reject(415, "Content-Type must be application/json")
            return
        if self.headers.get("Transfer-Encoding") is not None:
            self.close_connection = True
            self._reject(400, "Transfer-Encoding is unsupported")
            return
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or not lengths[0].isdigit():
            self.close_connection = True
            self._reject(411, "Content-Length is required")
            return
        size = int(lengths[0])
        if size < 1 or size > MAX_MESSAGE_BYTES:
            self.close_connection = True
            self._reject(413, "MCP message is empty or too large")
            return
        try:
            message = json.loads(self.rfile.read(size).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send(400, {"jsonrpc": "2.0", "id": None,
                             "error": {"code": -32700, "message": "Parse error"}})
            return
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
            self._reject(400, "Expected one JSON-RPC request or notification")
            return
        is_init = message["method"] == "initialize" and "id" in message
        if is_init:
            if self.headers.get("Mcp-Session-Id") is not None:
                self._reject(400, "Initialize without an MCP session ID")
                return
            with self.server.sessions_lock:
                if len(self.server.sessions) >= self.server.max_sessions:
                    self._reject(503, "MCP session limit reached")
                    return
                mcp: McpServer | None = None
                try:
                    mcp = McpServer(allow_writes=self.server.allow_writes,
                                    settings=self.server.settings)
                    params = message.get("params")
                    if isinstance(params, dict) and params.get("protocolVersion") == "2024-11-05":
                        # That release used the older two-endpoint HTTP+SSE
                        # transport. Negotiate a Streamable HTTP version here.
                        message = {**message, "params": {**message["params"],
                                                         "protocolVersion": PROTOCOL_VERSION}}
                    response = mcp.handle(message)
                except Exception:
                    if mcp is not None:
                        mcp.close()
                    self._reject(500, "Internal error")
                    return
                if response is None or "error" in response:
                    mcp.close()
                    self._send(400, response)
                    return
                session_id = secrets.token_urlsafe(32)
                version = response["result"]["protocolVersion"]
                self.server.sessions[session_id] = _Session(mcp, version)
            self._send(200, response, session_id=session_id)
            return
        resolved = self._session()
        if resolved is None:
            return
        session_id, session = resolved
        if message["method"] == "initialize":
            self._reject(400, "Initialize requires a new session")
            return
        with session.lock:
            with self.server.sessions_lock:
                if self.server.sessions.get(session_id) is not session:
                    self._reject(404, "Unknown MCP session")
                    return
            try:
                response = session.mcp.handle(message)
            except Exception:
                self._reject(500, "Internal error")
                return
        if response is None:
            self._send(202)
        else:
            self._send(200, response, session_id=session_id)

    def do_GET(self) -> None:
        if not self._guard():
            return
        if not self._accepts(self.headers.get("Accept", ""), "text/event-stream"):
            self._reject(406, "Accept must include text/event-stream")
            return
        self.send_response(405)
        self.send_header("Allow", "POST, DELETE")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_DELETE(self) -> None:
        if not self._guard():
            return
        resolved = self._session()
        if resolved is None:
            return
        session_id, session = resolved
        with self.server.sessions_lock:
            if self.server.sessions.pop(session_id, None) is None:
                self._reject(404, "Unknown MCP session")
                return
        with session.lock:
            session.mcp.close()
        self._send(204)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fangida-mcp-http")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--allowed-host", action="append", default=[],
                        help="DNS name accepted by Host validation; required for nonlocal bind")
    parser.add_argument("--allowed-origin", action="append", default=[],
                        help="Exact browser Origin, including scheme and port")
    parser.add_argument("--token-env", default="FANGIDA_MCP_HTTP_TOKEN",
                        help="Environment variable containing a bearer token")
    parser.add_argument("--cert-file", help="TLS certificate for a nonlocal bind")
    parser.add_argument("--key-file", help="TLS private key for a nonlocal bind")
    parser.add_argument("--allow-writes", action="store_true",
                        help="Allow session-only symbol renames")
    args = parser.parse_args(argv)
    if not _is_loopback(args.host) and not (args.cert_file and args.key_file):
        parser.error("a non-loopback bind requires --cert-file and --key-file")
    if bool(args.cert_file) != bool(args.key_file):
        parser.error("--cert-file and --key-file must be provided together")
    try:
        server = McpHttpServer((args.host, args.port), allow_writes=args.allow_writes,
                               allowed_hosts=args.allowed_host, allowed_origins=args.allowed_origin,
                               bearer_token=os.environ.get(args.token_env))
        if args.cert_file:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(args.cert_file, args.key_file)
            server.socket = context.wrap_socket(server.socket, server_side=True)
    except (OSError, ValueError, ssl.SSLError) as exc:
        parser.error(str(exc))
    scheme = "https" if args.cert_file else "http"
    print(f"Fangida MCP listening on {scheme}://{args.host}:{server.server_address[1]}/mcp",
          file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
