"""换行分隔 JSON-RPC 的 stdio 传输与 fangida-mcp 命令行入口。

McpServer、serve 与消息上限在调用时经门面查找，因此对 fangida.mcp_server 上这些
名字的补丁照旧生效；sys 是共享模块对象，补丁 sys.stdin/stdout 对此处同样可见。
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import BinaryIO

from . import _facade


def serve(input_stream: BinaryIO, output_stream: BinaryIO, *, allow_writes: bool = False,
          own_completed_results: bool = False) -> None:
    """Serve a stdio connection using newline-delimited UTF-8 JSON-RPC."""
    m = _facade()
    server = m.McpServer(allow_writes=allow_writes, own_completed_results=own_completed_results)
    try:
        while raw := input_stream.readline(m.MAX_MESSAGE_BYTES + 1):
            if len(raw) > m.MAX_MESSAGE_BYTES:
                while raw and not raw.endswith(b"\n"):
                    raw = input_stream.readline(m.MAX_MESSAGE_BYTES + 1)
                response = m._error(None, -32700, "Message too large")
            else:
                try:
                    response = server.handle(json.loads(raw.decode("utf-8")))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    response = m._error(None, -32700, "Parse error")
                except Exception as exc:
                    print(f"MCP handler failed: {type(exc).__name__}: {exc}", file=sys.stderr)
                    response = m._error(None, -32603, "Internal error")
            if response is not None:
                output_stream.write((json.dumps(response, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8"))
                output_stream.flush()
    finally:
        server.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fangida-mcp")
    parser.add_argument("--allow-writes", action="store_true",
                        help="Allow session renames and persistent project changes; never writes to the binary")
    parser.add_argument("--own-completed-results", action="store_true",
                        help="Transfer completed native full results from this private stdio service without copying IR")
    args = parser.parse_args(argv)
    try:
        _facade().serve(sys.stdin.buffer, sys.stdout.buffer, allow_writes=args.allow_writes,
                        own_completed_results=args.own_completed_results)
    except BrokenPipeError:
        return 0
    return 0
