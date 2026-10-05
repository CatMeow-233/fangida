"""MCP 协议版本、会话资源上限与 JSON-RPC 响应构造。"""
from __future__ import annotations

from typing import Any

PROTOCOL_VERSION = "2025-11-25"
SUPPORTED_VERSIONS = {"2024-11-05", "2025-03-26", "2025-06-18", PROTOCOL_VERSION}
MAX_MESSAGE_BYTES = 2 * 1024 * 1024
MAX_SCAN_BYTES = 64 * 1024 * 1024
MAX_OPEN_FILES = 8
MAX_OPEN_PROJECTS = 4
MAX_OPEN_DATABASES = 4
MAX_PAGE_SIZE = 200


def _response(request_id: str | int, value: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": value}


def _error(request_id: str | int | None, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
