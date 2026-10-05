"""Bounds checks shared by independent executable container loaders."""
from __future__ import annotations

import struct
from typing import Any

from .models import BinaryFormatError

MAX_SECTIONS = 4096
MAX_SEGMENTS = 1024
MAX_SYMBOLS = 10000


def _unpack(data: bytes, offset: int, fmt: str) -> tuple[Any, ...]:
    size = struct.calcsize(fmt)
    if offset < 0 or size > len(data) - offset:
        raise BinaryFormatError(f"Truncated structure at file offset {offset:#x}")
    return struct.unpack_from(fmt, data, offset)


def _table(data: bytes, offset: int, stride: int, count: int, minimum: int, limit: int) -> bool:
    return (0 <= count <= limit and stride >= minimum and offset >= 0
            and (count == 0 or (offset <= len(data) and
                 (count - 1) * stride + minimum <= len(data) - offset)))


def _name(data: bytes, offset: int, length: int = 256) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    return data[offset:min(len(data), offset + length)].split(b"\0", 1)[0].decode("utf-8", "replace")


