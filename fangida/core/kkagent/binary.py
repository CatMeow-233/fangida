"""Compatibility facade for the independent container loading modules.

Historical imports and helper call signatures remain available here. Container
implementations now live under fangida.loaders and contain no disassembly or
xref analysis.
"""
from __future__ import annotations

# Retain historically imported names as well as the documented binary API.
from dataclasses import dataclass, field
import struct
from typing import Any

from ...loaders import BinaryFormatError, BinaryImage, Section, load_binary
from ...loaders.common import MAX_SECTIONS, MAX_SEGMENTS, MAX_SYMBOLS, _name, _table, _unpack
from ...loaders.elf import _elf, _elf_symbols
from ...loaders.pe import _pe
from ...loaders.macho import _macho, _fat_macho


def parse_binary(data: bytes, kind: str) -> BinaryImage:
    """Parse native container metadata from the caller's bounded file prefix."""
    return load_binary(data, kind)
