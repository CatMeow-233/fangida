"""Shared container metadata, independent of processors and analysis plugins."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

Section = dict[str, Any]


@dataclass
class BinaryImage:
    format: str
    architecture: str
    bits: int
    endian: str
    entry_address: int | None = None
    entry_offset: int | None = None
    image_base: int | None = None
    fat_slice_offset: int | None = None
    sections: list[dict[str, Any]] = field(default_factory=list)
    functions: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    dynamic_relocations: list[dict[str, Any]] = field(default_factory=list)

    def metadata(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "architecture": self.architecture,
            "bits": self.bits,
            "endian": self.endian,
            "entry_address": self.entry_address,
            "entry_offset": self.entry_offset,
            "image_base": self.image_base,
            "fat_slice_offset": self.fat_slice_offset,
            "sections": self.sections,
            "dynamic_relocations": self.dynamic_relocations,
        }


class BinaryFormatError(ValueError):
    """A container header is missing or internally inconsistent."""
