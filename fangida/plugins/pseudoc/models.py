"""Results of bounded pseudo-C generation from completed instruction snapshots."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class PseudocodeResult:
    pseudoc: str = ""
    producer: str = ""
    truncated: bool = False
    warnings: tuple[str, ...] = ()
    microcode: tuple[dict[str, Any], ...] = ()
    machine_pseudoc: str = ""
    reconstruction: dict[str, Any] = field(default_factory=dict)


def validate_limits(max_instructions: int, max_chars: int) -> None:
    if type(max_instructions) is not int or not 1 <= max_instructions <= 8192:
        raise ValueError("max_instructions must be an integer in [1, 8192]")
    if type(max_chars) is not int or not 256 <= max_chars <= 131072:
        raise ValueError("max_chars must be an integer in [256, 131072]")
