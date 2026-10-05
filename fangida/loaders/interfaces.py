"""Format detection and container loading contracts; no instruction analysis."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from .models import BinaryImage


@dataclass(frozen=True)
class LoaderMatch:
    kind: str
    evidence: str = "magic"
    score: int = 100


@runtime_checkable
class FormatProbe(Protocol):
    name: str
    extensions: Mapping[str, str]

    def probe(self, data: bytes, path: str | Path | None = None) -> LoaderMatch | None: ...


@runtime_checkable
class Loader(FormatProbe, Protocol):
    """Load structural container metadata and explicitly declared symbols only."""

    def load(self, data: bytes, kind: str) -> BinaryImage: ...
