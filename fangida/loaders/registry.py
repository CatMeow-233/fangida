"""Register format probes and native container loaders independently of plugins."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import cast

from .interfaces import FormatProbe, Loader, LoaderMatch
from .models import BinaryFormatError, BinaryImage

PROBE_BYTES = 4096


@dataclass(frozen=True)
class _Registration:
    loader: FormatProbe
    priority: int
    extensions: Mapping[str, str]


class LoaderRegistry:
    def __init__(self) -> None:
        self._registrations: dict[str, _Registration] = {}
        self._lock = RLock()

    def register(self, loader: FormatProbe, *, priority: int = 0, replace: bool = False) -> None:
        if not isinstance(loader.name, str) or not loader.name or not callable(loader.probe):
            raise TypeError("A loader requires a name and a callable probe")
        if type(priority) is not int:
            raise TypeError("Loader priority must be an integer")
        extensions = dict(loader.extensions)
        if any(not isinstance(suffix, str) or not suffix.startswith(".") or
               not isinstance(kind, str) or not kind for suffix, kind in extensions.items()):
            raise TypeError("Loader extensions must map filename suffixes to format names")
        extensions = {suffix.lower(): kind for suffix, kind in extensions.items()}
        with self._lock:
            if loader.name in self._registrations and not replace:
                raise ValueError(f"Loader already registered: {loader.name}")
            self._registrations[loader.name] = _Registration(loader, priority, extensions)

    def unregister(self, name: str) -> None:
        with self._lock:
            del self._registrations[name]

    def get(self, name: str) -> FormatProbe:
        with self._lock:
            return self._registrations[name].loader

    def names(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._registrations)

    def _snapshot(self) -> tuple[_Registration, ...]:
        with self._lock:
            return tuple(self._registrations.values())

    def _match(self, data: bytes, path: str | Path | None = None, *,
               native_only: bool = False) -> tuple[FormatProbe, LoaderMatch] | None:
        winner = None
        best_rank = None
        for registration in self._snapshot():
            loader = registration.loader
            if native_only and not callable(getattr(loader, "load", None)):
                continue
            match = loader.probe(data, path)
            if match is None:
                continue
            if (not isinstance(match, LoaderMatch) or not match.kind or
                    type(match.score) is not int or not 0 <= match.score <= 100):
                raise TypeError(f"Loader {loader.name} returned an invalid format match")
            rank = (match.score, registration.priority)
            if best_rank is None or rank > best_rank:
                winner, best_rank = (loader, match), rank
        return winner

    def identify_bytes(self, data: bytes, path: str | Path | None = None) -> tuple[str, str]:
        winner = self._match(data, path)
        if winner is not None:
            return winner[1].kind, winner[1].evidence
        suffix = Path(path).suffix.lower() if path is not None else ""
        candidates = [item for item in self._snapshot() if suffix in item.extensions]
        if candidates:
            selected = max(candidates, key=lambda item: item.priority)
            return selected.extensions[suffix], "extension"
        return "unknown", "unknown"

    def identify_file(self, path: str | Path) -> tuple[str, str]:
        source = Path(path)
        with source.open("rb") as stream:
            data = stream.read(PROBE_BYTES)
        return self.identify_bytes(data, source)

    def load(self, data: bytes, kind: str = "unknown") -> BinaryImage:
        winner = self._match(data, native_only=True)
        if winner is None:
            raise BinaryFormatError(f"No supported native binary signature (identified as {kind})")
        return cast(Loader, winner[0]).load(data, kind)
