"""Public registry and interfaces for independent container loading modules."""
from __future__ import annotations

from pathlib import Path

from .elf import ELFLoader, ElfLoader
from .interfaces import FormatProbe, Loader, LoaderMatch
from .jvm import JvmContainerProbe
from .macho import MachOLoader
from .models import BinaryFormatError, BinaryImage, Section
from .pe import PELoader
from .registry import LoaderRegistry, PROBE_BYTES


def default_registry() -> LoaderRegistry:
    registry = LoaderRegistry()
    # Structural Mach-O probing precedes JVM's shared CAFEBABE signature.
    for loader in (ELFLoader(), PELoader(), MachOLoader(), JvmContainerProbe()):
        registry.register(loader)
    return registry


DEFAULT_LOADERS = default_registry()


def identify_bytes(data: bytes, path: str | Path | None = None) -> tuple[str, str]:
    return DEFAULT_LOADERS.identify_bytes(data, path)


def identify_file(path: str | Path) -> tuple[str, str]:
    return DEFAULT_LOADERS.identify_file(path)


def load_binary(data: bytes, kind: str = "unknown") -> BinaryImage:
    return DEFAULT_LOADERS.load(data, kind)


__all__ = [
    "BinaryFormatError", "BinaryImage", "Section", "FormatProbe", "Loader", "LoaderMatch",
    "LoaderRegistry", "ELFLoader", "ElfLoader", "PELoader", "MachOLoader", "JvmContainerProbe",
    "PROBE_BYTES", "DEFAULT_LOADERS", "default_registry", "identify_bytes", "identify_file", "load_binary",
]
