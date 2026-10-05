"""Independent, lazily constructed CPU processor registry.

Processors decode supplied byte windows. They neither choose executable
regions nor discover functions, build CFGs, or analyze cross references.
"""
from __future__ import annotations

from threading import RLock
from typing import Any, Callable, Protocol

from .decoder import NativeDecoder, UnavailableDecoder, branch_info, decode_objdump


class InstructionDecoder(Protocol):
    engine: str
    warning: str | None

    def decode_bytes(self, code: bytes, address: int, *, max_instructions: int = 128
                     ) -> tuple[list[dict[str, Any]], list[str]]: ...


ProcessorFactory = Callable[[str, str], InstructionDecoder]


class ProcessorRegistry:
    """Register CPU decoder factories without loading their optional engines."""

    def __init__(self) -> None:
        self._factories: dict[str, ProcessorFactory] = {}
        self._lock = RLock()

    def register(self, architecture: str, factory: ProcessorFactory, *, replace: bool = False) -> None:
        if not isinstance(architecture, str) or not architecture or not callable(factory):
            raise ValueError("architecture must be a non-empty string and factory must be callable")
        with self._lock:
            if architecture in self._factories and not replace:
                raise ValueError(f"Processor already registered: {architecture}")
            self._factories[architecture] = factory

    def create(self, architecture: str, endian: str = "little") -> InstructionDecoder:
        with self._lock:
            factory = self._factories.get(architecture)
        if factory is None:
            return UnavailableDecoder(architecture)
        return factory(architecture, endian)

    def names(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._factories))


_registry = ProcessorRegistry()
for _architecture in ("x86", "x86_64", "arm", "arm64"):
    _registry.register(_architecture, NativeDecoder)


def register_processor(architecture: str, factory: ProcessorFactory, *, replace: bool = False) -> None:
    _registry.register(architecture, factory, replace=replace)


def list_processors() -> tuple[str, ...]:
    return _registry.names()


def get_processor(architecture: str, endian: str = "little") -> InstructionDecoder:
    return _registry.create(architecture, endian)


def decode_bytes(code: bytes, address: int, architecture: str, endian: str = "little",
                 max_instructions: int = 128) -> tuple[list[dict[str, Any]], list[str]]:
    return get_processor(architecture, endian).decode_bytes(
        code, address, max_instructions=max_instructions)


__all__ = ["InstructionDecoder", "ProcessorFactory", "ProcessorRegistry", "register_processor",
           "list_processors", "get_processor", "decode_bytes", "branch_info", "decode_objdump"]
