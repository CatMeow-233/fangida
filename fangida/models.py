"""JSON-compatible boundary objects. Schema version is independent of package version."""
from __future__ import annotations
from dataclasses import asdict, dataclass, field
from typing import Any

SCHEMA_VERSION = "1.0"

@dataclass(frozen=True)
class AnalysisTask:
    path: str
    kind: str
    max_bytes: int = 16 * 1024 * 1024
    worker_timeout_seconds: float = 30.0
    max_archive_entries: int = 10000
    max_archive_uncompressed_bytes: int = 256 * 1024 * 1024
    use_ghidra: bool = False
    ghidra_timeout_seconds: float = 120.0
    ghidra_max_cpu: int = 2
    ghidra_decompiled_functions: int = 16
    ghidra_decompile_seconds: int = 30
    deep_analysis: bool = True
    semantic_max_functions: int = 128
    semantic_max_instructions: int = 8192
    semantic_threads: int = 1
    parse_threads: int = 2
    # None keeps legacy direct-plugin calls deriving the mode from
    # semantic_threads. The service passes 0 only for a one-thread budget.
    xref_threads: int | None = None
    full_analysis: bool = False

@dataclass(frozen=True)
class Instruction:
    addr: int
    size: int
    mnemonic: str
    operands: tuple[str, ...] = ()
    reads: tuple[str, ...] = ()
    writes: tuple[str, ...] = ()
    branch_info: dict[str, Any] = field(default_factory=dict)
    arch_meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass(frozen=True)
class Xref:
    src: int
    dst: int
    kind: str
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass
class AnalysisResult:
    path: str
    kind: str
    analyzer: str
    status: str
    metadata: dict[str, Any] = field(default_factory=dict)
    functions: list[dict[str, Any]] = field(default_factory=list)
    strings: list[dict[str, Any]] = field(default_factory=list)
    imports: list[dict[str, Any]] = field(default_factory=list)
    exports: list[dict[str, Any]] = field(default_factory=list)
    xrefs: list[dict[str, Any]] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
