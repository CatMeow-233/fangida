"""Snapshot-based API for trusted Fangida Python scripts.

Capability checks govern writes through this API. Executing Python is not a
security sandbox: a script may still use the operating system directly.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping, Protocol

from fangida import _json_stream
from fangida.models import AnalysisResult

_CAPABILITIES = frozenset({"rename", "comment", "export"})
_SYMBOL_RE = re.compile(r"^[A-Za-z_.$?@][A-Za-z0-9_.$?@]*$")


class ProjectStoreProtocol(Protocol):
    """The small part of :class:`fangida.project.ProjectStore` used here."""

    def load_analysis(self, source_path: str) -> dict[str, Any] | None: ...
    def rename_symbol(self, source_path: str, address: int, name: str) -> None: ...
    def set_comment(self, source_path: str, address: int, text: str) -> None: ...
    def annotations(self, source_path: str) -> dict[str, Any]: ...


@dataclass(frozen=True)
class ScriptCapabilities:
    """Write operations explicitly granted by the embedding application."""

    grants: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        grants = frozenset(self.grants)
        object.__setattr__(self, "grants", grants)
        unknown = grants - _CAPABILITIES
        if unknown:
            raise ValueError(f"unknown script capability: {', '.join(sorted(unknown))}")

    @classmethod
    def from_names(cls, names: Iterable[str]) -> ScriptCapabilities:
        return cls(frozenset(names))

    def require(self, name: str) -> None:
        if name not in self.grants:
            raise PermissionError(f"script capability '{name}' was not granted")


class ScriptContext:
    """A private analysis snapshot and an optional, capability-gated project.

    Reading any returned dictionary/list gives a deep copy. Mutating it never
    changes a persisted analysis or another caller's view. For store-backed
    contexts, rename and comment operations persist in the project's annotation
    layer and leave the underlying analysis snapshot intact.
    """

    def __init__(
        self,
        result: AnalysisResult | Mapping[str, Any],
        *,
        source_path: str | Path | None = None,
        store: ProjectStoreProtocol | None = None,
        capabilities: ScriptCapabilities | None = None,
        export_root: str | Path | None = None,
    ) -> None:
        payload = (vars(result) if type(result) is AnalysisResult and result.stats.get("full_analysis")
                   else result.to_dict() if isinstance(result, AnalysisResult) else dict(result))
        self._snapshot = deepcopy(payload)
        self._source_path = str(source_path) if source_path is not None else str(payload.get("path", ""))
        self._store = store
        self._capabilities = capabilities or ScriptCapabilities()
        self._export_root = Path(export_root).expanduser().resolve() if export_root is not None else None

    @classmethod
    def from_project(
        cls,
        store: ProjectStoreProtocol,
        source_path: str | Path,
        *,
        capabilities: ScriptCapabilities | None = None,
        export_root: str | Path | None = None,
    ) -> ScriptContext:
        key = str(source_path)
        snapshot = store.load_analysis(key)
        if snapshot is None:
            raise FileNotFoundError(f"no saved analysis for {key}")
        return cls(snapshot, source_path=key, store=store, capabilities=capabilities, export_root=export_root)

    def snapshot(self) -> dict[str, Any]:
        return deepcopy(self._snapshot)

    def functions(self) -> list[dict[str, Any]]:
        return deepcopy(self._snapshot.get("functions", []))

    def strings(self) -> list[dict[str, Any]]:
        return deepcopy(self._snapshot.get("strings", []))

    def imports(self) -> list[dict[str, Any]]:
        return deepcopy(self._snapshot.get("imports", []))

    def exports(self) -> list[dict[str, Any]]:
        return deepcopy(self._snapshot.get("exports", []))

    def xrefs(self, address: int | None = None, *, source: str | None = None,
              address_space: str | None = None) -> list[dict[str, Any]]:
        if address is not None:
            _address(address)
        def matches(ref):
            return any((address is None or ref.get(side) == address) and
                       (source is None or ref.get(side + "_source", ref.get("source")) == source) and
                       (address_space is None or ref.get(side + "_address_space", ref.get("address_space")) == address_space)
                       for side in ("src", "dst"))
        return deepcopy([ref for ref in self._snapshot.get("xrefs", []) if matches(ref)])

    def disassembly(self, start: int = 0, limit: int = 100) -> list[dict[str, Any]]:
        _address(start)
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        metadata = self._snapshot.get("metadata", {})
        direct = metadata.get("full_disassembly", metadata.get("disassembly", []))
        functions = self._snapshot.get("functions", [])
        instructions = direct or [ins for function in functions for ins in function.get("disassembly", [])]
        if not instructions:
            instructions = [ins for function in functions for block in function.get("blocks", [])
                            for ins in block.get("instructions", [])]
        return deepcopy([ins for ins in instructions if ins.get("addr", -1) >= start][:limit])

    def annotations(self) -> dict[str, Any]:
        if self._store is None:
            return {"renames": {}, "comments": {}}
        return deepcopy(self._store.annotations(self._source_path))

    def rename_symbol(self, address: int, name: str) -> None:
        self._capabilities.require("rename")
        _address(address)
        if not isinstance(name, str) or not _SYMBOL_RE.fullmatch(name) or len(name) > 256:
            raise ValueError("symbol name must be 1–256 characters and use identifier characters")
        self._required_store().rename_symbol(self._source_path, address, name)

    def set_comment(self, address: int, text: str) -> None:
        self._capabilities.require("comment")
        _address(address)
        if not isinstance(text, str) or not text.strip() or len(text) > 16_384:
            raise ValueError("comment must contain 1–16384 characters")
        self._required_store().set_comment(self._source_path, address, text)

    def export_json(self, destination: str | Path) -> Path:
        self._capabilities.require("export")
        if self._export_root is None:
            raise ValueError("export_root must be set to enable exports")
        target = Path(destination).expanduser()
        if not target.is_absolute():
            target = self._export_root / target
        target = target.resolve()
        if not target.is_relative_to(self._export_root) or target == self._export_root:
            raise PermissionError("export destination must be inside export_root")
        target.parent.mkdir(parents=True, exist_ok=True)
        # 与先完整序列化、再 write_text 写出的文件逐字节相同，但流式写出、不生成整串：先完整
        # 校验一遍再原地写入，序列化失败时仍不会创建或截断目标文件。
        # 3.11/3.12 的 C 编码器不支持 indent，由分块编码器生成逐字节相同的文本。
        _json_stream.write_text(target, self._snapshot, end="\n", encoding="utf-8",
                                indent=2, ensure_ascii=False)
        return target

    def _required_store(self) -> ProjectStoreProtocol:
        if self._store is None or not self._source_path:
            raise RuntimeError("persistent writes require a project store and source path")
        return self._store


def _address(value: int) -> None:
    if type(value) is not int or value < 0 or value >= 1 << 64:
        raise ValueError("address must be an unsigned 64-bit integer")


from .runner import ScriptExecutionError, ScriptOutputLimitExceeded, ScriptRun, ScriptTimeout, run_script

__all__ = [
    "ProjectStoreProtocol", "ScriptCapabilities", "ScriptContext", "ScriptExecutionError",
    "ScriptOutputLimitExceeded", "ScriptRun", "ScriptTimeout", "run_script",
]
