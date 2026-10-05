"""Analyzer plugin contract, separate from loaders and instruction processors."""
from __future__ import annotations

from threading import Event
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Mapping, Protocol, runtime_checkable

if TYPE_CHECKING:
    from .pseudoc.models import PseudocodeResult

from ..models import AnalysisResult, AnalysisTask

PLUGIN_API_VERSION = (1, 0)
STORAGE_API_VERSION = (1, 0)
PSEUDOC_API_VERSION = (1, 0)
BRANCH_SOLVER_API_VERSION = (1, 0)
ProgressCallback = Callable[[dict[str, Any]], None]


@runtime_checkable
class BranchSolverPlugin(Protocol):
    """显式触发的快照求解插件；不扩充原分析器协议或默认流水线。"""
    name: str
    version: str

    def capabilities(self) -> tuple[str, ...]: ...
    def solve(self, snapshot: Mapping[str, Any], branch_address: int, *,
              source_path: str | Path | None = None, registers=None, memory=(),
              function_address: int | None = None, max_instructions: int = 512,
              max_paths: int = 32, timeout_ms: int = 200,
              cancel: Event | Callable[[], bool] | None = None,
              on_progress: ProgressCallback | None = None, include_details: bool = False) -> dict[str, Any]: ...
    def teardown(self) -> None: ...


@runtime_checkable
class PseudocodePlugin(Protocol):
    """Independent snapshot consumer; no loader, decoder or xref methods."""
    name: str
    version: str

    def capabilities(self) -> tuple[str, ...]: ...
    def generate(self, function: Mapping[str, Any], architecture: str, *,
                 max_instructions: int = 512,
                 max_chars: int = 32768) -> PseudocodeResult: ...
    def teardown(self) -> None: ...


@runtime_checkable
class Plugin(Protocol):
    name: str
    version: str

    def capabilities(self) -> tuple[str, ...]: ...
    def analyze(self, task: AnalysisTask) -> AnalysisResult: ...
    def teardown(self) -> None: ...


@runtime_checkable
class ControlledPlugin(Plugin, Protocol):
    """Optional progress/cancellation extension; original plugins remain valid."""

    def analyze_with_control(self, task: AnalysisTask,
                             on_progress: ProgressCallback | None = None,
                             cancel: Event | None = None) -> AnalysisResult: ...


@runtime_checkable
class StorageDatabase(Protocol):
    """Persist completed evidence; opening never dispatches an analyzer.

    The independent protocol preserves the analyzer plugin contract. Original
    binary bytes are not stored. Snapshot-based edits work without the source.
    """
    path: Path
    read_only: bool

    def save_analysis(self, source_path: str | Path,
                      result: AnalysisResult | Mapping[str, Any], *,
                      expected_hash: str | None = None) -> int: ...
    def get_snapshot(self, snapshot_id: int | None = None) -> dict[str, Any]: ...
    def info(self) -> dict[str, Any]: ...
    def history(self, source_path: str | Path | None = None, *,
                offset: int = 0, limit: int = 100) -> dict[str, Any]: ...
    def page(self, snapshot_id: int, collection: str, *,
             offset: int = 0, limit: int = 100) -> dict[str, Any]: ...
    def rename_symbol(self, snapshot_id: int, address: int, name: str) -> None: ...
    def set_comment(self, snapshot_id: int, address: int, text: str) -> None: ...
    def annotations(self, snapshot_id: int) -> dict[str, Any]: ...
    def close(self) -> None: ...


@runtime_checkable
class StoragePlugin(Protocol):
    """Separate persistence extension; does not require analyze(task)."""
    name: str
    version: str

    def capabilities(self) -> tuple[str, ...]: ...
    def open_database(self, path: str | Path, *, read_only: bool = False,
                      create: bool = False) -> StorageDatabase: ...
    def teardown(self) -> None: ...
