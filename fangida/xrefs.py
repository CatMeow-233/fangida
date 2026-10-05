"""Cross-reference analysis on completed instruction snapshots.

This module has no loader or instruction decoder dependency. With more than
one analysis thread, XrefStage owns a dedicated worker; one-thread callers
execute the same operations inline. A submitted snapshot belongs to the xref
stage until its future completes, so decoders never mutate it concurrently.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from bisect import bisect_right
from dataclasses import dataclass, field
from threading import BoundedSemaphore, local
from typing import Any, Callable, Iterable, TypeVar

from .models import Xref

T = TypeVar("T")


def mapped_data_ranges(sections: Iterable[dict[str, Any]], *, kind: str = "",
                       file_size: int | None = None) -> tuple[tuple[int, int], ...]:
    """Read validated, file-backed data ranges from completed loader declarations."""
    from .addresses import NativeAddressMap
    ranges = []
    for section in sections:
        if section.get("executable"):
            continue
        offset, address = section.get("offset"), section.get("address")
        size = section.get("file_size", section.get("size"))
        if any(type(value) is not int or value < 0 for value in (offset, address, size)):
            continue
        virtual_size = section.get("virtual_size")
        if type(virtual_size) is int and virtual_size > 0:
            size = min(size, virtual_size)
        if file_size is not None:
            size = min(size, max(0, file_size - offset))
        if not size:
            continue
        bounded = {**section, "file_size": size}
        mapping = NativeAddressMap((bounded,), kind=kind)
        if (address in mapping.addresses_for_offset(offset)
                and address + size - 1 in mapping.addresses_for_offset(offset + size - 1)):
            ranges.append((address, address + size))
    return tuple(sorted(ranges))


class DataRangeIndex:
    """Immutable membership index; its size depends on input maps, not instructions."""

    def __init__(self, ranges: Iterable[tuple[int, int]] = ()) -> None:
        merged: list[tuple[int, int]] = []
        for start, end in sorted(ranges):
            if type(start) is not int or type(end) is not int or not 0 <= start < end <= (1 << 64):
                continue
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
            else:
                merged.append((start, end))
        self.starts = tuple(start for start, _ in merged)
        self.ends = tuple(end for _, end in merged)

    def contains(self, address: int) -> bool:
        position = bisect_right(self.starts, address) - 1
        return position >= 0 and address < self.ends[position]


@dataclass
class ReferenceState:
    """Bounded ARM64 address state handed between completed xref batches.

    Only x0..x30 can be retained, never instruction records or growing history.
    The next address detects gaps, reordered windows and region boundaries.
    """

    registers: dict[str, int] = field(default_factory=dict)
    next_address: int | None = None

    def clear(self) -> None:
        self.registers.clear()
        self.next_address = None


def _arm64_register(name: Any) -> str | None:
    if (isinstance(name, str) and len(name) in {2, 3} and name[0] in {"x", "w"}
            and name[1:].isdigit() and 0 <= int(name[1:]) <= 30):
        return "x" + str(int(name[1:]))
    # Capstone uses ABI aliases for x29/x30 in register access lists.
    return {"fp": "x29", "lr": "x30"}.get(name) if isinstance(name, str) else None


def _data_targets(instruction: dict[str, Any], state: ReferenceState,
                  ranges: DataRangeIndex) -> Iterable[tuple[int, float, str | None]]:
    metadata = instruction.get("arch_meta") or {}
    emitted: set[int] = set()
    for target in metadata.get("memory_references", ()):
        if type(target) is int and target not in emitted:
            emitted.add(target)
            yield target, 1.0, None
    for target in metadata.get("address_candidates", ()):
        if type(target) is int and target not in emitted and ranges.contains(target):
            emitted.add(target)
            yield target, 0.8, "mapped_immediate"
    if metadata.get("architecture") != "arm64":
        state.clear()
        return
    address, size = instruction["addr"], instruction["size"]
    if address != state.next_address or metadata.get("address_state_clobber"):
        state.clear()
    state.next_address = address + size
    for base, displacement in metadata.get("memory_address_operations", ()):
        value = state.registers.get(_arm64_register(base))
        if value is not None:
            target = (value + displacement) & ((1 << 64) - 1)
            if target not in emitted:
                emitted.add(target)
                yield target, 1.0, None
    operation = metadata.get("address_operation") or {}
    destination = _arm64_register(operation.get("destination"))
    kind, value = operation.get("kind"), operation.get("value")
    resolved = None
    if destination is not None and type(value) is int:
        if kind in {"set", "page"}:
            resolved = value & ((1 << 64) - 1)
        elif kind == "add":
            base = state.registers.get(_arm64_register(operation.get("source")))
            if base is not None:
                resolved = (base + value) & ((1 << 64) - 1)
                if resolved not in emitted:
                    emitted.add(resolved)
                    yield resolved, 1.0, None
    # Evaluate source registers before applying writes (ADD x0,x0,#imm).
    for written in instruction.get("writes", ()):
        register = _arm64_register(written)
        if register is not None:
            state.registers.pop(register, None)
    if resolved is not None:
        state.registers[destination] = resolved
    if (instruction.get("branch_info") or {}).get("kind") in {"call", "jump", "return", "trap"}:
        state.clear()


def direct_references(instructions: Iterable[dict[str, Any]],
                      reached: set[int] | None = None, *, include_data: bool = False,
                      data_ranges: Iterable[tuple[int, int]] | DataRangeIndex = (),
                      state: ReferenceState | None = None,
                      reset_at: frozenset[int] = frozenset()) -> list[dict[str, Any]]:
    """Extract completed control-flow/address evidence without decoding.

    Data references are opt-in for legacy callers. Pointer-immediate candidates
    require a mapped data range; explicit memory/ADR address operands do not.
    """
    references: list[dict[str, Any]] = []
    if include_data:
        ranges = data_ranges if isinstance(data_ranges, DataRangeIndex) else DataRangeIndex(data_ranges)
        if state is None:
            state = ReferenceState()
    for instruction in instructions:
        if include_data and instruction["addr"] in reset_at:
            state.clear()
        if reached is not None and instruction["addr"] not in reached:
            if include_data:
                state.clear()
            continue
        branch = instruction.get("branch_info") or {}
        if branch.get("kind") in {"call", "jump"} and branch.get("target") is not None:
            if include_data:
                references.append({"src": instruction["addr"], "dst": branch["target"],
                                   "kind": "call" if branch["kind"] == "call" else "jmp", "confidence": 1.0})
            else:
                references.append(Xref(instruction["addr"], branch["target"],
                                       "call" if branch["kind"] == "call" else "jmp").to_dict())
        if include_data:
            metadata = instruction.get("arch_meta") or {}
            # 大多数 x86 指令没有地址证据：不分配去重集合/生成器，也不清空空状态。
            if (metadata.get("architecture") != "arm64" and not metadata.get("memory_references")
                    and not metadata.get("address_candidates")):
                if state.next_address is not None:
                    state.clear()
                continue
            for target, confidence, evidence in _data_targets(instruction, state, ranges):
                reference = {"src": instruction["addr"], "dst": target, "kind": "data", "confidence": confidence}
                if evidence is not None:
                    reference["evidence"] = evidence
                references.append(reference)
    return references


def function_references(instructions: Iterable[dict[str, Any]],
                        executable_ranges: tuple[tuple[int, int], ...], *,
                        include_data: bool = False,
                        data_ranges: Iterable[tuple[int, int]] | DataRangeIndex = ()
                        ) -> tuple[list[dict[str, Any]], set[int]]:
    """Return references and executable direct-call seeds from one snapshot."""
    if include_data:
        # CFG work queues need not visit fallthrough chains in address order.
        # Sorting only the readonly xref snapshot restores contiguous evidence;
        # preserve the legacy control-reference order for existing consumers.
        snapshot = tuple(instructions)
        references = [ref for ref in direct_references(snapshot) if isinstance(ref["dst"], int)]
        references.extend(ref for ref in direct_references(sorted(snapshot, key=lambda item: item["addr"]),
                          include_data=True, data_ranges=data_ranges,
                          reset_at=frozenset(start for start, _ in executable_ranges)) if ref["kind"] == "data")
    else:
        references = [ref for ref in direct_references(instructions) if isinstance(ref["dst"], int)]
    targets = {ref["dst"] for ref in references if ref["kind"] == "call"
               and any(start <= ref["dst"] < end for start, end in executable_ranges)}
    return references, targets


def merge_references(index: dict[tuple[int, int, str], dict[str, Any]],
                      references: Iterable[dict[str, Any]]) -> None:
    """Commit a completed batch once, preserving evidence insertion order."""
    for reference in references:
        index.setdefault((reference["src"], reference["dst"], reference["kind"]), reference)


def sorted_references(references: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(references, key=lambda ref: (ref["src"], ref["dst"], ref["kind"]))


def index_references(functions: list[dict[str, Any]],
                     references: Iterable[dict[str, Any]]) -> None:
    """Attach references after the coordinator hands over the function records."""
    # 只为引用源地址建立“指令 -> 函数”索引，避免为每条指令创建列表
    # （完整模式约 25 万个列表，会触发多次分代 GC）。结果与顺序不变。
    if not isinstance(references, (list, tuple)):
        references = list(references)
    sources = {reference["src"] for reference in references}
    by_start: dict[int, list[dict[str, Any]]] = {}
    by_instruction: dict[int, list[dict[str, Any]]] = {}
    for function in functions:
        by_start.setdefault(function["start"], []).append(function)
        for block in function.get("blocks", []):
            for instruction in block["instructions"]:
                address = instruction["addr"]
                if address in sources:
                    owners = by_instruction.get(address)
                    if owners is None:
                        by_instruction[address] = [function]
                    else:
                        owners.append(function)
    for reference in references:
        for target in by_start.get(reference["dst"], []):
            target.setdefault("xrefs_in", []).append(reference)
        for source in by_instruction.get(reference["src"], []):
            source.setdefault("xrefs_out", []).append(reference)


def index_entry_references(functions: list[dict[str, Any]],
                           entry_functions: list[dict[str, Any]],
                           references: Iterable[dict[str, Any]]) -> None:
    """Preserve the legacy entry-window indexing rules."""
    for reference in references:
        for function in functions:
            if (function.get("start") == reference["dst"] and
                    function.get("source") != "entry_window"):
                function.setdefault("xrefs_in", []).append(reference)
        for function in entry_functions:
            function.setdefault("xrefs_out", []).append(reference)


class XrefStage:
    """Bounded reference worker whose thread never executes instruction decoding."""

    def __init__(self, separate_thread: bool = False, max_pending: int = 2) -> None:
        if type(max_pending) is not int or max_pending < 1:
            raise ValueError("max_pending must be a positive integer")
        self.separate_thread = separate_thread
        self._executor = (ThreadPoolExecutor(max_workers=1, thread_name_prefix="fangida-xref")
                          if separate_thread else None)
        self._local = local()
        self._pending = BoundedSemaphore(max_pending)
        self._closed = False

    def run(self, function: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        if self._closed:
            raise RuntimeError("Xref stage is closed")
        # A stage helper may call another helper without submitting back to
        # its own one-worker executor and waiting on itself.
        if self._executor is None or getattr(self._local, "active", False):
            return function(*args, **kwargs)

        def invoke() -> T:
            self._local.active = True
            try:
                return function(*args, **kwargs)
            finally:
                self._local.active = False

        with self._pending:
            if self._closed:
                raise RuntimeError("Xref stage is closed")
            return self._executor.submit(invoke).result()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._executor is not None:
            self._executor.shutdown(wait=True, cancel_futures=True)

    def __enter__(self) -> XrefStage:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
