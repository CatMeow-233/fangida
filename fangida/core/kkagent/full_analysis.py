"""Opt-in complete code-region sweep, evidence-based roots and CFGs.

Container declarations come from loaders, instructions from processors and
references from the independent xref stage. Complete byte coverage does not
prove complete function recovery or resolve every indirect branch.
"""
from __future__ import annotations

from bisect import bisect_right
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from threading import Event, Lock, get_ident
from time import perf_counter
from typing import Any, Callable

from ...loaders.models import BinaryImage
from ...processors.full_decode import stream_decode_regions
from ...xrefs import (XrefStage, index_references, direct_references, mapped_data_ranges,
                     DataRangeIndex, ReferenceState)
from .noreturn import import_noreturn, local_noreturn, named_targets
from .semantic import MAX_WORKERS, _Region, _analyze_function


class _CachedDecoder:
    """Read-only completed decode with logarithmic overlap checks."""

    def __init__(self, cache: dict[int, dict[str, Any]], addresses: list[int],
                 regions: list[_Region], start: int, end: int | None,
                 engine: str) -> None:
        self.cache, self.addresses, self.regions = cache, addresses, regions
        self.start, self.end, self.engine = start, end, engine
        self.windows = 0
        # 区间互不重叠时，“列表中第一个包含该地址的区域”就是唯一包含它的区域，
        # 可用二分查找；存在重叠时保留原线性扫描语义。
        ordered = sorted(regions, key=lambda item: item.address)
        disjoint = all(left.address + left.size <= right.address
                       for left, right in zip(ordered, ordered[1:]))
        self._ordered = ordered if disjoint else None
        self._starts = [item.address for item in ordered]
        self._ends = [item.address + item.size for item in ordered]

    def region(self, address: int) -> _Region | None:
        ordered = self._ordered
        if ordered is None:
            return next((item for item in self.regions if item.contains(address)), None)
        try:
            pos = bisect_right(self._starts, address) - 1
        except TypeError:
            # 非契约类型的地址：回退原线性扫描，保持原异常与结果。
            return next((item for item in self.regions if item.contains(address)), None)
        if pos >= 0 and address < self._ends[pos]:
            return ordered[pos]
        return None

    def decode(self, address: int, limit: int | None = None):
        if address < self.start or (self.end is not None and address >= self.end):
            return None, "outside_function_range"
        instruction = self.cache.get(address)
        if instruction is not None:
            if limit is not None and address + instruction["size"] > limit:
                return None, "symbol_end"
            return instruction, None
        pos = bisect_right(self.addresses, address) - 1
        if pos >= 0:
            previous = self.cache[self.addresses[pos]]
            if address < previous["addr"] + previous["size"]:
                return None, "overlapping_decode"
        return None, "undecoded" if self.region(address) else "outside_executable"


def _references(snapshot: tuple[dict[str, Any], ...], *,
                state: ReferenceState | None = None,
                data_ranges: DataRangeIndex | tuple[tuple[int, int], ...] = (),
                reset_at: frozenset[int] = frozenset()) -> list[dict[str, Any]]:
    """Consume only completed processor metadata; never invoke a decoder."""
    return [reference for reference in direct_references(snapshot, include_data=True,
            state=state, data_ranges=data_ranges, reset_at=reset_at) if isinstance(reference["dst"], int)]


def _resync_anchors(image: BinaryImage) -> list[int]:
    """线性扫描的重同步锚点：Loader 声明的函数起点（符号表、LC_FUNCTION_STARTS 等）与入口点。

    只把地址交给处理器层；扫描不会让一条指令跨越这些地址，从而前一个函数以不返回
    调用结尾、其后是填充字节时，下一个函数的入口仍是指令边界。
    """
    starts = [item.get("start") for item in image.functions]
    starts.append(image.entry_address)
    return sorted({address for address in starts if type(address) is int})


def _roots(data: bytes, image: BinaryImage, cache: dict[int, dict[str, Any]],
           references: list[dict[str, Any]], coverage: list[dict[str, Any]]
           ) -> tuple[list[dict[str, Any]], list[str]]:
    declarations = [dict(item) for item in image.functions]
    warnings: list[str] = []
    if image.format == "elf":
        from ...loaders.elf import recover_function_ranges
        recovered, extra = recover_function_ranges(data, image)
        declarations.extend(recovered)
        warnings.extend(extra)
    elif image.format == "macho":
        # 容器声明的函数起点（LC_FUNCTION_STARTS）与构造/析构指针（__mod_init/term_func、
        # __init_offsets）。只消费已是解码边界的起点：实测被跳过的起点本身是真函数，但前面
        # 内联跳转表数据的末尾字节与函数首字节被线性扫描拼成一条跨越该起点的指令（例如表项
        # 末字节 ff 与 push rbp; mov rbp,rsp 的 55 48 被解成 call [rbp+0x48]），在当前解码下
        # 无法建图，纳入只会产生 not_decoded 噪声；把它们
        # 对齐成边界属于处理器层的重同步锚点职责，不在本发现流程内。
        from ...loaders.macho import recover_function_ranges
        recovered, extra = recover_function_ranges(data)
        declarations.extend(item for item in recovered if item.get("start") in cache)
        warnings.extend(extra)
    elif image.format == "pe":
        # 容器声明的函数起点（.pdata RUNTIME_FUNCTION、导出表）；基址重定位写入的代码
        # 指针（source="data_pointer"）证据较弱，留给首轮 CFG 之后的第二轮按完整规则裁决。
        # 同样只消费已是解码边界的声明起点（见 macho 分支说明）。
        from ...loaders.pe import recover_function_ranges
        recovered, extra = recover_function_ranges(data, image)
        declarations.extend(item for item in recovered
                            if item.get("source") != "data_pointer" and item.get("start") in cache)
        warnings.extend(extra)
    if isinstance(image.entry_address, int):
        declarations.append({"name": f"entry_{image.entry_address:x}",
                             "start": image.entry_address, "size": None,
                             "source": "entry", "boundary_known": False})
    seeds: dict[int, dict[str, Any]] = {}
    for declaration in declarations:
        start = declaration.get("start")
        if not isinstance(start, int):
            continue
        if start not in seeds:
            seeds[start] = declaration
        else:
            old = seeds[start]
            sources = set(old.get("sources", ())) | set(declaration.get("sources", ()))
            sources.update(filter(None, (old.get("source"), declaration.get("source"))))
            old["sources"] = sorted(sources)
            if not old.get("size") and declaration.get("size"):
                old.update(size=declaration["size"], boundary_known=True,
                           boundary_scope=declaration.get("boundary_scope", "declared_range"))
    # Use declaration intervals to avoid inventing a function for calls into
    # the interior of a declared unwind/symbol range. Overlaps use prefix max.
    intervals: list[tuple[int, int]] = []
    for start, seed in seeds.items():
        if start not in cache:
            warnings.append(f"Declared function start {start:#x} is outside decoded instruction boundaries")
            continue
        size = seed.get("size")
        if not isinstance(size, int) or size <= 0:
            continue
        region = next((item for item in coverage
                       if item["address"] <= start < item["address"] + item["size"]), None)
        if region is None or start + size > region["address"] + region["size"]:
            warnings.append(f"Declared function range {start:#x}+{size:#x} exceeds its executable region")
            seed.update(declared_size=size, size=None, boundary_known=False)
            continue
        intervals.append((start, start + size))
    intervals.sort()
    interval_starts = [start for start, _ in intervals]
    maximum = 0
    interval_ends: list[int] = []
    for _, end in intervals:
        maximum = max(maximum, end)
        interval_ends.append(maximum)
    for target in sorted({ref["dst"] for ref in references if ref["kind"] == "call"}):
        if target not in cache or target in seeds:
            continue
        pos = bisect_right(interval_starts, target) - 1
        if pos >= 0 and target < interval_ends[pos]:
            continue
        seeds[target] = {"name": f"sub_{target:x}", "start": target, "size": None,
                         "source": "direct_call", "boundary_known": False}
    # Region starts provide CFG coverage for otherwise unseeded executable
    # areas; they are explicitly named as regions, not proven functions.
    for region in coverage:
        start = region["address"]
        if start in cache and start not in seeds:
            pos = bisect_right(interval_starts, start) - 1
            if pos < 0 or start >= interval_ends[pos]:
                seeds[start] = {"name": f"region_{start:x}", "start": start,
                                "size": None, "source": "executable_region",
                                "boundary_known": False}
    return [seeds[start] for start in sorted(seeds)], warnings


def _pointer_candidates(data: bytes, image: BinaryImage
                        ) -> tuple[list[dict[str, Any]], list[str]]:
    """消费 Loader 给出的、指向代码的数据指针候选（证据较弱，留给第二轮裁决）。

    只读取容器结构化结果（重定位写入的代码指针），不解码指令、不恢复 CFG。每个候选
    带 ``start``、``source``（"data_pointer"）与可审计 ``evidence``（指针所在地址、重定位
    类型）。ELF 来自 RELATIVE/ABS/GLOB_DAT；PE 来自基址重定位（DIR64/HIGHLOW），逐槽位
    给出（同一目标可出现在多个槽位），供第二轮按相邻槽位组成的指针表做表级裁决。
    """
    candidates: list[dict[str, Any]] = []
    warnings: list[str] = []
    if image.format == "elf":
        from ...loaders.elf import recover_code_pointers
        found, extra = recover_code_pointers(data, image)
        for item in found:
            candidate = {"start": item["target"], "source": item["source"],
                         "evidence": item.get("evidence", {})}
            if "isa_mode" in item:
                candidate["isa_mode"] = item["isa_mode"]
            candidates.append(candidate)
        warnings.extend(extra)
    elif image.format == "pe":
        # PE 的声明起点（pdata/export）已在 _roots 消费；这里逐槽位取基址重定位指针候选，
        # 其告警已由 _roots 的 pe 分支一并上报，避免重复。
        from ...loaders.pe import recover_code_pointers
        found, _extra = recover_code_pointers(data, image)
        candidates.extend({"start": item["target"], "source": item["source"],
                           "evidence": item.get("evidence", {})} for item in found)
    return candidates, warnings


def _starts_cleanly(cache: dict[int, dict[str, Any]], addresses: list[int],
                    target: int, noreturn_targets: dict[int, dict[str, Any]]) -> bool:
    """前一条已解码指令是否不会顺序落空进入 ``target``。

    成立条件：与前一条指令之间有空隙（填充/数据），或前一条是无条件跳转/返回/陷阱/
    对不返回目标的无条件调用/对齐 nop。用于挡住落在直线代码中部的指针（如 switch 分支）。
    """
    position = bisect_right(addresses, target) - 1
    if position <= 0:
        return True  # 没有更靠前的指令
    previous = addresses[position - 1] if addresses[position] == target else addresses[position]
    instruction = cache[previous]
    if previous + instruction["size"] != target:
        return True
    branch = instruction.get("branch_info") or {}
    kind = branch.get("kind")
    conditional = bool(branch.get("conditional"))
    if kind in {"return", "trap"}:
        return True
    if kind == "jump" and not conditional:
        return True
    if kind == "call" and not conditional and branch.get("target") in noreturn_targets:
        return True
    mnemonic = instruction.get("mnemonic", "")
    return mnemonic == "nop" or mnemonic.startswith("nop")


# 数据指针表的拒绝原因，按优先次序排列：同一张表命中多个原因时，整表记为最靠前的那个。
# 逐项原因描述单个目标本身的反证；表级原因描述表的形状（重复目标、多个新目标落在同一
# 已知函数区间、没有任何已知函数项）。
_POINTER_ITEM_REASONS = ("slot_in_code", "not_boundary", "padding_or_trap", "inside_declared",
                         "claimed", "fallthrough", "indirect_jump_interval")
_POINTER_TABLE_REASONS = ("duplicate_target", "shared_interval", "no_known_function")
MAX_UNCONFIRMED_POINTERS = 256


def _pointer_tables(candidates: list[dict[str, Any]], pointer_size: int
                    ) -> list[list[dict[str, Any]]]:
    """把候选按槽位地址分组为“指针表”：相邻槽位间距不超过一个指针宽度即属同一张表。

    同一槽位、同一目标的重复候选只保留一份；缺少槽位地址的候选各自成表。只读证据，
    不解码、不解引用任何地址。
    """
    slotted: dict[tuple[int, int], dict[str, Any]] = {}
    tables: list[list[dict[str, Any]]] = []
    for item in candidates:
        place = (item.get("evidence") or {}).get("pointer_address")
        if type(place) is int:
            slotted.setdefault((place, item["start"]), item)
        else:
            tables.append([item])
    previous: int | None = None
    for place, target in sorted(slotted):
        if previous is None or place - previous > pointer_size:
            tables.append([])
        tables[-1].append(slotted[(place, target)])
        previous = place
    return tables


def _accept_pointer_candidates(candidates: list[dict[str, Any]],
                               cache: dict[int, dict[str, Any]], addresses: list[int],
                               seed_starts: set[int], sized_seeds: list[dict[str, Any]],
                               reached: set[int], region_starts: frozenset[int],
                               noreturn_targets: dict[int, dict[str, Any]], *,
                               functions: list[dict[str, Any]] | None = None,
                               pointer_size: int | None = None,
                               executable: list[tuple[int, int]] | None = None,
                               code_bytes: Callable[[int, int], bytes | None] | None = None,
                               details: dict[str, Any] | None = None
                               ) -> tuple[list[dict[str, Any]], Counter]:
    """按表级证据规则裁决数据指针候选；返回接受的种子与逐项拒绝计数。

    重定位支撑的代码指针既可能是函数指针表/虚表，也可能是 switch 跳转表、混淆分支表或
    指令操作数。宁缺毋滥：先把相邻槽位归为一张指针表，表中任何一项有反证就整表拒绝——
    槽位本身在可执行区域内（内联表或指令操作数）、目标不是解码边界、目标是填充或陷阱、
    目标在已声明区间内部、已被首轮 CFG 认领、前一条指令会顺序落空进入它、或目标所在
    “已知函数起点到下一个已知起点”区间的起点函数带 indirect_jump 前沿。只有表中各新
    目标互不重复、各自落在不同的已知函数区间，且表中至少一项已是已知函数起点（或表
    处于容器声明的函数指针结构中，例如 .init_array）时，才接受其中的新目标；被任何
    其它表以反证拒绝过的目标也不接受。不求解、不输出任何跳转目标。

    只消费已完成的解码快照、已声明区间与首轮 CFG（``functions`` 的前沿），不解码、不新建
    引用。新增的关键字参数均可省略：``pointer_size`` 缺省按 8 字节分组；省略 ``executable``/
    ``code_bytes``/``functions`` 时不做对应检查。``details`` 若给出则就地填入表级审计信息。
    """
    intervals = sorted((seed["start"], seed["start"] + seed["size"]) for seed in sized_seeds
                       if isinstance(seed.get("size"), int) and seed["size"] > 0)
    interval_starts = [start for start, _ in intervals]
    interval_ends: list[int] = []
    maximum = 0
    for _, end in intervals:
        maximum = max(maximum, end)
        interval_ends.append(maximum)
    known = sorted(start for start in seed_starts if type(start) is int)
    indirect = {fn["start"] for fn in functions or ()
                if any(item.get("reason") == "indirect_jump"
                       for item in (fn.get("cfg") or {}).get("frontier", ()))}
    spans = sorted(executable or ())
    span_starts = [start for start, _ in spans]

    def in_code(address: Any) -> bool:
        if type(address) is not int:
            return False
        position = bisect_right(span_starts, address) - 1
        return position >= 0 and address < spans[position][1]

    def owner(target: int) -> int | None:
        # 目标所在的“已知函数起点到下一个已知起点”区间，以区间起点标识。
        position = bisect_right(known, target) - 1
        return known[position] if position >= 0 else None

    def item_reason(item: dict[str, Any]) -> str | None:
        target = item["start"]
        if in_code((item.get("evidence") or {}).get("pointer_address")):
            return "slot_in_code"
        if target in seed_starts:
            return None  # 已知函数起点：作为锚点，不产生新函数
        instruction = cache.get(target)
        if instruction is None:
            return "not_boundary"
        if (instruction.get("branch_info") or {}).get("kind") == "trap":
            return "padding_or_trap"
        raw = code_bytes(target, instruction["size"]) if code_bytes is not None else None
        if raw and not any(raw):
            return "padding_or_trap"
        position = bisect_right(interval_starts, target) - 1
        if position >= 0 and target < interval_ends[position]:
            return "inside_declared"
        if target in reached:
            return "claimed"
        if target not in region_starts and not _starts_cleanly(cache, addresses, target, noreturn_targets):
            return "fallthrough"
        if owner(target) in indirect:
            return "indirect_jump_interval"
        return None

    tables = _pointer_tables(candidates, pointer_size if isinstance(pointer_size, int)
                             and pointer_size > 0 else 8)
    verdicts: list[tuple[list[dict[str, Any]], list[str | None], str | None]] = []
    vetoed: set[int] = set()
    for table in tables:
        reasons = [item_reason(item) for item in table]
        present = {reason for reason in reasons if reason}
        verdict = next((reason for reason in _POINTER_ITEM_REASONS if reason in present), None)
        if verdict is None:
            fresh = Counter(item["start"] for item in table if item["start"] not in seed_starts)
            owners = Counter(owner(target) for target in fresh)
            anchored = any(item["start"] in seed_starts
                           or (item.get("evidence") or {}).get("structure") for item in table)
            if any(count > 1 for count in fresh.values()):
                verdict = "duplicate_target"
            elif any(count > 1 for count in owners.values()):
                verdict = "shared_interval"
            elif fresh and not anchored:
                verdict = "no_known_function"
        if verdict is not None and verdict != "no_known_function":
            # 有反证的表（像跳转表/分支表）里的新目标，不再由其它表接受。
            vetoed.update(item["start"] for item in table if item["start"] not in seed_starts)
        verdicts.append((table, reasons, verdict))
    accepted: dict[int, dict[str, Any]] = {}
    rejected: Counter = Counter()
    unconfirmed: dict[int, dict[str, Any]] = {}
    table_outcomes: Counter = Counter()
    for table, reasons, verdict in verdicts:
        fresh_items = any(item["start"] not in seed_starts for item in table)
        table_outcomes[verdict or ("accepted" if fresh_items else "known_only")] += 1
        known_items = sum(item["start"] in seed_starts for item in table)
        for item, reason in zip(table, reasons):
            target = item["start"]
            if target in seed_starts or target in accepted:
                rejected["already_seed"] += 1
                continue
            if verdict is None and target not in vetoed:
                seed = {"name": f"ptr_{target:x}", "start": target, "size": None,
                        "source": item["source"], "boundary_known": False,
                        # 新增证据：所在指针表的首槽位地址、表项数与其中已知函数项数。
                        "evidence": {**item.get("evidence", {}),
                                     "table_address": (table[0].get("evidence") or {}).get("pointer_address"),
                                     "table_entries": len(table),
                                     "table_known_functions": known_items}}
                if "isa_mode" in item:
                    seed["isa_mode"] = item["isa_mode"]
                accepted[target] = seed
                continue
            # 逐项原因优先；本项无反证但被同表其它项拖累时记为 table_rejected，表级形状
            # 原因直接记该原因，被其它表否决时记为 vetoed。
            label = reason or (verdict if verdict in _POINTER_TABLE_REASONS
                               else "table_rejected" if verdict else "vetoed")
            rejected[label] += 1
            unconfirmed.setdefault(target, {
                "start": target,
                "pointer_address": (item.get("evidence") or {}).get("pointer_address"),
                "reason": label})
    for target in accepted:
        unconfirmed.pop(target, None)  # 先被无锚点的表搁置、后被另一张表接受的目标
    if details is not None:
        details.update(
            tables=len(tables), accepted_tables=table_outcomes.pop("accepted", 0),
            known_only_tables=table_outcomes.pop("known_only", 0),
            rejected_tables=dict(sorted(table_outcomes.items())),
            unconfirmed_total=len(unconfirmed),
            unconfirmed=[unconfirmed[start] for start in sorted(unconfirmed)][:MAX_UNCONFIRMED_POINTERS])
    return [accepted[start] for start in sorted(accepted)], rejected


def analyze_full(data: bytes, image: BinaryImage, *, workers: int,
                 xref_stage: XrefStage,
                 is_cancelled: Callable[[], bool] | None = None,
                 on_progress: Callable[[dict[str, Any]], None] | None = None,
                 on_decoded: Callable[[list[dict[str, Any]], list[dict[str, Any]],
                                       list[dict[str, Any]]], None] | None = None,
                 imports: list[dict[str, Any]] | None = None
                 ) -> tuple[list[dict[str, Any]], list[dict[str, Any]],
                            dict[str, Any], dict[str, Any], list[str]]:
    """imports（可选）：容器导入记录（PE IAT / Mach-O 桩与槽位），用于识别不返回的导入；
    省略时 PE/Mach-O 从容器重新读取，ELF 只用 Loader 的动态重定位。"""
    if workers > 1 and not xref_stage.separate_thread:
        raise ValueError("Multiple analysis workers require a separate xref thread")
    started = perf_counter()
    phases: dict[str, float] = {}
    stopped, cancel_lock = Event(), Lock()
    warnings: list[str] = []
    def cancelled() -> bool:
        if stopped.is_set():
            return True
        if is_cancelled is None:
            return False
        with cancel_lock:
            if stopped.is_set():
                return True
            try:
                if is_cancelled():
                    stopped.set()
            except Exception as exc:
                warnings.append(f"Cancellation callback failed: {type(exc).__name__}: {exc}")
                stopped.set()
        return stopped.is_set()
    def emit(stage: str, **details: Any) -> None:
        if on_progress is not None:
            on_progress({"stage": stage, **details})

    # 直接调用者也不超过 semantic 路径的同一线程上限；统计仍报告调用方请求的 workers。
    pool_workers = min(workers, MAX_WORKERS) if type(workers) is int else workers
    # 解码子进程数只用于统计；full_decode_workers_used 仍只计进程内参与解码/协调的线程。
    decode_diagnostics: dict[str, Any] = {}
    cache, coverage, notes = stream_decode_regions(
        data, image, workers=pool_workers, is_cancelled=cancelled if is_cancelled else None,
        on_progress=on_progress, include_data=True, diagnostics=decode_diagnostics,
        anchors=_resync_anchors(image))
    warnings.extend(notes)
    phases["disassembly"] = perf_counter() - started
    decode_workers = {item.pop("worker_id", None) for item in coverage}
    decode_workers.discard(None)
    addresses = sorted(cache)
    instructions = [cache[address] for address in addresses]
    if on_decoded is not None and not cancelled():
        # 渐进式结果：解码已完成的指令快照此后只读，可先交给调用方显示；
        # 回调在本线程同步执行，调用方应尽快返回（例如转交给自己的线程）。
        # 预览函数只用不依赖 xref 的声明（符号、unwind 表、入口与区域起点），
        # 是独立的新字典；正式函数恢复稍后基于完整 xref 另行计算。
        try:
            preview_coverage = [dict(item) for item in coverage]
            preview_functions, _ = _roots(data, image, cache, [], preview_coverage)
            on_decoded(instructions, preview_coverage, preview_functions)
        except Exception as exc:
            warnings.append(f"Preview callback failed: {type(exc).__name__}: {exc}")
    refs: list[dict[str, Any]] = []
    stamp = perf_counter()
    xref_instructions = 0
    reference_state = ReferenceState()
    data_ranges = DataRangeIndex(mapped_data_ranges(image.sections, kind=image.format, file_size=len(data)))
    region_starts = frozenset(item["address"] for item in coverage)
    # A bounded batch is transferred once; no repeated decode or per-function
    # reference submissions. Results remain useful when later work cancels.
    for offset in range(0, len(instructions), 4096):
        if cancelled():
            break
        snapshot = tuple(instructions[offset:offset + 4096])
        refs.extend(xref_stage.run(_references, snapshot, state=reference_state,
                                   data_ranges=data_ranges, reset_at=region_starts))
        xref_instructions += len(snapshot)
    phases["xref"] = perf_counter() - stamp
    stamp = perf_counter()
    seeds, extra = _roots(data, image, cache, refs, coverage)
    warnings.extend(extra)
    phases["function_recovery"] = perf_counter() - stamp
    # 非返回调用目标：在 xref 与函数恢复之后、CFG 之前确定。只读取 Loader 元数据、
    # 已完成的指令快照与已完成的引用，不调用解码器，也不新建引用；种子保持不变。
    stamp = perf_counter()
    noreturn_targets: dict[int, dict[str, Any]] = {}
    noreturn_sites: dict[int, dict[str, Any]] = {}
    if not cancelled():
        try:
            if imports is None and image.format in {"pe", "macho"}:
                from .symbols import parse_symbols
                imports = parse_symbols(data, image)[0]
            noreturn_targets = named_targets([*image.functions, *seeds], image.format,
                                             accept=cache.__contains__)
            stub_targets, noreturn_sites = import_noreturn(
                cache, refs, image, imports,
                is_cancelled=cancelled if is_cancelled is not None else None)
            for address, evidence in stub_targets.items():
                noreturn_targets.setdefault(address, evidence)
        except Exception as exc:
            warnings.append(f"Non-returning call analysis failed: {type(exc).__name__}: {exc}")
            noreturn_targets, noreturn_sites = {}, {}
    phases["noreturn"] = perf_counter() - stamp
    regions = [_Region(item["address"], item["offset"], item["size"])
               for item in coverage if item["size"] > 0]
    known = set(seed["start"] for seed in seeds)
    engine = next((item.get("engine", "none") for item in coverage
                   if item.get("instruction_count")), "none")
    functions: list[dict[str, Any]] = []
    reached: set[int] = set()
    worker_ids: set[int] = set()

    def cfg(seed: dict[str, Any], targets: dict[int, dict[str, Any]] = noreturn_targets,
            sites: dict[int, dict[str, Any]] = noreturn_sites):
        size = seed.get("size")
        end = seed["start"] + size if isinstance(size, int) and size > 0 else None
        decoder = _CachedDecoder(cache, addresses, regions, seed["start"], end, engine)
        fn, _, _, seen = _analyze_function(
            seed, decoder, known, set(), len(cache) + 1, len(cache) + 1,
            is_cancelled=cancelled if is_cancelled is not None else None,
            validate_overlaps=False, collect_xrefs=False,
            compute_liveness=False, noreturn_targets=targets, noreturn_sites=sites)
        fn["analysis_scope"] = "full_region_recovered_function"
        fn["cfg"]["scope"] = "full_region_recovered_function"
        # 完整模式统一给出审计字段（未截断任何调用时为空列表）。
        fn["cfg"].setdefault("noreturn_calls", [])
        return fn, seen, get_ident()

    stamp = perf_counter()
    pending = [seed for seed in seeds if seed["start"] in cache]
    seeds_by_start = {seed["start"]: seed for seed in pending}
    local_found: dict[int, dict[str, Any]] = {}
    noreturn_rounds = rebuilt = 0
    # 第二轮（指针根）函数补算本地不动点的轮数；没有第二轮函数时为 0。
    pointer_rounds = 0
    # 第二轮数据指针发现的审计计数（缺省为 0/空，默认 deep 模式不涉及）。
    pointer_candidate_count = pointer_built = 0
    pointer_accepted: list[dict[str, Any]] = []
    pointer_rejected: Counter = Counter()
    pointer_details: dict[str, Any] = {}
    # 首轮各函数可达指令数之和：等于 len(reached) 时没有任何指令被两个函数共享，
    # 重建后只需从 reached 中减去被截掉的指令（不保留逐函数集合，不额外占内存）。
    seen_total = 0
    pool = (ThreadPoolExecutor(max_workers=pool_workers, thread_name_prefix="fangida-full-cfg")
            if pool_workers > 1 else None)
    try:
        for offset in range(0, len(pending), max(1, pool_workers * 2)):
            if cancelled():
                break
            batch = pending[offset:offset + max(1, pool_workers * 2)]
            results = list(pool.map(cfg, batch)) if pool else [cfg(seed) for seed in batch]
            for fn, seen, worker_id in results:
                functions.append(fn)
                reached.update(seen)
                seen_total += len(seen)
                worker_ids.add(worker_id)
            emit("cfg", completed_functions=len(functions), total_functions=len(pending),
                 reached_instructions=len(reached))
        # 本地不动点：在已完成的 CFG 上推导“所有出口都不返回”的函数（协调线程只读 CFG，
        # 不解码、不建引用）；新增的不返回函数只重建其调用者，重建仍在同一 CFG 线程池执行。
        if not cancelled() and functions:
            local_found, rebuild, noreturn_rounds = local_noreturn(
                functions, noreturn_targets, noreturn_sites,
                is_cancelled=cancelled if is_cancelled is not None else None)
            if local_found:
                noreturn_targets = {**noreturn_targets, **local_found}
                positions = {fn["start"]: index for index, fn in enumerate(functions)}
                again = [seeds_by_start[start] for start in rebuild if start in positions]
                rebuild_cfg = partial(cfg, targets=noreturn_targets, sites=noreturn_sites)
                step = max(1, pool_workers * 2)
                exclusive = seen_total == len(reached)
                removed: set[int] = set()
                grown = False
                for offset in range(0, len(again), step):
                    if cancelled():
                        break
                    batch = again[offset:offset + step]
                    results = (list(pool.map(rebuild_cfg, batch)) if pool
                               else [rebuild_cfg(seed) for seed in batch])
                    for fn, seen, worker_id in results:
                        position = positions[fn["start"]]
                        # 只为被重建的函数从旧 CFG 取回原可达集合。
                        old = {instruction["addr"] for block in functions[position]["blocks"]
                               for instruction in block["instructions"]}
                        removed |= old - seen
                        grown = grown or not seen <= old
                        functions[position] = fn
                        worker_ids.add(worker_id)
                        rebuilt += 1
                if rebuilt and exclusive and not grown:
                    # 重建只截掉落空边（新集合是旧集合的子集），被截掉的指令此前只属于该函数：
                    # 增量结果与按最终 CFG 重新汇总全部函数相同。
                    reached -= removed
                elif rebuilt:
                    # 存在被多个函数共享的指令（或重建意外新增了指令）：按最终 CFG 重新汇总。
                    reached = {instruction["addr"] for fn in functions
                               for block in fn["blocks"] for instruction in block["instructions"]}
        # 第二轮：容器数据指针候选（ELF RELATIVE/ABS/GLOB_DAT、PE 基址重定位）只在首轮
        # CFG 之后处理——此时才知道哪些指令已被认领。种子计算在协调线程，只消费已完成的
        # 重定位、指令快照与首轮 CFG，不解码、不新建引用；按相邻槽位组成的指针表做表级
        # 裁决（见 _accept_pointer_candidates），接受的候选在同一 CFG 线程池中有界分批建图。
        # xref 仍在独立线程，不受影响。
        if not cancelled():
            raw_candidates, pointer_warnings = _pointer_candidates(data, image)
            warnings.extend(pointer_warnings)
            pointer_candidate_count = len(raw_candidates)
            ordered_regions = sorted(regions, key=lambda item: item.address)
            region_addresses = [item.address for item in ordered_regions]

            def code_bytes(address: int, size: int) -> bytes | None:
                # 只读输入文件中已映射的可执行字节（判断目标是否为全零填充），不解码。
                position = bisect_right(region_addresses, address) - 1
                if position < 0:
                    return None
                region = ordered_regions[position]
                if address + size > region.address + region.size:
                    return None
                start = region.offset + address - region.address
                return bytes(data[start:start + size])

            pointer_accepted, pointer_rejected = _accept_pointer_candidates(
                raw_candidates, cache, addresses, known, seeds, reached,
                region_starts, noreturn_targets, functions=functions,
                pointer_size=image.bits // 8 if image.bits in (32, 64) else None,
                executable=[(item.address, item.address + item.size) for item in regions],
                code_bytes=code_bytes, details=pointer_details)
            if pointer_accepted:
                # 接受的入口互为已知边界（与首轮种子一致）。建图前先全部计入 pending：
                # 中途取消时未建图的种子以 not_decoded 出现，完整度统计为 false。
                known.update(seed["start"] for seed in pointer_accepted)
                pending.extend(pointer_accepted)
                # 与重建调用者一致，使用本地不动点之后的最新不返回集合（cfg 的缺省参数
                # 绑定的是不动点之前的旧字典）。
                pointer_cfg = partial(cfg, targets=noreturn_targets, sites=noreturn_sites)
                step = max(1, pool_workers * 2)
                for offset in range(0, len(pointer_accepted), step):
                    if cancelled():
                        break
                    batch = pointer_accepted[offset:offset + step]
                    results = (list(pool.map(pointer_cfg, batch)) if pool
                               else [pointer_cfg(seed) for seed in batch])
                    for fn, seen, worker_id in results:
                        functions.append(fn)
                        reached.update(seen)
                        worker_ids.add(worker_id)
                        pointer_built += 1
                    emit("cfg", completed_functions=len(functions),
                         total_functions=len(pending), reached_instructions=len(reached))
                # 第二轮函数的本地不动点：首轮不动点只覆盖首轮 CFG，这里在第二轮建好的 CFG 上
                # 补算，使只经指针到达、所有出口都不返回的函数与首轮同形函数一样得到 noreturn
                # 标注。协调线程只读已完成的 CFG，不解码、不建引用。第二轮函数没有直接调用者：
                # 线性解码中的任何直接调用目标在首轮已是种子（或落在声明区间内），都会被裁决
                # 拒绝，因此新增结论不需要重建任何调用者的落空边；万一出现，只告警不静默。
                if pointer_built and not cancelled():
                    first = len(functions) - pointer_built
                    pointer_found, pointer_callers, pointer_rounds = local_noreturn(
                        functions[first:], noreturn_targets, noreturn_sites,
                        is_cancelled=cancelled if is_cancelled is not None else None)
                    if pointer_found:
                        for evidence in pointer_found.values():
                            # 新增证据字段：标明结论来自第二轮（指针根）的不动点。
                            evidence["pass"] = "pointer_roots"
                        noreturn_targets = {**noreturn_targets, **pointer_found}
                        local_found = {**local_found, **pointer_found}
                    if pointer_callers:
                        warnings.append(f"Second-round non-returning analysis left "
                                        f"{len(pointer_callers)} direct callers unrebuilt")
    finally:
        if pool is not None:
            pool.shutdown(wait=True)
    analyzed = {fn["start"] for fn in functions}
    for fn in functions:
        evidence = noreturn_targets.get(fn["start"])
        if evidence is not None:
            # 新增字段：缺省（字段不存在）表示未证明不返回。
            fn["noreturn"] = True
            fn["noreturn_evidence"] = dict(evidence)
    noreturn_calls = sum(len(fn["cfg"].get("noreturn_calls", ())) for fn in functions)
    cfg_complete = len(analyzed) == len(pending) and not any(
        item.get("reason") == "cancelled" for fn in functions
        for item in fn.get("cfg", {}).get("frontier", []))
    functions.extend({**seed, "analysis_scope": "not_decoded"} for seed in (*seeds, *pointer_accepted)
                     if seed["start"] not in analyzed)
    # Retain aliases previously supplied by the public loader API.
    names = {(fn["start"], fn.get("name")) for fn in functions}
    functions.extend({**symbol, "analysis_scope": "not_decoded"} for symbol in image.functions
                     if (symbol["start"], symbol.get("name")) not in names)
    phases["cfg"] = perf_counter() - stamp
    stamp = perf_counter()
    xref_stage.run(index_references, functions, refs)
    phases["xref_index"] = perf_counter() - stamp
    phases["total"] = perf_counter() - started
    decoded_bytes = sum(item["decoded_bytes"] for item in coverage)
    executable_bytes = sum(item["size"] for item in coverage)
    decode_complete = bool(coverage) and all(item["complete"] for item in coverage)
    unassigned = len(cache.keys() - reached)
    metadata = {"full_disassembly": instructions,
                "full_analysis": {"enabled": True,
                    "scope": "all_file_backed_executable_regions",
                    "executable_bytes": executable_bytes, "decoded_bytes": decoded_bytes,
                    "decode_complete": decode_complete, "instruction_count": len(cache),
                    "unassigned_instructions": unassigned,
                    "function_recovery_complete": False, "regions": coverage,
                    "xref_pass_complete": xref_instructions == len(cache),
                    "cfg_pass_complete": cfg_complete,
                    "xref_scope": "direct_control_flow_resolved_memory_and_mapped_pointer_constants",
                    # 新增：不返回调用目标及其证据（地址升序），供审计与下游使用。
                    "noreturn": {
                        "scope": "known_names_import_stubs_slot_calls_and_local_fixed_point",
                        "targets": [{"address": address, **noreturn_targets[address]}
                                    for address in sorted(noreturn_targets)],
                        "call_sites": [{"address": address, **noreturn_sites[address]}
                                       for address in sorted(noreturn_sites)],
                        "fixed_point_rounds": noreturn_rounds,
                        # 新增：第二轮函数补算不动点的轮数（缺省 0）。
                        "pointer_fixed_point_rounds": pointer_rounds,
                        "rebuilt_functions": rebuilt},
                    # 新增：第二轮数据指针发现的审计（候选数、接受数、按规则拒绝数）。
                    # 默认 deep 模式与非 full 路径不出现此流程，计数保持 0。built 是实际建图
                    # 的接受数（中途取消时小于 accepted，其余以 not_decoded 出现）；tables/
                    # accepted_tables/known_only_tables（只含已知函数项、不产生新函数）/
                    # rejected_tables 是表级裁决计数，unconfirmed 列出未确认
                    # 的新目标及原因（按地址升序，最多 MAX_UNCONFIRMED_POINTERS 项）。
                    "pointer_roots": {
                        "scope": "relocation_backed_code_pointer_tables_with_known_function_evidence",
                        "candidates": pointer_candidate_count,
                        "accepted": len(pointer_accepted),
                        "built": pointer_built,
                        "rejected": dict(sorted(pointer_rejected.items())),
                        "sources": dict(sorted(Counter(seed["source"]
                                        for seed in pointer_accepted).items())),
                        "tables": pointer_details.get("tables", 0),
                        "accepted_tables": pointer_details.get("accepted_tables", 0),
                        "known_only_tables": pointer_details.get("known_only_tables", 0),
                        "rejected_tables": pointer_details.get("rejected_tables", {}),
                        "unconfirmed_total": pointer_details.get("unconfirmed_total", 0),
                        "unconfirmed": pointer_details.get("unconfirmed", [])}}}
    stats = {"full_analysis": True, "full_instructions": len(cache),
             "full_decoded_bytes": decoded_bytes, "full_executable_bytes": executable_bytes,
             "full_decode_complete": decode_complete,
             "full_cfg_functions": len(analyzed),
             "full_xref_instructions": xref_instructions,
             "full_xref_pass_complete": xref_instructions == len(cache),
             "full_cfg_pass_complete": cfg_complete,
             "full_unassigned_instructions": unassigned,
             "full_function_sources": dict(Counter(seed.get("source", "unknown")
                                                    for seed in (*seeds, *pointer_accepted))),
             "full_decode_workers_used": len(decode_workers),
             "full_decode_processes_used": decode_diagnostics.get("processes_used", 0),
             "full_cfg_workers_used": len(worker_ids), "phase_seconds": phases,
             "semantic_functions": len(analyzed), "semantic_instructions": len(reached),
             "semantic_budget_exhausted": False, "semantic_cancelled": cancelled(),
             "semantic_workers_requested": workers, "semantic_workers_used": len(worker_ids),
             "semantic_parallel_functions": len(analyzed) if workers > 1 else 0,
             "semantic_decoder": engine,
             "semantic_partial_functions": sum(not fn.get("cfg", {}).get("complete", False)
                                                 for fn in functions),
             # 新增计数（缺省为 0）：不返回目标总数、其中由本地不动点推出的函数数、
             # 经导入槽位的不返回间接调用点数、被截断落空边的调用总数、因此重建的调用者数。
             "full_noreturn_targets": len(noreturn_targets),
             "full_noreturn_local_functions": len(local_found),
             "full_noreturn_call_sites": len(noreturn_sites),
             "full_noreturn_calls": noreturn_calls,
             "full_noreturn_rebuilt_functions": rebuilt,
             # 新增计数（缺省为 0）：数据指针候选总数、经表级证据规则接受且实际建图的新函数数，
             # 以及接受数（中途取消时可能大于建图数，差额以 not_decoded 出现）。
             "full_pointer_candidates": pointer_candidate_count,
             "full_pointer_functions": pointer_built,
             "full_pointer_accepted": len(pointer_accepted)}
    warnings.append("Executable-region sweep may decode padding/data as instructions. "
                    "Function recovery and indirect targets remain incomplete")
    if stopped.is_set():
        warnings.append("Full analysis cancelled; partial results retained")
    return functions, refs, stats, metadata, warnings
