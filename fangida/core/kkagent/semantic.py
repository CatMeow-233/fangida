"""Bounded, evidence-based native function and control-flow analysis.

Only an entry address, an executable function symbol, or the direct target of a
reachable call can seed a function. Decoding never linear-sweeps executable
sections to invent function starts. An exhausted budget or a missing successor
is represented by a graph frontier, not by a presumed return/boundary.
"""
from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from threading import get_ident
from typing import Any, Callable, Mapping

from ...processors import get_processor
from ...processors.decoder import NativeDecoder, objdump_data_metadata
from ...xrefs import (XrefStage, function_references, index_references,
                      merge_references, sorted_references, mapped_data_ranges)
from .binary import BinaryImage
from .noreturn import declared_noreturn_stubs, named_targets
from .translator import _branch, _objdump


MAX_FUNCTIONS = 128
MAX_INSTRUCTIONS = 8192
MAX_INSTRUCTIONS_PER_FUNCTION = 512
MAX_DECODE_WINDOWS = 128
MAX_WINDOWS_PER_FUNCTION = 32
WINDOW_BYTES = 512
MAX_WORKERS = 16


@dataclass(frozen=True)
class _Region:
    address: int
    offset: int
    size: int

    def contains(self, address: int) -> bool:
        return self.address <= address < self.address + self.size


@dataclass
class _Decoder:
    data: bytes
    image: BinaryImage
    regions: list[_Region]
    max_windows: int = MAX_DECODE_WINDOWS
    cache: dict[int, dict[str, Any]] = field(default_factory=dict)
    windows: int = 0
    engine: str = "none"
    warning: str | None = None
    _capstone: Any = None
    _disassembler: Any = None
    _processor: Any = None
    # cache 起始地址的有序索引，只服务于重叠检查；不是构造参数，也不参与 repr/比较。
    # 索引绑定到某个 cache 对象及其条目数：cache 被整体替换或被外部追加条目后，
    # 下次查询时整体重建，因此直接写 decoder.cache 的旧用法仍然正确。cache 只追加：
    # 同一地址重复写入的总是同一字节的同一解码结果（批量合并走 _merge_from）。
    _starts: list[int] = field(default_factory=list, init=False, repr=False, compare=False)
    _indexed: dict[int, dict[str, Any]] | None = field(default=None, init=False,
                                                       repr=False, compare=False)
    _indexed_count: int = field(default=0, init=False, repr=False, compare=False)
    # 已索引指令长度的上界：跨过某地址的指令起点必然落在 (地址 - 上界, 地址) 内。
    _max_size: int = field(default=0, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        self._processor = get_processor(self.image.architecture, self.image.endian)
        self.engine = self._processor.engine
        self.warning = self._processor.warning
        # Retain diagnostic attributes used by older native integrations.
        self._capstone = getattr(self._processor, "capstone", None)
        self._disassembler = getattr(self._processor, "disassembler", None)

    def region(self, address: int) -> _Region | None:
        return next((region for region in self.regions if region.contains(address)), None)

    def _ordered_starts(self) -> list[int]:
        """返回与当前 cache 同步的有序起点列表（过期时整体重建）。"""
        cache = self.cache
        if self._indexed is not cache or self._indexed_count != len(cache):
            self._starts = sorted(cache)
            self._max_size = max((ins["size"] for ins in cache.values()), default=0)
            self._indexed, self._indexed_count = cache, len(cache)
        return self._starts

    def _adopt_index(self, starts: list[int], max_size: int) -> None:
        """采用调用方为本 cache 预先算好的有序起点（须恰为 cache 的全部键）。"""
        self._starts, self._max_size = starts, max_size
        self._indexed, self._indexed_count = self.cache, len(self.cache)

    def _inside_cached(self, address: int) -> bool:
        """是否有缓存指令严格跨过 address（start < address < start + size）。

        与原先对整个 cache 的线性扫描逐值等价。不同窗口的线性解码流可能互相
        重叠，所以不能只看有序前驱：检查 (address - 最大长度, address) 内的
        全部起点，x86 上至多十几个，与 cache 规模无关。
        """
        starts = self._ordered_starts()
        if not starts:
            return False
        cache = self.cache
        low = bisect_right(starts, address - self._max_size)
        for position in range(bisect_left(starts, address) - 1, low - 1, -1):
            start = starts[position]
            if address < start + cache[start]["size"]:
                return True
        return False

    def _index_fresh(self, fresh: list[int]) -> None:
        """把刚写入 cache 的新起点并入有序索引（索引此前已同步时才增量维护）。"""
        cache = self.cache
        if self._indexed is not cache or self._indexed_count != len(cache) - len(fresh):
            self._indexed = None  # 索引本就过期，留给下次查询整体重建。
            return
        fresh.sort()
        starts = self._starts
        # 同一窗口的新起点通常连续且有序，只需与落在其间的旧起点归并。
        low, high = bisect_left(starts, fresh[0]), bisect_right(starts, fresh[-1])
        starts[low:high] = sorted(starts[low:high] + fresh) if high > low else fresh
        self._max_size = max(self._max_size, max(cache[start]["size"] for start in fresh))
        self._indexed_count = len(cache)

    def _merge_from(self, other: _Decoder) -> None:
        """等价于 self.cache.update(other.cache)，并尽量增量维护有序索引。"""
        cache, entries = self.cache, other.cache
        synced = (self._indexed is cache and self._indexed_count == len(cache) and
                  other._indexed is entries and other._indexed_count == len(entries))
        fresh = list(entries.keys() - cache.keys()) if synced else []
        cache.update(entries)
        if not synced:
            self._indexed = None
            return
        # update 也可能替换已有地址的条目；对方的长度上界覆盖其全部条目，
        # 合并两者的上界后，邻域查询仍不会漏掉任何跨越指令。
        self._max_size = max(self._max_size, other._max_size)
        if fresh:
            self._index_fresh(fresh)

    def decode(self, address: int, limit: int | None = None) -> tuple[dict[str, Any] | None, str | None]:
        # Different decode windows may overlap. Even an exact cached start is
        # ambiguous if another cached instruction spans that address.
        if self._inside_cached(address):
            return None, "overlapping_decode"
        if address in self.cache:
            instruction = self.cache[address]
            if limit is not None and address + instruction["size"] > limit:
                return None, "symbol_end"
            return instruction, None
        if self.engine == "none":
            return None, "decoder_unavailable"
        region = self.region(address)
        if region is None:
            return None, "outside_executable"
        if limit is not None and address >= limit:
            return None, "symbol_end"
        if self.windows >= self.max_windows:
            return None, "window_limit"
        # A branch into the middle of an already decoded instruction is
        # ambiguous; refusing to silently create overlapping instructions is
        # safer than selecting one of the two possible instruction streams.
        end = min(region.address + region.size, address + WINDOW_BYTES)
        if limit is not None:
            end = min(end, limit)
        offset = region.offset + address - region.address
        chunk = self.data[offset:offset + end - address]
        if not chunk:
            return None, "outside_scan"
        self.windows += 1
        if self.engine == "objdump" and type(self._processor) is NativeDecoder:
            instructions, warnings = _objdump(chunk, address, self.image.architecture)
            instructions = objdump_data_metadata(instructions, self.image.architecture)
            if not instructions and warnings and self.warning is None:
                self.warning = warnings[0]
        else:
            try:
                if type(self._processor) is NativeDecoder:
                    instructions, warnings = self._processor.decode_bytes(
                        chunk, address, max_instructions=128, classify=_branch, include_data=True)
                else:
                    instructions, warnings = self._processor.decode_bytes(
                        chunk, address, max_instructions=128)
                if warnings and self.warning is None:
                    self.warning = warnings[0]
            except Exception as exc:
                instructions = []
                if self.warning is None:
                    self.warning = f"Capstone decode failed: {type(exc).__name__}: {exc}"
        cache = self.cache
        fresh: list[int] = []
        for ins in instructions:
            # Processor pseudo-ops never become executable CFG instructions.
            if (ins["size"] > 0 and ins["addr"] + ins["size"] <= end and
                    not ins["mnemonic"].startswith(".") and
                    ins["mnemonic"] not in {"(bad)", "bad", "<unknown>"}):
                start = ins["addr"]
                # 等价于原 setdefault：已缓存的起点保持原对象，新起点同时进入有序索引。
                if start not in cache:
                    cache[start] = ins
                    fresh.append(start)
        if fresh:
            self._index_fresh(fresh)
        instruction = cache.get(address)
        return (instruction, None) if instruction is not None else (None, "undecoded")


def _regions(image: BinaryImage, data: bytes) -> list[_Region]:
    regions: list[_Region] = []
    for section in image.sections:
        if not section.get("executable"):
            continue
        address, offset, size = section.get("address"), section.get("offset"), section.get("size")
        if not all(isinstance(value, int) for value in (address, offset, size)):
            continue
        # 与 processors.full_decode._regions 同一约定：容器可单独声明文件中实际存储的字节数，
        # 取第一个存在的 file_size/filesize/raw_size 与 size 的较小值，不读入节之后的字节；
        # 该值非 int 或为负时整个节不可信，跳过。
        for key in ("file_size", "filesize", "raw_size"):
            if key in section:
                stored = section[key]
                if type(stored) is not int or stored < 0:
                    size = 0
                else:
                    size = min(size, stored)
                break
        if address < 0 or offset < 0 or size <= 0 or offset >= len(data):
            continue
        regions.append(_Region(address, offset, min(size, len(data) - offset)))
    return sorted(regions, key=lambda region: (region.address, region.offset))


def _liveness(blocks: list[dict[str, Any]], edges: list[dict[str, Any]],
              complete: bool, engine: str) -> dict[str, Any]:
    """Backward may-liveness; register names retain Capstone's native spelling."""
    if engine != "capstone":
        return {"available": False, "reason": "Capstone register access is unavailable"}
    starts = {block["start"] for block in blocks}
    successors: dict[int, set[int]] = {start: set() for start in starts}
    owner_by_instruction = {ins["addr"]: block["start"]
                            for block in blocks for ins in block["instructions"]}
    for edge in edges:
        if edge["dst"] in starts:
            owner = owner_by_instruction.get(edge["src"])
            if owner is not None:
                successors[owner].add(edge["dst"])
    uses: dict[int, set[str]] = {}
    definitions: dict[int, set[str]] = {}
    for block in blocks:
        used: set[str] = set()
        defined: set[str] = set()
        for ins in block["instructions"]:
            used.update(set(ins["reads"]) - defined)
            defined.update(ins["writes"])
        uses[block["start"]] = used
        definitions[block["start"]] = defined
    live_in = {start: set() for start in starts}
    live_out = {start: set() for start in starts}
    changed = True
    while changed:
        changed = False
        for start in sorted(starts, reverse=True):
            outgoing = set().union(*(live_in[dst] for dst in successors[start]))
            incoming = uses[start] | (outgoing - definitions[start])
            if incoming != live_in[start] or outgoing != live_out[start]:
                live_in[start], live_out[start] = incoming, outgoing
                changed = True
    return {"available": True, "complete": complete,
            "scope": "ISA register access; ABI call clobbers and aliasing are not modeled",
            "blocks": [{"start": start, "use": sorted(uses[start]),
                        "def": sorted(definitions[start]), "live_in": sorted(live_in[start]),
                        "live_out": sorted(live_out[start])} for start in sorted(starts)]}


def _crosses_accepted(ordered: list[int], instructions: dict[int, dict[str, Any]],
                      address: int, size: int) -> tuple[bool, int]:
    """新指令是否与已接受指令互相跨越，并返回它在有序起点中的插入位置。

    与原扫描 any(old < address < old + size(old) or address < old < address + size)
    等价：已接受指令两两互不跨越（任意 x < y 都有 y >= x + size(x)），
    所以只可能命中有序前驱或有序后继，其余起点无需比较。
    """
    position = bisect_left(ordered, address)
    if position:
        previous = ordered[position - 1]
        if address < previous + instructions[previous]["size"]:
            return True, position
    return position < len(ordered) and ordered[position] < address + size, position


def _fallthrough_trap(decoder: Any, address: int, start: int, limit: int | None,
                      instructions: dict[int, dict[str, Any]], ordered: list[int],
                      known: set[int], claimed: set[int], instruction_cap: int,
                      base_windows: int, validate_overlaps: bool) -> bool:
    """不返回调用的落空目标是否是一条可以照常接受的陷阱指令（只看这一条指令）。

    编译器常在不返回调用之后放一条陷阱（x86 ud2、arm64 brk #1、MSVC int3）。陷阱本身就是
    CFG 终点，保留这条落空边不会多吸入任何代码，下游伪 C/微码看到的“调用 → 陷阱”形状与
    不截断时一致。检查顺序与工作队列接受一条指令时相同（其它函数、重叠函数、符号边界、
    可执行区域、指令与窗口预算、重叠解码），任何一项不满足都保持截断。
    """
    if address == start or address in known or address in claimed:
        return False
    if (limit is not None and address >= limit) or decoder.region(address) is None:
        return False
    instruction = instructions.get(address)
    if instruction is None:
        if len(instructions) >= instruction_cap:
            return False
        if (decoder.windows - base_windows >= MAX_WINDOWS_PER_FUNCTION
                and address not in decoder.cache):
            return False
        # 不截断时这条指令本来就会被解码；这里只是提前看一眼它的种类。
        instruction, _ = decoder.decode(address, limit)
        if instruction is None:
            return False
        if validate_overlaps and _crosses_accepted(ordered, instructions, address,
                                                   instruction["size"])[0]:
            return False
    return (instruction.get("branch_info") or {}).get("kind") == "trap"


def _analyze_function(seed: dict[str, Any], decoder: _Decoder,
                      known: set[int], claimed: set[int], global_left: int,
                      max_per_function: int,
                      is_cancelled: Callable[[], bool] | None = None,
                      instruction_progress: Callable[[int], None] | None = None,
                      xref_stage: XrefStage | None = None,
                      validate_overlaps: bool = True,
                      collect_xrefs: bool = True,
                      compute_liveness: bool = True,
                      noreturn_targets: Mapping[int, Any] | None = None,
                      noreturn_sites: Mapping[int, Any] | None = None
                      ) -> tuple[dict[str, Any], list[dict[str, Any]], set[int], set[int]]:
    """noreturn_targets（调用目标 → 证据）与 noreturn_sites（间接调用指令地址 → 证据）可选：
    二者都为空时行为与原实现完全相同；否则对不返回目标的无条件调用不跟随顺序落空边，
    并在 cfg["noreturn_calls"] 中逐条记录（from/fallthrough/target/name/evidence）。
    落空目标本身是陷阱指令时（不返回调用之后的 ud2/brk #1/int3）仍保留这条边，记录中
    额外带 fallthrough_trap=True（缺省表示 False）。"""
    start = seed["start"]
    size = seed.get("size")
    boundary_known = isinstance(size, int) and size > 0
    limit = start + size if boundary_known else None
    queue = deque([(start, start)])  # (successor, edge source)
    queued = {start}
    instructions: dict[int, dict[str, Any]] = {}
    # 已接受指令起点的有序列表，仅在 validate_overlaps 时维护，用于二分重叠检查。
    ordered: list[int] = []
    # 每条指令至多两条后继边（分支目标、顺序落空）。按源地址保存为 int->int，
    # 避免逐边创建字典；instructions 的插入顺序就是原 successors 列表的边顺序。
    branch_to: dict[int, int] = {}
    fall_to: dict[int, int] = {}
    # leaders 与原实现集合相等：入口、分支边目标、带 branch_info 指令的落空目标。
    # （原第三条规则 dst != src + size 只可能命中分支边，已被第一条覆盖。）
    fall_leaders: list[int] = []
    frontier: list[dict[str, Any]] = []
    # 不返回调用的审计记录；未提供不返回信息时为 None，结果不新增任何字段。
    noreturn_calls: list[dict[str, Any]] | None = (
        [] if noreturn_targets or noreturn_sites else None)
    base_windows = decoder.windows
    instruction_cap = min(max_per_function, global_left)
    # 解码器契约不变：仍经由 decoder.decode / decoder.region 调用（测试可在类上打补丁）。
    decode = decoder.decode
    region = decoder.region
    popleft, push = queue.popleft, queue.append
    while queue:
        address, source = popleft()
        if is_cancelled is not None and is_cancelled():
            frontier.append({"from": source, "to": address, "reason": "cancelled"})
            break
        if address in instructions:
            continue
        if address != start and address in known:
            frontier.append({"from": source, "to": address, "reason": "other_function"})
            continue
        if address != start and address in claimed:
            frontier.append({"from": source, "to": address, "reason": "overlapping_functions"})
            continue
        if len(instructions) >= instruction_cap:
            frontier.append({"from": source, "to": address, "reason": "instruction_limit"})
            continue
        if decoder.windows - base_windows >= MAX_WINDOWS_PER_FUNCTION and address not in decoder.cache:
            frontier.append({"from": source, "to": address, "reason": "function_window_limit"})
            continue
        ins, reason = decode(address, limit)
        if ins is None:
            frontier.append({"from": source, "to": address, "reason": reason})
            continue
        if validate_overlaps:
            crossed, position = _crosses_accepted(ordered, instructions, address, ins["size"])
            if crossed:
                frontier.append({"from": source, "to": address, "reason": "overlapping_decode"})
                continue
            ordered.insert(position, address)
        instructions[address] = ins
        if instruction_progress is not None and len(instructions) % 32 == 0:
            instruction_progress(len(instructions))
        next_addr = address + ins["size"]
        branch = ins["branch_info"]
        kind = branch.get("kind")
        # 与原实现相同的后继顺序：先分支目标，再顺序落空。
        if kind == "jump":
            target = branch.get("target")
            if target is None:
                frontier.append({"from": address, "to": None, "reason": "indirect_jump"})
            elif target != start and target in known:
                frontier.append({"from": address, "to": target, "reason": "other_function"})
            elif target != start and target in claimed:
                frontier.append({"from": address, "to": target, "reason": "overlapping_functions"})
            elif limit is not None and target >= limit:
                frontier.append({"from": address, "to": target, "reason": "symbol_end"})
            elif region(target) is None:
                frontier.append({"from": address, "to": target, "reason": "outside_executable"})
            else:
                branch_to[address] = target
                if target not in queued:
                    push((target, address))
                    queued.add(target)
            if not branch.get("conditional"):
                continue
        elif kind in {"return", "trap"}:
            continue
        elif (kind == "call" and noreturn_calls is not None
              and not branch.get("conditional")):
            # 条件调用（AArch32 bl<cond>）条件不成立时仍会落空，只截断无条件调用。
            target = branch.get("target")
            evidence = (noreturn_targets.get(target)
                        if noreturn_targets and type(target) is int else None)
            if evidence is None and noreturn_sites:
                evidence = noreturn_sites.get(address)
            if evidence is not None:
                record = {"from": address, "fallthrough": next_addr,
                          "target": target if type(target) is int else None}
                if isinstance(evidence, dict):
                    record["name"] = evidence.get("name")
                    record["evidence"] = evidence.get("evidence", "noreturn")
                else:
                    record["name"] = evidence if isinstance(evidence, str) else None
                    record["evidence"] = "noreturn"
                noreturn_calls.append(record)
                if not _fallthrough_trap(decoder, next_addr, start, limit, instructions, ordered,
                                         known, claimed, instruction_cap, base_windows,
                                         validate_overlaps):
                    continue
                # 新增字段（缺省表示 False）：落空目标是陷阱指令，这条边照常保留。
                record["fallthrough_trap"] = True
        if next_addr != start and next_addr in known:
            frontier.append({"from": address, "to": next_addr, "reason": "other_function"})
        elif next_addr != start and next_addr in claimed:
            frontier.append({"from": address, "to": next_addr, "reason": "overlapping_functions"})
        elif limit is not None and next_addr >= limit:
            frontier.append({"from": address, "to": next_addr, "reason": "symbol_end"})
        elif region(next_addr) is None:
            frontier.append({"from": address, "to": next_addr, "reason": "outside_executable"})
        else:
            fall_to[address] = next_addr
            if branch:
                fall_leaders.append(next_addr)
            if next_addr not in queued:
                push((next_addr, address))
                queued.add(next_addr)
    # An edge into a reachable instruction creates a block leader. Any
    # fallthrough to a missing successor is already in the explicit frontier.
    # 与原实现相同的插入顺序（入口、全部分支目标、带分支信息的落空目标），
    # 使与 int 相等的非 int 目标在集合中保留的对象也一致。
    leaders = {start}
    leaders.update(branch_to.values())
    leaders.update(fall_leaders)
    blocks: list[dict[str, Any]] = []
    visited: set[int] = set()
    for leader in sorted(leaders & instructions.keys()):
        if leader in visited:
            continue
        members: list[dict[str, Any]] = []
        blocks.append({"start": leader, "instructions": members, "successors": []})
        cursor = leader
        while cursor in instructions and cursor not in visited:
            visited.add(cursor)
            ins = instructions[cursor]
            members.append(ins)
            following = fall_to.get(cursor)
            if following is None or ins["branch_info"] or following in leaders:
                break
            cursor = following
    # A converging incoming edge could reveal another leader after linear
    # grouping. Keep the graph total even in that rare case.
    for address in sorted(instructions.keys() - visited):
        blocks.append({"start": address, "instructions": [instructions[address]], "successors": []})
    blocks.sort(key=lambda block: block["start"])
    block_start = {ins["addr"]: block["start"] for block in blocks for ins in block["instructions"]}
    # 按原 successors 顺序（指令处理顺序，先分支后落空）过滤出跨块边与分支边。
    graph_edges: list[dict[str, Any]] = []
    destinations: dict[int, list[int]] = {}
    for address in instructions:
        owner = block_start.get(address)
        if owner is None:
            continue
        target = branch_to.get(address)
        if target is not None and target in block_start:
            graph_edges.append({"src": address, "dst": target, "kind": "branch"})
            destinations[address] = [target]
        target = fall_to.get(address)
        if target is not None:
            other = block_start.get(target)
            if other is not None and other != owner:
                graph_edges.append({"src": address, "dst": target, "kind": "fallthrough"})
                # 每个源至多两条边；去重后排序，与原 set 语义一致。
                seen_targets = destinations.get(address)
                if seen_targets is None:
                    destinations[address] = [target]
                elif target not in seen_targets:
                    seen_targets.append(target)
    for block in blocks:
        tail = block["instructions"][-1]["addr"]
        block["successors"] = sorted(destinations.get(tail, ()))
    complete = bool(instructions) and not frontier
    graph = {"scope": "bounded_function", "entry": start,
             "complete": complete, "boundary_known": boundary_known,
             "blocks": blocks, "edges": graph_edges, "frontier": frontier,
             "assumptions": ["Calls may return to their fallthrough address",
                             "Unseeded jump targets are treated as intraprocedural"]}
    if noreturn_calls is not None:
        graph["assumptions"].append(
            "Unconditional calls to known non-returning targets do not fall through")
        graph["noreturn_calls"] = noreturn_calls
    function = {**seed, "blocks": blocks,
                "cfg": {key: value for key, value in graph.items() if key != "blocks"},
                "analysis_scope": "bounded_function", "boundary_known": boundary_known,
                "liveness": (_liveness(blocks, graph_edges, complete, decoder.engine)
                             if compute_liveness else
                             {"available": False, "reason": "Not requested in full CFG/xref mode"}),
                "xrefs_in": [], "xrefs_out": []}
    # Transfer the completed instruction snapshot to the reference stage.
    # CFG traversal uses processor branch metadata, but never builds xrefs.
    if not collect_xrefs:
        return function, [], set(), set(instructions)
    snapshot = tuple(instructions.values())
    ranges = tuple((region.address, region.address + region.size) for region in decoder.regions)
    image = getattr(decoder, "image", None)
    data_ranges = mapped_data_ranges(getattr(image, "sections", ()), kind=getattr(image, "format", ""),
                                    file_size=len(decoder.data) if hasattr(decoder, "data") else None)
    if xref_stage is None:
        references, call_targets = function_references(snapshot, ranges, include_data=True, data_ranges=data_ranges)
    else:
        references, call_targets = xref_stage.run(function_references, snapshot, ranges,
                                                 include_data=True, data_ranges=data_ranges)
    return function, references, call_targets, set(instructions)


def _private_cache(decoder: _Decoder, address: int, size: int | None
                   ) -> tuple[dict[int, dict[str, Any]], tuple[list[int], int]]:
    """在主线程为一个 worker 复制 cache 及其有序索引（复制品归该 worker 独享）。

    键值与原推导式 {old: ins for old, ins in cache.items() if size is None or
    address <= old < address + size} 完全相同。有界种子改为按地址序复制：私有
    cache 的迭代顺序不进入任何结果，合并回主 cache 时已有键的位置也不会变。
    """
    cache, starts = decoder.cache, decoder._ordered_starts()
    if size is None:
        return dict(cache), (starts.copy(), decoder._max_size)
    selected = starts[bisect_left(starts, address):bisect_left(starts, address + size)]
    # 主 cache 的长度上界对其子集依然成立。
    return {old: cache[old] for old in selected}, (selected, decoder._max_size)


def _parallel_function(seed: dict[str, Any], data: bytes, image: BinaryImage,
                       regions: list[_Region], known: set[int], claimed: set[int],
                       cached: dict[int, dict[str, Any]],
                       xref_stage: XrefStage | None = None,
                       index: tuple[list[int], int] | None = None,
                       noreturn_targets: Mapping[int, Any] | None = None
                       ) -> tuple[dict[str, Any], list[dict[str, Any]], set[int],
                                  set[int], _Decoder, int]:
    """Analyze one bounded symbol with a private decoder and no shared writes."""
    # A previous window may have speculatively decoded this symbol already.
    # Keep those exact instruction boundaries without sharing a mutable cache.
    decoder = _Decoder(data, image, regions, max_windows=MAX_WINDOWS_PER_FUNCTION,
                       cache=cached)
    if index is not None:
        # 主线程已按 cached 的键算好有序起点，worker 无需再排序整份副本。
        decoder._adopt_index(*index)
    function, references, targets, reached = _analyze_function(
        seed, decoder, known, claimed, MAX_INSTRUCTIONS_PER_FUNCTION,
        MAX_INSTRUCTIONS_PER_FUNCTION, xref_stage=xref_stage,
        noreturn_targets=noreturn_targets)
    return function, references, targets, reached, decoder, get_ident()


def _parallel_candidates(queue: deque[int], seeds: dict[int, dict[str, Any]],
                         known: set[int], claimed: set[int], decoder: _Decoder,
                         capacity: int) -> list[int]:
    """Choose adjacent bounded symbols or adjacent discovered call seeds."""
    candidates: list[int] = []
    intervals: list[tuple[int, int]] = []
    first = seeds[queue[0]]
    discovered = first.get("source") == "direct_call" and first.get("size") is None
    for address in queue:
        if len(candidates) >= capacity:
            break
        seed = seeds[address]
        size = seed.get("size")
        if decoder.region(address) is None:
            break
        if discovered:
            if seed.get("source") != "direct_call" or size is not None:
                break
            if address in claimed or decoder._inside_cached(address):
                break
            # An uncached decode window normally prefetches 512 bytes. If
            # another seed is nearby, analyzing the earlier one first is
            # cheaper and avoids a likely cache overlap/replay.
            if any(abs(address - earlier) < WINDOW_BYTES and
                   (address not in decoder.cache or earlier not in decoder.cache)
                   for earlier in candidates):
                break
            candidates.append(address)
            continue
        if not isinstance(size, int) or size <= 0:
            break
        end = address + size
        # Previously *reached* instructions and split instructions affect CFG
        # ownership. A cached full instruction is merely speculative and can
        # be copied to a worker's private decoder.
        if (any(start < end and address < stop for start, stop in intervals) or
                any(address <= old < end for old in claimed) or
                any(other != address and address < other < end for other in known) or
                decoder._inside_cached(address)):
            break
        candidates.append(address)
        intervals.append((address, end))
    return candidates if len(candidates) >= 2 else []


def _byte_cover(spans: list[tuple[int, int]]) -> set[int] | None:
    """区间集合覆盖的全部整数字节；出现非 int 端点或长度不在 1..WINDOW_BYTES 时返回 None。

    对正整数长度的半开区间，a < b + bs and b < a + az 恰好等价于两区间共享
    某个整数字节，因此两两区间比较可以换成集合求交。
    """
    cover: set[int] = set()
    for start, size in spans:
        if type(start) is not int or type(size) is not int or not 0 < size <= WINDOW_BYTES:
            return None
        cover.update(range(start, start + size))
    return cover


def _batch_is_independent(candidates: list[int],
                          proposed: list[tuple[dict[str, Any], list[dict[str, Any]],
                                               set[int], set[int], _Decoder, int]],
                          seeds: dict[int, dict[str, Any]], known: set[int],
                          initial_cache: dict[int, dict[str, Any]]) -> bool:
    """Validate speculative work against all earlier results in commit order."""
    # 结论与 _batch_is_independent_scan 完全相同（各项检查都是无副作用的布尔量，
    # 只是不再两两扫描区间）：每个结果的已到达指令与新解码指令只提取一次，
    # 展开为字节覆盖集合后用 isdisjoint 判断重叠。前提不成立时回退原扫描。
    batch = list(zip(candidates, proposed))
    reached = [[(ins["addr"], ins["size"]) for block in result[0]["blocks"]
                for ins in block["instructions"]] for _, result in batch]
    fresh = [[(old, ins["size"]) for old, ins in result[4].cache.items()
              if old not in initial_cache] for _, result in batch]
    reached_cover = [_byte_cover(spans) for spans in reached]
    fresh_cover = [_byte_cover(spans) for spans in fresh]
    if any(cover is None for cover in reached_cover + fresh_cover):
        return _batch_is_independent_scan(candidates, proposed, seeds, known, initial_cache)
    frontiers = [{item.get("to") for item in result[0]["cfg"]["frontier"]} for _, result in batch]
    for index, (address, result) in enumerate(batch):
        size = seeds[address].get("size")
        if isinstance(size, int) and any(
                not address <= instruction < address + size for instruction in result[3]):
            return False
        for later_index in range(index + 1, len(batch)):
            later = batch[later_index][0]
            later_frontier = frontiers[later_index]
            if not reached_cover[index].isdisjoint(reached_cover[later_index]):
                return False
            if not later_frontier.isdisjoint([start for start, _ in reached[index]]):
                return False
            if not fresh_cover[index].isdisjoint(fresh_cover[later_index]):
                return False
            if not fresh_cover[index].isdisjoint(reached_cover[later_index]):
                return False
            for to in later_frontier:
                # 只有严格的 int 才能用集合成员判断；bool 等子类保留原比较式。
                if isinstance(to, int) and (to in fresh_cover[index] if type(to) is int else
                                            any(a <= to < a + az for a, az in fresh[index])):
                    return False
            later_size = seeds[later].get("size")
            for target in result[2]:
                if target in known:
                    continue
                if target in later_frontier:
                    return False
                if (target in reached_cover[later_index] if type(target) is int else
                        any(b <= target < b + bs for b, bs in reached[later_index])):
                    return False
                if isinstance(later_size, int) and later <= target < later + later_size:
                    return False
    return True


def _batch_is_independent_scan(candidates: list[int],
                               proposed: list[tuple[dict[str, Any], list[dict[str, Any]],
                                                    set[int], set[int], _Decoder, int]],
                               seeds: dict[int, dict[str, Any]], known: set[int],
                               initial_cache: dict[int, dict[str, Any]]) -> bool:
    """原始两两扫描实现：非常规输入的回退路径，也是测试中的等价参照。"""
    for index, (address, result) in enumerate(zip(candidates, proposed)):
        size = seeds[address].get("size")
        if isinstance(size, int) and any(
                not address <= instruction < address + size for instruction in result[3]):
            return False
        earlier_new = [(old, ins["size"]) for old, ins in result[4].cache.items()
                       if old not in initial_cache]
        earlier_reached = [(ins["addr"], ins["size"])
                           for block in result[0]["blocks"] for ins in block["instructions"]]
        for later, subsequent in zip(candidates[index + 1:], proposed[index + 1:]):
            later_reached = [(ins["addr"], ins["size"])
                             for block in subsequent[0]["blocks"]
                             for ins in block["instructions"]]
            later_new = [(old, ins["size"]) for old, ins in subsequent[4].cache.items()
                         if old not in initial_cache]
            later_frontier = {item.get("to") for item in subsequent[0]["cfg"]["frontier"]}
            if any(a < b + bs and b < a + az for a, az in earlier_reached
                   for b, bs in later_reached):
                return False
            if any(start in later_frontier for start, _ in earlier_reached):
                return False
            if any(a < b + bs and b < a + az for a, az in earlier_new
                   for b, bs in later_new):
                return False
            if any(a < b + bs and b < a + az for a, az in earlier_new
                   for b, bs in later_reached):
                return False
            if any(a <= to < a + az for a, az in earlier_new
                   for to in later_frontier if isinstance(to, int)):
                return False
            if any(target not in known and
                   (target in later_frontier or
                    any(b <= target < b + bs for b, bs in later_reached) or
                    (isinstance(seeds[later].get("size"), int) and
                     later <= target < later + seeds[later]["size"]))
                   for target in result[2]):
                return False
    return True


def analyze_semantics(data: bytes, image: BinaryImage, *,
                      max_functions: int = MAX_FUNCTIONS,
                      max_instructions: int = MAX_INSTRUCTIONS,
                      max_workers: int = 1,
                      is_cancelled: Callable[[], bool] | None = None,
                      on_progress: Callable[[dict[str, Any]], None] | None = None,
                      xref_stage: XrefStage | None = None,
                      imports: list[dict[str, Any]] | None = None
                      ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any], list[str]]:
    """Keep the legacy semantic API while separating decoding and references.

    Direct calls with one worker run inline. Multiple decode workers always
    use a dedicated reference thread, including cancellation and serial replay.
    A service may supply its already budgeted reference stage.
    imports（可选）：容器导入记录，仅用于 Mach-O 容器声明的不返回导入桩。
    """
    if xref_stage is not None:
        if max_workers > 1 and not xref_stage.separate_thread:
            raise ValueError("Multiple decode workers require a separate xref thread")
        return _analyze_semantics(data, image, max_functions=max_functions,
                                 max_instructions=max_instructions, max_workers=max_workers,
                                 is_cancelled=is_cancelled, on_progress=on_progress,
                                 xref_stage=xref_stage, imports=imports)
    with XrefStage(separate_thread=max_workers > 1) as stage:
        return _analyze_semantics(data, image, max_functions=max_functions,
                                 max_instructions=max_instructions, max_workers=max_workers,
                                 is_cancelled=is_cancelled, on_progress=on_progress,
                                 xref_stage=stage, imports=imports)


def _analyze_semantics(data: bytes, image: BinaryImage, *,
                       max_functions: int, max_instructions: int, max_workers: int,
                       is_cancelled: Callable[[], bool] | None,
                       on_progress: Callable[[dict[str, Any]], None] | None,
                       xref_stage: XrefStage,
                       imports: list[dict[str, Any]] | None = None
                       ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any], list[str]]:
    """Return (functions, direct xrefs, statistics, warnings) from a scanned prefix.

    `data` is the same bounded prefix passed to `parse_binary`; the function
    never reads the filesystem. Symbol size is the only known function size;
    all call/entry-discovered boundaries remain unknown. Cancellation keeps
    the evidence decoded so far and marks the unfinished graph as partial.
    Progress events contain only small, JSON-compatible counters and addresses.
    Independent bounded symbols or discovered calls can use private decoders
    concurrently. A conflicting speculative batch is rerun in serial order.
    Progress/cancellation callbacks use the serial path so their side effects
    and event order remain predictable.
    """
    regions = _regions(image, data)
    warnings: list[str] = []
    cancellation_error: str | None = None

    def cancelled_now() -> bool:
        nonlocal cancellation_error
        if is_cancelled is None:
            return False
        try:
            return bool(is_cancelled())
        except Exception as exc:
            cancellation_error = f"Cancellation callback failed: {type(exc).__name__}: {exc}"
            return True

    def emit(event: dict[str, Any]) -> None:
        nonlocal on_progress
        if on_progress is None:
            return
        try:
            on_progress({"phase": "native_semantic", **event})
        except Exception as exc:
            warnings.append(f"Progress callback failed: {type(exc).__name__}: {exc}")
            on_progress = None

    if not regions:
        stats = {"semantic_functions": 0, "semantic_instructions": 0,
                 "semantic_cancelled": False, "semantic_budget_exhausted": False,
                 "semantic_workers_requested": max(1, min(max_workers, MAX_WORKERS)),
                 "semantic_workers_used": 0, "semantic_parallel_functions": 0,
                 "semantic_noreturn_calls": 0}
        warnings.append("No executable section bytes within scan budget")
        emit({"event": "done", "cancelled": False, "completed_functions": 0,
              "decoded_instructions": 0})
        return image.functions.copy(), [], stats, warnings
    decoder = _Decoder(data, image, regions)
    seeds: dict[int, dict[str, Any]] = {}
    for symbol in image.functions:
        if isinstance(symbol.get("start"), int) and decoder.region(symbol["start"]) is not None:
            seeds.setdefault(symbol["start"], symbol)
    if isinstance(image.entry_address, int) and decoder.region(image.entry_address) is not None:
        seeds.setdefault(image.entry_address, {
            "name": f"entry_{image.entry_address:x}", "start": image.entry_address,
            "size": None, "source": "entry", "boundary_known": False})
    # 有界语义路径没有完整的 xref 遍历，只接入不需要快照的不返回证据：本地函数符号的
    # 已知名单与 Mach-O 容器声明的导入桩（ELF PLT/PE IAT 需要已完成的引用，只在完整模式推导）。
    noreturn_targets = named_targets(image.functions, image.format,
                                     accept=lambda start: decoder.region(start) is not None)
    for address, evidence in declared_noreturn_stubs(image, imports).items():
        if decoder.region(address) is not None:
            noreturn_targets.setdefault(address, evidence)
    queue = deque(seeds)
    functions: list[dict[str, Any]] = []
    refs: dict[tuple[int, int, str], dict[str, Any]] = {}
    claimed: set[int] = set()
    known: set[int] = set(seeds)
    instruction_count = 0
    capped = False
    cancelled = False
    ambiguous_targets = 0
    max_functions = max(0, min(max_functions, MAX_FUNCTIONS))
    max_instructions = max(0, min(max_instructions, MAX_INSTRUCTIONS))
    max_workers = max(1, min(max_workers, MAX_WORKERS))
    parallel_allowed = is_cancelled is None and on_progress is None
    worker_ids: set[int] = set()
    parallel_functions = 0
    executor: ThreadPoolExecutor | None = None
    emit({"event": "started", "known_functions": len(seeds),
          "max_functions": max_functions, "max_instructions": max_instructions})
    try:
        while queue:
            if cancelled_now():
                cancelled = True
                break
            if len(functions) >= max_functions or instruction_count >= max_instructions:
                capped = True
                break
            batch_results: list[tuple[dict[str, Any], list[dict[str, Any]],
                                      set[int], set[int], _Decoder, int]] = []
            # Conservative reservations mean concurrency never changes the
            # number of instructions/windows available to each seed.
            capacity = min(max_workers, max_functions - len(functions),
                           (max_instructions - instruction_count) // MAX_INSTRUCTIONS_PER_FUNCTION,
                           (decoder.max_windows - decoder.windows) // MAX_WINDOWS_PER_FUNCTION)
            if capacity >= 2 and parallel_allowed:
                candidates = _parallel_candidates(
                    queue, seeds, known, claimed, decoder, capacity)
                if candidates:
                    if executor is None:
                        executor = ThreadPoolExecutor(max_workers=max_workers,
                                                      thread_name_prefix="fangida-semantic")
                    try:
                        futures = []
                        for address in candidates:
                            cached, index = _private_cache(decoder, address,
                                                           seeds[address].get("size"))
                            futures.append(executor.submit(
                                _parallel_function, seeds[address], data, image, regions,
                                known.copy(), claimed.copy(), cached, xref_stage, index,
                                noreturn_targets))
                        proposed = [future.result() for future in futures]
                        if _batch_is_independent(candidates, proposed, seeds, known,
                                                 decoder.cache):
                            batch_results = proposed
                            for _ in candidates:
                                queue.popleft()
                            parallel_functions += len(candidates)
                            worker_ids.update(result[5] for result in proposed)
                    except Exception as exc:
                        warnings.append(f"Parallel semantic analysis failed; using serial decoder: "
                                        f"{type(exc).__name__}: {exc}")
            if not batch_results:
                address = queue.popleft()
                seed = seeds[address]
                fn, references, targets, reached = _analyze_function(
                    seed, decoder, known, claimed, max_instructions - instruction_count,
                    MAX_INSTRUCTIONS_PER_FUNCTION, cancelled_now,
                    lambda count: emit({"event": "instructions", "function_start": address,
                                        "completed_functions": len(functions),
                                        "decoded_instructions": instruction_count + count}),
                    xref_stage=xref_stage, noreturn_targets=noreturn_targets)
                batch_results = [(fn, references, targets, reached, decoder, get_ident())]
            for fn, references, targets, reached, local_decoder, _worker_id in batch_results:
                address = fn["start"]
                if local_decoder is not decoder:
                    # 即 decoder.cache.update(local_decoder.cache)，同时增量维护有序索引。
                    decoder._merge_from(local_decoder)
                    decoder.windows += local_decoder.windows
                    if decoder.warning is None:
                        decoder.warning = local_decoder.warning
                functions.append(fn)
                interrupted = any(item["reason"] == "cancelled" for item in fn["cfg"]["frontier"])
                if any(item["reason"] in {"instruction_limit", "window_limit", "function_window_limit"}
                       for item in fn["cfg"]["frontier"]):
                    capped = True
                claimed.update(reached)
                instruction_count += len(reached)
                xref_stage.run(merge_references, refs, tuple(references))
                for target in sorted(targets):
                    if target in known:
                        continue
                    if target in claimed or decoder._inside_cached(target):
                        ambiguous_targets += 1
                        continue
                    if len(known) >= max_functions:
                        capped = True
                        continue
                    known.add(target)
                    seeds[target] = {"name": f"sub_{target:x}", "start": target, "size": None,
                                     "source": "direct_call", "boundary_known": False}
                    queue.append(target)
                emit({"event": "function", "function_start": address,
                      "completed_functions": len(functions),
                      "decoded_instructions": instruction_count,
                      "complete": fn["cfg"]["complete"]})
                if interrupted:
                    cancelled = True
                    break
            if cancelled:
                break
    finally:
        if executor is not None:
            executor.shutdown(wait=True)
    analyzed_count = len(functions)
    analyzed_symbols = {(fn["start"], fn.get("name")) for fn in functions}
    # A decode quota must not erase symbol-table facts obtained independently
    # by the container parser. Aliases at one address are retained as well.
    pending_symbols = [symbol for symbol in image.functions
                       if (symbol.get("start"), symbol.get("name")) not in analyzed_symbols]
    functions.extend({**symbol, "analysis_scope": "not_decoded"}
                     for symbol in pending_symbols)
    xref_stage.run(index_references, functions, tuple(refs.values()))
    if decoder.warning:
        warnings.append(decoder.warning)
    if cancellation_error:
        warnings.append(cancellation_error)
    if cancelled:
        warnings.append("Semantic analysis cancelled; partial results retained")
    if capped:
        warnings.append("Semantic analysis stopped at a function or instruction budget")
    if ambiguous_targets:
        warnings.append(f"{ambiguous_targets} direct-call targets overlap already decoded code; "
                        "no new function boundary inferred")
    stats = {"semantic_functions": analyzed_count,
             "semantic_pending_symbols": len(pending_symbols),
             "semantic_discovered_calls": sum(fn.get("source") == "direct_call" for fn in functions),
             "semantic_instructions": instruction_count,
             "semantic_partial_functions": sum(not fn["cfg"]["complete"] for fn in functions[:analyzed_count]),
             "semantic_decode_windows": decoder.windows, "semantic_decoder": decoder.engine,
             "semantic_budget_exhausted": capped,
             "semantic_ambiguous_call_targets": ambiguous_targets,
             "semantic_cancelled": cancelled,
             "semantic_workers_requested": max_workers,
             "semantic_workers_used": len(worker_ids) if parallel_functions else int(bool(analyzed_count)),
             "semantic_parallel_functions": parallel_functions,
             # 新增：被截断落空边的不返回调用数（无不返回证据时为 0）。
             "semantic_noreturn_calls": sum(len(fn["cfg"].get("noreturn_calls", ()))
                                            for fn in functions[:analyzed_count])}
    emit({"event": "done", "cancelled": cancelled,
          "completed_functions": analyzed_count, "decoded_instructions": instruction_count})
    return functions, xref_stage.run(sorted_references, tuple(refs.values())), stats, warnings
