"""Stream file-backed executable regions without function or xref analysis.

Adjacent windows always start at the end of the preceding instruction. A
small lookahead allows an instruction to cross a window boundary; complete
instructions in that lookahead are consumed once. Independent regions can be
decoded concurrently, with a private registered processor per region.

Large regions decoded by the built-in Capstone processor may be split into
pieces decoded by worker processes (threads cannot run the Python binding in
parallel under the GIL). Pieces are stitched at a cursor shared with the
serial sweep, so records, gaps and coverage stay identical to serial decoding.

Optional resynchronization anchors (plain addresses, for example declared
function starts supplied by the caller) stop an instruction from straddling
a known boundary: a decoded instruction that would cross an anchor is
discarded, its bytes up to the anchor become an ``anchor_resync`` gap, and the
sweep restarts at the anchor. Without anchors the sweep is unchanged.
"""
from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait  # noqa: F401（保留既有模块属性）
from heapq import merge
from itertools import islice
import marshal
import os
from queue import Empty, SimpleQueue
import re
import sys
from contextlib import nullcontext
from threading import Event, Lock, get_ident
from typing import Any, Callable, Iterable, Sequence

from . import _decode_worker, get_processor
from ._decode_worker import DecodeProcessPool, HandshakeMismatch, sweep as _sweep
from .decoder import NativeDecoder


# The old external-tool adapter receives bounded input even for a huge region.
MAX_OBJDUMP_WINDOW = 4096
_LOOKAHEAD = 15
_INVALID_MNEMONICS = {"(bad)", "bad", "<unknown>", "invalid", "db", "dw", "dd", "dq"}
# 跨越重同步锚点而被丢弃的指令字节（[指令起点, 锚点)）在覆盖记录中的缺口原因。
ANCHOR_RESYNC = _decode_worker.ANCHOR_RESYNC
_following_anchor = _decode_worker.following_anchor
_share_dict = _decode_worker._share_dict


def _append_warning(warnings: list[str], message: str) -> None:
    if message not in warnings:
        warnings.append(message)


def _gap(coverage: dict[str, Any], start: int, size: int, reason: str) -> None:
    if size <= 0:
        return
    gaps = coverage["gaps"]
    address, offset = coverage["address"] + start, coverage["offset"] + start
    if gaps and gaps[-1]["reason"] == reason and gaps[-1]["address"] + gaps[-1]["size"] == address:
        gaps[-1]["size"] += size
    else:
        gaps.append({"address": address, "offset": offset, "size": size, "reason": reason})


def _gil_enabled() -> bool:
    """3.13+ 自由线程构建可关闭 GIL；3.11/3.12 没有该函数，按启用处理。"""
    check = getattr(sys, "_is_gil_enabled", None)
    return True if check is None else bool(check())


def _ascending(instructions: dict[int, dict[str, Any]]) -> bool:
    """确认记录按地址严格升序且互不重叠（_decode_region 的线性扫描保证此性质）。"""
    end = None
    for address, instruction in instructions.items():
        if end is not None and address < end:
            return False
        end = address + instruction["size"]
    return True


def _regions(data: bytes, image: Any) -> tuple[list[dict[str, Any]], list[str]]:
    regions: list[dict[str, Any]] = []
    warnings: list[str] = []
    for index, section in enumerate(image.sections):
        if not section.get("executable") or section.get("file_backed") is False:
            continue
        if section.get("type") in (8, "NOBITS", "SHT_NOBITS"):
            continue
        address, offset, size = (section.get(key) for key in ("address", "offset", "size"))
        if any(type(value) is not int or value < 0 for value in (address, offset, size)):
            _append_warning(warnings, f"Executable region {index} has invalid file/address bounds")
            continue
        # Container loaders may distinguish file storage from virtual extent.
        for key in ("file_size", "filesize", "raw_size"):
            if key in section:
                stored = section[key]
                if type(stored) is not int or stored < 0:
                    _append_warning(warnings, f"Executable region {index} has invalid {key}")
                    size = 0
                else:
                    size = min(size, stored)
                break
        if not size:
            continue
        available = min(size, max(0, len(data) - offset))
        coverage = {
            "name": str(section.get("name") or f"region_{index}"),
            "address": address, "offset": offset, "size": size,
            "file_backed_size": available, "decoded_bytes": 0,
            "instruction_count": 0, "gaps": [], "complete": False, "details_complete": False,
            "cancelled": False, "engine": "none", "worker_id": None,
        }
        if available < size:
            _gap(coverage, available, size - available, "outside_file")
            _append_warning(warnings, f"Executable region {coverage['name']} extends beyond file content")
        regions.append(coverage)
    if not regions:
        _append_warning(warnings, "No file-backed executable regions are available for full decoding")
    return regions, warnings


def _sweep_step(architecture: Any) -> int:
    """线性扫描在不可解码字节上的步长（ARM/ARM64 为定长 4 字节指令）。"""
    return 4 if architecture in {"arm", "arm64"} else 1


def _region_anchors(ordered: list[int], coverage: dict[str, Any], step: int) -> list[int]:
    """区域内的重同步锚点：区域相对偏移，升序且互不相同。

    只保留严格位于 (区域起点, 文件内容末尾) 之间的地址：起点处扫描本来就从此开始，
    文件外的字节不解码。定长指令集只保留落在扫描步长网格上的地址——网格上的锚点
    永远不会被一条对齐的指令跨越（因而不改变扫描），网格外的地址（例如带 Thumb
    位的符号）若作为锚点会让此后整段扫描失去对齐。
    """
    base, length = coverage["address"], coverage["file_backed_size"]
    low, high = bisect_right(ordered, base), bisect_left(ordered, base + length)
    return [address - base for address in ordered[low:high] if (address - base) % step == 0]


def _decode_region(
    data: bytes, image: Any, coverage: dict[str, Any], chunk_bytes: int,
    cancelled: Callable[[], bool], progress: Callable[[int, int, int, int | None], None],
    window_lock: Any = None,
    include_data: bool = False,
    anchors: Sequence[int] = (),
) -> tuple[dict[int, dict[str, Any]], dict[str, Any], list[str]]:
    """Linear sweep of one region.

    ``anchors`` (optional) are region-relative resynchronization offsets in
    ascending order, each strictly inside ``(0, file_backed_size)``. A decoded
    instruction that would straddle one is discarded and the sweep restarts at
    the anchor; the default (no anchors) keeps the historical sweep.
    """
    records: dict[int, dict[str, Any]] = {}
    warnings: list[str] = []
    length = coverage["file_backed_size"]
    cursor = reported = 0
    # 惰性维护的“下一个锚点”：值 ≤ 游标时视为过期，只在快速比较命中时用二分重新定位，
    # 因此每条指令只多一次整数比较；没有更多锚点时取区域长度（任何指令都不会越过）。
    next_anchor = _following_anchor(anchors, 0, length)
    if cancelled():
        coverage["cancelled"] = True
        _gap(coverage, 0, length, "cancelled")
    else:
        try:
            processor = get_processor(image.architecture, image.endian)
        except Exception as exc:
            _append_warning(warnings, f"Processor construction failed: {type(exc).__name__}: {exc}")
            _gap(coverage, 0, length, "decoder_unavailable")
            cursor = length
            processor = None
        if processor is None:
            coverage["partial_reason"] = "decoder unavailable"
            coverage["gaps"].sort(key=lambda item: item["address"])
            progress(cursor, 0, 0, None)
            return records, coverage, warnings
        coverage["engine"] = processor.engine
        warning = getattr(processor, "warning", None)
        if warning:
            _append_warning(warnings, warning)
        builtin = type(processor) is NativeDecoder
        decode = processor.decode_bytes_fast if builtin else processor.decode_bytes
        # 未被替换的内置快路径：记录在区域内按值共享只读子对象（与进程路径的 share_records
        # 同样的值共享，值与键顺序逐字不变）。只做廉价的部分：助记符、空 branch_info、
        # arch_meta（只含 engine/architecture 的二键字典直接比较，其余按值共享）；
        # 共享表属于本次调用（一个区域、一个线程），线程之间不共享任何对象。
        share = builtin and getattr(decode, "__func__", None) is _BUILTIN_FAST
        shared_mnemonics: dict[str, str] = {}
        shared_meta: dict[Any, Any] = {}
        empty_branch: dict[str, Any] = {}
        plain_meta: dict[str, Any] | None = None
        # 内置 Capstone 快路径在 GIL 下是纯 CPU 绑定，且每条指令有多次释放 GIL 的 ctypes
        # 调用；多个区域线程并发只会产生 GIL 交接开销。按窗口互斥以消除争用，
        # 每个区域仍由各自的私有处理器和线程解码。注册的处理器不受影响。
        # 只对进程内 Capstone 快路径互斥；objdump 回退是子进程 I/O，可真正并行，不加锁。
        guard = (window_lock if builtin and window_lock is not None and processor.engine == "capstone"
                 else nullcontext())
        step = _sweep_step(image.architecture)
        window_limit = min(chunk_bytes, MAX_OBJDUMP_WINDOW) if processor.engine == "objdump" else chunk_bytes
        retry_short = False
        base = coverage["address"]
        accepted_mnemonics: set[str] = set()
        while cursor < length:
            if cancelled():
                coverage["cancelled"] = True
                _gap(coverage, cursor, length - cursor, "cancelled")
                break
            if processor.engine == "none":
                _append_warning(warnings, warning or "Instruction decoder is unavailable")
                _gap(coverage, cursor, length - cursor, "decoder_unavailable")
                cursor = length
                break
            start = cursor
            limit = min(window_limit, _LOOKAHEAD + 1) if retry_short else window_limit
            target_end = min(length, start + limit)
            window_end = min(length, target_end + _LOOKAHEAD)
            file_start = coverage["offset"] + start
            coverage["worker_id"] = get_ident()
            try:
                with guard:
                    code = data[file_start:coverage["offset"] + window_end]
                    if builtin and include_data:
                        instructions, notes = decode(code, coverage["address"] + start,
                                                     max_instructions=window_end - start, include_data=True)
                    else:
                        instructions, notes = decode(code, coverage["address"] + start,
                                                     max_instructions=window_end - start)
            except Exception as exc:
                _append_warning(warnings, f"Processor decode failed: {type(exc).__name__}: {exc}")
                _gap(coverage, cursor, length - cursor, "decoder_failed")
                cursor = length
                break
            for note in notes:
                _append_warning(warnings, note)
            decoded = 0
            for instruction in instructions:
                get = instruction.get
                address, size, mnemonic = get("addr"), get("size"), get("mnemonic", "")
                # 已通过校验的 str 助记符按区域记忆；非 str 仍逐条走原始 str() 校验。
                if type(mnemonic) is not str or mnemonic not in accepted_mnemonics:
                    mnemonic = str(mnemonic)
                    if not mnemonic or mnemonic.startswith(".") or mnemonic.lower() in _INVALID_MNEMONICS:
                        mnemonic = None
                    elif type(get("mnemonic", "")) is str:
                        accepted_mnemonics.add(mnemonic)
                if (mnemonic is None or type(address) is not int or type(size) is not int or size <= 0):
                    _append_warning(warnings, "Processor emitted an invalid or data-only instruction record")
                    continue
                relative = address - base
                if relative < cursor or relative + size > window_end:
                    _append_warning(warnings, "Processor emitted an instruction outside its contiguous byte window")
                    continue
                if relative + size > next_anchor:
                    # 慢路径（每个锚点约进入一次）：重新定位游标之后的第一个锚点。
                    next_anchor = _following_anchor(anchors, cursor, length)
                    if next_anchor < relative:
                        # 处理器跳过的字节中含锚点（例如 objdump 列表省略无效字节）：
                        # 缺口只记到锚点为止，从锚点重新扫描，不越过已声明的入口。
                        _gap(coverage, cursor, next_anchor - cursor, "undecodable")
                        cursor = next_anchor
                        break
                    if next_anchor == relative:
                        next_anchor = _following_anchor(anchors, relative, length)
                    if next_anchor < relative + size:
                        # 指令跨越锚点：丢弃它及本窗口其后的指令（它们与锚点处的相位不同），
                        # [指令起点, 锚点) 记为重同步缺口，下一个窗口从锚点开始。
                        _gap(coverage, cursor, relative - cursor, "undecodable")
                        _gap(coverage, relative, next_anchor - relative, ANCHOR_RESYNC)
                        cursor = next_anchor
                        break
                if relative > cursor:
                    _gap(coverage, cursor, relative - cursor, "undecodable")
                if share:
                    instruction["mnemonic"] = shared_mnemonics.setdefault(mnemonic, mnemonic)
                    if not instruction["branch_info"]:
                        instruction["branch_info"] = empty_branch
                    metadata = instruction["arch_meta"]
                    if len(metadata) == 2:
                        # 内置解码器的二键 arch_meta 只有 {"engine", "architecture"} 一种形状。
                        if plain_meta is None:
                            plain_meta = metadata
                        elif metadata == plain_meta:
                            instruction["arch_meta"] = plain_meta
                    else:
                        instruction["arch_meta"] = _share_dict(shared_meta, "arch_meta", metadata)
                records[address] = instruction
                decoded += size
                cursor = relative + size
            coverage["decoded_bytes"] += decoded
            if cursor == start:
                # External objdump can skip invalid bytes in its listing. Do
                # not launch a subprocess once per undecodable byte.
                advance = (target_end - cursor if processor.engine == "objdump"
                           else min(step, length - cursor))
                if cursor + advance > next_anchor:
                    # 不可解码步进不越过锚点（x86 步长为 1、定长指令集的网格锚点都不会触发）。
                    next_anchor = _following_anchor(anchors, cursor, length)
                    advance = min(advance, next_anchor - cursor)
                _gap(coverage, cursor, advance, "undecodable")
                cursor += advance
                retry_short = True
            else:
                retry_short = False
            if cursor - reported >= chunk_bytes:
                progress(cursor, coverage["decoded_bytes"], len(records), coverage["worker_id"])
                reported = cursor
    coverage["instruction_count"] = len(records)
    coverage["gaps"].sort(key=lambda item: item["address"])
    coverage["complete"] = not coverage["gaps"] and coverage["engine"] != "none"
    coverage["details_complete"] = coverage["complete"] and not warnings and coverage["engine"] != "objdump"
    if coverage["engine"] == "objdump":
        coverage["partial_reason"] = "objdump fallback omits register access information"
    elif coverage["cancelled"]:
        coverage["partial_reason"] = "cancelled"
    elif coverage["gaps"]:
        coverage["partial_reason"] = "uncovered bytes"
    elif warnings:
        coverage["partial_reason"] = "decoder warnings"
    progress(cursor, coverage["decoded_bytes"], len(records), coverage["worker_id"])
    return records, coverage, warnings


# 进程切块解码。线性扫描在游标 p 处的下一步只取决于 p 之后的字节与区域末尾，与窗口划分
# 无关；两条扫描一旦经过同一游标就此后完全相同。因此各块从对齐的起点独立扫描并多扫一段
# 重叠区，父进程只要让“真实游标”落到下一块的游标路径上即可逐条精确拼接。
_PROCESS_MIN_BYTES = 256 * 1024     # 实测：可执行字节总数更小时付不起子进程启动与反序列化成本
_PROCESS_PIECE_BYTES = 256 * 1024   # 单块上限：限制单条响应的内存与反序列化耗时（取消粒度）
_PROCESS_MIN_PIECE_BYTES = 16 * 1024
_PIECES_PER_PROCESS = 8             # 每进程多块：负载均衡、进度与取消粒度（实测 8 与 16 持平）
_SYNC_OVERLAP = 512                 # 块尾越过下一块起点继续扫描的字节数
_RESYNC_WINDOW = 4096               # 未同步时父进程串行补扫的窗口，越小越早切回子进程结果
_POLL_SECONDS = 0.01                # 等待子进程期间轮询取消回调的间隔
_BATCH_JOBS = 1024                  # 一个请求最多合并的作业数（多个小区域合批，限制单帧拼接耗时）
_START_TIMEOUT = 30.0               # 子进程从启动到握手的最长无进展等待（只计父进程等待它的时间）
_REQUEST_TIMEOUT_FLOOR = 10.0       # 在途请求无读写进展的最短容忍时间
_REQUEST_SECONDS_PER_BYTE = 50e-6   # 与请求字节数成比例（约 20KB/s，远低于实测单进程解码吞吐）
_WRITE_BURST_SECONDS = 0.02         # 派发时立即写出请求的最长时间；其余由轮询继续写出
_BUILTIN_FAST = NativeDecoder.decode_bytes_fast
_GAP_START = lambda gap: gap[0]  # noqa: E731
_GAP_END = lambda gap: gap[0] + gap[1]  # noqa: E731
# 子进程握手不一致属于环境的确定性问题（解释器、包或 Capstone 不同），本进程内不再尝试。
_process_mismatch = False


def _process_limit(workers: int, processes: bool | None) -> int:
    """Worker processes allowed for this call; 0 keeps the in-process paths."""
    if processes is False or workers < 2 or _process_mismatch:
        return 0
    limit = workers
    if processes is None:
        setting = os.environ.get("FANGIDA_DECODE_PROCESSES", "").strip().lower()
        if setting in {"0", "false", "no", "off"}:
            return 0
        if setting.isdigit():
            limit = min(limit, int(setting))
        # 自动模式不超过可用 CPU 数（3.13+ 考虑亲和性）：多出的进程只增加启动与切换成本。
        limit = min(limit, getattr(os, "process_cpu_count", os.cpu_count)() or 1)
    if limit < 2 or getattr(sys, "frozen", False):
        return 0
    # 嵌入式宿主的 sys.executable 可能是宿主程序本身；只启动可识别的 Python 解释器。
    executable = sys.executable
    if (not executable or not os.path.isfile(executable)
            or not re.match(r"(?i)(python|pypy)", os.path.basename(executable))):
        return 0
    if not os.path.isdir(os.path.dirname(__file__)):
        return 0  # zip 等非目录安装无法用 -m 在子进程中定位同一份包
    return limit


def _process_processor(image: Any) -> NativeDecoder | None:
    """The parent's own built-in Capstone processor, or None if a child could differ."""
    try:
        processor = get_processor(image.architecture, image.endian)
    except Exception:
        # 只放弃子进程加速路径：进程内 _decode_region 会再次构造处理器，
        # 并把同一异常记为警告与 decoder_unavailable 缺口，不会丢失。
        return None
    if (type(processor) is not NativeDecoder or processor.engine != "capstone" or processor.warning
            or NativeDecoder.decode_bytes_fast is not _BUILTIN_FAST
            or type(image.architecture) is not str or type(image.endian) is not str):
        return None
    # 子进程只会构造内置 NativeDecoder；注册表中被替换的工厂（即使返回 NativeDecoder）不启用。
    registry = getattr(sys.modules.get(__package__ or ""), "_registry", None)
    factories = getattr(registry, "_factories", None)
    lock = getattr(registry, "_lock", None)
    if not isinstance(factories, dict) or lock is None:
        return None
    with lock:
        return processor if factories.get(image.architecture) is NativeDecoder else None


def _on_path(piece: tuple[Any, ...], start: int, cursor: int, base: int, step: int) -> bool:
    """Whether the piece's own sweep visits ``cursor`` (start, event ends, gap steps)."""
    # 子进程的块可带第 5 项（ROWS）：这里只用地址、缺口与结束游标。
    addrs, gaps, end = piece[0], piece[2], piece[3]
    if cursor == start or cursor == end:
        return True
    if not start < cursor < end:
        return False
    position = bisect_left(addrs, base + cursor)
    if position < len(addrs) and addrs[position] == base + cursor:
        return True
    position = bisect_right(gaps, cursor, key=_GAP_START) - 1
    if position < 0:
        return False
    gap = gaps[position]
    gap_start, size = gap[0], gap[1]
    if len(gap) > 2:
        # 锚点重同步缺口是一步跳过的：扫描只经过其起点；终点（锚点）是下一事件的起点或 end。
        return cursor == gap_start
    return cursor < gap_start + size and (cursor - gap_start) % step == 0


class _ProcessRegion:
    """Pieces and stitching state of one region; [0, cursor) equals the serial sweep."""

    def __init__(self, index: int, coverage: dict[str, Any], pieces: int, step: int,
                 anchors: Sequence[int] = ()) -> None:
        self.index, self.coverage, self.step = index, coverage, step
        self.length, self.base = coverage["file_backed_size"], coverage["address"]
        self.offset = coverage["offset"]
        self.anchors = anchors  # 区域相对、升序的重同步锚点（与串行扫描使用同一份）
        # 起点按 step 对齐（ARM/ARM64 为 4），否则块内扫描的相位永远无法与真实扫描重合。
        self.starts = list(dict.fromkeys(self.length * k // pieces // step * step for k in range(pieces)))
        # 在副本上拼接：任何回退都让原 coverage 保持未解码状态，交给原串行循环从头处理。
        self.work = dict(coverage, gaps=[dict(gap) for gap in coverage["gaps"]],
                         engine="capstone", worker_id=get_ident())
        self.records: dict[int, dict[str, Any]] = {}
        self.cursor = self.next = 0
        self.results: dict[int, tuple[Any, ...]] = {}
        self.pids: set[int] = set()  # 已拼入本区域的子进程；区域收尾成功后才计入 processes_used
        self.started = self.failed = self.done = False
        # 流式交付（可选）：commit 把新拼接的记录追加到这里，由 stitch 交给调用方后清空。
        self.fresh: list[dict[str, Any]] | None = None

    def bounds(self, piece: int) -> tuple[int, int, int]:
        start = self.starts[piece]
        stop = (min(self.length, self.starts[piece + 1] + _SYNC_OVERLAP)
                if piece + 1 < len(self.starts) else self.length)
        return start, stop, min(self.length, stop + 2 * _LOOKAHEAD)

    def piece_anchors(self, start: int, high: int) -> tuple[int, ...]:
        """块缓冲区 (start, high) 内的锚点：块内扫描不会越过缓冲区末尾。"""
        anchors = self.anchors
        return tuple(anchors[bisect_right(anchors, start):bisect_left(anchors, high)])

    def commit(self, piece: tuple[Any, ...]) -> None:
        """Append the piece's events from the current cursor, which is on its path."""
        addrs, records, gaps, end = piece[:4]
        cursor = self.cursor
        first = bisect_left(addrs, self.base + cursor)
        if len(piece) > 4 and piece[4] == _decode_worker.ROWS:
            # 子进程以行传输记录：只为实际拼入的部分重建紧凑 dict（重叠区的重复行不重建）；
            # 同一批对象同时进入区域结果与流式交付，消费方的逐对象核对仍然成立。
            built = _decode_worker.records_from_rows(islice(records, first, None))
            self.records.update(zip(islice(addrs, first, None), built))
            if self.fresh is not None:
                self.fresh.extend(built)
        else:
            self.records.update(zip(islice(addrs, first, None), islice(records, first, None)))
            if self.fresh is not None:
                self.fresh.extend(islice(records, first, None))
        gap_bytes = 0
        for gap in islice(gaps, bisect_right(gaps, cursor, key=_GAP_END), None):
            # 二元组是不可解码缺口；三元组带原因（锚点重同步），游标只会位于其起点。
            gap_start, size = gap[0], gap[1]
            if gap_start < cursor:
                gap_start, size = cursor, gap_start + size - cursor
            _gap(self.work, gap_start, size, gap[2] if len(gap) > 2 else "undecodable")
            gap_bytes += size
        # 子进程已验证事件首尾相接地铺满 [起点, end)，指令字节数即跨度减去缺口字节。
        self.work["decoded_bytes"] += end - cursor - gap_bytes
        self.cursor = end

    def finish(self, cancelled: bool) -> tuple[dict[int, dict[str, Any]], dict[str, Any], list[str]]:
        """Finalize exactly like _decode_region; a cancel keeps the stitched prefix."""
        work = self.work
        if cancelled:
            work["cancelled"] = True
            _gap(work, self.cursor, self.length - self.cursor, "cancelled")
        work["instruction_count"] = len(self.records)
        work["gaps"].sort(key=lambda item: item["address"])
        work["complete"] = not work["gaps"]
        work["details_complete"] = work["complete"]
        if work["cancelled"]:
            work["partial_reason"] = "cancelled"
        elif work["gaps"]:
            work["partial_reason"] = "uncovered bytes"
        self.coverage.update(work)
        self.done = True
        return self.records, self.coverage, []


def _decode_with_processes(
    data: bytes, image: Any, regions: list[dict[str, Any]], indices: list[int],
    processor: NativeDecoder, count: int, chunk_bytes: int, include_data: bool,
    cancelled: Callable[[], bool], progress: Callable[[int, int, int, int, int | None], None],
    finished: Callable[[int, tuple[dict[int, dict[str, Any]], dict[str, Any], list[str]]], None],
    used: set[int],
    anchors: dict[int, Sequence[int]] | None = None,
    on_records: Callable[[int, list[dict[str, Any]]], None] | None = None,
) -> None:
    """Decode regions with one shared, bounded set of worker processes.

    ``on_records(index, records)`` (optional) receives, on the calling thread,
    each newly stitched extension of a region's ``[0, cursor)`` prefix in
    ascending address order. Those records are final for this path; a region
    that later falls back is redone in-process with new record objects.

    ``anchors`` (optional) maps a region index to the region-relative
    resynchronization offsets that the serial sweep of that region uses.

    Runs entirely on the calling thread: it polls children, cancellation and
    progress itself and creates no thread. ``finished(index, result)`` is
    called as each region completes (or keeps its prefix on cancellation).
    Other regions (process failure or timeout, a sweep the serial loop would
    warn about, or cancellation before dispatch) are left untouched for the
    in-process path, so a fallback adds no warning and changes no field.
    ``used`` receives the PIDs of children whose pieces were stitched into a
    region that was then finalized here.

    Requests go only to children that completed the handshake. A child that
    does not greet within ``_START_TIMEOUT``, or makes no I/O progress on a
    request for longer than its size-proportional timeout, is killed; the
    regions of its request fall back. Small regions (and pieces) are batched
    into one request up to the piece size, so many tiny sections cost one
    round trip per batch. Bookkeeping is proportional to the frames received,
    not to the number of regions.
    """
    global _process_mismatch
    step = _sweep_step(image.architecture)
    total = sum(regions[index]["file_backed_size"] for index in indices)
    target = max(_PROCESS_MIN_PIECE_BYTES,
                 min(_PROCESS_PIECE_BYTES, -(-total // (count * _PIECES_PER_PROCESS))))
    anchors = anchors or {}
    states = [_ProcessRegion(index, regions[index],
                             max(1, -(-regions[index]["file_backed_size"] // target)), step,
                             anchors.get(index, ()))
              for index in indices]
    if on_records is not None:
        for state in states:
            state.fresh = []
    tasks = deque((position, piece) for position, state in enumerate(states)
                  for piece in range(len(state.starts)))
    owner: dict[int, tuple[int, list[tuple[int, int]]]] = {}
    decode = processor.decode_bytes_fast
    stopped = False
    remaining = len(states)   # 既未完成也未回退的区域数
    waiting = 0               # 已到达但尚未拼接的块数
    serial = 0
    pool = DecodeProcessPool(min(count, len(tasks)), _decode_worker.hello(), _START_TIMEOUT)

    def fail(state: _ProcessRegion) -> None:
        nonlocal remaining, waiting
        if state.failed or state.done:
            return
        state.failed = True
        waiting -= len(state.results)
        state.results.clear()
        remaining -= 1

    def dispatch() -> None:
        nonlocal serial
        for worker in pool.idle():
            # 已到达但未拼接的块数受限：等待最早一块时不会无界堆积结果（背压）。
            if waiting >= 2 * pool.count:
                return
            jobs: list[tuple[int, int]] = []
            payload = []
            size = 0
            while tasks and len(jobs) < _BATCH_JOBS:
                position, piece = tasks[0]
                state = states[position]
                if state.failed or state.done:
                    tasks.popleft()
                    continue
                start, stop, high = state.bounds(piece)
                if jobs and size + high - start > target:
                    break
                tasks.popleft()
                state.started = True
                jobs.append((position, piece))
                job = (state.base, state.length, start, start, stop,
                       data[state.offset + start:state.offset + high])
                # 第 7 项（可选）：块内锚点；没有锚点的作业保持原六元组。
                piece_anchors = state.piece_anchors(start, high) if state.anchors else ()
                payload.append((*job, piece_anchors) if piece_anchors else job)
                size += high - start
            if not jobs:
                return
            serial += 1
            owner[serial] = (worker, jobs)
            pool.submit(worker, (serial, image.architecture, image.endian, chunk_bytes, step,
                                 _LOOKAHEAD, _INVALID_MNEMONICS, include_data, payload),
                        max(_REQUEST_TIMEOUT_FLOOR, size * _REQUEST_SECONDS_PER_BYTE),
                        _WRITE_BURST_SECONDS)

    def drop(worker: int) -> None:
        # 超时的子进程：杀掉并回收；它在途请求涉及的区域整体交回进程内路径。
        for task, (holder, jobs) in list(owner.items()):
            if holder == worker:
                del owner[task]
                for position, _ in jobs:
                    fail(states[position])
        pool.drop(worker)

    def stitch(state: _ProcessRegion) -> None:
        nonlocal stopped, waiting, remaining
        while not state.done and not state.failed and state.next in state.results:
            pid, piece = state.results.pop(state.next)
            waiting -= 1
            start, end = state.starts[state.next], piece[3]
            state.next += 1
            # 真实游标尚未落在本块的游标路径上：父进程串行补扫，直到同步或越过本块（该块作废）。
            while state.cursor < end and not _on_path(piece, start, state.cursor, state.base, step):
                if cancelled():
                    stopped = True
                    return
                extra = _sweep(decode, data, -state.offset, state.base, state.length, state.cursor,
                               state.cursor + 1, min(chunk_bytes, _RESYNC_WINDOW), step, _LOOKAHEAD,
                               _INVALID_MNEMONICS, include_data, state.anchors)
                if extra is None:
                    fail(state)
                    return
                state.commit(extra)
            if state.cursor < end:
                state.commit(piece)
                state.pids.add(pid)
            if state.fresh:
                fresh, state.fresh = state.fresh, []
                on_records(state.index, fresh)
            complete = state.next == len(state.starts)
            if complete and state.cursor != state.length:
                fail(state)
                return
            result = state.finish(False) if complete else None
            if result is not None:
                remaining -= 1
                used.update(state.pids)
            progress(state.index, state.cursor, state.work["decoded_bytes"], len(state.records),
                     state.work["worker_id"])
            if result is not None:
                finished(state.index, result)

    try:
        pool.start()
        pids = pool.pids
        while remaining:
            if cancelled():
                stopped = True
                break
            # 先派满已握手的空闲子进程，读取就绪结果后立即重新派发，再反序列化与拼接，使子进程不空等。
            dispatch()
            if not owner and not pool.starting():
                break  # 无在途请求、无待握手的子进程且无法派发：剩余区域交回进程内路径
            frames = pool.collect(_POLL_SECONDS)
            expired = pool.expired()
            if expired:
                if not any(pool.greeted):
                    # 没有任何子进程完成握手（解释器启动即挂起等环境问题）：本进程内不再尝试，
                    # 避免之后每次调用都先等满启动超时。
                    _process_mismatch = True
                for worker in expired:
                    drop(worker)
            if frames:
                dispatch()
            touched: dict[int, _ProcessRegion] = {}
            for worker, frame in frames:
                # 反序列化是父进程的主要开销：逐帧检查取消，使取消延迟保持在单块量级。
                if cancelled():
                    stopped = True
                    break
                task, results = marshal.loads(frame)
                holder, jobs = owner.pop(task, (None, ()))
                if holder != worker or type(results) is not list or len(results) != len(jobs):
                    raise _decode_worker.ProtocolError("decode worker answered another request")
                for (position, piece), result in zip(jobs, results):
                    state = states[position]
                    if result is None:
                        fail(state)  # 串行循环会告警或在窗口内记缺口的扫描：整区交回原循环
                    elif not state.failed and not state.done:
                        state.results[piece] = (pids[worker], result)
                        waiting += 1
                        touched[position] = state
            if stopped:
                break
            # 只拼接本轮收到帧的区域：协调开销与收到的帧成正比，与区域总数无关。
            for state in touched.values():
                stitch(state)
                if stopped:
                    break
            if stopped:
                break
    except HandshakeMismatch:
        _process_mismatch = True
        for state in states:
            fail(state)
    except Exception:
        # 启动失败、子进程崩溃、管道或反序列化错误：静默回退到进程内路径，不新增告警。
        for state in states:
            fail(state)
    finally:
        pool.close()
    if stopped:
        # 取消：只保留从区域起点连续拼接的前缀；尚未派发的区域交给原路径按取消语义处理。
        for state in states:
            if state.started and not state.done and not state.failed:
                result = state.finish(True)
                used.update(state.pids)
                progress(state.index, state.cursor, state.work["decoded_bytes"], len(state.records),
                         state.work["worker_id"])
                finished(state.index, result)


def stream_decode_regions(
    data: bytes, image: Any, *, workers: int = 1, chunk_bytes: int = 65536,
    is_cancelled: Callable[[], bool] | None = None,
    on_progress: Callable[[dict[str, Any]], None] | None = None,
    include_data: bool = False,
    processes: bool | None = None,
    diagnostics: dict[str, Any] | None = None,
    anchors: Iterable[int] | None = None,
    on_records: Callable[[list[dict[str, Any]], int, list[dict[str, Any]]], None] | None = None,
) -> tuple[dict[int, dict[str, Any]], list[dict[str, Any]], list[str]]:
    """Decode every file-backed executable region into an address-keyed IR.

    Coverage explicitly includes undecodable bytes, unavailable file bytes,
    and cancellation tails. Linear decoding does not establish that every
    valid instruction is reachable code. No data pseudo instruction is emitted.
    ``is_cancelled`` and ``on_progress(event)`` run on the calling thread;
    callbacks do not disable parallel decoding. ``worker_id`` is diagnostic
    scheduling information and should not be included in persisted evidence.
    Rich address-operation metadata is opt-in; the legacy default snapshot
    remains unchanged and registered processor signatures stay untouched.

    With ``workers > 1`` and at least ``_PROCESS_MIN_BYTES`` of executable
    bytes for the built-in Capstone processor, regions are split into pieces
    decoded by at most ``workers`` child processes. ``processes=None`` is
    automatic (``FANGIDA_DECODE_PROCESSES=0`` disables it, ``=N`` caps it),
    ``False`` disables and ``True`` requests them regardless of that variable.
    Results are identical to serial decoding; any process failure, or a child
    that does not complete its handshake or stops making progress within its
    timeout, silently falls back in-process. Such regions report the
    coordinating calling thread as ``worker_id``, so ``workers_used`` counts
    in-process threads only. An optional ``diagnostics`` dict receives
    ``processes_used`` (children whose pieces were stitched into regions
    finalized by the process path) and ``process_regions``; progress events
    also carry ``processes_used``. Progress totals never move backwards when
    a region falls back.

    ``anchors`` (optional, default None) are absolute addresses at which the
    sweep resynchronizes, typically declared function starts and the entry
    point; this processor-layer function only receives the addresses. A
    decoded instruction that would straddle an anchor is discarded, the bytes
    from its start to the anchor become a gap with reason ``anchor_resync``,
    and decoding continues at the anchor. Anchors outside a region's file
    content, at a region start, or (for fixed 4-byte ARM/ARM64 instructions)
    off the sweep's 4-byte grid are ignored. The process path applies the
    same anchors, so results stay identical to serial decoding.

    ``on_records(regions, index, records)`` (optional, default None) lets a
    consumer start on completed instructions while decoding continues, in the
    manner of an auto-analysis queue. It runs on the calling thread with the
    coverage list (read only), a region index and records that the process
    path has stitched for that region, in ascending address order. Delivery
    is best effort: regions decoded in-process are not delivered, and a
    delivered region may still fall back or lose records to an earlier
    overlapping region, so the consumer must check what it received against
    the returned instructions. An exception from the callback stops delivery
    and adds a warning; decoding results never depend on it.
    """
    if type(workers) is not int or workers < 1:
        raise ValueError("workers must be a positive integer")
    if type(chunk_bytes) is not int or chunk_bytes < 1:
        raise ValueError("chunk_bytes must be a positive integer")
    if type(include_data) is not bool:
        raise ValueError("include_data must be boolean")
    if processes is not None and type(processes) is not bool:
        raise ValueError("processes must be boolean or None")
    if diagnostics is not None and not isinstance(diagnostics, dict):
        raise ValueError("diagnostics must be a dict or None")
    if anchors is not None:
        try:
            ordered = sorted(set(anchors))
        except TypeError:
            raise ValueError("anchors must be an iterable of integers or None") from None
        if any(type(address) is not int for address in ordered):
            raise ValueError("anchors must be an iterable of integers or None")
    if diagnostics is not None:
        diagnostics.update(processes_used=0, process_regions=0)
    regions, warnings = _regions(data, image)
    if not regions:
        return {}, [], warnings
    # 区域索引 -> 区域相对锚点；没有锚点的区域不出现（串行与进程路径共用同一份）。
    region_anchors: dict[int, list[int]] = {}
    if anchors is not None and ordered:
        step = _sweep_step(image.architecture)
        for index, coverage in enumerate(regions):
            inside = _region_anchors(ordered, coverage, step)
            if inside:
                region_anchors[index] = inside
    stop = Event()
    snapshots: dict[int, tuple[int, int, int]] = {}
    totals = [0, 0, 0]   # 各区域快照之和，逐事件增量维护（事件开销与区域数无关）
    # 进程路径中途回退的区域：进程内重做追上之前，进度保持该区域已报告的最大值，不倒退。
    floors: dict[int, tuple[int, int, int]] = {}
    raw_processed: dict[int, int] = {}   # 套用下限之前的真实已处理字节，供区域收尾上报
    worker_ids: set[int] = set()
    process_ids: set[int] = set()
    completed = 0
    total_bytes = sum(region["file_backed_size"] for region in regions)
    output: dict[int, dict[str, Any]] = {}
    results: dict[int, tuple[dict[int, dict[str, Any]], dict[str, Any], list[str]]] = {}

    def check_cancelled() -> bool:
        if not stop.is_set() and is_cancelled is not None:
            try:
                if is_cancelled():
                    stop.set()
            except Exception as exc:
                _append_warning(warnings, f"Cancellation callback failed: {type(exc).__name__}: {exc}")
                stop.set()
        return stop.is_set()

    def report(index: int, processed: int, decoded: int, count: int, worker_id: int | None) -> None:
        nonlocal on_progress
        raw_processed[index] = processed
        floor = floors.get(index)
        if floor is not None:
            if processed >= floor[0] and decoded >= floor[1] and count >= floor[2]:
                del floors[index]
            else:
                processed, decoded, count = (max(processed, floor[0]), max(decoded, floor[1]),
                                             max(count, floor[2]))
        previous = snapshots.get(index, (0, 0, 0))
        snapshots[index] = (processed, decoded, count)
        totals[0] += processed - previous[0]
        totals[1] += decoded - previous[1]
        totals[2] += count - previous[2]
        if worker_id is not None:
            worker_ids.add(worker_id)
        if on_progress is None:
            return
        event = {"phase": "native_full_decode", "stage": "decode",
                 "regions_completed": completed, "regions_total": len(regions),
                 "processed_bytes": totals[0], "decoded_bytes": totals[1],
                 "instruction_count": totals[2],
                 "total_bytes": total_bytes, "workers_used": len(worker_ids),
                 "processes_used": len(process_ids)}
        try:
            on_progress(event)
        except Exception as exc:
            _append_warning(warnings, f"Progress callback failed: {type(exc).__name__}: {exc}")
            on_progress = None

    def report_final(index: int) -> None:
        # 区域结果已确定：撤销回退期间的进度下限，按真实结果上报。回退后又被取消时，
        # 最终事件与返回的 coverage 一致，不再沿用回退前的较大数值。
        floors.pop(index, None)
        coverage = regions[index]
        report(index, raw_processed.get(index, 0), coverage["decoded_bytes"],
               coverage["instruction_count"], coverage["worker_id"])

    check_cancelled()
    limit = 0 if stop.is_set() else _process_limit(workers, processes)
    # 启用条件按可执行字节总数判断：值得启动子进程时，小区域也交给同一组子进程，
    # 按块大小合批成一个请求（避免每个小区域一次往返），与大区域的切块并行解码；
    # 调用线程只做协调，不再另开解码线程池。
    processor = (_process_processor(image) if limit and total_bytes >= _PROCESS_MIN_BYTES
                 else None)
    if processor is not None:
        def finished(index: int, result: tuple[dict[int, dict[str, Any]], dict[str, Any], list[str]]
                     ) -> None:
            nonlocal completed
            results[index] = result
            completed += 1
            report_final(index)

        # 锚点只在存在时以关键字传入：无锚点的调用与原调用形式完全相同。
        extra: dict[str, Any] = {"anchors": region_anchors} if region_anchors else {}
        if on_records is not None:
            delivery = [on_records]

            def deliver(index: int, records: list[dict[str, Any]]) -> None:
                if not delivery:
                    return
                try:
                    delivery[0](regions, index, records)
                except Exception as exc:
                    delivery.clear()
                    _append_warning(warnings, f"Instruction stream callback failed: {type(exc).__name__}: {exc}")
            extra["on_records"] = deliver
        _decode_with_processes(data, image, regions, list(range(len(regions))), processor, limit,
                               chunk_bytes, include_data, check_cancelled, report, finished, process_ids,
                               **extra)
        if diagnostics is not None:
            diagnostics.update(processes_used=len(process_ids), process_regions=len(results))
    remaining = [index for index in range(len(regions)) if index not in results]
    for index in remaining:
        if index in snapshots:
            floors[index] = snapshots[index]
    if workers == 1:
        for index in remaining:
            coverage = regions[index]
            results[index] = _decode_region(
                data, image, coverage, chunk_bytes, check_cancelled,
                lambda processed, decoded, count, worker_id, index=index:
                    report(index, processed, decoded, count, worker_id), include_data=include_data,
                **({"anchors": region_anchors[index]} if index in region_anchors else {}))
            completed += 1
            report_final(index)
    else:
        updates: SimpleQueue[tuple[int, int, int, int, int | None]] = SimpleQueue()

        def drain_updates() -> None:
            while True:
                try:
                    report(*updates.get_nowait())
                except Empty:
                    break

        # 完成通知经队列送回调用线程：每次等待与区域总数无关（大量小区域时不再二次方）。
        finished_queue: SimpleQueue[int] = SimpleQueue()
        with ThreadPoolExecutor(max_workers=max(1, min(workers, len(remaining))),
                                thread_name_prefix="fangida-decode") as pool:
            pending = {}
            window_lock = Lock() if _gil_enabled() else None
            for index in remaining:
                coverage = regions[index]
                future = pool.submit(
                    _decode_region, data, image, coverage, chunk_bytes, stop.is_set,
                    lambda processed, decoded, count, worker_id, index=index:
                        updates.put((index, processed, decoded, count, worker_id)),
                    window_lock, include_data,
                    **({"anchors": region_anchors[index]} if index in region_anchors else {}))
                pending[index] = future
                future.add_done_callback(lambda _, index=index: finished_queue.put(index))
            try:
                while pending:
                    check_cancelled()
                    try:
                        done = [finished_queue.get(timeout=0.05)]
                    except Empty:
                        drain_updates()
                        continue
                    while True:
                        try:
                            done.append(finished_queue.get_nowait())
                        except Empty:
                            break
                    drain_updates()
                    for index in done:
                        results[index] = pending.pop(index).result()
                        completed += 1
                        report_final(index)
                drain_updates()
            finally:
                stop.set()
    # Earlier regions own instruction intervals, not merely instruction starts.
    # The sorted index is updated once per region; each lookup checks at most
    # two neighbours, avoiding repeated scans or inserts into the full cache.
    starts: list[int] = []
    for index in range(len(regions)):
        instructions, coverage, notes = results[index]
        for note in notes:
            _append_warning(warnings, note)
        accepted: list[int] = []
        if instructions:
            # 区域内记录按地址升序且互不重叠；若与已接受区间整体不相交则批量接受，
            # 结果与逐条检查完全相同（插入顺序也相同）。
            first = next(iter(instructions))
            last = next(reversed(instructions))
            low, high = first, last + instructions[last]["size"]
            position = bisect_left(starts, low)
            if ((position == 0 or starts[position - 1] + output[starts[position - 1]]["size"] <= low)
                    and (position == len(starts) or starts[position] >= high)
                    and _ascending(instructions)):
                output.update(instructions)
                accepted = list(instructions)
                instructions = {}
        for address, instruction in instructions.items():
            position = bisect_left(starts, address)
            end = address + instruction["size"]
            overlaps = ((position > 0 and starts[position - 1] + output[starts[position - 1]]["size"] > address)
                        or (position < len(starts) and starts[position] < end))
            if overlaps:
                _append_warning(warnings, f"Executable region {coverage['name']} overlaps instructions owned by an earlier region")
                _gap(coverage, address - coverage["address"], instruction["size"], "overlapping_region")
                coverage["decoded_bytes"] -= instruction["size"]
                coverage["instruction_count"] -= 1
                coverage["complete"] = False
                coverage["details_complete"] = False
                coverage["partial_reason"] = "overlapping executable regions"
                continue
            output[address] = instruction
            accepted.append(address)
        if accepted:
            if not starts or accepted[0] > starts[-1]:
                starts.extend(accepted)
            elif accepted[-1] < starts[0]:
                starts = accepted + starts
            else:
                starts = list(merge(starts, accepted))
        if coverage["gaps"]:
            coverage["gaps"].sort(key=lambda gap: gap["address"])
        if on_progress is not None:
            report_final(index)
    if any(region["cancelled"] for region in regions):
        _append_warning(warnings, "Full-region instruction decoding was cancelled")
    if any(any(gap["reason"] == "undecodable" for gap in region["gaps"]) for region in regions):
        _append_warning(warnings, "Executable regions contain undecodable bytes; coverage is partial")
    if region_anchors and any(any(gap["reason"] == ANCHOR_RESYNC for gap in region["gaps"])
                              for region in regions):
        _append_warning(warnings, "Linear sweep discarded instructions crossing resynchronization "
                                  "anchors and restarted at them; coverage is partial")
    return output, regions, warnings
