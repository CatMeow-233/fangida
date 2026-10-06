"""Isolated processes for chunked full-region instruction decoding.

Only the processor layer runs in a child: it receives one byte span plus the
linear-sweep parameters and returns completed instruction records. Loaders,
xref analysis and plugin orchestration are never imported there. Messages are
length-framed marshal over stdin/stdout; the child's stdout is a private pipe
that carries only this protocol, so stray output can never reach the parent's
own stdout (for example an MCP stdio transport).

The parent side owns at most ``count`` children, sends a request only after a
child's handshake, keeps at most one request per child, and polls readiness on
the calling thread without helper threads. Parent-side pipe I/O never blocks,
so a child that hangs at startup or mid-request is detected by a timeout,
killed, and its work is redone in-process.
"""
from __future__ import annotations

from bisect import bisect_right
import gc
import hashlib
import marshal
import os
import re
import struct
import sys
import time
import types
from typing import Any, Callable, Sequence

# 记录的键顺序与紧凑重建在处理器（decoder）中定义，两端共用并计入代码指纹。
from .decoder import RECORD_KEYS, record_from_row, records_from_rows  # noqa: F401（供父进程使用）

PROTOCOL = 4  # 2：一个请求携带多个作业（小区域合批）；3：作业可带第 7 项重同步锚点；
              # 4：应答中的记录可按 RECORD_KEYS 顺序以元组传输（第 5 项 ROWS），父进程重建紧凑 dict
_MAGIC = b"FDW1"
_HEADER = struct.Struct("<4sQ")
# 单条消息上限：远大于任何切块的结果，只用于拒绝损坏的帧头，避免巨量分配。
MAX_MESSAGE_BYTES = 1 << 31
# 握手消息用最老的通用 marshal 版本编码，使版本不一致的解释器也能被识别并拒绝。
_HELLO_MARSHAL_VERSION = 2

# (records 的地址列表, 指令记录, 缺口, 结束游标)。缺口按游标顺序排列：
# (区域相对起点, 字节数) 是逐步跨过的不可解码连续段；
# (区域相对起点, 字节数, ANCHOR_RESYNC) 是一步跳到锚点的重同步缺口（相邻的不合并）。
SweepResult = tuple[list[int], list[dict[str, Any]], list[tuple[Any, ...]], int]
ANCHOR_RESYNC = "anchor_resync"


def following_anchor(anchors: Sequence[int], position: int, default: int) -> int:
    """升序锚点中第一个大于 ``position`` 的值；没有时返回 ``default``。"""
    index = bisect_right(anchors, position)
    return anchors[index] if index < len(anchors) else default


class ProtocolError(OSError):
    """A child violated the framing or handshake; callers fall back in-process."""


class HandshakeMismatch(ProtocolError):
    """The child runs a different interpreter, package or Capstone build."""


def sweep(decode: Callable[..., tuple[list[dict[str, Any]], list[str]]], code: bytes,
          code_start: int, base: int, length: int, start: int, stop: int, chunk_bytes: int,
          step: int, lookahead: int, invalid_mnemonics: Any, include_data: bool,
          anchors: Sequence[int] = ()) -> SweepResult | None:
    """Linear sweep from ``start`` until the cursor reaches ``stop``.

    Region-relative position ``p`` is ``code[p - code_start]``. Windows advance
    exactly like ``full_decode._decode_region`` for the built-in Capstone path.
    Every case in which that loop would warn, or would record a gap inside a
    window, returns ``None``: the caller then decodes the whole region with the
    original loop, so warning text and order never need to be reproduced here.

    ``anchors`` (optional) are ascending region-relative resynchronization
    offsets, the same the serial loop uses for every anchor this sweep can
    reach. An instruction that would straddle one is discarded and recorded
    as an ``ANCHOR_RESYNC`` gap up to the anchor, where the sweep restarts.
    """
    addrs: list[int] = []
    records: list[dict[str, Any]] = []
    gaps: list[tuple[Any, ...]] = []
    append_addr, append_record = addrs.append, records.append
    accepted: set[str] = set()
    cursor, retry_short = start, False
    # 惰性“下一个锚点”：值 ≤ 游标即过期，仅在快速比较命中时重新二分；无锚点时为区域长度。
    next_anchor = following_anchor(anchors, start, length)
    while cursor < stop:
        window_start = cursor
        limit = min(chunk_bytes, lookahead + 1) if retry_short else chunk_bytes
        target_end = min(length, window_start + limit)
        window_end = min(length, target_end + lookahead)
        # 子进程的缓冲区可能在 stop 之后被截断；窗口起点之后始终留有 ≥ 2*lookahead 字节，
        # 被截断的只是窗口尾部，其后的指令由下一个窗口用完整字节重新解码（与串行一致）。
        window = code[window_start - code_start:window_end - code_start]
        if include_data:
            instructions, notes = decode(window, base + window_start,
                                         max_instructions=window_end - window_start, include_data=True)
        else:
            instructions, notes = decode(window, base + window_start,
                                         max_instructions=window_end - window_start)
        if notes:
            return None
        for instruction in instructions:
            get = instruction.get
            address, size, mnemonic = get("addr"), get("size"), get("mnemonic", "")
            if type(mnemonic) is not str or mnemonic not in accepted:
                if (type(mnemonic) is not str or not mnemonic or mnemonic.startswith(".")
                        or mnemonic.lower() in invalid_mnemonics):
                    return None
                accepted.add(mnemonic)
            if type(address) is not int or type(size) is not int or size <= 0:
                return None
            # 串行路径对越界记录告警、对窗口内跳过的字节记 gap；两者都依赖窗口划分，交给串行处理。
            if address - base != cursor or cursor + size > window_end:
                return None
            if cursor + size > next_anchor:
                if next_anchor <= cursor:
                    next_anchor = following_anchor(anchors, cursor, length)
                if cursor + size > next_anchor:
                    # 跨越锚点：丢弃该指令及本窗口其后的指令，与串行循环一样从锚点开新窗口。
                    gaps.append((cursor, next_anchor - cursor, ANCHOR_RESYNC))
                    cursor = next_anchor
                    break
            append_addr(address)
            append_record(instruction)
            cursor += size
        if cursor == window_start:
            advance = min(step, length - cursor)
            if cursor + advance > next_anchor:
                if next_anchor <= cursor:
                    next_anchor = following_anchor(anchors, cursor, length)
                if cursor + advance > next_anchor:
                    # 步进会越过锚点（只在定长指令集的游标偏离网格时可能）：交给串行循环。
                    return None
            if gaps and len(gaps[-1]) == 2 and gaps[-1][0] + gaps[-1][1] == cursor:
                gaps[-1] = (gaps[-1][0], gaps[-1][1] + advance)
            else:
                gaps.append((cursor, advance))
            cursor += advance
            retry_short = True
        else:
            retry_short = False
    return addrs, records, gaps, cursor


# 应答第 5 项的标记：该作业的记录是按 RECORD_KEYS 顺序的元组（行），不是 dict。
ROWS = "rows"
_SCALARS = frozenset({int, str, bool, float, bytes, type(None)})


def _frozen(value: Any) -> Any:
    """可哈希、带类型标记的递归冻结键：等值但类型不同的标量（1/True/1.0）不会被当成同一值。

    字典的键顺序也是内容的一部分；列表等不支持的类型抛出 TypeError（调用方保留原对象）。
    """
    kind = type(value)
    if kind is str or kind is int:
        return (kind, value)
    if kind is dict:
        return ("d",) + tuple([(_frozen(key), _frozen(item)) for key, item in value.items()])
    if kind is tuple:
        return ("t",) + tuple([_frozen(item) for item in value])
    if kind in _SCALARS:
        return (kind, value)
    raise TypeError(f"unshareable {kind.__name__}")


def _share_dict(canonical: dict[Any, Any], key: str, value: dict[str, Any]) -> dict[str, Any]:
    """返回与 value 值相同（含键顺序）的共享字典；首次出现的值登记为共享实例。"""
    try:
        # 带类型标记，避免与同值的元组/字符串键冲突；键顺序也是内容的一部分。
        return canonical.setdefault((key, tuple(value.items())), value)
    except TypeError:
        pass  # 含字典等不可哈希的值（如 address_operation）：改用冻结键
    try:
        marker = (key, _frozen(value))
    except TypeError:
        return value  # 含列表等无法冻结的值：保留独立对象
    found = canonical.get(marker)
    if found is None:
        # 首次出现：嵌套字典（address_operation）同样按冻结键共享后再登记。
        for name, item in value.items():
            if type(item) is dict:
                value[name] = canonical.setdefault((name, _frozen(item)), item)
        found = canonical[marker] = value
    return found


def share_records(results: list[Any]) -> None:
    """在一个应答帧内把值相同的子对象换成同一个实例（值逐字不变），并把记录换成行。

    marshal 在同一次 dumps 内按对象身份去重，父进程 loads 后得到的也是共享对象：
    指令记录里大量重复的 arch_meta / branch_info 字典、operands/reads/writes 元组
    （以及元组内的寄存器名、操作数字符串）与助记符字符串只占一份内存，反序列化也更快
    （实测完整指令记录约 762 字节/条，几千万条指令时内存超过物理内存而大量换页）。
    含嵌套字典（address_operation）的 arch_meta 按带类型标记的冻结键共享。

    一个作业的记录全部是键与键顺序都为 RECORD_KEYS 的 dict 时，改为按该顺序的元组，
    结果变为 ``(地址列表, 行列表, 缺口, 结束游标, ROWS)``：帧不再逐条携带键（约小 44%），
    父进程用 ``records_from_rows`` 重建与原记录逐值相同的紧凑 dict。其他作业原样发送。
    解码记录在交付后不再被就地修改（各层只读这些子对象）。
    """
    canonical: dict[Any, Any] = {}
    shared = canonical.setdefault
    tuples: dict[tuple[Any, ...], tuple[Any, ...]] = {}

    def share_tuple(value: tuple[Any, ...]) -> tuple[Any, ...]:
        # 每个不同的元组只重建一次：元组内的字符串也按值共享（marshal 因此只写一次）。
        try:
            found = tuples.get(value)
            if found is None:
                found = tuples[value] = tuple([shared(item, item) if type(item) is str else item
                                               for item in value])
            return found
        except TypeError:
            return value  # 含不可哈希的元素：保留原元组

    for index, result in enumerate(results):
        if result is None:
            continue
        rows: list[tuple[Any, ...]] | None = []
        append = rows.append
        for record in result[1]:
            if type(record) is not dict or tuple(record) != RECORD_KEYS:
                rows = None
                break
            address, size, mnemonic, operands, reads, writes, branch, metadata = record.values()
            if type(mnemonic) is str:
                mnemonic = shared(mnemonic, mnemonic)
            # 已见过的元组直接取共享实例（常见情形不进入函数调用）；空元组本身就是单例。
            if type(operands) is tuple and operands:
                try:
                    operands = tuples[operands]
                except (KeyError, TypeError):
                    operands = share_tuple(operands)
            if type(reads) is tuple and reads:
                try:
                    reads = tuples[reads]
                except (KeyError, TypeError):
                    reads = share_tuple(reads)
            if type(writes) is tuple and writes:
                try:
                    writes = tuples[writes]
                except (KeyError, TypeError):
                    writes = share_tuple(writes)
            if type(branch) is dict:
                try:
                    branch = shared(("branch_info", tuple(branch.items())), branch)
                except TypeError:
                    branch = _share_dict(canonical, "branch_info", branch)
            if type(metadata) is dict:
                try:
                    metadata = shared(("arch_meta", tuple(metadata.items())), metadata)
                except TypeError:
                    metadata = _share_dict(canonical, "arch_meta", metadata)
            append((address, size, mnemonic, operands, reads, writes, branch, metadata))
        if rows is not None:
            results[index] = (result[0], rows, result[2], result[3], ROWS)
            continue
        # 非标准形状的作业：只在原记录上共享子对象，仍以 dict 发送。
        for record in result[1]:
            if type(record) is not dict:
                continue
            mnemonic = record.get("mnemonic")
            if type(mnemonic) is str:
                record["mnemonic"] = shared(mnemonic, mnemonic)
            for key in ("operands", "reads", "writes"):
                value = record.get(key)
                if type(value) is tuple:
                    record[key] = share_tuple(value)
            for key in ("branch_info", "arch_meta"):
                value = record.get(key)
                if type(value) is dict:
                    record[key] = _share_dict(canonical, key, value)


def _read_exact(stream: Any, size: int) -> bytearray:
    buffer = bytearray(size)
    view, received = memoryview(buffer), 0
    while received < size:
        count = stream.readinto(view[received:])
        if not count:
            raise EOFError("decode worker closed its pipe")
        received += count
    return buffer


def read_frame(stream: Any) -> bytearray:
    magic, size = _HEADER.unpack(bytes(_read_exact(stream, _HEADER.size)))
    if magic != _MAGIC or size > MAX_MESSAGE_BYTES:
        raise ProtocolError("invalid decode worker frame")
    return _read_exact(stream, size)


def read_message(stream: Any) -> Any:
    return marshal.loads(read_frame(stream))


def write_message(stream: Any, value: Any, version: int = marshal.version) -> None:
    payload = marshal.dumps(value, version)
    for part in (_HEADER.pack(_MAGIC, len(payload)), payload):
        view = memoryview(part)
        while view:
            written = stream.write(view)
            if written is None:
                raise BlockingIOError("decode worker pipe is not writable")
            view = view[written:]
    flush = getattr(stream, "flush", None)
    if flush is not None:
        flush()


def package_directory() -> str:
    """The fangida package used by this interpreter, normalised for comparison."""
    return os.path.normcase(os.path.realpath(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def capstone_identity() -> tuple[Any, ...] | None:
    try:
        import capstone  # type: ignore[import-not-found]
        return (str(getattr(capstone, "__version__", "")), tuple(capstone.cs_version()))
    except Exception:
        # 可选依赖探测：未安装或动态库加载失败都记为 None，仅作握手比较键；两端不一致会触发 HandshakeMismatch 回退进程内解码。
        return None


def _feed(digest: Any, value: Any, module: str, depth: int = 0) -> None:
    """Hash loaded code and constants deterministically (no ids, no hash seeds)."""
    if depth > 8:
        return
    if isinstance(value, types.CodeType):
        digest.update(value.co_code)
        digest.update(repr((value.co_names, value.co_varnames, value.co_argcount,
                            value.co_kwonlyargcount, value.co_flags)).encode())
        for constant in value.co_consts:
            _feed(digest, constant, module, depth + 1)
    elif isinstance(value, (types.FunctionType, staticmethod, classmethod, property)):
        function = getattr(value, "__func__", None) or getattr(value, "fget", None) or value
        digest.update(getattr(function, "__qualname__", "").encode())
        _feed(digest, getattr(function, "__code__", None), module, depth + 1)
        for default in (getattr(function, "__defaults__", None), getattr(function, "__kwdefaults__", None)):
            _feed(digest, default, module, depth + 1)
    elif isinstance(value, type):
        digest.update(value.__qualname__.encode())
        if value.__module__ == module:
            for name, member in vars(value).items():
                digest.update(name.encode())
                _feed(digest, member, module, depth + 1)
    elif isinstance(value, (set, frozenset)):
        digest.update(repr(sorted(map(repr, value))).encode())
    elif isinstance(value, dict):
        for key in sorted(value, key=repr):
            digest.update(repr(key).encode())
            _feed(digest, value[key], module, depth + 1)
    elif isinstance(value, (tuple, list)):
        digest.update(f"{type(value).__name__}{len(value)}".encode())
        for item in value:
            _feed(digest, item, module, depth + 1)
    elif value is None or isinstance(value, (str, bytes, int, float, complex, re.Pattern)):
        digest.update(repr(value).encode())
    else:
        digest.update(type(value).__qualname__.encode())


def _compute_fingerprint() -> str:
    from . import decoder

    digest = hashlib.sha256()
    for name, value in sorted(vars(decoder).items()):
        # 跳过模块元信息（__builtins__ 在 IPython 等宿主中会多出条目）与导入的模块/外部定义。
        if name.startswith("__") or isinstance(value, types.ModuleType) or (
                isinstance(value, (type, types.FunctionType))
                and value.__module__ != decoder.__name__):
            continue
        digest.update(name.encode())
        _feed(digest, value, decoder.__name__)
    _feed(digest, sweep, __name__)
    _feed(digest, following_anchor, __name__)
    # 应答的行格式与共享方式也是协议的一部分：两端代码不同则握手失败、回退进程内解码。
    for value in (share_records, _share_dict, _frozen, ROWS, _SCALARS):
        _feed(digest, value, __name__)
    return digest.hexdigest()


# 导入本模块时（父进程导入 full_decode 时、子进程启动时）立即计算：之后对 decoder 模块
# 的运行时替换（例如测试中的 Mock）不会被算进指纹，也就不会让本进程永久误判为不一致。
try:
    _FINGERPRINT: str | None = _compute_fingerprint()
except Exception:  # 指纹只用于握手；导入阶段异常时推迟到首次握手再算
    _FINGERPRINT = None


def code_fingerprint() -> str:
    """Fingerprint of the decoder code this interpreter loaded, taken at import.

    A parent whose modules were edited on disk after import would otherwise
    start children running different decoding code; the handshake rejects it.
    """
    global _FINGERPRINT
    if _FINGERPRINT is None:
        _FINGERPRINT = _compute_fingerprint()
    return _FINGERPRINT


def hello() -> tuple[Any, ...]:
    """Identity checked by the parent before any decoded record is trusted."""
    return ("fangida-decode-worker", PROTOCOL, sys.hexversion, capstone_identity(),
            package_directory(), code_fingerprint())


def worker_command() -> list[str]:
    # 沿用父进程的解释器选项（-B、-O、-I、-X 等）：不写字节码的约定与编译出的代码保持一致。
    import subprocess

    flags = getattr(subprocess, "_args_from_interpreter_flags", lambda: [])()
    return [sys.executable, *flags, "-m", "fangida.processors._decode_worker"]


def main() -> int:
    # 协议独占原 stdout 管道；其余任何输出（包括 C 层 printf）都改到 stderr，父进程会丢弃。
    output = os.fdopen(os.dup(1), "wb", buffering=0)
    os.dup2(2, 1)
    sys.stdout = sys.stderr
    source = os.fdopen(os.dup(0), "rb", buffering=0)
    from .decoder import NativeDecoder

    write_message(output, hello(), _HELLO_MARSHAL_VERSION)
    from .._gc import enabled as gc_pause_enabled
    pause_gc = gc_pause_enabled() and gc.isenabled()
    decoders: dict[tuple[str, str], Any] = {}
    while True:
        try:
            request = read_message(source)
        except EOFError:
            return 0
        (task, architecture, endian, chunk_bytes, step, lookahead, invalid_mnemonics,
         include_data, jobs) = request
        try:
            decoder = decoders.get((architecture, endian))
            if decoder is None:
                decoder = decoders[(architecture, endian)] = NativeDecoder(architecture, endian)
            usable = decoder.engine == "capstone" and not decoder.warning
        except Exception:
            usable = False
        results: list[SweepResult | None] = []
        # 一个请求可以携带多个作业（大区域的一块，或若干个完整的小区域）；逐个独立扫描。
        # 扫描结果全部要发回父进程，期间的自动循环 GC 只会反复遍历它们，因此暂停。
        if pause_gc:
            gc.disable()
        try:
            for job in jobs:
                try:
                    # 作业为六元组，或带第 7 项（块内的区域相对锚点，升序）的七元组。
                    base, length, code_start, start, stop, code = job[:6]
                    anchors = job[6] if len(job) > 6 else ()
                    results.append(sweep(decoder.decode_bytes_fast, code, code_start, base, length,
                                         start, stop, chunk_bytes, step, lookahead, invalid_mnemonics,
                                         include_data, anchors) if usable else None)
                except Exception:
                    # 未预期的解码异常：让父进程用原串行循环重做该区域，由它产生既有告警文本。
                    results.append(None)
            share_records(results)
            write_message(output, (task, results))
        finally:
            if pause_gc:
                gc.enable()
        del results


def frame_bytes(value: Any, version: int = marshal.version) -> bytes:
    """One length-framed marshal message, as ``write_message`` would send it."""
    payload = marshal.dumps(value, version)
    return _HEADER.pack(_MAGIC, len(payload)) + payload


# 握手消息只有几十字节；未握手的子进程声明更大的帧即视为协议错误，不为它分配内存。
_MAX_HELLO_BYTES = 1 << 16
# Windows 匿名管道无法查询剩余空间：子进程 stdin 管道的缓冲按“一整条请求”设置，
# 写入空管道立即完成，子进程中途停止读取也不会阻塞父进程（请求上限约 300KiB）。
WINDOWS_PIPE_BYTES = 1 << 21
_INFINITE = float("inf")


class DecodeProcessPool:
    """Parent side: a bounded set of persistent children for one decode call.

    Requests go only to children that completed the handshake, and each child
    has at most one outstanding request. All pipe I/O is non-blocking and
    polled on the calling thread (selectors on POSIX, PeekNamedPipe on
    Windows): partial request writes and partial response frames are kept per
    child, so a child that hangs, stops reading or stops writing can never
    block the parent. ``stall`` accumulates the time the parent spent waiting
    on a child without any I/O progress; ``expired`` reports children past
    their limit (``start_timeout`` before the handshake, the per-request
    timeout afterwards) and ``drop`` kills one. Children run in their own
    process group or kill-on-close Job Object and are killed and reaped by
    ``drop``/``close``; their stderr is discarded.
    """

    def __init__(self, count: int, expected: tuple[Any, ...],
                 start_timeout: float = _INFINITE) -> None:
        if type(count) is not int or count < 1:
            raise ValueError("count must be a positive integer")
        self.count, self.expected, self.start_timeout = count, expected, start_timeout
        self.trees: list[Any] = []
        self.greeted: list[bool] = []
        self.busy: list[bool] = []
        self.alive: list[bool] = []
        self.stall: list[float] = []
        self._limit: list[float] = []
        self._outbox: list[memoryview | None] = []
        self._header: list[bytearray] = []
        self._payload: list[bytearray | None] = []
        self._received: list[int] = []

    def start(self) -> None:
        import subprocess
        from .. import processes

        root = os.path.dirname(package_directory())
        environment = dict(os.environ)
        # -m 以 cwd 为 sys.path[0]；PYTHONSAFEPATH 等情形再由 PYTHONPATH 保证导入同一份包。
        environment["PYTHONPATH"] = os.pathsep.join(
            filter(None, (root, environment.get("PYTHONPATH"))))
        extra: dict[str, Any] = {}
        if os.name == "nt":
            extra["creationflags"] = 0x08000000  # CREATE_NO_WINDOW：GUI 宿主下不弹控制台
        for _ in range(self.count):
            stdin: Any = subprocess.PIPE
            writer = None
            if os.name == "nt":
                try:
                    stdin, writer = processes.input_pipe(WINDOWS_PIPE_BYTES)
                except OSError:
                    stdin, writer = subprocess.PIPE, None  # 退回标准管道：握手后子进程总在读取
            try:
                tree = processes.start_process(
                    worker_command(), stdin=stdin, stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL, bufsize=0, cwd=root, env=environment, **extra)
            except BaseException:
                if writer is not None:
                    writer.close()
                raise
            finally:
                if writer is not None:
                    os.close(stdin)  # 子进程已持有自己的可继承副本
            if writer is not None:
                tree.process.stdin = writer
            self.trees.append(tree)
            self.greeted.append(False)
            self.busy.append(False)
            self.alive.append(True)
            self.stall.append(0.0)
            self._limit.append(self.start_timeout)
            self._outbox.append(None)
            self._header.append(bytearray(_HEADER.size))
            self._payload.append(None)
            self._received.append(0)
            processes.set_nonblocking(tree.process.stdin)
            processes.set_nonblocking(tree.process.stdout)

    def idle(self) -> list[int]:
        """Live children that completed the handshake and have no request."""
        return [index for index in range(len(self.trees))
                if self.alive[index] and self.greeted[index] and not self.busy[index]]

    def starting(self) -> bool:
        """Whether a live child is still expected to send its handshake."""
        return any(alive and not greeted for alive, greeted in zip(self.alive, self.greeted))

    def live(self) -> int:
        return sum(self.alive)

    @property
    def pids(self) -> list[int]:
        return [tree.process.pid for tree in self.trees]

    def submit(self, index: int, request: tuple[Any, ...], timeout: float = _INFINITE,
               burst: float = 0.0) -> None:
        """Queue one request for a greeted idle child and start writing it.

        Up to ``burst`` seconds are spent writing right away (the child is
        blocked reading, so the pipe drains immediately); the rest is written
        by ``collect``. ``timeout`` bounds the child's time without progress.
        """
        if not self.alive[index] or not self.greeted[index] or self.busy[index]:
            raise ProtocolError("decode worker is not ready for a request")
        self.busy[index] = True
        self.stall[index] = 0.0
        self._limit[index] = timeout
        self._outbox[index] = memoryview(frame_bytes(request))
        self._write(index, burst)

    def _write(self, index: int, burst: float = 0.0) -> bool:
        from ..processes import wait_streams, write_available

        stream = self.trees[index].process.stdin
        deadline = time.monotonic() + burst
        progressed = False
        while True:
            view = self._outbox[index]
            if view is None:
                return progressed
            written = write_available(stream, view)
            if written:
                progressed = True
                view = view[written:]
                self._outbox[index] = view if len(view) else None
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return progressed
            wait_streams([], [stream], remaining)

    def _read(self, index: int) -> tuple[bool, bytearray | None]:
        """Read what is available; returns (progress, completed frame or None)."""
        from ..processes import read_available

        stream = self.trees[index].process.stdout
        progressed = False
        while True:
            payload = self._payload[index]
            target = self._header[index] if payload is None else payload
            received = self._received[index]
            count = read_available(stream, memoryview(target)[received:])
            if count is None:
                return progressed, None
            if not count:
                raise EOFError("decode worker closed its pipe")
            progressed = True
            received += count
            self._received[index] = received
            if received < len(target):
                continue
            if payload is None:
                magic, size = _HEADER.unpack(bytes(target))
                limit = MAX_MESSAGE_BYTES if self.greeted[index] else _MAX_HELLO_BYTES
                if magic != _MAGIC or size > limit:
                    raise ProtocolError("invalid decode worker frame")
                self._payload[index], self._received[index] = bytearray(size), 0
                if size:
                    continue
            frame = self._payload[index]
            self._payload[index], self._received[index] = None, 0
            return True, frame

    def collect(self, timeout: float) -> list[tuple[int, bytearray]]:
        """Advance pending writes and reads; return completed response frames.

        Handshakes are verified here and never returned. Frames are returned
        undecoded so the caller can hand freed children their next request
        before spending time on deserialisation. EOF or a framing error
        raises; a handshake that differs raises ``HandshakeMismatch``.
        """
        from ..processes import wait_streams

        started = time.monotonic()
        live = [index for index in range(len(self.trees)) if self.alive[index]]
        progressed = {index for index in live if self._outbox[index] is not None and self._write(index)}
        readers = [index for index in live if not self.greeted[index] or self.busy[index]]
        writers = [index for index in live if self._outbox[index] is not None]
        read_streams = [self.trees[index].process.stdout for index in readers]
        write_streams = [self.trees[index].process.stdin for index in writers]
        ready_read, ready_write = wait_streams(read_streams, write_streams, timeout)
        ready = {id(stream) for stream in ready_write}
        for index, stream in zip(writers, write_streams):
            if id(stream) in ready and self._write(index):
                progressed.add(index)
        ready = {id(stream) for stream in ready_read}
        responses = []
        for index, stream in zip(readers, read_streams):
            if id(stream) not in ready:
                continue
            moved, frame = self._read(index)
            if moved:
                progressed.add(index)
            if frame is None:
                continue
            if not self.greeted[index]:
                if marshal.loads(frame) != self.expected:
                    raise HandshakeMismatch("decode worker identity differs from the parent")
                self.greeted[index] = True
                continue
            if self._outbox[index] is not None:
                raise ProtocolError("decode worker answered before reading its request")
            self.busy[index] = False
            responses.append((index, frame))
        # 只累计父进程实际在等待该子进程、且它没有任何读写进展的时间：父进程忙于拼接时不计。
        elapsed = time.monotonic() - started
        for index in live:
            if index in progressed or not (self.busy[index] or not self.greeted[index]):
                self.stall[index] = 0.0
            else:
                self.stall[index] += elapsed
        return responses

    def expired(self) -> list[int]:
        """Live children whose handshake or request made no progress for too long."""
        return [index for index in range(len(self.trees))
                if self.alive[index] and (self.busy[index] or not self.greeted[index])
                and self.stall[index] > (self._limit[index] if self.greeted[index]
                                         else self.start_timeout)]

    def drop(self, index: int) -> None:
        """Kill and reap one child; its outstanding request is abandoned."""
        self.alive[index] = self.busy[index] = False
        self._outbox[index] = self._payload[index] = None
        self._close_tree(self.trees[index])

    @staticmethod
    def _close_tree(tree: Any) -> None:
        try:
            tree.close()
        except OSError:
            pass
        for stream in (tree.process.stdin, tree.process.stdout):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass

    def close(self) -> None:
        for tree in self.trees:
            self._close_tree(tree)
        self.trees = []
        self.greeted, self.busy, self.alive, self.stall = [], [], [], []
        self._limit, self._outbox, self._header, self._payload, self._received = [], [], [], [], []

    def __enter__(self) -> DecodeProcessPool:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


if __name__ == "__main__":
    raise SystemExit(main())
