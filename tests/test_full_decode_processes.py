"""full 模式多进程切块解码：与串行逐字段一致、回退、取消、进程与线程约束。

阈值与块大小在测试中调小（每块 0x300 字节，每个区域都切成多块），覆盖：
  - x86-64 类真实代码、EB/B8 相位不收敛字节、随机字节、区域超出文件、多区域共用子进程；
  - ARM/ARM64 小端/大端随机字（块起点按 4 对齐）；
  - 子进程启动失败、握手不一致、协议垃圾、中途崩溃均静默回退且结果不变；
  - 子进程启动挂起、处理请求中途挂起、握手后不再读取请求：超时后杀掉并回退，取消立即返回；
  - 回退时进度不倒退，processes_used 只统计结果被区域采用的子进程；小区域按块合批；
  - 代码指纹在导入时固定，运行时替换 decoder 中的名字不会让进程路径永久失效；
  - 解码中途取消：只保留从区域起点连续拼接的前缀 + cancelled 缺口，子进程全部回收；
  - workers=1、第三方/替换的处理器、被替换的快路径、环境变量关闭时不启动子进程；
  - 进程数不超过 workers，父进程不新建线程，子进程 stdout 不进入父进程 stdout。
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import importlib.util
import json
import os
import random
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from typing import Any, Iterator
from unittest.mock import patch

from fangida import processes, processors
from fangida.loaders.models import BinaryImage
from fangida.processors import _decode_worker, full_decode
from fangida.processors.decoder import NativeDecoder
from fangida.processors.full_decode import stream_decode_regions

CAPSTONE_AVAILABLE = importlib.util.find_spec("capstone") is not None
BASE = 0x400000


def _x86_code(size: int, seed: int) -> bytes:
    """变长 x86-64 指令流（序言、RIP 相对、调用、分支、长 nop、movabs），夹杂少量随机字节。"""
    rng = random.Random(seed)
    templates = ("55", "4889e5", "4883ec{b}", "48897df8", "e8{d}", "488d05{d}", "488b05{d}",
                 "0f84{d}", "74{b}", "eb{b}", "c3", "0f1f440000", "660f1f840000000000",
                 "48b8{q}", "f30f1efa", "c5f877", "ff15{d}", "cc", "4c8d0c{b}", "41ff24c4")
    out = bytearray()
    while len(out) < size:
        if rng.random() < 0.01:
            out += rng.randbytes(rng.randrange(1, 24))
            continue
        text = rng.choice(templates).format(b=rng.randbytes(1).hex(), d=rng.randbytes(4).hex(),
                                            q=rng.randbytes(8).hex())
        out += bytes.fromhex(text)
    return bytes(out[:size])


def _image(architecture: str, endian: str, sizes: list[int], declared: dict[int, int] | None = None
           ) -> BinaryImage:
    sections, offset = [], 0
    for index, size in enumerate(sizes):
        sections.append({"name": f".text{index}", "address": BASE + offset + 0x100 * index,
                         "offset": offset, "size": (declared or {}).get(index, size),
                         "executable": True})
        offset += size
    return BinaryImage("elf", architecture, 64 if architecture in {"x86_64", "arm64"} else 32,
                       endian, entry_address=BASE, sections=sections)


def _canonical(result: tuple[Any, ...]) -> str:
    records, coverage, warnings = result
    coverage = [{key: value for key, value in item.items() if key != "worker_id"} for item in coverage]
    return json.dumps([list(records.items()), coverage, warnings], default=list)


class _Spawned:
    """记录本次调用启动的子进程，用于检查进程数上限与回收（无僵尸）。"""

    def __init__(self) -> None:
        self.trees: list[Any] = []
        self.real = processes.start_process

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        tree = self.real(*args, **kwargs)
        self.trees.append(tree)
        return tree

    def assert_reaped(self, case: unittest.TestCase) -> None:
        for tree in self.trees:
            case.assertIsNotNone(tree.process.returncode, "child process was not reaped")
            case.assertTrue(tree.process.stdin.closed and tree.process.stdout.closed)
            if os.name == "posix":
                with case.assertRaises(ChildProcessError):
                    os.waitpid(tree.process.pid, os.WNOHANG)


@contextmanager
def _small_pieces(overlap: int = 24) -> Iterator[_Spawned]:
    """调低阈值与块大小；同步重叠很小，使部分块必须由父进程串行补扫后才能对齐。"""
    spawned = _Spawned()
    with ExitStack() as stack:
        stack.enter_context(patch.object(full_decode, "_PROCESS_MIN_BYTES", 0x1000))
        stack.enter_context(patch.object(full_decode, "_PROCESS_MIN_PIECE_BYTES", 0x100))
        stack.enter_context(patch.object(full_decode, "_PROCESS_PIECE_BYTES", 0x300))
        stack.enter_context(patch.object(full_decode, "_SYNC_OVERLAP", overlap))
        stack.enter_context(patch.object(full_decode, "_RESYNC_WINDOW", 48))
        stack.enter_context(patch.object(full_decode, "_process_mismatch", False))
        stack.enter_context(patch.dict(os.environ, {"FANGIDA_DECODE_PROCESSES": ""}))
        stack.enter_context(patch.object(processes, "start_process", side_effect=spawned))
        yield spawned


def _worker_script(body: str) -> list[str]:
    """替换子进程命令：在真实 worker 模块上注入故障后再运行。

    代码指纹在导入 worker 模块时已固定，注入的包装函数不会被握手当成“不同的解码代码”。
    """
    return [sys.executable, "-c", "import os, sys, time\n"
            "from fangida.processors import _decode_worker as w\n"
            "w.code_fingerprint()\n" + body]


# 挂起的子进程只休眠 60 秒：正常情况下会被超时或取消杀掉；即使测试进程本身被外部
# 强杀（子进程在独立会话中），残留的子进程也会自行退出。
# 握手后挂起：第二次扫描（已读完请求）时休眠。
_HANG_ON_SECOND_SWEEP = _worker_script(
    "real = w.sweep\ncount = [0]\n"
    "def sweep(*args, **kwargs):\n"
    "    count[0] += 1\n"
    "    if count[0] > 1:\n        time.sleep(60)\n"
    "    return real(*args, **kwargs)\n"
    "w.sweep = sweep\nw.main()\n")
# 解释器启动后一直不发握手（相当于启动阶段挂起的伪解释器）。
_HANG_BEFORE_HELLO = [sys.executable, "-c", "import time; time.sleep(60)"]


def _assert_prefix(case: unittest.TestCase, serial: dict[int, Any], result: tuple[Any, ...]) -> None:
    """取消结果：每个区域都是串行结果从区域起点开始的连续前缀，其后是 cancelled 缺口。"""
    records, coverage, warnings = result
    for region in coverage:
        low, high = region["address"], region["address"] + region["size"]
        mine = [address for address in records if low <= address < high]
        expected = [address for address in serial if low <= address < high]
        case.assertEqual(mine, expected[:len(mine)])
        case.assertTrue(all(records[address] == serial[address] for address in mine))
        case.assertEqual(region["decoded_bytes"], sum(records[address]["size"] for address in mine))
        if region["cancelled"]:
            tail = region["gaps"][-1]
            case.assertEqual((tail["reason"], tail["address"] + tail["size"]), ("cancelled", high))
    case.assertIn("Full-region instruction decoding was cancelled", warnings)


@unittest.skipUnless(CAPSTONE_AVAILABLE, "Capstone is required for the process decoding path")
class ProcessDecodeEquivalenceTests(unittest.TestCase):
    def _assert_same(self, data: bytes, image: BinaryImage, *, workers: int = 3,
                     overlap: int = 24, flags: tuple[bool, ...] = (False, True)) -> None:
        serial = [_canonical(stream_decode_regions(data, image, include_data=flag))
                  for flag in flags]
        with _small_pieces(overlap) as spawned:
            for flag, expected in zip(flags, serial):
                diagnostics: dict[str, Any] = {}
                result = stream_decode_regions(data, image, workers=workers, include_data=flag,
                                               processes=True, diagnostics=diagnostics)
                self.assertEqual(diagnostics["process_regions"], len(image.sections))
                self.assertGreaterEqual(diagnostics["processes_used"], 2)
                self.assertEqual(_canonical(result), expected)
        self.assertLessEqual(len(spawned.trees), 2 * workers)
        spawned.assert_reaped(self)

    def test_x86_64_real_code_nonconverging_phases_outside_file_and_multiple_regions(self):
        regions = [_x86_code(0x3000, 1), b"\xeb" * 0x901, b"\xb8" * 0x903,
                   random.Random(2).randbytes(0x800), _x86_code(0x600, 3)]
        data = b"".join(regions)
        # 最后一个区域声明的大小超出文件，形成 outside_file 缺口。
        image = _image("x86_64", "little", [len(item) for item in regions],
                       declared={len(regions) - 1: 0x800})
        self._assert_same(data, image)
        # 重叠区足够大时块间直接同步，不走补扫路径。
        self._assert_same(data, image, workers=2, overlap=512, flags=(True,))

    def test_x86_32_reinterpreted_code(self):
        data = _x86_code(0x2000, 4)
        self._assert_same(data, _image("x86", "little", [len(data)]))

    def test_arm_and_arm64_random_words_both_endians(self):
        rng = random.Random(5)
        for architecture in ("arm64", "arm"):
            for endian in ("little", "big"):
                with self.subTest(architecture=architecture, endian=endian):
                    # 非 4 倍数长度：最后一步缺口只前进剩余字节。
                    data = rng.randbytes(0x1802)
                    self._assert_same(data, _image(architecture, endian, [len(data)]))


@unittest.skipUnless(CAPSTONE_AVAILABLE, "Capstone is required for the process decoding path")
class ProcessDecodeControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = _x86_code(0x3000, 11) + b"\xeb" * 0x601
        cls.image = _image("x86_64", "little", [0x3000, 0x601])
        cls.serial = _canonical(stream_decode_regions(cls.data, cls.image, include_data=True))

    def _run(self, **kwargs: Any) -> tuple[str, dict[str, Any]]:
        diagnostics: dict[str, Any] = {}
        result = stream_decode_regions(self.data, self.image, include_data=True,
                                       diagnostics=diagnostics, **kwargs)
        return _canonical(result), diagnostics

    def test_failures_fall_back_silently_without_changing_output(self):
        crash_after_first = (
            "real = w.sweep\ncount = [0]\n"
            "def sweep(*args, **kwargs):\n"
            "    count[0] += 1\n"
            "    if count[0] > 1:\n        os._exit(3)\n"
            "    return real(*args, **kwargs)\n"
            "w.sweep = sweep\nw.main()\n")
        failures = {
            "spawn": None,
            "exit_before_hello": _worker_script("os._exit(2)\n"),
            "garbage": _worker_script("os.write(1, b'garbage-before-protocol')\nw.main()\n"),
            "crash_mid_run": _worker_script(crash_after_first),
            "bad_frame": _worker_script(
                "w.write_message(os.fdopen(1, 'wb', buffering=0, closefd=False), w.hello(), 2)\n"
                "os.write(1, b'FDW1' + b'\\xff' * 8)\nsys.stdin.buffer.read()\n"),
        }
        for name, command in failures.items():
            with self.subTest(failure=name), _small_pieces() as spawned:
                if command is None:
                    context = patch.object(processes, "start_process", side_effect=OSError("no fork"))
                else:
                    context = patch.object(_decode_worker, "worker_command", return_value=command)
                with context:
                    output, diagnostics = self._run(workers=3, processes=True)
                self.assertEqual(output, self.serial)
                self.assertEqual(diagnostics, {"processes_used": 0, "process_regions": 0})
                self.assertFalse(full_decode._process_mismatch)
                spawned.assert_reaped(self)

    def test_handshake_mismatch_disables_processes_for_this_interpreter(self):
        wrong = _worker_script("w.write_message(os.fdopen(1, 'wb', buffering=0, closefd=False), "
                               "('fangida-decode-worker', -1), 2)\nsys.stdin.buffer.read()\n")
        with _small_pieces() as spawned:
            with patch.object(_decode_worker, "worker_command", return_value=wrong):
                output, diagnostics = self._run(workers=3, processes=True)
            self.assertEqual(output, self.serial)
            self.assertTrue(full_decode._process_mismatch)
            started = len(spawned.trees)
            output, diagnostics = self._run(workers=3, processes=True)
            self.assertEqual((output, len(spawned.trees)), (self.serial, started))
            self.assertEqual(diagnostics["processes_used"], 0)
            spawned.assert_reaped(self)

    def test_cancel_keeps_contiguous_prefix_and_reaps_children(self):
        serial_records, _, _ = stream_decode_regions(self.data, self.image, include_data=True)
        events: list[dict[str, Any]] = []
        callers: set[int] = set()

        def progress(event: dict[str, Any]) -> None:
            callers.add(threading.get_ident())
            events.append(event)

        def cancelled() -> bool:
            callers.add(threading.get_ident())
            return bool(events)

        with _small_pieces() as spawned:
            records, coverage, warnings = stream_decode_regions(
                self.data, self.image, workers=3, include_data=True, processes=True,
                is_cancelled=cancelled, on_progress=progress)
        self.assertEqual(callers, {threading.get_ident()})
        first = coverage[0]
        self.assertTrue(first["cancelled"])
        tail = first["gaps"][-1]
        self.assertEqual(tail["reason"], "cancelled")
        self.assertEqual(tail["address"] + tail["size"], first["address"] + first["size"])
        cut = tail["address"]
        self.assertGreater(cut, first["address"])
        self.assertLess(cut, first["address"] + first["size"])
        prefix = {address: record for address, record in serial_records.items()
                  if first["address"] <= address < cut}
        self.assertEqual({address: records[address] for address in records
                          if first["address"] <= address < first["address"] + first["size"]}, prefix)
        self.assertEqual(first["decoded_bytes"], sum(item["size"] for item in prefix.values()))
        self.assertEqual(first["decoded_bytes"] + sum(gap["size"] for gap in first["gaps"]),
                         first["size"])
        self.assertEqual(first["partial_reason"], "cancelled")
        self.assertFalse(first["complete"])
        self.assertTrue(coverage[1]["cancelled"])
        self.assertIn("Full-region instruction decoding was cancelled", warnings)
        self.assertTrue(spawned.trees)
        spawned.assert_reaped(self)

    def test_disabled_cases_do_not_start_processes(self):
        class Registered(NativeDecoder):
            pass

        replaced = processors.ProcessorRegistry()
        replaced.register("x86_64", Registered)
        same_class = processors.ProcessorRegistry()
        same_class.register("x86_64", lambda architecture, endian: NativeDecoder(architecture, endian))
        cases = {
            "single_worker": ({}, {"workers": 1, "processes": True}),
            "explicitly_off": ({}, {"workers": 3, "processes": False}),
            "environment_off": ({"env": "0"}, {"workers": 3}),
            "frozen": ({"frozen": True}, {"workers": 3, "processes": True}),
            "registered_subclass": ({"registry": replaced}, {"workers": 3, "processes": True}),
            "replaced_factory": ({"registry": same_class}, {"workers": 3, "processes": True}),
            "patched_fast_path": ({"fast": True}, {"workers": 3, "processes": True}),
            "below_threshold": ({"threshold": 1 << 30}, {"workers": 3, "processes": True}),
        }
        for name, (setup, arguments) in cases.items():
            with self.subTest(case=name), _small_pieces() as spawned, ExitStack() as stack:
                if "env" in setup:
                    stack.enter_context(patch.dict(os.environ, {"FANGIDA_DECODE_PROCESSES": setup["env"]}))
                if "frozen" in setup:
                    stack.enter_context(patch.object(sys, "frozen", True, create=True))
                if "registry" in setup:
                    stack.enter_context(patch.object(processors, "_registry", setup["registry"]))
                if "fast" in setup:
                    real = NativeDecoder.decode_bytes_fast
                    stack.enter_context(patch.object(
                        NativeDecoder, "decode_bytes_fast",
                        lambda self, *args, **kwargs: real(self, *args, **kwargs)))
                if "threshold" in setup:
                    stack.enter_context(patch.object(full_decode, "_PROCESS_MIN_BYTES", setup["threshold"]))
                output, diagnostics = self._run(**arguments)
                expected, _ = self._run(workers=1, processes=False)
                self.assertEqual(spawned.trees, [])
                self.assertEqual(output, expected)
                self.assertEqual(diagnostics, {"processes_used": 0, "process_regions": 0})

    def test_process_count_threads_progress_and_stdout_isolation(self):
        noisy = _worker_script(
            "real = w.sweep\n"
            "def sweep(*args, **kwargs):\n"
            "    print('noise from print')\n"
            "    os.write(1, b'noise from fd 1')\n"
            "    return real(*args, **kwargs)\n"
            "w.sweep = sweep\nw.main()\n")
        started_threads: list[str] = []
        real_start = threading.Thread.start

        def record(thread: threading.Thread) -> None:
            started_threads.append(thread.name)
            real_start(thread)

        events: list[dict[str, Any]] = []
        sys.stdout.flush()
        saved = os.dup(1)
        try:
            with tempfile.TemporaryFile() as captured, _small_pieces() as spawned:
                os.dup2(captured.fileno(), 1)
                try:
                    with patch.object(_decode_worker, "worker_command", return_value=noisy), \
                         patch.object(threading.Thread, "start", record):
                        output, diagnostics = self._run(workers=2, processes=True,
                                                        on_progress=events.append)
                finally:
                    sys.stdout.flush()
                    os.dup2(saved, 1)
                captured.seek(0)
                self.assertEqual(captured.read(), b"")
        finally:
            os.close(saved)
        self.assertEqual(output, self.serial)
        self.assertEqual(started_threads, [])
        self.assertEqual(len(spawned.trees), 2)
        self.assertEqual(diagnostics, {"processes_used": 2, "process_regions": 2})
        self.assertGreater(len(events), 2)
        completed = [event["regions_completed"] for event in events]
        self.assertEqual(completed, sorted(completed))
        self.assertIn(1, completed)
        self.assertEqual(events[-1]["processes_used"], 2)
        self.assertEqual(events[-1]["workers_used"], 1)
        self.assertEqual(events[-1]["regions_completed"], 2)
        self.assertEqual(events[-1]["processed_bytes"], len(self.data))
        spawned.assert_reaped(self)

    def _cancel_after(self, seconds: float) -> tuple[Any, float]:
        """取消回调与“请求取消”的时刻；延迟从该时刻算起，而不是从回调首次被调用算起。"""
        requested = time.monotonic() + seconds
        return (lambda: time.monotonic() >= requested), requested

    def test_hung_children_time_out_and_fall_back(self):
        cases = {
            # 启动挂起：从不握手；所有子进程都没握手时本解释器不再尝试进程路径。
            "before_hello": (_HANG_BEFORE_HELLO, {"_START_TIMEOUT": 0.25}, True),
            # 处理请求中途挂起：按请求超时杀掉，涉及的区域交回进程内路径。
            "mid_request": (_HANG_ON_SECOND_SWEEP,
                            {"_REQUEST_TIMEOUT_FLOOR": 0.25, "_REQUEST_SECONDS_PER_BYTE": 0.0}, False),
        }
        for name, (command, timeouts, disabled) in cases.items():
            with self.subTest(hang=name), _small_pieces() as spawned, ExitStack() as stack:
                for key, value in timeouts.items():
                    stack.enter_context(patch.object(full_decode, key, value))
                stack.enter_context(patch.object(_decode_worker, "worker_command", return_value=command))
                started = time.monotonic()
                output, diagnostics = self._run(workers=3, processes=True)
                self.assertLess(time.monotonic() - started, 10)
                self.assertEqual(output, self.serial)
                self.assertEqual(diagnostics["process_regions"], 0)
                self.assertEqual(full_decode._process_mismatch, disabled)
                self.assertEqual(len(spawned.trees), 3)
                spawned.assert_reaped(self)

    def test_cancel_while_children_hang_returns_promptly(self):
        serial_records, _, _ = stream_decode_regions(self.data, self.image, include_data=True)
        for name, command in (("before_hello", _HANG_BEFORE_HELLO), ("mid_request", _HANG_ON_SECOND_SWEEP)):
            with self.subTest(hang=name), _small_pieces() as spawned, \
                    patch.object(_decode_worker, "worker_command", return_value=command):
                cancelled, requested = self._cancel_after(0.15)
                result = stream_decode_regions(self.data, self.image, workers=3, include_data=True,
                                               processes=True, is_cancelled=cancelled)
                # 超时是 30 秒/10 秒；能在取消后很快返回只能依靠轮询中的取消检查。
                self.assertLess(time.monotonic() - requested, 1.0)
                self.assertTrue(all(region["cancelled"] for region in result[1]))
                _assert_prefix(self, serial_records, result)
                spawned.assert_reaped(self)

    def test_fallback_keeps_progress_monotonic_and_counts_only_adopted_processes(self):
        expected = _canonical(stream_decode_regions(self.data, self.image, include_data=True,
                                                    chunk_bytes=0x80))

        def reported_then_abandoned(data, image, regions, indices, processor, count, chunk_bytes,
                                    include_data, cancelled, progress, finished, used):
            # 进程路径已为区域 0 报告到很靠后的位置，随后整区回退（结果被丢弃，未计入 used）。
            progress(0, 0x2F00, 0x2E00, 900, threading.get_ident())

        events: list[dict[str, Any]] = []
        with _small_pieces(), patch.object(full_decode, "_decode_with_processes", reported_then_abandoned):
            output, diagnostics = self._run(workers=3, processes=True, chunk_bytes=0x80,
                                            on_progress=events.append)
        self.assertEqual(output, expected)
        self.assertEqual(diagnostics, {"processes_used": 0, "process_regions": 0})
        for key in ("processed_bytes", "decoded_bytes", "instruction_count"):
            values = [event[key] for event in events]
            self.assertEqual(values, sorted(values), key)
        self.assertGreater(len(events), 10)  # 进程内重做从小游标开始报告，最大值保持期确实被覆盖
        self.assertEqual(events[-1]["processed_bytes"], len(self.data))
        self.assertEqual(events[-1]["processes_used"], 0)

    def test_cancel_after_fallback_reports_the_returned_prefix(self):
        fell_back = [False]

        def reported_then_abandoned(data, image, regions, indices, processor, count, chunk_bytes,
                                    include_data, cancelled, progress, finished, used):
            progress(0, 0x2F00, 0x2E00, 900, threading.get_ident())
            fell_back[0] = True

        # 回退一发生就取消进程内重做：最终事件必须与返回结果一致，不能沿用回退前的大数值。
        def cancel_soon() -> bool:
            return fell_back[0]

        events: list[dict[str, Any]] = []
        with _small_pieces(), patch.object(full_decode, "_decode_with_processes", reported_then_abandoned):
            records, coverage, _ = stream_decode_regions(
                self.data, self.image, include_data=True, chunk_bytes=0x80, workers=3,
                processes=True, is_cancelled=cancel_soon, on_progress=events.append)
        self.assertTrue(any(region["cancelled"] for region in coverage))
        self.assertLess(len(records), 900)
        self.assertEqual(events[-1]["instruction_count"], len(records))
        self.assertEqual(events[-1]["decoded_bytes"], sum(region["decoded_bytes"] for region in coverage))

    def test_small_regions_are_batched_into_few_requests(self):
        rng = random.Random(13)
        sizes = [rng.randrange(0x20, 0x60) for _ in range(120)]
        data = _x86_code(sum(sizes), 14)
        image = _image("x86_64", "little", sizes)
        serial = _canonical(stream_decode_regions(data, image))
        requests: list[int] = []
        real_submit = _decode_worker.DecodeProcessPool.submit

        def submit(pool: Any, index: int, request: tuple[Any, ...], *args: Any, **kwargs: Any) -> None:
            requests.append(len(request[-1]))
            real_submit(pool, index, request, *args, **kwargs)

        events: list[dict[str, Any]] = []
        with _small_pieces() as spawned, patch.object(_decode_worker.DecodeProcessPool, "submit", submit):
            diagnostics: dict[str, Any] = {}
            result = stream_decode_regions(data, image, workers=3, processes=True,
                                           diagnostics=diagnostics, on_progress=events.append)
        self.assertEqual(_canonical(result), serial)
        self.assertEqual(diagnostics["process_regions"], len(sizes))
        self.assertEqual(sum(requests), len(sizes))
        self.assertLess(len(requests), len(sizes) // 4)
        self.assertEqual(events[-1]["regions_completed"], len(sizes))
        spawned.assert_reaped(self)

    def test_fingerprint_is_fixed_at_import_despite_runtime_patches(self):
        # 新解释器中只导入 full_decode，尚未发生任何解码：指纹已经算好。
        probe = subprocess.run(
            [sys.executable, "-c", "from fangida.processors import full_decode, _decode_worker as w\n"
             "print(w._FINGERPRINT == w._compute_fingerprint())"],
            capture_output=True, text=True, timeout=60,
            cwd=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(_decode_worker.__file__)))))
        self.assertEqual(probe.stdout.strip(), "True", probe.stderr)
        fingerprint = _decode_worker.code_fingerprint()
        with _small_pieces() as spawned, \
                patch("fangida.processors.decoder.disassemble_bytes", return_value=("", "llvm")):
            # 替换期间重新计算会得到不同的值；导入时固定的指纹不受影响。
            self.assertNotEqual(_decode_worker._compute_fingerprint(), fingerprint)
            self.assertEqual(_decode_worker.code_fingerprint(), fingerprint)
            output, diagnostics = self._run(workers=2, processes=True)
            self.assertEqual(output, self.serial)
            self.assertGreaterEqual(diagnostics["processes_used"], 1)
            self.assertFalse(full_decode._process_mismatch)
        spawned.assert_reaped(self)

    def test_arguments_are_validated(self):
        for name, value in (("processes", 1), ("processes", "yes"), ("diagnostics", [])):
            with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                stream_decode_regions(self.data, self.image, **{name: value})


class StalledChildTests(unittest.TestCase):
    def test_request_to_a_child_that_stops_reading_never_blocks_the_parent(self):
        """握手后只读帧头就停止读取的子进程：父进程写超过管道容量的请求也不阻塞。

        在独立解释器中运行并设外层超时：即使写入意外阻塞，测试也只会失败而不会挂住。
        """
        root = os.path.dirname(os.path.dirname(os.path.abspath(_decode_worker.__file__)))
        root = os.path.dirname(root)
        script = textwrap.dedent("""
            import os, sys, time
            from unittest.mock import patch
            from fangida.processors import _decode_worker as w
            stalled = [sys.executable, "-c", "import os, time\\n"
                       "from fangida.processors import _decode_worker as w\\n"
                       "w.write_message(os.fdopen(1, 'wb', buffering=0, closefd=False), w.hello(), 2)\\n"
                       "os.read(0, 12)\\ntime.sleep(60)\\n"]
            with patch.object(w, "worker_command", return_value=stalled):
                pool = w.DecodeProcessPool(1, w.hello(), start_timeout=20)
                try:
                    pool.start()
                    deadline = time.monotonic() + 20
                    while not pool.idle() and time.monotonic() < deadline:
                        pool.collect(0.01)
                    started = time.monotonic()
                    pool.submit(0, ("x" * (768 * 1024),), timeout=0.2, burst=0.02)
                    submitted = time.monotonic() - started
                    while not pool.expired():
                        assert pool.collect(0.01) == []
                    waited = time.monotonic() - started
                    pool.drop(0)
                    print(pool.idle() == [], round(submitted, 3), round(waited, 3),
                          pool.trees[0].process.returncode is not None)
                finally:
                    pool.close()
        """)
        environment = dict(os.environ, PYTHONPATH=os.pathsep.join(
            filter(None, (root, os.environ.get("PYTHONPATH")))))
        completed = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True,
                                   timeout=60, cwd=root, env=environment)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        idle_empty, submitted, waited, reaped = completed.stdout.split()
        self.assertEqual((idle_empty, reaped), ("True", "True"))
        self.assertLess(float(submitted), 1.0)
        self.assertGreaterEqual(float(waited), 0.2)
        self.assertLess(float(waited), 5.0)


class ReadinessTests(unittest.TestCase):
    def test_wait_readable_reports_data_and_eof_without_threads(self):
        import subprocess

        tree = processes.start_process(
            [sys.executable, "-c", "import sys; sys.stdout.write('x'); sys.stdout.flush(); sys.stdin.read()"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
        try:
            stream = tree.process.stdout
            self.assertEqual(processes.wait_readable([stream], 10), [stream])
            self.assertEqual(stream.read(1), b"x")
            self.assertEqual(processes.wait_readable([stream], 0.01), [])
            tree.process.stdin.close()
            self.assertEqual(processes.wait_readable([stream], 10), [stream])
            self.assertEqual(stream.read(1), b"")
            self.assertEqual(processes.wait_readable([], 0), [])
        finally:
            tree.close()
            tree.process.stdout.close()


if __name__ == "__main__":
    unittest.main()
