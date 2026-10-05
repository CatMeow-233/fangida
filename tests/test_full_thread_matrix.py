"""full 模式线程约束矩阵：预算 1/2/3/5 × 普通/进度/解码阶段取消/CFG 阶段取消/fast/deep。

补充 test_full_analysis（单区域、预算 1/3）与 test_xref_threads（预算 1/2）未覆盖的组合：
  - 预算 > 1 时，解码类函数与引用类函数的执行线程集合不相交，引用只在唯一的
    xref 线程上执行；预算 = 1 时二者共用同一个分析线程且不另起分析线程；
  - 进度回调、解码或 CFG 阶段取消、快速分析同样不得绕过上述约束；
  - xref 只消费完成的快照：每批 ≤ 4096 条且为不可变 tuple，引用函数内不调用解码器，
    提交侧已提交未完成的 xref 工作受 XrefStage 背压约束（单一提交者 ≤ 2）；
  - 线程预算包含 xref 线程：同时存活的分析线程不超过预算，CFG 线程池不超过 MAX_WORKERS；
  - 内置 Capstone 且 GIL 启用时，多区域并行解码的窗口解码调用互不重叠。

线程身份用 Thread 对象记录，而不是 get_ident()：线程退出后 ident 会被新线程复用
（实测解码池线程退出后懒创建的 fangida-xref_0 拿到了相同 ident），用 ident 比较会把
先后存在的两个线程误判为同一线程。
"""
from __future__ import annotations

from contextlib import ExitStack
import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
import threading
import time
from typing import Any, Callable
import unittest
from unittest.mock import patch

from fangida.core import kkagent
from fangida.core.kkagent import full_analysis, semantic
from fangida.core.kkagent.test_semantic import DECODER_AVAILABLE, _sample
from fangida.dispatcher import AnalysisService
from fangida.loaders.models import BinaryImage
from fangida.processors.decoder import NativeDecoder
from fangida.processors.full_decode import stream_decode_regions
from fangida.settings import Settings
from fangida.xrefs import XrefStage

# full_analysis 每批交给 xref 阶段的指令上限，以及 XrefStage 默认的在途上限。
BATCH_LIMIT = 4096
MAX_PENDING = 2
# 每区域 0x1800 字节（约 6000 条 nop），三个区域合计 > 4096 条，足以产生多个 xref 批次，
# 同时让 16 个预算/场景组合的总耗时保持在 1 秒量级。
REGIONS, REGION_SIZE = 3, 0x1800
BASE, CODE_OFFSET = 0x400000, 0x100
FULL_SCENARIOS = ("plain", "progress", "cancel_decode", "cancel_cfg")
SCHEDULER_PREFIXES = ("fangida-io", "fangida-parse", "fangida-analyze", "fangida-native")
CAPSTONE_AVAILABLE = importlib.util.find_spec("capstone") is not None
# 3.13+ 的自由线程构建可关闭 GIL；3.11/3.12 没有该函数，按启用处理。
GIL_ENABLED = bool(getattr(sys, "_is_gil_enabled", lambda: True)())


def _code(size: int) -> bytes:
    """nop 填充 + 每 256 字节一个 call 到下一个 256 字节边界 + 结尾 ret。

    每个 call 目标都会成为 direct_call 种子，使 CFG 种子数（约 72）远大于 MAX_WORKERS。
    """
    out = bytearray(b"\x90" * size)
    for offset in range(0, size - 256, 256):
        out[offset:offset + 5] = b"\xe8" + (256 - 5).to_bytes(4, "little", signed=True)
    out[-1] = 0xC3
    return bytes(out)


def _elf(regions: int = REGIONS, size: int = REGION_SIZE) -> bytes:
    """无程序头的最小 ELF64：每个区域一个 SHF_ALLOC|SHF_EXECINSTR 的 .textN 节。"""
    body = _code(size) * regions
    names = b"\0.shstrtab\0" + b"".join(f".text{index}\0".encode() for index in range(regions))
    names_offset = CODE_OFFSET + len(body)
    section_offset = (names_offset + len(names) + 7) & ~7
    count = regions + 2
    data = bytearray(section_offset + 64 * count)
    data[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 2, 62, 1, BASE + CODE_OFFSET,
                     0, section_offset, 0, 64, 0, 0, 64, count, 1)
    data[CODE_OFFSET:names_offset] = body
    data[names_offset:names_offset + len(names)] = names
    struct.pack_into("<IIQQQQIIQQ", data, section_offset + 64, 1, 3, 0, 0,
                     names_offset, len(names), 0, 0, 1, 0)
    name = len(b"\0.shstrtab\0")
    for index in range(regions):
        offset = CODE_OFFSET + index * size
        struct.pack_into("<IIQQQQIIQQ", data, section_offset + 64 * (index + 2), name, 1, 6,
                         BASE + offset, offset, size, 0, 0, 16, 0)
        name += len(f".text{index}\0")
    return bytes(data)


def _image(regions: int = REGIONS, size: int = REGION_SIZE) -> tuple[bytes, BinaryImage]:
    """直接调用 analyze_full/stream_decode_regions 用的同构合成镜像。"""
    data = _code(size) * regions
    sections = [{"name": f".text{index}", "address": BASE + index * size,
                 "offset": index * size, "size": size, "executable": True}
                for index in range(regions)]
    return data, BinaryImage("elf", "x86_64", 64, "little", entry_address=BASE,
                             sections=sections)


class _Probe:
    """包装解码类与引用类函数，记录执行线程、批次、嵌套调用与在途提交数。"""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.local = threading.local()
        self.decoded: set[threading.Thread] = set()
        self.referenced: set[threading.Thread] = set()
        self.batches: list[int] = []
        self.mutable_snapshots = 0
        self.nested: list[str] = []
        self.decoding: dict[threading.Thread, int] = {}
        self.peak_decoding = 0
        self.in_flight = self.peak_in_flight = 0
        self.submitters: set[threading.Thread] = set()
        self.started: list[str] = []
        self.analysis_threads: list[threading.Thread] = []
        self.peak_alive = 0
        self._stack = ExitStack()

    def count(self, prefix: str) -> int:
        return sum(name.startswith(prefix) for name in self.started)

    def _decoder(self, name: str, function: Callable[..., Any]) -> Callable[..., Any]:
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            thread = threading.current_thread()
            with self.lock:
                self.decoded.add(thread)
                # 引用函数执行期间（同一线程）调用了解码器：违反“xref 不调用解码器”。
                if getattr(self.local, "xref_depth", 0):
                    self.nested.append(name)
                depth = self.decoding.get(thread, 0)
                self.decoding[thread] = depth + 1
                self.peak_decoding = max(self.peak_decoding, len(self.decoding))
            try:
                return function(*args, **kwargs)
            finally:
                with self.lock:
                    if depth:
                        self.decoding[thread] = depth
                    else:
                        del self.decoding[thread]
        return wrapped

    def _reference(self, function: Callable[..., Any], *, batch: bool = False) -> Callable[..., Any]:
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            with self.lock:
                self.referenced.add(threading.current_thread())
                if batch:
                    self.batches.append(len(args[0]))
                    self.mutable_snapshots += type(args[0]) is not tuple
            self.local.xref_depth = getattr(self.local, "xref_depth", 0) + 1
            try:
                return function(*args, **kwargs)
            finally:
                self.local.xref_depth -= 1
        return wrapped

    def _submit(self, run: Callable[..., Any]) -> Callable[..., Any]:
        """在提交侧统计“已提交未完成”：进入 run 时 +1，被提交的函数真正结束时 -1。

        不以 run 返回作为完成：若 run 改成异步投递而不等待，计数仍能反映积压。
        """
        def wrapped(stage: XrefStage, function: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
            finished: list[bool] = []

            def finish() -> None:
                with self.lock:
                    if not finished:
                        finished.append(True)
                        self.in_flight -= 1

            def tracked(*inner: Any, **named: Any) -> Any:
                self.local.stage_depth = getattr(self.local, "stage_depth", 0) + 1
                try:
                    return function(*inner, **named)
                finally:
                    self.local.stage_depth -= 1
                    finish()

            with self.lock:
                # 阶段函数内部的嵌套 run 不算独立的提交者。
                if not getattr(self.local, "stage_depth", 0):
                    self.submitters.add(threading.current_thread())
                self.in_flight += 1
                self.peak_in_flight = max(self.peak_in_flight, self.in_flight)
            try:
                return run(stage, tracked, *args, **kwargs)
            except BaseException:
                finish()
                raise
        return wrapped

    def __enter__(self) -> _Probe:
        try:
            self._install(self._stack)
        except BaseException:
            self._stack.close()
            raise
        return self

    def _install(self, stack: ExitStack) -> None:
        decoders = ((NativeDecoder, "decode_bytes_fast"), (NativeDecoder, "decode_bytes"),
                    (full_analysis._CachedDecoder, "decode"), (semantic._Decoder, "decode"),
                    # translator 入口解码（kkagent 按名字导入 disassemble_entry）。
                    (kkagent, "disassemble_entry"))
        for owner, name in decoders:
            stack.enter_context(patch.object(owner, name, self._decoder(
                f"{getattr(owner, '__name__', owner)}.{name}", getattr(owner, name))))
        stack.enter_context(patch.object(full_analysis, "_references",
                                         self._reference(full_analysis._references, batch=True)))
        # xrefs 中的函数被各消费模块按名字导入，须在调用点所在模块替换。
        references = ((full_analysis, "index_references"), (semantic, "function_references"),
                      (semantic, "merge_references"), (semantic, "index_references"),
                      (semantic, "sorted_references"), (kkagent, "direct_references"),
                      (kkagent, "index_entry_references"))
        for owner, name in references:
            stack.enter_context(patch.object(owner, name, self._reference(getattr(owner, name))))
        stack.enter_context(patch.object(XrefStage, "run", self._submit(XrefStage.run)))
        original_start = threading.Thread.start

        def record_start(thread: threading.Thread) -> None:
            with self.lock:
                self.started.append(thread.name)
                # 调度器自身的池线程只是承载插件的协调线程，不计入单次分析的线程预算。
                if not thread.name.startswith(SCHEDULER_PREFIXES):
                    alive = sum(item.is_alive() for item in self.analysis_threads) + 1
                    self.peak_alive = max(self.peak_alive, alive)
                    self.analysis_threads.append(thread)
            original_start(thread)

        stack.enter_context(patch.object(threading.Thread, "start", record_start))

    def __exit__(self, *exc: object) -> None:
        self._stack.close()


@unittest.skipUnless(DECODER_AVAILABLE, "A native decoder is required")
class FullThreadMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._directory = tempfile.TemporaryDirectory()
        root = Path(cls._directory.name)
        cls.full_path = root / "regions.elf"
        cls.full_path.write_bytes(_elf())
        # deep 模式的语义解码对指令数近似平方增长，用两函数小样本覆盖其线程约束即可。
        cls.deep_path = root / "sample.elf"
        cls.deep_path.write_bytes(_sample())

    @classmethod
    def tearDownClass(cls) -> None:
        cls._directory.cleanup()

    def analyze(self, budget: int, scenario: str) -> tuple[Any, _Probe, list[Any]]:
        stop = threading.Event()
        stages: list[Any] = []

        def progress(event: dict[str, Any]) -> None:
            stage = event.get("full_stage")
            stages.append(stage)
            if (scenario, stage) in {("cancel_decode", "decode"), ("cancel_cfg", "cfg")}:
                stop.set()

        if scenario in FULL_SCENARIOS:
            path, options = self.full_path, {"full_analysis": True}
            if scenario != "plain":
                options["on_progress"] = progress
            if scenario.startswith("cancel"):
                options["cancel"] = stop
        else:
            path = self.deep_path if scenario == "deep" else self.full_path
            options = {"full_analysis": False, "deep_analysis": scenario == "deep"}
        with _Probe() as probe:
            with AnalysisService(Settings(analyze_threads=budget, semantic_threads=8)) as service:
                result = service.analyze(path, **options)
        return result, probe, stages

    def check_threads(self, budget: int, result: Any, probe: _Probe) -> None:
        self.assertNotEqual(result.status, "error", result.warnings)
        self.assertTrue(probe.decoded)
        self.assertTrue(probe.referenced)
        self.assertEqual(probe.nested, [], "xref 阶段调用了解码器")
        self.assertTrue(all(size <= BATCH_LIMIT for size in probe.batches), probe.batches)
        self.assertEqual(probe.mutable_snapshots, 0)
        # 背压：每个提交者同步等待自己的批次，单一提交者（full/fast 的协调线程）
        # 已提交未完成的 xref 工作 ≤ 2；deep 并行路径有多个提交者，阻塞在背压
        # 信号量上的调用也计入，上限为提交者数。
        self.assertLessEqual(probe.peak_in_flight, max(MAX_PENDING, len(probe.submitters)))
        # 预算包含 xref 线程：分析期间同时存活的分析线程（xref + 解码/CFG/语义池）不超过预算。
        self.assertLessEqual(probe.peak_alive, budget, probe.started)
        analysis_prefixes = ("fangida-xref", "fangida-decode", "fangida-full-cfg", "fangida-semantic")
        if budget == 1:
            # 唯一允许共用线程的情形：同一个分析线程完成解码与引用，且不另起分析线程。
            self.assertEqual(len(probe.decoded | probe.referenced), 1)
            self.assertEqual(probe.decoded, probe.referenced)
            for prefix in analysis_prefixes:
                self.assertEqual(probe.count(prefix), 0, (prefix, probe.started))
            return
        self.assertTrue(probe.decoded.isdisjoint(probe.referenced),
                        ([t.name for t in probe.decoded], [t.name for t in probe.referenced]))
        self.assertEqual(len(probe.referenced), 1)
        self.assertTrue(next(iter(probe.referenced)).name.startswith("fangida-xref"))
        self.assertEqual(probe.count("fangida-xref"), 1)
        # 预算包含 xref 线程：任一时刻并发解码的线程数与各解码/CFG 线程池都不超过 budget - 1。
        workers = budget - 1
        for prefix in analysis_prefixes[1:]:
            self.assertLessEqual(probe.count(prefix), workers, (prefix, probe.started))
        self.assertLessEqual(probe.peak_decoding, workers)
        if "semantic_workers_requested" in result.stats:
            self.assertLessEqual(result.stats["semantic_workers_requested"], workers)

    def test_thread_identity_matrix(self) -> None:
        evidence: dict[int, tuple[Any, Any]] = {}
        for budget in (1, 2, 3, 5):
            for scenario in (*FULL_SCENARIOS, "fast", "deep"):
                with self.subTest(budget=budget, scenario=scenario):
                    result, probe, stages = self.analyze(budget, scenario)
                    self.check_threads(budget, result, probe)
                    stats = result.stats
                    if scenario in {"plain", "progress"}:
                        # 多个有界批次逐一交付，且恰好覆盖全部已解码指令。
                        self.assertGreater(len(probe.batches), 1)
                        self.assertEqual(sum(probe.batches), stats["full_instructions"])
                        self.assertTrue(stats["full_xref_pass_complete"])
                        self.assertTrue(stats["full_cfg_pass_complete"])
                    if scenario == "plain":
                        evidence[budget] = (result.functions, result.xrefs)
                    elif scenario == "progress":
                        self.assertIn("decode", stages)
                        self.assertIn("cfg", stages)
                    elif scenario.startswith("cancel"):
                        self.assertTrue(stats.get("cancelled"))
                        self.assertTrue(stats["semantic_cancelled"])
                        self.assertFalse(stats["full_cfg_pass_complete"])
                        if scenario == "cancel_cfg":
                            # 取消确实发生在 CFG 阶段：已有函数由 CFG 线程完成。
                            self.assertGreater(stats["full_cfg_functions"], 0)
                    elif scenario == "fast":
                        self.assertNotIn("full_analysis", stats)
                        self.assertGreater(stats["entry_instructions"], 0)
                    elif scenario == "deep":
                        self.assertGreater(stats["semantic_functions"], 0)
        # 未取消的证据与线程预算无关。
        for budget, other in evidence.items():
            with self.subTest(evidence_budget=budget):
                self.assertEqual(other, evidence[1])

    def test_direct_call_caps_cfg_pool_at_max_workers(self) -> None:
        data, image = _image()
        original = full_analysis._analyze_function

        def slow(*args: Any, **kwargs: Any) -> Any:
            # 线程池按需建线程：任务完成太快时空闲线程会被复用，掩盖上限缺失。
            # 每个 CFG 任务稍作停留，使批内所有任务都需要独立线程。
            time.sleep(0.01)
            return original(*args, **kwargs)

        with _Probe() as probe, patch.object(full_analysis, "_analyze_function", slow):
            with XrefStage(separate_thread=True) as stage:
                functions, refs, stats, _, _ = full_analysis.analyze_full(
                    data, image, workers=64, xref_stage=stage)
        # 种子数远大于 MAX_WORKERS，未设上限的线程池会创建远超 16 个线程。
        self.assertGreater(stats["full_cfg_functions"], 2 * semantic.MAX_WORKERS)
        self.assertGreater(probe.count("fangida-full-cfg"), 1)
        self.assertLessEqual(probe.count("fangida-full-cfg"), semantic.MAX_WORKERS)
        self.assertLessEqual(probe.count("fangida-decode"), min(semantic.MAX_WORKERS, REGIONS))
        self.assertLessEqual(stats["full_cfg_workers_used"], semantic.MAX_WORKERS)
        self.assertLessEqual(probe.peak_alive, semantic.MAX_WORKERS + 1)  # CFG 池 + xref 线程
        # 统计仍报告调用方请求的 workers（输出兼容）。
        self.assertEqual(stats["semantic_workers_requested"], 64)
        self.assertTrue(probe.decoded.isdisjoint(probe.referenced))
        self.assertEqual(len(probe.referenced), 1)
        self.assertEqual(probe.nested, [])
        self.assertTrue(all(size <= BATCH_LIMIT for size in probe.batches), probe.batches)
        self.assertTrue(functions)
        self.assertTrue(refs)

    def test_inline_stage_rejects_multiple_workers(self) -> None:
        data, image = _image(1, 0x100)
        with XrefStage() as stage:
            with self.assertRaisesRegex(ValueError, "separate xref thread"):
                full_analysis.analyze_full(data, image, workers=2, xref_stage=stage)


@unittest.skipUnless(CAPSTONE_AVAILABLE and GIL_ENABLED, "Built-in Capstone with the GIL enabled is required")
class CapstoneWindowLockTests(unittest.TestCase):
    def test_parallel_region_windows_do_not_overlap(self) -> None:
        # 小窗口让每个区域被切成多次解码调用；若窗口互斥锁失效，
        # Capstone 的 ctypes 调用会释放 GIL，多区域线程的窗口必然交错。
        data, image = _image()
        lock = threading.Lock()
        active = [0, 0]  # 当前并发窗口数、峰值
        threads: set[threading.Thread] = set()
        calls = [0]
        original = NativeDecoder.decode_bytes_fast

        def observed(decoder: NativeDecoder, *args: Any, **kwargs: Any) -> Any:
            with lock:
                threads.add(threading.current_thread())
                calls[0] += 1
                active[0] += 1
                active[1] = max(active[1], active[0])
            try:
                return original(decoder, *args, **kwargs)
            finally:
                with lock:
                    active[0] -= 1

        with patch.object(NativeDecoder, "decode_bytes_fast", observed):
            records, coverage, warnings = stream_decode_regions(
                data, image, workers=REGIONS, chunk_bytes=512)
        self.assertEqual({item["engine"] for item in coverage}, {"capstone"})
        self.assertTrue(all(item["complete"] for item in coverage), warnings)
        self.assertGreaterEqual(len(threads), 2)
        self.assertGreater(calls[0], 2 * REGIONS)
        self.assertEqual(active[1], 1)
        self.assertEqual(len(records), sum(item["instruction_count"] for item in coverage))


if __name__ == "__main__":
    unittest.main()
