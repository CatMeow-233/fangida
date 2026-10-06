"""完整分析的流式引用分析：解码进行时 xref 线程消费已拼接完成的指令块。

  - 流式结果与原"全部解码后串行扫描"逐字相同（函数、引用、统计）；
  - 引用只在 xref 线程执行，每批 ≤ 4096 条且为不可变 tuple；
  - 区域交付顺序与地址顺序不同、交界处状态可能延续、交付缺失时都正确回退；
  - XrefStage.submit 受同一有界信号量约束，单线程预算时就地执行。
"""
from __future__ import annotations

from contextlib import ExitStack
import importlib.util
import os
import threading
import unittest
from unittest.mock import patch

from fangida.core.kkagent import full_analysis
from fangida.processors import full_decode
from fangida.xrefs import DataRangeIndex, ReferenceState, XrefStage
from tests.test_full_thread_matrix import _image

CAPSTONE_AVAILABLE = importlib.util.find_spec("capstone") is not None


def _arm64(address: int, operation: dict, writes: tuple[str, ...] = ("x0",)) -> dict:
    return {"addr": address, "size": 4, "writes": list(writes),
            "arch_meta": {"architecture": "arm64", "address_operation": operation}}


def _page_add(address: int, page: int, offset: int) -> list[dict]:
    """adrp x0, page; add x0, x0, #offset —— 第二条依赖第一条留下的地址状态。"""
    return [_arm64(address, {"destination": "x0", "kind": "page", "value": page}),
            _arm64(address + 4, {"destination": "x0", "kind": "add", "source": "x0", "value": offset})]


def _serial(instructions: list[dict], reset_at: frozenset[int]) -> list[dict]:
    """原路径：按地址排序后单遍扫描（4096 一批，状态跨批延续）。"""
    state, refs = ReferenceState(), []
    for offset in range(0, len(instructions), 4096):
        refs.extend(full_analysis._references(tuple(instructions[offset:offset + 4096]), state=state,
                                              data_ranges=DataRangeIndex(), reset_at=reset_at))
    return refs


class ReferenceStreamUnitTests(unittest.TestCase):
    def test_regions_delivered_out_of_address_order_match_serial_pass(self):
        low = _page_add(0x1000, 0x5000, 0x10)
        high = _page_add(0x2000, 0x6000, 0x20)
        regions = [{"address": 0x2000}, {"address": 0x1000}]
        with XrefStage(separate_thread=True) as stage:
            stream = full_analysis._ReferenceStream(stage, DataRangeIndex())
            stream(regions, 0, high)   # 地址较高的区域先到
            stream(regions, 1, low)
            result = stream.result(low + high)
        expected = _serial(low + high, frozenset({0x1000, 0x2000}))
        self.assertEqual(result, expected)
        self.assertEqual([ref["dst"] for ref in result], [0x5010, 0x6020])

    def test_contiguous_boundary_without_reset_falls_back(self):
        # 第二个区域首条指令紧接上一区域末尾且不在区域起点：原单遍扫描会延续地址状态。
        first = [_arm64(0x1000, {"destination": "x0", "kind": "page", "value": 0x5000})]
        second = [_arm64(0x1004, {"destination": "x0", "kind": "add", "source": "x0", "value": 8})]
        regions = [{"address": 0x1000}, {"address": 0x1002}]
        with XrefStage(separate_thread=True) as stage:
            stream = full_analysis._ReferenceStream(stage, DataRangeIndex())
            stream(regions, 0, first)
            stream(regions, 1, second)
            self.assertIsNone(stream.result(first + second))

    def test_missing_or_replaced_records_fall_back(self):
        records = _page_add(0x1000, 0x5000, 0x10)
        regions = [{"address": 0x1000}]
        with XrefStage(separate_thread=True) as stage:
            stream = full_analysis._ReferenceStream(stage, DataRangeIndex())
            stream(regions, 0, records[:1])
            self.assertIsNone(stream.result(records))
            stream = full_analysis._ReferenceStream(stage, DataRangeIndex())
            stream(regions, 0, records)
            # 区域回退后由进程内路径重做：内容相同但对象不同，也必须回退。
            self.assertIsNone(stream.result([dict(item) for item in records]))

    def test_snapshots_are_bounded_tuples_on_the_xref_thread(self):
        records = [{"addr": 0x1000 + 4 * index, "size": 4} for index in range(10000)]
        seen: list[tuple[str, type, int]] = []
        real = full_analysis._references

        def probe(snapshot, **kwargs):
            seen.append((threading.current_thread().name, type(snapshot), len(snapshot)))
            return real(snapshot, **kwargs)

        with patch.object(full_analysis, "_references", probe), XrefStage(separate_thread=True) as stage:
            stream = full_analysis._ReferenceStream(stage, DataRangeIndex())
            stream([{"address": 0x1000}], 0, records)
            self.assertEqual(stream.result(records), [])
        self.assertEqual([size for _, _, size in seen], [4096, 4096, 1808])
        self.assertTrue(all(kind is tuple for _, kind, _ in seen))
        self.assertTrue(all(name.startswith("fangida-xref") for name, _, _ in seen))

    def test_submit_runs_inline_for_one_thread_budget_and_bounds_pending(self):
        with XrefStage(separate_thread=False) as stage:
            future = stage.submit(threading.get_ident)
            self.assertTrue(future.done())
            self.assertEqual(future.result(), threading.get_ident())
        gate = threading.Event()
        with XrefStage(separate_thread=True, max_pending=2) as stage:
            futures = [stage.submit(gate.wait, 5) for _ in range(2)]
            blocked = threading.Thread(target=lambda: futures.append(stage.submit(int)))
            blocked.start()
            blocked.join(0.2)
            self.assertTrue(blocked.is_alive())   # 背压：第三个提交等待在途批次完成
            gate.set()
            blocked.join(5)
            self.assertFalse(blocked.is_alive())
            self.assertEqual([future.result() for future in futures], [True, True, 0])


@unittest.skipUnless(CAPSTONE_AVAILABLE, "Capstone is required for the process decoding path")
class ReferenceStreamAnalysisTests(unittest.TestCase):
    def _run(self, *, streaming: bool):
        data, image = _image()
        with ExitStack() as stack:
            stack.enter_context(patch.object(full_decode, "_PROCESS_MIN_BYTES", 0x1000))
            stack.enter_context(patch.object(full_decode, "_PROCESS_MIN_PIECE_BYTES", 0x400))
            stack.enter_context(patch.object(full_decode, "_PROCESS_PIECE_BYTES", 0x800))
            stack.enter_context(patch.object(full_decode, "_process_mismatch", False))
            stack.enter_context(patch.dict(os.environ, {"FANGIDA_DECODE_PROCESSES": ""}))
            if not streaming:
                stack.enter_context(patch.object(full_analysis._ReferenceStream, "result",
                                                 lambda self, instructions: None))
            stage = stack.enter_context(XrefStage(separate_thread=True))
            functions, refs, stats, _, warnings = full_analysis.analyze_full(
                data, image, workers=3, xref_stage=stage)
        return functions, refs, stats, warnings

    def test_streamed_references_equal_serial_pass(self):
        streamed = self._run(streaming=True)
        serial = self._run(streaming=False)
        self.assertTrue(streamed[2]["full_xref_streamed"])
        self.assertFalse(serial[2]["full_xref_streamed"])
        self.assertTrue(streamed[2]["full_xref_pass_complete"])
        self.assertEqual(streamed[0], serial[0])
        self.assertEqual(streamed[1], serial[1])
        self.assertEqual(streamed[3], serial[3])
        ignored = {"phase_seconds", "full_xref_streamed", "full_decode_processes_used"}
        self.assertEqual({key: value for key, value in streamed[2].items() if key not in ignored},
                         {key: value for key, value in serial[2].items() if key not in ignored})


if __name__ == "__main__":
    unittest.main()
