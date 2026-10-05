"""full 模式线性扫描的重同步锚点：Loader 声明的函数入口不会被一条解码出的指令跨越。

覆盖：
  - 合成 x86-64 字节（不返回调用 + 零填充后接函数入口）：串行、区域线程与多进程切块
    三条路径都在锚点处重同步，records/gaps/coverage/告警逐字段一致；
  - 缺省（不传锚点或传 None）扫描完全不变；区域起点、区域外、文件外以及 ARM/ARM64
    非 4 对齐的锚点被忽略；参数校验；
  - 相邻锚点（重同步缺口合并）、锚点后紧跟不可解码字节、块边界附近的锚点（父进程补扫）；
  - 注册处理器：跨越锚点、处理器跳过的字节含锚点、objdump 式整窗口步进被锚点截断；
  - 子进程 sweep 的三元组缺口与 _on_path 只把重同步缺口的起点视为扫描路径；
  - analyze_full 从 image.functions 与入口点取锚点，处理器层只接收地址；
  - 本机 clang 编译的 x86-64 Mach-O：_die 被解码、CFG 完整、被识别为不返回；
  - /bin/zsh、/bin/bash 的 x86_64 切片：zsh 不再有 not_decoded，bash 结果与无锚点相同。
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import platform
import random
import shutil
import subprocess
import tempfile
import unittest
from typing import Any
from unittest.mock import patch

from fangida import processors
from fangida.core.kkagent import full_analysis
from fangida.loaders.models import BinaryImage
from fangida.processors import _decode_worker, full_decode
from fangida.processors.decoder import NativeDecoder
from fangida.processors.full_decode import ANCHOR_RESYNC, stream_decode_regions
from fangida.xrefs import XrefStage
from tests.test_full_decode_processes import _small_pieces

CAPSTONE = importlib.util.find_spec("capstone") is not None
BASE = 0x400000
# 函数序言：push rbp; mov rbp, rsp。
PROLOGUE = bytes.fromhex("554889e5")


def _image(code_size: int, architecture: str = "x86_64", *, sections: list[dict[str, Any]] | None = None,
           endian: str = "little", functions: list[dict[str, Any]] | None = None,
           entry: int | None = BASE) -> BinaryImage:
    return BinaryImage("macho", architecture, 64 if architecture in {"x86_64", "arm64"} else 32,
                       endian, entry_address=entry, functions=functions or [],
                       sections=sections or [{"name": "__text", "address": BASE, "offset": 0,
                                              "size": code_size, "executable": True}])


def _canonical(result: tuple[Any, ...]) -> str:
    """去掉调度信息 worker_id 后的完整结果（记录、覆盖、告警）。"""
    records, coverage, warnings = result
    coverage = [{key: value for key, value in item.items() if key != "worker_id"} for item in coverage]
    return json.dumps([list(records.items()), coverage, warnings], default=list)


def _functions(seed: int, count: int) -> tuple[bytes, list[int]]:
    """若干个以不返回调用结尾的 x86-64 函数，函数之间是 0~15 个零字节填充。

    返回 (代码, 各函数入口的绝对地址)。少数函数入口处放置相邻锚点或不可解码字节：
      - 相邻锚点：入口前一字节也是声明的入口（零字节 + 序言，连续两次重同步）；
      - 入口处是 64 位模式下无效的 06 字节（重同步后紧接不可解码缺口）。
    """
    rng = random.Random(seed)
    bodies = ("4883ec{b}", "48897df8", "488d05{d}", "488b05{d}", "74{b}", "0f1f440000", "31c0",
              "4889c7", "e8{d}", "c3", "48b8{q}", "f30f1efa", "ff15{d}")
    out = bytearray()
    starts: list[int] = []
    for index in range(count):
        kind = index % 7
        if kind == 3 and out:
            # 相邻锚点：入口 a 处是 00，a+1 处是序言；前面的填充指令跨越 a，a 处的指令又跨越 a+1。
            starts.append(BASE + len(out))
            out += b"\x00"
        if kind == 5 and out:
            starts.append(BASE + len(out))
            out += b"\x06\x06"  # 64 位模式下无效：锚点之后是不可解码字节
        starts.append(BASE + len(out))
        out += PROLOGUE
        for _ in range(rng.randrange(2, 24)):
            out += bytes.fromhex(rng.choice(bodies).format(
                b=rng.randbytes(1).hex(), d=rng.randbytes(4).hex(), q=rng.randbytes(8).hex()))
        out += b"\xe8" + rng.randbytes(4)          # call exit 之类的不返回调用
        out += b"\x00" * rng.randrange(0, 16)      # 链接器零填充
    return bytes(out), starts


def _assert_resynchronized(case: unittest.TestCase, result: tuple[Any, ...], anchors: list[int],
                           base: int = BASE) -> None:
    """没有任何记录跨越锚点；每个锚点都被扫描经过：指令起点、重同步缺口边界或不可解码缺口内。"""
    records, coverage, _ = result
    ordered = sorted(records)
    for address in ordered:
        end = address + records[address]["size"]
        crossed = [anchor for anchor in anchors if address < anchor < end]
        case.assertEqual(crossed, [], f"instruction {address:#x} crosses an anchor")
    undecodable = [(gap["address"], gap["address"] + gap["size"]) for region in coverage
                   for gap in region["gaps"] if gap["reason"] == "undecodable"]
    # 重同步缺口的边界（相邻锚点合并后的中间锚点也在其中）都被扫描经过。
    resync = {address for region in coverage for gap in region["gaps"] if gap["reason"] == ANCHOR_RESYNC
              for address in range(gap["address"], gap["address"] + gap["size"] + 1)}
    for anchor in anchors:
        if anchor in records or anchor in resync:
            continue
        case.assertTrue(any(low <= anchor < high for low, high in undecodable),
                        f"anchor {anchor:#x} is neither decoded, resynchronized nor undecodable")


@unittest.skipUnless(CAPSTONE, "Capstone is required")
class SerialAnchorTests(unittest.TestCase):
    def test_zero_padding_before_declared_entry_resynchronizes(self):
        # main: push rbp; mov rbp,rsp; mov edi,1; call exit; 一个零字节填充; die: push rbp; mov rbp,rsp; ret
        code = bytes.fromhex("554889e5bf01000000e800000000") + b"\x00" + bytes.fromhex("554889e5c3")
        die = BASE + 15
        image = _image(len(code))
        plain = stream_decode_regions(code, image)
        # 不传锚点：0x40000e 的 `00 55 48` 跨过 die 的入口（问题本身）。
        self.assertNotIn(die, plain[0])
        self.assertEqual(plain[0][BASE + 14]["size"], 3)
        records, coverage, warnings = stream_decode_regions(code, image, anchors=[BASE, die])
        self.assertEqual([hex(address) for address in records],
                         [hex(BASE + offset) for offset in (0, 1, 4, 9, 15, 16, 19)])
        self.assertEqual(coverage[0]["gaps"], [{"address": BASE + 14, "offset": 14, "size": 1,
                                                 "reason": ANCHOR_RESYNC}])
        self.assertEqual(coverage[0]["decoded_bytes"], len(code) - 1)
        self.assertEqual(coverage[0]["instruction_count"], 7)
        self.assertFalse(coverage[0]["complete"])
        self.assertEqual(coverage[0]["partial_reason"], "uncovered bytes")
        self.assertIn("Linear sweep discarded instructions crossing resynchronization anchors "
                      "and restarted at them; coverage is partial", warnings)

    def test_default_and_ignored_anchors_keep_the_historical_sweep(self):
        code, starts = _functions(1, 60)
        image = _image(len(code))
        expected = _canonical(stream_decode_regions(code, image))
        for chunk_bytes in (7, 64, 65536):
            baseline = _canonical(stream_decode_regions(code, image, chunk_bytes=chunk_bytes))
            self.assertEqual(baseline, expected)
            for anchors in (None, [], [BASE], [BASE - 5, BASE + len(code), BASE + len(code) + 9, -1]):
                with self.subTest(chunk_bytes=chunk_bytes, anchors=anchors):
                    self.assertEqual(_canonical(stream_decode_regions(
                        code, image, chunk_bytes=chunk_bytes, anchors=anchors)), baseline)
        # 文件内容之外（声明大小超出文件）的锚点也被忽略。
        declared = _image(len(code) + 64)
        self.assertEqual(_canonical(stream_decode_regions(code, declared, anchors=[BASE + len(code) + 8])),
                         _canonical(stream_decode_regions(code, declared)))

    def test_every_chunk_size_resynchronizes_identically(self):
        code, starts = _functions(2, 80)
        image = _image(len(code))
        reference = stream_decode_regions(code, image, anchors=starts)
        _assert_resynchronized(self, reference, starts)
        reasons = {gap["reason"] for gap in reference[1][0]["gaps"]}
        self.assertEqual(reasons, {ANCHOR_RESYNC, "undecodable"})
        # 相邻锚点的两次重同步合并成一个缺口（与 _gap 的相邻同因合并一致）。
        self.assertTrue(any(gap["reason"] == ANCHOR_RESYNC and gap["size"] >= 2
                            for gap in reference[1][0]["gaps"]))
        for chunk_bytes in (1, 3, 16, 17, 255, 4096):
            with self.subTest(chunk_bytes=chunk_bytes):
                self.assertEqual(_canonical(stream_decode_regions(code, image, chunk_bytes=chunk_bytes,
                                                                  anchors=starts)),
                                 _canonical(reference))

    def test_anchors_are_validated(self):
        code = PROLOGUE
        for anchors in (5, [1.5], [True], ["0x10"], [BASE, None]):
            with self.subTest(anchors=anchors), self.assertRaises(ValueError):
                stream_decode_regions(code, _image(len(code)), anchors=anchors)
        # 任意可迭代对象、重复与乱序都可以。
        result = stream_decode_regions(code, _image(len(code)), anchors=iter([BASE + 1, BASE + 1, BASE]))
        self.assertEqual(list(result[0]), [BASE, BASE + 1])

    def test_arm_grid_anchors_are_noops_and_off_grid_anchors_are_ignored(self):
        rng = random.Random(3)
        for architecture in ("arm64", "arm"):
            for endian in ("little", "big"):
                with self.subTest(architecture=architecture, endian=endian):
                    data = rng.randbytes(0x802)
                    image = _image(len(data), architecture, endian=endian)
                    expected = _canonical(stream_decode_regions(data, image))
                    anchors = [BASE + offset for offset in range(4, len(data), 12)]
                    anchors += [BASE + offset for offset in range(1, len(data), 37)]  # 非 4 对齐（如 Thumb 位）
                    self.assertEqual(_canonical(stream_decode_regions(data, image, anchors=anchors)),
                                     expected)


def _fixture_processor(behaviour: str, calls: list[int]):
    """注册处理器：2 字节记录（skip 模式会跳过一段字节）或 objdump 式整窗口无输出。"""

    class FixtureDecoder(NativeDecoder):
        engine, warning = ("objdump" if behaviour == "objdump" else "fixture"), None

        def __init__(self, architecture, endian):
            pass

        def decode_bytes(self, code, address, *, max_instructions=128):
            calls.append(address)
            output = []
            if behaviour == "objdump" and address < BASE + 6:
                return [], []
            size = 1 if behaviour == "objdump" else 2
            for position in range(address, address + len(code) - size + 1, size):
                if behaviour == "skip" and position in (BASE + 2, BASE + 4):
                    continue  # 处理器在列表中省略的字节（偶数相位上的 2..6）
                output.append({"addr": position, "size": size, "mnemonic": "fixture", "operands": (),
                               "reads": (), "writes": (), "branch_info": {},
                               "arch_meta": {"engine": "fixture", "architecture": "fixture"}})
                if len(output) >= max_instructions:
                    break
            return output, []

    return FixtureDecoder


class RegisteredProcessorAnchorTests(unittest.TestCase):
    def _decode(self, behaviour: str, anchors: list[int] | None, chunk_bytes: int = 16):
        calls: list[int] = []
        registry = processors.ProcessorRegistry()
        registry.register("fixture", _fixture_processor(behaviour, calls))
        data = bytes(32)
        with patch.object(processors, "_registry", registry):
            records, coverage, _ = stream_decode_regions(data, _image(len(data), "fixture"),
                                                         chunk_bytes=chunk_bytes, anchors=anchors)
        gaps = [(gap["address"] - BASE, gap["size"], gap["reason"]) for gap in coverage[0]["gaps"]]
        return [address - BASE for address in records], gaps

    def test_crossing_record_restarts_at_anchor(self):
        self.assertEqual(self._decode("pairs", None)[0], list(range(0, 32, 2)))
        records, gaps = self._decode("pairs", [BASE + 3])
        self.assertEqual(records, [0] + list(range(3, 31, 2)))
        self.assertEqual(gaps, [(2, 1, ANCHOR_RESYNC), (31, 1, "undecodable")])

    def test_skipped_bytes_containing_an_anchor_stop_at_the_anchor(self):
        records, gaps = self._decode("skip", None)
        self.assertEqual(records, [0] + list(range(6, 32, 2)))
        self.assertEqual(gaps, [(2, 4, "undecodable")])
        records, gaps = self._decode("skip", [BASE + 3])
        # 缺口只记到锚点，从锚点（奇数相位）重新解码。
        self.assertEqual(records, [0, 3] + list(range(5, 31, 2)))
        self.assertEqual(gaps, [(2, 1, "undecodable"), (31, 1, "undecodable")])

    def test_objdump_style_window_step_is_clamped_at_anchor(self):
        records, gaps = self._decode("objdump", None)
        self.assertEqual((records[0], gaps), (16, [(0, 16, "undecodable")]))
        records, gaps = self._decode("objdump", [BASE + 6])
        self.assertEqual((records, gaps), (list(range(6, 32)), [(0, 6, "undecodable")]))


@unittest.skipUnless(CAPSTONE, "Capstone is required for the process decoding path")
class PathEquivalenceTests(unittest.TestCase):
    def _assert_paths_equal(self, data: bytes, image: BinaryImage, anchors: list[int], *,
                            overlap: int = 24) -> None:
        for flag in (False, True):
            serial = stream_decode_regions(data, image, include_data=flag, anchors=anchors)
            expected = _canonical(serial)
            with self.subTest(path="threads", include_data=flag):
                threaded = stream_decode_regions(data, image, workers=2, include_data=flag,
                                                 processes=False, anchors=anchors)
                self.assertEqual(_canonical(threaded), expected)
            with _small_pieces(overlap) as spawned:
                for workers in (2, 3):
                    with self.subTest(path="processes", workers=workers, include_data=flag):
                        diagnostics: dict[str, Any] = {}
                        result = stream_decode_regions(data, image, workers=workers, include_data=flag,
                                                       processes=True, diagnostics=diagnostics,
                                                       anchors=anchors)
                        self.assertEqual(diagnostics["process_regions"], len(image.sections))
                        self.assertGreaterEqual(diagnostics["processes_used"], 2)
                        self.assertEqual(_canonical(result), expected)
            spawned.assert_reaped(self)

    def test_serial_threads_and_process_pieces_resynchronize_identically(self):
        code, starts = _functions(4, 700)
        self.assertGreater(len(code), 0x3000)
        image = _image(len(code))
        serial = stream_decode_regions(code, image, anchors=starts)
        _assert_resynchronized(self, serial, starts)
        self.assertGreater(sum(gap["reason"] == ANCHOR_RESYNC for gap in serial[1][0]["gaps"]), 50)
        self._assert_paths_equal(code, image, starts)
        # 同步重叠足够大时块间直接同步，不走父进程补扫。
        self._assert_paths_equal(code, image, starts, overlap=512)

    def test_multiple_regions_with_and_without_anchors(self):
        first, first_starts = _functions(5, 300)
        second, second_starts = _functions(6, 300)
        noise = random.Random(7).randbytes(0x900)
        data = first + noise + second
        sections = [{"name": "__text", "address": BASE, "offset": 0, "size": len(first),
                     "executable": True},
                    {"name": "__noise", "address": BASE + 0x100000, "offset": len(first),
                     "size": len(noise), "executable": True},
                    {"name": "__text2", "address": BASE + 0x200000, "offset": len(first) + len(noise),
                     "size": len(second), "executable": True}]
        shifted = [BASE + 0x200000 + address - BASE for address in second_starts]
        anchors = first_starts + shifted
        image = _image(len(data), sections=sections)
        serial = stream_decode_regions(data, image, anchors=anchors)
        _assert_resynchronized(self, serial, anchors)
        # 没有锚点的噪声区域与不传锚点时完全相同。
        plain = stream_decode_regions(data, image)
        self.assertEqual({key: value for key, value in serial[1][1].items() if key != "worker_id"},
                         {key: value for key, value in plain[1][1].items() if key != "worker_id"})
        self._assert_paths_equal(data, image, anchors)

    def test_arm64_grid_anchors_in_process_pieces(self):
        data = random.Random(8).randbytes(0x1802)
        image = _image(len(data), "arm64")
        anchors = [BASE + offset for offset in range(0, len(data), 20)] + [BASE + 2, BASE + 0x101]
        expected = _canonical(stream_decode_regions(data, image))
        self.assertEqual(_canonical(stream_decode_regions(data, image, anchors=anchors)), expected)
        self._assert_paths_equal(data, image, anchors)


@unittest.skipUnless(CAPSTONE, "Capstone is required")
class WorkerSweepTests(unittest.TestCase):
    def test_sweep_reports_unmerged_anchor_gaps_and_on_path_skips_their_interior(self):
        # xor | 00 | 锚点 3: 00 | 锚点 4: 序言 ret。02 处 00 00 跨越 3，03 处 00 55 48 又跨越 4：
        # 两次重同步各记一个三元组缺口，不合并（父进程 _gap 再合并）。
        code = bytes.fromhex("31c0") + b"\x00\x00" + PROLOGUE + b"\xc3"
        decode = NativeDecoder("x86_64").decode_bytes_fast
        anchors = (3, 4)
        result = _decode_worker.sweep(decode, code, 0, BASE, len(code), 0, len(code), 64, 1,
                                      full_decode._LOOKAHEAD, full_decode._INVALID_MNEMONICS,
                                      False, anchors)
        addrs, _, gaps, end = result
        self.assertEqual([address - BASE for address in addrs], [0, 4, 5, 8])
        self.assertEqual(gaps, [(2, 1, ANCHOR_RESYNC), (3, 1, ANCHOR_RESYNC)])
        self.assertEqual(end, len(code))
        on_path = [cursor for cursor in range(len(code) + 1)
                   if full_decode._on_path(result, 0, cursor, BASE, 1)]
        self.assertEqual(on_path, [0, 2, 3, 4, 5, 8, 9])
        # 缺省参数（无锚点）与原扫描相同：02 处的 00 00 正常解码，不重同步。
        plain = _decode_worker.sweep(decode, code, 0, BASE, len(code), 0, len(code), 64, 1,
                                     full_decode._LOOKAHEAD, full_decode._INVALID_MNEMONICS, False)
        self.assertEqual([address - BASE for address in plain[0]], [0, 2, 4, 5, 8])
        self.assertEqual(plain[2], [])

    def test_interior_of_a_long_resync_gap_is_not_on_the_sweep_path(self):
        # movabs rax, imm64（10 字节）跨越锚点 5：缺口 [0, 5) 一步跳过，内部 1..4 不在路径上；
        # 若父进程把它们当作路径，会把真实扫描在那里解出的指令错记为重同步缺口。
        code = bytes.fromhex("48b8112233") + b"\x90" * 5 + b"\xc3"
        decode = NativeDecoder("x86_64").decode_bytes_fast
        result = _decode_worker.sweep(decode, code, 0, BASE, len(code), 0, len(code), 64, 1,
                                      full_decode._LOOKAHEAD, full_decode._INVALID_MNEMONICS,
                                      False, (5,))
        self.assertEqual(result[2], [(0, 5, ANCHOR_RESYNC)])
        self.assertEqual([address - BASE for address in result[0]], [5, 6, 7, 8, 9, 10])
        on_path = [cursor for cursor in range(len(code) + 1)
                   if full_decode._on_path(result, 0, cursor, BASE, 1)]
        self.assertEqual(on_path, [0, 5, 6, 7, 8, 9, 10, 11])
        # 父进程拼接：游标位于缺口起点时提交，缺口原因与字节数按串行记账。
        coverage = {"address": BASE, "offset": 0, "size": len(code), "file_backed_size": len(code),
                    "decoded_bytes": 0, "instruction_count": 0, "gaps": [], "complete": False,
                    "details_complete": False, "cancelled": False, "engine": "none", "worker_id": None}
        state = full_decode._ProcessRegion(0, coverage, 1, 1, [5])
        state.commit(result)
        self.assertEqual(state.work["gaps"], [{"address": BASE, "offset": 0, "size": 5,
                                               "reason": ANCHOR_RESYNC}])
        self.assertEqual(state.work["decoded_bytes"], len(code) - 5)
        serial = stream_decode_regions(code, _image(len(code)), anchors=[BASE + 5])
        self.assertEqual(serial[1][0]["gaps"], state.work["gaps"])
        self.assertEqual(serial[1][0]["decoded_bytes"], state.work["decoded_bytes"])

    def test_step_that_would_skip_an_off_grid_anchor_falls_back(self):
        # 定长步进跨过网格外的锚点只可能出现在异常相位：子进程交回串行循环（返回 None）。
        decode = NativeDecoder("arm64").decode_bytes_fast
        code = b"\xff\xff\xff\xff" * 4
        self.assertIsNone(_decode_worker.sweep(decode, code, 0, BASE, len(code), 0, len(code), 64, 4,
                                               full_decode._LOOKAHEAD, full_decode._INVALID_MNEMONICS,
                                               False, (2,)))


class FullAnalysisAnchorTests(unittest.TestCase):
    def test_analyze_full_passes_declared_starts_and_entry_as_anchors(self):
        seen: dict[str, Any] = {}

        def fake(data, image, **kwargs):
            seen.update(kwargs)
            return {}, [], []

        functions = [{"name": "b", "start": BASE + 0x20, "size": 4},
                     {"name": "a", "start": BASE + 0x10, "size": None},
                     {"name": "a_alias", "start": BASE + 0x10},
                     {"name": "odd", "start": None}, {"name": "flag", "start": True}]
        image = _image(0x40, functions=functions, entry=BASE + 0x30)
        with patch.object(full_analysis, "stream_decode_regions", side_effect=fake):
            with XrefStage() as stage:
                full_analysis.analyze_full(bytes(0x40), image, workers=1, xref_stage=stage)
        self.assertEqual(seen["anchors"], [BASE + 0x10, BASE + 0x20, BASE + 0x30])
        self.assertTrue(seen["include_data"])
        self.assertEqual(full_analysis._resync_anchors(_image(0x40, entry=None)), [])


_DIE_SOURCE = r"""
#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline)) void die(const char *message) {
    fprintf(stderr, "fatal: %s\n", message);
    abort();
}

int main(int argc, char **argv) {
    if (argc > 3)
        die(argv[1]);
    exit(argc);
}
"""


@unittest.skipUnless(CAPSTONE and shutil.which("clang") and platform.system() == "Darwin",
                     "Requires clang on macOS")
class CompiledMachOTests(unittest.TestCase):
    def test_die_after_zero_padding_is_decoded_and_noreturn(self):
        from fangida.core.kkagent import PluginImpl
        from fangida.core.kkagent.binary import parse_binary
        from fangida.models import AnalysisTask

        with tempfile.TemporaryDirectory() as directory:
            source, binary = Path(directory) / "die.c", Path(directory) / "die"
            source.write_text(_DIE_SOURCE)
            compiled = subprocess.run(["clang", "-O2", "-arch", "x86_64", "-o", str(binary), str(source)],
                                      capture_output=True)
            if compiled.returncode:
                self.skipTest(f"clang cannot build x86_64: {compiled.stderr.decode(errors='replace')[:200]}")
            data = binary.read_bytes()
            image = parse_binary(data, "macho")
            die = next(item["start"] for item in image.functions if item.get("name") == "_die")
            plain = stream_decode_regions(data, image)
            anchored = stream_decode_regions(data, image, anchors=full_analysis._resync_anchors(image))
            self.assertIn(die, anchored[0])
            if die not in plain[0]:
                # 当前工具链的布局：main 的 exit 调用之后是零填充，填充末尾的指令跨过 _die。
                gaps = [gap for region in anchored[1] for gap in region["gaps"]
                        if gap["reason"] == ANCHOR_RESYNC]
                self.assertEqual([gap["address"] + gap["size"] for gap in gaps], [die])
            for threads in (1, 2):
                with self.subTest(threads=threads):
                    result = PluginImpl().analyze(AnalysisTask(str(binary), "macho", full_analysis=True,
                                                               semantic_threads=threads))
                    self.assertFalse([warning for warning in result.warnings
                                      if "outside decoded instruction boundaries" in warning])
                    named = {fn["name"]: fn for fn in result.functions if fn.get("cfg")}
                    function = named["_die"]
                    self.assertEqual(function["analysis_scope"], "full_region_recovered_function")
                    self.assertTrue(function["cfg"]["complete"])
                    self.assertTrue(function["noreturn"])
                    self.assertEqual(function["noreturn_evidence"]["evidence"], "local_fixed_point")
                    self.assertEqual([call["name"] for call in function["cfg"]["noreturn_calls"]],
                                     ["abort"])
                    # 调用者现在知道 _die 不返回。
                    calls = {call["name"] for call in named["_main"]["cfg"]["noreturn_calls"]}
                    self.assertEqual(calls, {"_die", "exit"})
                    self.assertFalse(any(fn.get("analysis_scope") == "not_decoded"
                                         for fn in result.functions))


def _thin_slice(path: str, directory: str) -> Path | None:
    output = Path(directory) / (Path(path).name + "_x86_64")
    done = subprocess.run(["lipo", "-thin", "x86_64", path, "-output", str(output)], capture_output=True)
    return output if done.returncode == 0 and output.is_file() else None


@unittest.skipUnless(CAPSTONE and platform.system() == "Darwin" and shutil.which("lipo")
                     and os.path.isfile("/bin/zsh") and os.path.isfile("/bin/bash"),
                     "Requires the x86_64 slices of /bin/zsh and /bin/bash on macOS")
class SystemSliceTests(unittest.TestCase):
    def test_zsh_declared_starts_decode_and_bash_is_unchanged(self):
        from fangida.core.kkagent import PluginImpl
        from fangida.core.kkagent.binary import parse_binary
        from fangida.models import AnalysisTask

        with tempfile.TemporaryDirectory() as directory:
            zsh, bash = _thin_slice("/bin/zsh", directory), _thin_slice("/bin/bash", directory)
            if zsh is None or bash is None:
                self.skipTest("lipo cannot extract the x86_64 slices")
            # bash 的声明入口原本都是指令边界：锚点不改变任何记录或覆盖。
            data = bash.read_bytes()
            image = parse_binary(data, "macho")
            anchors = full_analysis._resync_anchors(image)
            self.assertEqual(_canonical(stream_decode_regions(data, image, anchors=anchors)),
                             _canonical(stream_decode_regions(data, image)))
            # zsh：串行与默认阈值下的多进程路径逐字段一致，且不再有声明入口落在指令内部。
            data = zsh.read_bytes()
            image = parse_binary(data, "macho")
            anchors = full_analysis._resync_anchors(image)
            serial = stream_decode_regions(data, image, include_data=True, anchors=anchors)
            diagnostics: dict[str, Any] = {}
            parallel = stream_decode_regions(data, image, workers=4, include_data=True, processes=True,
                                             diagnostics=diagnostics, anchors=anchors)
            self.assertEqual(_canonical(parallel), _canonical(serial))
            self.assertGreaterEqual(diagnostics["processes_used"], 2)
            _assert_resynchronized(self, serial, [anchor for anchor in anchors
                                                  if any(region["address"] <= anchor
                                                         < region["address"] + region["file_backed_size"]
                                                         for region in serial[1])])
            result = PluginImpl().analyze(AnalysisTask(str(zsh), "macho", full_analysis=True,
                                                       semantic_threads=4))
            self.assertEqual([warning for warning in result.warnings
                              if "outside decoded instruction boundaries" in warning], [])
            self.assertEqual(sum(fn.get("analysis_scope") == "not_decoded" for fn in result.functions), 0)


if __name__ == "__main__":
    unittest.main()
