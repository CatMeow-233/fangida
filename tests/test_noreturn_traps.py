"""非返回函数分析复核：可恢复陷阱不是终点、不返回调用之后的陷阱照常保留、
x86 “mov reg, [槽位]; call reg” 调用点、本地不动点精简路径与摘要路径一致、reached 增量更新。

机器码一律经处理器（Capstone）真实解码后进入完整分析或语义路径；Mach-O 用例由本机 clang++
编译，x86_64 版本在 Rosetta 下实际运行，确认 int3 之后确实继续执行、调试陷阱包装函数会返回。
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from fangida.core.kkagent import full_analysis, noreturn
from fangida.core.kkagent.binary import parse_binary
from fangida.core.kkagent.cfg import build_entry_cfg
from fangida.core.kkagent.noreturn import (MAX_STUB_INSTRUCTIONS, deterministic_trap,
                                           import_noreturn, local_noreturn)
from fangida.core.kkagent.semantic import analyze_semantics
from fangida.loaders.models import BinaryImage
from fangida.xrefs import XrefStage
from tests._speed import slow

from tests.test_noreturn import addresses, by_start, instruction, run_full


CAPSTONE = importlib.util.find_spec("capstone") is not None
LIBTERSAFE = Path("/Users/meow233/Downloads/libtersafe.so")
CHALLENGE = Path("/Users/meow233/Downloads/project/dist/challenge")
_BITS = {"x86_64": 64, "arm64": 64, "arm": 32}
# 各架构的填充字节：只填在函数之间，不会被任何 CFG 到达。
_FILL = {"x86_64": b"\xcc", "arm64": b"\0", "arm": b"\0"}


def decode_one(architecture, code):
    """用处理器解码一条指令（与完整分析使用同一处理器）。"""
    from fangida.processors import get_processor
    rows, _ = get_processor(architecture, "little").decode_bytes(code, 0x1000, max_instructions=1)
    return rows[0]


def flat_image(architecture, chunks, functions, *, relocations=(), extra=b"", extra_sections=()):
    """把 {地址: 机器码} 放进一个文件偏移从 0 开始的可执行节，返回 (data, BinaryImage)。"""
    base = min(chunks)
    end = max(address + len(code) for address, code in chunks.items())
    text = bytearray(_FILL[architecture] * (end - base))
    for address, code in chunks.items():
        text[address - base:address - base + len(code)] = code
    image = BinaryImage("elf", architecture, _BITS[architecture], "little", entry_address=base,
                        sections=[{"name": ".text", "address": base, "offset": 0, "size": len(text),
                                   "executable": True}, *extra_sections],
                        functions=[{"source": "symtab", **item} for item in functions],
                        dynamic_relocations=list(relocations))
    return bytes(text) + extra, image


def analyze(data, image, *, workers=1):
    with XrefStage(separate_thread=workers > 1) as stage:
        return full_analysis.analyze_full(data, image, workers=workers, xref_stage=stage)


def a64(*words):
    return struct.pack(f"<{len(words)}I", *words)


def a64_bl(source, target):
    return 0x94000000 | (((target - source) // 4) & 0x3FFFFFF)


def arm_bl(source, target):
    return 0xEB000000 | (((target - (source + 8)) // 4) & 0xFFFFFF)


def x86_call(source, target):
    return b"\xe8" + struct.pack("<i", target - (source + 5))


@unittest.skipUnless(CAPSTONE, "Capstone is required for real decoding")
class DeterministicTrapTests(unittest.TestCase):
    def test_only_traps_that_never_fall_through_are_deterministic(self):
        cases = [
            ("x86_64", "0f0b", "ud2", True),
            ("x86_64", "0fff", "ud0", True),
            ("x86_64", "0fb9c0", "ud1", True),
            ("x86_64", "cc", "int3", False),      # 调试器/SIGTRAP 处理函数返回后继续执行
            ("x86_64", "f4", "hlt", False),       # 内核态被中断唤醒后继续执行
            ("arm64", "200020d4", "brk", True),   # brk #1：__builtin_trap
            ("arm64", "00003ed4", "brk", False),  # brk #0xf000：__builtin_debugtrap
            ("arm64", "000021d4", "brk", False),  # brk #0x800：Linux 内核 WARN，处理后继续
            ("arm64", "00000000", "udf", True),
            ("arm", "f000f0e7", "udf", True),
            ("arm", "700020e1", "bkpt", False),
        ]
        for architecture, code, mnemonic, expected in cases:
            with self.subTest(architecture=architecture, code=code):
                row = decode_one(architecture, bytes.fromhex(code))
                self.assertEqual(row["mnemonic"], mnemonic)
                self.assertEqual(row["branch_info"]["kind"], "trap")
                self.assertIs(deterministic_trap(row), expected)
        # objdump 风格的立即数写法同样识别。
        self.assertTrue(deterministic_trap({"mnemonic": "brk", "operands": ("#0x1",)}))
        self.assertFalse(deterministic_trap({"mnemonic": "brk", "operands": ("#0xf000",)}))
        self.assertFalse(deterministic_trap({"mnemonic": "brk", "operands": ()}))

    def test_module_documentation_matches_stub_budget(self):
        self.assertEqual(MAX_STUB_INSTRUCTIONS, 6)
        self.assertIn(f"MAX_STUB_INSTRUCTIONS（{MAX_STUB_INSTRUCTIONS}）", noreturn.__doc__)
        self.assertNotIn("不超过 4 条", noreturn.__doc__)


def _x86_trap_program(trap):
    """dbg: <trap>; ret | use_dbg: call dbg; add eax, 1; ret | main: call use_dbg; xor eax, eax; ret"""
    chunks = {0x1000: trap + b"\xc3",
              0x1004: x86_call(0x1004, 0x1000) + bytes.fromhex("83c001c3"),
              0x1010: x86_call(0x1010, 0x1004) + bytes.fromhex("31c0c3")}
    functions = [{"name": "dbg", "start": 0x1000, "size": len(trap) + 1},
                 {"name": "use_dbg", "start": 0x1004, "size": 9},
                 {"name": "main", "start": 0x1010, "size": 8}]
    return flat_image("x86_64", chunks, functions)


def _a64_trap_program(trap_word):
    """dbg: <trap>; ret | use_dbg: bl dbg; add w0, w0, #1; ret | main: bl use_dbg; mov w0, #0; ret"""
    chunks = {0x1000: a64(trap_word, 0xD65F03C0),
              0x1008: a64(a64_bl(0x1008, 0x1000), 0x11000400, 0xD65F03C0),
              0x1014: a64(a64_bl(0x1014, 0x1008), 0x52800000, 0xD65F03C0)}
    functions = [{"name": "dbg", "start": 0x1000, "size": 8},
                 {"name": "use_dbg", "start": 0x1008, "size": 12},
                 {"name": "main", "start": 0x1014, "size": 12}]
    return flat_image("arm64", chunks, functions)


def _arm_trap_program(trap_word):
    """dbg: <trap>; bx lr | use_dbg: bl dbg; add r0, r0, #1; bx lr | main: bl use_dbg; mov r0, #0; bx lr"""
    chunks = {0x1000: a64(trap_word, 0xE12FFF1E),
              0x1008: a64(arm_bl(0x1008, 0x1000), 0xE2800001, 0xE12FFF1E),
              0x1014: a64(arm_bl(0x1014, 0x1008), 0xE3A00000, 0xE12FFF1E)}
    functions = [{"name": "dbg", "start": 0x1000, "size": 8},
                 {"name": "use_dbg", "start": 0x1008, "size": 12},
                 {"name": "main", "start": 0x1014, "size": 12}]
    return flat_image("arm", chunks, functions)


@unittest.skipUnless(CAPSTONE, "Capstone is required for real decoding")
class RecoverableTrapFixedPointTests(unittest.TestCase):
    """“陷阱; 返回”形式的函数：只有确定性陷阱才让它（及其调用者）成为不返回函数。"""

    def check(self, data, image, *, recoverable, use_dbg_size):
        functions, _, stats, metadata, _ = analyze(data, image)
        named = {fn["name"]: fn for fn in by_start(functions).values()}
        dbg, use_dbg, main = named["dbg"], named["use_dbg"], named["main"]
        # reached（无共享指令时走增量更新）与按最终 CFG 汇总的结果相同。
        union = {address for fn in by_start(functions).values() for address in addresses(fn)}
        self.assertEqual(stats["semantic_instructions"], len(union))
        self.assertEqual(stats["full_unassigned_instructions"], stats["full_instructions"] - len(union))
        if recoverable:
            # 可恢复陷阱按未知出口处理：没有任何函数被推为不返回，调用者保留调用之后的代码。
            self.assertEqual(stats["full_noreturn_local_functions"], 0)
            self.assertEqual(stats["full_noreturn_rebuilt_functions"], 0)
            for function in (dbg, use_dbg, main):
                self.assertNotIn("noreturn", function)
                self.assertEqual(function["cfg"]["noreturn_calls"], [])
            self.assertEqual(len(addresses(use_dbg)), use_dbg_size)
            self.assertEqual(len(addresses(main)), 3)
            self.assertEqual(metadata["full_analysis"]["noreturn"]["targets"], [])
        else:
            # 对照组：确定性陷阱逐层传播，调用者在调用处截断。
            self.assertEqual([named[name]["noreturn_evidence"]["round"] for name in ("dbg", "use_dbg", "main")],
                             [1, 2, 3])
            self.assertEqual(len(addresses(use_dbg)), 1)
            self.assertEqual(len(addresses(main)), 1)
            self.assertEqual([call["name"] for call in use_dbg["cfg"]["noreturn_calls"]], ["dbg"])
            self.assertEqual(stats["full_noreturn_rebuilt_functions"], 2)

    def test_x86_int3_and_hlt_are_recoverable_but_ud2_is_not(self):
        for trap, recoverable in ((b"\xcc", True), (b"\xf4", True), (b"\x0f\x0b", False)):
            with self.subTest(trap=trap.hex()):
                self.check(*_x86_trap_program(trap), recoverable=recoverable, use_dbg_size=3)

    def test_arm64_debugtrap_is_recoverable_but_builtin_trap_is_not(self):
        for word, recoverable in ((0xD43E0000, True), (0xD4210000, True), (0xD4200020, False),
                                  (0x00000000, False)):
            with self.subTest(word=hex(word)):
                self.check(*_a64_trap_program(word), recoverable=recoverable, use_dbg_size=3)

    def test_arm_bkpt_is_recoverable_but_udf_is_not(self):
        for word, recoverable in ((0xE1200070, True), (0xE7F000F0, False)):
            with self.subTest(word=hex(word)):
                self.check(*_arm_trap_program(word), recoverable=recoverable, use_dbg_size=3)

    def test_kernel_style_hlt_loop_wrapper_is_not_noreturn(self):
        # native_halt: hlt; ret —— 它的调用者 halt_loop: call native_halt; jmp halt_loop（无 ret 的循环）。
        # 循环本身确实不返回；但 native_halt 会返回，所以调用者是因为循环才不返回，而非因为 hlt。
        chunks = {0x1000: b"\xf4\xc3",
                  0x1004: x86_call(0x1004, 0x1000) + b"\xeb\xf9",
                  0x1010: x86_call(0x1010, 0x1000) + bytes.fromhex("31c0c3")}
        functions = [{"name": "native_halt", "start": 0x1000, "size": 2},
                     {"name": "halt_loop", "start": 0x1004, "size": 7},
                     {"name": "idle", "start": 0x1010, "size": 8}]
        resulting, _, stats, _, _ = analyze(*flat_image("x86_64", chunks, functions))
        named = {fn["name"]: fn for fn in by_start(resulting).values()}
        self.assertNotIn("noreturn", named["native_halt"])
        self.assertNotIn("noreturn", named["idle"])
        self.assertEqual(addresses(named["idle"]), [0x1010, 0x1015, 0x1017])
        self.assertEqual(named["halt_loop"]["noreturn_evidence"]["evidence"], "local_fixed_point")
        self.assertEqual(stats["full_noreturn_local_functions"], 1)


def _x86_exit_program(after, *, trap_function=False):
    """main: push rbp; mov edi, 1; call exit; <after> | exit: ret（名字在已知名单中）。"""
    head = bytes.fromhex("55bf01000000") + x86_call(0x1006, 0x1010)
    functions = [{"name": "main", "start": 0x1000, "size": 0xB if trap_function else 0xB + len(after)},
                 {"name": "exit", "start": 0x1010, "size": 1}]
    if trap_function:
        functions.append({"name": "trap_stub", "start": 0x100B, "size": len(after)})
    return flat_image("x86_64", {0x1000: head + after, 0x1010: b"\xc3"}, functions)


@unittest.skipUnless(CAPSTONE, "Capstone is required for real decoding")
class TrapAfterNoreturnCallTests(unittest.TestCase):
    """不返回调用之后紧跟的陷阱照常保留：不多吸入代码，下游伪 C 与微码保持完整。"""

    def test_semantic_path_keeps_trap_and_marks_the_record(self):
        for after in (b"\x0f\x0b", b"\xcc"):
            with self.subTest(after=after.hex()):
                data, image = _x86_exit_program(after)
                functions = analyze_semantics(data, image)[0]
                # 并行路径（私有解码器）与串行结果逐字节一致。
                parallel = analyze_semantics(data, image, max_workers=2)[0]
                self.assertEqual(json.dumps(parallel, sort_keys=True), json.dumps(functions, sort_keys=True))
                main = by_start(functions)[0x1000]
                self.assertEqual(addresses(main), [0x1000, 0x1001, 0x1006, 0x100B])
                self.assertTrue(main["cfg"]["complete"])
                self.assertEqual(main["cfg"]["noreturn_calls"],
                                 [{"from": 0x1006, "fallthrough": 0x100B, "target": 0x1010,
                                   "name": "exit", "evidence": "symbol_name", "fallthrough_trap": True}])
                trap_block = [block for block in main["blocks"] if block["start"] == 0x100B]
                self.assertEqual(len(trap_block), 1)
                self.assertEqual(trap_block[0]["successors"], [])
                self.assertIn(0x100B, [block["successors"] for block in main["blocks"]
                                       if block["start"] == 0x1000][0])

    def test_non_trap_fallthrough_and_trap_at_another_function_start_stay_truncated(self):
        data, image = _x86_exit_program(b"\x90\xc3")
        main = by_start(analyze_semantics(data, image)[0])[0x1000]
        self.assertEqual(addresses(main), [0x1000, 0x1001, 0x1006])
        self.assertNotIn("fallthrough_trap", main["cfg"]["noreturn_calls"][0])
        self.assertTrue(main["cfg"]["complete"])
        # 陷阱是另一个已知函数的入口：不跨入别的函数，仍然截断且不留出口。
        data, image = _x86_exit_program(b"\x0f\x0b", trap_function=True)
        main = by_start(analyze_semantics(data, image)[0])[0x1000]
        self.assertEqual(addresses(main), [0x1000, 0x1001, 0x1006])
        self.assertEqual(main["cfg"]["frontier"], [])
        self.assertNotIn("fallthrough_trap", main["cfg"]["noreturn_calls"][0])

    def test_full_mode_and_entry_window_keep_the_trap(self):
        data, image = _x86_exit_program(b"\x0f\x0b")
        functions, _, stats, _, _ = analyze(data, image)
        main = by_start(functions)[0x1000]
        self.assertEqual(addresses(main), [0x1000, 0x1001, 0x1006, 0x100B])
        self.assertTrue(main["cfg"]["noreturn_calls"][0]["fallthrough_trap"])
        # 陷阱块只经不返回调用的落空边到达，不影响“main 不返回”的推导。
        self.assertEqual(main["noreturn_evidence"]["evidence"], "local_fixed_point")
        self.assertEqual(stats["semantic_instructions"], 5)
        from fangida.processors import get_processor
        rows, _ = get_processor("x86_64", "little").decode_bytes(data[:0xD], 0x1000, max_instructions=16)
        graph, reached = build_entry_cfg(rows, 0x1000, {0x1010: {"name": "exit", "evidence": "symbol_name"}})
        self.assertEqual(sorted(reached), [0x1000, 0x1001, 0x1006, 0x100B])
        self.assertTrue(graph["complete"])
        self.assertTrue(graph["noreturn_calls"][0]["fallthrough_trap"])
        truncated, reached = build_entry_cfg(
            get_processor("x86_64", "little").decode_bytes(
                _x86_exit_program(b"\x90\xc3")[0][:0xD], 0x1000, max_instructions=16)[0],
            0x1000, {0x1010: {"name": "exit", "evidence": "symbol_name"}})
        self.assertEqual(sorted(reached), [0x1000, 0x1001, 0x1006])
        self.assertNotIn("fallthrough_trap", truncated["noreturn_calls"][0])

    def test_pseudoc_and_microcode_stay_complete(self):
        from fangida.plugins.pseudoc import generate_pseudoc
        data, image = _x86_exit_program(b"\x0f\x0b")
        main = by_start(analyze_semantics(data, image)[0])[0x1000]
        output = generate_pseudoc(main, "x86_64", style="readable")
        self.assertIn("trap();", output.pseudoc)
        self.assertNotIn("unresolved_fallthrough", output.pseudoc)
        self.assertFalse(output.truncated)
        self.assertTrue(output.microcode and all(row["supported"] for row in output.microcode))
        self.assertFalse([item for item in output.reconstruction.get("unresolved", ())
                          if item.get("kind") == "control_flow_target"])


def _slot_program(name, call, *, between=b""):
    """main: mov rax, [rip + 槽位]; <between>; <call>; xor eax, eax; ret；槽位由 GLOB_DAT 绑定到 name。"""
    text, got = 0x1000, 0x3000
    load = bytes.fromhex("488b05") + struct.pack("<i", got - (text + 7))
    code = load + between + call + bytes.fromhex("31c0c3")
    relocations = [{"type": 6, "address": got, "symbol_name": name, "address_kind": "virtual_address"}]
    data, image = flat_image("x86_64", {text: code}, [{"name": "main", "start": text, "size": len(code)}],
                             relocations=relocations,
                             extra_sections=[{"name": ".got", "address": got, "offset": 0x100, "size": 8,
                                              "executable": False}])
    return data.ljust(0x100, b"\xcc") + b"\0" * 8, image, 0x1007 + len(between)


@unittest.skipUnless(CAPSTONE, "Capstone is required for real decoding")
class X86SlotRegisterCallTests(unittest.TestCase):
    """x86 ``mov reg, [slot]; call reg``：经导入槽位装入寄存器后的间接调用点。"""

    def test_load_then_call_register_is_a_noreturn_call_site(self):
        data, image, call = _slot_program("abort", b"\xff\xd0")
        functions, _, stats, metadata, _ = analyze(data, image)
        main = by_start(functions)[0x1000]
        self.assertEqual(addresses(main), [0x1000, call])
        self.assertEqual(main["cfg"]["noreturn_calls"],
                         [{"from": call, "fallthrough": call + 2, "target": None, "name": "abort",
                           "evidence": "import_slot_call"}])
        site = metadata["full_analysis"]["noreturn"]["call_sites"]
        self.assertEqual([(item["address"], item["slot"], item["source"]) for item in site],
                         [(call, 0x3000, "elf_relocation")])
        self.assertEqual(stats["full_noreturn_call_sites"], 1)
        self.assertEqual(main["noreturn_evidence"]["evidence"], "local_fixed_point")

    def test_returning_import_memory_operand_and_overwritten_register_are_not_sites(self):
        cases = [("puts", b"\xff\xd0", b""),                     # 会返回的导入
                 ("abort", b"\xff\x50\x08", b""),                 # call [rax + 8]：以装入值为基址
                 ("abort", b"\xff\xd0", bytes.fromhex("4889d8"))]  # mov rax, rbx 覆盖了装入值
        for name, call, between in cases:
            with self.subTest(name=name, call=call.hex(), between=between.hex()):
                data, image, _ = _slot_program(name, call, between=between)
                functions, _, stats, _, _ = analyze(data, image)
                main = by_start(functions)[0x1000]
                self.assertEqual(stats["full_noreturn_call_sites"], 0)
                self.assertEqual(main["cfg"]["noreturn_calls"], [])
                rows = sorted((row for block in main["blocks"] for row in block["instructions"]),
                              key=lambda row: row["addr"])
                self.assertEqual(rows[-1]["mnemonic"], "ret")  # 调用之后的代码仍被保留
                self.assertNotIn("noreturn", main)

    def test_join_point_between_load_and_call_disables_the_site(self):
        data, image, call = _slot_program("abort", b"\xff\xd0")
        from fangida.processors import get_processor
        rows, _ = get_processor("x86_64", "little").decode_bytes(data[:0x10], 0x1000, max_instructions=8)
        cache = {row["addr"]: row for row in rows}
        references = [{"src": 0x1000, "dst": 0x3000, "kind": "data", "confidence": 1.0}]
        self.assertEqual(sorted(import_noreturn(cache, references, image)[1]), [call])
        joined = references + [{"src": 0x2000, "dst": call, "kind": "jmp", "confidence": 1.0}]
        self.assertEqual(import_noreturn(cache, joined, image)[1], {})


class ReachedIncrementalUpdateTests(unittest.TestCase):
    def test_exclusive_instructions_use_the_incremental_update(self):
        # 首轮没有共享指令：重建后只减去被截掉的指令，不再按全部函数重新汇总。
        if not CAPSTONE:
            self.skipTest("Capstone is required for real decoding")
        functions, _, stats, _, _ = analyze(*_x86_trap_program(b"\x0f\x0b"))
        union = {address for fn in by_start(functions).values() for address in addresses(fn)}
        self.assertEqual(stats["full_noreturn_rebuilt_functions"], 2)
        self.assertEqual(stats["semantic_instructions"], len(union))
        self.assertEqual(sorted(union), [0x1000, 0x1004, 0x1010])

    def test_shared_tail_stays_reached_after_rebuild(self):
        # A: call F; nop; jmp T | B: jmp T | T: nop; ret | F: ud2（确定性陷阱，首轮即不返回）。
        # T 被 A、B 共享：走按最终 CFG 重新汇总的分支，结果同样精确。
        cache = {0x1000: instruction(0x1000, "call", 0x2000, size=5),
                 0x1005: instruction(0x1005),
                 0x1006: instruction(0x1006, "jump", 0x1100, size=2),
                 0x1080: instruction(0x1080, "jump", 0x1100, size=2),
                 0x1100: instruction(0x1100),
                 0x1101: instruction(0x1101, "return"),
                 0x2000: instruction(0x2000, "trap")}
        image = BinaryImage("elf", "x86_64", 64, "little", entry_address=0x1000,
                            functions=[{"name": "A", "start": 0x1000, "size": None, "source": "symtab"},
                                       {"name": "B", "start": 0x1080, "size": None, "source": "symtab"},
                                       {"name": "F", "start": 0x2000, "size": None, "source": "symtab"}])
        functions, _, stats, _, _ = run_full(cache, image, (0x1000, 0x1001))
        named = {fn["name"]: fn for fn in by_start(functions).values()}
        self.assertEqual(addresses(named["A"]), [0x1000])
        self.assertEqual(addresses(named["B"]), [0x1080, 0x1100, 0x1101])
        self.assertEqual(stats["full_noreturn_rebuilt_functions"], 1)
        union = {address for fn in by_start(functions).values() for address in addresses(fn)}
        self.assertEqual(stats["semantic_instructions"], len(union))
        self.assertEqual(stats["full_unassigned_instructions"], len(cache.keys() - union))
        self.assertEqual(sorted(cache.keys() - union), [0x1005, 0x1006])


def _first_pass(data, image, *, workers):
    """运行完整分析并截获交给本地不动点的首轮 CFG。"""
    captured = {}
    original = full_analysis.local_noreturn

    def capture(functions, targets, sites, **options):
        captured["args"] = (list(functions), dict(targets), dict(sites))
        return original(functions, targets, sites, **options)

    with patch.object(full_analysis, "local_noreturn", side_effect=capture):
        result = analyze(data, image, workers=workers)
    return captured["args"], result


class LeanScanEquivalenceMixin:
    """精简扫描 + 块上遍历（本项目 CFG）与 _summary + _may_return（通用图）结论逐项一致。"""

    sample: Path

    def test_lean_and_summary_paths_agree(self):
        data = self.sample.read_bytes()
        (functions, targets, sites), (final, _, stats, _, _) = _first_pass(
            data, parse_binary(data, "elf"), workers=4)
        stripped = [{**fn, "cfg": {**fn["cfg"], "scope": "external_graph"}} for fn in functions]
        lean, generic = local_noreturn(functions, targets, sites), local_noreturn(stripped, targets, sites)
        self.assertEqual(lean, generic)
        known = {**targets, **lean[0]}
        for function in functions:
            summary = noreturn._summary(function)
            if summary is None:
                continue
            for current in (targets, known):
                self.assertEqual(noreturn._may_return_blocks(function, current, sites),
                                 noreturn._may_return(summary[0], summary[1], current, sites),
                                 hex(function["start"]))
        # reached 增量更新与按最终 CFG 汇总的结果相同。
        union = {address for fn in final if fn.get("cfg") for address in addresses(fn)}
        self.assertEqual(stats["semantic_instructions"], len(union))
        self.assertEqual(stats["full_unassigned_instructions"], stats["full_instructions"] - len(union))


@unittest.skipUnless(CAPSTONE and CHALLENGE.is_file(), "challenge sample is not available")
class ChallengeLeanScanTests(LeanScanEquivalenceMixin, unittest.TestCase):
    sample = CHALLENGE


@slow("libtersafe 全量扫描")
@unittest.skipUnless(CAPSTONE and LIBTERSAFE.is_file(), "libtersafe.so sample is not available")
class LibtersafeLeanScanTests(LeanScanEquivalenceMixin, unittest.TestCase):
    sample = LIBTERSAFE


_TRAP_SOURCE = r"""
#include <cstdio>
#include <cstdlib>
#include <csignal>
extern "C" {
static volatile int g_hits;
__attribute__((noinline)) void die(const char *m) { puts(m); abort(); }
__attribute__((noinline)) int check(int v) { if (v < 0) die("neg"); return v * 2; }
// 调试陷阱：x86 上 int3 之后继续执行（SIGTRAP 处理函数返回后）
__attribute__((noinline)) void dbg(void) { __builtin_debugtrap(); }
__attribute__((noinline)) int use_dbg(int v) { dbg(); g_hits += v; return g_hits; }
__attribute__((noinline)) int catcher(int x) { try { if (x) throw x; return 0; } catch (int e) { return e + 100; } }
static void on_trap(int) { g_hits += 1000; }
int main(int argc, char **argv) {
  signal(SIGTRAP, on_trap);
  if (argc > 3) exit(3);
  int a = use_dbg(argc);
  int b = catcher(argc - 1);
  printf("use_dbg=%d catcher=%d check=%d\n", a, b, check(argc - 1));
  return 0;
}
}
"""


def _rosetta_available():
    try:
        return subprocess.run(["/usr/bin/arch", "-x86_64", "/usr/bin/true"], capture_output=True,
                              timeout=30).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


@unittest.skipUnless(CAPSTONE and shutil.which("clang++") and platform.system() == "Darwin",
                     "Requires clang++ on macOS")
class CompiledDebugTrapTests(unittest.TestCase):
    """clang++ 编译的 Mach-O：__builtin_debugtrap 包装函数会返回；__cxa_throw 之后的陷阱保留。"""

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        root = Path(cls.directory.name)
        source = root / "t.cpp"
        source.write_text(_TRAP_SOURCE)
        cls.binaries = {}
        for arch in ("x86_64", "arm64"):
            binary = root / f"t_{arch}"
            compiled = subprocess.run(["clang++", "-O1", "-arch", arch, "-o", str(binary), str(source)],
                                      capture_output=True)
            if compiled.returncode == 0:
                cls.binaries[arch] = binary

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_x86_64_program_really_returns_after_int3(self):
        binary = self.binaries.get("x86_64")
        if binary is None or not _rosetta_available():
            self.skipTest("x86_64 toolchain or Rosetta is not available")
        run = subprocess.run(["/usr/bin/arch", "-x86_64", str(binary), "x"], capture_output=True,
                             text=True, timeout=60)
        self.assertEqual(run.returncode, 0)
        # 1000（SIGTRAP 处理函数）+ 2（argc）：int3 之后 use_dbg 继续执行并返回。
        self.assertIn("use_dbg=1002 catcher=101 check=2", run.stdout)

    def test_full_analysis_keeps_debugtrap_callers_returning(self):
        for arch, binary in sorted(self.binaries.items()):
            with self.subTest(arch=arch):
                data = binary.read_bytes()
                functions, _, _, metadata, _ = analyze(data, parse_binary(data, "macho"))
                named = {fn["name"]: fn for fn in functions if fn.get("cfg")}
                for name in ("_dbg", "_use_dbg", "_main", "_catcher", "_check"):
                    self.assertNotIn("noreturn", named[name], name)
                self.assertEqual(named["_die"]["noreturn_evidence"]["evidence"], "local_fixed_point")
                mnemonics = [row["mnemonic"] for block in named["_use_dbg"]["blocks"]
                             for row in block["instructions"]]
                self.assertIn("ret", mnemonics)
                local = [item["name"] for item in metadata["full_analysis"]["noreturn"]["targets"]
                         if item["evidence"] == "local_fixed_point"]
                self.assertNotIn("_dbg", local)

    def test_plugin_pseudoc_keeps_trap_after_cxa_throw(self):
        from fangida.core.kkagent import PluginImpl
        from fangida.models import AnalysisTask
        for arch, binary in sorted(self.binaries.items()):
            for full in (False, True):
                with self.subTest(arch=arch, full=full):
                    result = PluginImpl().analyze(AnalysisTask(str(binary), "macho", full_analysis=full,
                                                               semantic_threads=1))
                    catcher = next(fn for fn in result.functions if fn.get("name") == "_catcher")
                    calls = catcher["cfg"].get("noreturn_calls") or []
                    throws = [call for call in calls if call.get("name") == "__cxa_throw"]
                    if not throws or not throws[0].get("fallthrough_trap"):
                        self.skipTest("compiler did not place a trap after __cxa_throw")
                    self.assertTrue(catcher["microcode_complete"])
                    self.assertFalse(catcher["pseudoc_truncated"])
                    self.assertIn("trap();", catcher["pseudoc"])
                    self.assertNotIn("unresolved_fallthrough", catcher["pseudoc"])
                    json.dumps(catcher["cfg"])  # 记录可序列化


if __name__ == "__main__":
    unittest.main()
