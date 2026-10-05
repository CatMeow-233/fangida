"""非返回函数分析：已知名单、导入桩、本地不动点、默认行为不变与线程约束。

合成快照只用于精确控制 CFG 形状；arm64 PLT 与语义路径使用真实机器码经处理器解码，
Mach-O 用本机 clang 编译并实际运行确认语义，两个真实样本存在时做端到端核对。
"""
from __future__ import annotations

from contextlib import ExitStack
import importlib.util
import json
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import tempfile
from threading import get_ident
import unittest
from unittest.mock import patch

from fangida.core.kkagent import full_analysis
from fangida.core.kkagent.binary import parse_binary
from fangida.core.kkagent.cfg import build_entry_cfg
from fangida.core.kkagent.noreturn import (import_noreturn, local_noreturn, noreturn_name,
                                           normalize_symbol_name)
from fangida.core.kkagent.semantic import _analyze_function, analyze_semantics
from fangida.loaders.models import BinaryImage
from fangida.xrefs import XrefStage
from tests._speed import slow


CAPSTONE = importlib.util.find_spec("capstone") is not None
LIBTERSAFE = Path("/Users/meow233/Downloads/libtersafe.so")
CHALLENGE = Path("/Users/meow233/Downloads/project/dist/challenge")


def instruction(address, kind=None, target=None, *, size=1, conditional=False, mnemonic=None,
                operands=(), reads=(), writes=(), meta=None):
    """合成指令记录（与处理器输出同形）。"""
    names = {"call": "call", "jump": "jmp", "return": "ret", "trap": "ud2"}
    return {"addr": address, "size": size, "mnemonic": mnemonic or names.get(kind, "nop"),
            "operands": tuple(operands), "reads": tuple(reads), "writes": tuple(writes),
            "branch_info": ({"kind": kind, "target": target, "conditional": conditional}
                            if kind else {}),
            "arch_meta": {"engine": "test", **(meta or {})}}


def coverage(start, size):
    return [{"address": start, "offset": 0, "size": size, "decoded_bytes": size,
             "instruction_count": size, "complete": True, "engine": "test", "worker_id": None}]


def run_full(cache, image, region, *, workers=1, imports=None):
    """用给定的已完成快照运行完整分析（解码阶段被替换为该快照）。"""
    start, size = region
    with patch.object(full_analysis, "stream_decode_regions",
                      return_value=(dict(cache), coverage(start, size), [])):
        with XrefStage(separate_thread=workers > 1) as stage:
            return full_analysis.analyze_full(bytes(size), image, workers=workers,
                                              xref_stage=stage, imports=imports)


def by_start(functions):
    return {fn["start"]: fn for fn in functions if fn.get("cfg")}


def addresses(function):
    return sorted(ins["addr"] for block in function["blocks"] for ins in block["instructions"])


class NameNormalizationTests(unittest.TestCase):
    def test_version_prefix_and_underscore_rules(self):
        self.assertEqual(normalize_symbol_name("exit@GLIBC_2.2.5"), "exit")
        self.assertEqual(normalize_symbol_name("__imp__ExitProcess@4"), "_ExitProcess")
        self.assertEqual(normalize_symbol_name("?terminate@@YAXXZ"), "?terminate@@YAXXZ")
        self.assertEqual(noreturn_name("exit@@GLIBC_2.2.5", "elf"), "exit")
        self.assertEqual(noreturn_name("abort@plt", "elf"), "abort")
        self.assertEqual(noreturn_name("_exit", "elf"), "_exit")
        # Mach-O：C 名字等于符号去掉一个前导下划线。
        self.assertEqual(noreturn_name("_exit", "macho"), "exit")
        self.assertEqual(noreturn_name("__exit", "macho"), "_exit")
        self.assertEqual(noreturn_name("___stack_chk_fail", "macho"), "__stack_chk_fail")
        self.assertEqual(noreturn_name("__imp_ExitProcess", "pe"), "ExitProcess")
        self.assertEqual(noreturn_name("__imp__ExitProcess@4", "pe"), "ExitProcess")
        self.assertEqual(noreturn_name("__imp_?terminate@@YAXXZ", "pe"), "?terminate@@YAXXZ")
        # ELF 名字精确匹配；Windows 专有名字不用于 ELF。
        self.assertIsNone(noreturn_name("_abort", "elf"))
        self.assertIsNone(noreturn_name("terminate", "elf"))
        self.assertEqual(noreturn_name("terminate", "pe"), "terminate")
        self.assertIsNone(noreturn_name("printf", "elf"))
        self.assertIsNone(noreturn_name("exit_handler", "elf"))
        for name in ("__stack_chk_fail", "__cxa_throw", "_Unwind_Resume", "__assert2",
                     "__android_log_assert", "longjmp", "pthread_exit"):
            self.assertEqual(noreturn_name(name, "elf"), name)

    def test_std_throw_helpers_require_a_complete_std_source_name(self):
        for name in ("_ZSt20__throw_length_errorPKc", "_ZSt24__throw_out_of_range_fmtPKcz",
                     "_ZNKSt6__ndk120__vector_base_commonILb1EE20__throw_length_errorEv",
                     "_ZNSt3__120__throw_length_errorEPKc"):
            self.assertEqual(noreturn_name(name, "elf"), name)
        self.assertEqual(noreturn_name("__ZSt20__throw_length_errorPKc", "macho"),
                         "_ZSt20__throw_length_errorPKc")
        # 非 std 命名空间、长度与标识符不一致、或只是更长标识符的一部分：不接受。
        for name in ("_ZN3foo20__throw_length_errorEv", "_ZSt12do__throw_errv",
                     "_ZSt8__throw_v", "my__throw_error"):
            self.assertIsNone(noreturn_name(name, "elf"), name)


class FullModeNoreturnTests(unittest.TestCase):
    def test_known_name_target_truncates_fallthrough_with_evidence(self):
        cache = {0x1000: instruction(0x1000, "call", 0x1010, size=5),
                 0x1005: instruction(0x1005),
                 0x1006: instruction(0x1006, "return"),
                 0x1010: instruction(0x1010, "return")}
        image = BinaryImage("elf", "x86_64", 64, "little", entry_address=0x1000,
                            sections=[{"name": ".text", "address": 0x1000, "offset": 0,
                                       "size": 0x11, "executable": True}],
                            functions=[{"name": "main", "start": 0x1000, "size": 7, "source": "symtab"},
                                       {"name": "exit@GLIBC_2.2.5", "start": 0x1010, "size": 1,
                                        "source": "symtab"}])
        functions, _, stats, metadata, _ = run_full(cache, image, (0x1000, 0x11))
        functions = by_start(functions)
        main = functions[0x1000]
        self.assertEqual(addresses(main), [0x1000])
        self.assertTrue(main["cfg"]["complete"])
        self.assertEqual(main["cfg"]["frontier"], [])
        self.assertEqual(main["cfg"]["noreturn_calls"],
                         [{"from": 0x1000, "fallthrough": 0x1005, "target": 0x1010,
                           "name": "exit", "evidence": "symbol_name"}])
        self.assertTrue(functions[0x1010]["noreturn"])
        self.assertEqual(functions[0x1010]["noreturn_evidence"]["evidence"], "symbol_name")
        # main 唯一的路径结束于 exit：本地不动点把它也标为不返回。
        self.assertEqual(main["noreturn_evidence"], {"name": "main", "evidence": "local_fixed_point",
                                                     "round": 1})
        self.assertEqual(stats["full_noreturn_targets"], 2)
        self.assertEqual(stats["full_noreturn_calls"], 1)
        self.assertEqual(stats["full_noreturn_local_functions"], 1)
        self.assertEqual(stats["full_noreturn_rebuilt_functions"], 0)
        self.assertEqual(stats["full_unassigned_instructions"], 2)
        self.assertEqual([item["address"] for item in metadata["full_analysis"]["noreturn"]["targets"]],
                         [0x1000, 0x1010])
        json.dumps(metadata["full_analysis"]["noreturn"])  # 元数据须可 JSON 序列化

    def test_default_parameters_keep_the_original_cfg(self):
        cache = {0x1000: instruction(0x1000, "call", 0x1010, size=5),
                 0x1005: instruction(0x1005),
                 0x1006: instruction(0x1006, "return"),
                 0x1010: instruction(0x1010, "return")}
        regions = [full_analysis._Region(0x1000, 0, 0x11)]
        seed = {"name": "main", "start": 0x1000, "size": None, "source": "test", "boundary_known": False}

        def analyze(**options):
            decoder = full_analysis._CachedDecoder(cache, sorted(cache), regions, 0x1000, None, "test")
            return _analyze_function(dict(seed), decoder, {0x1000, 0x1010}, set(), 100, 100,
                                     validate_overlaps=False, collect_xrefs=False,
                                     compute_liveness=False, **options)

        default = analyze()
        self.assertEqual(analyze(noreturn_targets=None, noreturn_sites=None), default)
        self.assertEqual(analyze(noreturn_targets={}, noreturn_sites={}), default)
        function = default[0]
        self.assertNotIn("noreturn_calls", function["cfg"])
        self.assertEqual(function["cfg"]["assumptions"],
                         ["Calls may return to their fallthrough address",
                          "Unseeded jump targets are treated as intraprocedural"])
        self.assertEqual(addresses(function), [0x1000, 0x1005, 0x1006])
        # 名单中没有命中的调用：只多出空的审计字段，图本身不变。
        unrelated = analyze(noreturn_targets={0x2000: {"name": "abort"}})[0]
        self.assertEqual(unrelated["cfg"]["noreturn_calls"], [])
        self.assertEqual(unrelated["blocks"], function["blocks"])
        self.assertEqual(unrelated["cfg"]["edges"], function["cfg"]["edges"])
        self.assertEqual(unrelated["cfg"]["frontier"], function["cfg"]["frontier"])

    def test_conditional_call_keeps_its_fallthrough(self):
        cache = {0x1000: instruction(0x1000, "call", 0x1010, size=4, conditional=True, mnemonic="blne"),
                 0x1004: instruction(0x1004, "return", size=4),
                 0x1010: instruction(0x1010, "return", size=4)}
        regions = [full_analysis._Region(0x1000, 0, 0x14)]
        decoder = full_analysis._CachedDecoder(cache, sorted(cache), regions, 0x1000, None, "test")
        function = _analyze_function({"name": "f", "start": 0x1000, "size": None}, decoder,
                                     {0x1000, 0x1010}, set(), 100, 100, validate_overlaps=False,
                                     collect_xrefs=False, compute_liveness=False,
                                     noreturn_targets={0x1010: {"name": "abort"}})[0]
        self.assertEqual(addresses(function), [0x1000, 0x1004])
        self.assertEqual(function["cfg"]["noreturn_calls"], [])

    def _fixed_point_case(self):
        cache = {
            # C：调用包装函数 W 之后的代码只能经落空到达
            0x1000: instruction(0x1000, "call", 0x1100), 0x1001: instruction(0x1001),
            0x1002: instruction(0x1002, "return"),
            # W：所有路径都结束于 abort
            0x1100: instruction(0x1100), 0x1101: instruction(0x1101, "call", 0x1200),
            0x1102: instruction(0x1102), 0x1103: instruction(0x1103, "return"),
            # abort（按名字识别）
            0x1200: instruction(0x1200, "return"),
            # R：条件跳转绕过 abort 调用后返回，因此可能返回
            0x1300: instruction(0x1300, "jump", 0x1302, conditional=True),
            0x1301: instruction(0x1301, "call", 0x1200), 0x1302: instruction(0x1302, "return"),
            # I：间接跳转是未知出口，保守地不推导
            0x1400: instruction(0x1400, "call", 0x1200, conditional=False, mnemonic="call"),
            0x1401: instruction(0x1401, "jump", None),
            # D：调用 C（第三轮才成为不返回）
            0x1500: instruction(0x1500, "call", 0x1000), 0x1501: instruction(0x1501, "return"),
            # T：尾跳转进入不返回的 W
            0x1600: instruction(0x1600), 0x1601: instruction(0x1601, "jump", 0x1100),
        }
        # I 的第一条是对 abort 的调用：其后 0x1401 不可达，所以 I 实际上也不返回；
        # 换成普通调用目标 0x1700（会返回）以保留间接跳转出口。
        cache[0x1400] = instruction(0x1400, "call", 0x1700)
        cache[0x1700] = instruction(0x1700, "return")
        symbols = [{"name": name, "start": start, "size": size, "source": "symtab"}
                   for name, start, size in (("C", 0x1000, 3), ("W", 0x1100, 4), ("abort", 0x1200, 1),
                                             ("R", 0x1300, 3), ("I", 0x1400, 2), ("D", 0x1500, 2),
                                             ("T", 0x1600, 2), ("helper", 0x1700, 1))]
        image = BinaryImage("elf", "x86_64", 64, "little", entry_address=0x1000,
                            sections=[{"name": ".text", "address": 0x1000, "offset": 0,
                                       "size": 0x701, "executable": True}], functions=symbols)
        return cache, image

    def test_local_fixed_point_and_bounded_caller_rebuild(self):
        cache, image = self._fixed_point_case()
        functions, _, stats, metadata, _ = run_full(cache, image, (0x1000, 0x701))
        functions = by_start(functions)
        evidence = {start: fn.get("noreturn_evidence", {}).get("evidence")
                    for start, fn in functions.items() if fn.get("noreturn")}
        self.assertEqual(evidence, {0x1000: "local_fixed_point", 0x1100: "local_fixed_point",
                                    0x1200: "symbol_name", 0x1500: "local_fixed_point",
                                    0x1600: "local_fixed_point"})
        rounds = {start: functions[start]["noreturn_evidence"]["round"]
                  for start in (0x1000, 0x1100, 0x1500, 0x1600)}
        self.assertEqual(rounds, {0x1100: 1, 0x1000: 2, 0x1600: 2, 0x1500: 3})
        # 调用者被重建：落空边截断，证据指向本地不动点。
        self.assertEqual(addresses(functions[0x1000]), [0x1000])
        self.assertEqual(functions[0x1000]["cfg"]["noreturn_calls"][0]["evidence"], "local_fixed_point")
        self.assertEqual(addresses(functions[0x1500]), [0x1500])
        self.assertTrue(functions[0x1000]["cfg"]["complete"])
        # W 自身在第一遍就按已知名单截断。
        self.assertEqual(addresses(functions[0x1100]), [0x1100, 0x1101])
        # R 可能返回；I 有未知出口：都不推导，R 中对 abort 的调用仍被截断。
        self.assertNotIn("noreturn", functions[0x1300])
        self.assertEqual(addresses(functions[0x1300]), [0x1300, 0x1301, 0x1302])
        self.assertNotIn("noreturn", functions[0x1400])
        self.assertEqual(stats["full_noreturn_local_functions"], 4)
        self.assertEqual(stats["full_noreturn_rebuilt_functions"], 2)  # C 与 D
        self.assertEqual(stats["full_noreturn_targets"], 5)
        self.assertEqual(metadata["full_analysis"]["noreturn"]["fixed_point_rounds"], 3)

    def test_fixed_point_is_deterministic_and_rebuild_keeps_thread_separation(self):
        cache, image = self._fixed_point_case()
        outputs = []
        for workers in (1, 3):
            decoded, indexed = set(), set()

            def observe(function, target):
                def wrapped(*args, **kwargs):
                    target.add(get_ident())
                    return function(*args, **kwargs)
                return wrapped

            with ExitStack() as stack:
                stack.enter_context(patch.object(full_analysis._CachedDecoder, "decode",
                                                 observe(full_analysis._CachedDecoder.decode, decoded)))
                for name in ("_references", "index_references"):
                    stack.enter_context(patch.object(full_analysis, name,
                                                     observe(getattr(full_analysis, name), indexed)))
                functions, references, stats, metadata, _ = run_full(cache, image, (0x1000, 0x701),
                                                                     workers=workers)
            if workers > 1:
                # CFG（含不动点后的重建）在 CFG 线程池执行，引用在独立的 xref 线程：线程互不相交。
                self.assertTrue(decoded.isdisjoint(indexed))
                self.assertNotIn(get_ident(), decoded)
            self.assertEqual(stats["full_noreturn_rebuilt_functions"], 2)
            ignored = {"phase_seconds", "full_cfg_workers_used", "semantic_workers_used",
                       "semantic_workers_requested", "semantic_parallel_functions",
                       "full_decode_workers_used"}
            outputs.append((json.dumps(functions, sort_keys=True), json.dumps(references, sort_keys=True),
                            {key: value for key, value in stats.items() if key not in ignored},
                            json.dumps(metadata["full_analysis"]["noreturn"], sort_keys=True)))
        self.assertEqual(outputs[0], outputs[1])

    def test_pe_call_through_iat_slot_is_a_noreturn_call_site(self):
        slot = 0x402000
        call = instruction(0x401000, "call", None, size=6, operands=("qword ptr [rip + 0xffa]",),
                           reads=("rip",), meta={"architecture": "x86_64", "memory_references": (slot,)})
        cache = {0x401000: call, 0x401006: instruction(0x401006), 0x401007: instruction(0x401007, "return")}
        image = BinaryImage("pe", "x86_64", 64, "little", entry_address=0x401000, image_base=0x400000,
                            sections=[{"name": ".text", "address": 0x401000, "offset": 0, "size": 8,
                                       "executable": True}])
        imports = [{"name": "ExitProcess", "address": slot, "source": "pe-import",
                    "library": "KERNEL32.dll"},
                   {"name": "GetLastError", "address": slot + 8, "source": "pe-import",
                    "library": "KERNEL32.dll"}]
        functions, _, stats, metadata, _ = run_full(cache, image, (0x401000, 8), imports=imports)
        entry = by_start(functions)[0x401000]
        self.assertEqual(addresses(entry), [0x401000])
        self.assertEqual(entry["cfg"]["noreturn_calls"],
                         [{"from": 0x401000, "fallthrough": 0x401006, "target": None,
                           "name": "ExitProcess", "evidence": "import_slot_call"}])
        self.assertEqual(stats["full_noreturn_call_sites"], 1)
        self.assertEqual(metadata["full_analysis"]["noreturn"]["call_sites"][0]["slot"], slot)
        # 同一调用点经另一个（会返回的）导入槽位：不截断。
        imports[0]["name"] = "Sleep"
        functions, _, stats, _, _ = run_full(cache, image, (0x401000, 8), imports=imports)
        self.assertEqual(addresses(by_start(functions)[0x401000]), [0x401000, 0x401006, 0x401007])
        self.assertEqual(stats["full_noreturn_call_sites"], 0)

    def test_arm64_slot_load_then_blr_is_a_call_site_only_without_join_points(self):
        slot = 0x20018
        meta = {"architecture": "arm64"}
        cache = {
            0x1000: instruction(0x1000, size=4, mnemonic="adrp", operands=("x16", "#0x20000"),
                                writes=("x16",), meta={**meta, "address_operation":
                                                       {"kind": "page", "destination": "x16", "value": 0x20000}}),
            0x1004: instruction(0x1004, size=4, mnemonic="ldr", operands=("x16", "[x16, #0x18]"),
                                reads=("x16",), writes=("x16",),
                                meta={**meta, "memory_address_operations": (("x16", 0x18),)}),
            0x1008: instruction(0x1008, "call", None, size=4, mnemonic="blr", operands=("x16",),
                                reads=("x16",), writes=("lr",), meta=meta),
            0x100c: instruction(0x100c, "return", size=4, mnemonic="ret", meta=meta),
        }
        references = [{"src": 0x1004, "dst": slot, "kind": "data", "confidence": 1.0}]
        image = BinaryImage("elf", "arm64", 64, "little",
                            dynamic_relocations=[{"type": 1025, "address": slot, "symbol_name": "abort",
                                                  "address_kind": "virtual_address"}])
        targets, sites = import_noreturn(cache, references, image)
        self.assertEqual(targets, {})
        self.assertEqual(sites[0x1008]["name"], "abort")
        self.assertEqual(sites[0x1008]["slot"], slot)
        # blr 是某条直接分支的目标：别的路径可能带来不同的 x16，放弃。
        joined = references + [{"src": 0x2000, "dst": 0x1008, "kind": "jmp", "confidence": 1.0}]
        self.assertEqual(import_noreturn(cache, joined, image)[1], {})


class BtiPacPltTests(unittest.TestCase):
    def test_bti_pac_plt_stub_is_recognized_through_autia1716(self):
        meta = {"architecture": "arm64"}

        def row(address, mnemonic, operands=(), reads=(), writes=(), kind=None, extra=None):
            return instruction(address, kind, None, size=4, mnemonic=mnemonic, operands=operands,
                               reads=reads, writes=writes, meta={**meta, **(extra or {})})

        stub = 0x5000
        cache = {
            stub: row(stub, "bti", ("c",)),
            stub + 4: row(stub + 4, "adrp", ("x16", "#0x20000"), writes=("x16",)),
            stub + 8: row(stub + 8, "ldr", ("x17", "[x16, #0x18]"), reads=("x16",), writes=("x17",)),
            stub + 12: row(stub + 12, "add", ("x16", "x16", "#0x18"), reads=("x16",), writes=("x16",)),
            stub + 16: row(stub + 16, "autia1716", reads=("x16", "x17"), writes=("x17",)),
            stub + 20: row(stub + 20, "br", ("x17",), reads=("x17",), kind="jump"),
        }
        references = [{"src": 0x100, "dst": stub, "kind": "call", "confidence": 1.0},
                      {"src": stub + 8, "dst": 0x20018, "kind": "data", "confidence": 1.0},
                      {"src": stub + 12, "dst": 0x20018, "kind": "data", "confidence": 1.0}]
        image = BinaryImage("elf", "arm64", 64, "little",
                            dynamic_relocations=[{"type": 1026, "address": 0x20018,
                                                  "symbol_name": "__stack_chk_fail",
                                                  "address_kind": "virtual_address"}])
        targets, sites = import_noreturn(cache, references, image)
        self.assertEqual(targets[stub]["name"], "__stack_chk_fail")
        self.assertEqual(targets[stub]["slot"], 0x20018)
        self.assertEqual(sites, {})
        # 若跳转寄存器最后由地址计算（add）而非装入写入，则不是经槽位的跳转。
        cache[stub + 20] = row(stub + 20, "br", ("x16",), reads=("x16",), kind="jump")
        self.assertEqual(import_noreturn(cache, references, image)[0], {})


def _a64(word):
    return struct.pack("<I", word)


def _adrp(register, pc, target):
    delta = (target >> 12) - (pc >> 12)
    return _a64(0x90000000 | ((delta & 3) << 29) | (((delta >> 2) & 0x7FFFF) << 5) | register)


@unittest.skipUnless(CAPSTONE, "Capstone is required for real arm64 decoding")
class Arm64PltTests(unittest.TestCase):
    """真实 arm64 机器码经处理器解码，GOT 槽位来自 R_AARCH64_JUMP_SLOT 重定位。"""

    @staticmethod
    def image(symbol="exit", branch_register=17):
        code = (_a64(0x94000008)            # 0x10000: bl 0x10020
                + _a64(0xD503201F)          # 0x10004: nop（只能经落空到达）
                + _a64(0xD65F03C0)          # 0x10008: ret
                + _a64(0xD503201F) * 5      # 0x1000c..0x1001c: 填充
                + _adrp(16, 0x10020, 0x20000)  # 0x10020: adrp x16, 0x20000
                + _a64(0xF9400E11)          # 0x10024: ldr x17, [x16, #0x18]
                + _a64(0x91006210)          # 0x10028: add x16, x16, #0x18
                + _a64(0xD61F0000 | (branch_register << 5)))  # 0x1002c: br x17
        data = code + bytes(0x40 - len(code)) + bytes(0x20)
        image = BinaryImage(
            "elf", "arm64", 64, "little", entry_address=0x10000,
            sections=[{"name": ".text", "address": 0x10000, "offset": 0, "size": len(code),
                       "executable": True},
                      {"name": ".got.plt", "address": 0x20000, "offset": 0x40, "size": 0x20,
                       "executable": False}],
            dynamic_relocations=[{"type": 1026, "address": 0x20018, "symbol_name": symbol,
                                  "address_kind": "virtual_address", "symbol_value": 0}])
        return data, image

    def analyze(self, **options):
        data, image = self.image(**options)
        with XrefStage() as stage:
            return full_analysis.analyze_full(data, image, workers=1, xref_stage=stage)

    def test_plt_stub_through_got_jump_slot_is_recognized_as_exit(self):
        functions, references, stats, metadata, _ = self.analyze()
        functions = by_start(functions)
        # xref 阶段已给出 ldr 对 GOT 槽位的数据引用；桩识别只消费这条证据。
        self.assertIn({"src": 0x10024, "dst": 0x20018, "kind": "data", "confidence": 1.0}, references)
        stub = functions[0x10020]
        self.assertTrue(stub["noreturn"])
        self.assertEqual(stub["noreturn_evidence"],
                         {"name": "exit", "evidence": "import_stub", "symbol": "exit",
                          "slot": 0x20018, "source": "elf_relocation"})
        caller = functions[0x10000]
        self.assertEqual(addresses(caller), [0x10000])
        self.assertEqual(caller["cfg"]["noreturn_calls"],
                         [{"from": 0x10000, "fallthrough": 0x10004, "target": 0x10020,
                           "name": "exit", "evidence": "import_stub"}])
        # 调用者自身只剩这条不返回调用，本地不动点随之把它也标为不返回。
        self.assertEqual(caller["noreturn_evidence"]["evidence"], "local_fixed_point")
        self.assertEqual(stats["full_noreturn_targets"], 2)
        self.assertEqual(stats["full_noreturn_local_functions"], 1)

    def test_returning_import_or_mismatched_register_is_not_recognized(self):
        for options in ({"symbol": "puts"}, {"branch_register": 16}):
            with self.subTest(**options):
                functions, _, stats, _, _ = self.analyze(**options)
                caller = by_start(functions)[0x10000]
                self.assertEqual(addresses(caller), [0x10000, 0x10004, 0x10008])
                self.assertEqual(caller["cfg"]["noreturn_calls"], [])
                self.assertEqual(stats["full_noreturn_targets"], 0)


@unittest.skipUnless(CAPSTONE, "Capstone is required for real x86-64 decoding")
class SemanticPathTests(unittest.TestCase):
    @staticmethod
    def image(name):
        # 0x1000: call 0x1010; nop; ret; 填充; 0x1010: ret
        code = bytes.fromhex("e80b000000" "90" "c3") + b"\x90" * 9 + b"\xc3"
        image = BinaryImage("elf", "x86_64", 64, "little", entry_address=0x1000,
                            sections=[{"name": ".text", "address": 0x1000, "offset": 0,
                                       "size": len(code), "executable": True}],
                            functions=[{"name": "main", "start": 0x1000, "size": 7},
                                       {"name": name, "start": 0x1010, "size": 1}])
        return code, image

    def test_semantic_path_uses_the_known_name_list(self):
        data, image = self.image("exit")
        functions, _, stats, _ = analyze_semantics(data, image)
        main = by_start(functions)[0x1000]
        self.assertEqual(addresses(main), [0x1000])
        self.assertEqual(main["cfg"]["noreturn_calls"][0]["name"], "exit")
        self.assertEqual(stats["semantic_noreturn_calls"], 1)
        parallel = analyze_semantics(data, image, max_workers=2)
        self.assertEqual(json.dumps(parallel[0], sort_keys=True), json.dumps(functions, sort_keys=True))

    def test_semantic_path_without_noreturn_names_is_unchanged(self):
        data, image = self.image("helper")
        functions, _, stats, _ = analyze_semantics(data, image)
        main = by_start(functions)[0x1000]
        self.assertEqual(addresses(main), [0x1000, 0x1005, 0x1006])
        self.assertNotIn("noreturn_calls", main["cfg"])
        self.assertEqual(stats["semantic_noreturn_calls"], 0)


_MACHO_SOURCE = r"""
#include <stdio.h>
#include <stdlib.h>
__attribute__((noinline)) void die(const char *message) { puts(message); abort(); }
__attribute__((noinline)) int check(int value) { if (value < 0) die("negative"); return value * 2; }
int main(int argc, char **argv) { if (argc > 3) exit(3); return check(argc - 2); }
"""


@unittest.skipUnless(CAPSTONE and shutil.which("clang") and platform.system() == "Darwin"
                     and platform.machine() == "arm64", "Requires clang on arm64 macOS")
class CompiledMachOTests(unittest.TestCase):
    def test_compiled_program_stubs_and_wrapper(self):
        with tempfile.TemporaryDirectory() as directory:
            source, binary = Path(directory) / "t.c", Path(directory) / "t"
            source.write_text(_MACHO_SOURCE)
            subprocess.run(["clang", "-O1", "-fno-inline", "-o", str(binary), str(source)],
                           check=True, capture_output=True)
            # 实际运行确认语义：abort 路径以 SIGABRT 结束，exit 路径返回 3，正常路径返回 0。
            self.assertEqual(subprocess.run([str(binary)], capture_output=True).returncode, -6)
            self.assertEqual(subprocess.run([str(binary), "a", "b", "c", "d"]).returncode, 3)
            self.assertEqual(subprocess.run([str(binary), "a"]).returncode, 0)
            data = binary.read_bytes()
        image = parse_binary(data, "macho")
        with XrefStage() as stage:
            functions, _, stats, metadata, _ = full_analysis.analyze_full(data, image, workers=1,
                                                                          xref_stage=stage)
        named = {fn["name"]: fn for fn in functions if fn.get("cfg")}
        targets = {item["name"]: item for item in metadata["full_analysis"]["noreturn"]["targets"]}
        for name in ("abort", "exit"):
            self.assertEqual(targets[name]["evidence"], "declared_stub")
            self.assertIsNotNone(targets[name]["slot"])  # 桩快照读取的槽位与容器声明一致
        self.assertEqual(named["_die"]["noreturn_evidence"]["evidence"], "local_fixed_point")
        check = named["_check"]
        self.assertTrue(check["cfg"]["complete"])
        self.assertEqual([call["name"] for call in check["cfg"]["noreturn_calls"]], ["_die"])
        main_calls = named["_main"]["cfg"]["noreturn_calls"]
        self.assertEqual([call["name"] for call in main_calls], ["exit"])
        # 落空边不再流入下一个函数（_die 紧跟在 main 的 exit 调用之后）。
        self.assertFalse(any(item["to"] == named["_die"]["start"]
                             for item in named["_main"]["cfg"]["frontier"]))
        self.assertGreaterEqual(stats["full_noreturn_rebuilt_functions"], 1)


@slow("libtersafe 全量扫描")
@unittest.skipUnless(CAPSTONE and LIBTERSAFE.is_file(), "libtersafe.so sample is not available")
class LibtersafeSampleTests(unittest.TestCase):
    def test_import_stubs_and_truncated_callers(self):
        data = LIBTERSAFE.read_bytes()
        image = parse_binary(data, "elf")
        with XrefStage(separate_thread=True) as stage:
            functions, _, stats, metadata, _ = full_analysis.analyze_full(data, image, workers=4,
                                                                          xref_stage=stage)
        targets = metadata["full_analysis"]["noreturn"]["targets"]
        stubs = {item["name"]: item["address"] for item in targets if item["evidence"] == "import_stub"}
        self.assertEqual(stubs, {"_exit": 0x50E740, "abort": 0x50E990, "__stack_chk_fail": 0x50E9B0,
                                 "__assert2": 0x50EAD0, "exit": 0x50ED70})
        self.assertGreater(stats["full_noreturn_local_functions"], 0)
        functions = by_start(functions)
        # 0x2d8f90: bl abort 之后原先落空进入下一个函数，现在截断且 CFG 完整。
        caller = functions[0x2D8F78]
        self.assertTrue(caller["cfg"]["complete"])
        self.assertEqual(caller["cfg"]["noreturn_calls"][0]["from"], 0x2D8F90)
        # 0x508398 是静态链接的 __cxa_throw：_Unwind_RaiseException 之后调用 failed_throw。
        self.assertEqual(functions[0x508398]["noreturn_evidence"]["evidence"], "local_fixed_point")


@unittest.skipUnless(CAPSTONE and CHALLENGE.is_file(), "x86-64 challenge sample is not available")
class ChallengeSampleTests(unittest.TestCase):
    def test_x86_64_plt_stub_and_signal_handler(self):
        data = CHALLENGE.read_bytes()
        image = parse_binary(data, "elf")
        with XrefStage() as stage:
            functions, _, _, metadata, _ = full_analysis.analyze_full(data, image, workers=1,
                                                                      xref_stage=stage)
        targets = {item["address"]: item for item in metadata["full_analysis"]["noreturn"]["targets"]}
        self.assertEqual(targets[0x2090]["name"], "siglongjmp")
        self.assertEqual(targets[0x2090]["evidence"], "import_stub")
        handler = by_start(functions)[0xF3740]
        self.assertTrue(handler["cfg"]["complete"])
        self.assertEqual(handler["cfg"]["noreturn_calls"][0]["target"], 0x2090)


class EntryWindowTests(unittest.TestCase):
    def test_entry_cfg_optional_noreturn_targets(self):
        rows = [instruction(0x1000, "call", 0x2000, size=5), instruction(0x1005),
                instruction(0x1006, "return")]
        default, reached = build_entry_cfg(rows, 0x1000)
        self.assertEqual((default, reached), build_entry_cfg(rows, 0x1000, {}))
        self.assertNotIn("noreturn_calls", default)
        self.assertEqual(reached, {0x1000, 0x1005, 0x1006})
        graph, reached = build_entry_cfg(rows, 0x1000, {0x2000: {"name": "exit", "evidence": "symbol_name"}})
        self.assertEqual(reached, {0x1000})
        self.assertTrue(graph["complete"])
        self.assertEqual(graph["noreturn_calls"], [{"from": 0x1000, "fallthrough": 0x1005, "target": 0x2000,
                                                    "name": "exit", "evidence": "symbol_name"}])


class LocalFixedPointUnitTests(unittest.TestCase):
    def test_round_cap_and_unknown_exits(self):
        def function(start, blocks, frontier=()):
            return {"start": start, "name": f"f{start:x}", "blocks": blocks,
                    "cfg": {"frontier": list(frontier)}}

        def block(start, *rows, successors=()):
            return {"start": start, "instructions": list(rows), "successors": list(successors)}

        # f100 → f200 → f300 → f400 → abort：每个函数“调用；返回”，调用的落空边通向返回块。
        chain = [function(0x100 * index,
                          [block(0x100 * index, instruction(0x100 * index, "call", 0x100 * (index + 1)),
                                 successors=(0x100 * index + 1,)),
                           block(0x100 * index + 1, instruction(0x100 * index + 1, "return"))])
                 for index in range(1, 5)]
        abort = {0x500: {"name": "abort"}}
        found, rebuild, rounds = local_noreturn(chain, abort)
        self.assertEqual(sorted(found), [0x100, 0x200, 0x300, 0x400])
        self.assertEqual(rebuild, [0x100, 0x200, 0x300])
        self.assertEqual(rounds, 4)
        capped, _, rounds = local_noreturn(chain, abort, max_rounds=2)
        self.assertEqual(sorted(capped), [0x300, 0x400])
        self.assertEqual(rounds, 2)
        # 未知出口（未解码、越界）不能被当作不返回。
        unknown = function(0x600, [block(0x600, instruction(0x600))],
                           [{"from": 0x600, "to": 0x601, "reason": "undecoded"}])
        self.assertEqual(local_noreturn([unknown], abort)[0], {})


if __name__ == "__main__":
    unittest.main()
