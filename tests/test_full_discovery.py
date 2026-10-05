"""完整模式下“只经数据指针/容器声明到达”的函数发现：表级证据规则的正反例、Loader 读取器、
以及真实编码（Capstone）端到端恢复。合成快照不依赖解码器；端到端用例按 DECODER_AVAILABLE
跳过；真实 Mach-O 用例按 clang 是否可用跳过；libtersafe 用例按样本是否存在跳过。

覆盖：
  * 逐项规则：指令边界、填充/陷阱、已声明区间内部、已认领 CFG、前一条顺序落空（无条件
    跳转、返回、陷阱、对不返回目标的调用、对齐 nop、空隙逐条单独检验，前驱与目标紧邻）、
    区域起点豁免、槽位位于可执行区域、所在区间起点函数带 indirect_jump 前沿；
  * 表级规则：相邻槽位成表、任一项有反证整表拒绝、重复目标、多个新目标同区间、没有已知
    函数项（容器声明的 init/fini 数组除外）、跨表否决；
  * Loader：ELF RELA/RELR/Android RELR/APS2 打包重定位（含 APS2 中经 .dynsym 解析的
    GLOB_DAT/ABS）与 init_array 结构证据、elf_unwind 的 init/fini 数组根同样读取 RELR/APS2、PE 逐槽位
    基址重定位与按 Machine 区分的 .pdata（x64 12 字节、ARM64/ARM32 8 字节打包与 .xdata）、
    Mach-O __mod_init_func 与 __init_offsets；
  * 端到端：手工构造的 ELF 中“只经指针表到达”的函数被恢复；PE32 绝对地址 switch 跳转表
    （.rdata 与内联在 .text 两种）0 误报；第二轮使用本地不动点之后的不返回集合，并在第二轮
    函数上补算不动点（所有出口都不返回的指针函数标为 noreturn）；第二轮
    中途取消时未建图的种子以 not_decoded 出现且完整度为 false；workers=1/3/8 结果一致且
    解码线程与 xref 线程分离；
  * 真实样本：clang 编译并实际运行（输出与返回值确认构造函数执行）的 Mach-O；libtersafe
    的混淆分支表项 0x2f4e88（FDE 末尾零填充）不再被接受；Android NDK 的 ld.lld 产物上 APS2/
    RELR/Android RELR 解码与 llvm-readelf 逐项一致、各打包方式结果相同，lld-link 产物上
    ARM64/ARMNT/x64 .pdata 与 llvm-readobj 一致（找到 NDK 时运行）。
"""
from __future__ import annotations

from collections import Counter
from contextlib import ExitStack
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from fangida.api import AnalysisView
from fangida.benchmark import _evidence_digest
from fangida.core.kkagent import full_analysis
from fangida.core.kkagent.test_semantic import DECODER_AVAILABLE
from fangida.dispatcher import AnalysisService
from fangida.loaders.elf import load_elf, recover_code_pointers
from fangida.loaders.macho import recover_function_ranges as macho_recover
from fangida.loaders.pe import (load_pe, recover_code_pointers as pe_pointers,
                                recover_function_ranges as pe_recover)
from fangida.processors.decoder import NativeDecoder
from fangida.settings import Settings
from fangida.xrefs import XrefStage
from tests.test_elf_unwind import elf_file
from tests.test_loader_code_regions import _macho

LIBTERSAFE = Path("/Users/meow233/Downloads/libtersafe.so")
ANCHOR = 0x100   # 合成快照中的已知函数起点（表中的锚点项）


def _instruction(address, size=1, mnemonic="nop", kind=None, conditional=False, target=None):
    branch = {"kind": kind, "conditional": conditional, "target": target} if kind else {}
    return {"addr": address, "size": size, "mnemonic": mnemonic,
            "operands": (), "branch_info": branch}


def _snapshot(*instructions):
    """锚点函数（ret）加上给定指令组成的只读解码快照。"""
    cache = {ANCHOR: _instruction(ANCHOR, mnemonic="ret", kind="return")}
    cache.update({item["addr"]: item for item in instructions})
    return cache


class PointerAcceptanceRuleTests(unittest.TestCase):
    """表级证据规则逐条正反例，使用合成快照，不依赖任何解码器。"""

    def _accept(self, tables, cache, *, seeds=(ANCHOR,), sized=(), reached=(ANCHOR,),
                regions=(), noreturn=(), functions=(), executable=None, code=None,
                structure=None, pointer_size=8):
        """tables 为若干张表（每张表是目标地址列表），各表的槽位相距足够远，互不相邻。"""
        candidates = []
        for index, table in enumerate(tables):
            for position, target in enumerate(table):
                evidence = {"pointer_address": 0x9000 + index * 0x100 + position * pointer_size}
                if structure:
                    evidence["structure"] = structure
                candidates.append({"start": target, "source": "data_pointer", "evidence": evidence})
        details = {}
        accepted, rejected = full_analysis._accept_pointer_candidates(
            candidates, cache, sorted(cache), set(seeds), list(sized), set(reached),
            frozenset(regions), {address: {"name": "n"} for address in noreturn},
            functions=list(functions), pointer_size=pointer_size, executable=executable,
            code_bytes=code, details=details)
        return [seed["start"] for seed in accepted], rejected, details

    # ---- 前驱规则：每条单独检验，前驱与目标紧邻（没有空隙可依赖）。----

    def _predecessor(self, previous, *, noreturn=()):
        target = previous["addr"] + previous["size"]
        cache = _snapshot(previous, _instruction(target, mnemonic="push"))
        return self._accept([[ANCHOR, target]], cache, noreturn=noreturn), target

    def test_unconditional_jump_predecessor_is_clean(self):
        (accepted, rejected, _), target = self._predecessor(
            _instruction(0x300, size=2, mnemonic="jmp", kind="jump", target=0x100))
        self.assertEqual(accepted, [target], rejected)

    def test_return_predecessor_is_clean(self):
        (accepted, rejected, _), target = self._predecessor(
            _instruction(0x300, mnemonic="ret", kind="return"))
        self.assertEqual(accepted, [target], rejected)

    def test_trap_predecessor_is_clean(self):
        (accepted, rejected, _), target = self._predecessor(
            _instruction(0x300, size=2, mnemonic="ud2", kind="trap"))
        self.assertEqual(accepted, [target], rejected)

    def test_call_to_noreturn_target_predecessor_is_clean(self):
        call = _instruction(0x300, size=5, mnemonic="call", kind="call", target=0x9999)
        (accepted, rejected, _), target = self._predecessor(call, noreturn={0x9999})
        self.assertEqual(accepted, [target], rejected)
        # 反例：同一调用的目标不是不返回函数时，调用之后顺序落空。
        (accepted, rejected, _), _ = self._predecessor(call)
        self.assertEqual(accepted, [])
        self.assertEqual(rejected["fallthrough"], 1)

    def test_alignment_nop_predecessor_is_clean(self):
        (accepted, rejected, _), target = self._predecessor(
            _instruction(0x2fc, size=4, mnemonic="nop"))
        self.assertEqual(accepted, [target], rejected)

    def test_gap_before_target_is_clean(self):
        cache = _snapshot(_instruction(0x2f0, size=3, mnemonic="mov"), _instruction(0x302, mnemonic="push"))
        accepted, rejected, _ = self._accept([[ANCHOR, 0x302]], cache)
        self.assertEqual(accepted, [0x302], rejected)

    def test_fallthrough_predecessors_are_rejected(self):
        for previous in (_instruction(0x300, size=2, mnemonic="mov"),
                         _instruction(0x300, size=2, mnemonic="je", kind="jump", conditional=True)):
            (accepted, rejected, _), _ = self._predecessor(previous)
            self.assertEqual(accepted, [], previous["mnemonic"])
            self.assertEqual(rejected["fallthrough"], 1)

    def test_region_start_overrides_fallthrough_rule(self):
        cache = _snapshot(_instruction(0x200, size=5, mnemonic="mov"), _instruction(0x205))
        accepted, _, _ = self._accept([[ANCHOR, 0x205]], cache, regions={0x205})
        self.assertEqual(accepted, [0x205])

    # ---- 逐项反证：任一项命中即整表拒绝。----

    def test_target_without_a_decoded_boundary_is_rejected(self):
        accepted, rejected, _ = self._accept([[ANCHOR, 0x140]], _snapshot())
        self.assertEqual(accepted, [])
        self.assertEqual(rejected["not_boundary"], 1)

    def test_padding_or_trap_target_is_rejected(self):
        trap = _snapshot(_instruction(0x300, mnemonic="ret", kind="return"),
                         _instruction(0x301, size=4, mnemonic="udf", kind="trap"))
        accepted, rejected, _ = self._accept([[ANCHOR, 0x301]], trap)
        self.assertEqual((accepted, rejected["padding_or_trap"]), ([], 1))
        # 全零字节（x86 上解成 add [rax], al）同样是填充，与助记符无关。
        zero = _snapshot(_instruction(0x300, mnemonic="ret", kind="return"),
                         _instruction(0x301, size=2, mnemonic="add"))
        accepted, rejected, _ = self._accept([[ANCHOR, 0x301]], zero, code=lambda address, size: bytes(size))
        self.assertEqual((accepted, rejected["padding_or_trap"]), ([], 1))
        accepted, _, _ = self._accept([[ANCHOR, 0x301]], zero, code=lambda address, size: b"\x55" * size)
        self.assertEqual(accepted, [0x301])

    def test_pointer_inside_a_declared_range_is_rejected(self):
        cache = _snapshot(*(_instruction(address) for address in range(0x200, 0x220)))
        accepted, rejected, _ = self._accept([[ANCHOR, 0x208]], cache,
                                             seeds={ANCHOR, 0x200}, sized=[{"start": 0x200, "size": 0x10}])
        self.assertEqual(accepted, [])
        self.assertEqual(rejected["inside_declared"], 1)

    def test_pointer_to_already_claimed_instruction_is_rejected(self):
        cache = _snapshot(_instruction(0x300, mnemonic="ret", kind="return"), _instruction(0x301))
        accepted, rejected, _ = self._accept([[ANCHOR, 0x301]], cache, reached={ANCHOR, 0x301})
        self.assertEqual(accepted, [])
        self.assertEqual(rejected["claimed"], 1)

    def test_existing_seed_is_not_reinvented(self):
        accepted, rejected, details = self._accept([[ANCHOR]], _snapshot())
        self.assertEqual(accepted, [])
        self.assertEqual(rejected["already_seed"], 1)
        self.assertEqual((details["accepted_tables"], details["known_only_tables"]), (0, 1))

    def test_slot_inside_executable_region_rejects_the_table(self):
        # 内联在代码中的跳转表或指令操作数：槽位本身在可执行区域内。
        cache = _snapshot(_instruction(0x300, mnemonic="ret", kind="return"), _instruction(0x301))
        accepted, rejected, _ = self._accept([[ANCHOR, 0x301]], cache, executable=[(0x9000, 0x9100)])
        self.assertEqual(accepted, [])
        self.assertEqual((rejected["slot_in_code"], rejected["already_seed"]), (1, 1))
        accepted, _, _ = self._accept([[ANCHOR, 0x301]], cache, executable=[(0x0, 0x1000)])
        self.assertEqual(accepted, [0x301])

    def test_interval_owner_with_indirect_jump_rejects_the_table(self):
        # 目标落在“已知函数起点到下一个已知起点”区间内，而区间起点函数带 indirect_jump
        # 前沿：可能是该函数未解析跳转表的分支。
        cache = _snapshot(_instruction(0x300, mnemonic="ret", kind="return"), _instruction(0x301))
        owner = {"start": ANCHOR, "cfg": {"frontier": [{"from": ANCHOR, "to": None,
                                                         "reason": "indirect_jump"}]}}
        accepted, rejected, _ = self._accept([[ANCHOR, 0x301]], cache, functions=[owner])
        self.assertEqual(accepted, [])
        self.assertEqual(rejected["indirect_jump_interval"], 1)
        owner["cfg"]["frontier"] = []
        accepted, _, _ = self._accept([[ANCHOR, 0x301]], cache, functions=[owner])
        self.assertEqual(accepted, [0x301])

    def test_one_bad_item_rejects_every_item_of_its_table(self):
        cache = _snapshot(_instruction(0x300, mnemonic="ret", kind="return"), _instruction(0x301),
                          _instruction(0x400, mnemonic="ret", kind="return"), _instruction(0x401))
        accepted, rejected, details = self._accept([[ANCHOR, 0x301, 0x402]], cache,
                                                   seeds={ANCHOR, 0x400})
        self.assertEqual(accepted, [])
        self.assertEqual((rejected["not_boundary"], rejected["table_rejected"]), (1, 1))
        self.assertEqual(details["rejected_tables"], {"not_boundary": 1})
        self.assertEqual({item["start"]: item["reason"] for item in details["unconfirmed"]},
                         {0x301: "table_rejected", 0x402: "not_boundary"})

    # ---- 表级形状规则。----

    def test_new_targets_sharing_one_function_interval_are_rejected(self):
        cache = _snapshot(_instruction(0x300, mnemonic="ret", kind="return"), _instruction(0x301),
                          _instruction(0x310, mnemonic="ret", kind="return"), _instruction(0x311))
        accepted, rejected, _ = self._accept([[ANCHOR, 0x301, 0x311]], cache)
        self.assertEqual(accepted, [])
        self.assertEqual(rejected["shared_interval"], 2)
        # 对照：两者之间有已知函数起点，各自落在不同区间，接受。
        accepted, _, _ = self._accept([[ANCHOR, 0x301, 0x311]], cache, seeds={ANCHOR, 0x310},
                                      reached={ANCHOR, 0x310})
        self.assertEqual(accepted, [0x301, 0x311])

    def test_duplicate_new_target_is_rejected(self):
        cache = _snapshot(_instruction(0x300, mnemonic="ret", kind="return"), _instruction(0x301))
        accepted, rejected, _ = self._accept([[ANCHOR, 0x301, 0x301]], cache)
        self.assertEqual(accepted, [])
        self.assertEqual(rejected["duplicate_target"], 2)

    def test_table_without_known_function_needs_a_declared_structure(self):
        cache = _snapshot(_instruction(0x300, mnemonic="ret", kind="return"), _instruction(0x301))
        accepted, rejected, details = self._accept([[0x301]], cache)
        self.assertEqual(accepted, [])
        self.assertEqual(rejected["no_known_function"], 1)
        self.assertEqual(details["unconfirmed"], [{"start": 0x301, "pointer_address": 0x9000,
                                                   "reason": "no_known_function"}])
        accepted, _, _ = self._accept([[0x301]], cache, structure="init_array")
        self.assertEqual(accepted, [0x301])

    def test_target_rejected_by_another_table_is_vetoed(self):
        cache = _snapshot(_instruction(0x300, mnemonic="ret", kind="return"), _instruction(0x301))
        accepted, rejected, _ = self._accept([[ANCHOR, 0x301], [ANCHOR, 0x301, 0x301]], cache)
        self.assertEqual(accepted, [])
        self.assertEqual((rejected["vetoed"], rejected["duplicate_target"]), (1, 2))
        # 无锚点（不是反证）的表不否决其它表。
        accepted, _, _ = self._accept([[ANCHOR, 0x301], [0x301]], cache)
        self.assertEqual(accepted, [0x301])

    def test_pe32_switch_table_shape_is_rejected_without_decoder(self):
        # 审查样本同形：分支标签前一条是 jmp [table] 或 ret（干净起点），全部落在派发函数
        # 区间内；派发函数带 indirect_jump 前沿。去掉前沿规则后仍由 shared_interval 挡下。
        cases = [_instruction(0x200, size=4, mnemonic="mov"),
                 _instruction(0x204, size=7, mnemonic="jmp", kind="jump"),
                 _instruction(0x20b, size=5, mnemonic="mov"), _instruction(0x210, mnemonic="ret", kind="return"),
                 _instruction(0x211, size=5, mnemonic="mov"), _instruction(0x216, mnemonic="ret", kind="return")]
        cache = _snapshot(*cases)
        dispatch = {"start": 0x200, "cfg": {"frontier": [{"from": 0x204, "to": None,
                                                           "reason": "indirect_jump"}]}}
        kwargs = dict(seeds={ANCHOR, 0x200}, reached={ANCHOR, 0x200, 0x204}, pointer_size=4)
        accepted, rejected, _ = self._accept([[0x20b, 0x211]], cache, functions=[dispatch], **kwargs)
        self.assertEqual(accepted, [])
        self.assertEqual(rejected["indirect_jump_interval"], 2)
        accepted, rejected, _ = self._accept([[0x20b, 0x211, ANCHOR]], cache, **kwargs)
        self.assertEqual(accepted, [])
        self.assertEqual(rejected["shared_interval"], 2)


class ElfCodePointerLoaderTests(unittest.TestCase):
    """ELF Loader 读取器：只产出指向可执行区域的重定位候选，不解码指令。"""

    @staticmethod
    def _image(relocation_sections, *, data_words=(0x100b,), arrays=()):
        """.text@0x1000、.data@0x8000（槽位内容为 data_words）以及给定的重定位节。"""
        data = bytearray(64)
        sections = [("", 0, 0, 0, 0, 0, 0, 0, 0, 0)]

        def add(name, section_type, flags, address, content, entry_size=0):
            data.extend(bytes(-len(data) % 16))
            offset = len(data)
            data.extend(content)
            sections.append((name, section_type, flags, address, offset, len(content), 0, 0, 16, entry_size))

        code = bytearray(b"\xcc" * 0x40)
        code[0] = code[0x0b] = 0xc3
        add(".text", 1, 6, 0x1000, bytes(code))
        add(".data", 1, 3, 0x8000, b"".join(struct.pack("<Q", word) for word in data_words))
        for name, section_type, address, values in arrays:
            add(name, section_type, 3, address, b"".join(struct.pack("<Q", value) for value in values), 8)
        for name, section_type, payload, entry_size in relocation_sections:
            add(name, section_type, 2, 0x9000, payload, entry_size)
        names = bytearray(b"\0")
        offsets = {"": 0}
        for name in [section[0] for section in sections] + [".shstrtab"]:
            if name not in offsets:
                offsets[name] = len(names)
                names.extend(name.encode() + b"\0")
        add(".shstrtab", 3, 0, 0, names)
        data.extend(bytes(-len(data) % 16))
        shoff = len(data)
        for section in sections:
            data.extend(struct.pack("<IIQQQQIIQQ", offsets[section[0]], *section[1:]))
        data[:16] = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
        struct.pack_into("<HHIQQQIHHHHHH", data, 16, 3, 62, 1, 0x1000, 0, shoff, 0,
                         64, 0, 0, 64, len(sections), len(sections) - 1)
        return bytes(data)

    @staticmethod
    def _sleb(value):
        out = bytearray()
        while True:
            byte = value & 0x7F
            value >>= 7
            if (value == 0 and not byte & 0x40) or (value == -1 and byte & 0x40):
                return bytes(out + bytes([byte]))
            out.append(byte | 0x80)

    def _found(self, data):
        candidates, warnings = recover_code_pointers(data, load_elf(data))
        return sorted((item["evidence"]["pointer_address"], item["target"],
                       item["evidence"].get("encoding")) for item in candidates), warnings

    def test_rela_relative_pointer_into_text_is_a_candidate(self):
        data = elf_file(relocations=((0x9000, 8, 0, 0x4010),))  # R_X86_64_RELATIVE → .text
        candidates, warnings = recover_code_pointers(data, load_elf(data))
        self.assertEqual([item["target"] for item in candidates], [0x4010])
        self.assertEqual(candidates[0]["evidence"]["relocation"], "relative")
        self.assertEqual(candidates[0]["source"], "data_pointer")
        self.assertEqual(warnings, [])

    def test_relative_pointer_outside_executable_is_dropped(self):
        data = elf_file(relocations=((0x9000, 8, 0, 0x8000),))  # 指向 .rela/.shstrtab 之外的数据
        candidates, _ = recover_code_pointers(data, load_elf(data))
        self.assertEqual(candidates, [])

    def test_relr_section_is_decoded_like_rela(self):
        # 审查者 relr.py 场景：同一个槽位分别用 .rela.dyn 与 .relr.dyn（SHT_RELR=19）表示。
        rela = self._image([(".rela.dyn", 4, struct.pack("<QQq", 0x8000, 8, 0x100b), 24)])
        relr = self._image([(".relr.dyn", 19, struct.pack("<Q", 0x8000), 8)])
        self.assertEqual(self._found(rela), ([(0x8000, 0x100b, "rela")], []))
        self.assertEqual(self._found(relr), ([(0x8000, 0x100b, "relr")], []))

    def test_relr_bitmap_and_android_relr_cover_following_slots(self):
        # 地址项 0x8000，随后位图 0b111（第 1、2 位 → 0x8008、0x8010）；值从槽位读取。
        words = (0x100b, 0x1000, 0x2000, 0x100b)   # 0x2000 不在可执行区域，被丢弃
        payload = struct.pack("<QQ", 0x8000, 0b111)
        expected = [(0x8000, 0x100b), (0x8008, 0x1000)]
        for name, section_type, encoding in ((".relr.dyn", 19, "relr"),
                                             (".relr.android", 0x6fffff00, "android_relr")):
            found, warnings = self._found(self._image([(name, section_type, payload, 8)], data_words=words))
            self.assertEqual([(place, target) for place, target, _ in found], expected)
            self.assertEqual({item[2] for item in found}, {encoding})
            self.assertEqual(warnings, [])

    def test_android_aps2_packed_relocations_are_decoded(self):
        # APS2：2 条 R_X86_64_RELATIVE，按 r_info 与 offset 增量分组、各自带加数增量。
        stream = b"APS2" + b"".join(self._sleb(value) for value in (
            2, 0x8000 - 8,                      # 总数、初始 r_offset
            2, 1 | 2 | 8, 8, 8,                 # 组大小 2；按 info + offset 增量分组且带加数
            0x100b, 0x1000 - 0x100b))           # 每项的加数增量（累加）
        found, warnings = self._found(self._image([(".rela.android", 0x60000002, stream, 1)],
                                                  data_words=(0, 0)))
        self.assertEqual(found, [(0x8000, 0x100b, "android_rela"), (0x8008, 0x1000, "android_rela")])
        self.assertEqual(warnings, [])

    def test_unparseable_packed_relocations_warn_instead_of_silence(self):
        for payload in (b"APS1\x00\x00", b"APS2\x81"):
            found, warnings = self._found(self._image([(".rela.android", 0x60000002, payload, 1)]))
            self.assertEqual(found, [])
            self.assertTrue(any("android_rela" in message for message in warnings), warnings)
        found, warnings = self._found(self._image([(".relr.dyn", 19, struct.pack("<Q", 0b11), 8)]))
        self.assertEqual(found, [])
        self.assertTrue(any("relr" in message for message in warnings), warnings)

    def test_init_array_slots_carry_structure_evidence(self):
        payload = struct.pack("<QQq", 0xA000, 8, 0x100b) + struct.pack("<QQq", 0x8000, 8, 0x1000)
        data = self._image([(".rela.dyn", 4, payload, 24)],
                           arrays=[(".init_array", 14, 0xA000, (0,))])
        candidates, _ = recover_code_pointers(data, load_elf(data))
        structures = {item["evidence"]["pointer_address"]: item["evidence"].get("structure")
                      for item in candidates}
        self.assertEqual(structures, {0xA000: "init_array", 0x8000: None})

    def test_glob_dat_to_local_definition_is_a_candidate_and_imports_are_not(self):
        data = elf_file()
        image = load_elf(data)
        image.dynamic_relocations = [
            {"relocation_type": 6, "address_kind": "virtual_address", "symbol_defined": True,
             "symbol_value": 0x4020, "address": 0x9100, "addend": 0},            # 本地已定义 → 候选
            {"relocation_type": 6, "address_kind": "virtual_address", "symbol_defined": False,
             "symbol_value": 0, "address": 0x9108, "addend": 0},                  # 导入未定义 → 跳过
            {"relocation_type": 1, "address_kind": "virtual_address", "symbol_defined": True,
             "symbol_value": 0x90000, "address": 0x9110, "addend": 0}]            # 本地但非代码 → 跳过
        candidates, _ = recover_code_pointers(data, image)
        self.assertEqual([item["target"] for item in candidates], [0x4020])
        self.assertEqual(candidates[0]["evidence"]["relocation"], "glob_dat")

    def test_symbolic_entries_in_aps2_tables_resolve_through_the_linked_dynsym(self):
        # Loader 的 dynamic_relocations 只读普通 REL/RELA；APS2 表里的 GLOB_DAT/R_X86_64_64
        # 经该节 sh_link 指向的 .dynsym 读取：已定义且落在代码内才是候选（2 号符号未定义，
        # 其值虽落在代码内也不采用；3 号定义在 .data）。
        symbols = bytes(24) + b"".join(struct.pack("<IBBHQQ", 0, 0x12, 0, section_index, value, 0)
                                       for section_index, value in ((1, 0x100b), (0, 0x1000), (2, 0x8000)))
        # 第 5 项是指向同一已定义代码符号的 JUMP_SLOT（7）：不是 GLOB_DAT/ABS，不采用。
        infos = ((1 << 32) | 6, (1 << 32) | 1, (2 << 32) | 6, (3 << 32) | 1, (1 << 32) | 7)
        stream = b"APS2" + b"".join(self._sleb(value) for value in (
            5, 0x8000 - 8, 5, 2 | 8, 8, *(item for info in infos for item in (info, 0))))
        data = bytearray(self._image([(".dynsym", 11, symbols, 24),
                                      (".rela.android", 0x60000002, stream, 1)],
                                     data_words=(0, 0, 0, 0, 0)))
        shoff, = struct.unpack_from("<Q", data, 0x28)
        struct.pack_into("<I", data, shoff + 4 * 64 + 40, 3)   # .rela.android 的 sh_link → .dynsym
        candidates, warnings = recover_code_pointers(bytes(data), load_elf(bytes(data)))
        self.assertEqual(sorted((item["evidence"]["pointer_address"], item["target"],
                                 item["evidence"]["relocation"], item["evidence"].get("encoding"))
                                for item in candidates),
                         [(0x8000, 0x100b, "glob_dat", "android_rela"),
                          (0x8008, 0x100b, "absolute", "android_rela")])
        self.assertEqual(warnings, [])


class ElfArrayRootPackedRelocationTests(unittest.TestCase):
    """elf_unwind 的 init/fini 数组根与 elf_pointers 覆盖同样的重定位编码（RELR、APS2）。"""

    _image = staticmethod(ElfCodePointerLoaderTests._image)
    _sleb = staticmethod(ElfCodePointerLoaderTests._sleb)

    def _roots(self, relocation_sections, slot_value=0):
        from fangida.loaders.elf_unwind import recover_function_ranges as unwind_recover
        data = self._image(relocation_sections, arrays=[(".init_array", 14, 0xA000, (slot_value,))])
        roots, warnings = unwind_recover(data, load_elf(data))
        return [(root["start"], root["array_slots"]) for root in roots
                if "init_array" in root["sources"]], warnings

    def test_aps2_rela_supplies_the_addend_of_a_zero_filled_array_slot(self):
        # APS2 打包的 RELA 中数组槽位内容为 0：不读加数就没有根（修复前的行为）。
        stream = b"APS2" + b"".join(self._sleb(value) for value in (
            1, 0, 1, 8, 0xA000, 8, 0x100b))     # 1 项：offset 增量、info=RELATIVE、加数
        self.assertEqual(self._roots([(".rela.android", 0x60000002, stream, 1)]),
                         ([(0x100b, [0xA000])], []))

    def test_relr_slots_use_the_implicit_addend(self):
        for section_type in (19, 0x6fffff00):
            self.assertEqual(self._roots([(".relr.dyn", section_type, struct.pack("<Q", 0xA000), 8)],
                                         slot_value=0x100b),
                             ([(0x100b, [0xA000])], []))

    def test_malformed_packed_table_withholds_every_literal_array_pointer(self):
        # 无法解析的打包表可能改写任何数组槽位：与畸形 REL/RELA 一样不采用字面值，并告警。
        for name, section_type, payload in ((".rela.android", 0x60000002, b"APS2\x81"),
                                            (".relr.dyn", 19, struct.pack("<Q", 0b11))):
            roots, warnings = self._roots([(name, section_type, payload, 1)], slot_value=0x100b)
            self.assertEqual(roots, [])
            self.assertTrue(any("initialization relocations unavailable" in message
                                for message in warnings), warnings)

    def test_symbolic_packed_relocation_of_an_array_slot_is_unresolved(self):
        stream = b"APS2" + b"".join(self._sleb(value) for value in (
            1, 0, 1, 8, 0xA000, (1 << 32) | 1, 0))   # R_X86_64_64 带符号：不是 RELATIVE
        roots, warnings = self._roots([(".rela.android", 0x60000002, stream, 1)], slot_value=0x100b)
        self.assertEqual(roots, [])
        self.assertIn("Unresolved ELF array relocation 1 at 0xa000", warnings)


def _pe(*, machine=0x8664, pdata=b"", export_rva=0x1010, relocations=(), rdata_words=(),
        image_base=0x140000000, text=b"", bits=64):
    """手工 PE：.text@RVA 0x1000、.rdata@RVA 0x2000（导出目录 0x2000、AddressOfFunctions
    0x2100、.pdata 0x2300、基址重定位 0x2500）；rdata_words 为 (RVA, 值, 宽度) 写入 .rdata。"""
    rdata = bytearray(0x600)
    struct.pack_into("<IIHHIIIIIII", rdata, 0, 0, 0, 0, 0, 0x2200, 1, 1, 1, 0x2100, 0, 0)
    struct.pack_into("<I", rdata, 0x100, export_rva)
    rdata[0x300:0x300 + len(pdata)] = pdata
    for rva, value, width in rdata_words:
        rdata[rva - 0x2000:rva - 0x2000 + width] = value.to_bytes(width, "little")
    blocks = bytearray()
    for page in sorted({rva & ~0xfff for rva, _ in relocations}):
        entries = [(kind << 12) | (rva & 0xfff) for rva, kind in relocations if rva & ~0xfff == page]
        entries += [0] * (len(entries) % 2)
        blocks += struct.pack("<II", page, 8 + 2 * len(entries)) + b"".join(
            struct.pack("<H", entry) for entry in entries)
    rdata[0x500:0x500 + len(blocks)] = blocks
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3c, 0x80)
    optional_size = 0xf0 if bits == 64 else 0xe0
    coff = struct.pack("<IHHIIIHH", 0x00004550, machine, 2, 0, 0, 0, optional_size,
                       0x22 if bits == 64 else 0x0102)
    opt = bytearray(optional_size)
    struct.pack_into("<H", opt, 0, 0x20b if bits == 64 else 0x10b)
    struct.pack_into("<I", opt, 16, 0x1000)
    struct.pack_into("<I", opt, 20, 0x1000)
    if bits == 64:
        struct.pack_into("<Q", opt, 24, image_base)
        directories, count_offset = 112, 108
    else:
        struct.pack_into("<I", opt, 28, image_base)
        directories, count_offset = 96, 92
    struct.pack_into("<I", opt, count_offset, 16)
    for index, (rva, size) in {0: (0x2000, 0x200), 3: (0x2300, len(pdata)),
                               5: (0x2500, len(blocks))}.items():
        if size:
            struct.pack_into("<II", opt, directories + index * 8, rva, size)
    text_header = struct.pack("<8sIIIIIIHHI", b".text", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    rdata_header = struct.pack("<8sIIIIIIHHI", b".rdata", 0x600, 0x2000, 0x600, 0x400, 0, 0, 0, 0, 0x40000040)
    out = bytearray(dos) + coff + opt + text_header + rdata_header
    out += bytes(0x200 - len(out))
    out += bytes(text) + b"\xcc" * (0x200 - len(text))
    out += bytes(rdata)
    return bytes(out)


class PeFunctionRangeLoaderTests(unittest.TestCase):
    """PE Loader 读取器：.pdata/导出给出声明起点，基址重定位逐槽位给出指针候选。"""

    def test_pdata_export_and_base_relocation_sources(self):
        data = _pe(pdata=struct.pack("<III", 0x1000, 0x1008, 0x2400),
                   rdata_words=[(0x2050, 0x140001020, 8)], relocations=[(0x2050, 10)])
        roots, warnings = pe_recover(data, load_pe(data))
        by_source = {item["start"]: item["source"] for item in roots}
        self.assertEqual(by_source, {0x140001000: "pdata", 0x140001010: "export",
                                     0x140001020: "data_pointer"})
        self.assertEqual(warnings, [])
        pdata = next(item for item in roots if item["source"] == "pdata")
        self.assertEqual(pdata["size"], 8)

    def test_base_relocation_to_non_code_is_dropped(self):
        data = _pe(rdata_words=[(0x2050, 0x140002000, 8)], relocations=[(0x2050, 10)])
        starts = {item["start"]: item["source"] for item in pe_recover(data, load_pe(data))[0]}
        self.assertNotIn(0x140002000, starts)
        self.assertEqual(pe_pointers(data, load_pe(data))[0], [])

    def test_code_pointers_are_reported_per_slot(self):
        # 同一目标出现在两个槽位（例如跳转表的缺省分支）：逐槽位各一条，供表级裁决。
        words = [(0x2050, 0x140001020, 8), (0x2058, 0x140001020, 8), (0x2060, 0x140001030, 8)]
        data = _pe(rdata_words=words, relocations=[(rva, 10) for rva, _, _ in words])
        found, warnings = pe_pointers(data, load_pe(data))
        self.assertEqual([(item["evidence"]["pointer_address"], item["target"]) for item in found],
                         [(0x140002050, 0x140001020), (0x140002058, 0x140001020),
                          (0x140002060, 0x140001030)])
        self.assertEqual(warnings, [])

    def test_arm64_pdata_uses_eight_byte_entries(self):
        # 审查者 arm64_pdata.py 场景：3 个 8 字节项。第 1 项 UnwindData 指向 .xdata（首字
        # 函数长度 0x10 个 4 字节单位），第 2 项是打包展开数据（长度 8 个单位），第 3 项的
        # .xdata 不在文件中（长度未知）。
        packed = 1 | (8 << 2)
        pdata = struct.pack("<IIIIII", 0x1000, 0x2400, 0x1040, packed, 0x1080, 0x9000)
        data = _pe(machine=0xAA64, pdata=pdata, export_rva=0, rdata_words=[(0x2400, 0x10, 4)])
        roots, warnings = pe_recover(data, load_pe(data))
        self.assertEqual([(item["start"], item["size"]) for item in roots],
                         [(0x140001000, 0x40), (0x140001040, 0x20), (0x140001080, None)])
        self.assertEqual([item["evidence"]["unwind_encoding"] for item in roots],
                         ["xdata", "packed", "xdata_unavailable"])
        self.assertEqual(warnings, [])

    def test_armnt_pdata_strips_thumb_bit_and_uses_halfword_units(self):
        pdata = struct.pack("<II", 0x1001, 1 | (6 << 2))
        data = _pe(machine=0x1C4, pdata=pdata, export_rva=0, bits=32, image_base=0x400000)
        roots, _ = pe_recover(data, load_pe(data))
        self.assertEqual([(item["start"], item["size"], item.get("isa_mode")) for item in roots],
                         [(0x401000, 12, "thumb")])

    def test_other_machines_do_not_parse_pdata_and_warn(self):
        pdata = struct.pack("<III", 0x1000, 0x1008, 0x2400)
        data = _pe(machine=0x14C, pdata=pdata, export_rva=0, bits=32, image_base=0x400000)
        roots, warnings = pe_recover(data, load_pe(data))
        self.assertEqual(roots, [])
        self.assertTrue(any("0x14c" in message and "not parsed" in message for message in warnings),
                        warnings)


class MachoInitializerLoaderTests(unittest.TestCase):
    """Mach-O 构造函数指针：__mod_init_func（指针）与 __init_offsets（32 位镜像基址偏移）。"""

    BASE = 0x100000000

    def _image(self, *, mod_init=(), init_offsets=()):
        text = [("__text", self.BASE + 0x800, 0x40, 0x800, 0x80000400)]
        if init_offsets:
            text.append(("__init_offsets", self.BASE + 0x840, 4 * len(init_offsets), 0x840, 0x16))
        segments = [("__TEXT", self.BASE, 0x1000, 0, 0x1000, 5, text)]
        if mod_init:
            segments.append(("__DATA", self.BASE + 0x1000, 0x1000, 0x1000, 0x100, 3,
                             [("__mod_init_func", self.BASE + 0x1000, 8 * len(mod_init), 0x1000, 0x9)]))
        data = _macho(segments, entry=0x800)
        data[0x800:0x840] = b"\xc3" * 0x40
        for index, value in enumerate(init_offsets):
            struct.pack_into("<I", data, 0x840 + 4 * index, value)
        for index, value in enumerate(mod_init):
            struct.pack_into("<Q", data, 0x1000 + 8 * index, value)
        return bytes(data)

    def test_mod_init_func_pointers_are_initializer_roots(self):
        roots, warnings = macho_recover(self._image(mod_init=(self.BASE + 0x810, 0x7777)))
        self.assertEqual([(item["start"], item["source"]) for item in roots],
                         [(self.BASE + 0x810, "mod_init_func")])
        self.assertEqual(roots[0]["evidence"]["pointer_address"], self.BASE + 0x1000)
        self.assertEqual(warnings, [])

    def test_init_offsets_are_relative_to_the_image_base(self):
        roots, warnings = macho_recover(self._image(init_offsets=(0x820, 0x5000)))
        self.assertEqual([(item["start"], item["source"]) for item in roots],
                         [(self.BASE + 0x820, "init_offsets")])
        self.assertEqual(roots[0]["evidence"]["pointer_address"], self.BASE + 0x840)
        self.assertEqual(warnings, [])


def _elf_with_table(code, targets, *, entry=0x1000):
    """x86-64 ET_DYN：.text@0x1000 为 code，.data@0x2000 起连续槽位依次存放 targets
    （RELA RELATIVE 重定位），即一张指针表。"""
    data = bytearray(64)
    sections = [("", 0, 0, 0, 0, 0, 0, 0, 0, 0)]

    def add(name, section_type, flags, address, content, entry_size=0):
        data.extend(bytes(-len(data) % 16))
        offset = len(data)
        data.extend(content)
        sections.append((name, section_type, flags, address, offset, len(content), 0, 0, 16, entry_size))

    add(".text", 1, 6, 0x1000, bytes(code))
    add(".data", 1, 3, 0x2000, b"\x00" * (8 * max(1, len(targets))))
    add(".rela.dyn", 4, 2, 0x3000, b"".join(struct.pack("<QQq", 0x2000 + 8 * index, 8, target)
                                            for index, target in enumerate(targets)), 24)
    names = bytearray(b"\0")
    name_offsets = {"": 0}
    for name in [section[0] for section in sections] + [".shstrtab"]:
        if name not in name_offsets:
            name_offsets[name] = len(names)
            names.extend(name.encode() + b"\0")
    add(".shstrtab", 3, 0, 0, names)
    data.extend(bytes(-len(data) % 16))
    shoff = len(data)
    for section in sections:
        data.extend(struct.pack("<IIQQQQIIQQ", name_offsets[section[0]], *section[1:]))
    data[:16] = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 3, 62, 1, entry, 0, shoff, 0,
                     64, 0, 0, 64, len(sections), len(sections) - 1)
    return bytes(data)


def _analyze_elf(data, workers=1, **kwargs):
    with XrefStage(separate_thread=workers > 1) as stage:
        return full_analysis.analyze_full(data, load_elf(data), workers=workers,
                                          xref_stage=stage, **kwargs)


def _recovered(functions, start):
    return next((fn for fn in functions if fn["start"] == start
                 and fn.get("analysis_scope") == "full_region_recovered_function"), None)


@unittest.skipUnless(DECODER_AVAILABLE, "A native decoder is required")
class ElfPointerDiscoveryEndToEndTests(unittest.TestCase):
    """手工构造的真实编码 ELF：只经指针表到达的函数应被恢复，孤立指针不接受。"""

    @staticmethod
    def _code():
        code = bytearray(b"\xcc" * 0x40)
        code[0:5] = b"\xe8" + struct.pack("<i", 5)   # 0x1000 call 0x100a
        code[5] = 0xc3                                # 0x1005 ret
        code[0x0a] = 0xc3                             # 0x100a funcA ret（直接调用到达，已知函数）
        code[0x0b] = 0xc3                             # 0x100b funcB ret（只经指针到达）
        return bytes(code)

    def test_pointer_only_function_in_a_table_is_recovered_with_evidence(self):
        functions, _, stats, metadata, _ = _analyze_elf(_elf_with_table(self._code(), [0x100a, 0x100b]))
        recovered = _recovered(functions, 0x100b)
        self.assertIsNotNone(recovered, "pointer-only function was not recovered")
        self.assertEqual(recovered["source"], "data_pointer")
        self.assertEqual(recovered["evidence"]["relocation"], "relative")
        self.assertEqual((recovered["evidence"]["table_address"], recovered["evidence"]["table_entries"],
                          recovered["evidence"]["table_known_functions"]), (0x2000, 2, 1))
        self.assertTrue(recovered["cfg"]["complete"])
        pointer_roots = metadata["full_analysis"]["pointer_roots"]
        self.assertEqual((pointer_roots["accepted"], pointer_roots["built"]), (1, 1))
        self.assertEqual(stats["full_pointer_functions"], 1)
        self.assertEqual(stats["full_pointer_accepted"], 1)
        self.assertEqual(stats["full_function_sources"].get("data_pointer"), 1)

    def test_lone_pointer_is_recorded_but_not_accepted(self):
        functions, _, stats, metadata, _ = _analyze_elf(_elf_with_table(self._code(), [0x100b]))
        self.assertIsNone(_recovered(functions, 0x100b))
        pointer_roots = metadata["full_analysis"]["pointer_roots"]
        self.assertEqual((pointer_roots["accepted"], stats["full_pointer_functions"]), (0, 0))
        self.assertEqual(pointer_roots["unconfirmed"],
                         [{"start": 0x100b, "pointer_address": 0x2000, "reason": "no_known_function"}])

    def test_table_with_claimed_item_is_rejected_whole(self):
        _, _, _, metadata, _ = _analyze_elf(_elf_with_table(self._code(), [0x100a, 0x100b, 0x1005]))
        pointer_roots = metadata["full_analysis"]["pointer_roots"]
        self.assertEqual(pointer_roots["accepted"], 0)
        self.assertEqual(pointer_roots["rejected"],
                         {"already_seed": 1, "claimed": 1, "table_rejected": 1})
        _, _, _, metadata, _ = _analyze_elf(_elf_with_table(self._code(), [0x1000]))
        self.assertEqual(metadata["full_analysis"]["pointer_roots"]["rejected"], {"already_seed": 1})

    def test_worker_budgets_agree_byte_for_byte_and_separate_threads(self):
        data = _elf_with_table(self._code(), [0x100a, 0x100b])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pointer.elf"
            path.write_bytes(data)
            digests = []
            for budget in (1, 3, 8):
                decoded, indexed = set(), set()

                def observe(function, target):
                    def wrapped(*args, **kwargs):
                        target.add(threading.get_ident())
                        return function(*args, **kwargs)
                    return wrapped

                with ExitStack() as stack:
                    stack.enter_context(patch.object(NativeDecoder, "decode_bytes_fast",
                        observe(NativeDecoder.decode_bytes_fast, decoded)))
                    stack.enter_context(patch.object(full_analysis._CachedDecoder, "decode",
                        observe(full_analysis._CachedDecoder.decode, decoded)))
                    for name in ("_references", "index_references"):
                        stack.enter_context(patch.object(full_analysis, name,
                            observe(getattr(full_analysis, name), indexed)))
                    with AnalysisService(Settings(analyze_threads=budget, semantic_threads=2)) as service:
                        result = service.analyze(path, full_analysis=True)
                self.assertNotEqual(result.status, "error", result.warnings)
                self.assertEqual(result.stats["full_pointer_functions"], 1)
                self.assertTrue(decoded and indexed)
                # 预算为 1 时解码与引用共用唯一分析线程；预算 > 1 时二者线程集合不相交，
                # 第二轮指针 CFG 也在解码线程集合内，不会落到 xref 线程。
                if budget == 1:
                    self.assertEqual(decoded, indexed)
                else:
                    self.assertTrue(decoded.isdisjoint(indexed))
                recovered = _recovered(result.functions, 0x100b)
                self.assertEqual(recovered["source"], "data_pointer")
                self.assertEqual(AnalysisView(result).disassembly(0x100b, 1)[0]["mnemonic"], "ret")
                digests.append(_evidence_digest(result))
            self.assertEqual(len(set(digests)), 1, "worker budgets disagreed")


@unittest.skipUnless(DECODER_AVAILABLE, "A native decoder is required")
class SecondRoundStateTests(unittest.TestCase):
    """第二轮与首轮一致：使用本地不动点之后的不返回集合；中途取消时统计如实。"""

    def test_second_round_uses_noreturn_targets_from_the_local_fixed_point(self):
        # 审查者 noreturn_default.py 场景：D=0x1020 是 ud2，被本地不动点判为不返回；入口与
        # 只经指针到达的 F=0x1030 都调用 D，F 的落空边（nop; nop; ret）同样应被截断。
        code = bytearray(b"\xcc" * 0x60)
        code[0x00:0x05] = b"\xe8" + struct.pack("<i", 0x20 - 5)      # 0x1000 call D
        code[0x05] = 0xc3                                             # 0x1005 ret
        code[0x20:0x22] = b"\x0f\x0b"                                 # 0x1020 D: ud2
        code[0x30:0x35] = b"\xe8" + struct.pack("<i", 0x20 - 0x35)    # 0x1030 F: call D
        code[0x35:0x38] = b"\x90\x90\xc3"                             # 0x1035 nop; nop; ret
        functions, _, stats, metadata, _ = _analyze_elf(_elf_with_table(bytes(code), [0x1020, 0x1030]))
        targets = {item["address"] for item in metadata["full_analysis"]["noreturn"]["targets"]}
        self.assertIn(0x1020, targets)
        pointer = _recovered(functions, 0x1030)
        self.assertIsNotNone(pointer)
        self.assertEqual(pointer["source"], "data_pointer")
        self.assertEqual([instruction["addr"] for block in pointer["blocks"]
                          for instruction in block["instructions"]], [0x1030])
        self.assertEqual([(item["from"], item["target"]) for item in pointer["cfg"]["noreturn_calls"]],
                         [(0x1030, 0x1020)])
        # 与首轮入口函数的处理方式一致。
        entry = _recovered(functions, 0x1000)
        self.assertEqual([(item["from"], item["target"]) for item in entry["cfg"]["noreturn_calls"]],
                         [(0x1000, 0x1020)])

    def test_second_round_function_with_only_noreturn_exits_is_marked_noreturn(self):
        # 审查者 nr_anchor.py 场景加一个会返回的指针函数：表 [入口(已知), G, F]，G=0x1010 只有
        # ret，F=0x1030 调用不返回的 D=0x1020 后才 ret。首轮入口与 F 同形，二者都应标为
        # noreturn（F 的结论来自第二轮补算的本地不动点）；G 会返回，不得标注。
        code = bytearray(b"\xcc" * 0x60)
        code[0x00:0x05] = b"\xe8" + struct.pack("<i", 0x20 - 5)      # 0x1000 入口: call D
        code[0x05] = 0xc3                                             # 0x1005 ret
        code[0x10] = 0xc3                                             # 0x1010 G: ret
        code[0x20:0x22] = b"\x0f\x0b"                                 # 0x1020 D: ud2
        code[0x30:0x35] = b"\xe8" + struct.pack("<i", 0x20 - 0x35)    # 0x1030 F: call D
        code[0x35:0x38] = b"\x90\x90\xc3"                             # 0x1035 nop; nop; ret
        functions, _, stats, metadata, warnings = _analyze_elf(
            _elf_with_table(bytes(code), [0x1000, 0x1010, 0x1030]))
        self.assertEqual(metadata["full_analysis"]["pointer_roots"]["built"], 2)
        entry, returning, pointer = (_recovered(functions, start) for start in (0x1000, 0x1010, 0x1030))
        self.assertTrue(entry["noreturn"])
        self.assertEqual(entry["noreturn_evidence"]["evidence"], "local_fixed_point")
        self.assertTrue(pointer["noreturn"])
        self.assertEqual((pointer["noreturn_evidence"]["evidence"], pointer["noreturn_evidence"]["pass"]),
                         ("local_fixed_point", "pointer_roots"))
        self.assertNotIn("noreturn", returning)
        noreturn = metadata["full_analysis"]["noreturn"]
        self.assertIn(0x1030, {item["address"] for item in noreturn["targets"]})
        self.assertNotIn(0x1010, {item["address"] for item in noreturn["targets"]})
        self.assertGreaterEqual(noreturn["pointer_fixed_point_rounds"], 1)
        self.assertEqual(stats["full_noreturn_local_functions"], 3)   # D、入口与 F
        self.assertFalse(any("unrebuilt" in message for message in warnings))

    def test_second_round_fixed_point_is_skipped_without_pointer_functions(self):
        functions, _, _, metadata, _ = _analyze_elf(
            _elf_with_table(ElfPointerDiscoveryEndToEndTests._code(), [0x100b]))
        self.assertEqual(metadata["full_analysis"]["noreturn"]["pointer_fixed_point_rounds"], 0)

    @staticmethod
    def _cancel_sample():
        # 入口依次调用 h1..h6（已知函数）；p_k 紧跟 h_k 之后、只经指针表到达，各自落在不同
        # 的已知函数区间内。表为 [h1, p1, ..., p6]。
        code = bytearray(b"\xcc" * 0x300)
        helpers = [0x1100 + 0x40 * k for k in range(1, 7)]
        pointers = [helper + 0x20 for helper in helpers]
        cursor = 0
        for helper in helpers:
            code[cursor:cursor + 5] = b"\xe8" + struct.pack("<i", helper - (0x1000 + cursor + 5))
            cursor += 5
        code[cursor] = 0xc3
        for address in helpers + pointers:
            code[address - 0x1000] = 0xc3
        return _elf_with_table(bytes(code), [helpers[0], *pointers]), pointers

    def test_cancel_between_second_round_batches_reports_unbuilt_seeds(self):
        # 审查者 cancel_second.py 场景：workers=1 时每批 2 个；第二轮第一批完成后请求取消。
        data, pointers = self._cancel_sample()
        state = {"second_round": False, "stop": False}
        original = full_analysis._accept_pointer_candidates

        def judge(*args, **kwargs):
            result = original(*args, **kwargs)
            state["second_round"] = True
            return result

        def progress(event):
            if event.get("stage") == "cfg" and state["second_round"]:
                state["stop"] = True

        with patch.object(full_analysis, "_accept_pointer_candidates", judge):
            functions, _, stats, metadata, warnings = _analyze_elf(
                data, is_cancelled=lambda: state["stop"], on_progress=progress)
        pointer_roots = metadata["full_analysis"]["pointer_roots"]
        built = sorted(fn["start"] for fn in functions if fn.get("source") == "data_pointer"
                       and fn.get("analysis_scope") == "full_region_recovered_function")
        unbuilt = sorted(fn["start"] for fn in functions if fn.get("source") == "data_pointer"
                         and fn.get("analysis_scope") == "not_decoded")
        self.assertEqual(built, pointers[:2])
        self.assertEqual(unbuilt, pointers[2:])
        self.assertEqual((pointer_roots["accepted"], pointer_roots["built"]), (6, 2))
        self.assertEqual((stats["full_pointer_accepted"], stats["full_pointer_functions"]), (6, 2))
        self.assertFalse(metadata["full_analysis"]["cfg_pass_complete"])
        self.assertFalse(stats["full_cfg_pass_complete"])
        self.assertTrue(stats["semantic_cancelled"])
        self.assertIn("Full analysis cancelled; partial results retained", warnings)

    def test_uncancelled_second_round_builds_every_accepted_seed(self):
        data, pointers = self._cancel_sample()
        functions, _, stats, metadata, _ = _analyze_elf(data)
        self.assertEqual(sorted(fn["start"] for fn in functions if fn.get("source") == "data_pointer"
                                and fn.get("analysis_scope") == "full_region_recovered_function"),
                         pointers)
        self.assertEqual((stats["full_pointer_accepted"], stats["full_pointer_functions"]), (6, 6))
        self.assertTrue(metadata["full_analysis"]["cfg_pass_complete"])


def _pe32_switch(*, inline):
    """PE32 x86：cb1@0x401000（.text 起点）、cb2@0x401010（只经函数指针表到达）、
    dispatch@0x401020（cmp/ja/jmp dword ptr [ecx*4+table] 与 4 个 case 块）、main 调用 dispatch。
    函数指针表 [cb1, cb2] 在 .rdata；switch 表在 .rdata（inline=False）或内联在 .text 末尾。"""
    table = 0x40104c if inline else 0x402010
    text = bytearray(b"\xcc" * 0x80)
    text[0x00:0x08] = bytes.fromhex("8b442404" "83c003" "c3")               # cb1
    text[0x10:0x18] = bytes.fromhex("8b442404" "83f055" "c3")               # cb2
    text[0x20:0x29] = bytes.fromhex("8b4c2404" "83f903" "771f")             # mov/cmp/ja default
    text[0x29:0x30] = bytes.fromhex("ff248d") + struct.pack("<I", table)    # jmp [ecx*4+table]
    for index in range(4):                                                  # case0..3: mov eax,k; ret
        text[0x30 + 6 * index:0x36 + 6 * index] = b"\xb8" + struct.pack("<I", index + 1) + b"\xc3"
    text[0x48:0x4b] = bytes.fromhex("31c0c3")                               # default: xor eax,eax; ret
    cases = [0x401030 + 6 * index for index in range(4)]
    main = 0x401060
    text[0x60:0x62] = bytes.fromhex("6a01")                                 # push 1
    text[0x62:0x67] = b"\xe8" + struct.pack("<i", 0x401020 - (main + 7))    # call dispatch
    text[0x67:0x6b] = bytes.fromhex("83c404c3")                             # add esp,4; ret
    words = [(0x2000, 0x401000, 4), (0x2004, 0x401010, 4)]
    relocations = [(0x2000, 3), (0x2004, 3), (0x102c, 3)]
    if inline:
        for index, case in enumerate(cases):
            struct.pack_into("<I", text, 0x4c + 4 * index, case)
            relocations.append((0x104c + 4 * index, 3))
    else:
        words += [(0x2010 + 4 * index, case, 4) for index, case in enumerate(cases)]
        relocations += [(0x2010 + 4 * index, 3) for index in range(4)]
    data = bytearray(_pe(machine=0x14C, export_rva=0, bits=32, image_base=0x400000,
                         text=bytes(text), rdata_words=words, relocations=relocations))
    # 入口改为 main；去掉导出目录（测试只关心基址重定位）。
    struct.pack_into("<I", data, 0x80 + 24 + 16, main - 0x400000)
    struct.pack_into("<II", data, 0x80 + 24 + 96, 0, 0)
    return bytes(data), cases


@unittest.skipUnless(DECODER_AVAILABLE, "A native decoder is required")
class Pe32SwitchTableEndToEndTests(unittest.TestCase):
    """审查者 PE32 switch 样本同形（.rdata 跳转表与内联跳转表两种）：0 误报，真函数指针仍被恢复。"""

    def _check(self, inline):
        data, cases = _pe32_switch(inline=inline)
        image = load_pe(data)
        with XrefStage() as stage:
            functions, _, stats, metadata, _ = full_analysis.analyze_full(
                data, image, workers=1, xref_stage=stage)
        pointer_roots = metadata["full_analysis"]["pointer_roots"]
        accepted = sorted(fn["start"] for fn in functions if fn.get("source") == "data_pointer")
        self.assertEqual(accepted, [0x401010], pointer_roots)
        self.assertEqual(_recovered(functions, 0x401010)["evidence"]["table_known_functions"], 1)
        unconfirmed = {item["start"]: item["reason"] for item in pointer_roots["unconfirmed"]}
        self.assertTrue(set(cases) <= set(unconfirmed), unconfirmed)
        for case in cases:
            self.assertIsNone(_recovered(functions, case), hex(case))
        # 分支标签前一条是 jmp [table] 或 ret：只看前驱会被当成干净起点，必须由表级证据挡下。
        expected = "slot_in_code" if inline else "indirect_jump_interval"
        self.assertEqual({unconfirmed[case] for case in cases}, {expected})
        return pointer_roots

    def test_rdata_jump_table_entries_are_not_functions(self):
        self._check(inline=False)

    def test_inline_jump_table_entries_are_not_functions(self):
        pointer_roots = self._check(inline=True)
        # jmp 指令的 disp32 槽位（在 .text 内）指向内联表本身，同样不是函数。
        self.assertEqual(pointer_roots["unconfirmed"][-1],
                         {"start": 0x40104c, "pointer_address": 0x40102c, "reason": "slot_in_code"})


@unittest.skipUnless(DECODER_AVAILABLE and LIBTERSAFE.is_file(), "libtersafe.so sample is not available")
class LibtersafeBranchTableTests(unittest.TestCase):
    """libtersafe：混淆函数 0x2f4e3c 的 br 分支表 [0x2f4e78, 0x2f4e80, 0x2f4e3c, 0x2f4e88]，
    末项是 FDE 末尾的零填充（udf #0），不得被当作函数。"""

    def test_branch_table_padding_entry_is_not_accepted(self):
        from fangida.core.kkagent.binary import parse_binary
        data = LIBTERSAFE.read_bytes()
        captured = {}
        original = full_analysis._accept_pointer_candidates

        def judge(*args, **kwargs):
            captured["args"], captured["kwargs"] = args, kwargs
            return original(*args, **kwargs)

        with patch.object(full_analysis, "_accept_pointer_candidates", judge):
            with XrefStage() as stage:
                functions, _, _, metadata, _ = full_analysis.analyze_full(
                    data, parse_binary(data, "elf"), workers=1, xref_stage=stage)
        self.assertFalse(any(fn["start"] == 0x2f4e88 and fn.get("source") == "data_pointer"
                             for fn in functions))
        self.assertEqual(metadata["full_analysis"]["pointer_roots"]["accepted"], 0)
        # 只取这张表重新裁决，确认拒绝原因是目标本身为填充（而不是偶然被其它规则挡下）。
        args = list(captured["args"])
        table = [item for item in args[0]
                 if 0x53bd50 <= item["evidence"]["pointer_address"] < 0x53bd70]
        self.assertEqual([item["start"] for item in table], [0x2f4e78, 0x2f4e80, 0x2f4e3c, 0x2f4e88])
        details = {}
        accepted, rejected = original(table, *args[1:], **{**captured["kwargs"], "details": details})
        self.assertEqual(accepted, [])
        self.assertEqual(details["rejected_tables"], {"padding_or_trap": 1})
        self.assertEqual(rejected["padding_or_trap"], 1)


@unittest.skipUnless(DECODER_AVAILABLE and shutil.which("clang"), "clang and a decoder are required")
class MachoRealSampleTests(unittest.TestCase):
    """clang 编译并实际运行的 Mach-O：输出与返回值确认构造函数与指针函数确实执行；剥符号后
    构造函数分别经 LC_FUNCTION_STARTS、__init_offsets（链式修订默认产物）与 __mod_init_func
    （旧式 -no_fixup_chains）恢复。"""

    SOURCE = (
        "#include <stdio.h>\n"
        "static int flag;\n"
        "static int reached_via_pointer(int x) { return x * 3 + 1; }\n"
        "int (*table[1])(int) = { reached_via_pointer };\n"
        "static void only_ctor(void) __attribute__((constructor));\n"
        "static void only_ctor(void) { flag = 7; puts(\"ctor-ran\"); }\n"
        "int main(int argc, char **argv) { return table[0](argc) + flag; }\n")

    def _build(self, architecture, *flags):
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, directory, True)
        source = directory / "sample.c"
        source.write_text(self.SOURCE)
        binary = directory / "sample"
        compile_result = subprocess.run(
            ["clang", "-arch", architecture, "-O1", *flags, str(source), "-o", str(binary)],
            capture_output=True)
        if compile_result.returncode != 0:
            self.skipTest(f"clang cannot build {architecture} {flags}: {compile_result.stderr.decode()[:200]}")
        subprocess.run(["strip", "-x", str(binary)], check=True, capture_output=True)
        runner = ["/usr/bin/arch", "-x86_64"] if architecture == "x86_64" else []
        try:
            run_result = subprocess.run([*runner, str(binary)], capture_output=True, timeout=60)
        except (OSError, subprocess.SubprocessError) as exc:
            self.skipTest(f"cannot run {architecture} sample: {exc}")
        if architecture == "x86_64" and run_result.returncode != 11 and not run_result.stdout:
            self.skipTest("x86_64 samples need Rosetta")
        # 运行确认语义：构造函数打印并把 flag 置 7；main 返回 table[0](1) + flag = 4 + 7。
        self.assertEqual(run_result.stdout, b"ctor-ran\n")
        self.assertEqual(run_result.returncode, 11)
        return binary.read_bytes()

    def _analyze(self, data):
        from fangida.loaders.macho import load_macho
        with XrefStage() as stage:
            functions, _, stats, _, _ = full_analysis.analyze_full(
                data, load_macho(data), workers=1, xref_stage=stage)
        return functions, stats

    def _constructor(self, data, source):
        starts = [root["start"] for root in macho_recover(data)[0] if source in root.get("sources", ())]
        self.assertEqual(len(starts), 1, f"expected one {source} root")
        return starts[0]

    def _check_function_starts(self, architecture):
        data = self._build(architecture)
        from fangida.loaders.macho import read_macho_symbols
        symbols = {function["start"] for function in read_macho_symbols(data)["functions"]}
        starts = {root["start"] for root in macho_recover(data)[0] if root["source"] == "function_starts"}
        pointer_only = starts - symbols
        self.assertTrue(pointer_only, "no symbol-free function starts after stripping")
        functions, stats = self._analyze(data)
        recovered = {fn["start"] for fn in functions
                     if fn.get("analysis_scope") == "full_region_recovered_function"}
        self.assertTrue(pointer_only <= recovered,
                        "a symbol-free function start was not recovered via function_starts")
        self.assertGreaterEqual(stats["full_function_sources"].get("function_starts", 0), len(pointer_only))

    def _check_initializer(self, architecture, source, *flags):
        data = self._build(architecture, "-Wl,-no_function_starts", *flags)
        constructor = self._constructor(data, source)
        functions, stats = self._analyze(data)
        recovered = _recovered(functions, constructor)
        self.assertIsNotNone(recovered, f"{source} constructor was not recovered")
        self.assertIn(source, [recovered.get("source"), *recovered.get("sources", ())])
        self.assertTrue(recovered["blocks"])
        self.assertEqual(stats["full_function_sources"].get(source), 1)

    def test_x86_64_function_starts_recover_symbol_free_functions(self):
        self._check_function_starts("x86_64")

    def test_arm64_function_starts_recover_symbol_free_functions(self):
        self._check_function_starts("arm64")

    def test_x86_64_constructor_from_init_offsets(self):
        self._check_initializer("x86_64", "init_offsets")

    def test_arm64_constructor_from_init_offsets(self):
        self._check_initializer("arm64", "init_offsets")

    def test_x86_64_constructor_from_mod_init_func(self):
        self._check_initializer("x86_64", "mod_init_func", "-mmacosx-version-min=10.15",
                                "-Wl,-no_fixup_chains")

    def test_arm64_constructor_from_mod_init_func(self):
        self._check_initializer("arm64", "mod_init_func", "-mmacosx-version-min=10.15",
                                "-Wl,-no_fixup_chains")



def _ndk_bin():
    """Android NDK 的 LLVM 工具目录（ld.lld、lld-link、llvm-readelf/readobj/nm）；找不到时为 None。"""
    import os
    roots = [os.environ.get(name) for name in ("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT")]
    roots += sorted(map(str, (Path.home() / "Library/Android/sdk/ndk").glob("*")), reverse=True)
    roots += sorted(map(str, (Path.home() / "Android/Sdk/ndk").glob("*")), reverse=True)
    for root in filter(None, roots):
        for candidate in sorted(Path(root).glob("toolchains/llvm/prebuilt/*/bin")):
            if all((candidate / tool).exists() for tool in ("clang", "ld.lld", "lld-link",
                                                            "llvm-readelf", "llvm-readobj", "llvm-nm")):
                return candidate
    return None


NDK_BIN = _ndk_bin()


@unittest.skipUnless(NDK_BIN, "Android NDK LLVM tools are required")
class NdkPackedRelocationRealSampleTests(unittest.TestCase):
    """NDK ld.lld 真实链接产物：APS2/RELR/Android RELR 解码与 llvm-readelf 逐项一致；
    不同打包方式下的指针候选与 init/fini 数组根按符号完全相同。"""

    SOURCE = (
        "typedef int (*fn_t)(int);\n"
        "__attribute__((noinline)) int f0(int x){return x*3+1;}\n"
        "__attribute__((noinline)) int f1(int x){return x^0x55;}\n"
        "__attribute__((noinline)) static int hidden_a(int x){return x*x+11;}\n"
        "__attribute__((noinline)) static int hidden_b(int x){return x*5-3;}\n"
        "fn_t table[] = {f0, f1, hidden_a, hidden_b};\n"
        "const char *strs[] = {\"a\",\"bb\",\"ccc\",\"dddd\",\"e\",\"ff\",\"ggg\",\"hhhh\"};\n"
        "static volatile int counter;\n"
        "__attribute__((constructor)) static void ctor_a(void){counter = 42;}\n"
        "__attribute__((constructor(101))) static void ctor_b(void){counter += 1;}\n"
        "__attribute__((destructor)) static void dtor_a(void){counter = 0;}\n"
        "int run(int i, int x){return table[i & 3](x) + counter + strs[i & 7][0];}\n")
    # (目标三元组, 链接选项)：aarch64 用 RELA，armv7a 用 REL；含 APS2、RELR 与 Android RELR 旧标签。
    VARIANTS = [(target, mode, extra)
                for target in ("aarch64-linux-android30", "armv7a-linux-androideabi30")
                for mode, extra in (("none", ()), ("android", ()), ("relr", ()), ("android+relr", ()),
                                    ("android+relr", ("-Wl,--use-android-relr-tags",)))]

    @classmethod
    def setUpClass(cls):
        cls.directory = Path(tempfile.mkdtemp())
        source = cls.directory / "lib.c"
        source.write_text(cls.SOURCE)
        cls.samples = {}
        for index, (target, mode, extra) in enumerate(cls.VARIANTS):
            output = cls.directory / f"lib{index}.so"
            result = subprocess.run(
                [str(NDK_BIN / "clang"), f"--target={target}", "-O2", "-fPIC", "-shared", "-nostdlib",
                 f"-Wl,--pack-dyn-relocs={mode}", *extra, str(source), "-o", str(output)],
                capture_output=True)
            if result.returncode != 0:
                raise unittest.SkipTest(f"NDK cannot link {target} {mode}: {result.stderr.decode()[:200]}")
            cls.samples[(target, mode, extra)] = output

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.directory, True)

    @staticmethod
    def _readelf(path):
        """llvm-readelf -r：{节文件偏移: [(r_offset, r_info, 加数或 None)]}（REL 的加数列为空）。"""
        import re
        output = subprocess.run([str(NDK_BIN / "llvm-readelf"), "-r", str(path)],
                                capture_output=True, text=True, check=True).stdout
        sections, current = {}, None
        for line in output.splitlines():
            match = re.match(r"Relocation section '[^']+' at offset (0x[0-9a-f]+)", line)
            if match:
                current = sections.setdefault(int(match.group(1), 16), [])
                continue
            match = re.match(r"\s*([0-9a-f]{8,16})\s+([0-9a-f]{8,16})\s+R_\S+(.*)$", line)
            if match and current is not None:
                addend = re.search(r"([+-])\s*([0-9a-f]+)\s*$", match.group(3))
                rest = match.group(3).strip()
                value = (int(addend.group(2), 16) * (-1 if addend.group(1) == "-" else 1) if addend
                         else int(rest, 16) if re.fullmatch(r"[0-9a-f]+", rest) else None)
                current.append((int(match.group(1), 16), int(match.group(2), 16), value))
        return sections

    @staticmethod
    def _section_headers(data, bits):
        shoff = struct.unpack_from("<Q" if bits == 64 else "<I", data, 0x28 if bits == 64 else 0x20)[0]
        stride, count = struct.unpack_from("<HH", data, 0x3a if bits == 64 else 0x2e)
        fmt = "<IIQQQQIIQQ" if bits == 64 else "<IIIIIIIIII"
        return [struct.unpack_from(fmt, data, shoff + index * stride) for index in range(count)]

    def test_packed_decoders_match_llvm_readelf_entry_for_entry(self):
        from fangida.loaders.elf_pointers import _android_packed, _relr_slots
        seen = Counter()
        for key, path in self.samples.items():
            data = path.read_bytes()
            bits = load_elf(data).bits
            mask = (1 << bits) - 1
            truth = self._readelf(path)
            for header in self._section_headers(data, bits):
                kind, offset, size = header[1], header[4], header[5]
                raw = data[offset:offset + size]
                if kind in (0x60000001, 0x60000002):
                    explicit = kind == 0x60000002
                    ours = [(place, info, addend if explicit else None)
                            for place, info, addend in _android_packed(raw, bits, explicit)]
                    expected = [(place, info, (addend or 0) & mask if explicit else None)
                                for place, info, addend in truth[offset]]
                elif kind in (19, 0x6fffff00):
                    width = bits // 8
                    ours = list(_relr_slots((int.from_bytes(raw[at:at + width], "little")
                                             for at in range(0, size, width)), bits))
                    expected = [place for place, _, _ in truth[offset]]
                else:
                    continue
                with self.subTest(sample=key, section_type=hex(kind)):
                    self.assertTrue(ours)
                    self.assertEqual(ours, expected)
                seen[kind] += 1
        # 四种打包节类型都被真实产物覆盖。
        self.assertEqual(set(seen), {0x60000001, 0x60000002, 19, 0x6fffff00})

    def test_pointer_candidates_and_array_roots_agree_across_packing_modes(self):
        from fangida.loaders.elf_unwind import recover_function_ranges as unwind_recover
        per_target = {}
        for (target, mode, extra), path in self.samples.items():
            data = path.read_bytes()
            image = load_elf(data)
            output = subprocess.run([str(NDK_BIN / "llvm-nm"), str(path)],
                                    capture_output=True, text=True, check=True).stdout
            names = {int(parts[0], 16) & ~1: parts[2] for parts in map(str.split, output.splitlines())
                     if len(parts) == 3 and parts[1] in "tT"}
            candidates, warnings = recover_code_pointers(data, image)
            self.assertEqual(warnings, [])
            pointers = sorted((names.get(item["target"], hex(item["target"])), item["evidence"]["relocation"],
                               item["evidence"].get("structure")) for item in candidates)
            roots, _ = unwind_recover(data, image)
            arrays = sorted((names.get(root["start"]), source) for root in roots
                            for source in root["sources"] if source in ("init_array", "fini_array"))
            per_target.setdefault(target, {})[(mode, extra)] = (pointers, arrays)
        for target, results in per_target.items():
            baseline = results[("none", ())]
            with self.subTest(target=target):
                self.assertEqual(baseline[1], [("ctor_a", "init_array"), ("ctor_b", "init_array"),
                                               ("dtor_a", "fini_array")])
                self.assertTrue({"f0", "f1", "hidden_a", "hidden_b"}
                                <= {name for name, _, _ in baseline[0]})
                for variant, result in results.items():
                    self.assertEqual(result, baseline, f"{target} {variant} differs from unpacked")


@unittest.skipUnless(NDK_BIN, "Android NDK LLVM tools are required")
class LldLinkPdataRealSampleTests(unittest.TestCase):
    """lld-link 真实链接的 ARM64/ARMNT/x64 PE：.pdata 起点与函数长度（打包展开数据与 .xdata
    两种编码）与 llvm-readobj --unwind 完全一致。"""

    SOURCE = (
        "typedef int (*fn_t)(int);\n"
        "__declspec(noinline) int leaf(int x){return x*3+1;}\n"
        "__declspec(noinline) int helper(int x){volatile int a[4]; a[0]=x; return a[0]+leaf(x);}\n"
        "__declspec(noinline) int big_frame(int x){volatile char b[9000]; b[x&4095]=(char)x;"
        " return b[(x*7)&4095]+helper(x);}\n"
        "__declspec(noinline) int many(int a,int b,int c,int d){int r=0;"
        " for(int i=0;i<a;i++){r+=helper(i*b)^leaf(c+d+i);} return r;}\n"
        "fn_t table[] = {leaf, helper, big_frame};\n"
        "int mainCRTStartup(void){return table[1](3) + many(2,3,4,5) + big_frame(1);}\n")

    def _build(self, target, machine, optimization):
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, directory, True)
        source = directory / "pe.c"
        source.write_text(self.SOURCE)
        obj, exe = directory / "pe.obj", directory / "pe.exe"
        for command in ([str(NDK_BIN / "clang"), f"--target={target}", optimization, "-fno-stack-protector",
                         "-mno-stack-arg-probe", "-c", str(source), "-o", str(obj)],
                        [str(NDK_BIN / "lld-link"), "/nodefaultlib", "/entry:mainCRTStartup",
                         "/subsystem:console", f"/machine:{machine}", f"/out:{exe}", str(obj)]):
            result = subprocess.run(command, capture_output=True)
            if result.returncode != 0:
                self.skipTest(f"cannot build {target}: {result.stderr.decode()[:200]}")
        return exe

    @staticmethod
    def _readobj(path):
        import re
        output = subprocess.run([str(NDK_BIN / "llvm-readobj"), "--unwind", str(path)],
                                capture_output=True, text=True, check=True).stdout
        truth, current = {}, None
        for line in output.splitlines():
            line = line.strip()
            match = re.match(r"(?:Function|StartAddress): (?:\S+ )?\(?(0x[0-9A-Fa-f]+)\)?$", line)
            if match:
                current = int(match.group(1), 16) & ~1
                truth[current] = None
                continue
            match = re.match(r"FunctionLength: (\d+)$", line)
            if match and current is not None and truth[current] is None:
                truth[current] = int(match.group(1))
            match = re.match(r"EndAddress: (?:\S+ )?\((0x[0-9A-Fa-f]+)\)$", line)
            if match and current is not None:
                truth[current] = int(match.group(1), 16) - current
        return truth

    def _check(self, target, machine, encodings):
        for optimization in ("-O2", "-O0"):
            with self.subTest(target=target, optimization=optimization):
                path = self._build(target, machine, optimization)
                data = path.read_bytes()
                roots, warnings = pe_recover(data, load_pe(data))
                pdata = [root for root in roots if "pdata" in root["sources"]]
                expected = self._readobj(path)
                self.assertGreaterEqual(len(expected), 4)
                self.assertEqual({root["start"]: root["size"] for root in pdata}, expected)
                self.assertEqual(warnings, [])
                if machine == "arm":
                    self.assertEqual({root.get("isa_mode") for root in pdata}, {"thumb"})
                found = {(root.get("evidence") or {}).get("unwind_encoding") for root in pdata}
                self.assertTrue(found <= encodings, found)

    def test_arm64_pdata_matches_llvm_readobj(self):
        self._check("aarch64-pc-windows-msvc", "arm64", {"packed", "xdata"})

    def test_armnt_pdata_matches_llvm_readobj(self):
        self._check("thumbv7-pc-windows-msvc", "arm", {"packed", "xdata"})

    def test_x64_pdata_matches_llvm_readobj(self):
        self._check("x86_64-pc-windows-msvc", "x64", {None})


if __name__ == "__main__":
    unittest.main()
