"""名字恢复：Mach-O 符号表与间接符号表、x86-64 ELF PLT、PE IAT 的链接命名。

合成样本覆盖 Loader 的边界检查与链接解析的证据规则；真实样本只做冒烟测试，
文件不存在时跳过（可用 FANGIDA_SAMPLE_DIRS 指定样本目录，os.pathsep 分隔）。
"""
from __future__ import annotations

import copy
import os
import random
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fangida.core.kkagent import PluginImpl
from fangida.core.kkagent.symbols import parse_symbols
from fangida.loaders import BinaryFormatError, load_binary
from fangida.loaders.macho import display_symbol_name, read_macho_symbols
from fangida.models import AnalysisResult, AnalysisTask
from fangida.plugins.pseudoc.linkage import resolve_linkage
from fangida.plugins.pseudoc.pipeline import populate_native_pseudoc

TEXT = 0x100000000
STUB_FLAGS = 0x80000408          # S_SYMBOL_STUBS | PURE_INSTRUCTIONS | SOME_INSTRUCTIONS
CODE_FLAGS = 0x80000400
N_SECT, N_EXT, N_UNDF, N_FUN = 0xE, 0x1, 0x0, 0x24


def _uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _section(name, segment, address, size, offset, flags, reserved1=0, reserved2=0):
    return struct.pack("<16s16sQQIIIIIIII", name.encode(), segment.encode(), address, size,
                       offset, 2, 0, 0, flags, reserved1, reserved2, 0)


def _segment(name, vmaddr, vmsize, fileoff, filesize, initprot, sections):
    return struct.pack("<II16sQQQQIIII", 0x19, 72 + 80 * len(sections), name.encode(), vmaddr,
                       vmsize, fileoff, filesize, 7, initprot, len(sections), 0) + b"".join(sections)


def build_macho(*, function_starts: bool = True, filetype: int = 2, twolevel: bool = True,
                symbols=None, indirect=(5, 6, 5, 6)) -> bytes:
    """x86-64 Mach-O：_helper/_main 在 __text，_puts/_exit 经 __stubs → __got 导入。

    0x100000400 _helper: mov eax, 1 ; ret
    0x100000410 _main:   call stub_puts ; call _helper ; xor eax, eax ; ret   (LC_MAIN 入口)
    0x100000420 __stubs: jmp [rip → __got[0]] ; jmp [rip → __got[1]]
    0x100001000 __got:   _puts, _exit
    """
    data = bytearray(0x2200)
    data[0x400:0x410] = bytes.fromhex("b801000000c3") + b"\xcc" * 10
    data[0x410:0x420] = (b"\xe8" + struct.pack("<i", 0x420 - 0x415) + b"\xe8" + struct.pack("<i", 0x400 - 0x41a)
                         + bytes.fromhex("31c0c3") + b"\xcc" * 3)
    data[0x420:0x426] = b"\xff\x25" + struct.pack("<i", 0x1000 - 0x426)
    data[0x426:0x42c] = b"\xff\x25" + struct.pack("<i", 0x1008 - 0x42c)
    if symbols is None:
        symbols = [("_main", N_FUN, 1, 0, TEXT + 0x410),                  # 调试 STAB：忽略
                   ("_helper", N_SECT, 1, 0, TEXT + 0x400),               # 局部函数
                   ("ltmp0", N_SECT, 1, 0, TEXT + 0x400),                 # 汇编器私有标签：忽略
                   ("__mh_execute_header", N_SECT | N_EXT, 1, 0, TEXT),  # 不在 __text 范围内
                   ("_main", N_SECT | N_EXT, 1, 0, TEXT + 0x410),
                   ("_puts", N_UNDF | N_EXT, 0, 0x0100, 0),
                   ("_exit", N_UNDF | N_EXT, 0, 0x0100, 0)]
    strings = bytearray(b" \0")
    records = bytearray()
    for name, n_type, n_sect, n_desc, value in symbols:
        records += struct.pack("<IBBHQ", len(strings), n_type, n_sect, n_desc, value)
        strings += name.encode() + b"\0"
    starts = _uleb(0x400) + _uleb(0x10) + b"\0" if function_starts else b""
    starts = starts.ljust(8, b"\0")
    linkedit = 0x2000
    symoff = linkedit + len(starts)
    indirectoff = symoff + len(records)
    stroff = indirectoff + 4 * len(indirect)
    blob = starts + records + struct.pack(f"<{len(indirect)}I", *indirect) + strings
    data[linkedit:linkedit + len(blob)] = blob
    dylib = b"/usr/lib/libSystem.B.dylib\0".ljust(32, b"\0")
    commands = [
        _segment("__TEXT", TEXT, 0x1000, 0, 0x1000, 5, [
            _section("__text", "__TEXT", TEXT + 0x400, 0x20, 0x400, CODE_FLAGS),
            _section("__stubs", "__TEXT", TEXT + 0x420, 12, 0x420, STUB_FLAGS, 0, 6)]),
        _segment("__DATA_CONST", TEXT + 0x1000, 0x1000, 0x1000, 0x1000, 3, [
            _section("__got", "__DATA_CONST", TEXT + 0x1000, 16, 0x1000, 0x6, 2)]),
        _segment("__LINKEDIT", TEXT + 0x2000, 0x1000, 0x2000, 0x200, 1, []),
        struct.pack("<IIIIII", 0x2, 24, symoff, len(symbols), stroff, len(strings)),
        struct.pack("<II18I", 0xB, 80, 0, 3, 3, 2, 5, 2, 0, 0, 0, 0, 0, 0, indirectoff, len(indirect), 0, 0, 0, 0),
        struct.pack("<IIIIII", 0xC, 24 + len(dylib), 24, 2, 0x10000, 0x10000) + dylib,
        struct.pack("<IIQQ", 0x80000028, 24, 0x410, 0),
    ]
    if function_starts:
        commands.append(struct.pack("<IIII", 0x26, 16, linkedit, len(starts)))
    body = b"".join(commands)
    struct.pack_into("<IIIIIIII", data, 0, 0xFEEDFACF, 0x01000007, 3, filetype, len(commands),
                     len(body), 0x00200005 | (0x80 if twolevel else 0), 0)
    data[32:32 + len(body)] = body
    return bytes(data)


def fat(thin: bytes, offset: int = 0x1000) -> bytes:
    data = bytearray(offset + len(thin))
    struct.pack_into(">II", data, 0, 0xCAFEBABE, 1)
    struct.pack_into(">IIIII", data, 8, 0x01000007, 3, offset, len(thin), 12)
    data[offset:] = thin
    return bytes(data)


def row(addr, mnemonic, *operands, size=4, kind=None, target=None, conditional=False,
        writes=None, refs=None):
    item = {"addr": addr, "size": size, "mnemonic": mnemonic, "operands": operands,
            "branch_info": {"kind": kind, "target": target, "conditional": conditional} if kind else {}}
    if writes is not None:
        item["writes"] = writes
    if refs is not None:
        item["arch_meta"] = {"memory_references": refs}
    return item


def function(*rows, name="caller", **fields):
    return {"name": name, "start": rows[0]["addr"],
            "blocks": [{"start": rows[0]["addr"], "instructions": list(rows)}],
            "cfg": {"complete": True, "frontier": []}, **fields}


def _decoder_available(architecture: str = "x86_64") -> bool:
    from fangida.processors import get_processor
    try:
        code = b"\xc0\x03\x5f\xd6" if architecture == "arm64" else b"\xc3"   # ret
        rows, _warnings = get_processor(architecture).decode_bytes(code, 0x1000, max_instructions=1)
    except Exception:
        return False
    return bool(rows)


def build_macho32(*, filetype: int = 2) -> bytes:
    """i386 Mach-O（nlist 为 12 字节）：两个 __text 函数符号，无 LC_FUNCTION_STARTS。"""
    data = bytearray(0x400)
    data[0x100:0x108] = bytes.fromhex("b801000000c3cccc")
    data[0x108:0x10a] = bytes.fromhex("c3cc")
    strings = b" \0_first\0_second\0"
    records = (struct.pack("<IBBHI", 2, N_SECT | N_EXT, 1, 0, 0x1100) +
               struct.pack("<IBBHI", 9, N_SECT | N_EXT, 1, 0, 0x1108))
    data[0x200:0x200 + len(records)] = records
    data[0x280:0x280 + len(strings)] = strings
    segment = struct.pack("<II16sIIIIIIII", 1, 56 + 68, b"__TEXT", 0x1000, 0x1000, 0, 0x400, 7, 5, 1, 0)
    section = struct.pack("<16s16sIIIIIIIII", b"__text", b"__TEXT", 0x1100, 0x10, 0x100, 2, 0, 0,
                          CODE_FLAGS, 0, 0)
    symtab = struct.pack("<IIIIII", 0x2, 24, 0x200, 2, 0x280, len(strings))
    body = segment + section + symtab
    struct.pack_into("<IIIIIII", data, 0, 0xFEEDFACE, 7, 3, filetype, 2, len(body), 0)
    data[28:28 + len(body)] = body
    return bytes(data)


class MachOSymbolTableTests(unittest.TestCase):
    def test_32bit_nlist_records(self):
        image = load_binary(build_macho32(), "macho")
        self.assertEqual([(f["name"], f["start"], f["size"]) for f in image.functions],
                         [("_first", 0x1100, None), ("_second", 0x1108, None)])
        image = load_binary(build_macho32(filetype=1), "macho")
        self.assertEqual([f["size"] for f in image.functions], [8, 8])
        _imports, exports, _warnings = parse_symbols(build_macho32(filetype=1), image)
        self.assertEqual([e["name"] for e in exports], ["_first", "_second"])

    def test_symtab_functions_named_sized_and_entry_first(self):
        image = load_binary(build_macho(), "macho")
        self.assertEqual([(f["name"], f["start"], f["size"], f["source"]) for f in image.functions],
                         [("_main", TEXT + 0x410, 0x10, "symtab"), ("_helper", TEXT + 0x400, 0x10, "symtab")])
        self.assertEqual([f["display_name"] for f in image.functions], ["main", "helper"])
        self.assertEqual({f["size_source"] for f in image.functions}, {"function_starts"})
        self.assertTrue(image.functions[1]["local"])
        self.assertEqual(image.functions[0]["blocks"], [])
        stubs = next(s for s in image.sections if s["name"] == "__stubs")
        got = next(s for s in image.sections if s["name"] == "__got")
        self.assertEqual((stubs["indirect_symbol_index"], stubs["indirect_entry_size"]), (0, 6))
        self.assertEqual((got["indirect_symbol_index"], got["indirect_entry_size"]), (2, 8))
        self.assertEqual(image.warnings, [])

    def test_size_is_unknown_without_function_starts_except_in_object_files(self):
        image = load_binary(build_macho(function_starts=False), "macho")
        self.assertEqual([f["size"] for f in image.functions], [None, None])
        image = load_binary(build_macho(function_starts=False, filetype=1), "macho")
        self.assertEqual({f["name"]: (f["size"], f["size_source"]) for f in image.functions},
                         {"_main": (0x10, "next_symbol"), "_helper": (0x10, "next_symbol")})

    def test_imports_map_stubs_and_pointer_slots_through_indirect_table(self):
        data = build_macho()
        image = load_binary(data, "macho")
        imports, exports, warnings = parse_symbols(data, image)
        self.assertEqual(warnings, [])
        self.assertEqual([(i["name"], i["display_name"], i["stub_address"], i["address"], i["library"], i["kind"])
                          for i in imports],
                         [("_puts", "puts", TEXT + 0x420, TEXT + 0x1000, "/usr/lib/libSystem.B.dylib", "function"),
                          ("_exit", "exit", TEXT + 0x426, TEXT + 0x1008, "/usr/lib/libSystem.B.dylib", "function")])
        self.assertEqual({(e["name"], e["kind"]) for e in exports},
                         {("_main", "function"), ("__mh_execute_header", "object")})
        table = read_macho_symbols(data)
        self.assertEqual([(item["address"], item["name"], item["kind"]) for item in table["indirect"]],
                         [(TEXT + 0x420, "_puts", "stub"), (TEXT + 0x426, "_exit", "stub"),
                          (TEXT + 0x1000, "_puts", "non_lazy_pointer"), (TEXT + 0x1008, "_exit", "non_lazy_pointer")])

    def test_flat_namespace_has_no_library_and_local_indirect_entries_are_skipped(self):
        data = build_macho(twolevel=False, indirect=(0x80000000, 6, 0x40000000, 6))
        imports, _exports, _warnings = parse_symbols(data, load_binary(data, "macho"))
        self.assertEqual([(i["name"], i["stub_addresses"], i["pointer_addresses"], i["library"]) for i in imports],
                         [("_puts", [], [], None), ("_exit", [TEXT + 0x426], [TEXT + 0x1008], None)])

    def test_fat_slice_offsets_and_symbols_match_thin_image(self):
        thin = build_macho()
        image = load_binary(fat(thin), "macho")
        self.assertEqual(image.fat_slice_offset, 0x1000)
        self.assertEqual([f["name"] for f in image.functions], ["_main", "_helper"])
        self.assertEqual(image.entry_offset, 0x1410)
        imports, _exports, warnings = parse_symbols(fat(thin), image)
        self.assertEqual(warnings, [])
        self.assertEqual([i["stub_address"] for i in imports], [TEXT + 0x420, TEXT + 0x426])

    def test_display_name_strips_exactly_one_leading_underscore(self):
        self.assertEqual([display_symbol_name(n) for n in ("_main", "__Z3foov", "-[A b]", "_", "plain")],
                         ["main", "_Z3foov", "-[A b]", "_", "plain"])

    def test_malformed_symbol_metadata_only_warns(self):
        base = bytearray(build_macho())
        # LC_SYMTAB 在第 4 条命令：定位后把各字段改为越界值。
        cursor = 32
        for _ in range(3):
            cursor += struct.unpack_from("<I", base, cursor + 4)[0]
        cases = {"string table": (cursor + 16, 0xFFFFFF00), "symbols": (cursor + 8, 0xFFFFFF00),
                 "count": (cursor + 12, 0x7FFFFFFF)}
        for label, (offset, value) in cases.items():
            with self.subTest(label):
                data = bytearray(base)
                struct.pack_into("<I", data, offset, value)
                image = load_binary(bytes(data), "macho")
                self.assertTrue(image.warnings)
                parse_symbols(bytes(data), image)
        data = bytearray(base)
        dysymtab = cursor + 24
        struct.pack_into("<I", data, dysymtab + 8 + 12 * 4, 0xFFFFFFF0)  # indirectsymoff
        image = load_binary(bytes(data), "macho")
        self.assertIn("Mach-O indirect symbol table exceeds scan budget", image.warnings)
        self.assertEqual([f["name"] for f in image.functions], ["_main", "_helper"])

    def test_bounded_mutations_never_raise_other_than_format_error(self):
        base = build_macho()
        generator = random.Random(20261001)
        for _ in range(400):
            data = bytearray(base)
            for _ in range(generator.randint(1, 6)):
                position = generator.choice((generator.randrange(32, 0x300), generator.randrange(0x2000, 0x20C0)))
                data[position] = generator.randrange(256)
            try:
                image = load_binary(bytes(data), "macho")
                parse_symbols(bytes(data), image)
            except BinaryFormatError:
                pass
        for length in (0, 4, 31, 64, 0x400, 0x2010, 0x2060):
            try:
                load_binary(base[:length], "macho")
                read_macho_symbols(base[:length])
            except BinaryFormatError:
                pass

    @unittest.skipUnless(_decoder_available(), "需要 x86-64 指令解码器")
    def test_analysis_names_entry_function_and_import_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "named"
            path.write_bytes(build_macho())
            result = PluginImpl().analyze(AnalysisTask(str(path), "macho"))
        names = [f["name"] for f in result.functions]
        self.assertIn("_main", names)
        self.assertFalse(any(name.startswith("entry_window") for name in names))
        self.assertEqual(result.stats["imports"], 2)
        main = next(f for f in result.functions if f["name"] == "_main")
        # 伪 C 使用源码级名字（display_name：去掉 Mach-O 前导下划线），原始符号仍在 name/证据中。
        self.assertRegex(main["pseudoc"], r"\bputs\(")
        self.assertRegex(main["pseudoc"], r"\bhelper\(")
        self.assertNotIn("_puts(", main["pseudoc"])
        self.assertIn("int32_t main(", main["pseudoc"])
        self.assertIn("（_main）", main["pseudoc"].splitlines()[0])
        linkage = {item["target"]: item for item in result.metadata["pseudoc_linkage"]}
        self.assertEqual(linkage[TEXT + 0x420]["name"], "_puts")
        self.assertEqual(linkage[TEXT + 0x420]["evidence"], "macho_indirect_symbol_table_and_completed_stub_snapshot")


def macho_result(stub_rows, *, architecture="x86_64", calls=(TEXT + 0x420,)):
    caller = function(*[row(TEXT + 0x410 + 4 * i, "bl" if architecture == "arm64" else "call", hex(target),
                            kind="call", target=target) for i, target in enumerate(calls)])
    imports = [{"name": "_puts", "display_name": "puts", "library": "libSystem", "source": "macho-import",
                "stub_addresses": [TEXT + 0x420], "pointer_addresses": [TEXT + 0x1000]},
               {"name": "_exit", "display_name": "exit", "library": "libSystem", "source": "macho-import",
                "stub_addresses": [TEXT + 0x430], "pointer_addresses": [TEXT + 0x1008]}]
    functions = [caller] + ([function(*stub_rows, name="sub_stub")] if stub_rows else [])
    return AnalysisResult("fixture", "macho", "kkagent", "partial", functions=functions,
                          imports=imports, metadata={"architecture": architecture})


class MachOStubLinkageTests(unittest.TestCase):
    def test_x86_64_stub_is_verified_against_pointer_slot(self):
        stub = [row(TEXT + 0x420, "jmp", "qword ptr [rip + 0xbda]", size=6, kind="jump", refs=[TEXT + 0x1000])]
        result = macho_result(stub)
        before = copy.deepcopy(result)
        with patch("fangida.processors.get_processor", side_effect=AssertionError("不得重新解码")):
            evidence = resolve_linkage(result)
        self.assertEqual(result, before)
        self.assertEqual(evidence[TEXT + 0x420]["name"], "_puts")
        self.assertEqual(evidence[TEXT + 0x420]["display_name"], "puts")
        self.assertEqual(evidence[TEXT + 0x420]["slot_address"], TEXT + 0x1000)
        self.assertEqual(evidence[TEXT + 0x420]["target_kind"], "linkage_thunk")
        self.assertNotIn(TEXT + 0x430, evidence)  # 未被调用的桩不输出

    def test_stub_contradicting_its_slot_or_decoder_reference_is_rejected(self):
        wrong_slot = [row(TEXT + 0x420, "jmp", "qword ptr [rip + 0xbe2]", size=6, kind="jump")]
        self.assertEqual(resolve_linkage(macho_result(wrong_slot)), {})
        mismatch = [row(TEXT + 0x420, "jmp", "qword ptr [rip + 0xbda]", size=6, kind="jump", refs=[TEXT + 0x1008])]
        evidence = resolve_linkage(macho_result(mismatch))
        # 引用不一致时快照形状不成立，只剩容器声明，证据级别随之降低。
        self.assertEqual(evidence[TEXT + 0x420]["evidence"], "macho_indirect_symbol_table")
        self.assertIsNone(evidence[TEXT + 0x420]["slot_address"])

    def test_declared_stub_without_snapshot_rows_uses_indirect_table(self):
        evidence = resolve_linkage(macho_result([]))
        self.assertEqual(evidence[TEXT + 0x420]["name"], "_puts")
        self.assertEqual(evidence[TEXT + 0x420]["evidence"], "macho_indirect_symbol_table")

    def test_conflicting_stub_declarations_or_decodes_are_unresolved(self):
        result = macho_result([])
        result.imports.append({"name": "_other", "source": "macho-import", "stub_addresses": [TEXT + 0x420]})
        self.assertEqual(resolve_linkage(result), {})
        stub = [row(TEXT + 0x420, "jmp", "qword ptr [rip + 0xbda]", size=6, kind="jump")]
        result = macho_result(stub)
        result.metadata["full_disassembly"] = [row(TEXT + 0x420, "nop", size=1)]
        self.assertEqual(resolve_linkage(result), {})

    def test_arm64_and_arm64e_stub_shapes(self):
        plain = [row(TEXT + 0x420, "adrp", "x16", "#0x100001000"), row(TEXT + 0x424, "ldr", "x16", "[x16]"),
                 row(TEXT + 0x428, "br", "x16", kind="jump")]
        evidence = resolve_linkage(macho_result(plain, architecture="arm64"))
        self.assertEqual(evidence[TEXT + 0x420]["slot_address"], TEXT + 0x1000)
        self.assertTrue(evidence[TEXT + 0x420]["evidence"].endswith("stub_snapshot"))
        auth = [row(TEXT + 0x420, "adrp", "x17", "#0x100001000"), row(TEXT + 0x424, "add", "x17", "x17", "#0x0"),
                row(TEXT + 0x428, "ldr", "x16", "[x17]"), row(TEXT + 0x42c, "braa", "x16", "x17", kind="jump")]
        evidence = resolve_linkage(macho_result(auth, architecture="arm64"))
        self.assertEqual(evidence[TEXT + 0x420]["slot_address"], TEXT + 0x1000)
        wrong = copy.deepcopy(auth)
        wrong[1]["operands"] = ("x17", "x17", "#0x8")   # 指向 _exit 的槽位
        self.assertEqual(resolve_linkage(macho_result(wrong, architecture="arm64")), {})

    def test_cancellation_returns_no_partial_names(self):
        self.assertEqual(resolve_linkage(macho_result([]), is_cancelled=lambda: True), {})
        calls = []

        def cancel_on_second_check():
            calls.append(None)
            return len(calls) > 1

        stub = [row(TEXT + 0x420, "jmp", "qword ptr [rip + 0xbda]", size=6, kind="jump")]
        self.assertEqual(resolve_linkage(macho_result(stub), is_cancelled=cancel_on_second_check), {})
        self.assertGreater(len(calls), 1)

    def test_pipeline_uses_linkage_name_for_stub_calls(self):
        stub = [row(TEXT + 0x420, "jmp", "qword ptr [rip + 0xbda]", size=6, kind="jump")]
        result = macho_result(stub)
        populate_native_pseudoc(result)
        self.assertRegex(result.functions[0]["pseudoc"], r"\bputs\(")
        self.assertNotIn("_puts(", result.functions[0]["pseudoc"])
        self.assertEqual(result.metadata["pseudoc_linkage"][0]["name"], "_puts")


def elf_x64_result(plt_rows, *, relocations=None, caller_rows=None):
    caller_rows = caller_rows or [row(0x1100, "call", "0x1030", size=5, kind="call", target=0x1030),
                                  row(0x1105, "call", "qword ptr [rip + 0x2ee5]", size=6, kind="call"),
                                  row(0x110b, "ret", size=1, kind="return")]
    if relocations is None:
        relocations = [{"type": 7, "address": 0x4018, "symbol_name": "puts", "symbol_value": 0},
                       {"type": 6, "address": 0x3ff0, "symbol_name": "__libc_start_main", "symbol_value": 0}]
    functions = [function(*caller_rows)] + ([function(*plt_rows, name="sub_1030")] if plt_rows else [])
    return AnalysisResult("fixture", "elf", "kkagent", "partial", functions=functions, metadata={
        "architecture": "x86_64", "dynamic_relocations": relocations,
        "sections": [{"name": ".plt", "address": 0x1020, "size": 0x40},
                     {"name": ".text", "address": 0x1100, "size": 0x100}]})


LAZY_PLT = [row(0x1030, "jmp", "qword ptr [rip + 0x2fe2]", size=6, kind="jump", refs=[0x4018]),
            row(0x1036, "push", "0", size=5), row(0x103b, "jmp", "0x1020", size=5, kind="jump", target=0x1020)]


class ElfX86PltLinkageTests(unittest.TestCase):
    def test_lazy_plt_entry_and_got_call_site(self):
        result = elf_x64_result(LAZY_PLT)
        before = copy.deepcopy(result)
        with patch("fangida.processors.get_processor", side_effect=AssertionError("不得重新解码")):
            evidence = resolve_linkage(result)
        self.assertEqual(result, before)
        self.assertEqual(evidence[0x1030]["name"], "puts")
        self.assertEqual(evidence[0x1030]["got_address"], 0x4018)
        self.assertEqual(evidence[0x1030]["evidence"], "elf_relocation_and_completed_thunk_snapshot")
        slot = evidence[0x3ff0]
        self.assertEqual((slot["name"], slot["target_kind"], slot["call_sites"]),
                         ("__libc_start_main", "import_pointer_slot", [0x1105]))

    def test_ibt_plt_sec_entry(self):
        rows = [row(0x1030, "endbr64"), row(0x1034, "bnd jmp", "qword ptr [rip + 0x2fdd]", size=7, kind="jump")]
        self.assertEqual(resolve_linkage(elf_x64_result(rows))[0x1030]["name"], "puts")

    def test_wrong_type_conflict_or_reference_mismatch_is_not_guessed(self):
        self.assertNotIn(0x1030, resolve_linkage(elf_x64_result(LAZY_PLT, relocations=[
            {"type": 1, "address": 0x4018, "symbol_name": "puts"}])))
        self.assertNotIn(0x1030, resolve_linkage(elf_x64_result(LAZY_PLT, relocations=[
            {"type": 7, "address": 0x4018, "symbol_name": "puts"},
            {"type": 7, "address": 0x4018, "symbol_name": "other"}])))
        mismatch = copy.deepcopy(LAZY_PLT)
        mismatch[0]["arch_meta"]["memory_references"] = [0x4020]
        self.assertNotIn(0x1030, resolve_linkage(elf_x64_result(mismatch)))
        not_jump = copy.deepcopy(LAZY_PLT)
        not_jump[0]["mnemonic"] = "call"
        self.assertNotIn(0x1030, resolve_linkage(elf_x64_result(not_jump)))

    def test_intra_function_branches_do_not_consume_candidate_budget(self):
        branches = [row(0x1100 + 2 * i, "jne", hex(0x1100), size=2, kind="jump", target=0x1100, conditional=True)
                    for i in range(8)]
        caller = branches + [row(0x1110, "call", "0x1030", size=5, kind="call", target=0x1030)]
        with patch("fangida.plugins.pseudoc.linkage.MAX_LINKAGE_TARGETS", 1):
            self.assertIn(0x1030, resolve_linkage(elf_x64_result(LAZY_PLT, caller_rows=caller)))

    def test_cancellation_and_row_budget(self):
        self.assertEqual(resolve_linkage(elf_x64_result(LAZY_PLT), is_cancelled=lambda: True), {})
        with patch("fangida.plugins.pseudoc.linkage.MAX_LINKAGE_ROWS", 1):
            self.assertNotIn(0x1030, resolve_linkage(elf_x64_result(LAZY_PLT)))

    def test_pipeline_names_plt_call(self):
        result = elf_x64_result(LAZY_PLT)
        populate_native_pseudoc(result)
        self.assertIn("puts(", result.functions[0]["pseudoc"])


def pe_result(caller_rows, extra=(), architecture="x86_64"):
    imports = [{"name": "ExitProcess", "library": "KERNEL32.dll", "address": 0x140003000, "source": "pe-import"},
               {"name": "#23", "ordinal": 23, "library": "WS2_32.dll", "address": 0x140003008, "source": "pe-import"}]
    functions = [function(*caller_rows)] + [function(*rows, name=f"sub_{rows[0]['addr']:x}") for rows in extra]
    return AnalysisResult("fixture", "pe", "kkagent", "partial", functions=functions, imports=imports,
                          metadata={"architecture": architecture})


class PeImportLinkageTests(unittest.TestCase):
    def test_x64_call_iat_and_jmp_iat_thunk(self):
        caller = [row(0x140001000, "call", "qword ptr [rip + 0x1ffa]", size=6, kind="call"),
                  row(0x140001006, "call", "0x140001100", size=5, kind="call", target=0x140001100),
                  row(0x14000100b, "ret", size=1, kind="return")]
        thunk = [row(0x140001100, "jmp", "qword ptr [rip + 0x1f02]", size=6, kind="jump")]
        evidence = resolve_linkage(pe_result(caller, [thunk]))
        self.assertEqual(evidence[0x140001100]["name"], "WS2_32_ordinal_23")
        self.assertEqual(evidence[0x140001100]["symbol_name"], "#23")
        self.assertEqual((evidence[0x140003000]["name"], evidence[0x140003000]["call_sites"]),
                         ("ExitProcess", [0x140001000]))
        self.assertNotIn(0x140003008, evidence)  # thunk 自身的 jmp 不重复记为调用点

    def test_x86_absolute_iat_call(self):
        caller = [row(0x401000, "call", "dword ptr [0x403000]", size=6, kind="call")]
        result = AnalysisResult("fixture", "pe", "kkagent", "partial", functions=[function(*caller)],
                                imports=[{"name": "ExitProcess", "address": 0x403000, "source": "pe-import"}],
                                metadata={"architecture": "x86"})
        self.assertEqual(resolve_linkage(result)[0x403000]["call_sites"], [0x401000])

    def test_arm64_iat_call_site_and_thunk(self):
        caller = [row(0x140001000, "adrp", "x8", "#0x140003000", writes=["x8"]),
                  row(0x140001004, "ldr", "x8", "[x8]", writes=["x8"]),
                  row(0x140001008, "mov", "x0", "#0", writes=["x0"]),
                  row(0x14000100c, "blr", "x8", kind="call", writes=["lr"]),
                  row(0x140001010, "bl", "#0x140001100", kind="call", target=0x140001100, writes=["lr"])]
        thunk = [row(0x140001100, "adrp", "x16", "#0x140003000"), row(0x140001104, "ldr", "x16", "[x16, #8]"),
                 row(0x140001108, "br", "x16", kind="jump")]
        evidence = resolve_linkage(pe_result(caller, [thunk], architecture="arm64"))
        self.assertEqual(evidence[0x140003000]["call_sites"], [0x14000100c])
        self.assertEqual(evidence[0x140001100]["name"], "WS2_32_ordinal_23")

    def test_arm64_clobbered_or_called_register_is_not_traced(self):
        for middle in (row(0x140001008, "mov", "x8", "x0", writes=["x8"]),
                       row(0x140001008, "bl", "#0x140002000", kind="call", target=0x140002000, writes=["lr"])):
            caller = [row(0x140001000, "adrp", "x8", "#0x140003000", writes=["x8"]),
                      row(0x140001004, "ldr", "x8", "[x8]", writes=["x8"]), middle,
                      row(0x14000100c, "blr", "x8", kind="call", writes=["lr"])]
            self.assertNotIn(0x140003000, resolve_linkage(pe_result(caller, architecture="arm64")))

    def test_unknown_formats_are_unresolved(self):
        result = AnalysisResult("fixture", "pe", "kkagent", "partial", functions=[], metadata={"architecture": "mips"})
        self.assertEqual(resolve_linkage(result), {})


def _sample(*names: str) -> Path | None:
    roots = [Path(item) for item in os.environ.get("FANGIDA_SAMPLE_DIRS", "").split(os.pathsep) if item]
    roots += [Path("/private/tmp/claude-501/-Users-meow233-Desktop-ai-fangida-0-4-0/"
                   "70e0294c-cd71-4a61-b306-2e9f8aacfda4/scratchpad") / part
              for part in ("pc", "r2-loaders-work/samples", "")]
    for root in roots:
        for name in names:
            if (root / name).is_file():
                return root / name
    return None


class RealSampleSmokeTests(unittest.TestCase):
    def _analyze(self, path):
        from fangida.loaders import identify_file
        return PluginImpl().analyze(AnalysisTask(str(path), identify_file(path)[0]))

    @unittest.skipUnless(_sample("demo_O2") and _decoder_available("arm64"), "需要 demo_O2 样本与解码器")
    def test_demo_o2_main_and_imports_are_named(self):
        result = self._analyze(_sample("demo_O2"))
        names = {f["name"] for f in result.functions}
        self.assertTrue({"_main", "_check_password", "_total_qty", "_classify"} <= names)
        main = next(f for f in result.functions if f["name"] == "_main")
        for callee in ("printf", "puts", "strlen", "malloc", "free"):
            self.assertRegex(main["pseudoc"], r"\b" + callee + r"\(")

    @unittest.skipUnless(_sample("demo_x64") and _decoder_available(), "需要 demo_x64 样本与解码器")
    def test_demo_x64_names(self):
        result = self._analyze(_sample("demo_x64"))
        self.assertEqual(result.functions[0]["name"], "_main")
        self.assertGreaterEqual(len(result.metadata.get("pseudoc_linkage", [])), 5)

    @unittest.skipUnless(_sample("zsh.x86_64"), "需要 zsh.x86_64 样本")
    def test_zsh_symbols_and_imports(self):
        data = _sample("zsh.x86_64").read_bytes()
        image = load_binary(data, "macho")
        self.assertGreater(len(image.functions), 500)
        self.assertEqual(image.functions[0]["name"], "_main")
        imports, exports, _warnings = parse_symbols(data, image)
        self.assertGreater(sum(1 for item in imports if item["stub_address"]), 100)
        self.assertGreater(len(exports), 500)

    @unittest.skipUnless(_sample("t64.exe") and _decoder_available(), "需要 t64.exe 样本与解码器")
    def test_pe_iat_call_sites(self):
        result = self._analyze(_sample("t64.exe"))
        slots = [item for item in result.metadata.get("pseudoc_linkage", [])
                 if item.get("target_kind") == "import_pointer_slot"]
        self.assertTrue(slots)
        self.assertTrue(all(item["call_sites"] for item in slots))

    @unittest.skipUnless(_sample("demo_win.obj"), "需要 demo_win.obj 样本")
    def test_coff_object_does_not_crash(self):
        result = self._analyze(_sample("demo_win.obj"))
        self.assertIn(result.status, {"partial", "ok", "error"})
        self.assertNotEqual(result.status, "error")


if __name__ == "__main__":
    unittest.main()
