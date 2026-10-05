"""Mach-O / PE 可执行代码区域判定：节属性、映射大小与各消费者看到的区域。"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest

from fangida.core.kkagent.semantic import _regions as semantic_regions
from fangida.core.kkagent.translator import _entry_bytes
from fangida.loaders import identify_file, load_binary
from fangida.processors.full_decode import _regions as full_regions
from fangida.xrefs import mapped_data_ranges

PURE, SOME = 0x80000000, 0x00000400
CODE = PURE | SOME
TEXT_BASE = {64: 0x100000000, 32: 0x1000}
# 这些名字在真实 Mach-O 中只承载数据（字面量、指针、展开/异常表、Info.plist 等）。
MACHO_DATA_SECTIONS = {"__const", "__cstring", "__unwind_info", "__eh_frame", "__gcc_except_tab",
                       "__info_plist", "__objc_methname", "__init_offsets", "__got", "__auth_got",
                       "__mod_init_func", "__la_symbol_ptr", "__data", "__bss", "__common"}
LEGACY_MACHO_FIELDS = {"name", "address", "offset", "size", "type", "section_flags",
                       "file_backed", "file_size", "executable"}
LEGACY_PE_FIELDS = {"name", "address", "offset", "size", "virtual_size", "type",
                    "file_backed", "file_size", "executable"}


def _macho(segments, *, bits: int = 64, entry: int | None = None, size: int = 0x2000,
           filetype: int = 2, extra_commands: tuple[bytes, ...] = ()) -> bytearray:
    """构造薄 Mach-O：segments 为 (段名, vmaddr, vmsize, fileoff, filesize, initprot, 节列表)，

    节为 (节名, 地址, 大小, 文件偏移, flags)；extra_commands 为追加在段命令之后的原始 load command。
    """
    header_size = 32 if bits == 64 else 28
    commands = bytearray()
    for segname, vmaddr, vmsize, fileoff, filesize, initprot, sections in segments:
        if bits == 64:
            commands += struct.pack("<II16sQQQQIIII", 0x19, 72 + 80 * len(sections), segname.encode(),
                                    vmaddr, vmsize, fileoff, filesize, 7, initprot, len(sections), 0)
        else:
            commands += struct.pack("<II16sIIIIIIII", 1, 56 + 68 * len(sections), segname.encode(),
                                    vmaddr, vmsize, fileoff, filesize, 7, initprot, len(sections), 0)
        for name, address, length, offset, flags in sections:
            values = (name.encode(), segname.encode(), address, length, offset, 2, 0, 0, flags, 0, 0)
            commands += (struct.pack("<16s16sQQIIIIIIII", *values, 0) if bits == 64
                         else struct.pack("<16s16sIIIIIIIII", *values))
    for command in extra_commands:
        commands += command
    ncmds = len(segments) + len(extra_commands)
    if entry is not None:
        commands += struct.pack("<IIQQ", 0x80000028, 24, entry, 0)
        ncmds += 1
    data = bytearray(size)
    if bits == 64:
        struct.pack_into("<IIIIIIII", data, 0, 0xFEEDFACF, 0x01000007, 3, filetype, ncmds,
                         len(commands), 0, 0)
    else:
        struct.pack_into("<IIIIIII", data, 0, 0xFEEDFACE, 7, 3, filetype, ncmds, len(commands), 0)
    data[header_size:header_size + len(commands)] = commands
    return data


def _typical_macho(bits: int = 64) -> bytes:
    """r-x __TEXT 同时含代码节与各种数据节，rw- __DATA 含指针、带指令属性的数据与 zerofill。"""
    base = TEXT_BASE[bits]
    text = [("__text", 0x800, 0x10, CODE), ("__stubs", 0x810, 0xC, CODE | 0x8),
            ("__stub_helper", 0x81C, 0x14, CODE), ("__const", 0x830, 0x20, 0),
            ("__cstring", 0x850, 0x10, 0x2), ("__unwind_info", 0x860, 0x10, 0),
            ("__eh_frame", 0x870, 0x10, 0x6800000B), ("__gcc_except_tab", 0x880, 0x8, 0),
            ("__init_offsets", 0x888, 0x8, 0x16)]
    data_sections = [("__mod_init_func", 0x1000, 8, 0x9), ("__got", 0x1008, 8, 0x6),
                     ("__data", 0x1010, 0x10, SOME)]
    segments = [
        ("__TEXT", base, 0x1000, 0, 0x1000, 5,
         [(name, base + offset, length, offset, flags) for name, offset, length, flags in text]),
        ("__DATA", base + 0x1000, 0x1000, 0x1000, 0x100, 3,
         [(name, base + offset, length, offset, flags) for name, offset, length, flags in data_sections]
         + [("__bss", base + 0x1100, 0x100, 0, 0x1)]),
    ]
    data = _macho(segments, bits=bits, entry=0x800)
    data[0x800:0x810] = b"\x90" * 15 + b"\xc3"
    data[0x830:0x850] = b"\x48\x8b\x05\x00\x00\x00\x00" * 4 + b"\0" * 4  # 能被解码的数据字节
    data[0x850:0x860] = b"not code at all\0"
    return bytes(data)


def _fileset_entry(vmaddr: int, fileoff: int, entry_id: str) -> bytes:
    """LC_FILESET_ENTRY（0x80000035）：内核集合中一个内嵌镜像的地址、文件偏移与名字。"""
    name = entry_id.encode() + b"\0"
    length = (32 + len(name) + 7) & ~7
    return struct.pack("<IIQQII", 0x80000035, length, vmaddr, fileoff, 32, 0) + name.ljust(length - 32, b"\0")


def _fat(thin: bytes, offset: int = 0x1000) -> bytes:
    data = bytearray(offset + len(thin))
    struct.pack_into(">II", data, 0, 0xCAFEBABE, 1)
    struct.pack_into(">IIIII", data, 8, 0x01000007, 3, offset, len(thin), 12)
    data[offset:] = thin
    return bytes(data)


def _pe(sections, *, entry_rva: int = 0x1000, bits: int = 64, size: int = 0x1000) -> bytearray:
    """节为 (名, VirtualSize, RVA, SizeOfRawData, PointerToRawData, Characteristics)。"""
    data = bytearray(size)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    optsize = 0xF0 if bits == 64 else 0xE0
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664 if bits == 64 else 0x14C, len(sections),
                     0, 0, 0, optsize, 0x22)
    struct.pack_into("<H", data, 0x98, 0x20B if bits == 64 else 0x10B)
    struct.pack_into("<I", data, 0x98 + 16, entry_rva)
    if bits == 64:
        struct.pack_into("<Q", data, 0x98 + 24, 0x140000000)
    else:
        struct.pack_into("<I", data, 0x98 + 28, 0x400000)
    for index, (name, vsize, rva, rawsize, rawoff, flags) in enumerate(sections):
        struct.pack_into("<8sIIIIIIHHI", data, 0x98 + optsize + index * 40, name.encode(),
                         vsize, rva, rawsize, rawoff, 0, 0, 0, 0, flags)
    return data


PE_SECTIONS = [
    (".text", 0x30, 0x1000, 0x200, 0x400, 0x60000020),   # VirtualSize < SizeOfRawData
    (".ztext", 0, 0x2000, 0x200, 0x600, 0x60000020),     # VirtualSize 为 0：回退到原始大小
    (".rdata", 0x100, 0x3000, 0x200, 0x800, 0x40000040),  # 无执行权限
    (".code", 0x40, 0x4000, 0x200, 0xA00, 0x40000020),   # 只有 CNT_CODE：不可执行
    (".xdata", 0x40, 0x5000, 0x200, 0xC00, 0xE0000040),  # 只有 MEM_EXECUTE
    (".bss", 0x100, 0x6000, 0, 0, 0xC0000080),           # 无文件内容
    (".data", 0x400, 0x7000, 0x200, 0xE00, 0xC0000040),  # VirtualSize > SizeOfRawData
]


def _typical_pe(entry_rva: int = 0x1020, bits: int = 64) -> bytes:
    data = _pe(PE_SECTIONS, entry_rva=entry_rva, bits=bits)
    data[0x400:0x430] = b"\x90" * 0x2F + b"\xc3"
    data[0x430:0x600] = b"\xcc" * 0x1D0  # 文件对齐填充：若被当成代码会解码成 int3
    return bytes(data)


class MachOCodeRegionTests(unittest.TestCase):
    def test_code_sections_follow_instruction_attributes_not_segment_permission(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                image = load_binary(_typical_macho(bits), "macho")
                by_name = {section["name"]: section for section in image.sections}
                self.assertEqual([section["name"] for section in image.sections if section["executable"]],
                                 ["__text", "__stubs", "__stub_helper"])
                for name in ("__const", "__cstring", "__unwind_info", "__eh_frame",
                             "__gcc_except_tab", "__init_offsets"):
                    self.assertFalse(by_name[name]["executable"], name)
                    self.assertTrue(by_name[name]["segment_executable"], name)
                    self.assertTrue(by_name[name]["file_backed"], name)
                # 不可执行段中的 SOME_INSTRUCTIONS 不授予执行权限；指针节与 zerofill 也不是代码。
                for name in ("__mod_init_func", "__got", "__data", "__bss"):
                    self.assertFalse(by_name[name]["executable"], name)
                    self.assertFalse(by_name[name]["segment_executable"], name)
                self.assertFalse(by_name["__bss"]["file_backed"])
                stubs = by_name["__stubs"]
                self.assertEqual((stubs["segment"], stubs["section_type"], stubs["section_attributes"],
                                  stubs["section_flags"]), ("__TEXT", 0x8, CODE, CODE | 0x8))
                self.assertEqual((by_name["__eh_frame"]["section_type"],
                                  by_name["__eh_frame"]["section_attributes"]), (0xB, 0x68000000))
                self.assertEqual(by_name["__got"]["segment"], "__DATA")
                for section in image.sections:
                    self.assertLessEqual(LEGACY_MACHO_FIELDS, set(section), section["name"])

    def test_data_only_section_types_ignore_instruction_attributes(self):
        base = TEXT_BASE[64]
        cases = {0x2: False, 0x5: False, 0x6: False, 0x9: False, 0x16: False,  # 字面量/指针/偏移
                 0x0: True, 0x8: True, 0xB: True, 0x30: True}                  # 可含代码与未知类型
        sections = [(f"__s{index}", base + 0x800 + index * 0x10, 0x10, 0x800 + index * 0x10,
                     PURE | section_type) for index, section_type in enumerate(cases)]
        sections.append(("__plain", base + 0x900, 0x10, 0x900, 0x8))  # 无属性的 S_SYMBOL_STUBS
        data = _macho([("__TEXT", base, 0x1000, 0, 0x1000, 5, sections)])
        image = load_binary(bytes(data), "macho")
        expected = list(cases.values()) + [True]
        self.assertEqual([section["executable"] for section in image.sections], expected)

    def test_code_attributes_without_file_bytes_are_not_regions(self):
        base = TEXT_BASE[64]
        data = _macho([("__TEXT", base, 0x2000, 0, 0x1000, 5, [
            ("__text", base + 0x800, 0x10, 0x800, CODE),
            ("__zcode", base + 0x1000, 0x100, 0, CODE | 0x1),        # zerofill
            ("__outside", base + 0x1800, 0x10, 0x1800, CODE)])])     # 偏移在段文件内容之外
        image = load_binary(bytes(data), "macho")
        self.assertEqual([(section["name"], section["file_backed"], section["executable"])
                          for section in image.sections],
                         [("__text", True, True), ("__zcode", False, False),
                          ("__outside", False, False)])
        self.assertEqual([region.offset for region in semantic_regions(image, bytes(data))], [0x800])

    def test_consumers_see_only_code_sections_and_data_ranges_cover_the_rest(self):
        thin = _typical_macho()
        for data, slice_offset in ((thin, 0), (_fat(thin), 0x1000)):
            with self.subTest(slice_offset=slice_offset):
                image = load_binary(data, "macho")
                regions, warnings = full_regions(data, image)
                self.assertEqual(warnings, [])
                self.assertEqual([(region["name"], region["offset"], region["size"]) for region in regions],
                                 [("__text", slice_offset + 0x800, 0x10),
                                  ("__stubs", slice_offset + 0x810, 0xC),
                                  ("__stub_helper", slice_offset + 0x81C, 0x14)])
                self.assertEqual([(region.address, region.size) for region in semantic_regions(image, data)],
                                 [(region["address"], region["size"]) for region in regions])
                base = TEXT_BASE[64]
                data_ranges = mapped_data_ranges(image.sections, kind="macho", file_size=len(data))
                self.assertIn((base + 0x830, base + 0x850), data_ranges)  # __const
                self.assertIn((base + 0x850, base + 0x860), data_ranges)  # __cstring
                self.assertIn((base + 0x870, base + 0x880), data_ranges)  # __eh_frame
                code_end = base + 0x830
                self.assertFalse(any(start < code_end and base + 0x800 < end for start, end in data_ranges))
                code, address = _entry_bytes(data, image)
                self.assertEqual((address, code), (base + 0x800, b"\x90" * 15 + b"\xc3"))

    def test_sectionless_executable_segment_produces_no_region(self):
        # 代码区域只来自节表：无节的 r-x 段（无论能否容纳头之外的字节）都不产生可执行区域，
        # 但段仍参与 LC_MAIN 入口地址映射。
        for bits in (32, 64):
            with self.subTest(bits=bits):
                base = TEXT_BASE[bits]
                segments = [("__PAGEZERO", 0, base, 0, 0, 0, []),
                            ("__TEXT", base, 0x1000, 0, 0x400, 5, []),
                            ("__LINKEDIT", base + 0x1000, 0x1000, 0x400, 0x100, 1, [])]
                data = _macho(segments, bits=bits, entry=0x300, size=0x500)
                data[0x300:0x302] = b"\x90\xc3"
                for blob, slice_offset in ((bytes(data), 0), (_fat(bytes(data)), 0x1000)):
                    with self.subTest(slice_offset=slice_offset):
                        image = load_binary(blob, "macho")
                        self.assertEqual(image.sections, [])
                        self.assertEqual(image.entry_address, base + 0x300)
                        self.assertEqual(image.entry_offset, slice_offset + 0x300)
                        self.assertIsNone(_entry_bytes(blob, image))
                        self.assertEqual(semantic_regions(image, blob), [])
                        self.assertEqual(full_regions(blob, image),
                                         ([], ["No file-backed executable regions are available "
                                               "for full decoding"]))
                tiny_end = (32 if bits == 64 else 28) + (72 if bits == 64 else 56)
                tiny = _macho([("__TEXT", base, 0x1000, 0, tiny_end, 5, [])], bits=bits, size=0x400)
                self.assertEqual(load_binary(bytes(tiny), "macho").sections, [])

    def test_fileset_segments_with_embedded_images_are_not_code_regions(self):
        # MH_FILESET（filetype 0xC，内核集合）：无节的 r-x 段以内嵌 Mach-O 头开头，后面混排
        # 代码与 __cstring/__const 数据。整段不得当作代码；带节表的段仍按节属性判断。
        base = 0xFFFFFE0007000000
        inner_base = base + 0x1000
        inner = _macho([("__TEXT_EXEC", inner_base, 0x1000, 0, 0x1000, 5, [
            ("__text", inner_base + 0x400, 0x10, 0x400, CODE),
            ("__cstring", inner_base + 0x410, 0x20, 0x410, 0x2)])], size=0x1000, filetype=0xB)
        inner[0x400:0x410] = b"\x90" * 15 + b"\xc3"
        inner[0x410:0x430] = b"kext string data, not code\0".ljust(0x20, b"\0")
        segments = [
            ("__TEXT", base, 0x1000, 0, 0x1000, 1, []),
            ("__TEXT_EXEC", inner_base, 0x1000, 0x1000, 0x1000, 5, []),
            ("__HIB", base + 0x2000, 0x1000, 0x2000, 0x1000, 5,
             [("__text", base + 0x2000, 0x10, 0x2000, CODE)]),
            ("__LINKEDIT", base + 0x3000, 0x1000, 0x3000, 0x100, 1, []),
        ]
        data = _macho(segments, size=0x3100, filetype=0xC,
                      extra_commands=(_fileset_entry(inner_base, 0x1000, "com.example.kext"),))
        data[0x1000:0x2000] = inner
        data[0x2000:0x2010] = b"\x90" * 15 + b"\xc3"
        self.assertEqual(bytes(data[0x1000:0x1004]), b"\xcf\xfa\xed\xfe")  # 段首是内嵌头
        image = load_binary(bytes(data), "macho")
        self.assertEqual([section["name"] for section in image.sections], ["__text"])
        self.assertEqual([(section["segment"], section["executable"]) for section in image.sections],
                         [("__HIB", True)])
        self.assertFalse(any(section.get("type") == "MACHO_SEGMENT" for section in image.sections))
        regions, warnings = full_regions(bytes(data), image)
        self.assertEqual(warnings, [])
        self.assertEqual([(region["offset"], region["size"]) for region in regions], [(0x2000, 0x10)])
        self.assertEqual([(region.offset, region.size) for region in semantic_regions(image, bytes(data))],
                         [(0x2000, 0x10)])


class SemanticRegionBoundsTests(unittest.TestCase):
    def test_truncated_macho_section_stops_at_segment_file_content(self):
        # 节声明 0x200 字节，但段的文件内容在 0x900 结束：只有 0x100 字节属于该节，其后是别的内容。
        base = TEXT_BASE[64]
        data = bytes(_macho([("__TEXT", base, 0x2000, 0, 0x900, 5, [
            ("__text", base + 0x800, 0x200, 0x800, CODE)])], size=0x2000))
        image = load_binary(data, "macho")
        section = image.sections[0]
        self.assertEqual((section["size"], section["file_size"], section["executable"]), (0x200, 0x100, True))
        self.assertEqual([(region.address, region.offset, region.size)
                          for region in semantic_regions(image, data)], [(base + 0x800, 0x800, 0x100)])
        regions, _ = full_regions(data, image)
        self.assertEqual([(region["address"], region["offset"], region["file_backed_size"])
                          for region in regions], [(base + 0x800, 0x800, 0x100)])

    def test_stored_size_keys_follow_full_decode_convention(self):
        def section(address: int, **fields):
            return {"name": f"s{address:x}", "executable": True, "address": address,
                    "offset": address, "size": 0x40, **fields}

        valid = [section(0x100), section(0x200, file_size=0x10), section(0x300, filesize=0x20),
                 section(0x400, raw_size=0x30), section(0x500, file_size=0x80),
                 section(0x600, file_size=0x8, raw_size=0x30)]   # 第一个存在的键生效
        invalid = [section(0x700, file_size=0), section(0x800, file_size=-1),
                   section(0x900, filesize="16"), section(0xA00, raw_size=1.5),
                   section(0xB00, file_size=True), section(0xC00, file_size=None)]
        data = bytes(0x1000)
        image = SimpleNamespace(sections=valid + invalid)
        expected = [(0x100, 0x40), (0x200, 0x10), (0x300, 0x20), (0x400, 0x30), (0x500, 0x40), (0x600, 0x8)]
        self.assertEqual([(region.address, region.size) for region in semantic_regions(image, data)], expected)
        regions, _ = full_regions(data, image)
        self.assertEqual([(region["address"], region["file_backed_size"]) for region in regions], expected)


class PECodeRegionTests(unittest.TestCase):
    def test_region_size_is_min_of_raw_and_virtual_size(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                image = load_binary(_typical_pe(bits=bits), "pe")
                rows = {section["name"]: section for section in image.sections}
                self.assertEqual({name: (row["size"], row["file_size"], row["size_of_raw_data"],
                                         row["virtual_size"], row["file_backed"], row["executable"])
                                  for name, row in rows.items()},
                                 {".text": (0x30, 0x30, 0x200, 0x30, True, True),
                                  ".ztext": (0x200, 0x200, 0x200, 0, True, True),
                                  ".rdata": (0x100, 0x100, 0x200, 0x100, True, False),
                                  ".code": (0x40, 0x40, 0x200, 0x40, True, False),
                                  ".xdata": (0x40, 0x40, 0x200, 0x40, True, True),
                                  ".bss": (0, 0, 0, 0x100, False, False),
                                  ".data": (0x200, 0x200, 0x200, 0x400, True, False)})
                self.assertEqual([row["section_flags"] for row in image.sections],
                                 [flags for *_, flags in PE_SECTIONS])
                for row in image.sections:
                    self.assertLessEqual(LEGACY_PE_FIELDS, set(row), row["name"])

    def test_alignment_padding_is_not_decoded_or_used_for_entry_windows(self):
        data = _typical_pe()
        image = load_binary(data, "pe")
        regions, warnings = full_regions(data, image)
        self.assertEqual(warnings, [])
        self.assertEqual([(region["name"], region["offset"], region["size"]) for region in regions],
                         [(".text", 0x400, 0x30), (".ztext", 0x600, 0x200), (".xdata", 0xC00, 0x40)])
        self.assertEqual([(region.offset, region.size) for region in semantic_regions(image, data)],
                         [(0x400, 0x30), (0x600, 0x200), (0xC00, 0x40)])
        self.assertEqual(image.entry_offset, 0x420)
        self.assertEqual(_entry_bytes(data, image), (b"\x90" * 0xF + b"\xc3", 0x140001020))
        # 只有 CNT_CODE 的 .code 不可执行，与 .rdata/.data 一样按数据映射。
        rdata, code_only, data_section = 0x140003000, 0x140004000, 0x140007000
        self.assertEqual(mapped_data_ranges(image.sections, kind="pe", file_size=len(data)),
                         ((rdata, rdata + 0x100), (code_only, code_only + 0x40),
                          (data_section, data_section + 0x200)))

    def test_entry_in_alignment_padding_does_not_map(self):
        image = load_binary(_typical_pe(entry_rva=0x1100), "pe")
        self.assertIsNone(image.entry_offset)
        self.assertIn("Entry point does not map to scanned sections", image.warnings)


def _macho_samples() -> list[Path]:
    paths = [Path("/bin/ls"), Path("/bin/zsh"), Path("/usr/bin/vim"), Path("/usr/lib/dyld"),
             Path("/Applications/IDA Professional 9.4.app/Contents/MacOS/hv")]
    found = []
    for path in paths:
        try:
            if path.is_file() and identify_file(path)[0] == "macho":
                found.append(path)
        except OSError:
            continue
    return found


def _pe_samples() -> list[Path]:
    # pip 的 wheel 自带 distlib 启动器；只定位顶层包，不导入 pip。
    spec = importlib.util.find_spec("pip")
    if spec is None or not spec.origin:
        return []
    return sorted((Path(spec.origin).parent / "_vendor" / "distlib").glob("*.exe"))


class LocalSampleSmokeTests(unittest.TestCase):
    @unittest.skipUnless(_macho_samples(), "本机没有可读的 Mach-O 样本")
    def test_real_macho_code_regions_are_instruction_sections(self):
        for path in _macho_samples():
            with self.subTest(path=str(path)):
                data = path.read_bytes()
                image = load_binary(data, "macho")
                executable = [section for section in image.sections if section["executable"]]
                self.assertIn("__text", [section["name"] for section in executable])
                for section in executable:
                    self.assertTrue(section["segment_executable"] and section["file_backed"], section)
                    self.assertTrue(section.get("section_attributes", 0) & CODE
                                    or section.get("section_type") == 0x8, section)
                for section in image.sections:
                    if section["name"] in MACHO_DATA_SECTIONS:
                        self.assertFalse(section["executable"], section)
                regions, _ = full_regions(data, image)
                self.assertEqual([region["name"] for region in regions],
                                 [section["name"] for section in executable if section["file_size"]])

    @unittest.skipUnless(_pe_samples(), "当前环境没有 distlib PE 启动器")
    def test_real_pe_regions_match_section_headers(self):
        for path in _pe_samples():
            with self.subTest(path=path.name):
                data = path.read_bytes()
                image = load_binary(data, "pe")
                peoff, = struct.unpack_from("<I", data, 0x3C)
                count, = struct.unpack_from("<H", data, peoff + 6)
                optsize, = struct.unpack_from("<H", data, peoff + 20)
                expected = []
                for index in range(count):
                    _name, vsize, _rva, rawsize, _rawoff, *_rest, flags = struct.unpack_from(
                        "<8sIIIIIIHHI", data, peoff + 24 + optsize + index * 40)
                    expected.append((min(rawsize, vsize) if vsize else rawsize,
                                     bool(flags & 0x20000000)))
                self.assertEqual([(section["size"], section["executable"]) for section in image.sections],
                                 expected)
                regions, _ = full_regions(data, image)
                self.assertTrue(regions)
                for region in regions:
                    section = next(item for item in image.sections if item["name"] == region["name"])
                    self.assertLessEqual(region["size"], section["virtual_size"] or section["size_of_raw_data"])


if __name__ == "__main__":
    unittest.main()
