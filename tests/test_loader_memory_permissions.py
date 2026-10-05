"""容器权限元数据：来自格式声明，不根据节名推断，不载入分析器。"""
from __future__ import annotations

import struct
import subprocess
import sys
import unittest

from fangida.loaders import load_binary


def elf_permissions(bits: int = 64, order: str = "<", *, stripped: bool = False,
                    overlap: bool = False) -> bytes:
    data = bytearray(0x800)
    data[:16] = b"\x7fELF" + bytes((2 if bits == 64 else 1,
                                   1 if order == "<" else 2, 1)) + bytes(9)
    segments = [(0x200, 0x401000, 0x20, 0x40, 6),
                (0x240, 0x402000, 0x20, 0x20, 1)]
    if overlap:
        segments.append((0x200, 0x401000, 0x20, 0x40, 4))
    names = b"\0.rodata\0.data\0.unmapped\0.debug\0.shstrtab\0"
    data[0x380:0x380 + len(names)] = names
    sections = [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (1, 1, 2, 0x401000, 0x200, 0x20, 0, 0, 8, 0),
        (9, 1, 3, 0x402000, 0x240, 0x20, 0, 0, 8, 0),
        (15, 1, 3, 0x403000, 0x280, 0x20, 0, 0, 8, 0),
        (25, 1, 0, 0, 0x300, 0x20, 0, 0, 1, 0),
        (32, 3, 0, 0, 0x380, len(names), 0, 0, 1, 0),
    ]
    header = order + ("HHIQQQIHHHHHH" if bits == 64 else "HHIIIIIHHHHHH")
    segment_fmt = order + ("IIQQQQQQ" if bits == 64 else "IIIIIIII")
    section_fmt = order + ("IIQQQQIIQQ" if bits == 64 else "IIIIIIIIII")
    header_size = 64 if bits == 64 else 52
    segment_size, section_size = struct.calcsize(segment_fmt), struct.calcsize(section_fmt)
    struct.pack_into(header, data, 16, 2, 183 if bits == 64 else 40, 1,
                     0x401000, header_size, 0 if stripped else 0x400, 0,
                     header_size, segment_size, len(segments), section_size,
                     0 if stripped else len(sections), 0 if stripped else 5)
    for index, (offset, address, file_size, memory_size, flags) in enumerate(segments):
        values = ((1, flags, offset, address, address, file_size, memory_size, 0x1000)
                  if bits == 64 else
                  (1, offset, address, address, file_size, memory_size, flags, 0x1000))
        struct.pack_into(segment_fmt, data, header_size + index * segment_size, *values)
    if not stripped:
        for index, values in enumerate(sections):
            struct.pack_into(section_fmt, data, 0x400 + index * section_size, *values)
    return bytes(data)


def pe_permissions(bits: int, flags: int) -> bytes:
    data = bytearray(0x220)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0xAA64 if bits == 64 else 0x14C,
                     1, 0, 0, 0, 0xF0, 0x22)
    struct.pack_into("<H", data, 0x98, 0x20B if bits == 64 else 0x10B)
    struct.pack_into("<I", data, 0xA8, 0x1000)
    struct.pack_into("<Q" if bits == 64 else "<I", data,
                     0x98 + (24 if bits == 64 else 28),
                     0x140000000 if bits == 64 else 0x400000)
    struct.pack_into("<8sIIIIIIHHI", data, 0x188, b".rdata\0\0", 0x10,
                     0x1000, 0x10, 0x200, 0, 0, 0, 0, flags)
    return bytes(data)


def macho_permissions(bits: int, order: str, initprot: int) -> bytes:
    data = bytearray(0x220)
    base = 0x100000000 if bits == 64 else 0x1000
    if bits == 64:
        struct.pack_into(order + "IIIIIIII", data, 0, 0xFEEDFACF, 0x0100000C,
                         0, 2, 1, 152, 0, 0)
        struct.pack_into(order + "II16sQQQQIIII", data, 32, 0x19, 152,
                         b"__DATA".ljust(16, b"\0"), base, 0x1000, 0, len(data),
                         7, initprot, 1, 0)
        struct.pack_into(order + "16s16sQQIIIIIIII", data, 104,
                         b"__const".ljust(16, b"\0"), b"__DATA".ljust(16, b"\0"),
                         base + 0x200, 0x20, 0x200, 3, 0, 0, 0, 0, 0, 0)
    else:
        struct.pack_into(order + "IIIIIII", data, 0, 0xFEEDFACE, 12,
                         0, 2, 1, 124, 0)
        struct.pack_into(order + "II16sIIIIIIII", data, 28, 1, 124,
                         b"__DATA".ljust(16, b"\0"), base, 0x1000, 0, len(data),
                         7, initprot, 1, 0)
        struct.pack_into(order + "16s16sIIIIIIIII", data, 84,
                         b"__const".ljust(16, b"\0"), b"__DATA".ljust(16, b"\0"),
                         base + 0x200, 0x20, 0x200, 3, 0, 0, 0, 0, 0)
    return bytes(data)


class LoaderMemoryPermissionsTests(unittest.TestCase):
    def test_elf_sections_take_runtime_permissions_from_covering_load_segments(self):
        for bits in (32, 64):
            for order in ("<", ">"):
                with self.subTest(bits=bits, order=order):
                    sections = load_binary(elf_permissions(bits, order)).sections
                    declared_readonly, declared_writable = sections[1:3]
                    self.assertFalse(declared_readonly["section_writable"])
                    self.assertTrue(declared_readonly["writable"])
                    self.assertTrue(declared_readonly["readable"])
                    self.assertEqual(declared_readonly["permissions_source"], "segment")
                    self.assertTrue(declared_writable["section_writable"])
                    self.assertFalse(declared_writable["writable"])
                    self.assertFalse(declared_writable["readable"])
                    self.assertEqual(declared_writable["permissions_source"], "segment")

    def test_elf_uncovered_or_unallocated_sections_keep_readability_unknown(self):
        sections = load_binary(elf_permissions()).sections
        unmapped, debug = sections[3:5]
        self.assertIsNone(unmapped["readable"])
        self.assertTrue(unmapped["writable"])
        self.assertEqual(unmapped["permissions_source"], "section")
        self.assertIsNone(debug["readable"])
        self.assertFalse(debug["writable"])
        self.assertEqual(debug["permissions_source"], "section")

    def test_elf_overlapping_load_segments_preserve_any_write_possibility(self):
        image = load_binary(elf_permissions(overlap=True))
        self.assertTrue(image.sections[1]["writable"])
        self.assertTrue(image.sections[1]["readable"])
        self.assertFalse(image.sections[1]["section_writable"])
        # 若覆盖段读取声明冲突，不能凭可加载属性推测 readable=True。
        data = bytearray(elf_permissions(overlap=True))
        struct.pack_into("<I", data, 64 + 56 * 2 + 4, 0)
        section = load_binary(bytes(data)).sections[1]
        self.assertIsNone(section["readable"])
        self.assertTrue(section["writable"])

    def test_elf_partial_writable_overlay_prevents_whole_section_readonly_claim(self):
        data = bytearray(elf_permissions(overlap=True))
        struct.pack_into("<I", data, 64 + 4, 4)  # 完整覆盖的首段只有 PF_R。
        struct.pack_into("<IIQQQQQQ", data, 64 + 56 * 2, 1, 2, 0x210,
                         0x401010, 0x401010, 0x10, 0x10, 0x1000)
        section = load_binary(bytes(data)).sections[1]
        self.assertTrue(section["writable"])
        self.assertIsNone(section["readable"])
        self.assertEqual(section["permissions_source"], "segment")

    def test_stripped_elf_load_segments_declare_read_write_independently(self):
        for bits in (32, 64):
            for order in ("<", ">"):
                with self.subTest(bits=bits, order=order):
                    image = load_binary(elf_permissions(bits, order, stripped=True))
                    self.assertEqual(len(image.sections), 2)
                    rw, execute_only = image.sections
                    self.assertTrue(rw["readable"])
                    self.assertTrue(rw["writable"])
                    self.assertFalse(rw["executable"])
                    self.assertFalse(execute_only["readable"])
                    self.assertFalse(execute_only["writable"])
                    self.assertTrue(execute_only["executable"])
                    self.assertTrue(all(section["permissions_source"] == "segment"
                                        for section in image.sections))
                    self.assertEqual((image.entry_address, image.entry_offset),
                                     (0x401000, 0x200))

    def test_pe_permissions_follow_characteristics_even_with_misleading_name(self):
        for bits in (32, 64):
            for flags in (0, 0x40000000, 0x80000000, 0xC0000000, 0x60000020):
                with self.subTest(bits=bits, flags=flags):
                    section = load_binary(pe_permissions(bits, flags)).sections[0]
                    self.assertEqual(section["name"], ".rdata")
                    self.assertEqual(section["readable"], bool(flags & 0x40000000))
                    self.assertEqual(section["writable"], bool(flags & 0x80000000))
                    self.assertEqual(section["executable"], bool(flags & 0x20000000))
                    self.assertEqual(section["section_flags"], flags)
                    self.assertEqual(section["permissions_source"], "section")
                    self.assertEqual((section["offset"], section["size"]), (0x200, 0x10))

    def test_macho_permissions_follow_initprot_in_all_widths_and_byte_orders(self):
        for bits in (32, 64):
            for order in ("<", ">"):
                for initprot in (0, 1, 2, 3, 5, 7):
                    with self.subTest(bits=bits, order=order, initprot=initprot):
                        section = load_binary(macho_permissions(bits, order, initprot)).sections[0]
                        self.assertEqual(section["name"], "__const")
                        self.assertEqual(section["readable"], bool(initprot & 1))
                        self.assertEqual(section["writable"], bool(initprot & 2))
                        self.assertEqual(section["permissions_source"], "segment")
                        # maxprot=7 不意味着当前可写，且数据节不能因 RX 段成为代码。
                        self.assertFalse(section["executable"])

    def test_fat_macho_rebases_offsets_and_preserves_permissions(self):
        thin = macho_permissions(64, "<", 3)
        data = bytearray(0x1000 + len(thin))
        struct.pack_into(">II", data, 0, 0xCAFEBABE, 1)
        struct.pack_into(">IIIII", data, 8, 0x0100000C, 0, 0x1000, len(thin), 12)
        data[0x1000:] = thin
        section = load_binary(bytes(data)).sections[0]
        self.assertEqual(section["offset"], 0x1200)
        self.assertTrue(section["readable"])
        self.assertTrue(section["writable"])
        self.assertEqual(section["permissions_source"], "segment")

    def test_loaders_do_not_import_solver_unicorn_or_processors(self):
        code = (
            "import sys; import fangida.loaders; "
            "assert not any(name.startswith(('fangida.processors', 'fangida.plugins', "
            "'unicorn')) for name in sys.modules)"
        )
        result = subprocess.run([sys.executable, "-c", code], capture_output=True,
                                text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
