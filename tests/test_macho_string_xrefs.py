"""Mach-O 同一 RX segment 内的代码/字符串分类及真实引用回归。"""
from __future__ import annotations

from pathlib import Path
import struct
import tempfile
import unittest

from fangida.core.kkagent.strings import scan_native_strings
from fangida.core.kkagent.test_native import macho64 as legacy_macho64
from fangida.core.kkagent.test_semantic import DECODER_AVAILABLE
from fangida.dispatcher import AnalysisService
from fangida.loaders import load_binary
from fangida.settings import Settings
from fangida.xrefs import mapped_data_ranges


def _macho(bits: int = 64, *, text_flags: int = 0x80000400,
           initprot: int = 5) -> tuple[bytes, int, int]:
    """真实薄容器：RX __TEXT 包含声明为代码的 __text 和 CSTRING_LITERALS。"""
    data = bytearray(0x280)
    base = 0x100000000 if bits == 64 else 0x1000
    target = base + 0x240
    code = (b"\x48\xbf" + struct.pack("<Q", target) + b"\xc3" if bits == 64
            else b"\xbf" + struct.pack("<I", target) + b"\xc3")
    literal = b"referenced string\0"
    if bits == 64:
        header_size, segment_size = 32, 232
        struct.pack_into("<IIIIIIII", data, 0, 0xFEEDFACF, 0x01000007, 3, 2,
                         2, segment_size + 24, 0, 0)
        struct.pack_into("<II16sQQQQIIII", data, header_size, 0x19, segment_size,
                         b"__TEXT".ljust(16, b"\0"), base, 0x1000, 0, len(data),
                         7, initprot, 2, 0)
        section_start, stride, section_format = header_size + 72, 80, "<16s16sQQIIIIIIII"
    else:
        header_size, segment_size = 28, 192
        struct.pack_into("<IIIIIII", data, 0, 0xFEEDFACE, 7, 3, 2,
                         2, segment_size + 24, 0)
        struct.pack_into("<II16sIIIIIIII", data, header_size, 1, segment_size,
                         b"__TEXT".ljust(16, b"\0"), base, 0x1000, 0, len(data),
                         7, initprot, 2, 0)
        section_start, stride, section_format = header_size + 56, 68, "<16s16sIIIIIIIII"
    for index, (name, offset, content, flags) in enumerate((
            ("__text", 0x200, code, text_flags),
            ("__cstring", 0x240, literal, 2))):
        values = (name.encode().ljust(16, b"\0"), b"__TEXT".ljust(16, b"\0"),
                  base + offset, len(content), offset, 0, 0, 0, flags, 0, 0)
        if bits == 64:
            values += (0,)
        struct.pack_into(section_format, data, section_start + index * stride, *values)
        data[offset:offset + len(content)] = content
    struct.pack_into("<IIQQ", data, header_size + segment_size, 0x80000028, 24, 0x200, 0)
    return bytes(data), target, len(code)


def _fat(thin: bytes) -> bytes:
    data = bytearray(0x1000 + len(thin))
    struct.pack_into(">II", data, 0, 0xCAFEBABE, 1)
    struct.pack_into(">IIIII", data, 8, 0x01000007, 3, 0x1000, len(thin), 12)
    data[0x1000:] = thin
    return bytes(data)


class MachoSectionClassificationTests(unittest.TestCase):
    def test_rx_segment_keeps_code_and_cstring_sections_distinct_in_thin_and_fat(self):
        thin, target, _ = _macho()
        cases = ((_macho(32)[0], 0), (thin, 0), (_fat(thin), 0x1000))
        for data, slice_offset in cases:
            with self.subTest(slice_offset=slice_offset, magic=data[:4].hex()):
                image = load_binary(data, "macho")
                text, cstring = image.sections
                self.assertTrue(text["executable"])
                self.assertFalse(cstring["executable"])
                self.assertEqual(text["section_flags"], 0x80000400)
                self.assertEqual(cstring["section_flags"], 2)
                self.assertTrue(cstring["file_backed"])
                self.assertEqual(cstring["offset"], slice_offset + 0x240)
                strings, _ = scan_native_strings(data, image)
                string = next(item for item in strings if item["value"] == "referenced string")
                self.assertEqual(string["offset"], slice_offset + 0x240)
                self.assertEqual(string["data_ranges"], [[cstring["address"], 17]])
                self.assertEqual(mapped_data_ranges(image.sections, kind="macho", file_size=len(data)),
                                 ((cstring["address"], cstring["address"] + cstring["size"]),))

    def test_instruction_attributes_symbol_stubs_and_zero_flags_text_remain_code(self):
        for bits in (32, 64):
            for flags in (0x80000000, 0x400, 8, 0):
                with self.subTest(bits=bits, flags=flags):
                    image = load_binary(_macho(bits, text_flags=flags)[0], "macho")
                    self.assertTrue(image.sections[0]["executable"])
                    self.assertEqual(image.sections[0]["section_flags"], flags)
                    self.assertFalse(image.sections[1]["executable"])
        legacy = load_binary(legacy_macho64(), "macho")
        self.assertTrue(legacy.sections[0]["executable"])
        self.assertEqual(legacy.sections[0]["section_flags"], 0)

    def test_section_code_attributes_do_not_grant_missing_segment_execute_permission(self):
        for bits in (32, 64):
            image = load_binary(_macho(bits, initprot=1)[0], "macho")
            self.assertFalse(any(section["executable"] for section in image.sections))


@unittest.skipUnless(DECODER_AVAILABLE, "需要原生解码器验证实际字符串引用")
class MachoStringAnalysisTests(unittest.TestCase):
    def test_full_movabs_pointer_reference_is_preserved_without_decoding_cstring(self):
        thin, target, code_size = _macho()
        thin32, target32, code_size32 = _macho(32)
        cases = (("thin64", thin, target, code_size, 0),
                 ("thin32", thin32, target32, code_size32, 0),
                 ("fat64", _fat(thin), target, code_size, 0x1000))
        with tempfile.TemporaryDirectory() as directory:
            for name, data, string_address, executable_size, slice_offset in cases:
                with self.subTest(name=name):
                    path = Path(directory) / f"{name}.macho"
                    path.write_bytes(data)
                    with AnalysisService(Settings(analyze_threads=2)) as service:
                        result = service.analyze(path, full_analysis=True, use_ghidra=False)
                    self.assertNotEqual(result.status, "error", result.warnings)
                    string = next(item for item in result.strings if item["value"] == "referenced string")
                    self.assertEqual(string["data_ranges"], [[string_address, 17]])
                    self.assertEqual(string["offset"], slice_offset + 0x240)
                    refs = [item for item in result.xrefs if item["kind"] == "data"
                            and item["dst"] == string_address]
                    self.assertEqual(len(refs), 1, result.xrefs)
                    self.assertEqual(refs[0]["src"], string_address - 0x40)
                    self.assertEqual(refs[0]["evidence"], "mapped_immediate")
                    self.assertEqual(result.stats["full_executable_bytes"], executable_size)
                    self.assertEqual(result.stats["full_instructions"], 2)
                    self.assertTrue(result.stats["full_decode_complete"])
                    self.assertEqual([region["name"] for region in result.metadata["full_analysis"]["regions"]],
                                     ["__text"])
                    self.assertTrue(all(instruction["addr"] < string_address
                                        for instruction in result.metadata["full_disassembly"]))


if __name__ == "__main__":
    unittest.main()
