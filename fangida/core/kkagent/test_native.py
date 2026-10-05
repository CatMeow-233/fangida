"""Small synthetic binary samples with exact address and file-offset answers."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch
import struct
import tempfile
import unittest

from ...models import AnalysisTask
from . import PluginImpl
from .binary import BinaryFormatError, parse_binary
from .translator import _objdump, objdump_available


def elf64() -> bytes:
    data = bytearray(0x300)
    data[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 2, 62, 1, 0x401000,
                     0x40, 0x200, 0, 64, 56, 1, 64, 3, 2)
    struct.pack_into("<IIQQQQQQ", data, 0x40, 1, 5, 0x100, 0x401000,
                     0x401000, 5, 5, 0x1000)
    data[0x100:0x105] = b"\x55\x48\x89\xe5\xc3"  # push rbp; mov rbp,rsp; ret
    names = b"\0.text\0.shstrtab\0"
    data[0x120:0x120 + len(names)] = names
    struct.pack_into("<IIQQQQIIQQ", data, 0x240, 1, 1, 6, 0x401000,
                     0x100, 5, 0, 0, 16, 0)
    struct.pack_into("<IIQQQQIIQQ", data, 0x280, 7, 3, 0, 0,
                     0x120, len(names), 0, 0, 1, 0)
    return bytes(data)


def elf64_with_symbols() -> bytes:
    data = bytearray(elf64())
    data.extend(bytes(0x200))
    struct.pack_into("<H", data, 16 + 44, 5)  # e_shnum
    names = b"\0.text\0.shstrtab\0.symtab\0.strtab\0"
    data[0x120:0x120 + len(names)] = names
    struct.pack_into("<Q", data, 0x280 + 32, len(names))
    strings = b"\0known_func\0"
    data[0x160:0x160 + len(strings)] = strings
    struct.pack_into("<IBBHQQ", data, 0x180 + 24, 1, 0x12, 0, 1, 0x401000, 5)
    struct.pack_into("<IIQQQQIIQQ", data, 0x2c0, 17, 2, 0, 0,
                     0x180, 48, 4, 0, 8, 24)
    struct.pack_into("<IIQQQQIIQQ", data, 0x300, 25, 3, 0, 0,
                     0x160, len(strings), 0, 0, 1, 0)
    return bytes(data)


def pe64() -> bytes:
    data = bytearray(0x220)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 0xf0, 0x22)
    struct.pack_into("<H", data, 0x98, 0x20b)
    struct.pack_into("<I", data, 0x98 + 16, 0x1000)
    struct.pack_into("<Q", data, 0x98 + 24, 0x140000000)
    struct.pack_into("<8sIIIIIIHHI", data, 0x188, b".text\0\0\0", 0x10,
                     0x1000, 0x10, 0x200, 0, 0, 0, 0, 0x60000020)
    data[0x200:0x203] = b"\x90\x90\xc3"
    return bytes(data)


def macho64() -> bytes:
    data = bytearray(0x220)
    struct.pack_into("<IIIIIIII", data, 0, 0xfeedfacf, 0x01000007,
                     3, 2, 2, 176, 0, 0)
    struct.pack_into("<II16sQQQQIIII", data, 32, 0x19, 152,
                     b"__TEXT\0\0\0\0\0\0\0\0\0\0", 0x100000000, 0x300,
                     0, 0x203, 7, 5, 1, 0)
    struct.pack_into("<16s16sQQIIIIIIII", data, 104,
                     b"__text".ljust(16, b"\0"), b"__TEXT".ljust(16, b"\0"),
                     0x100000200, 3, 0x200, 2, 0, 0, 0, 0, 0, 0)
    struct.pack_into("<IIQQ", data, 184, 0x80000028, 24, 0x200, 0)
    data[0x200:0x203] = b"\x90\x90\xc3"
    return bytes(data)


class NativeTests(unittest.TestCase):
    def test_elf_entry_and_sections(self) -> None:
        image = parse_binary(elf64(), "elf")
        self.assertEqual((image.architecture, image.entry_address, image.entry_offset),
                         ("x86_64", 0x401000, 0x100))
        self.assertEqual(image.sections[1]["name"], ".text")

    def test_elf_symbol_functions_are_grounded_in_symtab(self) -> None:
        image = parse_binary(elf64_with_symbols(), "elf")
        self.assertEqual([(f["name"], f["start"], f["size"], f["source"])
                          for f in image.functions], [("known_func", 0x401000, 5, "symtab")])
        self.assertEqual(image.functions[0]["blocks"], [])

    def test_pe_entry_and_sections(self) -> None:
        image = parse_binary(pe64(), "pe")
        self.assertEqual((image.architecture, image.entry_address, image.entry_offset),
                         ("x86_64", 0x140001000, 0x200))
        self.assertTrue(image.sections[0]["executable"])

    def test_macho_entry_and_sections(self) -> None:
        image = parse_binary(macho64(), "macho")
        self.assertEqual((image.architecture, image.entry_address, image.entry_offset),
                         ("x86_64", 0x100000200, 0x200))
        self.assertEqual(image.sections[0]["name"], "__text")

    def test_truncated_and_malformed_files_are_partial(self) -> None:
        with self.assertRaises(BinaryFormatError):
            parse_binary(b"\x7fELF", "elf")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broken.elf"
            path.write_bytes(b"\x7fELFhello world\0")
            result = PluginImpl().analyze(AnalysisTask(str(path), "elf"))
        self.assertEqual(result.status, "partial")
        self.assertTrue(any("container metadata unavailable" in warning for warning in result.warnings))
        self.assertIn("hello world", result.strings[0]["value"])

    def test_entry_disassembly_is_bounded_and_does_not_claim_function_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.elf"
            path.write_bytes(elf64())
            result = PluginImpl().analyze(AnalysisTask(str(path), "elf"))
        self.assertEqual(result.status, "partial")
        instructions = result.metadata["disassembly"]
        self.assertLessEqual(len(instructions), 128)
        if instructions:  # Capstone / objdump availability depends on platform.
            self.assertEqual(instructions[0]["addr"], 0x401000)
            self.assertEqual(instructions[0]["size"], 1)
            self.assertEqual(result.functions[0]["source"], "entry_window")
            self.assertFalse(result.functions[0]["boundary_known"])
            self.assertEqual(result.metadata["entry_cfg"]["scope"], "bounded_entry_window")

    def test_direct_entry_xrefs_are_bounded(self) -> None:
        sample = bytearray(elf64())
        sample[0x100:0x105] = b"\xe8\xfb\xff\xff\xff"  # call entry
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "call.elf"
            path.write_bytes(sample)
            result = PluginImpl().analyze(AnalysisTask(str(path), "elf"))
        if result.metadata["disassembly"]:
            self.assertEqual(result.xrefs[0], {"src": 0x401000, "dst": 0x401000,
                                               "kind": "call", "confidence": 1.0})
            self.assertEqual(result.stats["entry_direct_xrefs"], 1)

    def test_direct_xref_attaches_to_explicit_symbol(self) -> None:
        sample = bytearray(elf64_with_symbols())
        sample[0x100:0x105] = b"\xe8\xfb\xff\xff\xff"  # self call
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "symbol-call.elf"
            path.write_bytes(sample)
            result = PluginImpl().analyze(AnalysisTask(str(path), "elf"))
        self.assertEqual(result.functions[0]["source"], "symtab")
        if result.metadata["disassembly"]:
            self.assertEqual(result.functions[0]["xrefs_in"], result.xrefs)
            self.assertEqual(result.functions[0]["xrefs_out"], result.xrefs)
            self.assertEqual(result.functions[0]["analysis_scope"], "bounded_function")

    def test_scan_budget_never_seeks_past_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.elf"
            path.write_bytes(elf64())
            result = PluginImpl().analyze(AnalysisTask(str(path), "elf", max_bytes=64))
        self.assertEqual(result.metadata["scanned_bytes"], 64)
        self.assertEqual(result.metadata["disassembly"], [])
        self.assertTrue(any("scan budget" in warning for warning in result.warnings))

    def test_optional_native_failure_keeps_python_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.elf"
            path.write_bytes(elf64_with_symbols())
            with patch.dict("os.environ", {"FANGIDA_NATIVE_LIB": str(path.parent / "missing.so")}):
                result = PluginImpl().analyze(AnalysisTask(str(path), "elf"))
        self.assertEqual(result.status, "partial")
        self.assertEqual(result.functions[0]["name"], "known_func")
        self.assertNotIn("native_summary", result.metadata)
        self.assertTrue(any("Optional native scan unavailable" in warning for warning in result.warnings))

    @unittest.skipUnless(objdump_available(), "GNU/LLVM objdump unavailable")
    def test_objdump_long_instruction_is_not_split_into_a_false_gap(self) -> None:
        code = bytes.fromhex("66 2e 0f 1f 84 00 00 00 00 00 c3")
        instructions, warnings = _objdump(code, 0x1000, "x86_64")
        self.assertFalse(any("could not decode" in warning for warning in warnings))
        self.assertEqual([(item["addr"], item["size"]) for item in instructions],
                         [(0x1000, 10), (0x100a, 1)])


if __name__ == "__main__":
    unittest.main()
