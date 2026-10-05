"""Known-answer and adversarial samples for bounded symbol extraction."""
from __future__ import annotations

import struct
import unittest

from .binary import parse_binary
from .symbols import parse_symbols


def pe64_with_symbols() -> bytes:
    data = bytearray(0x800)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 2, 0, 0, 0, 0xf0, 0x22)
    struct.pack_into("<H", data, 0x98, 0x20b)
    struct.pack_into("<I", data, 0x98 + 16, 0x1000)
    struct.pack_into("<Q", data, 0x98 + 24, 0x140000000)
    struct.pack_into("<I", data, 0x98 + 108, 16)
    struct.pack_into("<II", data, 0x98 + 112, 0x3000, 0x100)  # Exports.
    struct.pack_into("<II", data, 0x98 + 120, 0x2000, 0x40)  # Imports.
    struct.pack_into("<8sIIIIIIHHI", data, 0x188, b".idata\0\0", 0x200,
                     0x2000, 0x200, 0x200, 0, 0, 0, 0, 0x40000040)
    struct.pack_into("<8sIIIIIIHHI", data, 0x1b0, b".edata\0\0", 0x200,
                     0x3000, 0x200, 0x400, 0, 0, 0, 0, 0x40000040)

    struct.pack_into("<IIIII", data, 0x200, 0x2040, 0, 0, 0x2080, 0x2060)
    struct.pack_into("<QQQ", data, 0x240, 0x2090, 0x8000000000000042, 0)
    data[0x280:0x28d] = b"KERNEL32.dll\0"
    struct.pack_into("<H", data, 0x290, 7)
    data[0x292:0x29e] = b"ExitProcess\0"

    struct.pack_into("<IIHHIIIIIII", data, 0x400, 0, 0, 0, 0, 0x3090,
                     1, 2, 1, 0x3040, 0x3050, 0x3060)
    struct.pack_into("<II", data, 0x440, 0x1000, 0x3080)
    struct.pack_into("<I", data, 0x450, 0x3070)
    struct.pack_into("<H", data, 0x460, 0)
    data[0x470:0x479] = b"Exported\0"
    data[0x480:0x48f] = b"OTHER.Forward\0"
    data[0x490:0x499] = b"test.dll\0"
    return bytes(data)


def elf64_with_dynsym() -> bytes:
    data = bytearray(0x500)
    data[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 3, 62, 1, 0,
                     0, 0x300, 0, 64, 56, 0, 64, 4, 0)
    strings = b"\0puts\0public_func\0private_func\0"
    data[0x200:0x200 + len(strings)] = strings
    # Null, undefined import, exported function, hidden definition.
    struct.pack_into("<IBBHQQ", data, 0x100 + 24, 1, 0x12, 0, 0, 0, 0)
    struct.pack_into("<IBBHQQ", data, 0x100 + 48, 6, 0x12, 0, 3, 0x401000, 12)
    struct.pack_into("<IBBHQQ", data, 0x100 + 72, 18, 0x12, 2, 3, 0x401020, 9)
    struct.pack_into("<IIQQQQIIQQ", data, 0x340, 0, 11, 0, 0,
                     0x100, 96, 2, 0, 8, 24)
    struct.pack_into("<IIQQQQIIQQ", data, 0x380, 0, 3, 0, 0,
                     0x200, len(strings), 0, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", data, 0x3c0, 0, 1, 6, 0x401000,
                     0x280, 0x30, 0, 0, 16, 0)
    return bytes(data)


def elf32_big_endian_with_dynsym() -> bytes:
    data = bytearray(0x480)
    data[:16] = b"\x7fELF\x01\x02\x01" + bytes(9)
    struct.pack_into(">HHIIIIIHHHHHH", data, 16, 2, 40, 1, 0x1000,
                     0, 0x300, 0, 52, 32, 0, 40, 4, 0)
    strings = b"\0external\0visible\0"
    data[0x200:0x200 + len(strings)] = strings
    struct.pack_into(">IIIBBH", data, 0x100 + 16, 1, 0, 0, 0x12, 0, 0)
    struct.pack_into(">IIIBBH", data, 0x100 + 32, 10, 0x1000, 4, 0x12, 0, 3)
    struct.pack_into(">IIIIIIIIII", data, 0x328, 0, 11, 0, 0,
                     0x100, 48, 2, 0, 4, 16)
    struct.pack_into(">IIIIIIIIII", data, 0x350, 0, 3, 0, 0,
                     0x200, len(strings), 0, 0, 1, 0)
    struct.pack_into(">IIIIIIIIII", data, 0x378, 0, 1, 6, 0x1000,
                     0x280, 0x20, 0, 0, 4, 0)
    return bytes(data)


class SymbolTests(unittest.TestCase):
    def test_pe_named_ordinal_and_forwarded_symbols(self) -> None:
        data = pe64_with_symbols()
        imports, exports, warnings = parse_symbols(data, parse_binary(data, "pe"))
        self.assertEqual(warnings, [])
        self.assertEqual(imports, [
            {"library": "KERNEL32.dll", "name": "ExitProcess", "hint": 7,
             "address": 0x140002060, "source": "pe-import"},
            {"library": "KERNEL32.dll", "name": "#66", "ordinal": 66,
             "address": 0x140002068, "source": "pe-import"},
        ])
        self.assertEqual(exports, [
            {"name": "Exported", "ordinal": 1, "address": 0x140001000,
             "source": "pe-export"},
            {"name": "#2", "ordinal": 2, "address": None,
             "source": "pe-export", "forwarder": "OTHER.Forward"},
        ])

    def test_elf_undefined_vs_visible_defined_dynamic_symbols(self) -> None:
        data = elf64_with_dynsym()
        imports, exports, warnings = parse_symbols(data, parse_binary(data, "elf"))
        self.assertEqual(warnings, [])
        self.assertEqual([(s["name"], s["address"], s["kind"]) for s in imports],
                         [("puts", None, "function")])
        self.assertEqual([(s["name"], s["address"]) for s in exports],
                         [("public_func", 0x401000)])

    def test_pe32_import_pointer_and_big_endian_elf32(self) -> None:
        pe = bytearray(pe64_with_symbols())
        optional = 0x98
        struct.pack_into("<H", pe, optional, 0x10b)
        struct.pack_into("<I", pe, optional + 28, 0x400000)
        struct.pack_into("<I", pe, optional + 92, 16)
        struct.pack_into("<II", pe, optional + 96, 0x3000, 0x100)
        struct.pack_into("<II", pe, optional + 104, 0x2000, 0x40)
        struct.pack_into("<III", pe, 0x240, 0x2090, 0x80000042, 0)
        imports, exports, warnings = parse_symbols(bytes(pe), parse_binary(pe, "pe"))
        self.assertEqual(warnings, [])
        self.assertEqual([(item["name"], item["address"]) for item in imports],
                         [("ExitProcess", 0x402060), ("#66", 0x402064)])
        self.assertEqual(exports[0]["address"], 0x401000)

        elf = elf32_big_endian_with_dynsym()
        imports, exports, warnings = parse_symbols(elf, parse_binary(elf, "elf"))
        self.assertEqual(warnings, [])
        self.assertEqual(imports[0]["name"], "external")
        self.assertEqual((exports[0]["name"], exports[0]["address"]),
                         ("visible", 0x1000))

    def test_truncated_pe_imports_keep_bounded_partial_result(self) -> None:
        data = pe64_with_symbols()[:0x298]
        imports, exports, warnings = parse_symbols(data, parse_binary(data, "pe"))
        self.assertEqual([(item["name"], item["ordinal"]) for item in imports],
                         [("#66", 66)])
        self.assertEqual(exports, [])
        self.assertTrue(any("unterminated name" in warning for warning in warnings))
        self.assertTrue(any("export directory" in warning for warning in warnings))

    def test_poisoned_counts_and_elf_bad_name_do_not_escape_scan(self) -> None:
        data = bytearray(pe64_with_symbols())
        struct.pack_into("<I", data, 0x400 + 20, 0xffffffff)  # NumberOfFunctions.
        _imports, exports, warnings = parse_symbols(bytes(data), parse_binary(data, "pe"))
        self.assertLessEqual(len(exports), 128)
        self.assertTrue(any("export address table truncated" in warning for warning in warnings))
        elf = bytearray(elf64_with_dynsym())
        struct.pack_into("<I", elf, 0x100 + 24, 0xffffffff)  # Invalid name offset.
        imports, exports, warnings = parse_symbols(bytes(elf), parse_binary(elf, "elf"))
        self.assertEqual(imports, [])
        self.assertEqual(exports[0]["name"], "public_func")
        self.assertTrue(any("invalid or unterminated names" in warning for warning in warnings))


if __name__ == "__main__":
    unittest.main()
