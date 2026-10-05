"""独立 ELF 容器重定位元数据及不可信文件边界回归。"""
from __future__ import annotations

import struct
import unittest

from fangida.loaders import BinaryImage, load_binary
from fangida.loaders.elf_relocations import recover_dynamic_relocations


def relocation_elf(bits=64, order="<", *, rela=True, rows=None, extra=None, file_type=3):
    word = bits // 8
    symbol_fmt = order + ("IBBHQQ" if bits == 64 else "IIIBBH")
    section_fmt = order + ("IIQQQQIIQQ" if bits == 64 else "IIIIIIIIII")
    header_fmt = order + ("HHIQQQIHHHHHH" if bits == 64 else "HHIIIIIHHHHHH")
    relocation_fmt = order + ("QQ" if bits == 64 else "II") + (("q" if bits == 64 else "i") if rela else "")
    symbol_size, section_size, relocation_size = map(struct.calcsize, (symbol_fmt, section_fmt, relocation_fmt))
    data = bytearray(0x900 + 8 * section_size)
    data[:16] = b"\x7fELF" + bytes((2 if bits == 64 else 1, 1 if order == "<" else 2, 1)) + bytes(9)
    struct.pack_into(header_fmt, data, 16, file_type, 183 if bits == 64 else 40, 1, 0x1000,
                     0, 0x900, 0, 64 if bits == 64 else 52, 0, 0, section_size, 8, 6)
    strings = b"\0defined_target\0imported_target\0"
    data[0x200:0x200 + len(strings)] = strings
    defined = (1, 0x12, 0, 1, 0x1004, 4) if bits == 64 else (1, 0x1004, 4, 0x12, 0, 1)
    imported_name = strings.index(b"imported_target")
    imported = (imported_name, 0x22, 0, 0, 0, 0) if bits == 64 else (imported_name, 0, 0, 0x22, 0, 0)
    struct.pack_into(symbol_fmt, data, 0x300 + symbol_size, *defined)
    struct.pack_into(symbol_fmt, data, 0x300 + 2 * symbol_size, *imported)
    kind = 0x12345678 if bits == 64 else 0x77
    rows = rows if rows is not None else [(0x4000, 2, kind, -7), (0x4000 + word, 1, kind, 13)]
    for index, (address, symbol, relocation_type, addend) in enumerate(rows):
        fields = (address, (symbol << (32 if bits == 64 else 8)) | relocation_type)
        struct.pack_into(relocation_fmt, data, 0x500 + index * relocation_size, *(fields + (addend,) if rela else fields))
    if extra is not None:
        address, symbol, relocation_type, addend = extra
        fields = (address, (symbol << (32 if bits == 64 else 8)) | relocation_type)
        struct.pack_into(relocation_fmt, data, 0x600, *(fields + (addend,) if rela else fields))
    names = ["", ".text", ".dynstr", ".dynsym", ".got", ".rela.plt" if rela else ".rel.plt", ".shstrtab", ".rela.extra"]
    name_offsets, string_names = [], b""
    for name in names:
        name_offsets.append(len(string_names))
        string_names += name.encode() + b"\0"
    data[0x700:0x700 + len(string_names)] = string_names
    sections = [(0,) * 10,
                (name_offsets[1], 1, 6, 0x1000, 0x100, 16, 0, 0, 4, 0),
                (name_offsets[2], 3, 2, 0x2000, 0x200, len(strings), 0, 0, 1, 0),
                (name_offsets[3], 11, 2, 0x2100, 0x300, 3 * symbol_size, 2, 1, word, symbol_size),
                (name_offsets[4], 1, 3, 0x4000, 0x400, 2 * word, 0, 0, word, 0),
                (name_offsets[5], 4 if rela else 9, 2, 0x5000, 0x500, len(rows) * relocation_size, 3, 4, word, relocation_size),
                (name_offsets[6], 3, 0, 0, 0x700, len(string_names), 0, 0, 1, 0),
                (name_offsets[7], 4 if rela else 9, 2, 0x5100, 0x600, relocation_size if extra else 0, 3, 4, word, relocation_size)]
    for index, section in enumerate(sections):
        struct.pack_into(section_fmt, data, 0x900 + index * section_size, *section)
    return bytes(data), {"bits": bits, "order": order, "section_fmt": section_fmt, "sections": sections,
                         "section_size": section_size, "symbol_fmt": symbol_fmt, "symbol_size": symbol_size,
                         "relocation_fmt": relocation_fmt, "relocation_size": relocation_size, "names": names}


def change_section(data, layout, index, field, value):
    data = bytearray(data)
    section = list(layout["sections"][index])
    section[field] = value
    struct.pack_into(layout["section_fmt"], data, 0x900 + index * layout["section_size"], *section)
    return bytes(data)


def recover(data, layout, **options):
    return recover_dynamic_relocations(data, layout["sections"], layout["bits"], layout["order"],
                                       section_names=layout["names"], **options)


class ELFRelocationTests(unittest.TestCase):
    def test_rel_and_rela_in_both_classes_and_byte_orders(self):
        for bits in (32, 64):
            for order in ("<", ">"):
                for rela in (False, True):
                    with self.subTest(bits=bits, order=order, rela=rela):
                        data, layout = relocation_elf(bits, order, rela=rela)
                        image = load_binary(data)
                        self.assertEqual(image.warnings, [])
                        records = image.dynamic_relocations
                        self.assertEqual(len(records), 2)
                        self.assertEqual(records[0]["symbol_name"], "imported_target")
                        self.assertEqual(records[0]["binding"], 2)
                        self.assertFalse(records[0]["symbol_defined"])
                        self.assertEqual(records[0]["symbol_value"], 0)
                        self.assertEqual(records[1]["symbol_name"], "defined_target")
                        self.assertEqual(records[1]["symbol_value"], 0x1004)
                        self.assertTrue(records[1]["symbol_defined"])
                        self.assertEqual(records[1]["symbol_type"], 2)
                        self.assertEqual(records[1]["binding_name"], "global")
                        self.assertEqual(records[0]["address"], 0x4000)
                        self.assertEqual(records[0]["got_address"], 0x4000)
                        self.assertEqual(records[0]["type"], 0x12345678 if bits == 64 else 0x77)
                        self.assertEqual(records[0]["addend"], -7 if rela else None)
                        self.assertEqual(records[1]["addend"], 13 if rela else None)
                        self.assertEqual(records[0]["explicit_addend"], rela)
                        self.assertEqual(records[0]["record_offset"], 0x500)
                        self.assertEqual(records[0]["relocation_section_index"], 5)
                        self.assertEqual(records[0]["symbol_table_index"], 3)
                        self.assertEqual(image.metadata()["dynamic_relocations"], records)
                        self.assertEqual([item["name"] for item in image.functions], ["defined_target"])

    def test_relative_records_do_not_acquire_an_invented_symbol(self):
        data, layout = relocation_elf(rows=[(0x4000, 0, 1027, 42)], extra=(0x4008, 1, 1026, 0))
        records, warnings = recover(data, layout)
        self.assertEqual(warnings, [])
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["symbol_name"], "defined_target")
        self.assertEqual(records[0]["source"], "rela")

    def test_ordinary_symtab_relocations_are_skipped_without_error(self):
        data, layout = relocation_elf(file_type=1)
        image = load_binary(change_section(data, layout, 3, 1, 2))
        self.assertEqual(image.dynamic_relocations, [])
        self.assertEqual(image.warnings, [])
        self.assertEqual(image.functions[0]["name"], "defined_target")

    def test_duplicate_addresses_keep_separate_relocation_evidence(self):
        data, layout = relocation_elf(rows=[(0x4000, 1, 1026, 0), (0x4000, 2, 1026, 0)])
        records, warnings = recover(data, layout)
        self.assertEqual(warnings, [])
        self.assertEqual([item["symbol_name"] for item in records], ["defined_target", "imported_target"])
        self.assertNotEqual(records[0]["record_offset"], records[1]["record_offset"])

    def test_relocation_and_symbol_budgets_are_global(self):
        data, layout = relocation_elf(rows=[(0x4000, 1, 1026, 0)], extra=(0x4008, 2, 1026, 0))
        records, warnings = recover(data, layout, max_relocations=1)
        self.assertEqual([item["symbol_name"] for item in records], ["defined_target"])
        self.assertTrue(any("budget" in item for item in warnings))
        records, warnings = recover(data, layout, max_symbols=1)
        self.assertEqual([item["symbol_name"] for item in records], ["defined_target"])
        self.assertTrue(any("symbol lookup budget" in item for item in warnings))
        records, warnings = recover(data, layout, max_relocations=0)
        self.assertEqual(records, [])
        self.assertTrue(any("budget" in item for item in warnings))

    def test_symbol_cache_reuses_one_lookup_with_bounded_budget(self):
        data, layout = relocation_elf(rows=[(0x4000, 1, 1026, 0), (0x4008, 1, 1026, 0)])
        records, warnings = recover(data, layout, max_symbols=1)
        self.assertEqual(len(records), 2)
        self.assertEqual(warnings, [])

    def test_malformed_relocation_descriptors_are_rejected(self):
        data, layout = relocation_elf()
        for field, value in ((4, (1 << 64) - 1), (5, (1 << 64) - 1), (5, 25), (6, 100), (6, 1), (9, 0), (9, 8)):
            with self.subTest(field=field, value=value):
                image = load_binary(change_section(data, layout, 5, field, value))
                self.assertEqual(image.dynamic_relocations, [])
                self.assertTrue(image.warnings)

    def test_linked_symbol_and_string_tables_must_be_valid(self):
        data, layout = relocation_elf()
        for index, field, value in ((3, 9, 0), (3, 5, 25), (3, 4, (1 << 64) - 1),
                                     (3, 6, 4), (2, 1, 1), (2, 4, (1 << 64) - 1), (2, 5, (1 << 64) - 1)):
            with self.subTest(index=index, field=field):
                image = load_binary(change_section(data, layout, index, field, value))
                self.assertEqual(image.dynamic_relocations, [])
                self.assertTrue(image.warnings)

    def test_out_of_range_symbol_and_name_do_not_cross_linked_tables(self):
        data, layout = relocation_elf(rows=[(0x4000, 50, 1026, 0)])
        records, warnings = recover(data, layout)
        self.assertEqual(records, [])
        self.assertTrue(any("symbol index" in item for item in warnings))
        data, layout = relocation_elf(rows=[(0x4000, 1, 1026, 0)])
        bad = bytearray(data)
        struct.pack_into("<I", bad, 0x300 + layout["symbol_size"], 0xffffffff)
        records, warnings = recover(bytes(bad), layout)
        self.assertEqual(records, [])
        self.assertTrue(any("symbol name" in item for item in warnings))
        bad = bytearray(data)
        struct.pack_into("<H", bad, 0x300 + layout["symbol_size"] + 6, 100)
        records, warnings = recover(bytes(bad), layout)
        self.assertEqual(records, [])
        self.assertTrue(any("symbol section index" in item for item in warnings))
        records, warnings = recover(data, layout, max_name_bytes=5)
        self.assertEqual(records, [])
        self.assertTrue(any("name budget" in item for item in warnings))

    def test_truncated_table_does_not_return_an_unvalidated_prefix(self):
        data, layout = relocation_elf()
        records, warnings = recover(data[:0x500 + layout["relocation_size"]], layout)
        self.assertEqual(records, [])
        self.assertTrue(any("truncated" in item for item in warnings))

    def test_got_tag_requires_declared_extent_and_virtual_address(self):
        data, layout = relocation_elf(rows=[(0x6000, 1, 1026, 0)])
        records, warnings = recover(data, layout)
        self.assertEqual(warnings, [])
        self.assertEqual(records[0]["address"], 0x6000)
        self.assertIsNone(records[0]["got_address"])
        data, layout = relocation_elf(file_type=1)
        image = load_binary(data)
        self.assertEqual(image.dynamic_relocations[0]["address_kind"], "section_offset")
        self.assertIsNone(image.dynamic_relocations[0]["got_address"])

    def test_budget_options_reject_invalid_values(self):
        data, layout = relocation_elf()
        for options in ({"max_relocations": -1}, {"max_relocations": 65537}, {"max_symbols": True},
                        {"max_name_bytes": 0}, {"max_name_bytes": 257}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                recover(data, layout, **options)

    def test_new_model_field_has_compatible_independent_default(self):
        first = BinaryImage("elf", "arm64", 64, "little")
        second = BinaryImage("pe", "x86_64", 64, "little")
        self.assertEqual(first.dynamic_relocations, [])
        first.dynamic_relocations.append({"address": 1})
        self.assertEqual(second.dynamic_relocations, [])
        self.assertEqual(second.metadata()["dynamic_relocations"], [])


if __name__ == "__main__":
    unittest.main()
