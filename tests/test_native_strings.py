"""字符串地址映射和扫描边界回归；真实引用另由xref模块验证。"""
from pathlib import Path
import struct
import tempfile
import unittest

from fangida.addresses import NativeAddressMap, native_addresses_for_offset
from fangida.core.kkagent.strings import scan_native_strings
from fangida.core.kkagent.test_native import elf64_with_symbols
from fangida.dispatcher import AnalysisService
from fangida.gui_modules.navigation import AddressIndex, Location
from fangida.loaders.models import BinaryImage
from fangida.settings import Settings
from fangida.plugins.sqlite_storage import SQLiteAnalysisDatabase


class NativeAddressMapTests(unittest.TestCase):
    def test_file_backing_allocation_virtual_length_and_fat_offsets(self):
        sections = [
            {"offset": 0x210, "address": 0x100001010, "size": 32, "file_size": 12},
            {"offset": 0x210, "address": 0x3000, "size": 100, "file_backed": False},
            {"offset": 0x210, "address": 0x4000, "size": 100, "type": 8},
            {"offset": 0x210, "address": 0x5000, "size": 100, "allocated": False},
            {"offset": 0x240, "address": 0x140002000, "size": 32, "virtual_size": 8},
        ]
        mapping = NativeAddressMap(sections)
        self.assertEqual(mapping.addresses_for_offset(0x215), (0x100001015,))
        self.assertEqual(mapping.ranges_for_offset(0x215, 100), ((0x100001015, 7),))
        self.assertEqual(mapping.addresses_for_offset(0x21c), ())
        self.assertEqual(mapping.addresses_for_offset(0x247), (0x140002007,))
        self.assertEqual(mapping.addresses_for_offset(0x248), ())
        self.assertEqual(native_addresses_for_offset(0x215, sections, kind="apk"), ())

    def test_overlapping_mappings_are_not_silently_selected_or_duplicated(self):
        sections = [{"offset": 10, "address": address, "size": 10}
                    for address in (0x1000, 0x2000, 0x1000)]
        self.assertEqual(native_addresses_for_offset(12, sections), (0x1002, 0x2002))
        self.assertEqual(NativeAddressMap(sections).ranges_for_offset(12, 20),
                         ((0x1002, 8), (0x2002, 8)))

    def test_nonallocated_legacy_elf_and_invalid_ranges_are_not_mapped(self):
        sections = [{"offset": 0, "address": 0, "size": 50, "type": 3},
                    {"offset": 0, "address": 0x1000, "size": -1},
                    {"offset": True, "address": 0x2000, "size": 50},
                    {"offset": 0, "address": (1 << 64) - 2, "size": 4}]
        self.assertEqual(native_addresses_for_offset(1, sections, kind="elf"), ())
        for value in (True, -1, 1 << 64):
            with self.assertRaises(ValueError):
                native_addresses_for_offset(value, sections)
        sections.append({"offset": 0, "address": 0, "size": 50, "allocated": True})
        self.assertEqual(native_addresses_for_offset(1, sections, kind="elf"), (1,))


class NativeStringScanTests(unittest.TestCase):
    def test_data_literals_are_not_hidden_by_the_old_code_string_cap(self):
        code_noise = b"CODE\0" * 1100
        data = code_noise + b"real string\0"
        image = BinaryImage("elf", "x86_64", 64, "little", sections=[
            {"offset": 0, "address": 0x1000, "size": len(code_noise), "executable": True},
            {"offset": len(code_noise), "address": 0x8000, "size": 12, "allocated": True}])
        bounded, summary = scan_native_strings(data, image)
        self.assertEqual(len(bounded), 1000)
        self.assertEqual(bounded[0]["value"], "real string")
        self.assertEqual((bounded[0]["offset"], bounded[0]["address"], bounded[0]["length"]),
                         (len(code_noise), 0x8000, 11))
        self.assertTrue(summary["truncated"])
        full, full_summary = scan_native_strings(data, image, full_analysis=True)
        self.assertEqual(len(full), 1101)
        self.assertFalse(full_summary["truncated"])
        self.assertEqual({item["offset"] for item in full}, set(range(0, len(code_noise), 5)) | {len(code_noise)})

    def test_unmapped_and_multimapped_strings_keep_original_fields(self):
        data = b"hello\0world\0"
        image = BinaryImage("pe", "x86", 32, "little", sections=[
            {"offset": 0, "address": address, "size": 5} for address in (0x1000, 0x2000)])
        strings, _ = scan_native_strings(data, image, full_analysis=True)
        first, second = strings
        self.assertEqual(first["addresses"], [0x1000, 0x2000])
        self.assertNotIn("address", first)
        self.assertEqual(second, {"offset": 6, "value": "world", "length": 5})

    def test_string_mapping_does_not_extend_into_unmapped_tail(self):
        image = BinaryImage("pe", "x86", 32, "little", sections=[
            {"offset": 0, "address": 0x2000, "size": 12, "file_size": 12, "virtual_size": 5}])
        strings, _ = scan_native_strings(b"hello world\0", image)
        self.assertEqual(strings[0]["length"], 11)
        self.assertEqual(strings[0]["address_ranges"], [[0x2000, 5]])
        self.assertEqual(strings[0]["data_ranges"], [[0x2000, 5]])


def string_elf() -> bytes:
    data = bytearray(elf64_with_symbols())
    # lea rdi,[rip+0xff9]; ret, with a file-backed .rodata declaration.
    data[0x100:0x108] = bytes.fromhex("48 8d 3d f9 0f 00 00 c3")
    struct.pack_into("<Q", data, 0x40 + 32, 8)
    struct.pack_into("<Q", data, 0x40 + 40, 8)
    struct.pack_into("<Q", data, 0x240 + 32, 8)
    struct.pack_into("<Q", data, 0x180 + 24 + 16, 8)
    struct.pack_into("<H", data, 0x3c, 6)
    names = b"\0.text\0.shstrtab\0.symtab\0.strtab\0.rodata\0"
    data[0x120:0x120 + len(names)] = names
    struct.pack_into("<Q", data, 0x280 + 32, len(names))
    text = b"hello string\0"
    data[0x380:0x380 + len(text)] = text
    struct.pack_into("<IIQQQQIIQQ", data, 0x340, 33, 1, 2, 0x402000,
                     0x380, len(text), 0, 0, 1, 0)
    return bytes(data)


class StringAnalysisIntegrationTests(unittest.TestCase):
    def test_real_elf_string_reference_survives_database_without_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "strings.elf"
            path.write_bytes(string_elf())
            with AnalysisService(Settings(analyze_threads=2)) as service:
                result = service.analyze(path, full_analysis=True, use_ghidra=False)
            self.assertNotEqual(result.status, "error", result.warnings)
            string = next(item for item in result.strings if item["value"] == "hello string")
            self.assertEqual((string["offset"], string["address"]), (0x380, 0x402000))
            self.assertTrue(any(item["dst"] == 0x402000 and item["kind"] == "data" for item in result.xrefs))
            db_path = Path(directory) / "strings.fdb"
            store = SQLiteAnalysisDatabase(db_path, create=True)
            try:
                identifier = store.save_analysis(path, result)
            finally:
                store.close()
            path.unlink()
            store = SQLiteAnalysisDatabase(db_path, read_only=True)
            try:
                restored = store.get_snapshot(identifier)
            finally:
                store.close()
            # SQLite API 保留独立快照记录；不重新读取或分析已经删除的原文件。
            self.assertEqual(restored["strings"], result.to_dict()["strings"])
            index = AddressIndex({"Strings": restored["strings"], "Sections": restored["metadata"]["sections"],
                                  "Xrefs": restored["xrefs"]}, kind="elf")
            selected = next(i for i, item in enumerate(restored["strings"]) if item["value"] == "hello string")
            self.assertEqual(index.location_for_row("Strings", selected), Location(0x402000))
            self.assertEqual(index.incoming(Location(0x402000))[0].src.address, 0x401000)


if __name__ == "__main__":
    unittest.main()
