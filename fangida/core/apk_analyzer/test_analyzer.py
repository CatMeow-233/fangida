"""Small known-answer inputs exercise the worker without Android toolchains."""
from __future__ import annotations

import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from fangida.core.apk_analyzer.dex_analyzer import parse_dex
from fangida.core.apk_analyzer.jvm_analyzer import parse_class
from fangida.dispatcher import analyze


def sample_dex() -> bytes:
    strings = [b"Lcom/example/Foo;", b"Ljava/lang/Object;", b"V", b"run", b"Lkotlin/Metadata;"]
    data = bytearray(0x70)
    strings_off = len(data)
    data.extend(bytes(len(strings) * 4))
    types_off = len(data)
    data.extend(bytes(3 * 4))
    proto_off = len(data)
    data.extend(bytes(12))
    method_off = len(data)
    data.extend(bytes(8))
    class_off = len(data)
    data.extend(bytes(32))
    class_data_off = len(data)
    data.extend(b"\x00\x00\x01\x00\x00\x01\x00")  # one direct method, no code
    for index, value in enumerate(strings):
        struct.pack_into("<I", data, strings_off + index * 4, len(data))
        data.append(len(value))
        data.extend(value + b"\x00")
    for index, string_index in enumerate((0, 1, 2)):
        struct.pack_into("<I", data, types_off + index * 4, string_index)
    struct.pack_into("<III", data, proto_off, 2, 2, 0)
    struct.pack_into("<HHI", data, method_off, 0, 0, 3)
    struct.pack_into("<IIIIIIII", data, class_off, 0, 1, 1, 0, 0xffffffff, 0, class_data_off, 0)
    data[:8] = b"dex\n035\x00"
    struct.pack_into("<III", data, 0x20, len(data), 0x70, 0x12345678)
    for header_offset, count, offset in (
        (0x38, len(strings), strings_off), (0x40, 3, types_off),
        (0x48, 1, proto_off), (0x58, 1, method_off), (0x60, 1, class_off),
    ):
        struct.pack_into("<II", data, header_offset, count, offset)
    return bytes(data)


def sample_class() -> bytes:
    entries = [
        b"\x01\x00\x03Foo", b"\x07\x00\x01",
        b"\x01\x00\x10java/lang/Object", b"\x07\x00\x03",
        b"\x01\x00\x03run", b"\x01\x00\x03()V",
        b"\x01\x00\x11Lkotlin/Metadata;",
    ]
    return (struct.pack(">IHHH", 0xcafebabe, 0, 52, 8) + b"".join(entries) +
            struct.pack(">HHHHH", 0x21, 2, 4, 0, 0) +
            struct.pack(">H", 1) + struct.pack(">HHHH", 1, 5, 6, 0) +
            struct.pack(">H", 0))


def sample_calling_class() -> bytes:
    utf8 = lambda value: b"\x01" + struct.pack(">H", len(value)) + value
    entries = [
        utf8(b"Foo"), b"\x07\x00\x01", utf8(b"java/lang/Object"), b"\x07\x00\x03",
        utf8(b"run"), utf8(b"()V"), utf8(b"Code"), utf8(b"java/lang/System"),
        b"\x07\x00\x08", utf8(b"exit"), utf8(b"(I)V"),
        b"\x0c\x00\x0a\x00\x0b", b"\x0a\x00\x09\x00\x0c",
    ]
    bytecode = b"\x03\xb8\x00\x0d\xb1"  # iconst_0, invokestatic #13, return
    code_attribute = struct.pack(">HHI", 1, 0, len(bytecode)) + bytecode + struct.pack(">HH", 0, 0)
    return (struct.pack(">IHHH", 0xcafebabe, 0, 52, len(entries) + 1) + b"".join(entries) +
            struct.pack(">HHHHH", 0x21, 2, 4, 0, 0) + struct.pack(">H", 1) +
            struct.pack(">HHHH", 1, 5, 6, 1) +
            struct.pack(">HI", 7, len(code_attribute)) + code_attribute + struct.pack(">H", 0))


def sample_calling_dex() -> bytes:
    strings = [b"Lcom/example/Foo;", b"Ljava/lang/Object;", b"V", b"run",
               b"Landroid/util/Log;", b"e"]
    data = bytearray(0x70)
    strings_off = len(data)
    data.extend(bytes(len(strings) * 4))
    types_off = len(data)
    data.extend(bytes(4 * 4))
    proto_off = len(data)
    data.extend(bytes(12))
    method_off = len(data)
    data.extend(bytes(2 * 8))
    class_off = len(data)
    data.extend(bytes(32))
    class_data_off = len(data)
    code_off = class_data_off + 8
    assert 128 <= code_off < 16_384
    data.extend(b"\x00\x00\x01\x00\x00\x01" + bytes(((code_off & 0x7f) | 0x80, code_off >> 7)))
    data.extend(struct.pack("<HHHHII", 1, 0, 1, 0, 0, 5))
    data.extend(struct.pack("<HHHHH", 0x0012, 0x1071, 1, 0, 0x000e))
    for index, value in enumerate(strings):
        struct.pack_into("<I", data, strings_off + index * 4, len(data))
        data.append(len(value))
        data.extend(value + b"\x00")
    for index, string_index in enumerate((0, 1, 2, 4)):
        struct.pack_into("<I", data, types_off + index * 4, string_index)
    struct.pack_into("<III", data, proto_off, 2, 2, 0)
    struct.pack_into("<HHI", data, method_off, 0, 0, 3)
    struct.pack_into("<HHI", data, method_off + 8, 3, 0, 5)
    struct.pack_into("<IIIIIIII", data, class_off, 0, 1, 1, 0, 0xffffffff, 0, class_data_off, 0)
    data[:8] = b"dex\n035\x00"
    struct.pack_into("<III", data, 0x20, len(data), 0x70, 0x12345678)
    for header_offset, count, offset in (
        (0x38, len(strings), strings_off), (0x40, 4, types_off),
        (0x48, 1, proto_off), (0x58, 2, method_off), (0x60, 1, class_off),
    ):
        struct.pack_into("<II", data, header_offset, count, offset)
    return bytes(data)


class AndroidAnalyzerTests(unittest.TestCase):
    def test_dex_class_and_method(self) -> None:
        summary = parse_dex(sample_dex())
        self.assertEqual(summary.metadata["class_count"], 1)
        self.assertEqual(summary.metadata["defined_method_count"], 1)
        self.assertTrue(summary.metadata["kotlin_metadata_hint"])
        self.assertEqual(summary.functions[0]["name"], "Lcom/example/Foo;->run")
        self.assertEqual(summary.functions[0]["descriptor"], "()V")

    def test_jvm_class_and_method(self) -> None:
        summary = parse_class(sample_class(), "Foo.class")
        self.assertEqual(summary.metadata["method_count"], 1)
        self.assertEqual(summary.functions[0]["name"], "Foo->run")
        self.assertTrue(summary.metadata["kotlin_metadata_hint"])

    def test_jvm_bytecode_direct_api_reference(self) -> None:
        summary = parse_class(sample_calling_class(), "Foo.class")
        instructions = summary.functions[0]["disassembly"]
        call = instructions[1]
        self.assertEqual((call["mnemonic"], call["size"]), ("invokestatic", 3))
        self.assertEqual(call["addr"], summary.functions[0]["start"] + 1)
        self.assertEqual(call["arch_meta"]["address_space"], "file_offset")
        self.assertEqual(summary.metadata["api_calls"][0]["target"], "java/lang/System->exit")
        self.assertEqual(summary.functions[0]["calls"][0]["addr"], call["addr"])

    def test_dex_bytecode_direct_api_reference(self) -> None:
        summary = parse_dex(sample_calling_dex())
        instructions = summary.functions[0]["disassembly"]
        call = instructions[1]
        self.assertEqual((call["mnemonic"], call["size"]), ("invoke-static", 6))
        self.assertEqual(call["addr"], summary.functions[0]["start"] + 18)
        self.assertEqual(call["arch_meta"]["address_space"], "file_offset")
        self.assertEqual(summary.metadata["api_calls"][0]["target"], "Landroid/util/Log;->e")

    def test_operands_that_look_like_invokes_are_not_calls(self) -> None:
        dex = bytearray(sample_calling_dex())
        dex_start = parse_dex(bytes(dex)).functions[0]["start"] + 16
        struct.pack_into("<HHHHH", dex, dex_start, 0x0014, 0x0071, 0, 0x000e, 0x000e)
        dex_summary = parse_dex(bytes(dex))
        self.assertEqual(dex_summary.metadata["direct_invocations"], [])
        self.assertEqual(dex_summary.functions[0]["disassembly"][0]["size"], 6)

        class_file = bytearray(sample_calling_class())
        class_start = parse_class(bytes(class_file), "Foo.class").functions[0]["start"]
        class_file[class_start:class_start + 5] = b"\xb2\x00\xb8\xb1\x00"
        class_summary = parse_class(bytes(class_file), "Foo.class")
        self.assertEqual(class_summary.metadata["direct_invocations"], [])
        self.assertEqual(class_summary.functions[0]["disassembly"][0]["size"], 3)

    def test_worker_aggregates_api_calls(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "sample.apk"
            with zipfile.ZipFile(apk, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("classes.dex", sample_calling_dex())
                archive.writestr("Foo.class", sample_calling_class())
            result = analyze(apk)
            self.assertEqual(len(result.metadata["api_calls"]), 2)
            self.assertEqual(len(result.metadata["direct_invocations"]), 2)
            self.assertEqual(len([f for f in result.functions if f.get("disassembly")]), 2)

    def test_apk_worker_multidomain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "sample.apk"
            with zipfile.ZipFile(apk, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("AndroidManifest.xml", b"manifest")
                archive.writestr("classes.dex", sample_dex())
                archive.writestr("Foo.class", sample_class())
            result = analyze(apk)
            self.assertEqual(result.status, "partial")
            self.assertEqual(result.metadata["class_count"], 2)
            self.assertEqual(result.metadata["method_count"], 2)
            self.assertTrue(result.metadata["archive"]["android_manifest_present"])
            self.assertEqual({entry["kind"] for entry in result.functions}, {"dex", "jvm"})

    def test_archive_traversal_name_is_not_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "sample.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("../classes.dex", sample_dex())
            result = analyze(apk)
            self.assertEqual(result.metadata["class_count"], 0)
            self.assertTrue(any("Unsafe archive entry path" in warning for warning in result.warnings))

    def test_archive_decompression_budget(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "sample.apk"
            with zipfile.ZipFile(apk, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("classes.dex", sample_dex())
            result = analyze(apk, max_bytes=8)
            self.assertEqual(result.metadata["class_count"], 0)
            self.assertTrue(any("budget" in warning for warning in result.warnings))

    def test_truncated_dex_retains_partial_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            dex = Path(directory) / "sample.dex"
            dex.write_bytes(b"dex\n035\x00")
            result = analyze(dex)
            self.assertEqual(result.status, "partial")
            self.assertTrue(any("DEX parse failed" in warning for warning in result.warnings))


if __name__ == "__main__":
    unittest.main()
