"""Known-answer Kotlin annotation and bytecode-outline fixtures."""
from __future__ import annotations

import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from fangida.core.apk_analyzer.dex_analyzer import parse_dex
from fangida.core.apk_analyzer.jvm_analyzer import parse_class
from fangida.core.apk_analyzer.pseudocode import method_signature, outline
from fangida.core.apk_analyzer.test_analyzer import sample_calling_class, sample_calling_dex, sample_class
from fangida.dispatcher import analyze


def annotated_dex() -> bytes:
    strings = [b"Lexample/Kt;", b"Ljava/lang/Object;", b"V", b"run",
               b"Lkotlin/Metadata;", b"k", b"mv", b"d2", b"sourceMethod"]
    data = bytearray(0x70)
    string_base = len(data)
    data.extend(bytes(len(strings) * 4))
    type_base = len(data)
    data.extend(bytes(4 * 4))
    proto_base = len(data)
    data.extend(bytes(12))
    method_base = len(data)
    data.extend(bytes(8))
    class_base = len(data)
    data.extend(bytes(32))
    class_data = len(data)
    data.extend(b"\x00\x00\x01\x00\x00\x01\x00")
    annotation_item = len(data)
    data.extend(bytes((1, 3, 3, 5, 4, 1, 6, 0x1c, 2, 4, 1, 4, 9,
                       7, 0x1c, 1, 0x17, 8)))
    annotation_set = len(data)
    data.extend(struct.pack("<II", 1, annotation_item))
    annotation_directory = len(data)
    data.extend(struct.pack("<IIII", annotation_set, 0, 0, 0))
    for index, value in enumerate(strings):
        struct.pack_into("<I", data, string_base + index * 4, len(data))
        data.append(len(value))
        data.extend(value + b"\x00")
    for index, string_index in enumerate((0, 1, 2, 4)):
        struct.pack_into("<I", data, type_base + index * 4, string_index)
    struct.pack_into("<III", data, proto_base, 2, 2, 0)
    struct.pack_into("<HHI", data, method_base, 0, 0, 3)
    struct.pack_into("<IIIIIIII", data, class_base, 0, 1, 1, 0, 0xffffffff,
                     annotation_directory, class_data, 0)
    data[:8] = b"dex\n035\x00"
    struct.pack_into("<III", data, 0x20, len(data), 0x70, 0x12345678)
    for header_offset, count, base in ((0x38, len(strings), string_base),
                                       (0x40, 4, type_base), (0x48, 1, proto_base),
                                       (0x58, 1, method_base), (0x60, 1, class_base)):
        struct.pack_into("<II", data, header_offset, count, base)
    return bytes(data)


def annotated_class() -> bytes:
    values = [b"ExampleKt", b"java/lang/Object", b"run", b"()V", b"Code",
              b"RuntimeVisibleAnnotations", b"Lkotlin/Metadata;", b"k", b"mv",
              b"d2", b"sourceMethod"]
    entries = [b"\x01" + struct.pack(">H", len(value)) + value for value in values]
    entries.insert(1, b"\x07\x00\x01")  # ExampleKt Class at index 2
    entries.insert(3, b"\x07\x00\x03")  # Object Class at index 4
    entries.append(b"\x03" + struct.pack(">i", 1))  # index 14
    entries.append(b"\x03" + struct.pack(">i", 9))  # index 15
    code = b"\xb1"
    code_attribute = (struct.pack(">HHI", 0, 0, len(code)) + code +
                      struct.pack(">HH", 0, 0))
    annotation = (struct.pack(">HHHH", 1, 9, 3, 10) + b"I" + struct.pack(">H", 14) +
                  struct.pack(">H", 11) + b"[" + struct.pack(">H", 2) +
                  b"I" + struct.pack(">H", 14) + b"I" + struct.pack(">H", 15) +
                  struct.pack(">H", 12) + b"[" + struct.pack(">H", 1) +
                  b"s" + struct.pack(">H", 13))
    return (struct.pack(">IHHH", 0xcafebabe, 0, 52, len(entries) + 1) + b"".join(entries) +
            struct.pack(">HHHHH", 0x21, 2, 4, 0, 0) + struct.pack(">H", 1) +
            struct.pack(">HHHH", 1, 5, 6, 1) + struct.pack(">HI", 7, len(code_attribute)) +
            code_attribute + struct.pack(">H", 1) +
            struct.pack(">HI", 8, len(annotation)) + annotation)


class KotlinMetadataAndOutlineTests(unittest.TestCase):
    def test_dex_annotation_not_just_string_hint(self) -> None:
        result = parse_dex(annotated_dex())
        self.assertEqual(result.metadata["kotlin_metadata_count"], 1)
        metadata = result.metadata["kotlin_metadata"][0]
        self.assertEqual(metadata["metadata_version"], [1, 9])
        self.assertEqual(metadata["kind"], "class")
        self.assertEqual(metadata["data2"], ["sourceMethod"])
        self.assertIn("kotlin_metadata_annotation", result.functions[0]["kotlin_hints"])

    def test_jvm_annotation_and_outline(self) -> None:
        result = parse_class(annotated_class(), "ExampleKt.class")
        self.assertEqual(result.metadata["kotlin_metadata"]["metadata_version"], [1, 9])
        self.assertEqual(result.metadata["kotlin_metadata"]["data2"], ["sourceMethod"])
        function = result.functions[0]
        self.assertIn("kotlin_metadata_annotation", function["kotlin_hints"])
        self.assertIn("return;", function["pseudoc"])
        self.assertEqual(function["pseudoc_producer"], "fangida_bytecode_outline")
        self.assertFalse(function["pseudoc_truncated"])

    def test_descriptor_string_alone_is_only_a_hint(self) -> None:
        result = parse_class(sample_class(), "Foo.class")
        self.assertTrue(result.metadata["kotlin_metadata_hint"])
        self.assertIsNone(result.metadata["kotlin_metadata"])
        self.assertNotIn("kotlin_metadata_annotation", result.functions[0]["kotlin_hints"])

    def test_observed_calls_are_readable_but_values_symbolic(self) -> None:
        jvm = parse_class(sample_calling_class(), "Foo.class").functions[0]["pseudoc"]
        dex = parse_dex(sample_calling_dex()).functions[0]["pseudoc"]
        self.assertIn("java.lang.System.exit", jvm)
        self.assertIn("android.util.Log.e", dex)
        self.assertIn("symbolic args", jvm)
        self.assertIn("symbolic args", dex)

    def test_worker_aggregates_actual_annotations_and_pseudoc(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "annotated.apk"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("classes.dex", annotated_dex())
                archive.writestr("ExampleKt.class", annotated_class())
            result = analyze(path)
            self.assertEqual(result.metadata["kotlin_metadata_count"], 2)
            self.assertEqual({item["source"] for item in
                              result.metadata["kotlin_metadata_classes"]},
                             {"classes.dex", "ExampleKt.class"})
            self.assertTrue(any(method.get("pseudoc_producer") == "fangida_bytecode_outline"
                                for method in result.functions))

    def test_malformed_dex_annotation_retains_method(self) -> None:
        data = bytearray(annotated_dex())
        class_offset = struct.unpack_from("<I", data, 0x64)[0]
        struct.pack_into("<I", data, class_offset + 20, len(data) + 100)
        result = parse_dex(bytes(data))
        self.assertEqual(result.metadata["defined_method_count"], 1)
        self.assertEqual(result.metadata["kotlin_metadata_count"], 0)
        self.assertTrue(any("Annotation decode stopped" in warning for warning in result.warnings))

    def test_branch_targets_and_bounded_output(self) -> None:
        rows = [
            {"addr": 100, "size": 3, "mnemonic": "ifeq", "operands": ["0004"],
             "arch_meta": {"bytecode_offset": 0, "opcode": 0x99}},
            {"addr": 103, "size": 1, "mnemonic": "return", "operands": [],
             "arch_meta": {"bytecode_offset": 3, "opcode": 0xb1}},
            {"addr": 104, "size": 1, "mnemonic": "return", "operands": [],
             "arch_meta": {"bytecode_offset": 4, "opcode": 0xb1}},
        ]
        text, truncated = outline("Example->run", "()V", "jvm", rows, 5)
        self.assertIn("if (/* bytecode condition */) goto L0004", text)
        self.assertIn("L0004:", text)
        self.assertFalse(truncated)
        self.assertEqual(method_signature("Example->f", "(ILjava/lang/String;)Z"),
                         "boolean f(int arg0, java.lang.String arg1)")

    def test_dex_if_opcodes_keep_conditional_semantics(self) -> None:
        # if-eq v0,v1,+2 (format 22t), followed by two return-void rows.
        code = b"\x32\x10\x02\x00\x0e\x00\x0e\x00"
        rows = [
            {"addr": 0, "size": 4, "mnemonic": "op_32", "operands": ["0002"],
             "arch_meta": {"code_unit_offset": 0, "opcode": 0x32}},
            {"addr": 4, "size": 2, "mnemonic": "return-void", "operands": [],
             "arch_meta": {"code_unit_offset": 2, "opcode": 0x0e}},
            {"addr": 6, "size": 2, "mnemonic": "return-void", "operands": [],
             "arch_meta": {"code_unit_offset": 3, "opcode": 0x0e}},
        ]
        text, truncated = outline("Lexample/Kt;->run", "()V", "dex", rows, 8,
                                  bytecode=code)
        self.assertIn("if (/* bytecode condition */) goto L0002", text)
        self.assertFalse(truncated)

    def test_branch_outlines_from_parsed_class_and_dex(self) -> None:
        jvm = bytearray(sample_calling_class())
        jvm_start = parse_class(bytes(jvm), "Foo.class").functions[0]["start"]
        jvm[jvm_start:jvm_start + 5] = b"\x99\x00\x04\xb1\xb1"
        jvm_outline = parse_class(bytes(jvm), "Foo.class").functions[0]["pseudoc"]
        self.assertIn("goto L0004", jvm_outline)
        self.assertIn("L0004:", jvm_outline)

        dex = bytearray(sample_calling_dex())
        dex_start = parse_dex(bytes(dex)).functions[0]["start"] + 16
        struct.pack_into("<HHHHH", dex, dex_start, 0x0038, 3, 0x000e, 0x000e, 0)
        dex_outline = parse_dex(bytes(dex)).functions[0]["pseudoc"]
        self.assertIn("if (/* bytecode condition */) goto L0003", dex_outline)
        self.assertIn("L0003:", dex_outline)


if __name__ == "__main__":
    unittest.main()
