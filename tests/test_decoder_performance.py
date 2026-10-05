"""Bulk decoder optimization retains register, control-flow and memory evidence."""
from __future__ import annotations

import importlib.util
import unittest
from unittest.mock import patch

from fangida.processors.decoder import NativeDecoder


@unittest.skipUnless(importlib.util.find_spec("capstone"), "Capstone unavailable")
class BulkDecoderEvidenceTests(unittest.TestCase):
    def test_cached_register_names_match_public_ir_for_all_native_architectures(self):
        import capstone

        for architecture, endian, encoded in (
            ("x86_64", "little", "48 89 d8 48 01 c8 48 8b 05 10000000 e8 01000000 c3 c3"),
            ("x86", "little", "89 d8 01 c8 a1 10200000 e8 01000000 c3 c3"),
            ("arm", "little", "0100a0e1 020080e0 04009fe5 000000eb 1eff2fe1"),
            ("arm", "big", "e1a00001 e0800002 e59f0004 eb000000 e12fff1e"),
            ("arm64", "little", "e00301aa 0000028b 40000058 00000094 c0035fd6"),
        ):
            with self.subTest(architecture=architecture, endian=endian):
                data = bytes.fromhex(encoded) * 31
                decoder = NativeDecoder(architecture, endian)
                expected, warnings = decoder.decode_bytes(data, 0x1000, max_instructions=len(data))
                self.assertFalse(warnings)
                original_name, original_access = capstone.CsInsn.reg_name, capstone.CsInsn.regs_access
                queried, accessed = [], []

                def register_name(instruction, register, default=None):
                    queried.append(register)
                    return original_name(instruction, register, default)

                def register_access(instruction):
                    accessed.append(instruction.address)
                    return original_access(instruction)

                with patch.object(capstone.CsInsn, "reg_name", register_name), \
                        patch.object(capstone.CsInsn, "regs_access", register_access):
                    actual, warnings = decoder.decode_bytes_fast(data, 0x1000,
                                                                  max_instructions=len(data))
                self.assertFalse(warnings)
                self.assertEqual(len(actual), len(expected))
                self.assertEqual(accessed, [instruction["addr"] for instruction in actual])
                self.assertEqual(len(queried), len(set(queried)))
                self.assertLess(len(queried), len(actual))
                stripped = [{**instruction, "arch_meta": {
                    key: value for key, value in instruction["arch_meta"].items()
                    if key != "memory_references"}} for instruction in actual]
                self.assertEqual(stripped, expected)
                if architecture != "x86":
                    self.assertTrue(any(instruction["arch_meta"].get("memory_references")
                                        for instruction in actual))
                self.assertTrue(any(instruction["branch_info"].get("kind") == "call"
                                    for instruction in actual))

    def test_failed_register_access_does_not_remove_the_instruction_or_poison_later_records(self):
        import capstone

        decoder = NativeDecoder("x86_64")
        data = bytes.fromhex("48 89 d8") * 3
        expected, warnings = decoder.decode_bytes(data, 0x1000)
        self.assertFalse(warnings)
        original = capstone.CsInsn.regs_access

        def access(instruction):
            if instruction.address == 0x1003:
                raise ValueError("fixture register access failure")
            return original(instruction)

        with patch.object(capstone.CsInsn, "regs_access", access):
            actual, warnings = decoder.decode_bytes_fast(data, 0x1000)
        self.assertFalse(warnings)
        expected[1].update(reads=(), writes=())
        self.assertEqual(actual, expected)

    def test_register_name_cache_belongs_to_each_decoder_batch(self):
        import capstone

        decoder = NativeDecoder("x86_64")
        original = capstone.CsInsn.reg_name
        queried = []

        def name(instruction, register, default=None):
            queried.append(register)
            return original(instruction, register, default)

        with patch.object(capstone.CsInsn, "reg_name", name):
            first, warnings = decoder.decode_bytes_fast(bytes.fromhex("48 89 d8") * 8, 0x1000)
            count = len(queried)
            second, more = decoder.decode_bytes_fast(bytes.fromhex("48 89 d8") * 8, 0x1000)
        self.assertFalse(warnings + more)
        self.assertEqual(first, second)
        self.assertEqual(len(queried), count * 2)

    def test_cached_none_register_name_retains_the_existing_value_contract(self):
        import capstone

        with patch.object(capstone.CsInsn, "reg_name", return_value=None) as lookup:
            records, warnings = NativeDecoder("x86_64").decode_bytes_fast(
                bytes.fromhex("48 89 d8") * 8, 0x1000)
        self.assertFalse(warnings)
        self.assertEqual(lookup.call_count, 2)
        self.assertTrue(all(instruction["reads"] == (None,) and instruction["writes"] == (None,)
                            for instruction in records))


if __name__ == "__main__":
    unittest.main()
