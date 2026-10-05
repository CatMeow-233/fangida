"""Typed A64 register addresses and scalar SIMD raw-bit memory accesses."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest

from fangida.plugins.pseudoc.microcode import Expression, constant, evaluate_expression, lift_instruction
from tests.test_pseudoc import instruction as ins


def resolve_load(expression, bits):
    """Supply only the memory result; evaluate all width changes normally."""
    expression = Expression.from_dict(expression) if isinstance(expression, dict) else expression
    if expression.opcode == "load":
        return constant(bits, expression.width)
    return replace(expression, args=tuple(resolve_load(child, bits) for child in expression.args))


class ARM64IndexedMemoryTests(unittest.TestCase):
    def test_scalar_simd_loads_write_full_128_bits_with_zero_upper(self):
        for register, width in (("s0", 32), ("d31", 64)):
            for mnemonic, address in (("ldr", "[x1]"), ("ldur", "[x29, #-4]"), ("ldr", "#0x1004")):
                with self.subTest(register=register, mnemonic=mnemonic, address=address):
                    row = lift_instruction(ins(0x1000, mnemonic, register, address), "arm64")
                    self.assertTrue(row["supported"])
                    self.assertEqual(row["memory_effect"], "read")
                    operation = row["operations"][0]
                    self.assertEqual(operation["width"], 128)
                    self.assertEqual(operation["attributes"]["destination_width"], 128)
                    self.assertEqual(operation["attributes"]["storage_width"], 128)
                    self.assertEqual(operation["attributes"]["memory_width"], width)
                    self.assertEqual(operation["attributes"]["upper_lanes"], "zero")
                    expression = operation["expression"]
                    self.assertEqual(expression["opcode"], "zext")
                    self.assertEqual(expression["args"][0]["opcode"], "load")
                    self.assertEqual(expression["args"][0]["width"], width)
                    patterns = (0, 1, (1 << width) - 1, 1 << (width - 1),
                        0x7f800001 if width == 32 else 0x7ff0000000000001)
                    for bits in patterns:
                        self.assertEqual(evaluate_expression(resolve_load(expression, bits)), bits)
                    self.assertNotIn(operation["output"], row["reads"])

    def test_scalar_simd_stores_read_only_low_bit_pattern(self):
        for register, width in (("s0", 32), ("d31", 64)):
            for mnemonic in ("str", "stur"):
                with self.subTest(register=register, mnemonic=mnemonic):
                    row = lift_instruction(ins(0x1000, mnemonic, register, "[x1]"), "arm64")
                    self.assertTrue(row["supported"])
                    operation = row["operations"][0]
                    self.assertEqual(operation["opcode"], "store")
                    self.assertEqual(operation["width"], width)
                    source = operation["inputs"][1]
                    self.assertEqual(source["opcode"], "extract")
                    self.assertEqual(source["args"][0]["width"], 128)
                    root = "v" + register[1:]
                    pattern = 0x112233445566778899aabbccddeeff00
                    self.assertEqual(evaluate_expression(source, {root: pattern}), pattern & ((1 << width) - 1))
                    self.assertIn(root, row["reads"])
                    self.assertNotIn(root, row["writes"])
                    self.assertEqual(row["flag_effect"], "preserve")
                    self.assertEqual(row["memory_effect"], "write")

    def test_scalar_simd_pair_access_offsets_and_writeback(self):
        for first, second, width in (("s0", "s1", 32), ("d0", "d1", 64)):
            for mnemonic in ("ldp", "stp"):
                with self.subTest(first=first, mnemonic=mnemonic):
                    row = lift_instruction(ins(0x1000, mnemonic, first, second, "[sp]", "#16"), "arm64")
                    self.assertTrue(row["supported"])
                    second_operation = row["operations"][1]
                    load = second_operation["expression"]["args"][0] if mnemonic == "ldp" else None
                    address = load["args"][0] if load else second_operation["inputs"][0]
                    self.assertEqual(address["name"], f"(sp + {width // 8})")
                    self.assertEqual(row["operations"][-1]["opcode"], "address_writeback")
                    self.assertEqual(row["operations"][-1]["attributes"]["after_access"], True)
        for instruction in (ins(0x1000, "ldp", "s0", "s0", "[sp]"),
                ins(0x1000, "ldp", "s0", "d1", "[sp]"),
                ins(0x1000, "stur", "s0", "[sp, #-4]!"),
                ins(0x1000, "ldrb", "s0", "[x1]")):
            self.assertFalse(lift_instruction(instruction, "arm64")["supported"])

    def test_uxtw_uses_low_32_bits_before_extending_and_shifting(self):
        row = lift_instruction(ins(0x1000, "ldr", "x8", "[x10, w8, uxtw #3]"), "arm64")
        self.assertTrue(row["supported"])
        address = row["operations"][0]["expression"]["args"][0]
        self.assertEqual(address["opcode"], "add")
        extended = address["args"][1]["args"][0]
        self.assertEqual(extended["opcode"], "zext")
        self.assertEqual(extended["args"][0]["opcode"], "extract")
        self.assertEqual(extended["args"][0]["width"], 32)
        for index in (0, 1, 0x80000000, 0xffffffff, 0xdeadbeef00000003, 0xffffffffffffffff):
            self.assertEqual(evaluate_expression(address, {"x10": 0x1000, "x8": index}),
                (0x1000 + ((index & 0xffffffff) << 3)) & ((1 << 64) - 1))
        self.assertEqual(set(row["reads"]), {"x10", "x8"})

    def test_sxtw_extends_sign_before_unsigned_address_shift(self):
        row = lift_instruction(ins(0x1000, "ldr", "w0", "[sp, w2, sxtw #2]"), "arm64")
        self.assertTrue(row["supported"])
        address = row["operations"][0]["expression"]["args"][0]
        self.assertEqual(address["args"][1]["args"][0]["opcode"], "sext")
        for index, signed in ((0, 0), (1, 1), (0x7fffffff, 0x7fffffff),
                (0x80000000, -0x80000000), (0xffffffff, -1), (0xffff0000ffffffff, -1)):
            self.assertEqual(evaluate_expression(address, {"sp": 0x1000, "x2": index}),
                (0x1000 + (signed << 2)) & ((1 << 64) - 1))
    def test_x_index_offsets_and_signed_load_access_size(self):
        for mnemonic, destination, operand, values, expected in (
                ("ldrsw", "x0", "[x9, x8, lsl #2]", {"x9": 0x1000, "x8": 3}, 0x100c),
                ("ldr", "x0", "[x1, x2]", {"x1": 0x1000, "x2": 3}, 0x1003),
                ("ldr", "x0", "[x1, x2, sxtx #3]", {"x1": 0x1000, "x2": (1 << 64) - 1}, 0xff8),
                ("ldr", "d0", "[x1, xzr, lsl #3]", {"x1": 0x1000}, 0x1000)):
            with self.subTest(operand=operand):
                row = lift_instruction(ins(0x1000, mnemonic, destination, operand), "arm64")
                self.assertTrue(row["supported"])
                expression = row["operations"][0]["expression"]
                if expression["opcode"] in {"sext", "zext"}:
                    expression = expression["args"][0]
                self.assertEqual(evaluate_expression(expression["args"][0], values), expected)
                if mnemonic == "ldrsw":
                    self.assertEqual(expression["width"], 32)

    def test_invalid_register_offsets_remain_opaque(self):
        for operand in ("[x1, w2]", "[x1, x2, uxtw #3]", "[x1, w2, lsl #3]",
                "[x1, x2, lsl #2]", "[x1, x2, lsl #64]", "[x1, x2, asr #3]",
                "[x1, wsp, uxtw #3]", "[w1, x2]", "[xzr, x2]", "[x1, x2, lsl]",
                "[x1, x2, lsl #-1]", "[x1, x2, lsl #3]!", "[x1, x2, lsl #3, #4]"):
            with self.subTest(operand=operand):
                self.assertFalse(lift_instruction(ins(0x1000, "ldr", "x0", operand), "arm64")["supported"])
        for instruction in (ins(0x1000, "ldur", "x0", "[x1, x2]"),
                ins(0x1000, "ldr", "x0", "[x1, x2]", "#8"),
                ins(0x1000, "ldp", "x0", "x3", "[x1, x2]")):
            self.assertFalse(lift_instruction(instruction, "arm64")["supported"])

    def test_real_uncovered_memory_forms_are_supported(self):
        cases = (
            (0x1b824c, "str", "s0", "[x3]"), (0x1b8314, "ldr", "s1", "[x15]"),
            (0x1b8498, "ldr", "s1", "[x16]"), (0x1b8328, "stur", "s1", "[x29, #-4]"),
            (0x1b8708, "str", "d0", "[x14]"), (0x1b87e0, "ldr", "d1", "[x14]"),
            (0x1b87f4, "stur", "d1", "[x29, #-8]"), (0x1b8c0c, "ldr", "d0", "[x8]"),
            (0x1b88bc, "ldur", "s0", "[x29, #-4]"), (0x1b8c64, "ldur", "d0", "[x29, #-8]"),
            (0x1d338c, "ldr", "x8", "[x10, w8, uxtw #3]"),
            (0x1bd07c, "ldrsw", "x11", "[x9, x8, lsl #2]"))
        for case in cases:
            with self.subTest(address=hex(case[0])):
                self.assertTrue(lift_instruction(ins(*case), "arm64")["supported"])

    @unittest.skipUnless(platform.machine().lower() in {"aarch64", "arm64"} and shutil.which("cc"),
        "需要本机AArch64及C编译器核对LDR/STR SIMD位规则")
    def test_native_scalar_loads_clear_upper_bits_and_stores_preserve_source(self):
        # Executes only this tiny independent test, never the supplied SO.
        source = r'''#include <stdint.h>
int main(void) {
    uint32_t bits32=0x7f800001U;
    uint64_t bits64=0x7ff0000000000001ULL;
    _Alignas(16) uint64_t output[2]={0,0};
    __asm__ volatile("movi v0.16b, #0xff\nldr s0, [%0]\nstr q0, [%1]"
        : : "r"(&bits32), "r"(output) : "v0", "memory");
    if (output[0]!=bits32 || output[1]) return 1;
    __asm__ volatile("movi v0.16b, #0xff\nldr d0, [%0]\nstr q0, [%1]"
        : : "r"(&bits64), "r"(output) : "v0", "memory");
    if (output[0]!=bits64 || output[1]) return 2;
    uint64_t stored[2]={0,0x123456789abcdef0ULL};
    __asm__ volatile("movi v0.16b, #0xff\nstr d0, [%0]\nstr q0, [%1]"
        : : "r"(stored), "r"(output) : "v0", "memory");
    if (stored[0]!=UINT64_MAX || stored[1]!=0x123456789abcdef0ULL) return 3;
    if (output[0]!=UINT64_MAX || output[1]!=UINT64_MAX) return 4;
    return 0;
}'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "simd_bits.c"
            executable = Path(directory) / "simd_bits"
            path.write_text(source)
            subprocess.run([shutil.which("cc"), str(path), "-o", str(executable)], check=True, capture_output=True)
            subprocess.run([str(executable)], check=True, capture_output=True)


if __name__ == "__main__":
    unittest.main()
