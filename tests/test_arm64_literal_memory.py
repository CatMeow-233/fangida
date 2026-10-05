"""A64 PC-relative literal loads consume snapshots without reading a binary."""
from __future__ import annotations

import unittest

from fangida.plugins.pseudoc import generate_pseudoc
from fangida.plugins.pseudoc.microcode import lift_instruction
from tests.test_pseudoc import instruction as ins, function as fn


class ARM64LiteralMemoryTests(unittest.TestCase):
    def test_gpr_literal_loads_keep_access_width_and_w_zero_upper(self):
        for register, width in (("w0", 32), ("x0", 64), ("lr", 64), ("fp", 64)):
            with self.subTest(register=register):
                row = lift_instruction(ins(0x1000, "ldr", register, "#0x100c"), "arm64")
                self.assertTrue(row["supported"])
                self.assertEqual(row["category"], "memory")
                self.assertEqual(row["memory_effect"], "read")
                self.assertEqual(row["flag_effect"], "preserve")
                operation = row["operations"][0]
                self.assertEqual(operation["expression"]["opcode"], "load")
                self.assertEqual(operation["expression"]["width"], width)
                self.assertEqual(operation["expression"]["args"][0]["name"], "0x100c")
                self.assertEqual(operation["attributes"]["zero_upper"], width == 32)
                self.assertEqual(operation["attributes"]["storage_width"], 64)

    def test_ldrsw_literal_sign_extends_32_bit_load(self):
        row = lift_instruction(ins(0x1000, "ldrsw", "x0", "#0xffc"), "arm64")
        self.assertTrue(row["supported"])
        expression = row["operations"][0]["expression"]
        self.assertEqual(expression["opcode"], "sext")
        self.assertEqual(expression["width"], 64)
        self.assertEqual(expression["args"][0]["opcode"], "load")
        self.assertEqual(expression["args"][0]["width"], 32)

    def test_zero_register_literal_load_still_reads_memory(self):
        for mnemonic, register, width in (("ldr", "wzr", 32), ("ldr", "xzr", 64), ("ldrsw", "xzr", 64)):
            with self.subTest(mnemonic=mnemonic, register=register):
                row = lift_instruction(ins(0x1000, mnemonic, register, "#0x1000"), "arm64")
                self.assertTrue(row["supported"])
                self.assertEqual(row["memory_effect"], "read")
                operation = row["operations"][0]
                self.assertEqual(operation["opcode"], "discard")
                self.assertEqual(operation["width"], width)
                self.assertNotIn("output", operation)

    def test_q_literal_load_uses_full_128_bit_storage(self):
        row = lift_instruction(ins(0x1000, "ldr", "q31", "#0x1004"), "arm64")
        self.assertTrue(row["supported"])
        operation = row["operations"][0]
        self.assertEqual(operation["output"], "v31")
        self.assertEqual(operation["width"], 128)
        self.assertEqual(operation["expression"]["width"], 128)
        self.assertEqual(operation["attributes"]["storage_width"], 128)
        self.assertFalse(operation["attributes"]["zero_upper"])

    def test_literal_immediate_range_alignment_and_canonical_numbers(self):
        for at, target in ((0x200000, "#0x100000"), (0x200000, "#0x2ffffc"),
                (0x1000, "4096"), (0x1000, "#0X1004"), ((1 << 64) - 4, "#0")):
            with self.subTest(at=at, target=target):
                self.assertTrue(lift_instruction(ins(at, "ldr", "x0", target), "arm64")["supported"])
        for at, target in ((0x200000, "#0xffffc"), (0x200000, "#0x300000"),
                (0x1000, "#0x1002"), (0x1002, "#0x1004"), (-4, "#0"),
                (1 << 64, "#0"), (0x1000, "#18446744073709551616"),
                (0x1000, "#-4"), (0x1000, "#0x1000 + 4"), (0x1000, "some_label"),
                (0x1000, "$0x1000"), (0x1000, "#0x1000!")):
            with self.subTest(at=at, target=target):
                self.assertFalse(lift_instruction(ins(at, "ldr", "x0", target), "arm64")["supported"])

    def test_nonexistent_and_unproven_literal_forms_remain_opaque(self):
        for mnemonic, register in (("str", "x0"), ("ldur", "x0"), ("ldrb", "w0"),
                ("ldrh", "w0"), ("ldr", "sp"), ("ldr", "wsp"), ("ldrsw", "w0"),
                ("ldrsw", "wzr"), ("ldrsw", "s0"), ("ldrsw", "d0"), ("ldrsw", "q0")):
            with self.subTest(mnemonic=mnemonic, register=register):
                self.assertFalse(lift_instruction(ins(0x1000, mnemonic, register, "#0x1000"), "arm64")["supported"])
        self.assertFalse(lift_instruction(ins(0x1000, "ldr", "x0", "#0x1000", "#4"), "arm64")["supported"])
        self.assertFalse(lift_instruction(ins(0x1000, "ldr", "r0", "#0x1000"), "arm")["supported"])

    def test_readable_literal_target_is_memory_not_an_invented_constant(self):
        function = fn(ins(0x1000, "ldr", "x0", "#0x1008"),
            ins(0x1004, "ret", kind="return"), name="literal_read", pseudoc_context={"kind": "elf"})
        output = generate_pseudoc(function, "arm64", style="readable")
        self.assertNotIn("unresolved_operation", output.pseudoc)
        self.assertIn("global_", output.pseudoc)
        self.assertEqual(output.microcode[0]["operations"][0]["expression"]["opcode"], "load")
        self.assertNotIn("return 4104", output.pseudoc)


if __name__ == "__main__":
    unittest.main()
