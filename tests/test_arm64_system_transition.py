"""A64 SVC 的异常转移语义及平台未知边界回归。"""
from __future__ import annotations

import json
import unittest

from fangida.plugins.pseudoc.microcode import analyze_microcode, lift_function, lift_instruction
from tests.test_pseudoc import function, instruction


class ARM64SystemTransitionTests(unittest.TestCase):
    def test_svc_records_unsigned_imm16_and_instruction_address(self):
        for operand, expected in (("#0", 0), ("0", 0), ("#65535", 65535),
                                  ("#0xffff", 65535), ("#0X8000", 32768)):
            with self.subTest(operand=operand):
                result = lift_instruction(instruction(0x800, "svc", operand, size=4), "arm64")
                self.assertTrue(result["supported"])
                self.assertEqual(result["category"], "system")
                self.assertEqual(result["flag_effect"], "unknown")
                self.assertEqual(result["memory_effect"], "unknown")
                operation, = result["operations"]
                self.assertEqual(operation["opcode"], "system_transition")
                self.assertNotIn("output", operation)
                self.assertEqual(operation["width"], 0)
                self.assertEqual(operation["inputs"], [
                    {"opcode": "constant", "width": 16, "domain": "bitvector", "value": expected},
                    {"opcode": "constant", "width": 64, "domain": "bitvector", "value": 0x800},
                ])
                attributes = operation["attributes"]
                self.assertEqual(attributes["immediate"], expected)
                self.assertEqual(attributes["instruction_address"], 0x800)
                self.assertEqual(attributes["resume_address"], 0x804)
                self.assertEqual(attributes["input_roles"], ["imm16", "instruction_address"])
                self.assertEqual(attributes["syndrome"], {"exception_class": 0x15, "iss": expected})
                self.assertEqual(attributes["transition"], "exception")
                self.assertEqual(attributes["exception"], "supervisor_call")
                self.assertEqual(json.loads(json.dumps(result)), result)

    def test_out_of_range_or_non_immediate_is_opaque_instead_of_wrapping(self):
        for operands in (("#-1",), ("#65536",), ("#0x10000",), ("x8",),
                         ("#1.0",), ("##0",), (), ("#0", "#1")):
            with self.subTest(operands=operands):
                result = lift_instruction(instruction(0, "svc", *operands, size=4), "arm64")
                self.assertFalse(result["supported"])
                self.assertEqual(result["category"], "system")
                self.assertEqual(result["operations"][0]["opcode"], "opaque")

    def test_a64_handler_contract_is_not_applied_to_other_architectures(self):
        for architecture in ("arm", "x86", "x86_64"):
            with self.subTest(architecture=architecture):
                result = lift_instruction(instruction(0, "svc", "#0", size=4), architecture)
                self.assertFalse(result["supported"])
                self.assertEqual(result["operations"][0]["opcode"], "opaque")

    def test_platform_unknown_does_not_invent_syscall_abi_or_clobbers(self):
        result = lift_instruction(instruction(4, "svc", "#0", size=4), "arm64")
        attributes = result["operations"][0]["attributes"]
        self.assertTrue(attributes["state_boundary"])
        self.assertTrue(attributes["barrier"])
        self.assertEqual(attributes["platform"], "unknown")
        self.assertEqual(attributes["handler"], "unknown")
        self.assertEqual(attributes["exception_routing"], "execution_context_dependent")
        for effect in ("register_effects", "memory_effects", "condition_flags_effects", "return_behavior"):
            self.assertEqual(attributes[effect], "handler_dependent")
        self.assertEqual(attributes["source_recovery"], "requires_exception_handler_contract")
        self.assertNotIn("abi", attributes)
        self.assertNotIn("clobbers", attributes)
        self.assertNotIn("syscall", json.dumps(result).lower())
        self.assertNotIn("x8", result["reads"])
        self.assertNotIn("x0", result["writes"])

    def test_unknown_handler_invalidates_cross_transition_constant_facts(self):
        snapshot = function(
            instruction(0, "mov", "x0", "#42", size=4),
            instruction(4, "svc", "#0", size=4),
            instruction(8, "mov", "x1", "x0", size=4),
        )
        records = lift_function(snapshot, "arm64")["instructions"]
        report = analyze_microcode(records)
        self.assertEqual(report["unsupported_addresses"], [])
        self.assertEqual([(fact["addr"], fact["value"]) for fact in report["facts"]
                          if fact["kind"] == "constant_assignment"], [(0, 42)])
        self.assertNotIn("x0", report["remaining_register_bits"])
        self.assertNotIn("x1", report["remaining_register_bits"])


if __name__ == "__main__":
    unittest.main()
