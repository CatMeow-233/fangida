"""Reachability and frontier tests independent of any disassembler install."""
from __future__ import annotations

import unittest

from ...models import Instruction
from .cfg import build_entry_cfg


def ins(addr: int, size: int, mnemonic: str, branch: dict | None = None) -> dict:
    return Instruction(addr, size, mnemonic, branch_info=branch or {}).to_dict()


class EntryCfgTests(unittest.TestCase):
    def test_conditional_branch_only_reaches_its_two_paths(self) -> None:
        instructions = [
            ins(0x1000, 2, "jne", {"kind": "jump", "target": 0x1006, "conditional": True}),
            ins(0x1002, 1, "nop"), ins(0x1003, 1, "ret", {"kind": "return"}),
            ins(0x1004, 1, "int3"), ins(0x1005, 1, "nop"),
            ins(0x1006, 1, "ret", {"kind": "return"}),
        ]
        graph, reached = build_entry_cfg(instructions, 0x1000)
        self.assertIsNotNone(graph)
        self.assertEqual(reached, {0x1000, 0x1002, 0x1003, 0x1006})
        self.assertTrue(graph["complete"])
        self.assertFalse(graph["boundary_known"])
        self.assertEqual({(edge["src"], edge["dst"], edge["kind"]) for edge in graph["edges"]},
                         {(0x1000, 0x1006, "branch"), (0x1000, 0x1002, "fallthrough")})

    def test_missing_and_mid_instruction_targets_are_frontiers(self) -> None:
        instructions = [ins(0x1000, 2, "jne", {"kind": "jump", "target": 0x1001,
                                                   "conditional": True}),
                        ins(0x1002, 1, "ret", {"kind": "return"})]
        graph, _ = build_entry_cfg(instructions, 0x1000)
        self.assertFalse(graph["complete"])
        self.assertEqual(graph["frontier"], [{"from": 0x1000, "to": 0x1001,
                                              "reason": "not_instruction_boundary"}])

    def test_indirect_jump_and_code_limit_are_incomplete(self) -> None:
        indirect, _ = build_entry_cfg([ins(0x2000, 2, "jmp", {"kind": "jump", "target": None,
                                                                "conditional": False})], 0x2000)
        self.assertFalse(indirect["complete"])
        self.assertEqual(indirect["frontier"][0]["reason"], "indirect_jump")
        limited, _ = build_entry_cfg([ins(0x2000, 1, "nop")], 0x2000)
        self.assertFalse(limited["complete"])
        self.assertEqual(limited["frontier"][0]["to"], 0x2001)

    def test_arm64_ir_uses_same_branch_semantics(self) -> None:
        instructions = [ins(0x4000, 4, "b.eq", {"kind": "jump", "target": 0x4008,
                                                    "conditional": True}),
                        ins(0x4004, 4, "ret", {"kind": "return"}),
                        ins(0x4008, 4, "ret", {"kind": "return"})]
        graph, reached = build_entry_cfg(instructions, 0x4000)
        self.assertTrue(graph["complete"])
        self.assertEqual(reached, {0x4000, 0x4004, 0x4008})

    def test_trap_terminates_before_adjacent_function(self) -> None:
        graph, reached = build_entry_cfg([ins(0x5000, 1, "hlt", {"kind": "trap"}),
                                          ins(0x5001, 1, "nop")], 0x5000)
        self.assertTrue(graph["complete"])
        self.assertEqual(reached, {0x5000})


if __name__ == "__main__":
    unittest.main()
