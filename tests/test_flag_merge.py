"""汇合点的条件分支：标志来自不同前驱中的不同比较时，仍应还原为真实比较。"""
from __future__ import annotations

import unittest

from fangida.plugins.pseudoc import generate_pseudoc
from fangida.plugins.pseudoc.reconstruct.flagflow import reaching_flag_sets, reaching_flags
from tests.test_pseudoc import function as fn, instruction as ins
from tests.test_reconstruction import compile_run


def readable(architecture, *rows, name):
    return generate_pseudoc(fn(*rows, name=name, pseudoc_context={"kind": "elf"}), architecture, style="readable")


class FlagMergeTests(unittest.TestCase):
    def test_x86_join_of_two_compares_is_a_real_comparison(self):
        # edi < 0 时经 5 到达 6，标志来自 cmp edi, 0；否则标志来自 cmp esi, 3。
        output = readable("x86_64",
            ins(0, "cmp", "edi", "0"), ins(1, "jl", "0x5", kind="jump", target=5, conditional=True),
            ins(2, "cmp", "esi", "3"), ins(3, "jmp", "0x6", kind="jump", target=6),
            ins(5, "jmp", "0x6", kind="jump", target=6),
            ins(6, "jne", "0x9", kind="jump", target=9, conditional=True),
            ins(7, "mov", "eax", "1"), ins(8, "ret", kind="return"),
            ins(9, "mov", "eax", "2"), ins(10, "ret", kind="return"), name="joined")
        self.assertNotIn("unresolved_condition", output.pseudoc)
        self.assertFalse([item for item in output.reconstruction["unresolved"] if item.get("kind") == "condition"])
        compile_run(output.pseudoc,
            "return joined(-1, 3) == 2 && joined(0, 3) == 1 && joined(0, 4) == 2 && joined(5, 3) == 1"
            " && joined(-7, 9) == 2 ? 0 : 1;")

    def test_arm64_three_predecessors_with_different_compares(self):
        # 与 libtersafe.so 的 tss_sdt_float2uint 同形：多个 cmp/b.ge 汇入同一个 b.ne。
        output = readable("arm64",
            ins(0x00, "cmp", "w0", "w2", size=4), ins(0x04, "b.ge", "#0x20", size=4, kind="jump", target=0x20, conditional=True),
            ins(0x08, "cmp", "w1", "w2", size=4), ins(0x0c, "b.ge", "#0x20", size=4, kind="jump", target=0x20, conditional=True),
            ins(0x10, "mov", "w0", "#0", size=4), ins(0x14, "ret", size=4, kind="return"),
            ins(0x20, "b.ne", "#0x30", size=4, kind="jump", target=0x30, conditional=True),
            ins(0x24, "mov", "w0", "#1", size=4), ins(0x28, "ret", size=4, kind="return"),
            ins(0x30, "mov", "w0", "#2", size=4), ins(0x34, "ret", size=4, kind="return"), name="three_way")
        self.assertNotIn("unresolved_condition", output.pseudoc)
        compile_run(output.pseudoc,
            "return three_way(5, 0, 5) == 1 && three_way(6, 0, 5) == 2 && three_way(1, 5, 5) == 1"
            " && three_way(1, 7, 5) == 2 && three_way(1, 2, 5) == 0 && three_way(-1, -1, -1) == 1 ? 0 : 1;")

    def test_incompatible_widths_stay_unresolved(self):
        # 32 位与 64 位比较汇合时没有共同的比较类型，必须保守地保留未还原条件。
        output = readable("x86_64",
            ins(0, "cmp", "edi", "0"), ins(1, "jl", "0x5", kind="jump", target=5, conditional=True),
            ins(2, "cmp", "rsi", "3"), ins(3, "jmp", "0x6", kind="jump", target=6),
            ins(5, "jmp", "0x6", kind="jump", target=6),
            ins(6, "jne", "0x9", kind="jump", target=9, conditional=True),
            ins(7, "mov", "eax", "1"), ins(8, "ret", kind="return"),
            ins(9, "mov", "eax", "2"), ins(10, "ret", kind="return"), name="mixed")
        self.assertIn("unresolved_condition", output.pseudoc)

    def test_barrier_on_one_path_keeps_condition_unresolved(self):
        # 一条路径上的 call 清掉了标志，另一条路径有比较：不能只用另一条路径的比较。
        output = readable("x86_64",
            ins(0, "cmp", "edi", "0"), ins(1, "jl", "0x5", kind="jump", target=5, conditional=True),
            ins(2, "call", "0x40", kind="call", target=0x40), ins(3, "jmp", "0x6", kind="jump", target=6),
            ins(5, "jmp", "0x6", kind="jump", target=6),
            ins(6, "jne", "0x9", kind="jump", target=9, conditional=True),
            ins(7, "mov", "eax", "1"), ins(8, "ret", kind="return"),
            ins(9, "mov", "eax", "2"), ins(10, "ret", kind="return"), name="barrier")
        self.assertIn("unresolved_condition", output.pseudoc)

    def test_single_origin_api_is_unchanged(self):
        # 旧的 reaching_flags 仍只报告唯一来源；集合版本另行提供。
        class Block:
            def __init__(self, address, successors, records):
                self.address, self.successors, self.records = address, successors, records

        def row(addr, opcode):
            # 与 microcode 记录同形：比较带两个 32 位操作数，记录带整行标志效果。
            operands = [{"opcode": "register", "width": 32, "name": "w0"}, {"opcode": "constant", "width": 32, "value": addr}]
            operation = {"opcode": opcode, "width": 32, "inputs": operands} if opcode == "compare" else {"opcode": opcode}
            effect = {"compare": "write", "call": "unknown"}.get(opcode, "preserve")
            return {"addr": addr, "operations": [operation], "flag_effect": effect}

        blocks = {0: Block(0, [2, 1], [row(0, "compare")]), 1: Block(1, [2], [row(1, "compare")]),
                  2: Block(2, [], [row(2, "branch")])}
        self.assertIsNone(reaching_flags(blocks, 0)[2])
        self.assertEqual(reaching_flag_sets(blocks, 0)[2], frozenset({(0, 0), (1, 0)}))
        blocks[1].records = [row(1, "call")]
        self.assertIsNone(reaching_flag_sets(blocks, 0)[2])


if __name__ == "__main__":
    unittest.main()
