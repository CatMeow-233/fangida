"""过程间参数用法：转交、调用覆盖、尾跳转、导入原型、间接调用约定、变参、清零写法与递归。"""
from __future__ import annotations

import unittest

from fangida.plugins.pseudoc.reconstruct.arguments import argument_usage
from fangida.plugins.pseudoc.reconstruct.calls import restore_call

ARGS = tuple(f"x{index}" for index in range(8))


def row(addr, mnemonic, operands=(), reads=(), writes=(), call=None, indirect_call=False):
    branch = {}
    if call is not None:
        branch = {"kind": "call", "target": call, "conditional": False}
    elif indirect_call:
        branch = {"kind": "call", "target": None, "conditional": False}
    return {"addr": addr, "size": 4, "mnemonic": mnemonic, "operands": tuple(operands),
            "reads": tuple(reads), "writes": tuple(writes), "branch_info": branch}


def function(start, *rows_, frontier=(), blocks=None):
    """默认单块函数；blocks 可给出 [(起点, [行...], [后继...]), ...]。"""
    if blocks is None:
        blocks = [(start, list(rows_), [])]
    return {"start": start, "blocks": [{"start": b, "instructions": r, "successors": s} for b, r, s in blocks],
            "cfg": {"frontier": list(frontier)}}


def usage(*functions, **options):
    return argument_usage(functions, "arm64", ARGS, **options)


class ArgumentFlowTests(unittest.TestCase):
    def test_untouched_register_passed_to_callee_is_a_parameter(self):
        leaf = function(0x100, row(0x100, "add", ("w0", "w0", "w1"), reads=("w0", "w1"), writes=("w0",)),
                        row(0x104, "ret"))
        middle = function(0x200, row(0x200, "bl", call=0x100), row(0x204, "ret"))
        result = usage(leaf, middle)
        self.assertEqual(result[0x200], {"registers": ["x0", "x1"], "complete": True,
                                         "complete_assuming_indirect_calls": True})

    def test_register_written_before_the_call_is_not_a_parameter(self):
        leaf = function(0x100, row(0x100, "add", ("w0", "w0", "w1"), reads=("w0", "w1"), writes=("w0",)), row(0x104, "ret"))
        caller = function(0x200, row(0x200, "mov", ("w1", "#3"), writes=("w1",)), row(0x204, "bl", call=0x100), row(0x208, "ret"))
        self.assertEqual(usage(leaf, caller)[0x200]["registers"], ["x0"])

    def test_registers_read_after_a_call_are_not_parameters(self):
        callee = function(0x100, row(0x100, "ret"))
        caller = function(0x200, row(0x200, "bl", call=0x100), row(0x204, "mov", ("x2", "x1"), reads=("x1",), writes=("x2",)),
                          row(0x208, "ret"))
        self.assertEqual(usage(callee, caller)[0x200], {"registers": [], "complete": True,
                                                        "complete_assuming_indirect_calls": True})

    def test_tail_jump_passes_registers_through(self):
        leaf = function(0x100, row(0x100, "mov", ("x0", "x2"), reads=("x2",), writes=("x0",)), row(0x104, "ret"))
        trampoline = function(0x200, row(0x200, "b", ("#0x100",)),
                              frontier=[{"from": 0x200, "to": 0x100, "reason": "other_function"}])
        result = usage(leaf, trampoline)
        self.assertEqual((result[0x200]["registers"], result[0x200]["complete"]), (["x2"], True))

    def test_import_prototypes_and_unknown_imports(self):
        caller = function(0x200, row(0x200, "bl", call=0x900), row(0x204, "ret"))
        known = usage(caller, known_arity={0x900: 2})[0x200]
        self.assertEqual((known["registers"], known["complete"]), (["x0", "x1"], True))
        unknown = usage(caller, known_arity={0x900: None})[0x200]
        self.assertEqual((unknown["registers"], unknown["complete"]), ([], False))

    def test_local_export_alias_uses_the_local_function(self):
        export = function(0x300, row(0x300, "mov", ("x0", "x3"), reads=("x3",), writes=("x0",)), row(0x304, "ret"))
        caller = function(0x200, row(0x200, "bl", call=0x900), row(0x204, "ret"))
        result = usage(export, caller, aliases={0x900: 0x300})
        self.assertEqual((result[0x200]["registers"], result[0x200]["complete"]), (["x3"], True))

    def test_indirect_call_after_full_clobber_is_still_proven_complete(self):
        # 与 libc++ operator new 同形：先调用 malloc，之后的 blr 不可能读到调用者传入的值。
        caller = function(0x200, row(0x200, "bl", call=0x900), row(0x204, "blr", ("x0",), reads=("x0",), indirect_call=True),
                          row(0x208, "ret"))
        result = usage(caller, known_arity={0x900: 1})[0x200]
        self.assertEqual((result["registers"], result["complete"]), (["x0"], True))

    def test_indirect_call_before_clobber_is_complete_only_by_convention(self):
        # 与 tss_sdk_setuserinfo_ex 同形：mov x0, x19 ; blr x8 —— x1..x7 仍可能是入口值。
        caller = function(0x200, row(0x200, "mov", ("x0", "x19"), reads=("x19",), writes=("x0",)),
                          row(0x204, "blr", ("x8",), reads=("x8",), indirect_call=True), row(0x208, "ret"))
        result = usage(caller)[0x200]
        self.assertEqual((result["complete"], result["complete_assuming_indirect_calls"]), (False, True))

    def test_indirect_jump_keeps_untouched_registers_uncertain_even_by_convention(self):
        switch = function(0x200, row(0x200, "br", ("x9",), reads=("x9",)),
                          frontier=[{"from": 0x200, "to": None, "reason": "indirect_jump"}])
        result = usage(switch)[0x200]
        self.assertEqual((result["complete"], result["complete_assuming_indirect_calls"]), (False, False))

    def test_variadic_import_is_complete_only_by_convention(self):
        caller = function(0x200, row(0x200, "mov", ("w0", "#3"), writes=("w0",)), row(0x204, "bl", call=0x900), row(0x208, "ret"))
        result = usage(caller, known_arity={0x900: None}, variadic_fixed={0x900: 3})[0x200]
        self.assertEqual(result, {"registers": ["x1", "x2"], "complete": False, "complete_assuming_indirect_calls": True})

    def test_zero_idioms_are_not_reads(self):
        for mnemonic, operands in (("eor", ("w1", "w1", "w1")), ("sub", ("x1", "x2", "x2")), ("xor", ("esi", "esi"))):
            with self.subTest(mnemonic=mnemonic):
                f = function(0x200, row(0x200, mnemonic, operands, reads=operands[1:], writes=operands[:1]), row(0x204, "ret"))
                self.assertEqual(usage(f)[0x200]["registers"], [])

    def test_recursion_and_branch_join_terminate_with_must_definitions(self):
        # 入口分支：一条路径写 x1 后递归调用自己，另一条路径直接读 x1。
        f = function(0x200, blocks=[
            (0x200, [row(0x200, "cbz", ("x0", "#0x210"), reads=("x0",))], [0x204, 0x210]),
            (0x204, [row(0x204, "mov", ("x1", "#1"), writes=("x1",)), row(0x208, "bl", call=0x200), row(0x20c, "ret")], []),
            (0x210, [row(0x210, "mov", ("x0", "x1"), reads=("x1",), writes=("x0",)), row(0x214, "ret")], [])])
        result = usage(f)[0x200]
        self.assertEqual((result["registers"], result["complete"]), (["x0", "x1"], True))

    def test_missing_edges_are_never_reported_complete(self):
        broken = {"start": 0x200, "blocks": [{"start": 0x200, "instructions": [row(0x200, "ret")]}], "cfg": {"frontier": []}}
        self.assertFalse(usage(broken)[0x200]["complete"])


class CallRestorationTests(unittest.TestCase):
    def test_complete_argument_flow_drops_unknown_arguments_and_marks_assumptions(self):
        from fangida.plugins.pseudoc.reconstruct.abi import select_abi
        from fangida.plugins.pseudoc.reconstruct.model import Value

        class Expressions:
            variables = {"x0": None, "x1": None}
            call_names = {}

            def variable(self, root):
                return Value("variable", 64, name=root, ctype="uint64_t")

        abi = select_abi("arm64", {"kind": "elf"})
        operation = {"opcode": "call", "attributes": {"target": 0x100}, "width": 64}
        parameters = [{"register": "x0", "name": "arg_1"}, {"register": "x1", "name": "arg_2"}]
        for flags, assumed in (({"argument_uses_complete": True}, False),
                               ({"argument_uses_complete": True, "argument_uses_assumed": True}, True)):
            with self.subTest(assumed=assumed):
                value, evidence = restore_call(operation, Expressions(), abi, {0x100: {"parameters": parameters, **flags}},
                                               {0x100: "callee"}, {"x0", "x1"}, 0)
                self.assertEqual([arg.name for arg in value.args], ["x0", "x1"])
                self.assertTrue(evidence["argument_count_known"])
                self.assertEqual(evidence["argument_count_assumed"], assumed)


if __name__ == "__main__":
    unittest.main()
