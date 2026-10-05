"""未知控制边必须保留转移和 ABI 证据，不能伪造 C 返回。"""
from __future__ import annotations

import copy
import unittest

from tests.test_pseudoc import instruction as ins, function as fn
from fangida.plugins.pseudoc import generate_pseudoc
from tests.test_reconstruction import compile_run


def arm(*rows, **fields):
    snapshot = fn(*rows, name="transfer_case", pseudoc_context={"kind": "elf", **fields.pop("context", {})}, **fields)
    before = copy.deepcopy(snapshot)
    result = generate_pseudoc(snapshot, "arm64", style="readable")
    if snapshot != before:
        raise AssertionError("源码重建不得改写原始指令快照")
    return result


class ReconstructionTransferTests(unittest.TestCase):
    def test_indirect_transfer_keeps_register_target(self):
        result = arm(ins(0, "br", "x6", size=4, kind="jump"))
        self.assertIn("tail_transfer(arg_7, unknown_arguments());", result.pseudoc)
        self.assertNotIn("return ", result.pseudoc)
        self.assertFalse(result.reconstruction["complete"])
        self.assertEqual(result.reconstruction["calls"][0]["target_expression"]["name"], "x6")

    def test_indirect_memory_target_is_loaded_once(self):
        result = generate_pseudoc(fn(ins(0, "jmp", "qword ptr [rdi]", kind="jump"),
                                    pseudoc_context={"kind": "elf"}), "x86_64", style="readable")
        self.assertIn("tail_transfer(arg_1[0],", result.pseudoc)
        self.assertEqual(result.pseudoc.count("arg_1[0]"), 1)
        self.assertNotIn("return ", result.pseudoc)

    def test_direct_transfer_preserves_target_and_declared_arguments(self):
        result = arm(ins(0, "mov", "x0", "#4", size=4),
                     ins(4, "mov", "x1", "#7", size=4),
                     ins(8, "b", "0x999", size=4, kind="jump", target=2457),
                     context={"callees": {2457: {"name": "target", "signature_complete": True,
                         "parameters": [{"register": "x0", "type": "uint64_t"}, {"register": "x1", "type": "uint64_t"}],
                         "return_type": "uint32_t", "return_zero_extended": True}}})
        self.assertIn("tail_transfer(target,", result.pseudoc)
        self.assertNotIn("unknown_arguments", result.pseudoc)
        self.assertNotIn("return ", result.pseudoc)
        call = result.reconstruction["calls"][0]
        self.assertEqual(call["recovered_argument_count"], 2)
        self.assertEqual(call["target"], 2457)
        self.assertTrue(call["argument_count_known"])
        compile_run(result.pseudoc,
            "if (setjmp(transfer_exit) == 0) transfer_case(); return observed_target == target && observed_first == 4 && observed_second == 7 ? 0 : 1;",
            "#include <setjmp.h>\nstatic jmp_buf transfer_exit;\nstatic void target(void) {}\nstatic void (*observed_target)(void);\nstatic uint64_t observed_first, observed_second;\n"
            "_Noreturn void tail_transfer(void (*callee)(void), uint64_t first, uint64_t second) { observed_target=callee; observed_first=first; observed_second=second; longjmp(transfer_exit,1); }\n")

    def test_conditional_external_edge_is_not_a_return(self):
        result = arm(ins(0, "cbz", "w0", "0x99", size=4, kind="jump", target=153, conditional=True),
                     ins(4, "mov", "w0", "#1", size=4), ins(8, "ret", size=4, kind="return"))
        self.assertIn("if (arg_1 == 0)", result.pseudoc)
        self.assertIn("tail_transfer(0x99,", result.pseudoc)
        self.assertEqual(result.pseudoc.count("return "), 1)
        self.assertNotIn("unresolved_result", result.pseudoc)

    def test_truncated_fallthrough_has_separate_marker(self):
        result = arm(ins(0, "mov", "w0", "#1", size=4))
        self.assertIn("unresolved_fallthrough(4);", result.pseudoc)
        self.assertNotIn("tail_transfer", result.pseudoc)
        self.assertNotIn("return ", result.pseudoc)
        self.assertEqual(result.reconstruction["unresolved"][0]["transfer_kind"], "fallthrough")

    def test_specialization_preserves_external_target(self):
        result = arm(ins(0, "mov", "w0", "#0", size=4),
                     ins(4, "cbz", "w0", "0x99", size=4, kind="jump", target=153, conditional=True),
                     ins(8, "mov", "w0", "#7", size=4), ins(12, "ret", size=4, kind="return"))
        self.assertTrue(result.reconstruction["specialization"]["applied"])
        self.assertIn("tail_transfer(0x99,", result.pseudoc)
        self.assertNotIn("unresolved_result", result.pseudoc)
        self.assertEqual(result.reconstruction["calls"][0]["address"], 4)

    def test_specialization_preserves_unknown_fallthrough(self):
        result = arm(ins(0, "mov", "w0", "#1", size=4),
                     ins(4, "cbz", "w0", "0x0", size=4, kind="jump", target=0, conditional=True))
        self.assertTrue(result.reconstruction["specialization"]["applied"])
        self.assertIn("unresolved_fallthrough(8);", result.pseudoc)
        self.assertNotIn("tail_transfer", result.pseudoc)

    def test_call_clobber_is_not_an_incoming_argument(self):
        result = arm(ins(0, "bl", "0x20", size=4, kind="call", target=32),
                     ins(4, "add", "x0", "x6", "#1", size=4), ins(8, "ret", size=4, kind="return"))
        self.assertEqual(result.reconstruction["parameters"], [])
        self.assertIn("return unknown_value() + 1;", result.pseudoc)

    def test_call_arguments_survive_predecessor_blocks(self):
        result = arm(ins(0, "mov", "x0", "#4", size=4),
                     ins(4, "cbz", "x1", "0x10", size=4, kind="jump", target=16, conditional=True),
                     ins(8, "b", "0x14", size=4, kind="jump", target=20),
                     ins(16, "b", "0x14", size=4, kind="jump", target=20),
                     ins(20, "bl", "0x40", size=4, kind="call", target=64),
                     ins(24, "ret", size=4, kind="return"))
        call = result.reconstruction["calls"][0]
        self.assertEqual(call["recovered_argument_count"], 2)
        self.assertIn("unknown_function(4, arg_2, unknown_arguments())", result.pseudoc)
        compile_run(result.pseudoc, "return transfer_case(42) == 46 && transfer_case(0) == 4 ? 0 : 1;",
            "uint64_t unknown_arguments(void) { return 0; }\nuint64_t unknown_function(uint64_t first, uint64_t second, uint64_t tail) { return first+second+tail; }\n")

    def test_partial_summary_keeps_argument_slots_and_unknown_tail(self):
        result = arm(ins(0, "mov", "x0", "#4", size=4), ins(4, "mov", "x6", "#7", size=4),
                     ins(8, "bl", "0x40", size=4, kind="call", target=64),
                     ins(12, "ret", size=4, kind="return"),
                     context={"callees": {64: {"name": "partial", "signature_complete": False,
                         "parameters": [{"register": "x0"}, {"register": "x6"}], "return_type": "uint64_t"}}})
        self.assertIn("partial(4, unknown_value(), unknown_value(), unknown_value(), unknown_value(), unknown_value(), 7, unknown_arguments())", result.pseudoc)
        self.assertFalse(result.reconstruction["calls"][0]["argument_count_known"])

    def test_exception_handler_values_are_not_incoming_arguments(self):
        result = arm(ins(0, "svc", "#0", size=4), ins(4, "add", "x0", "x6", "#1", size=4),
                     ins(8, "ret", size=4, kind="return"))
        self.assertEqual(result.reconstruction["parameters"], [])
        self.assertFalse(result.reconstruction["complete"])


if __name__ == "__main__":
    unittest.main()
