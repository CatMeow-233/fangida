"""微码大类、比较边界、未知副作用、混淆表达式与只读 API 回归。"""
from __future__ import annotations

import copy
import importlib.util
import math
from pathlib import Path
import random
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from fangida.api import AnalysisView
from fangida.mcp_server import McpServer
from fangida.models import AnalysisResult
from fangida.plugins.pseudoc import generate_pseudoc, pipeline
from fangida.plugins.pseudoc.microcode import (
    ComparisonOrigin, Expression, UnknownValue, analyze_microcode, condition, constant,
    evaluate_condition, evaluate_expression, floating_flags, integer_flags,
    lift_function, lift_instruction, list_lifters, simplify_expression,
)
from fangida.processors.decoder import NativeDecoder
from tests.test_pseudoc import function, instruction


def register(name, width=32):
    return Expression("register", width, name=name)


def operation(opcode, width, *args):
    return Expression(opcode, width, tuple(args))


class ComparisonSemanticsTests(unittest.TestCase):
    def test_signed_unsigned_strict_and_inclusive_boundaries_all_widths(self):
        mappings = {
            "x86": {"g": (True, ">"), "ge": (True, ">="), "l": (True, "<"), "le": (True, "<="),
                    "a": (False, ">"), "ae": (False, ">="), "b": (False, "<"), "be": (False, "<="), "e": (False, "=="), "ne": (False, "!=")},
            "arm": {"gt": (True, ">"), "ge": (True, ">="), "lt": (True, "<"), "le": (True, "<="),
                    "hi": (False, ">"), "hs": (False, ">="), "lo": (False, "<"), "ls": (False, "<="), "eq": (False, "=="), "ne": (False, "!=")},
        }
        for width in (8, 16, 32, 64):
            modulus, sign = 1 << width, 1 << (width - 1)
            values = (0, 1, 2, sign - 1, sign, sign + 1, modulus - 2, modulus - 1)
            for family, codes in mappings.items():
                origin = ComparisonOrigin(0x100, family, width, "integer", "captured_left", "captured_right")
                for code, (is_signed, relation) in codes.items():
                    pred = condition(family, code, origin)
                    self.assertIn(f"{'int' if is_signed else 'uint'}{width}_t", pred.render())
                    for left in values:
                        for right in values:
                            a = left - modulus if is_signed and left >= sign else left
                            b = right - modulus if is_signed and right >= sign else right
                            expected = {">": a > b, ">=": a >= b, "<": a < b, "<=": a <= b, "==": a == b, "!=": a != b}[relation]
                            self.assertEqual(evaluate_condition(pred, left=left, right=right), expected,
                                (family, code, width, left, right))

    def test_carry_and_borrow_are_architecture_specific(self):
        for width in (8, 16, 32, 64):
            self.assertTrue(integer_flags("x86", "sub", 0, 1, width)["CF"])
            self.assertFalse(integer_flags("arm", "sub", 0, 1, width)["C"])
            self.assertFalse(integer_flags("x86", "sub", 1, 0, width)["CF"])
            self.assertTrue(integer_flags("arm", "sub", 1, 0, width)["C"])
            self.assertTrue(integer_flags("x86", "add", (1 << width) - 1, 0, width, carry=1)["CF"])

    def test_nan_zero_infinity_and_fp_condition_code_differences(self):
        values = (math.nan, -math.inf, -1.0, -0.0, 0.0, 1.0, math.inf)
        checks = {
            "x86": {"a": lambda a, b, u: not u and a > b,
                    "ae": lambda a, b, u: not u and a >= b,
                    "b": lambda a, b, u: u or a < b,
                    "be": lambda a, b, u: u or a <= b,
                    "e": lambda a, b, u: u or a == b,
                    "ne": lambda a, b, u: not u and a != b,
                    "p": lambda a, b, u: u, "np": lambda a, b, u: not u,
                    "g": lambda a, b, u: not u and a != b,
                    "ge": lambda a, b, u: True, "l": lambda a, b, u: False},
            "arm": {"eq": lambda a, b, u: not u and a == b,
                    "ne": lambda a, b, u: u or a != b,
                    "hi": lambda a, b, u: u or a > b,
                    "ls": lambda a, b, u: not u and a <= b,
                    "lt": lambda a, b, u: u or a < b,
                    "lo": lambda a, b, u: not u and a < b,
                    "gt": lambda a, b, u: not u and a > b,
                    "ge": lambda a, b, u: not u and a >= b,
                    "vs": lambda a, b, u: u, "vc": lambda a, b, u: not u},
        }
        for family, predicates in checks.items():
            origin = ComparisonOrigin(4, family, 64, "floating", "a", "b")
            for code, expected in predicates.items():
                pred = condition(family, code, origin)
                self.assertEqual(pred.domain, "floating")
                for a in values:
                    for b in values:
                        unordered = math.isnan(a) or math.isnan(b)
                        self.assertEqual(evaluate_condition(pred, left=a, right=b), expected(a, b, unordered), (family, code, a, b))
        self.assertEqual(floating_flags("arm", math.nan, 0), {"N": False, "Z": False, "C": True, "V": True})

    def test_missing_flags_are_unknown_with_three_valued_short_circuit(self):
        self.assertIsNone(evaluate_condition(condition("x86", "g"), flags={}))
        self.assertFalse(evaluate_condition(condition("x86", "a"), flags={"CF": True}))
        self.assertTrue(evaluate_condition(condition("x86", "be"), flags={"CF": True}))

    def test_comparison_captures_survive_register_changes_but_not_flag_changes(self):
        rows = [instruction(0, "cmp", "eax", "ebx"), instruction(1, "mov", "eax", "0"),
                instruction(2, "jl", "0x4", kind="jump", target=4, conditional=True),
                instruction(3, "ret", kind="return"), instruction(4, "ret", kind="return")]
        output = generate_pseudoc(function(*rows), "x86_64")
        self.assertIn("(int32_t)cmp_left_0 < (int32_t)cmp_right_0", output.pseudoc)
        rows[1] = instruction(1, "add", "eax", "1")
        output = generate_pseudoc(function(*rows), "x86_64")
        self.assertIn("flags.SF != flags.OF", output.pseudoc)
        pred = output.microcode[2]["operations"][0]["attributes"]["condition"]
        self.assertIsNone(pred["origin"])

    def test_join_does_not_use_lexically_adjacent_compare(self):
        rows = [instruction(0, "jne", "0x2", kind="jump", target=2, conditional=True),
                instruction(1, "cmp", "eax", "ebx"),
                instruction(2, "jg", "0x4", kind="jump", target=4, conditional=True),
                instruction(3, "ret", kind="return"), instruction(4, "ret", kind="return")]
        output = generate_pseudoc(function(*rows), "x86_64")
        pred = output.microcode[2]["operations"][0]["attributes"]["condition"]
        self.assertEqual(pred["domain"], "flags")
        self.assertIsNone(pred["origin"])

    @unittest.skipUnless(shutil.which("cc"), "需要 C 编译器验证实际比较代码")
    def test_generated_signed_and_unsigned_c_have_distinct_results(self):
        functions = []
        for branch, name in (("jl", "signed_less"), ("jb", "unsigned_less")):
            rows = [instruction(0, "cmp", "eax", "ebx"),
                    instruction(1, branch, "0x4", kind="jump", target=4, conditional=True),
                    instruction(2, "mov", "eax", "0"), instruction(3, "ret", kind="return"),
                    instruction(4, "mov", "eax", "1"), instruction(5, "ret", kind="return")]
            functions.append(generate_pseudoc(function(*rows, name=name), "x86_64").pseudoc)
        source = '''#include <stdint.h>
#include <string.h>
typedef struct { int SF, OF, ZF, CF, PF; } flags_t;
flags_t symbolic_flags(void) { return (flags_t){0}; }
flags_t x86_sub_flags32(uint32_t a, uint32_t b) { return (flags_t){0}; }
uint64_t symbolic_input(const char *name) { return strcmp(name,"rax")==0 ? 0xffffffffU : 1; }
'''
        source += "\n".join(functions)
        source += "\nint main(void) { return signed_less()==1 && unsigned_less()==0 ? 0 : 1; }\n"
        with tempfile.TemporaryDirectory() as tmp:
            path, binary = Path(tmp) / "compare.c", Path(tmp) / "compare"
            path.write_text(source)
            subprocess.run([shutil.which("cc"), str(path), "-o", str(binary)], check=True, capture_output=True)
            subprocess.run([str(binary)], check=True, capture_output=True)


class CategoryLifterTests(unittest.TestCase):
    def test_major_categories_have_independent_handlers(self):
        self.assertEqual(set(list_lifters()), {"control_flow", "comparison", "data_transfer", "integer_arithmetic",
            "bitwise", "memory", "stack", "floating_point", "system"})
        fixtures = [
            ("x86_64", instruction(0, "mov", "eax", "42"), "data_transfer", "assign"),
            ("x86_64", instruction(0, "movsx", "eax", "al"), "conversion", "assign"),
            ("x86_64", instruction(0, "adc", "eax", "ebx"), "integer_arithmetic", "carry_input"),
            ("x86_64", instruction(0, "xor", "eax", "eax"), "bitwise", "flags_logic"),
            ("x86_64", instruction(0, "push", "rax"), "stack", "stack_push"),
            ("arm64", instruction(0, "ldp", "x0", "x1", "[sp", "#16]!"), "memory", "assign"),
            ("x86_64", instruction(0, "cmp", "eax", "ebx"), "comparison", "compare"),
            ("x86_64", instruction(0, "setg", "al"), "conditional", "set_condition"),
            ("x86_64", instruction(0, "addsd", "xmm0", "xmm1"), "floating_point", "fadd"),
            ("x86_64", instruction(0, "stc"), "system", "flag_write"),
        ]
        for arch, row, category, opcode in fixtures:
            with self.subTest(architecture=arch, instruction=row["mnemonic"]):
                result = lift_instruction(row, arch)
                self.assertTrue(result["supported"])
                self.assertEqual(result["category"], category)
                self.assertEqual(result["operations"][0]["opcode"], opcode)

    def test_wide_immediate_and_normalized_pc_relative_addresses(self):
        for arch, mnemonic, operand, expected in (("x86_64", "movabs", "0x123456789abcdef0", 0x123456789abcdef0),
                ("arm64", "adr", "#0x1234", 0x1234), ("arm64", "adrp", "#0x2000", 0x2000)):
            row = lift_instruction(instruction(0, mnemonic, "rax" if arch == "x86_64" else "x0", operand), arch)
            self.assertTrue(row["supported"])
            self.assertEqual(evaluate_expression(row["operations"][0]["expression"]), expected)

    def test_opaque_effects_are_barriers_not_guessed_assignments(self):
        for mnemonic, args, category in (("made_up", (), "opaque"), ("syscall", (), "system"),
                ("cmpxchg", ("[rax]", "ebx"), "memory"), ("vaddps", ("ymm0", "ymm1", "ymm2"), "floating_point")):
            result = lift_instruction(instruction(0, mnemonic, *args), "x86_64")
            self.assertFalse(result["supported"])
            self.assertEqual(result["category"], category)
            self.assertEqual(result["memory_effect"], "unknown")
            self.assertEqual(result["flag_effect"], "unknown")
            self.assertTrue(result["operations"][0]["attributes"]["barrier"])

    def test_cmov_memory_source_is_unconditional_and_flags_preserved(self):
        result = lift_instruction(instruction(0, "cmovg", "eax", "dword ptr [rbx]"), "x86_64")
        self.assertEqual(result["memory_effect"], "read")
        self.assertEqual(result["flag_effect"], "preserve")
        self.assertIn("rbx", result["reads"])
        self.assertEqual(result["operations"][0]["attributes"]["source_read"], "unconditional")

    def test_false_32_bit_cmov_zeros_upper_bits_and_keeps_memory_read(self):
        snapshot = function(instruction(0, "mov", "rax", "0x100000002"),
            instruction(1, "mov", "ebx", "0"), instruction(2, "cmp", "ebx", "ebx"),
            instruction(3, "cmovne", "eax", "dword ptr [rcx]"), instruction(4, "ret", kind="return"))
        output = generate_pseudoc(snapshot, "x86_64")
        report = analyze_microcode(output.microcode)
        self.assertEqual(report["remaining_register_bits"]["rax"]["value"], 2)
        self.assertEqual(report["remaining_register_bits"]["rax"]["known_mask"], (1 << 64) - 1)
        self.assertIn("rax = (uint32_t)", output.pseudoc)
        self.assertEqual(output.pseudoc.count("load32(rcx)"), 1)

    def test_set_condition_records_partial_alias_and_memory_store(self):
        row = lift_instruction(instruction(0, "setne", "ah"), "x86_64")
        attributes = row["operations"][0]["attributes"]
        self.assertEqual((attributes["destination_width"], attributes["storage_width"], attributes["bit_offset"]), (8, 64, 8))
        store = lift_instruction(instruction(0, "setne", "byte ptr [rax]"), "x86_64")
        self.assertEqual(store["memory_effect"], "write")
        self.assertIn("rax", store["reads"])
        snapshot = function(instruction(0, "mov", "rax", "0x12345678"), instruction(1, "cmp", "rax", "rax"),
            instruction(2, "setne", "ah"), instruction(3, "ret", kind="return"))
        report = analyze_microcode(lift_function(snapshot, "x86_64")["instructions"])
        self.assertEqual(report["remaining_register_bits"]["rax"]["value"], 0x12340078)

    def test_scalar_conversions_record_rounding_signedness_and_invalid_results(self):
        fixtures = [
            ("x86_64", "cvtsi2ss", ("xmm0", "eax"), "integer_to_float", "fp_environment"),
            ("arm64", "ucvtf", ("d0", "w1"), "integer_to_float", "fp_environment"),
            ("x86_64", "cvttsd2si", ("eax", "xmm1"), "float_to_integer", "toward_zero"),
            ("x86_64", "cvtsd2si", ("rax", "xmm1"), "float_to_integer", "fp_environment"),
            ("arm64", "fcvtzu", ("w0", "d1"), "float_to_integer", "toward_zero"),
            ("x86_64", "cvtsd2ss", ("xmm0", "xmm1"), "float_resize", "fp_environment"),
        ]
        for arch, mnemonic, args, opcode, rounding in fixtures:
            with self.subTest(instruction=mnemonic):
                row = lift_instruction(instruction(0, mnemonic, *args), arch)
                self.assertTrue(row["supported"])
                self.assertEqual(row["category"], "conversion")
                operation = row["operations"][0]
                self.assertEqual(operation["opcode"], opcode)
                self.assertEqual(operation["attributes"]["rounding"], rounding)
                self.assertIn("fp_environment", row["reads"])
                with self.assertRaises(UnknownValue):
                    evaluate_expression(operation["expression"], {"rax": 1, "x1": 1, "v1": math.nan, "xmm1": math.nan})
        signed_input = lift_instruction(instruction(0, "cvtsi2ss", "xmm0", "eax"), "x86_64")
        unsigned_input = lift_instruction(instruction(0, "ucvtf", "d0", "w1"), "arm64")
        self.assertTrue(signed_input["operations"][0]["attributes"]["source_signed"])
        self.assertFalse(unsigned_input["operations"][0]["attributes"]["source_signed"])
        self.assertIn("xmm0", signed_input["reads"])
        ambiguous = lift_instruction(instruction(0, "cvtsi2ss", "xmm0", "[rax]"), "x86_64")
        self.assertFalse(ambiguous["supported"])

    def test_load_writeback_alias_uses_register_root(self):
        for mnemonic, args in (("ldr", ("w0", "[x0]", "#4")), ("ldp", ("w0", "w1", "[x0", "#8]!")),
                ("str", ("x0", "[x0]", "#8")), ("ldp", ("x0", "x0", "[x1]"))):
            row = lift_instruction(instruction(0, mnemonic, *args), "arm64")
            self.assertFalse(row["supported"])
            self.assertEqual(row["memory_effect"], "unknown")

    def test_zero_register_write_keeps_load_side_effect(self):
        output = generate_pseudoc(function(instruction(0, "ldr", "xzr", "[x0]", size=4),
            instruction(4, "ret", kind="return", size=4)), "arm64")
        self.assertIn("(void)(load64(memory_address_0));", output.pseudoc)
        self.assertEqual(output.microcode[0]["memory_effect"], "read")
        self.assertEqual(output.microcode[0]["operations"][0]["opcode"], "discard")

    def test_indirect_control_flow_keeps_target_expression_and_reads(self):
        for mnemonic, kind in (("jmp", "jump"), ("call", "call")):
            result = lift_instruction(instruction(0, mnemonic, "qword ptr [rax]", kind=kind), "x86_64")
            attributes = result["operations"][0]["attributes"]
            self.assertEqual(attributes["target_expression"]["opcode"], "load")
            self.assertIn("rax", result["reads"])
            self.assertIsNone(attributes["target"])

    def test_stack_memory_operands_have_both_read_and_write_effects(self):
        for mnemonic in ("push", "pop"):
            result = lift_instruction(instruction(0, mnemonic, "qword ptr [rsp]"), "x86_64")
            self.assertTrue(result["supported"])
            self.assertEqual(result["memory_effect"], "read_write")

    @unittest.skipUnless(importlib.util.find_spec("capstone"), "需要 Capstone 验证 ARM32 条件分支")
    def test_arm32_condition_suffix_survives_decode_and_lifting(self):
        decoder = NativeDecoder("arm")
        encoded = (0xba000002).to_bytes(4, "little")  # blt +16，PC 基值为 +8。
        for method in (decoder.decode_bytes, decoder.decode_bytes_fast):
            rows, warnings = method(encoded, 0)
            self.assertFalse(warnings)
            self.assertEqual(rows[0]["branch_info"], {"kind": "jump", "target": 16, "conditional": True})
            result = lift_instruction(rows[0], "arm")
            self.assertTrue(result["supported"])
            self.assertEqual(result["operations"][0]["attributes"]["condition"]["code"], "lt")

    def test_atomic_exchange_captures_address_before_register_write(self):
        output = generate_pseudoc(function(instruction(0, "xchg", "rax", "qword ptr [rax]"),
            instruction(1, "ret", kind="return")), "x86_64")
        self.assertIn("atomic_exchange64(rax, rax)", output.pseudoc)
        self.assertEqual(output.microcode[0]["memory_effect"], "atomic_read_write")

    def test_memory_arithmetic_does_not_duplicate_load(self):
        output = generate_pseudoc(function(instruction(0, "add", "eax", "dword ptr [rbx]"),
            instruction(1, "ret", kind="return")), "x86_64")
        self.assertEqual(output.pseudoc.count("load32(rbx)"), 1)
        for mnemonic, operands in (("inc", ("dword ptr [rbx]",)), ("neg", ("dword ptr [rbx]",)),
                ("shr", ("dword ptr [rbx]", "1")), ("imul", ("eax", "dword ptr [rbx]"))):
            with self.subTest(instruction=mnemonic):
                output = generate_pseudoc(function(instruction(0, mnemonic, *operands),
                    instruction(1, "ret", kind="return")), "x86_64")
                self.assertEqual(output.pseudoc.count("load32(rbx)"), 1)

    def test_shift_count_rules_are_in_semantics(self):
        result = lift_instruction(instruction(0, "shr", "eax", "32"), "x86_64")
        flags_op, assignment = result["operations"]
        self.assertEqual(flags_op["attributes"]["count_zero"], "preserve")
        self.assertEqual(evaluate_expression(assignment["expression"], {"rax": 0x80000000}), 0x80000000)
        arm = lift_instruction(instruction(0, "asr", "w0", "w1", "#31"), "arm64")
        self.assertEqual(evaluate_expression(arm["operations"][0]["expression"], {"x1": 0x80000000}), 0xffffffff)
        variable = lift_instruction(instruction(0, "lsl", "w0", "w1", "w2"), "arm64")
        self.assertEqual(evaluate_expression(variable["operations"][0]["expression"], {"x1": 7, "x2": 32}), 7)
        arm32 = lift_instruction(instruction(0, "lsl", "r0", "r1", "r2"), "arm")
        self.assertEqual(evaluate_expression(arm32["operations"][0]["expression"], {"r1": 7, "r2": 256}), 7)
        self.assertEqual(evaluate_expression(arm32["operations"][0]["expression"], {"r1": 7, "r2": 32}), 0)

    def test_signed_division_differs_from_unsigned_and_preserves_traps(self):
        signed_div = operation("sdiv", 32, constant(-7, 32), constant(2, 32))
        unsigned_div = operation("udiv", 32, constant(-7, 32), constant(2, 32))
        self.assertEqual(evaluate_expression(signed_div), (-3) & 0xffffffff)
        self.assertEqual(evaluate_expression(unsigned_div), 0xfffffff9 // 2)
        with self.assertRaises(UnknownValue):
            evaluate_expression(operation("sdiv", 32, constant(-(1 << 31), 32), constant(-1, 32)))
        self.assertEqual(evaluate_expression(operation("arm_sdiv", 32, constant(7, 32), constant(0, 32))), 0)
        division = lift_instruction(instruction(0, "idiv", "ecx"), "x86_64")
        self.assertEqual(division["operations"][0]["attributes"]["possible_traps"], ["zero_divisor", "quotient_overflow"])

    def test_conditional_compare_records_false_nzcv_and_drops_origin(self):
        snapshot = function(instruction(0, "cmp", "w0", "w1", size=4),
            instruction(4, "ccmp", "w2", "w3", "#0", "gt", size=4),
            instruction(8, "b.lt", "0x10", size=4, kind="jump", target=16, conditional=True),
            instruction(12, "ret", size=4, kind="return"), instruction(16, "ret", size=4, kind="return"))
        output = generate_pseudoc(snapshot, "arm64")
        ccmp = output.microcode[1]["operations"][0]
        self.assertEqual(ccmp["opcode"], "conditional_compare")
        self.assertEqual(ccmp["attributes"]["false_nzcv"], 0)
        self.assertIsNone(output.microcode[2]["operations"][0]["attributes"]["condition"]["origin"])

    @unittest.skipUnless(importlib.util.find_spec("capstone"), "需要 Capstone 验证真实 TBZ 操作数")
    def test_arm64_tbz_target_is_address_not_bit_number_in_both_decode_paths(self):
        decoder = NativeDecoder("arm64")
        encoded = (0x36080080).to_bytes(4, "little")  # tbz w0, #1, +16
        for method in (decoder.decode_bytes, decoder.decode_bytes_fast):
            rows, warnings = method(encoded, 0)
            self.assertFalse(warnings)
            self.assertEqual(rows[0]["branch_info"]["target"], 16)
            lifted = lift_instruction(rows[0], "arm64")
            self.assertEqual(lifted["operations"][0]["attributes"]["target"], 16)


class MicrocodeFactsTests(unittest.TestCase):
    def test_arm32_test_preserves_carry_while_arm64_test_clears_it(self):
        for arch, register_name, expected in (("arm", "r0", False), ("arm64", "w0", True)):
            snapshot = function(instruction(0, "mov", register_name, "0", size=4),
                instruction(4, "cmp", register_name, "0", size=4), instruction(8, "tst", register_name, register_name, size=4),
                instruction(12, "b.lo", "0x14", kind="jump", target=20, conditional=True, size=4),
                instruction(16, "ret", kind="return", size=4), instruction(20, "ret", kind="return", size=4))
            report = analyze_microcode(lift_function(snapshot, arch)["instructions"])
            self.assertEqual(next(fact for fact in report["facts"] if fact["kind"] == "branch")["taken"], expected)

    def test_arm32_immediate_rotation_carry_is_not_guessed(self):
        snapshot = function(instruction(0, "mov", "r0", "0", size=4),
            instruction(4, "cmp", "r0", "0", size=4), instruction(8, "tst", "r0", "#0x80000000", size=4),
            instruction(12, "blo", "0x14", kind="jump", target=20, conditional=True, size=4),
            instruction(16, "ret", kind="return", size=4), instruction(20, "ret", kind="return", size=4))
        report = analyze_microcode(lift_function(snapshot, "arm")["instructions"])
        self.assertIsNone(next(fact for fact in report["facts"] if fact["kind"] == "branch")["taken"])

    def test_unknown_partial_write_keeps_unaffected_known_bits(self):
        snapshot = function(instruction(0, "mov", "rax", "0x12345678"),
            instruction(1, "mov", "al", "byte ptr [rbx]"), instruction(2, "ret", kind="return"))
        report = analyze_microcode(lift_function(snapshot, "x86_64")["instructions"])
        known = report["remaining_register_bits"]["rax"]
        self.assertEqual(known["known_mask"], ((1 << 64) - 1) ^ 0xff)
        self.assertEqual(known["value"], 0x12345600)

    def test_xor_test_opaque_predicate_is_proven_without_assembly_execution(self):
        snapshot = function(instruction(0, "xor", "eax", "eax"), instruction(1, "test", "eax", "eax"),
            instruction(2, "jne", "0x4", kind="jump", target=4, conditional=True),
            instruction(3, "ret", kind="return"), instruction(4, "ret", kind="return"))
        report = analyze_microcode(lift_function(snapshot, "x86_64")["instructions"])
        branch = next(fact for fact in report["facts"] if fact["kind"] == "branch")
        self.assertFalse(branch["taken"])
        self.assertEqual(branch["proof"], "known_semantic_values")

    def test_unknown_effects_calls_joins_and_pop_invalidate_facts(self):
        for barrier in (instruction(1, "made_up"), instruction(1, "call", "0x20", kind="call", target=32),
                        instruction(1, "pop", "rax"), instruction(1, "xchg", "rax", "rbx")):
            snapshot = function(instruction(0, "mov", "eax", "0"), barrier, instruction(2, "test", "eax", "eax"),
                instruction(3, "jne", "0x5", kind="jump", target=5, conditional=True),
                instruction(4, "ret", kind="return"), instruction(5, "ret", kind="return"))
            report = analyze_microcode(lift_function(snapshot, "x86_64")["instructions"])
            branch = next(fact for fact in report["facts"] if fact["kind"] == "branch")
            self.assertIsNone(branch["taken"], barrier["mnemonic"])
        for operation in (instruction(1, "bts", "eax", "1"), instruction(1, "rcl", "eax", "1")):
            snapshot = function(instruction(0, "mov", "eax", "0"), operation, instruction(2, "test", "eax", "eax"),
                instruction(3, "jne", "0x5", kind="jump", target=5, conditional=True),
                instruction(4, "ret", kind="return"), instruction(5, "ret", kind="return"))
            report = analyze_microcode(lift_function(snapshot, "x86_64")["instructions"])
            self.assertIsNone(next(fact for fact in report["facts"] if fact["kind"] == "branch")["taken"])

    def test_partial_register_knowledge_and_explicit_budget(self):
        snapshot = function(instruction(0, "mov", "al", "0"), instruction(1, "test", "al", "al"),
            instruction(2, "jne", "0x4", kind="jump", target=4, conditional=True),
            instruction(3, "ret", kind="return"), instruction(4, "ret", kind="return"))
        lifted = lift_function(snapshot, "x86_64")["instructions"]
        report = analyze_microcode(lifted)
        self.assertFalse(next(fact for fact in report["facts"] if fact["kind"] == "branch")["taken"])
        self.assertTrue(analyze_microcode(lifted, max_steps=1)["truncated"])

    def test_mba_rewrite_is_equivalent_at_wraparound_boundaries(self):
        for width in (8, 16, 32, 64):
            x, y = register("x", width), register("y", width)
            original = operation("add", width, operation("and", width, x, y), operation("or", width, x, y))
            reduced = simplify_expression(original)
            self.assertEqual(reduced, operation("add", width, x, y))
            values = [0, 1, (1 << (width - 1)), (1 << width) - 1]
            rng = random.Random(width)
            values += [rng.getrandbits(width) for _ in range(10)]
            for a in values:
                for b in values:
                    self.assertEqual(evaluate_expression(original, {"x": a, "y": b}), evaluate_expression(reduced, {"x": a, "y": b}))
            opaque = operation("sub", width, original, operation("add", width, x, y))
            self.assertEqual(simplify_expression(opaque), constant(0, width))

    def test_effectful_loads_and_fp_nan_are_not_simplified_as_integers(self):
        load = Expression("load", 32, (Expression("address", 64, name="pointer"),))
        expression = operation("xor", 32, load, load)
        self.assertEqual(simplify_expression(expression), expression)
        floating = Expression("fsub", 64, (Expression("float_register", 64, name="x", domain="floating"),) * 2, domain="floating")
        self.assertEqual(simplify_expression(floating), floating)
        self.assertTrue(math.isnan(evaluate_expression(floating, {"x": math.inf})))
        for value in (operation("sdiv", 32, register("x"), register("y")),
                      Expression("float_to_signed", 32, (Expression("float_register", 64, name="v0", domain="floating"),))):
            expression = operation("sub", 32, value, value)
            self.assertEqual(simplify_expression(expression), expression)
        mixed = operation("sub", 64, floating, floating)
        self.assertEqual(simplify_expression(mixed), mixed)


class MicrocodeApiTests(unittest.TestCase):
    def setUp(self):
        self.result = AnalysisResult("missing.elf", "elf", "kkagent", "partial",
            metadata={"architecture": "x86_64"}, functions=[function(instruction(0, "xor", "eax", "eax"),
            instruction(1, "test", "eax", "eax"), instruction(2, "jne", "0x4", kind="jump", target=4, conditional=True),
            instruction(3, "ret", kind="return"), instruction(4, "ret", kind="return"))])
        pipeline.populate_native_pseudoc(self.result)

    def test_python_and_mcp_page_owned_snapshots_without_source_or_decoder(self):
        view = AnalysisView(self.result)
        server = McpServer()
        try:
            server._snapshots["fixture"] = view.snapshot()
            with patch("fangida.processors.get_processor", side_effect=AssertionError("查询不能重新解码")):
                page = view.microcode(0, 0, 1)
                self.assertEqual(page["next_offset"], 1)
                self.assertEqual(page["items"][0]["category"], "bitwise")
                page["items"][0]["operations"].clear()
                self.assertTrue(view.microcode(0)["items"][0]["operations"])
                response = server.call_tool("get_microcode", {"handle": "fixture", "address": 2, "category": "comparison"})
                self.assertEqual(response["structuredContent"]["items"][0]["mnemonic"], "test")
                facts = server.call_tool("get_microcode_facts", {"handle": "fixture", "address": 0, "kind": "branch"})
                self.assertFalse(facts["structuredContent"]["items"][0]["taken"])
                self.assertFalse(view.microcode_facts(0, kind="branch")["items"][0]["taken"])
        finally:
            server.close()

    def test_expression_tool_needs_no_file_handle(self):
        server = McpServer()
        try:
            expr = operation("xor", 32, register("x"), register("x"))
            response = server.call_tool("simplify_micro_expression", {"expression": expr.to_dict()})
            self.assertEqual(response["structuredContent"]["expression"], constant(0, 32).to_dict())
            self.assertFalse(response["structuredContent"]["assembly_execution"])
        finally:
            server.close()

    def test_old_saved_results_remain_readable_and_do_not_fabricate_microcode(self):
        old = AnalysisResult("missing", "elf", "kkagent", "partial", functions=[{"start": 0, "pseudoc": "void f() {}"}])
        view = AnalysisView(old)
        with self.assertRaisesRegex(ValueError, "unavailable"):
            view.microcode(0)
        self.assertEqual(view.functions()[0]["pseudoc"], "void f() {}")

    def test_existing_ghidra_c_keeps_provenance_and_receives_independent_microcode(self):
        entry = self.result.functions[0]
        entry.pop("microcode")
        entry.pop("microcode_analysis")
        entry.update(pseudoc="int ghidra() { return 0; }", pseudoc_producer="ghidra", pseudoc_truncated=False)
        pipeline.populate_native_pseudoc(self.result)
        self.assertEqual(entry["pseudoc"], "int ghidra() { return 0; }")
        self.assertEqual(entry["pseudoc_producer"], "ghidra")
        self.assertFalse(entry["pseudoc_truncated"])
        self.assertEqual(AnalysisView(self.result).microcode(0)["total"], 5)
        self.assertEqual(self.result.stats["pseudoc_functions"], 0)
        self.assertEqual(self.result.stats["microcode_functions"], 1)

    def test_optional_microcode_failure_does_not_discard_pseudoc_or_analysis(self):
        result = AnalysisResult("missing", "elf", "kkagent", "partial", metadata={"architecture": "x86_64"},
            functions=[function(instruction(0, "ret", kind="return"))])
        with patch("fangida.plugins.pseudoc.microcode.analyze_microcode", side_effect=ValueError("provider failure")):
            pipeline.populate_native_pseudoc(result)
        self.assertIn("pseudoc", result.functions[0])
        self.assertNotIn("microcode", result.functions[0])
        self.assertTrue(any("Microcode unavailable" in warning for warning in result.warnings))

    def test_c_text_truncation_does_not_truncate_independent_microcode(self):
        from fangida.plugins.pseudoc.models import PseudocodeResult
        entry = self.result.functions[0]
        for field in ("pseudoc", "microcode", "microcode_analysis"):
            entry.pop(field)
        with patch.object(pipeline, "generate_pseudoc", return_value=PseudocodeResult("/* text limit */", "fixture", True)):
            pipeline.populate_native_pseudoc(self.result)
        self.assertTrue(entry["pseudoc_truncated"])
        self.assertTrue(entry["microcode_complete"])
        self.assertEqual(len(entry["microcode"]), 5)

    def test_microcode_and_facts_round_trip_sqlite_without_source(self):
        from fangida.plugins.sqlite_storage import SQLiteAnalysisDatabase
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "sample.bin"
            source.write_bytes(b"\x31\xc0\xc3")
            result = copy.deepcopy(self.result)
            result.path = str(source)
            path = Path(directory) / "saved.fdb"
            with SQLiteAnalysisDatabase(path, create=True) as database:
                identifier = database.save_analysis(source, result)
            source.unlink()
            with SQLiteAnalysisDatabase(path, read_only=True) as database:
                view = AnalysisView.from_snapshot(database.get_snapshot(identifier))
                self.assertEqual(view.microcode(0)["items"], result.functions[0]["microcode"])
                branch = view.microcode_facts(0, kind="branch")["items"][0]
                self.assertFalse(branch["taken"])


if __name__ == "__main__":
    unittest.main()
