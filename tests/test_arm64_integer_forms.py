"""A64 移位操作数、宽乘法和乘减的独立固定宽度边界回归。"""
from __future__ import annotations

import unittest

from fangida.plugins.pseudoc import generate_pseudoc
from fangida.plugins.pseudoc.microcode import analyze_microcode, evaluate_expression, lift_function, lift_instruction
from tests.test_pseudoc import function, instruction
from tests.test_reconstruction import compile_run


def shifted(number, width, kind, count):
    mask = (1 << width) - 1
    number &= mask
    if kind == "lsl":
        return (number * (1 << count)) & mask
    if kind == "lsr":
        return number // (1 << count)
    if kind == "asr":
        if number >= 1 << (width - 1):
            number -= 1 << width
        return (number // (1 << count)) & mask
    bits = f"{number:0{width}b}"
    return int(bits[-count:] + bits[:-count], 2) if count else number


def flags_for(left, right, width, subtract):
    modulus = 1 << width
    sign = modulus // 2
    left, right = left % modulus, right % modulus
    raw = left - right if subtract else left + right
    result = raw % modulus
    signed_left = left - modulus if left >= sign else left
    signed_right = right - modulus if right >= sign else right
    signed_result = signed_left - signed_right if subtract else signed_left + signed_right
    return {"N": result >= sign, "Z": result == 0,
            "C": left >= right if subtract else raw >= modulus,
            "V": signed_result < -sign or signed_result >= sign}


def boundary_values(width):
    return (0, 1, (1 << (width - 1)) - 1, 1 << (width - 1), (1 << width) - 1,
            int("a5" * (width // 8), 16))


def assignment_from(row):
    return next(operation for operation in row["operations"] if operation["opcode"] == "assign")


class ARM64IntegerFormsTests(unittest.TestCase):
    def test_add_sub_all_register_shift_kinds_and_fixed_width_boundaries(self):
        for width in (32, 64):
            prefix = "w" if width == 32 else "x"
            for mnemonic in ("add", "sub", "adds", "subs"):
                for kind in ("lsl", "lsr", "asr"):
                    for count in (0, 1, width - 1):
                        row = lift_instruction(instruction(0, mnemonic, prefix + "0", prefix + "1",
                                                           prefix + "2", f"{kind} #{count}", size=4), "arm64")
                        self.assertTrue(row["supported"], (width, mnemonic, kind, count))
                        self.assertEqual(row["category"], "integer_arithmetic")
                        self.assertEqual(row["flag_effect"], "write" if mnemonic.endswith("s") else "preserve")
                        self.assertNotIn("x0", row["reads"])
                        operation = assignment_from(row)
                        self.assertEqual(operation["attributes"]["zero_upper"], width == 32)
                        for left in boundary_values(width):
                            for right in boundary_values(width):
                                shifted_right = shifted(right, width, kind, count)
                                expected = (left - shifted_right if mnemonic.startswith("sub") else left + shifted_right) % (1 << width)
                                self.assertEqual(evaluate_expression(operation["expression"], {"x1": left, "x2": right}), expected,
                                                 (width, mnemonic, kind, count, left, right))

    def test_arithmetic_flags_use_shifted_operand_and_arm_no_borrow(self):
        conditions = {"mi": "N", "eq": "Z", "hs": "C", "vs": "V"}
        for width in (32, 64):
            prefix = "w" if width == 32 else "x"
            for mnemonic in ("adds", "subs"):
                for kind in ("lsl", "lsr", "asr"):
                    count = width - 1
                    for left, right in ((0, (1 << width) - 1), ((1 << (width - 1)) - 1, 1),
                                        (1 << (width - 1), (1 << width) - 1)):
                        expected = flags_for(left, shifted(right, width, kind, count), width, mnemonic == "subs")
                        for condition, flag in conditions.items():
                            snapshot = function(
                                instruction(0, "mov", "x1", hex(left), size=4),
                                instruction(4, "mov", "x2", hex(right), size=4),
                                instruction(8, mnemonic, prefix + "0", prefix + "1", prefix + "2", f"{kind} #{count}", size=4),
                                instruction(12, "b." + condition, "#0x14", kind="jump", target=20, conditional=True, size=4),
                                instruction(16, "ret", kind="return", size=4), instruction(20, "ret", kind="return", size=4),
                            )
                            facts = analyze_microcode(lift_function(snapshot, "arm64")["instructions"])["facts"]
                            branch = next(fact for fact in facts if fact["kind"] == "branch")
                            self.assertEqual(branch["taken"], expected[flag], (width, mnemonic, kind, left, right, flag))

    def test_extended_arithmetic_sign_width_and_sp_alias_shift_limit(self):
        extensions = {"uxtb": (8, False), "uxth": (16, False), "uxtw": (32, False), "uxtx": (64, False),
                      "sxtb": (8, True), "sxth": (16, True), "sxtw": (32, True), "sxtx": (64, True)}
        for width in (32, 64):
            prefix = "w" if width == 32 else "x"
            for extension, (bits, signed) in extensions.items():
                source = "x2" if width == 64 and bits == 64 else "w2"
                for amount in (0, 4):
                    for mnemonic in ("add", "subs"):
                        row = lift_instruction(instruction(0, mnemonic, prefix + "0", prefix + "1", source, f"{extension} #{amount}", size=4), "arm64")
                        self.assertTrue(row["supported"], (width, mnemonic, extension, amount))
                        for right in boundary_values(64):
                            retained_width = min(width, bits)
                            retained = right % (1 << retained_width)
                            if signed and retained >= 1 << (retained_width - 1):
                                retained -= 1 << retained_width
                            operand = retained * (1 << amount)
                            expected = (7 - operand if mnemonic == "subs" else 7 + operand) % (1 << width)
                            self.assertEqual(evaluate_expression(assignment_from(row)["expression"], {"x1": 7, "x2": right}), expected)
        for args in (("x0", "sp", "x1"), ("sp", "x0", "x1", "lsl #4"),
                     ("wsp", "w0", "w1", "lsl #4"), ("x0", "sp", "w1", "sxtw #4")):
            self.assertTrue(lift_instruction(instruction(0, "add", *args, size=4), "arm64")["supported"])
        for args in (("x0", "sp", "x1", "lsl #5"), ("x0", "x1", "w2", "uxtw #5"),
                     ("x0", "x1", "x2", "uxtw #4"), ("x0", "xzr", "w2", "sxtw #4")):
            self.assertFalse(lift_instruction(instruction(0, "add", *args, size=4), "arm64")["supported"])
        compared = lift_instruction(instruction(0, "cmp", "sp", "w1", "sxtw #4", size=4), "arm64")
        self.assertTrue(compared["supported"])
        self.assertEqual(evaluate_expression(compared["operations"][0]["inputs"][1], {"x1": 0xffffffff}), (1 << 64) - 16)

    def test_immediate_shift_and_comparison_capture_use_the_effective_value(self):
        for width in (32, 64):
            prefix = "w" if width == 32 else "x"
            for immediate in (0, 1, 2, 4095):
                for shift in (0, 12):
                    row = lift_instruction(instruction(0x100, "cmp", prefix + "0", f"#{immediate}", f"lsl #{shift}", size=4), "arm64")
                    operation, = row["operations"]
                    self.assertTrue(row["supported"])
                    self.assertEqual(operation["opcode"], "compare")
                    self.assertEqual(evaluate_expression(operation["inputs"][1]), immediate << shift)
                    self.assertEqual(operation["attributes"]["captures"], ["cmp_left_100", "cmp_right_100"])
                    self.assertEqual(operation["attributes"]["operand_form"], "immediate")
            for mnemonic in ("add", "sub", "adds", "subs"):
                row = lift_instruction(instruction(0, mnemonic, prefix + "0", prefix + "1", "#4095", "lsl #12", size=4), "arm64")
                operation = assignment_from(row)
                for left in boundary_values(width):
                    expected = (left - (4095 << 12) if mnemonic.startswith("sub") else left + (4095 << 12)) % (1 << width)
                    self.assertEqual(evaluate_expression(operation["expression"], {"x1": left}), expected)
        for operand in ("#4096", "#0xfff000"):
            row = lift_instruction(instruction(0, "cmp", "w0", operand, size=4), "arm64")
            self.assertTrue(row["supported"])
            self.assertEqual(evaluate_expression(row["operations"][0]["inputs"][1]), int(operand[1:], 0))
        row = lift_instruction(instruction(0, "add", "sp", "sp", "#1", "lsl #12", size=4), "arm64")
        self.assertTrue(row["supported"])
        self.assertEqual(evaluate_expression(assignment_from(row)["expression"], {"sp": 0x10000}), 0x11000)

    def test_logical_shifts_include_rotate_and_invert_after_shifting(self):
        mappings = {"and": "and", "ands": "and", "orr": "or", "eor": "xor",
                    "bic": "and", "bics": "and", "orn": "or", "eon": "xor"}
        for width in (32, 64):
            prefix = "w" if width == 32 else "x"
            mask = (1 << width) - 1
            for mnemonic, logical in mappings.items():
                for kind in ("lsl", "lsr", "asr", "ror"):
                    for count in (0, 1, width - 1):
                        row = lift_instruction(instruction(0, mnemonic, prefix + "0", prefix + "1", prefix + "2", f"{kind} #{count}", size=4), "arm64")
                        self.assertTrue(row["supported"])
                        self.assertNotIn("x0", row["reads"])
                        operation = assignment_from(row)
                        for left in boundary_values(width):
                            for right in boundary_values(width):
                                right_value = shifted(right, width, kind, count)
                                if mnemonic in {"bic", "bics", "orn", "eon"}:
                                    right_value ^= mask
                                expected = {"and": left & right_value, "or": left | right_value, "xor": left ^ right_value}[logical]
                                self.assertEqual(evaluate_expression(operation["expression"], {"x1": left, "x2": right}), expected,
                                                 (width, mnemonic, kind, count, left, right))
                        self.assertEqual(row["flag_effect"], "write" if mnemonic in {"ands", "bics"} else "preserve")
                        if mnemonic in {"ands", "bics"}:
                            self.assertEqual(row["operations"][0]["attributes"]["shifter_carry"], "not_used")

    def test_signed_widening_multiply_and_multiply_subtract_are_not_reversed(self):
        for mnemonic in ("smull", "umull"):
            row = lift_instruction(instruction(0, mnemonic, "x0", "w1", "w2", size=4), "arm64")
            self.assertTrue(row["supported"])
            self.assertNotIn("x0", row["reads"])
            operation = assignment_from(row)
            self.assertEqual(operation["width"], 64)
            self.assertEqual(row["flag_effect"], "preserve")
            for left in boundary_values(32):
                for right in boundary_values(32):
                    first, second = left, right
                    if mnemonic == "smull":
                        first = left - (1 << 32) if left >= 1 << 31 else left
                        second = right - (1 << 32) if right >= 1 << 31 else right
                    expected = first * second % (1 << 64)
                    self.assertEqual(evaluate_expression(operation["expression"], {"x1": left | (0xa5 << 32), "x2": right | (0x5a << 32)}), expected)
        for width in (32, 64):
            prefix = "w" if width == 32 else "x"
            for mnemonic in ("madd", "msub"):
                row = lift_instruction(instruction(0, mnemonic, prefix + "0", prefix + "1", prefix + "2", prefix + "0", size=4), "arm64")
                operation = assignment_from(row)
                self.assertTrue(row["supported"])
                self.assertEqual(row["flag_effect"], "preserve")
                for left in boundary_values(width):
                    for right in boundary_values(width):
                        addend = (1 << width) - 7
                        expected = (addend - left * right if mnemonic == "msub" else addend + left * right) % (1 << width)
                        self.assertEqual(evaluate_expression(operation["expression"], {"x0": addend, "x1": left, "x2": right}), expected)

    def test_invalid_encoding_forms_remain_explicitly_unsupported(self):
        cases = (
            ("add", ("w0", "w1", "w2", "lsl #32")),
            ("sub", ("x0", "x1", "x2", "asr #64")),
            ("add", ("x0", "x1", "x2", "ror #0")),
            ("add", ("x0", "x1", "x2", "lsl #-1")),
            ("add", ("x0", "sp", "x2", "lsr #1")),
            ("add", ("w0", "w1", "x2", "lsl #1")),
            ("add", ("x0", "x1", "#4096", "lsl #12")),
            ("subs", ("sp", "sp", "#1", "lsl #12")),
            ("cmp", ("w0", "#1", "lsl #16")),
            ("cmp", ("w0", "#1", "lsr #12")),
            ("cmp", ("w0", "#-1", "lsl #12")),
            ("cmp", ("w0", "#4096", "lsl #12")),
            ("orr", ("x0", "x1", "x2", "ror #64")),
            ("eor", ("w0", "w1", "x2", "ror #1")),
            ("orn", ("x0", "x1", "sp", "lsl #1")),
            ("smull", ("w0", "w1", "w2")),
            ("smull", ("x0", "x1", "w2")),
            ("msub", ("x0", "x1", "x2", "w3")),
            ("msub", ("sp", "x1", "x2", "x3")),
        )
        for mnemonic, operands in cases:
            with self.subTest(mnemonic=mnemonic, operands=operands):
                self.assertFalse(lift_instruction(instruction(0, mnemonic, *operands, size=4), "arm64")["supported"])
        for mnemonic, operands in (("add", ("r0", "r1", "r2", "lsl #1")),
                                   ("orr", ("r0", "r1", "r2", "ror #1")),
                                   ("cmp", ("r0", "#1", "lsl #12")),
                                   ("smull", ("r0", "r1", "r2")),
                                   ("msub", ("r0", "r1", "r2", "r3"))):
            self.assertFalse(lift_instruction(instruction(0, mnemonic, *operands, size=4), "arm")["supported"])

    def test_cmp_cmn_and_tst_shift_forms_feed_correct_flag_branches(self):
        cases = (("cmp", ("w0", "w1", "asr #31"), "hs", True),
                 ("cmp", ("w0", "#1", "lsl #12"), "lo", True),
                 ("cmn", ("w0", "#1", "lsl #12"), "mi", False),
                 ("tst", ("w0", "w1", "ror #31"), "eq", False),
                 ("tst", ("w0", "w1", "ror #31"), "lo", True))
        for mnemonic, operands, condition, expected in cases:
            with self.subTest(mnemonic=mnemonic, operands=operands, condition=condition):
                snapshot = function(instruction(0, "mov", "w0", "#0xffffffff", size=4) if mnemonic == "cmp" and "w1" in operands else instruction(0, "mov", "w0", "#1", size=4),
                                    instruction(4, "mov", "w1", "#0x80000000", size=4),
                                    instruction(8, mnemonic, *operands, size=4),
                                    instruction(12, "b." + condition, "#0x14", kind="jump", target=20, conditional=True, size=4),
                                    instruction(16, "ret", kind="return", size=4), instruction(20, "ret", kind="return", size=4))
                report = analyze_microcode(lift_function(snapshot, "arm64")["instructions"])
                self.assertEqual(report["unsupported_addresses"], [])
                self.assertEqual(next(fact for fact in report["facts"] if fact["kind"] == "branch")["taken"], expected)

    def test_source_c_compiles_and_executes_shift_signed_product_and_msub(self):
        definitions = []
        cases = (
            ("shift_add", "uint32_t", ["uint32_t", "uint32_t"], instruction(0, "add", "w0", "w0", "w1", "asr #31", size=4)),
            ("rotate_or", "uint32_t", ["uint32_t", "uint32_t"], instruction(0, "orr", "w0", "w0", "w1", "ror #1", size=4)),
            ("signed_product", "uint64_t", ["uint32_t", "uint32_t"], instruction(0, "smull", "x0", "w0", "w1", size=4)),
            ("subtract_product", "uint32_t", ["uint32_t", "uint32_t", "uint32_t"], instruction(0, "msub", "w0", "w0", "w1", "w2", size=4)),
        )
        for name, returned, parameters, row in cases:
            prototype = {"return_type": returned, "parameters": [{"register": f"x{i}", "name": f"arg_{i + 1}", "type": ctype} for i, ctype in enumerate(parameters)]}
            result = generate_pseudoc(function(row, instruction(4, "ret", kind="return", size=4), name=name,
                                              prototype=prototype, pseudoc_context={"kind": "elf"}), "arm64", style="readable")
            self.assertNotIn("unknown_value", result.pseudoc)
            self.assertNotIn("unresolved_operation", result.pseudoc)
            definitions.append(result.pseudoc)
        compile_run("\n".join(definitions),
                    "return shift_add(7, UINT32_MAX)==6 && rotate_or(0, 3)==0x80000001U && "
                    "signed_product(UINT32_MAX,2)==UINT64_MAX-1 && "
                    "signed_product(0x80000000U,0x80000000U)==0x4000000000000000ULL && "
                    "subtract_product(3,4,17)==5 && subtract_product(UINT32_MAX,UINT32_MAX,0)==UINT32_MAX ? 0:1;")


if __name__ == "__main__":
    unittest.main()
