"""微码/操作数层性能优化的等价性与缓存安全回归。

这些测试保证：预编译正则、纯函数缓存、单次遍历与表达式复用不改变任何可观察结果
（返回值、异常类型与消息、寄存器副作用、返回对象的独立性），并且缓存有上限。
参考实现逐字取自优化前的代码，用作差分对照。
"""
from __future__ import annotations

import ast
import functools
import random
import re
import types
import unittest
from unittest.mock import patch

from fangida.plugins.pseudoc import native_operands
from fangida.plugins.pseudoc.microcode import common, conditions, evaluate, ir, optimize
from fangida.plugins.pseudoc.microcode import lift_function, lift_instruction
from fangida.plugins.pseudoc.microcode.ir import Expression, MicroOperation, constant
from fangida.plugins.pseudoc.microcode.registry import DEFAULT_LIFTERS, LifterRegistry
from fangida.plugins.pseudoc.native import _Renderer
from fangida.plugins.pseudoc.native_operands import Operands, Register, split_operands


# ---- 优化前的参考实现（仅用于差分对照） ----

def reference_register(architecture, bits, value):
    token = value.lower().strip()
    if architecture.startswith("x86"):
        for wide, dword, word, low, high in (
            ("rax", "eax", "ax", "al", "ah"), ("rbx", "ebx", "bx", "bl", "bh"),
            ("rcx", "ecx", "cx", "cl", "ch"), ("rdx", "edx", "dx", "dl", "dh"),
            ("rsi", "esi", "si", "sil", ""), ("rdi", "edi", "di", "dil", ""),
            ("rsp", "esp", "sp", "spl", ""), ("rbp", "ebp", "bp", "bpl", ""),
        ):
            if token and token in (wide, dword, word, low, high):
                if bits == 32 and token == wide:
                    return None
                width = {wide: 64, dword: 32, word: 16, low: 8, high: 8}[token]
                return Register(wide if bits == 64 else dword, width, 8 if token == high else 0)
        match = re.fullmatch(r"r(8|9|1[0-5])([dwb]?)", token)
        if match and bits == 64:
            return Register("r" + match[1], {"": 64, "d": 32, "w": 16, "b": 8}[match[2]])
    elif architecture == "arm64":
        token = {"fp": "x29", "lr": "x30"}.get(token, token)
        if token in {"xzr", "wzr"}:
            return Register("zero", 64 if token == "xzr" else 32)
        if token in {"sp", "wsp"}:
            return Register("sp", 64 if token == "sp" else 32)
        if re.fullmatch(r"[xw]([0-9]|[12][0-9]|30)", token):
            return Register("x" + token[1:], 64 if token[0] == "x" else 32)
    elif architecture == "arm":
        token = {"sp": "r13", "lr": "r14", "fp": "r11"}.get(token, token)
        if re.fullmatch(r"r([0-9]|1[0-4])", token):
            return Register(token, 32)
    return None


def reference_address(op, value):
    match = re.fullmatch(r"(?:byte|word|dword|qword)?\s*(?:ptr\s+)?\[([^\]]+)\]", value, re.I)
    if match is None:
        raise ValueError("Unsupported memory operand")
    expression = " ".join(match[1].replace(",", " + ").replace("#", "").split())
    if not re.fullmatch(r"[a-zA-Z0-9_+*\-\s]+", expression):
        raise ValueError("Unsupported address expression")
    def replace(found):
        token = found[0]
        if re.fullmatch(r"(?:0x[0-9a-fA-F]+|[0-9]+)", token):
            return token
        if token.lower() in {"rip", "eip"} and op.architecture.startswith("x86"):
            return hex(op.row["addr"] + op.row["size"])
        register = reference_register(op.architecture, op.bits, token)
        if register is None:
            raise ValueError("Unsupported address register")
        return op.read_register(register)
    return re.sub(r"0x[0-9a-fA-F]+|[a-zA-Z_][a-zA-Z0-9_]*|[0-9]+", replace, expression)


def reference_simplify(expression, *, _depth=0):
    expr = Expression.from_dict(expression) if isinstance(expression, dict) else expression
    if _depth > 64:
        raise ValueError("Micro-expression nesting exceeds limit")
    args = tuple(reference_simplify(arg, _depth=_depth + 1) for arg in expr.args)
    expr = Expression(expr.opcode, expr.width, args, expr.value, expr.name, expr.domain)
    if expr.domain != "bitvector" or any(arg.domain != "bitvector" for arg in args) or not expr.pure:
        return expr
    if args and all(arg.opcode == "constant" for arg in args):
        try:
            return constant(int(evaluate.evaluate_expression(expr)), expr.width)
        except evaluate.UnknownValue:
            return expr
    if len(args) != 2 or any(arg.width != expr.width for arg in args):
        return expr
    left, right = args
    if left == right:
        if expr.opcode in {"xor", "sub"}:
            return constant(0, expr.width)
        if expr.opcode in {"and", "or"}:
            return left
    if right.opcode == "constant":
        if right.value == 0:
            if expr.opcode in {"add", "sub", "or", "xor", "shl", "lshr", "ashr", "rol", "ror"}:
                return left
            if expr.opcode in {"and", "mul"}:
                return right
        if expr.opcode == "mul" and right.value == 1:
            return left
        if right.value == (1 << expr.width) - 1:
            if expr.opcode == "and":
                return left
            if expr.opcode == "or":
                return right
        if left.opcode == expr.opcode == "xor" and left.args[1] == right:
            return left.args[0]
        if expr.opcode == "sub" and left.opcode == "add" and left.args[1] == right:
            return left.args[0]
    if expr.opcode == "add" and {left.opcode, right.opcode} == {"and", "or"} and left.args == right.args:
        return Expression("add", expr.width, left.args)
    if expr.opcode == "add":
        for xor, product in ((left, right), (right, left)):
            if xor.opcode == "xor" and product.opcode == "mul":
                conjunction, factor = product.args
                if conjunction.opcode == "and" and conjunction.args == xor.args and factor == constant(2, expr.width):
                    return Expression("add", expr.width, xor.args)
    return expr


def reference_condition(predicate, flags):
    formula = (conditions.X86_CONDITIONS if predicate["family"] == "x86" else conditions.ARM_CONDITIONS)[predicate["code"]]
    code = re.sub(r"!(?!=)", "not ", formula).replace("&&", " and ").replace("||", " or ")
    tree = ast.parse(code.strip(), mode="eval")
    def visit(node):
        if isinstance(node, ast.Attribute):
            value = flags.get(node.attr)
            return None if value is None else bool(value)
        if isinstance(node, ast.UnaryOp):
            value = visit(node.operand)
            return None if value is None else not value
        if isinstance(node, ast.BoolOp):
            values = [visit(value) for value in node.values]
            if isinstance(node.op, ast.And):
                return False if False in values else None if None in values else True
            return True if True in values else None if None in values else False
        left, right = visit(node.left), visit(node.comparators[0])
        if left is None or right is None:
            return None
        return left == right if isinstance(node.ops[0], ast.Eq) else left != right
    return visit(tree.body)


def outcome(function, *args):
    try:
        return "ok", function(*args)
    except Exception as exc:  # noqa: BLE001 - 对照异常类型与消息
        return "raise", type(exc).__name__, str(exc)


REGISTER_TOKENS = ["rax", "eax", "ax", "al", "ah", "RBX", " ecx ", "dh", "sil", "spl", "rbp", "r8", "r9d", "r10w",
                   "r15b", "r16", "rip", "x0", "w30", "x31", "xzr", "wzr", "sp", "wsp", "fp", "lr", "r0", "r14",
                   "r15", "pc", "xmm0", "", "  ", "qword ptr [rax]"]
MEMORY_OPERANDS = ["qword ptr [rip + 0x10]", "dword ptr [rsp - 0x1c]", "[rax+rbx*4-0x8]", "dword ptr fs:[rax]",
                   "byte ptr [eip]", "[rax + foo]", "[foo + rax]", "[weird$]", "[]", "[sp, #16]", "[x0, x1, lsl #3]",
                   "[r1, #-4]", "[r13]", "[fp, #-8]", "QWORD PTR [RAX]", "[0x1000]", "word ptr [r8d]", "[rax-rax]"]
ARCHITECTURES = ("x86", "x86_64", "arm", "arm64", "mips")


class OperandCacheTests(unittest.TestCase):
    def test_register_lookup_matches_reference_on_every_architecture(self):
        for architecture in ARCHITECTURES:
            for token in REGISTER_TOKENS + MEMORY_OPERANDS:
                op = Operands(architecture, {"addr": 0, "size": 1}, set())
                with self.subTest(architecture=architecture, token=token):
                    for _ in range(2):  # 第二次命中缓存
                        self.assertEqual(op.register(token), reference_register(architecture, op.bits, token))

    def test_address_replays_side_effects_and_errors_in_source_order(self):
        rows = ({"addr": 0x1000, "size": 7}, {"addr": 0x1000}, {})
        for architecture in ARCHITECTURES:
            for operand in MEMORY_OPERANDS:
                for row in rows:
                    for _ in range(2):
                        actual_op = Operands(architecture, row, set())
                        expected_op = Operands(architecture, row, set())
                        with self.subTest(architecture=architecture, operand=operand, row=row):
                            self.assertEqual(outcome(actual_op.address, operand), outcome(reference_address, expected_op, operand))
                            self.assertEqual(actual_op.registers, expected_op.registers)
                            self.assertEqual(actual_op.reads, expected_op.reads)
        # 后出现的非法寄存器在已记录前面的读取之后才失败。
        op = Operands("x86_64", {"addr": 0, "size": 1}, set())
        with self.assertRaisesRegex(ValueError, "Unsupported address register"):
            op.address("[rax + foo]")
        self.assertEqual(op.registers, {"rax"})

    def test_non_string_operands_keep_original_exception_types(self):
        op = Operands("x86_64", {"addr": 0, "size": 1}, set())
        for bad in (None, 7):
            with self.subTest(bad=bad):
                self.assertRaises(AttributeError, op.register, bad)
                self.assertRaises(AttributeError, op.width, bad)
                self.assertRaises(TypeError, op.address, bad)

    def test_split_operands_returns_independent_lists(self):
        row = {"operands": ("dword ptr [rax, rbx]", "4")}
        first = split_operands(row)
        first.append("mutated")
        first[0] = "changed"
        self.assertEqual(split_operands(row), ["dword ptr [rax, rbx]", "4"])
        self.assertEqual(split_operands({"operands": "[x0, #8]!, x1"}), ["[x0, #8]!", "x1"])
        self.assertEqual(split_operands({}), [])
        self.assertRaises(TypeError, split_operands, {"operands": 5})

    def test_identifier_cache_keeps_fallback_and_truncation(self):
        self.assertEqual(native_operands.identifier("9lives"), "function_9lives")
        self.assertEqual(native_operands.identifier("9lives", "var"), "var_9lives")
        self.assertEqual(native_operands.identifier("a-b" * 40), ("a_b" * 40)[:64])
        self.assertRaises(TypeError, native_operands.identifier, "", 7)

    def test_all_memoized_helpers_are_bounded(self):
        cached = [native_operands._register_cached, native_operands._operand_width, native_operands._immediate_token,
                  native_operands._address_template, native_operands._split_text_cached, native_operands._identifier_cached,
                  common._register_value, common._immediate_value, conditions._parse_formula]
        for helper in cached:
            with self.subTest(helper=helper):
                self.assertIsNotNone(helper.cache_info().maxsize)


class ExpressionTests(unittest.TestCase):
    def random_expression(self, rng, depth=0, width=None):
        width = width or rng.choice([8, 16, 32, 64])
        if depth > 3 or rng.random() < 0.3:
            if rng.random() < 0.5:
                return constant(rng.choice([0, 1, 2, (1 << width) - 1, rng.getrandbits(width)]), width)
            return Expression("register", width, name=rng.choice(["rax", "rbx"]))
        opcode = rng.choice(["add", "sub", "xor", "and", "or", "mul", "shl", "lshr", "rol", "udiv", "load", "not", "zext", "fadd"])
        arity = 1 if opcode in {"not", "zext", "load"} else 2
        shared = self.random_expression(rng, depth + 1, width)
        args = tuple(shared if rng.random() < 0.3 else self.random_expression(rng, depth + 1, width) for _ in range(arity))
        return Expression(opcode, width, args, domain="floating" if opcode == "fadd" and rng.random() < 0.5 else "bitvector")

    def test_simplify_matches_reference_including_purity(self):
        rng = random.Random(20261001)
        x, y = Expression("register", 32, name="eax"), Expression("register", 32, name="ebx")
        samples = [Expression("add", 32, (Expression("and", 32, (x, y)), Expression("or", 32, (x, y)))),
                   Expression("add", 32, (Expression("xor", 32, (x, y)), Expression("mul", 32, (Expression("and", 32, (x, y)), constant(2, 32))))),
                   Expression("sub", 32, (Expression("add", 32, (x, y)), y)), Expression("xor", 32, (x, x))]
        samples += [self.random_expression(rng) for _ in range(1500)]
        for expression in samples:
            with self.subTest(expression=expression):
                expected = outcome(reference_simplify, expression)
                actual = outcome(optimize.simplify_expression, expression)
                self.assertEqual(actual, expected)
                if actual[0] == "ok":
                    self.assertEqual(actual[1].pure, expected[1].pure)
                    self.assertEqual(optimize.simplify_expression(expression.to_dict()), expected[1])

    def test_simplify_depth_limit_and_list_argument_normalization(self):
        chain = Expression("register", 8, name="al")
        for _ in range(66):
            chain = Expression("not", 8, (chain,))
        self.assertRaisesRegex(ValueError, "nesting exceeds limit", optimize.simplify_expression, chain)
        listed = Expression("rol", 8, [Expression("register", 8, name="al"), Expression("register", 8, name="bl")])
        result = optimize.simplify_expression(listed)
        self.assertIsInstance(result.args, tuple)
        self.assertEqual(result, reference_simplify(listed))

    def test_to_dict_always_returns_fresh_containers(self):
        renderer = _Renderer({"start": 0}, "x86_64", [])
        op = Operands("x86_64", {"addr": 0, "size": 1}, renderer.registers)
        shared = common.value(op, "eax")
        self.assertIs(shared, common.value(op, "eax"))  # 不可变表达式可共享
        first, second = shared.to_dict(), shared.to_dict()
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNot(first["args"], second["args"])
        first["args"][0]["name"] = "mutated"
        self.assertEqual(shared.to_dict(), second)
        operation = MicroOperation("assign", 32, (shared,), "rax", shared, {"outputs": ["rax"]})
        record = operation.to_dict()
        record["inputs"][0]["width"] = 1
        record["attributes"]["new"] = True
        self.assertEqual(operation.to_dict()["inputs"][0]["width"], 32)
        self.assertNotIn("new", operation.attributes)

    def test_evaluate_condition_reuses_parsed_formulas_without_changing_results(self):
        rng = random.Random(7)
        for family, table, names in (("x86", conditions.X86_CONDITIONS, ("ZF", "CF", "SF", "OF", "PF")),
                                     ("arm", conditions.ARM_CONDITIONS, ("N", "Z", "C", "V"))):
            for code in table:
                for _ in range(12):
                    flags = {name: rng.choice([True, False, None, 0, 1]) for name in names if rng.random() < 0.85}
                    predicate = {"family": family, "code": code}
                    with self.subTest(family=family, code=code, flags=flags):
                        self.assertEqual(conditions.evaluate_condition(predicate, flags=flags), reference_condition(predicate, flags))
        self.assertRaises(TypeError, conditions.evaluate_condition, {"family": "x86", "code": "e", "bogus": 1}, flags={})
        self.assertRaisesRegex(ValueError, "Unknown condition code", conditions.evaluate_condition, {"family": "x86", "code": "zz"}, flags={})

    def test_integer_operations_keep_fixed_width_results(self):
        for opcode, expected in (("add", 0x01), ("sub", 0x03), ("mul", 0xfe), ("and", 0xff & 0x02), ("or", 0xff), ("xor", 0xfd)):
            with self.subTest(opcode=opcode):
                self.assertEqual(evaluate.evaluate_expression(Expression(opcode, 8, (constant(0xff, 8), constant(2, 8)))),
                                 expected if opcode != "sub" else (0xff - 2) & 0xff)
        self.assertEqual(evaluate.evaluate_expression(Expression("fsub", 32, (Expression("float_constant", 32, value=1.5, domain="floating"),
                                                                          Expression("float_constant", 32, value=0.25, domain="floating")))), 1.25)


class LiftingTests(unittest.TestCase):
    ROWS = {
        "x86_64": [("mov", ("eax", "dword ptr [rsp - 0x1c]")), ("mov", ("dword ptr [rsp - 0x1c]", "eax")),
                   ("xor", ("eax", "edx")), ("add", ("eax", "edx")), ("imul", ("eax", "eax", "0x1234")),
                   ("movzx", ("eax", "al")), ("test", ("al", "1")), ("lea", ("rax", "[rip + 0x20]")),
                   ("cvtsi2sd", ("xmm0", "QWORD PTR [rax]")), ("addsd", ("xmm0", "xmm1")), ("shl", ("eax", "cl"))],
        "arm64": [("ldr", ("x0", "#0X1100")), ("ldr", ("x0", "[x1, x2, LSL #3]")), ("add", ("x0", "sp", "x1", "UXTW #2")),
                  ("movz", ("x0", "#0x10", "LSL #16")), ("svc", ("#0X80",)), ("fadd", ("s0", "s1", "s2")),
                  ("stp", ("x29", "x30", "[sp, #-16]!")), ("cmp", ("x0", "#0X10")), ("csel", ("x0", "x1", "x2", "ne"))],
        "arm": [("ldr", ("r0", "[r1, #4]")), ("ands", ("r0", "r1", "#3")), ("lsl", ("r0", "r1", "r2"))],
        "x86": [("mov", ("eax", "dword ptr [eip + 4]")), ("push", ("ebp",)), ("cmovne", ("eax", "ebx"))],
    }

    def rows(self, architecture):
        return [{"addr": 0x1000 + 4 * index, "size": 4, "mnemonic": mnemonic, "operands": operands, "branch_info": {}}
                for index, (mnemonic, operands) in enumerate(self.ROWS[architecture])]

    def test_hot_lifting_path_does_not_recompile_string_patterns(self):
        for architecture in self.ROWS:
            rows = self.rows(architecture)
            renderer = _Renderer({"start": 0x1000}, architecture, rows)
            for row in rows:  # 预热纯函数缓存
                renderer.statement(row)
            original = re._compile
            calls = []
            def counting(*args, **kwargs):
                calls.append(args[0])
                return original(*args, **kwargs)
            with patch.object(re, "_compile", counting):
                for row in rows:
                    op = Operands(architecture, row, renderer.registers)
                    renderer.current_operands = op
                    DEFAULT_LIFTERS.lift(renderer, row, split_operands(row), op)
            self.assertEqual(calls, [], architecture)

    def test_repeated_lifting_is_deterministic(self):
        for architecture in self.ROWS:
            function = {"start": 0x1000, "blocks": [{"instructions": self.rows(architecture)}], "cfg": {"complete": True, "frontier": []}}
            with self.subTest(architecture=architecture):
                first = lift_function(function, architecture)
                self.assertEqual(lift_function(function, architecture), first)
                for row in function["blocks"][0]["instructions"]:
                    self.assertEqual(lift_instruction(row, architecture), lift_instruction(row, architecture))

    def test_registry_snapshot_follows_registration_and_rejects_duplicates(self):
        registry = LifterRegistry()
        result = types.SimpleNamespace(flag_effect="preserve", category="data_transfer")
        context = types.SimpleNamespace(comparison_origin="kept", opaque=0)
        registry.register("late", lambda *args: None)
        self.assertEqual(registry.names(), ("late",))
        registry.register("early", lambda *args: result, first=True)
        self.assertEqual(registry.names(), ("early", "late"))
        self.assertIs(registry.lift(context, {"mnemonic": "x"}, [], None), result)
        self.assertEqual(context.comparison_origin, "kept")
        self.assertRaises(ValueError, registry.register, "early", lambda *args: result)
        self.assertEqual(registry.names(), ("early", "late"))

    def test_lifted_effects_match_operation_scan(self):
        context = types.SimpleNamespace(architecture="x86_64", current_operands=types.SimpleNamespace(reads={"rsp"}, writes=set()), flags=False)
        load = Expression("load", 32, (Expression("address", 64, name="rsp"),))
        operations = [MicroOperation("store", 32, (Expression("address", 64, name="rbx"), Expression("register", 32, name="eax"))),
                      MicroOperation("select", 32, (load, Expression("float_register", 64, name="xmm1", domain="floating")), "rcx",
                                     attributes={"outputs": ["rdx"], "preserved_inputs": ["xmm2"], "rounding": "fp_environment"})]
        lifted = common.lifted(context, {"addr": 1, "size": 2, "mnemonic": "x"}, "memory", ["s"], operations, flag_effect="write")
        self.assertEqual(lifted.reads, ("eax", "flags", "fp_environment", "rsp", "xmm1", "xmm2"))
        self.assertEqual(lifted.writes, ("flags", "rcx", "rdx"))
        self.assertEqual(lifted.memory_effect, "read_write")
        self.assertTrue(context.flags)


if __name__ == "__main__":
    unittest.main()
