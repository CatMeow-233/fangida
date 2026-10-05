"""microcode 指令语义缺口：A64 高位/宽乘法、AArch32 条件执行、SIMD/FP 搬移与 opaque 回退读写集。

每类指令都检查 lift_instruction 的读写集，再把生成的可读伪 C 用 cc -O2 编译运行，在边界值
网格上与参考 C 表达式逐一比对（写法同 test_bitfield_lifting.py）。
"""
from __future__ import annotations

import importlib.util
import re
import unittest

from fangida.plugins.pseudoc import generate_pseudoc
from fangida.plugins.pseudoc.microcode import analyze_microcode, evaluate_expression, lift_function, lift_instruction
from fangida.plugins.pseudoc.microcode.conditional import split_condition
from tests.test_pseudoc import function as fn, instruction as ins
from tests.test_reconstruction import compile_run

_VALUES32 = "0u, 1u, 2u, 0x7fu, 0x80u, 0xffu, 0x1234u, 0x7fffffffu, 0x80000000u, 0x80000001u, 0xdeadbeefu, 0xfffffffeu, 0xffffffffu"
_VALUES64 = ("0ull, 1ull, 2ull, 0x7full, 0xffffffffull, 0x100000000ull, 0x123456789abcdef0ull, 0x7fffffffffffffffull, "
             "0x8000000000000000ull, 0x8000000000000001ull, 0xdeadbeefcafef00dull, 0xfffffffffffffffeull, 0xffffffffffffffffull")
_HAS_CAPSTONE = importlib.util.find_spec("capstone") is not None


def _rows(architecture, texts):
    """把 "助记符 操作数, ..." 文本变成快照行；ret / bx lr 标为返回。"""
    size = 1 if architecture.startswith("x86") else 4
    rows = []
    for index, text in enumerate(texts):
        mnemonic, _, rest = text.partition(" ")
        operands = [item.strip() for item in _split(rest)] if rest else []
        kind = "return" if mnemonic == "ret" or (architecture == "arm" and text == "bx lr") else None
        rows.append(ins(index * size, mnemonic, *operands, size=size, kind=kind))
    return rows


def _split(text):
    parts, depth, current = [], 0, ""
    for character in text:
        depth += character == "["
        depth -= character == "]"
        if character == "," and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += character
    return parts + [current]


def _build(architecture, name, texts):
    return generate_pseudoc(fn(*_rows(architecture, texts), name=name, pseudoc_context={"kind": "elf"}),
                            architecture, style="readable")


def _call(text, name, values):
    """按函数签名里的参数名 arg_N（ABI 第 N 个参数）传入 values[N-1]，不依赖参数书写顺序。"""
    match = re.search(rf"\b{name}\(([^)]*)\)", text)
    parameters = match.group(1).strip() if match else ""
    if parameters in {"", "void"}:
        return f"{name}()"
    arguments = []
    for parameter in parameters.split(","):
        index = int(re.search(r"arg_(\d+)\s*$", parameter).group(1)) - 1
        arguments.append(values[index])
    return f"{name}({', '.join(arguments)})"


def _grid(values, kind, checks):
    return (f"static const {kind} values[] = {{{values}}};\n"
            "const unsigned n = sizeof values / sizeof *values;\n"
            "for (unsigned i = 0; i < n; ++i)\n"
            "for (unsigned j = 0; j < n; ++j) {\n"
            f"{kind} a = values[i], b = values[j], c = values[(i * 7 + j * 3) % n]; (void)a; (void)b; (void)c;\n"
            + "\n".join(checks) + "\n}\nreturn 0;")


class _Compiled(unittest.TestCase):
    def check_cases(self, architecture, cases, values, kind):
        """cases: (函数名, 指令文本列表, 比较类型, 参考表达式)；a、b、c 依次是 ABI 第 1、2、3 个参数。"""
        sources, checks = [], []
        for name, texts, compare, reference in cases:
            with self.subTest(name=name):
                output = _build(architecture, name, texts)
                self.assertNotIn("unresolved_operation", output.pseudoc, output.pseudoc)
                sources.append(output.pseudoc)
                call = _call(output.pseudoc, name, ("a", "b", "c"))
                checks.append(f"if (({compare}){call} != ({compare})({reference})) return {len(checks) + 1};")
        compile_run("\n".join(sources), _grid(values, kind, checks))


class Arm64MultiplyTests(_Compiled):
    def test_high_and_widening_multiplies_lift_with_exact_register_sets(self):
        fixtures = [
            ("umulh", ("x0", "x1", "x2"), ["x1", "x2"], ["x0"]),
            ("smulh", ("x3", "x4", "x5"), ["x4", "x5"], ["x3"]),
            ("umaddl", ("x0", "w1", "w2", "x3"), ["x1", "x2", "x3"], ["x0"]),
            ("smaddl", ("x0", "w1", "w2", "x3"), ["x1", "x2", "x3"], ["x0"]),
            ("umsubl", ("x0", "w1", "w2", "x3"), ["x1", "x2", "x3"], ["x0"]),
            ("smsubl", ("x0", "w1", "w2", "x3"), ["x1", "x2", "x3"], ["x0"]),
            ("umnegl", ("x0", "w1", "w2"), ["x1", "x2"], ["x0"]),
            ("smnegl", ("x0", "w1", "w2"), ["x1", "x2"], ["x0"]),
            ("mneg", ("x0", "x1", "x2"), ["x1", "x2"], ["x0"]),
            ("mneg", ("w0", "w1", "w2"), ["x1", "x2"], ["x0"]),
            ("negs", ("x0", "x1"), ["x1"], ["flags", "x0"]),
            ("neg", ("w0", "w1", "lsl #3"), ["x1"], ["x0"]),
        ]
        for mnemonic, operands, reads, writes in fixtures:
            with self.subTest(mnemonic=mnemonic, operands=operands):
                result = lift_instruction(ins(0, mnemonic, *operands, size=4), "arm64")
                self.assertTrue(result["supported"])
                self.assertEqual(result["category"], "integer_arithmetic")
                self.assertEqual(result["reads"], reads)
                self.assertEqual(result["writes"], writes)
        # 带符号高位乘积的中间结果是 128 位位向量。
        high = lift_instruction(ins(0, "smulh", "x0", "x1", "x2", size=4), "arm64")["operations"][0]["expression"]
        self.assertEqual((high["opcode"], high["value"], high["args"][0]["width"]), ("extract", 64, 128))

    def test_microcode_evaluation_matches_python_reference(self):
        mask = (1 << 64) - 1

        def signed(value, bits):
            value &= (1 << bits) - 1
            return value - (1 << bits) if value >> (bits - 1) else value

        samples = [0, 1, 2, 0x7f, 0xffffffff, 0x100000000, 0x7fffffffffffffff, 0x8000000000000000,
                   0x8000000000000001, 0xdeadbeefcafef00d, mask - 1, mask]
        references = {
            "umulh": lambda a, b, c: (a * b) >> 64,
            "smulh": lambda a, b, c: ((signed(a, 64) * signed(b, 64)) >> 64) & mask,
            "umaddl": lambda a, b, c: (c + (a & 0xffffffff) * (b & 0xffffffff)) & mask,
            "smaddl": lambda a, b, c: (c + signed(a, 32) * signed(b, 32)) & mask,
            "umsubl": lambda a, b, c: (c - (a & 0xffffffff) * (b & 0xffffffff)) & mask,
            "smsubl": lambda a, b, c: (c - signed(a, 32) * signed(b, 32)) & mask,
            "umnegl": lambda a, b, c: -((a & 0xffffffff) * (b & 0xffffffff)) & mask,
            "smnegl": lambda a, b, c: -(signed(a, 32) * signed(b, 32)) & mask,
        }
        for mnemonic, reference in references.items():
            wide = mnemonic in {"umulh", "smulh"}
            operands = ("x0", "x1", "x2") if wide else ("x0", "w1", "w2") + (() if mnemonic.endswith("negl") else ("x3",))
            expression = lift_instruction(ins(0, mnemonic, *operands, size=4), "arm64")["operations"][0]["expression"]
            for a in samples:
                for b in samples[::3]:
                    c = samples[(a + b) % len(samples)]
                    with self.subTest(mnemonic=mnemonic, a=a, b=b):
                        self.assertEqual(evaluate_expression(expression, {"x1": a, "x2": b, "x3": c}), reference(a, b, c))

    def test_multiplies_compile_and_match_reference(self):
        cases = [
            ("high_unsigned", ["umulh x0, x0, x1", "ret"], "uint64_t", "(uint64_t)(((__uint128_t)a * b) >> 64)"),
            ("high_signed", ["smulh x0, x0, x1", "ret"], "uint64_t",
             "(uint64_t)((__uint128_t)((__int128_t)(int64_t)a * (int64_t)b) >> 64)"),
            ("wide_umaddl", ["umaddl x0, w0, w1, x2", "ret"], "uint64_t", "c + (uint64_t)(uint32_t)a * (uint32_t)b"),
            ("wide_smaddl", ["smaddl x0, w0, w1, x2", "ret"], "uint64_t",
             "c + (uint64_t)((int64_t)(int32_t)a * (int64_t)(int32_t)b)"),
            ("wide_umsubl", ["umsubl x0, w0, w1, x2", "ret"], "uint64_t", "c - (uint64_t)(uint32_t)a * (uint32_t)b"),
            ("wide_smsubl", ["smsubl x0, w0, w1, x2", "ret"], "uint64_t",
             "c - (uint64_t)((int64_t)(int32_t)a * (int64_t)(int32_t)b)"),
            ("wide_umnegl", ["umnegl x0, w0, w1", "ret"], "uint64_t", "0 - (uint64_t)(uint32_t)a * (uint32_t)b"),
            ("wide_smnegl", ["smnegl x0, w0, w1", "ret"], "uint64_t",
             "0 - (uint64_t)((int64_t)(int32_t)a * (int64_t)(int32_t)b)"),
            ("wide_umull", ["umull x0, w0, w1", "ret"], "uint64_t", "(uint64_t)(uint32_t)a * (uint32_t)b"),
            ("wide_smull", ["smull x0, w0, w1", "ret"], "uint64_t", "(uint64_t)((int64_t)(int32_t)a * (int64_t)(int32_t)b)"),
            ("negated_product64", ["mneg x0, x0, x1", "ret"], "uint64_t", "0 - a * b"),
            ("negated_product32", ["mneg w0, w0, w1", "ret"], "uint32_t", "0u - (uint32_t)a * (uint32_t)b"),
            ("negated_shift", ["neg x0, x0, lsl #3", "ret"], "uint64_t", "0 - (a << 3)"),
            ("negated_value", ["negs x0, x0", "ret"], "uint64_t", "0 - a"),
            ("negs_sign", ["negs x8, x0", "cset w0, lt", "ret"], "uint32_t", "(int64_t)a > 0"),
            ("conditional_inc", ["cmp x0, x1", "cinc x0, x2, hi", "ret"], "uint64_t", "a > b ? c + 1 : c"),
            ("conditional_neg", ["cmp w0, w1", "cneg w0, w2, lt", "ret"], "uint32_t",
             "(int32_t)a < (int32_t)b ? 0u - (uint32_t)c : (uint32_t)c"),
            ("conditional_inv", ["cmp x0, x1", "cinv x0, x2, eq", "ret"], "uint64_t", "a == b ? ~c : c"),
        ]
        self.check_cases("arm64", cases, _VALUES64, "uint64_t")

    def test_overlapping_aarch32_long_multiply_stays_opaque(self):
        self.assertFalse(lift_instruction(ins(0, "umull", "r0", "r1", "r0", "r1", size=4), "arm")["supported"])
        self.assertFalse(lift_instruction(ins(0, "umull", "r0", "r0", "r2", "r3", size=4), "arm")["supported"])
        ordered = lift_instruction(ins(0, "umull", "r0", "r2", "r0", "r1", size=4), "arm")
        self.assertTrue(ordered["supported"])
        # RdLo 同时是源：先写高半 r2，再写低半 r0。
        self.assertEqual([operation["output"] for operation in ordered["operations"]], ["r2", "r0"])


class Arm32ConditionalTests(_Compiled):
    def test_condition_suffix_split_distinguishes_ambiguous_mnemonics(self):
        for mnemonic, expected in (("addeq", ("add", "eq")), ("moveq", ("mov", "eq")), ("subne", ("sub", "ne")),
                                   ("lslls", ("lsl", "ls")), ("movvs", ("mov", "vs")), ("mulls", ("mul", "ls")),
                                   ("movweq", ("movw", "eq")), ("uxtbne", ("uxtb", "ne")), ("bicle", ("bic", "le"))):
            self.assertEqual(split_condition(mnemonic), expected, mnemonic)
        # 以条件码字母结尾、但不是条件执行的指令。
        for mnemonic in ("teq", "mls", "umulls", "smulls", "lsls", "movs", "muls", "bls", "bhs", "blt", "bics",
                         "adcs", "sbcs", "vmls", "add", "mov", "ldrne", "strne", "addseq", "cmpeq", ""):
            self.assertIsNone(split_condition(mnemonic), mnemonic)

    def test_conditional_assignments_become_selects(self):
        result = lift_instruction(ins(0, "addeq", "r0", "r1", "r2", size=4), "arm")
        self.assertTrue(result["supported"])
        self.assertEqual(result["category"], "conditional")
        self.assertEqual(result["reads"], ["flags", "r0", "r1", "r2"])
        self.assertEqual(result["writes"], ["r0"])
        self.assertEqual(result["flag_effect"], "preserve")
        operation = result["operations"][0]
        self.assertEqual(operation["opcode"], "select")
        self.assertEqual(operation["attributes"]["condition"]["code"], "eq")
        self.assertEqual(operation["attributes"]["false_operation"], "identity")
        self.assertEqual(operation["inputs"][1], {"opcode": "register", "width": 32, "name": "r0", "domain": "bitvector"})
        for mnemonic, operands in (("movne", ("r0", "#0")), ("lslhs", ("r0", "r1", "#2")), ("movtlt", ("r0", "#0x5678")),
                                   ("mulls", ("r0", "r1", "r2")), ("umullhi", ("r2", "r3", "r0", "r1"))):
            with self.subTest(mnemonic=mnemonic):
                row = lift_instruction(ins(0, mnemonic, *operands, size=4), "arm")
                self.assertTrue(row["supported"])
                self.assertTrue(all(op["opcode"] == "select" for op in row["operations"]))
                self.assertIn("flags", row["reads"])

    def test_conditional_memory_flag_setting_and_pc_writes_stay_opaque(self):
        for mnemonic, operands in (("ldrne", ("r0", "[r1]")), ("strne", ("r0", "[r1]")),
                                   ("addseq", ("r0", "r1", "r2")), ("cmpeq", ("r0", "r1")),
                                   ("adceq", ("r0", "r1", "r2")), ("teq", ("r0", "r1")),
                                   ("umulls", ("r0", "r1", "r2", "r3")), ("lsls", ("r0", "r1", "#2"))):
            with self.subTest(mnemonic=mnemonic):
                row = lift_instruction(ins(0, mnemonic, *operands, size=4), "arm")
                self.assertFalse(row["supported"])
                self.assertEqual(row["category"], "opaque")
                self.assertNotIn("condition", row["operations"][0]["attributes"])
        # mls 是乘减指令本身，不是 m + ls。
        self.assertEqual(lift_instruction(ins(0, "mls", "r0", "r1", "r2", "r3", size=4), "arm")["category"], "integer_arithmetic")

    def test_condition_coded_branches_keep_their_predicates(self):
        for mnemonic, code in (("bls", "ls"), ("bhs", "hs"), ("blt", "lt"), ("bxeq", "eq")):
            operands = ("lr",) if mnemonic == "bxeq" else ("#0x20",)
            target = None if mnemonic == "bxeq" else 0x20
            with self.subTest(mnemonic=mnemonic):
                row = lift_instruction(ins(0, mnemonic, *operands, size=4, kind="jump", target=target, conditional=True), "arm")
                self.assertTrue(row["supported"])
                self.assertEqual(row["category"], "control_flow")
                self.assertEqual(row["operations"][0]["attributes"]["condition"]["code"], code)

    def test_conditional_execution_compiles_and_matches_reference(self):
        cases = [
            ("unsigned_min", ["cmp r0, r1", "movhi r0, r1", "bx lr"], "uint32_t", "a > b ? b : a"),
            ("signed_max", ["cmp r0, r1", "movlt r0, r1", "bx lr"], "uint32_t", "(int32_t)a < (int32_t)b ? b : a"),
            ("add_or_sub", ["cmp r0, r1", "addeq r0, r0, r2", "subne r0, r0, r2", "bx lr"], "uint32_t", "a == b ? a + c : a - c"),
            ("not_if_negative", ["cmp r0, #0", "mvnlt r0, r0", "bx lr"], "uint32_t", "(int32_t)a < 0 ? ~a : a"),
            ("low_bit", ["tst r0, #1", "moveq r0, #0", "movne r0, #1", "bx lr"], "uint32_t", "a & 1u"),
            ("wide_constant", ["cmp r0, r1", "movwlo r0, #0x1234", "movtlo r0, #0x5678", "bx lr"], "uint32_t",
             "a < b ? 0x56781234u : a"),
            ("shift_or_product", ["cmp r0, r1", "lslls r2, r0, #3", "mulhi r2, r0, r1", "mov r0, r2", "bx lr"], "uint32_t",
             "a <= b ? a << 3 : a * b"),
            ("byte_or_keep", ["cmp r1, #0x80", "uxtbhs r0, r0", "bx lr"], "uint32_t", "b >= 0x80u ? (a & 0xffu) : a"),
            ("mixed_logic", ["cmp r0, r1", "orrgt r0, r0, r2", "bicle r0, r0, r2", "bx lr"], "uint32_t",
             "(int32_t)a > (int32_t)b ? (a | c) : (a & ~c)"),
            ("long_high", ["umull r2, r0, r0, r1", "bx lr"], "uint32_t", "(uint32_t)(((uint64_t)a * b) >> 32)"),
            ("long_low_first", ["umull r0, r2, r0, r1", "bx lr"], "uint32_t", "a * b"),
            ("signed_long_high", ["smull r2, r0, r0, r1", "bx lr"], "uint32_t",
             "(uint32_t)((uint64_t)((int64_t)(int32_t)a * (int32_t)b) >> 32)"),
            ("multiply_add", ["mla r0, r0, r1, r2", "bx lr"], "uint32_t", "a * b + c"),
            ("multiply_sub", ["mls r0, r0, r1, r2", "bx lr"], "uint32_t", "c - a * b"),
        ]
        self.check_cases("arm", cases, _VALUES32, "uint32_t")

    @unittest.skipUnless(_HAS_CAPSTONE, "需要 Capstone 解码真实编码")
    def test_real_encodings_decode_and_lift(self):
        from fangida.processors.decoder import NativeDecoder
        decoder = NativeDecoder("arm")
        expected = [  # (编码, 助记符, 是否条件执行改写, 是否支持)
            ("02008100", "addeq", True, True), ("0100a003", "moveq", True, True), ("01304312", "subne", True, True),
            ("00009115", "ldrne", False, False), ("00008115", "strne", False, False), ("02009100", "addseq", False, False),
            ("010030e1", "teq", False, False), ("920391e0", "umulls", False, False), ("913260e0", "mls", False, True),
            ("91020090", "mulls", True, True), ("0101b0e1", "lsls", False, False), ("0101a091", "lslls", True, True),
            ("0100b0e1", "movs", False, False), ("0100a061", "movvs", True, True), ("34020103", "movweq", True, True),
            ("7100ef16", "uxtbne", True, True),
        ]
        for encoding, mnemonic, conditional, supported in expected:
            rows, warnings = decoder.decode_bytes(bytes.fromhex(encoding), 0x1000)
            with self.subTest(mnemonic=mnemonic):
                self.assertFalse(warnings)
                self.assertEqual(rows[0]["mnemonic"], mnemonic)
                result = lift_instruction(rows[0], "arm")
                self.assertEqual(result["supported"], supported)
                self.assertEqual(result["category"] == "conditional", conditional)
                snapshot_reads = {{"cpsr": "flags"}.get(register, register) for register in rows[0]["reads"]}
                snapshot_writes = {{"cpsr": "flags"}.get(register, register) for register in rows[0]["writes"] if register != "pc"}
                if mnemonic in {"ldrne", "strne", "addseq"}:
                    # 条件执行的 opaque 指令：写入可能不发生，不能当作必定定义（ABI 推断会把它当定义，
                    # 丢掉条件不成立时保留的入参）；改记为读（旧值可能保留），并读取 flags 求值条件。
                    self.assertEqual(result["writes"], ["flags"])
                    self.assertLessEqual(snapshot_writes | snapshot_reads | {"flags"}, set(result["reads"]))
                    self.assertEqual(set(result["operations"][0]["attributes"]["snapshot_writes"]), snapshot_writes)
                else:
                    # 无条件执行：不被同一指令读取的快照写寄存器必定写入，出现在写集合里。
                    self.assertLessEqual(snapshot_writes - snapshot_reads, set(result["writes"]))
        for encoding, mnemonic, code in (("4000009a", "bls", "ls"), ("4000002a", "bhs", "hs"), ("1eff2f01", "bxeq", "eq")):
            rows, _ = decoder.decode_bytes(bytes.fromhex(encoding), 0x1000)
            with self.subTest(mnemonic=mnemonic):
                self.assertEqual(rows[0]["mnemonic"], mnemonic)
                result = lift_instruction(rows[0], "arm")
                self.assertTrue(result["supported"])
                self.assertEqual(result["operations"][0]["attributes"]["condition"]["code"], code)

    def test_select_facts_follow_the_condition(self):
        report = analyze_microcode(lift_function(fn(*_rows("arm", ["mov r0, #5", "mov r1, #7", "cmp r0, r1",
                                                                   "movlo r0, #1", "movhs r1, #2", "bx lr"])), "arm")["instructions"])
        self.assertEqual(report["remaining_register_bits"]["r0"]["value"], 1)
        self.assertEqual(report["remaining_register_bits"]["r1"]["value"], 7)


class VectorMoveTests(_Compiled):
    def test_x86_vector_moves_have_exact_register_sets(self):
        fixtures = [
            ("movaps", ("xmm0", "xmm1"), ["xmm1"], ["xmm0"], "data_transfer"),
            ("movdqu", ("xmm1", "xmmword ptr [rsi + rax*8]"), ["rax", "rsi"], ["xmm1"], "memory"),
            ("movups", ("xmmword ptr [rdi]", "xmm0"), ["rdi", "xmm0"], [], "memory"),
            ("movdqa", ("xmmword ptr [rsp + 0x10]", "xmm2"), ["rsp", "xmm2"], [], "memory"),
            ("movq", ("xmm0", "rax"), ["rax"], ["xmm0"], "data_transfer"),
            ("movq", ("rax", "xmm0"), ["xmm0"], ["rax"], "data_transfer"),
            ("movq", ("xmm1", "xmm2"), ["xmm2"], ["xmm1"], "data_transfer"),
            ("movd", ("eax", "xmm3"), ["xmm3"], ["rax"], "data_transfer"),
            ("movq", ("qword ptr [rdi]", "xmm1"), ["rdi", "xmm1"], [], "memory"),
            ("pxor", ("xmm0", "xmm0"), [], ["xmm0"], "bitwise"),
            ("xorps", ("xmm5", "xmm5"), [], ["xmm5"], "bitwise"),
            ("vpxor", ("xmm4", "xmm4", "xmm4"), [], ["xmm4"], "bitwise"),
            ("pand", ("xmm0", "xmmword ptr [rdi]"), ["rdi", "xmm0"], ["xmm0"], "bitwise"),
            ("punpcklqdq", ("xmm0", "xmm1"), ["xmm0", "xmm1"], ["xmm0"], "data_transfer"),
            ("movss", ("xmm0", "xmm1"), ["xmm0", "xmm1"], ["xmm0"], "data_transfer"),
            ("movsd", ("xmm0", "qword ptr [rdi]"), ["rdi"], ["xmm0"], "memory"),
        ]
        for mnemonic, operands, reads, writes, category in fixtures:
            with self.subTest(mnemonic=mnemonic, operands=operands):
                result = lift_instruction(ins(0, mnemonic, *operands), "x86_64")
                self.assertTrue(result["supported"])
                self.assertEqual(result["category"], category)
                self.assertEqual(result["reads"], reads)
                self.assertEqual(result["writes"], writes)
                self.assertEqual(result["flag_effect"], "preserve")
        zero = lift_instruction(ins(0, "pxor", "xmm0", "xmm0"), "x86_64")["operations"][0]
        self.assertEqual((zero["width"], zero["expression"]["opcode"], zero["expression"]["value"]), (128, "constant", 0))
        aligned = lift_instruction(ins(0, "movaps", "xmm0", "xmmword ptr [rdi]"), "x86_64")["operations"][0]
        self.assertEqual((aligned["width"], aligned["attributes"]["alignment"]), (128, 16))
        self.assertEqual(lift_instruction(ins(0, "movups", "xmm0", "xmmword ptr [rdi]"), "x86_64")["operations"][0]["attributes"]["alignment"], 1)
        # MMX、256 位形式与 cmps/scas 串比较不在这里建模。
        for mnemonic, operands in (("movq", ("mm0", "mm1")), ("repe cmpsb", ("byte ptr [rsi]", "byte ptr [rdi]")),
                                   ("vmovdqu", ("ymm0", "ymmword ptr [rdi]")), ("movaps", ("xmm0", "qword ptr [rdi]"))):
            with self.subTest(mnemonic=mnemonic, operands=operands):
                self.assertFalse(lift_instruction(ins(0, mnemonic, *operands), "x86_64")["supported"])
        # 字符串 movsd 不是 SSE 标量搬移：由 x86_strings 按串复制建模（读 rsi/rdi、写 rsi/rdi，不碰 xmm）。
        string = lift_instruction(ins(0, "movsd", "dword ptr [rdi]", "dword ptr [rsi]"), "x86_64")
        self.assertEqual((string["category"], string["reads"], string["writes"]), ("memory", ["rdi", "rsi"], ["rdi", "rsi"]))
        self.assertEqual([operation["opcode"] for operation in string["operations"]], ["store", "assign", "assign"])

    def test_lane_insert_and_broadcast_evaluate_exactly_at_every_boundary(self):
        old, source = 0x0123456789abcdeffedcba9876543210, 0xa5a5a5a5c3c3c3c3
        mask128 = (1 << 128) - 1
        for lane, width in (("b", 8), ("h", 16), ("s", 32), ("d", 64)):
            for index in (0, 1, 128 // width // 2, 128 // width - 1):
                register = "x1" if width == 64 else "w1"
                operation = lift_instruction(ins(0, "mov", f"v0.{lane}[{index}]", register, size=4), "arm64")["operations"][0]
                shift, lane_mask = index * width, (1 << width) - 1
                expected = (old & ~(lane_mask << shift) & mask128) | ((source & lane_mask) << shift)
                with self.subTest(lane=lane, index=index):
                    self.assertEqual(evaluate_expression(operation["expression"], {"v0": old, "x1": source}), expected)
            arrangement = {"b": "16b", "h": "8h", "s": "4s", "d": "2d"}[lane]
            broadcast = lift_instruction(ins(0, "dup", f"v2.{arrangement}", "x1" if width == 64 else "w1", size=4), "arm64")
            lane_value = source & ((1 << width) - 1)
            expected = sum(lane_value << (offset * width) for offset in range(128 // width))
            self.assertEqual(evaluate_expression(broadcast["operations"][0]["expression"], {"x1": source}), expected)

    def test_arm64_vector_moves_have_exact_register_sets(self):
        fixtures = [
            ("mov", ("v0.16b", "v1.16b"), ["v1"], ["v0"], "data_transfer"),
            ("orr", ("v0.16b", "v1.16b", "v2.16b"), ["v1", "v2"], ["v0"], "bitwise"),
            ("eor", ("v3.16b", "v3.16b", "v3.16b"), [], ["v3"], "bitwise"),
            ("fmov", ("d0", "d1"), ["v1"], ["v0"], "data_transfer"),
            ("fmov", ("x0", "d1"), ["v1"], ["x0"], "data_transfer"),
            ("fmov", ("s0", "w1"), ["x1"], ["v0"], "data_transfer"),
            ("fmov", ("d2", "#20.00000000"), [], ["v2"], "data_transfer"),
            ("fmov", ("v0.d[1]", "x1"), ["v0", "x1"], ["v0"], "data_transfer"),
            ("fmov", ("x0", "v1.d[1]"), ["v1"], ["x0"], "data_transfer"),
            ("mov", ("v6.b[1]", "w25"), ["v6", "x25"], ["v6"], "data_transfer"),
            ("umov", ("w15", "v6.b[0]"), ["v6"], ["x15"], "data_transfer"),
            ("dup", ("v1.2d", "x0"), ["x0"], ["v1"], "data_transfer"),
            ("movi", ("v0.2d", "#0xffffffffffffffff"), [], ["v0"], "data_transfer"),
            ("movi", ("d2", "#0x00ff0000ff0000"), [], ["v2"], "data_transfer"),
        ]
        for mnemonic, operands, reads, writes, category in fixtures:
            with self.subTest(mnemonic=mnemonic, operands=operands):
                result = lift_instruction(ins(0, mnemonic, *operands, size=4), "arm64")
                self.assertTrue(result["supported"])
                self.assertEqual(result["category"], category)
                self.assertEqual(result["reads"], reads)
                self.assertEqual(result["writes"], writes)
        for mnemonic, operands in (("fmov", ("d0", "#0.10000000")), ("movi", ("v0.2d", "#0x1234")),
                                   ("movi", ("v0.4s", "#0xff", "msl #8")), ("fmla", ("v0.2d", "v1.2d", "v2.2d")),
                                   ("and", ("v0.4s", "v1.4s", "v2.4s")), ("umov", ("w0", "v1.b[16]"))):
            with self.subTest(mnemonic=mnemonic, operands=operands):
                self.assertFalse(lift_instruction(ins(0, mnemonic, *operands, size=4), "arm64")["supported"])

    def test_arm64_vector_moves_compile_and_match_reference(self):
        cases = [
            ("fmov_roundtrip", ["fmov d0, x0", "fmov x0, d0", "ret"], "uint64_t", "a"),
            ("fmov_single", ["fmov s0, w0", "fmov w0, s0", "ret"], "uint32_t", "(uint32_t)a"),
            ("upper_lane", ["fmov d0, x0", "mov v0.d[1], x1", "mov v1.16b, v0.16b", "mov x0, v1.d[1]", "ret"], "uint64_t", "b"),
            ("upper_fmov", ["fmov d0, x0", "fmov v0.d[1], x1", "fmov x0, v0.d[1]", "ret"], "uint64_t", "b"),
            ("scalar_clears_upper", ["fmov d0, x0", "mov v0.d[1], x1", "fmov d1, d0", "mov x0, v1.d[1]", "ret"], "uint64_t", "0"),
            ("half_clears_upper", ["fmov d0, x0", "mov v0.d[1], x1", "mov v1.8b, v0.8b", "mov x0, v1.d[1]", "ret"], "uint64_t", "0"),
            ("byte_insert", ["fmov d0, x0", "mov v0.b[3], w1", "fmov x0, d0", "ret"], "uint64_t",
             "(a & ~0xff000000ull) | ((uint64_t)(uint8_t)b << 24)"),
            ("lane_copy", ["fmov d0, x0", "fmov d1, x1", "mov v0.s[1], v1.s[0]", "fmov x0, d0", "ret"], "uint64_t",
             "(a & 0xffffffffull) | (b << 32)"),
            ("byte_extract", ["fmov d0, x0", "umov w0, v0.b[2]", "ret"], "uint32_t", "(uint32_t)((a >> 16) & 0xff)"),
            ("half_signed", ["fmov d0, x0", "smov x0, v0.h[1]", "ret"], "uint64_t", "(uint64_t)(int64_t)(int16_t)(a >> 16)"),
            ("broadcast_word", ["dup v0.4s, w0", "mov x0, v0.d[1]", "ret"], "uint64_t", "(uint64_t)(uint32_t)a * 0x100000001ull"),
            ("broadcast_half", ["dup v0.4h, w0", "fmov x0, d0", "ret"], "uint64_t", "(uint64_t)(uint16_t)a * 0x0001000100010001ull"),
            ("broadcast_constant", ["mov x8, #-1", "dup v0.2d, x8", "mov x0, v0.d[1]", "ret"], "uint64_t", "~0ull"),
            ("broadcast_lane", ["fmov d1, x0", "dup v0.8b, v1.b[1]", "fmov x0, d0", "ret"], "uint64_t",
             "(uint64_t)(uint8_t)(a >> 8) * 0x0101010101010101ull"),
            ("ones_upper", ["movi v0.2d, #0xffffffffffffffff", "mov x0, v0.d[1]", "ret"], "uint64_t", "~0ull"),
            ("shifted_words", ["movi v0.4s, #0x64, lsl #8", "mov x0, v0.d[1]", "ret"], "uint64_t", "0x0000640000006400ull"),
            ("byte_mask", ["movi d0, #0x00ff0000ff0000", "fmov x0, d0", "ret"], "uint64_t", "0x00ff0000ff0000ull"),
            ("float_one", ["fmov d0, #1.00000000", "fmov x0, d0", "ret"], "uint64_t", "0x3ff0000000000000ull"),
            ("float_eighth", ["fmov s0, #-0.12500000", "fmov w0, s0", "ret"], "uint32_t", "0xbe000000u"),
            ("float_vector", ["fmov v0.2d, #1.00000000", "mov x0, v0.d[1]", "ret"], "uint64_t", "0x3ff0000000000000ull"),
            ("float_vector_single", ["fmov v0.4s, #-0.12500000", "mov x0, v0.d[1]", "ret"], "uint64_t", "0xbe000000be000000ull"),
            ("float_vector_half", ["fmov v0.2s, #2.00000000", "mov x0, v0.d[1]", "ret"], "uint64_t", "0"),
            ("vector_bic", ["fmov d0, x0", "fmov d1, x1", "bic v2.8b, v0.8b, v1.8b", "fmov x0, d2", "ret"], "uint64_t", "a & ~b"),
            ("vector_not", ["fmov d0, x0", "not v1.8b, v0.8b", "fmov x0, d1", "ret"], "uint64_t", "~a"),
            ("vector_logic", ["fmov d0, x0", "mov v0.d[1], x1", "dup v1.2d, x2", "eor v2.16b, v0.16b, v1.16b",
                              "orn v3.16b, v2.16b, v0.16b", "and v3.16b, v3.16b, v1.16b", "mov x0, v3.d[1]", "ret"], "uint64_t",
             "((b ^ c) | ~b) & c"),
            ("vector_zero", ["fmov d0, x0", "eor v0.16b, v0.16b, v0.16b", "fmov x0, d0", "ret"], "uint64_t", "0"),
        ]
        self.check_cases("arm64", cases, _VALUES64, "uint64_t")

    def test_x86_vector_moves_compile_and_match_reference(self):
        cases = [
            ("movq_roundtrip", ["movq xmm0, rdi", "movq rax, xmm0", "ret"], "uint64_t", "a"),
            ("movd_roundtrip", ["movd xmm0, edi", "movq rax, xmm0", "ret"], "uint64_t", "(uint32_t)a"),
            ("pair_high", ["movq xmm0, rdi", "movq xmm1, rsi", "punpcklqdq xmm0, xmm1", "pxor xmm2, xmm2",
                           "movhlps xmm2, xmm0", "movq rax, xmm2", "ret"], "uint64_t", "b"),
            ("pair_unpack_high", ["movq xmm0, rdi", "movq xmm1, rsi", "punpcklqdq xmm0, xmm1", "movdqa xmm1, xmm0",
                                  "punpckhqdq xmm1, xmm0", "movaps xmm3, xmm1", "movq rax, xmm3", "ret"], "uint64_t", "b"),
            ("low_high_pair", ["movq xmm0, rdi", "movq xmm1, rsi", "movlhps xmm0, xmm1", "movups xmm2, xmm0",
                               "punpckhqdq xmm2, xmm2", "movq rax, xmm2", "ret"], "uint64_t", "b"),
            ("merge_single", ["movq xmm0, rdi", "movq xmm1, rsi", "movss xmm0, xmm1", "movq rax, xmm0", "ret"], "uint64_t",
             "(a & ~0xffffffffull) | (uint32_t)b"),
            ("merge_double", ["movq xmm0, rdi", "movq xmm1, rsi", "movsd xmm0, xmm1", "movq rax, xmm0", "ret"], "uint64_t", "b"),
            ("zero_idiom", ["movq xmm0, rdi", "pxor xmm0, xmm0", "movq rax, xmm0", "ret"], "uint64_t", "0"),
            ("xorps_zero", ["movq xmm1, rdi", "xorps xmm1, xmm1", "movd eax, xmm1", "ret"], "uint32_t", "0"),
            ("logic", ["movq xmm0, rdi", "movq xmm1, rsi", "pandn xmm0, xmm1", "movq xmm2, rdx", "por xmm0, xmm2",
                       "pxor xmm0, xmm1", "movq rax, xmm0", "ret"], "uint64_t", "((~a & b) | c) ^ b"),
            ("vex_logic", ["vmovq xmm0, rdi", "vmovq xmm1, rsi", "vpand xmm2, xmm0, xmm1", "vmovaps xmm3, xmm2",
                           "vmovq rax, xmm3", "ret"], "uint64_t", "a & b"),
        ]
        self.check_cases("x86_64", cases, _VALUES64, "uint64_t")

    def test_wide_vector_constants_render_as_compilable_c(self):
        # 超出 64 位的 128 位常量（含常量传播折叠出的）必须拆成两个 64 位半，C 才能编译。
        direct = _build("arm64", "store_bytes", ["movi v0.16b, #0x5a", "str q0, [x0]", "ret"])
        folded = _build("arm64", "store_words", ["mov x8, #0x1234", "dup v0.4s, w8", "str q0, [x0]", "ret"])
        for output in (direct, folded):
            self.assertNotIn("unresolved", output.pseudoc, output.pseudoc)
            self.assertIn("<< 64", output.pseudoc)
        compile_run(direct.pseudoc + "\n" + folded.pseudoc, "\n".join([
            "_Alignas(16) uint64_t buffer[2] = {0, 0};",
            f"(void){_call(direct.pseudoc, 'store_bytes', ('(void *)buffer',))};",
            "if (buffer[0] != 0x5a5a5a5a5a5a5a5aull || buffer[1] != 0x5a5a5a5a5a5a5a5aull) return 1;",
            f"(void){_call(folded.pseudoc, 'store_words', ('(void *)buffer',))};",
            "if (buffer[0] != 0x0000123400001234ull || buffer[1] != 0x0000123400001234ull) return 2;",
            "return 0;"]))

    def test_x86_vector_memory_moves_compile_and_store_both_halves(self):
        output = _build("x86_64", "store_pair", ["movq xmm0, rsi", "movq xmm1, rdx", "punpcklqdq xmm0, xmm1",
                                                 "movups xmmword ptr [rdi], xmm0", "xor eax, eax", "ret"])
        self.assertNotIn("unresolved_operation", output.pseudoc, output.pseudoc)
        call = _call(output.pseudoc, "store_pair", ("(void *)buffer", "b", "c"))
        loaded = _build("x86_64", "load_high", ["movdqu xmm0, xmmword ptr [rdi]", "pxor xmm1, xmm1", "movhlps xmm1, xmm0",
                                                "movq rax, xmm1", "ret"])
        self.assertNotIn("unresolved_operation", loaded.pseudoc, loaded.pseudoc)
        load_call = _call(loaded.pseudoc, "load_high", ("(void *)buffer",))
        compile_run(output.pseudoc + "\n" + loaded.pseudoc, _grid(_VALUES64, "uint64_t", [
            "_Alignas(16) uint64_t buffer[2] = {0, 0};",
            f"(void){call};",
            "if (buffer[0] != b || buffer[1] != c) return 1;",
            f"if ((uint64_t){load_call} != c) return 2;",
        ]))


class OpaqueSnapshotEffectsTests(unittest.TestCase):
    def _opaque(self, architecture, mnemonic, operands, reads, writes):
        row = {**ins(0, mnemonic, *operands, size=1 if architecture.startswith("x86") else 4), "reads": reads, "writes": writes}
        result = lift_instruction(row, architecture)
        self.assertFalse(result["supported"])
        operation = result["operations"][0]
        self.assertEqual(operation["opcode"], "opaque")
        self.assertTrue(operation["attributes"]["barrier"])
        self.assertEqual(operation["attributes"]["register_effects"], "unknown")
        self.assertEqual((result["flag_effect"], result["memory_effect"]), ("unknown", "unknown"))
        return result

    def test_snapshot_registers_are_normalized_to_microcode_roots(self):
        x86 = self._opaque("x86_64", "vaddps", ("ymm0", "ymm1", "ymmword ptr [rdi]"), ("ymm1", "rdi", "mxcsr", "rip"), ("ymm0",))
        self.assertEqual((x86["reads"], x86["writes"]), (["rdi", "xmm1"], ["flags", "xmm0"]))
        self.assertEqual(x86["operations"][0]["attributes"]["snapshot_writes"], ["xmm0"])
        legacy = self._opaque("x86_64", "cpuid", (), ("eax", "ecx"), ("eax", "ebx", "ecx", "edx", "rflags"))
        # eax/ecx 先读后写：opaque 没有输入表达式，读在 ABI 推断中不可见，记为定义会遮住入参，
        # 只留在读集合；属性里仍保留完整的快照写集合。
        self.assertEqual((legacy["reads"], legacy["writes"]), (["rax", "rcx"], ["flags", "rbx", "rdx"]))
        self.assertEqual(legacy["operations"][0]["attributes"]["snapshot_writes"], ["flags", "rax", "rbx", "rcx", "rdx"])
        narrow = self._opaque("x86", "cpuid", (), ("eax", "ah", "eip"), ("esp", "eflags"))
        self.assertEqual((narrow["reads"], narrow["writes"]), (["eax"], ["esp", "flags"]))
        arm64 = self._opaque("arm64", "uqshl", ("v0.8h", "v1.8b", "#0"), ("d1", "nzcv", "wzr"), ("q0", "w3"))
        self.assertEqual((arm64["reads"], arm64["writes"]), (["flags", "v1"], ["flags", "v0", "x3"]))
        arm = self._opaque("arm", "ldrne", ("r0", "[ip]"), ("ip", "sb", "sl", "pc", "cpsr"), ("r0", "lr"))
        # 条件执行：r0/lr 只是可能写，改记为读。
        self.assertEqual((arm["reads"], arm["writes"]), (["flags", "r0", "r10", "r12", "r14", "r9"], ["flags"]))
        self.assertEqual(arm["operations"][0]["attributes"]["snapshot_writes"], ["r0", "r14"])
        unconditional = self._opaque("arm", "ldrex", ("r0", "[ip]"), ("ip",), ("r0", "lr"))
        self.assertEqual((unconditional["reads"], unconditional["writes"]), (["r12"], ["flags", "r0", "r14"]))

    def test_missing_or_malformed_snapshots_are_ignored(self):
        for reads, writes in ((None, None), ("rax", "rbx"), ([1, None, ""], ("bogus", 7))):
            with self.subTest(reads=reads, writes=writes):
                result = self._opaque("x86_64", "made_up", (), reads, writes)
                self.assertEqual((result["reads"], result["writes"]), ([], ["flags"]))

    def test_lower_bound_keeps_barrier_semantics(self):
        rows = [ins(0, "mov", "eax", "1"), {**ins(1, "made_up", "xmm0"), "reads": (), "writes": ("xmm0",)},
                ins(2, "ret", kind="return")]
        report = analyze_microcode(lift_function(fn(*rows), "x86_64")["instructions"])
        self.assertEqual(report["remaining_register_bits"], {})
        self.assertEqual(report["unsupported_addresses"], [1])

    @unittest.skipUnless(_HAS_CAPSTONE, "需要 Capstone 提供真实读写集")
    def test_real_snapshot_effects_reach_opaque_rows(self):
        from fangida.processors.decoder import NativeDecoder
        rows, warnings = NativeDecoder("x86_64").decode_bytes(bytes.fromhex("c5fe6f07"), 0x1000)  # vmovdqu ymm0, [rdi]
        self.assertFalse(warnings)
        result = lift_instruction(rows[0], "x86_64")
        self.assertFalse(result["supported"])
        self.assertIn("rdi", result["reads"])
        self.assertIn("xmm0", result["writes"])
        rows, _ = NativeDecoder("x86_64").decode_bytes(bytes.fromhex("0f28c1"), 0x1000)  # movaps xmm0, xmm1
        result = lift_instruction(rows[0], "x86_64")
        self.assertTrue(result["supported"])
        self.assertEqual((result["reads"], result["writes"]), (["xmm1"], ["xmm0"]))

    def test_only_definite_snapshot_writes_enter_the_write_set(self):
        # (架构, 助记符, 操作数, 快照读, 快照写, 期望读集合, 期望写集合)
        fixtures = [
            # AArch32 条件执行：写入可能不发生；条件求值读取 flags。
            ("arm", "ldrexne", ("r0", "[r1]"), ("r1",), ("r0",), ["flags", "r0", "r1"], ["flags"]),
            ("arm", "popne", ("{r4, r5}",), ("sp",), ("sp", "r4", "r5"), ["flags", "r13", "r4", "r5"], ["flags"]),
            ("arm", "ldrexne.w", ("r0", "[r1]"), ("r1",), ("r0",), ["flags", "r0", "r1"], ["flags"]),
            # 无条件：sp 先读后写，只留在读集合；r4/r5 必定写。
            ("arm", "pop", ("{r4, r5}",), ("sp",), ("sp", "r4", "r5"), ["r13"], ["flags", "r4", "r5"]),
            # umulls 是 umull+s（设置标志），不是 umul+ls 条件执行。
            ("arm", "umulls", ("r0", "r1", "r2", "r3"), ("r2", "r3"), ("r0", "r1", "cpsr"), ["r2", "r3"], ["flags", "r0", "r1"]),
            # x86 读改写、可能不写与部分写。
            ("x86_64", "lock xadd", ("dword ptr [rdi]", "esi"), ("rdi", "esi"), ("esi",), ["rdi", "rsi"], ["flags"]),
            ("x86_64", "bsf", ("rdi", "rdi"), ("rdi",), ("rflags", "rdi"), ["rdi"], ["flags"]),
            ("x86_64", "bsf", ("rdi", "rsi"), ("rsi",), ("rflags", "rdi"), ["rdi", "rsi"], ["flags"]),
            ("x86_64", "rep lodsd", ("eax", "dword ptr [rsi]"), ("rsi", "rflags", "rcx"), ("eax", "rsi", "rcx"),
             ["flags", "rax", "rcx", "rsi"], ["flags"]),
            ("x86_64", "lahf", (), ("rflags",), ("ah",), ["flags", "rax"], ["flags"]),
            ("x86_64", "in", ("al", "dx"), ("dx",), ("al",), ["rax", "rdx"], ["flags"]),
            ("x86", "lahf", (), ("eflags",), ("ah",), ["eax", "flags"], ["flags"]),
            # 整体写：64 位寄存器、64 位模式下零扩展的 32 位写、A64 的 w 寄存器。
            ("x86_64", "rdtsc", (), (), ("rax", "rdx"), [], ["flags", "rax", "rdx"]),
            ("x86_64", "xgetbv", (), ("ecx",), ("edx", "eax"), ["rcx"], ["flags", "rax", "rdx"]),
            ("arm64", "ldaxr", ("w0", "[x1]"), ("x1",), ("w0",), ["x1"], ["flags", "x0"]),
        ]
        for architecture, mnemonic, operands, reads, writes, expected_reads, expected_writes in fixtures:
            with self.subTest(architecture=architecture, mnemonic=mnemonic, operands=operands):
                result = self._opaque(architecture, mnemonic, operands, reads, writes)
                self.assertEqual((result["reads"], result["writes"]), (expected_reads, expected_writes))
                # 读写集合的并集不丢任何快照寄存器；完整快照仍记录在属性里。
                attributes = result["operations"][0]["attributes"]
                self.assertLessEqual(set(attributes["snapshot_writes"]) | set(attributes["snapshot_reads"]),
                                     set(result["reads"]) | set(result["writes"]))

    def test_may_be_conditional_separates_flag_setting_forms(self):
        from fangida.plugins.pseudoc.microcode.conditional import may_be_conditional
        for mnemonic in ("ldrne", "strne", "popne", "ldmibne", "ldrne.w", "vmovne.f32", "movvs", "lslls", "adccs",
                         "mulls", "ldrhs", "umullls", "addseq", "movseq", "LDRNE"):
            self.assertTrue(may_be_conditional(mnemonic), mnemonic)
        for mnemonic in ("teq", "mls", "movs", "lsls", "muls", "bics", "adcs", "sbcs", "rscs", "umulls", "smlals",
                         "ldr", "pop", "add", "ne", "", None, 7):
            self.assertFalse(may_be_conditional(mnemonic), mnemonic)


def _snapshot_rows(architecture, entries):
    """entries: (助记符, 操作数元组, 快照读, 快照写)；快照为 None 时不附加读写集（由处理器提升）。"""
    size = 1 if architecture.startswith("x86") else 4
    rows = []
    for index, (mnemonic, operands, reads, writes) in enumerate(entries):
        kind = "return" if mnemonic == "ret" or (architecture == "arm" and mnemonic == "bx") else None
        row = ins(index * size, mnemonic, *operands, size=size, kind=kind)
        if reads is not None:
            row = {**row, "reads": tuple(reads), "writes": tuple(writes)}
        rows.append(row)
    return rows


class OpaqueSnapshotSignatureTests(unittest.TestCase):
    """快照读写下界对 ABI 参数推断的影响：可能写不能遮住入参，必定写仍能消除伪参数。

    reconstruct/abi 的 incoming_registers 把行的 writes 当作必定定义，读只从操作输入取；
    opaque 指令只有在必定整体写入某寄存器时才能让它之后的读取不再算作入参。
    """

    def _parameters(self, architecture, name, rows):
        output = generate_pseudoc(fn(*rows, name=name, pseudoc_context={"kind": "elf"}), architecture, style="readable")
        match = re.search(rf"\b{name}\(([^)]*)\)\s*\{{", output.pseudoc)
        self.assertIsNotNone(match, output.pseudoc)
        return {int(index) for index in re.findall(r"\barg_(\d+)\b", match.group(1))}

    def test_may_write_instructions_keep_incoming_parameters(self):
        cases = [
            # if (p) a = *p; return a;  —— 条件不成立时返回入参 a。
            ("arm", "load_or_keep", [("cmp", ("r1", "#0"), None, None), ("ldrne", ("r0", "[r1]"), ("r1",), ("r0",)),
                                     ("bx", ("lr",), None, None)], {1, 2}),
            ("arm", "pop_or_keep", [("cmp", ("r2", "#0"), None, None),
                                    ("popne", ("{r0", "r1}"), ("sp",), ("sp", "r0", "r1")),
                                    ("add", ("r0", "r0", "r1"), None, None), ("bx", ("lr",), None, None)], {1, 2, 3}),
            # 读改写：xadd 读入参 esi 后把旧内存值写回 esi。
            ("x86_64", "exchange_add", [("lock xadd", ("dword ptr [rdi]", "esi"), ("rdi", "esi"), ("esi",)),
                                        ("mov", ("eax", "esi"), None, None), ("ret", (), None, None)], {2}),
            ("x86_64", "scan_same", [("bsf", ("rdi", "rdi"), ("rdi",), ("rflags", "rdi")),
                                     ("mov", ("rax", "rdi"), None, None), ("ret", (), None, None)], {1}),
            # bsf 源为零时目的保持原值：rdi 只是可能写。
            ("x86_64", "scan_other", [("bsf", ("rdi", "rsi"), ("rsi",), ("rflags", "rdi")),
                                      ("mov", ("rax", "rdi"), None, None), ("ret", (), None, None)], {1}),
            # cpuid 读 ecx：之后读 rcx 仍说明 rcx 是入参。
            ("x86_64", "identify", [("cpuid", (), ("eax", "ecx"), ("eax", "ebx", "ecx", "edx", "rflags")),
                                    ("mov", ("rax", "rcx"), None, None), ("ret", (), None, None)], {4}),
            # 部分写：dl 之外的 rdx 位来自调用者。
            ("x86_64", "partial", [("made_up", ("dl",), (), ("dl",)), ("mov", ("rax", "rdx"), None, None),
                                   ("ret", (), None, None)], {3}),
        ]
        for architecture, name, entries, expected in cases:
            with self.subTest(name=name):
                self.assertLessEqual(expected, self._parameters(architecture, name, _snapshot_rows(architecture, entries)))

    def test_definite_writes_still_remove_false_parameters(self):
        cases = [
            ("x86_64", "timestamp", [("rdtsc", (), (), ("rax", "rdx")), ("mov", ("rax", "rdx"), None, None),
                                     ("ret", (), None, None)], set()),
            ("arm64", "acquire_add", [("ldaxr", ("x0", "[x1]"), ("x1",), ("x0",)), ("add", ("x0", "x0", "x2"), None, None),
                                      ("ret", (), None, None)], {3}),
            ("arm", "exclusive", [("ldrex", ("r0", "[r1]"), ("r1",), ("r0",)), ("bx", ("lr",), None, None)], set()),
        ]
        for architecture, name, entries, expected in cases:
            with self.subTest(name=name):
                self.assertEqual(self._parameters(architecture, name, _snapshot_rows(architecture, entries)), expected)

    @unittest.skipUnless(_HAS_CAPSTONE, "需要 Capstone 解码真实编码")
    def test_real_encodings_keep_parameters(self):
        from fangida.processors.decoder import NativeDecoder
        cases = [
            # clang armv7 -marm -O2：int32_t f(int32_t a, const int32_t *p) { if (p) a = *p; return a; }
            ("arm", "load_or_keep", "000051e3" "00009115" "1eff2fe1", {1, 2}),
            ("x86_64", "exchange_add", "f00fc137" "89f0" "c3", {2}),  # lock xadd [rdi], esi; mov eax, esi; ret
            ("x86_64", "scan_same", "480fbcff" "4889f8" "c3", {1}),  # bsf rdi, rdi; mov rax, rdi; ret
            ("x86_64", "timestamp", "0f31" "4889d0" "c3", set()),  # rdtsc; mov rax, rdx; ret
        ]
        for architecture, name, encoding, expected in cases:
            rows, warnings = NativeDecoder(architecture).decode_bytes(bytes.fromhex(encoding), 0x1000)
            with self.subTest(name=name):
                self.assertFalse(warnings)
                self.assertEqual(self._parameters(architecture, name, rows), expected)


class Arm32ConditionalShiftTests(_Compiled):
    """条件执行的移位：只有计数为小于宽度的常量时才改写为条件选择。"""

    def test_register_controlled_and_full_width_shifts_stay_opaque(self):
        for mnemonic, operands in (("lslne", ("r0", "r0", "r1")), ("lsrne", ("r0", "r0", "r1")),
                                   ("asreq", ("r0", "r0", "r1")), ("rorne", ("r0", "r0", "r1")),
                                   ("lsrne", ("r0", "r1", "#32")), ("asrne", ("r0", "r1", "#32"))):
            with self.subTest(mnemonic=mnemonic, operands=operands):
                row = lift_instruction(ins(0, mnemonic, *operands, size=4), "arm")
                self.assertFalse(row["supported"])
                self.assertEqual(row["category"], "opaque")
                self.assertNotIn("condition", row["operations"][0]["attributes"])
                # 基础指令试提升时记录的目的寄存器同样只是可能写：不进写集合，记为读。
                self.assertEqual(row["writes"], ["flags"])
                self.assertIn("r0", row["reads"])
                self.assertIn("flags", row["reads"])

    def test_unconditional_register_shift_microcode_handles_counts_beyond_width(self):
        counts = (0, 5, 31, 32, 0x7f, 0x100, 0x101, 0x121)
        references = {  # AArch32：计数取 Rs 低 8 位；LSL/LSR ≥ 32 得 0，ASR ≥ 32 填符号位，ROR 取模 32
            ("lsl", 1): [0x1, 0x20, 0x80000000, 0, 0, 0x1, 0x2, 0],
            ("lsr", 0x80000000): [0x80000000, 0x4000000, 0x1, 0, 0, 0x80000000, 0x40000000, 0],
            ("asr", 0x80000000): [0x80000000, 0xfc000000, 0xffffffff, 0xffffffff, 0xffffffff, 0x80000000, 0xc0000000,
                                  0xffffffff],
            ("ror", 0x80000001): [0x80000001, 0x0c000000, 0x3, 0x80000001, 0x3, 0x80000001, 0xc0000000, 0xc0000000],
        }
        for (mnemonic, value), expected in references.items():
            expression = lift_instruction(ins(0, mnemonic, "r0", "r0", "r1", size=4), "arm")["operations"][0]["expression"]
            with self.subTest(mnemonic=mnemonic):
                self.assertEqual([evaluate_expression(expression, {"r0": value, "r1": count}) for count in counts], expected)

    def test_immediate_shift_selects_evaluate_exactly(self):
        mask = 0xffffffff
        samples = (0, 1, 0x7f, 0x80000000, 0x80000001, 0xdeadbeef, mask)
        references = {
            "lsl": lambda value, amount: (value << amount) & mask,
            "lsr": lambda value, amount: value >> amount,
            "asr": lambda value, amount: ((value - (1 << 32) if value >> 31 else value) >> amount) & mask,
            "ror": lambda value, amount: ((value >> amount) | (value << (32 - amount))) & mask,
        }
        for base, reference in references.items():
            for amount in (1, 7, 31):
                row = lift_instruction(ins(0, base + "ne", "r0", "r1", f"#{amount}", size=4), "arm")
                with self.subTest(base=base, amount=amount):
                    self.assertTrue(row["supported"])
                    operation = row["operations"][0]
                    self.assertEqual(operation["opcode"], "select")
                    for value in samples:
                        self.assertEqual(evaluate_expression(operation["inputs"][0], {"r1": value}), reference(value, amount))

    def test_conditional_shifts_compile_and_match_reference(self):
        cases = [
            ("high_bit_or_keep", ["cmp r2, #0", "lsrne r0, r0, #31", "bx lr"], "uint32_t", "c != 0 ? a >> 31 : a"),
            ("low_bit_up_or_keep", ["cmp r2, #0", "lslne r0, r1, #31", "bx lr"], "uint32_t", "c != 0 ? b << 31 : a"),
            ("shift_pair", ["cmp r0, r1", "lslhi r0, r0, #1", "lsrls r0, r1, #1", "bx lr"], "uint32_t",
             "a > b ? a << 1 : b >> 1"),
        ]
        self.check_cases("arm", cases, _VALUES32, "uint32_t")

    def test_register_shift_pseudoc_is_explicitly_unresolved(self):
        output = _build("arm", "shift_or_keep", ["cmp r2, #0", "lslne r0, r0, r1", "bx lr"])
        self.assertIn('unresolved_operation("lslne")', output.pseudoc)
        match = re.search(r"\bshift_or_keep\(([^)]*)\)", output.pseudoc)
        # 条件不成立时返回入参 r0：参数不能因为 opaque 的“可能写”而消失。
        self.assertIn("arg_1", match.group(1))
        self.assertIn("arg_3", match.group(1))


if __name__ == "__main__":
    unittest.main()
