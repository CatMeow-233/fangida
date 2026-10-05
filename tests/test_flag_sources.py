"""各类标志来源（cmn/adds/add/inc/dec/neg/test/移位/ccmp）还原出的条件必须与机器语义一致。

每个用例生成一个函数：标志设置指令之后接一个条件分支，跳转返回 2、否则返回 1。
所有函数编译进同一个程序，在 32 位边界值网格上与 C 参考表达式逐一比对。
"""
from __future__ import annotations

import re
import unittest

from fangida.plugins.pseudoc import generate_pseudoc
from tests.test_pseudoc import function as fn, instruction as ins
from tests.test_reconstruction import compile_run

# 32 位边界值：0、±1、符号位两侧、全 1 附近以及几个普通值。
_VALUES = ("0u, 1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 10u, 11u, 0x7fu, 0x80u, 0xffu, 0x7ffffffeu, 0x7fffffffu, "
           "0x80000000u, 0x80000001u, 0xfffffffbu, 0xfffffffdu, 0xfffffffeu, 0xffffffffu, 0x12345678u, 0xdeadbeefu")

# (名字, 架构, 标志设置指令（不含分支）, 分支助记符, C 参考条件；a/b 为 uint32_t，sa/sb 为 int32_t)
_ARM64 = [
    ("cmn_imm_lt", ["cmn w0, #1"], "b.lt", "(int64_t)sa + 1 < 0"),
    ("cmn_imm_hs", ["cmn w0, #3"], "b.hs", "(uint64_t)a + 3 > 0xffffffffu"),
    ("cmn_imm_hi", ["cmn w0, #3"], "b.hi", "(uint64_t)a + 3 > 0xffffffffu && (uint32_t)(a + 3) != 0"),
    ("cmn_imm_ls", ["cmn w0, #3"], "b.ls", "!((uint64_t)a + 3 > 0xffffffffu) || (uint32_t)(a + 3) == 0"),
    ("cmn_zero_ge", ["cmn w0, #0"], "b.ge", "sa >= 0"),
    ("cmn_reg_eq", ["cmn w0, w1"], "b.eq", "(uint32_t)(a + b) == 0"),
    ("cmn_reg_hs", ["cmn w0, w1"], "b.hs", "(uint64_t)a + b > 0xffffffffu"),
    ("cmn_reg_hi", ["cmn w0, w1"], "b.hi", "(uint64_t)a + b > 0xffffffffu && (uint32_t)(a + b) != 0"),
    ("cmn_reg_ls", ["cmn w0, w1"], "b.ls", "!((uint64_t)a + b > 0xffffffffu) || (uint32_t)(a + b) == 0"),
    ("cmn_reg_ge", ["cmn w0, w1"], "b.ge", "(int64_t)sa + sb >= 0"),
    ("cmn_reg_gt", ["cmn w0, w1"], "b.gt", "(int64_t)sa + sb > 0"),
    ("cmn_reg_mi", ["cmn w0, w1"], "b.mi", "(int32_t)(a + b) < 0"),
    ("adds_reg_lo", ["adds w2, w0, w1"], "b.lo", "(uint64_t)a + b <= 0xffffffffu"),
    ("adds_imm_le", ["adds w2, w0, #7"], "b.le", "(int64_t)sa + 7 <= 0"),
    ("subs_pl", ["subs w2, w0, w1"], "b.pl", "(int32_t)(a - b) >= 0"),
    ("ccmp_eq", ["cmp w0, #5", "ccmp w1, #3, #4, ne"], "b.eq", "sa == 5 || b == 3"),
    ("ccmp_gt", ["cmp w0, w1", "ccmp w1, #10, #0, lt"], "b.gt", "sa < sb ? sb > 10 : 1"),
    ("ccmp_hi", ["cmp w0, #2", "ccmp w1, #9, #2, hs"], "b.hi", "a >= 2 ? b > 9 : 1"),
    ("ccmn_ne", ["cmp w0, #1", "ccmn w1, #4, #0, eq"], "b.ne", "a == 1 ? b != 0xfffffffcu : 1"),
    ("tst_ne", ["tst w0, #0x80"], "b.ne", "(a & 0x80) != 0"),
    ("tst_mi", ["tst w0, w1"], "b.mi", "(int32_t)(a & b) < 0"),
    ("ands_gt", ["ands w2, w0, w1"], "b.gt", "(int32_t)(a & b) > 0"),
    ("ands_le", ["ands w2, w0, w1"], "b.le", "(int32_t)(a & b) <= 0"),
]
_X86 = [
    ("test_le", ["test edi, edi"], "jle", "sa <= 0"),
    ("test_g", ["test edi, esi"], "jg", "(int32_t)(a & b) > 0"),
    ("test_s", ["test edi, esi"], "js", "(int32_t)(a & b) < 0"),
    ("test_a", ["test edi, edi"], "ja", "a != 0"),
    ("test_be", ["test edi, esi"], "jbe", "(a & b) == 0"),
    ("and_ns", ["and edi, esi"], "jns", "(int32_t)(a & b) >= 0"),
    ("or_e", ["or edi, esi"], "je", "(a | b) == 0"),
    ("add_b", ["add edi, esi"], "jb", "(uint64_t)a + b > 0xffffffffu"),
    ("add_a", ["add edi, esi"], "ja", "(uint64_t)a + b <= 0xffffffffu && (uint32_t)(a + b) != 0"),
    ("add_l", ["add edi, esi"], "jl", "(int64_t)sa + sb < 0"),
    ("add_imm_g", ["add edi, 5"], "jg", "(int64_t)sa + 5 > 0"),
    ("add_imm_ae", ["add edi, 5"], "jae", "(uint64_t)a + 5 <= 0xffffffffu"),
    ("add_neg_imm_b", ["add edi, -3"], "jb", "(uint64_t)a + 0xfffffffdu > 0xffffffffu"),
    ("add_imm_a", ["add edi, 5"], "ja", "(uint64_t)a + 5 <= 0xffffffffu && (uint32_t)(a + 5) != 0"),
    ("add_imm_be", ["add edi, 5"], "jbe", "(uint64_t)a + 5 > 0xffffffffu || (uint32_t)(a + 5) == 0"),
    ("add_zero_l", ["add edi, 0"], "jl", "sa < 0"),
    ("subtract_s", ["sub edi, esi"], "js", "(int32_t)(a - b) < 0"),
    ("dec_g", ["dec edi"], "jg", "(int64_t)sa - 1 > 0"),
    ("inc_e", ["inc edi"], "je", "a + 1 == 0"),
    ("inc_le", ["inc edi"], "jle", "(int64_t)sa + 1 <= 0"),
    ("neg_b", ["neg edi"], "jb", "a != 0"),
    ("neg_l", ["neg edi"], "jl", "0 - (int64_t)sa < 0"),
    ("shr_e", ["shr edi, 3"], "je", "(a >> 3) == 0"),
    ("sar_s", ["sar edi, 1"], "js", "sa < 0"),
    ("sar_e", ["sar edi, 2"], "je", "sa >= 0 && sa < 4"),
    ("shl_ne", ["shl edi, 4"], "jne", "(uint32_t)(a << 4) != 0"),
]
# MUL/IMUL 之后的 jo/jb/jae…（CF = OF = 乘积溢出，用到前导的 umul/smul_overflow_W）见 tests/test_pseudoc_exactness.py。


def _row(architecture, address, text):
    mnemonic, _, rest = text.partition(" ")
    operands = [item.strip() for item in rest.split(",")] if rest else []
    return ins(address, mnemonic, *operands, size=4 if architecture == "arm64" else 1)


def _case(architecture, name, setters, branch):
    """标志设置指令 + 条件分支；跳转目标返回 2，顺序执行返回 1。"""
    step = 4 if architecture == "arm64" else 1
    rows = [_row(architecture, index * step, text) for index, text in enumerate(setters)]
    at = len(rows) * step
    taken = at + 4 * step
    rows.append(ins(at, branch, hex(taken), size=step, kind="jump", target=taken, conditional=True))
    if architecture == "arm64":
        rows += [ins(at + 4, "mov", "w0", "#1", size=4), ins(at + 8, "ret", size=4, kind="return"),
                 ins(taken, "mov", "w0", "#2", size=4), ins(taken + 4, "ret", size=4, kind="return")]
    else:
        rows += [ins(at + 1, "mov", "eax", "1"), ins(at + 2, "ret", kind="return"),
                 ins(taken, "mov", "eax", "2"), ins(taken + 1, "ret", kind="return")]
    return generate_pseudoc(fn(*rows, name=name, pseudoc_context={"kind": "elf"}), architecture, style="readable")


def _arity(text, name):
    match = re.search(rf"\b{name}\(([^)]*)\)", text)
    parameters = match.group(1).strip() if match else ""
    return 0 if parameters in {"", "void"} else parameters.count(",") + 1


class FlagSourceTests(unittest.TestCase):
    def test_every_flag_source_matches_machine_semantics(self):
        sources, checks = [], []
        for architecture, cases in (("arm64", _ARM64), ("x86_64", _X86)):
            for name, setters, branch, reference in cases:
                with self.subTest(name=name):
                    output = _case(architecture, name, setters, branch)
                    self.assertNotIn("unresolved_condition", output.pseudoc, output.pseudoc)
                    self.assertFalse([item for item in output.reconstruction["unresolved"] if item.get("kind") == "condition"])
                    sources.append(output.pseudoc)
                    arguments = ", ".join(("a", "b")[:_arity(output.pseudoc, name)])
                    checks.append(f"if ({name}({arguments}) != (({reference}) ? 2u : 1u)) return {len(checks) + 1};")
        body = ("static const uint32_t values[] = {" + _VALUES + "};\n"
                "for (unsigned i = 0; i < sizeof values / sizeof *values; ++i)\n"
                "for (unsigned j = 0; j < sizeof values / sizeof *values; ++j) {\n"
                "uint32_t a = values[i], b = values[j]; int32_t sa = (int32_t)a, sb = (int32_t)b;\n"
                "(void)sa; (void)sb; (void)b;\n" + "\n".join(checks) + "\n}\nreturn 0;")
        compile_run("\n".join(sources), body)

    def test_ccmp_condition_is_simplified(self):
        output = _case("arm64", "ccmp_text", ["cmp w0, #5", "ccmp w1, #3, #4, ne"], "b.eq")
        self.assertNotIn("!(", output.pseudoc)
        self.assertRegex(output.pseudoc, r"== 5 \|\|")

    def test_conditions_without_exact_source_stay_unresolved(self):
        # inc 不写 CF、add 的溢出标志、64 位寄存器加法的带符号关系、进位输入的 adc：都不能伪造。
        # MUL/IMUL 只定义 CF/OF（见 tests/test_pseudoc_exactness.py），其后读机器未定义的 ZF/SF 的条件同样不能伪造。
        for architecture, setters, branch in (("x86_64", ["inc edi"], "jb"), ("x86_64", ["add edi, esi"], "jo"),
                                              ("x86_64", ["mov eax, edi", "mul esi"], "je"),
                                              ("x86_64", ["imul edi, esi"], "js"),
                                              ("x86_64", ["add rdi, rsi"], "jl"), ("x86_64", ["adc edi, esi"], "je"),
                                              ("x86_64", ["rol edi, 1"], "je"), ("x86_64", ["shr edi, cl"], "je")):
            with self.subTest(setters=setters, branch=branch):
                output = _case(architecture, "unknown_flags", setters, branch)
                self.assertIn("unresolved_condition", output.pseudoc)

    def test_later_flag_writers_hide_an_earlier_compare(self):
        # cmp 之后的 fcmp / mul / 未建模指令改写了标志：分支不得沿用更早的 cmp。
        for architecture, setters, branch in (("arm64", ["cmp w0, #5", "fcmp s0, s1"], "b.eq"),
                                              ("x86_64", ["cmp edi, 5", "mul esi"], "je"),
                                              ("x86_64", ["cmp edi, 5", "bt edi, 3"], "je")):
            with self.subTest(setters=setters):
                output = _case(architecture, "hidden", setters, branch)
                self.assertNotRegex(output.pseudoc, r"(?:==|!=) 5\b")
                self.assertIn("unresolved_condition", output.pseudoc)

    def test_cmn_and_cmp_merge_at_a_join(self):
        # 一条路径由 cmp 设置标志，另一条由 cmn（等价于与 -2 比较）设置：汇合点仍是真实比较。
        output = generate_pseudoc(fn(
            ins(0x00, "cmp", "w0", "#5", size=4), ins(0x04, "b.lt", "#0x10", size=4, kind="jump", target=0x10, conditional=True),
            ins(0x08, "cmn", "w1", "#2", size=4), ins(0x0c, "b", "#0x10", size=4, kind="jump", target=0x10),
            ins(0x10, "b.le", "#0x20", size=4, kind="jump", target=0x20, conditional=True),
            ins(0x14, "mov", "w0", "#1", size=4), ins(0x18, "ret", size=4, kind="return"),
            ins(0x20, "mov", "w0", "#2", size=4), ins(0x24, "ret", size=4, kind="return"),
            name="joined_cmn", pseudoc_context={"kind": "elf"}), "arm64", style="readable")
        self.assertNotIn("unresolved_condition", output.pseudoc)
        compile_run(output.pseudoc,
            "static const int32_t v[] = {INT32_MIN, -3, -2, -1, 0, 4, 5, 6, INT32_MAX};\n"
            "for (unsigned i = 0; i < 9; ++i) for (unsigned j = 0; j < 9; ++j) {\n"
            "int32_t a = v[i], b = v[j]; uint32_t expect = (a < 5 ? 1 : (int64_t)b + 2 <= 0) ? 2u : 1u;\n"
            "if (joined_cmn((uint32_t)a, (uint32_t)b) != expect) return 1; }\nreturn 0;")


if __name__ == "__main__":
    unittest.main()
