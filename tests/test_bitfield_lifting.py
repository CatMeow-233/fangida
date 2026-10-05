"""ARM 位域指令、x86 累加器符号扩展与 BTI 的语义提升：编译运行生成的 C 并与参考实现逐一比对。"""
from __future__ import annotations

import re
import unittest

from fangida.plugins.pseudoc import generate_pseudoc
from fangida.plugins.pseudoc.microcode import lift_instruction
from tests.test_pseudoc import function as fn, instruction as ins
from tests.test_reconstruction import compile_run

_VALUES32 = "0u, 1u, 0x10u, 0x1fu, 0x20u, 0x7fu, 0x80u, 0xffu, 0x1234u, 0x7fffffffu, 0x80000000u, 0xdeadbeefu, 0xfffffff0u, 0xffffffffu"
_VALUES64 = ("0ull, 1ull, 0x7full, 0x80ull, 0xffffffffull, 0x100000000ull, 0x7fffffffffffffffull, 0x8000000000000000ull, "
             "0xdeadbeefcafef00dull, 0xf000000000000001ull, 0xffffffffffffffffull")

# (名字, 指令（目标总是 w0/x0）, 参考表达式；a、b 为输入，宽度见 bits)
_ARM64_32 = [
    ("ubfx32", "ubfx w0, w0, #3, #5", "(a >> 3) & 0x1f"),
    ("ubfx32_top", "ubfx w0, w0, #24, #8", "a >> 24"),
    ("sbfx32", "sbfx w0, w0, #3, #5", "(uint32_t)((int32_t)(((a >> 3) & 0x1f) ^ 0x10) - 0x10)"),
    ("sbfx32_low", "sbfx w0, w0, #0, #8", "(uint32_t)(int32_t)(int8_t)a"),
    ("sbfx32_full", "sbfx w0, w0, #0, #32", "a"),
    ("ubfiz32", "ubfiz w0, w0, #4, #6", "(a & 0x3f) << 4"),
    ("sbfiz32", "sbfiz w0, w0, #4, #6", "(uint32_t)(((a & 0x3f) ^ 0x20) - 0x20) << 4"),
    ("bfxil32", "bfxil w0, w1, #4, #8", "(a & ~0xffu) | ((b >> 4) & 0xff)"),
    ("bfi32", "bfi w0, w1, #8, #4", "(a & ~0xf00u) | ((b & 0xf) << 8)"),
    ("bfc32", "bfc w0, #8, #4", "a & ~0xf00u"),
]
_ARM64_64 = [
    ("ubfx64", "ubfx x0, x0, #32, #32", "a >> 32"),
    ("sbfx64", "sbfx x0, x0, #60, #4", "(uint64_t)((int64_t)((a >> 60) ^ 0x8) - 0x8)"),
    ("bfxil64", "bfxil x0, x1, #40, #20", "(a & ~0xfffffull) | ((b >> 40) & 0xfffff)"),
    ("bfi64", "bfi x0, x1, #33, #31", "(a & ~(0x7fffffffull << 33)) | ((b & 0x7fffffff) << 33)"),
]


def _build(architecture, name, rows):
    return generate_pseudoc(fn(*rows, name=name, pseudoc_context={"kind": "elf"}), architecture, style="readable")


def _arity(text, name):
    match = re.search(rf"\b{name}\(([^)]*)\)", text)
    parameters = match.group(1).strip() if match else ""
    return 0 if parameters in {"", "void"} else parameters.count(",") + 1


def _grid(values, kind, checks):
    return (f"static const {kind} values[] = {{{values}}};\n"
            "for (unsigned i = 0; i < sizeof values / sizeof *values; ++i)\n"
            "for (unsigned j = 0; j < sizeof values / sizeof *values; ++j) {\n"
            f"{kind} a = values[i], b = values[j]; (void)b;\n" + "\n".join(checks) + "\n}\nreturn 0;")


class BitfieldLiftingTests(unittest.TestCase):
    def test_arm64_bitfield_instructions_match_reference(self):
        for bits, cases, values in ((32, _ARM64_32, _VALUES32), (64, _ARM64_64, _VALUES64)):
            kind = f"uint{bits}_t"
            sources, checks = [], []
            for name, text, reference in cases:
                mnemonic, _, rest = text.partition(" ")
                rows = (ins(0, mnemonic, *[item.strip() for item in rest.split(",")], size=4), ins(4, "ret", size=4, kind="return"))
                with self.subTest(text=text):
                    self.assertTrue(lift_instruction(rows[0], "arm64")["supported"])
                    output = _build("arm64", name, rows)
                    self.assertNotIn("unresolved_operation", output.pseudoc, output.pseudoc)
                    sources.append(output.pseudoc)
                    arguments = ", ".join(("a", "b")[:_arity(output.pseudoc, name)])
                    checks.append(f"if (({kind}){name}({arguments}) != ({kind})({reference})) return {len(checks) + 1};")
            compile_run("\n".join(sources), _grid(values, kind, checks))

    def test_x86_accumulator_sign_extension(self):
        cases = [
            ("widen_cdqe", [ins(0, "mov", "eax", "edi"), ins(1, "cdqe")], "rax", "(uint64_t)(int64_t)(int32_t)a"),
            ("widen_cwde", [ins(0, "mov", "eax", "edi"), ins(1, "cwde")], "eax", "(uint32_t)(int32_t)(int16_t)a"),
            ("widen_cbw", [ins(0, "mov", "eax", "edi"), ins(1, "cbw"), ins(2, "movzx", "eax", "ax")], "eax", "(uint16_t)(int16_t)(int8_t)a"),
            ("sign_cdq", [ins(0, "mov", "eax", "edi"), ins(1, "cdq"), ins(2, "mov", "eax", "edx")], "eax", "(int32_t)a < 0 ? 0xffffffffu : 0u"),
            ("sign_cqo", [ins(0, "mov", "rax", "rdi"), ins(1, "cqo"), ins(2, "mov", "rax", "rdx")], "rax", "(int64_t)a < 0 ? ~0ull : 0ull"),
        ]
        sources, checks = [], []
        for name, rows, _, reference in cases:
            rows = rows + [ins(len(rows), "ret", kind="return")]
            with self.subTest(name=name):
                output = _build("x86_64", name, rows)
                self.assertNotIn("unresolved_operation", output.pseudoc, output.pseudoc)
                sources.append(output.pseudoc)
                checks.append(f"if ((uint64_t){name}(a) != (uint64_t)({reference})) return {len(checks) + 1};")
        compile_run("\n".join(sources), _grid(_VALUES64, "uint64_t", checks))

    def test_bti_is_a_nop_and_bitfields_do_not_hide_flags(self):
        self.assertEqual([item["opcode"] for item in lift_instruction(ins(0, "bti", "c", size=4), "arm64")["operations"]], ["nop"])
        # 与 libtersafe.so 0x1dfb44 同形：cmp 与 csel 之间的 ubfx/mov 不改写标志。
        output = _build("arm64", "flags_through_ubfx", (
            ins(0x00, "bti", "c", size=4), ins(0x04, "cmp", "w0", "#0x1f", size=4),
            ins(0x08, "ubfx", "w2", "w1", "#0xa", "#3", size=4), ins(0x0c, "mov", "w1", "w0", size=4),
            ins(0x10, "csel", "w0", "w2", "w1", "eq", size=4), ins(0x14, "ret", size=4, kind="return")))
        self.assertNotIn("unresolved", output.pseudoc)
        compile_run(output.pseudoc, _grid(_VALUES32, "uint32_t", [
            "if ((uint32_t)flags_through_ubfx(a, b) != (a == 0x1f ? (b >> 10) & 7 : a)) return 1;"]))

    def test_invalid_bitfield_operands_stay_opaque(self):
        for operands in (("w0", "w1", "#30", "#5"), ("w0", "w1", "#0", "#0"), ("x0", "x1", "#64", "#1")):
            with self.subTest(operands=operands):
                self.assertFalse(lift_instruction(ins(0, "ubfx", *operands, size=4), "arm64")["supported"])


if __name__ == "__main__":
    unittest.main()
