"""可读伪 C 与微码 evaluate 的语义逐位一致（exactness）：窄位宽运算截回原宽度、x86 除法/乘法精确渲染。

修复前（窄算术不截回、x86 DIV/IDIV/MUL/IMUL 写成 unresolved_operation、IDIV r/m32 的结果在写回 rax/rdx 时被
符号扩展、MUL/IMUL 后的 jo/setc 是 unresolved_condition、ARM 语义取余除以 0 得 0）这些断言会失败；修复后通过。

* 窄位宽（8/16）的 add/sub/mul/not/neg 及其组合：合成叶子函数的可读 C 加前导编译运行（UBSan，-O0 与 -O2），
  在边界值（0、1、最大值、符号位、溢出）上与微码逐条执行（evaluate）逐一相同，且不含 C 未定义行为。
* 带符号类型的窄值零扩展（zext(sext(x))、64 位模式下 movsx r32 后读完整寄存器、select 两臂符号不同）：
  渲染与 evaluate 逐一相同。
* x86 DIV/IDIV、MUL/IMUL（8/16/32/64 位，寄存器与内存源）：流水线生成的函数在写回后读完整 64 位 rax/rdx
  （含 8/16 位部分写保留、32 位写清零高位、#DE 陷入），与独立的 Python 参考模型（按 Intel SDM 写成，
  不经项目代码）逐一相同（本机编译，UBSan，-O0 与 -O2）；能编译运行 x86-64 时（x86-64 本机，或 Apple Silicon
  经 Rosetta 2）再与真实 CPU 执行同一指令序列逐一对照（同样开 UBSan）。
* MUL/IMUL（单操作数与双/三操作数）后的 CF/OF（jo/seto/setc/setnc…）：流水线还原为精确条件
  （umul/smul_overflow_W），与参考模型及（可运行时）真实 CPU 对照；内存源宽乘/宽除只读一次内存。
* 通用 udiv/urem/sdiv/srem 的 division_semantics 声明（操作属性 "arm_zero"/"x86_fault"，以及表达式 name
  字段的逐节点声明）：evaluate 与渲染在 8/16/32/64/128 位都按声明一致执行；经 lower 的流水线同样如此。

本机没有 C 编译器、或不能编译运行 x86-64（非 x86-64 且没有 Rosetta）时跳过对应部分。
"""
from __future__ import annotations

import copy
import platform
import random
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from tests._speed import slow
from tests.test_lifter_gaps import _rows
from tests.test_pseudoc import function as fn
from tests.test_pseudoc_compilable import (
    _EXPRESSION_VARIABLES, _TRAPPED, _compiler, _leaf_case, _leaf_program, _op, _run_c, _render_expression, _reg,
    _const, _trap_statuses)
from fangida.plugins.pseudoc import generate_pseudoc, pseudoc_prelude
from fangida.plugins.pseudoc.microcode import analyze_microcode, evaluate_expression, lift_function
from fangida.plugins.pseudoc.microcode.evaluate import UnknownValue
from fangida.plugins.pseudoc.reconstruct import reconstruct_function
from fangida.plugins.pseudoc.reconstruct.expressions import Expressions, format_value


_X86_TARGET = []
_X86_SANITIZE = []


def _x86_target():
    """本机编译并运行 x86-64 程序所需的额外编译参数：x86-64 本机为空元组，Apple Silicon 经 Rosetta 2 为
    -arch x86_64；不能编译运行时为 None。结果缓存。"""
    if not _X86_TARGET:
        compiler = shutil.which("cc") or shutil.which("clang")
        machine = platform.machine().lower()
        candidates = [()] if machine in {"x86_64", "amd64"} else [("-arch", "x86_64")] if sys.platform == "darwin" else []
        found = None
        for flags in (candidates if compiler else ()):
            with tempfile.TemporaryDirectory() as tmp:
                source, binary = Path(tmp) / "p.c", Path(tmp) / "p"
                source.write_text("int main(void){return 0;}\n")
                built = subprocess.run([compiler, *flags, str(source), "-o", str(binary)], capture_output=True, text=True)
                if not built.returncode and not subprocess.run([str(binary)], capture_output=True).returncode:
                    found = flags
                    break
        _X86_TARGET.append(found)
    return _X86_TARGET[0]


def _can_run_x86():
    """本机能否编译并运行 x86-64 程序（x86-64 本机，或 Apple Silicon 经 Rosetta 2）。"""
    return _x86_target() is not None


def _x86_sanitizer_flags():
    """x86-64 目标上可用时开启 UBSan（出现 C 未定义行为即失败）。"""
    if not _X86_SANITIZE:
        flags = ("-fsanitize=undefined", "-fno-sanitize-recover=undefined")
        ok = False
        compiler = shutil.which("cc") or shutil.which("clang")
        if compiler and _can_run_x86():
            with tempfile.TemporaryDirectory() as tmp:
                source, binary = Path(tmp) / "p.c", Path(tmp) / "p"
                source.write_text("int main(int c, char **v){ (void)v; return c << 1 == 2 ? 0 : 1; }\n")
                built = subprocess.run([compiler, *_x86_target(), *flags, str(source), "-o", str(binary)],
                                       capture_output=True, text=True)
                ok = not built.returncode and not subprocess.run([str(binary)], capture_output=True).returncode
        _X86_SANITIZE.append(flags if ok else ())
    return _X86_SANITIZE[0]


def _assert_same_values(test, observed, expected, labels=None):
    """逐项比对两个结果序列，只报告前 10 处不一致（unittest 对上万元素的列表求差异会非常慢）。
    labels(index) 给出第 index 项的说明（函数名、输入等）。"""
    test.assertEqual(len(observed), len(expected), "输出个数不同")
    mismatches = [(labels(index) if labels else index, want, got)
                  for index, (want, got) in enumerate(zip(expected, observed)) if want != got]
    test.assertEqual(mismatches[:10], [], f"共 {len(mismatches)} 处不一致")


def _readable(architecture, texts, name="f"):
    return generate_pseudoc(fn(*_rows(architecture, texts), name=name, pseudoc_context={"kind": "elf"}),
                            architecture, style="readable").pseudoc


# ---------------------------------------------------------------------------
# 1. 窄位宽运算截回原宽度（8/16 位 add/sub/mul/not/neg）
# ---------------------------------------------------------------------------

def _narrow_cases():
    """合成叶子函数（x86-64），覆盖 8/16 位 add/sub/mul/not/neg 及其组合、以及对高位敏感的消费（比较、右移、扩展）。"""
    return [
        ("n_add8", ["mov eax, edi", "mov ecx, esi", "add al, cl", "movzx eax, al", "ret"]),
        ("n_sub8", ["mov eax, edi", "mov ecx, esi", "sub al, cl", "movzx eax, al", "ret"]),
        ("n_add16", ["mov eax, edi", "mov ecx, esi", "add ax, cx", "movzx eax, ax", "ret"]),
        ("n_sub16", ["mov eax, edi", "mov ecx, esi", "sub ax, cx", "movzx eax, ax", "ret"]),
        ("n_imul16", ["mov eax, edi", "mov ecx, esi", "imul ax, cx", "movzx eax, ax", "ret"]),
        ("n_not8", ["mov eax, edi", "not al", "movzx eax, al", "ret"]),
        ("n_neg8", ["mov eax, edi", "neg al", "movzx eax, al", "ret"]),
        ("n_not16", ["mov eax, edi", "not ax", "movzx eax, ax", "ret"]),
        ("n_neg16", ["mov eax, edi", "neg ax", "movzx eax, ax", "ret"]),
        # 链式窄算术：只在最外层截回，中间不重复转换（模 2^8 下可结合）。
        ("n_chain8", ["mov eax, edi", "mov ecx, esi", "add al, cl", "add al, cl", "imul al, cl", "movzx eax, al", "ret"]),
        # 窄结果被更宽的上下文消费：扩展、比较、右移、存入更宽变量——都必须先回绕。
        ("n_add8_zext", ["mov eax, edi", "mov ecx, esi", "add al, cl", "movzx eax, al", "add eax, 1", "ret"]),
        ("n_neg8_cmp", ["mov eax, edi", "neg al", "cmp al, 5", "seta al", "movzx eax, al", "ret"]),
        ("n_add8_shr", ["mov eax, edi", "mov ecx, esi", "add al, cl", "shr al, 2", "movzx eax, al", "ret"]),
        ("n_sub8_wide", ["mov eax, edi", "mov ecx, esi", "sub al, cl", "movzx rax, al", "ret"]),
    ]


class NarrowWidthTruncationTests(unittest.TestCase):
    """8/16 位 add/sub/mul/not/neg 截回原宽度：可读 C（UBSan，-O0 与 -O2）与微码逐条执行逐一相同。"""

    def test_narrow_leaf_functions_match_microcode_at_boundaries(self):
        _compiler()
        items, seed = [], 500
        for name, texts in _narrow_cases():
            function = fn(*_rows("x86_64", texts), name=name, pseudoc_context={"kind": "elf"})
            output = generate_pseudoc(function, "x86_64", style="readable")
            with self.subTest(name=name):
                self.assertTrue(output.reconstruction.get("complete"), output.pseudoc)
                self.assertNotRegex(output.pseudoc, r"unknown_value|unresolved_")
                # 结果确实做了截回：出现 (uint8_t)/(uint16_t) 的回绕转换。
                self.assertRegex(output.pseudoc, r"\(uint(?:8|16)_t\)\(")
                seed += 1
                items.append(_leaf_case(name, "x86_64", output, function, seed))
        program = _leaf_program(items)
        expected = [value for item in items for value in item["expected"]]
        for opt in ("-O0", "-O2"):
            with self.subTest(opt=opt):
                observed = [int(line, 16) for line in _run_c(program, opt)]
                self.assertEqual(observed, expected)

    def test_overflowing_byte_add_wraps_instead_of_leaking_high_bits(self):
        # add al, cl 的结果并入 rax 低 8 位：高位必须保持不变（回归点）。
        text = _readable("x86_64", ["mov rax, rdi", "mov rcx, rsi", "add al, cl", "ret"])
        self.assertIn("(uint8_t)((uint32_t)(uint8_t)arg_1 + (uint32_t)(uint8_t)arg_2)", text)
        program = (pseudoc_prelude() + "\n#include <stdio.h>\n"
                   "static uint64_t f(uint64_t arg_1, uint64_t arg_2) {\n    return "
                   + text.split("return ", 1)[1].split(";", 1)[0] + ";\n}\n"
                   "int main(void){\n"
                   "    unsigned long long cases[][2] = {{0xff00ull|0xff, 0x1}, {0x12ff, 0x1}, {0xabcdef80, 0x90}};\n"
                   "    for (unsigned i=0;i<3;i++){ unsigned long long a=cases[i][0],b=cases[i][1];\n"
                   "        unsigned long long got=f(a,b), want=(a & ~0xffull) | ((a + b) & 0xff);\n"
                   "        printf(\"%d\\n\", got == want); }\n    return 0;\n}\n")
        self.assertEqual(_run_c(program), ["1", "1", "1"])


# ---------------------------------------------------------------------------
# 1b. 带符号类型的窄值零扩展（渲染与 evaluate 逐一相同）
# ---------------------------------------------------------------------------

class SignedZeroExtensionTests(unittest.TestCase):
    """带符号类型的值零扩展到更宽类型：C 的转换会做符号扩展，渲染必须先转为同宽度无符号类型。"""

    def test_zero_extension_of_signed_values_matches_evaluate(self):
        _compiler()
        b0, h0, x0 = _reg("b0", 8), _reg("h0", 16), _reg("x0")
        low32 = _op("truncate", 32, x0)
        cases = {
            "z64_s16_s8": _op("zext", 64, _op("sext", 16, b0)),
            "z64_s8": _op("zext", 64, _op("sext", 32, b0)),
            "z64_s32_h": _op("zext", 64, _op("sext", 32, h0)),
            "z32_s16": _op("zext", 64, _op("zext", 32, _op("sext", 16, b0))),
            # 两臂符号不同的条件选择再零扩展（C 的 ?: 按通常算术转换，带符号臂可能为负）。
            "sel_mixed": _op("zext", 64, _op("select", 16, _op("truncate", 8, x0), _op("sext", 16, b0), h0)),
            "sel_signed": _op("zext", 64, _op("select", 32, _op("truncate", 8, x0), _op("sext", 32, b0), _op("sext", 32, h0))),
            # 64 位模式写 32 位寄存器（清零高位）的值来自带符号运算。
            "z64_s32_low": _op("zext", 64, _op("sext", 32, _op("truncate", 16, low32))),
        }
        values = (0, 1, 0x7f, 0x80, 0xff, 0x7fff, 0x8000, 0xffff, 0x12345, 0x7fffffff, 0x80000000, 0xffffffffffff8081)
        rows = [(a, a ^ 1, a & 0xffff, a & 0xff, 0) for a in values]
        items, expected = [], []
        for name, expression in cases.items():
            items.append((name, _render_expression(expression), rows))
            names = [item[0] for item in _EXPRESSION_VARIABLES]
            expected.extend(evaluate_expression(expression, dict(zip(names, row))) for row in rows)
        from tests.test_pseudoc_compilable import _expression_program
        program = _expression_program(items)
        for opt in ("-O0", "-O2"):
            with self.subTest(opt=opt):
                _assert_same_values(self, [int(line, 16) for line in _run_c(program, opt)], expected)

    def test_conditional_move_with_signed_arms_is_zero_extended(self):
        # lower 还原条件移动（微码 select 操作，写 32 位寄存器清零高位）时两臂可能是带符号类型的值：C 的 ?: 结果为
        # 负的 int32_t，再扩展到 64 位会被符号扩展。合成微码：cmovs eax, esi 的两臂换成 sext(16→32)，其后读完整 rax。
        _compiler()
        function = fn(*_rows("x86_64", ["mov eax, edi", "test edx, edx", "cmovs eax, esi", "shr rax, 16", "ret"]),
                      name="cmov_signed_arms", pseudoc_context={"kind": "elf"})
        records = lift_function(function, "x86_64")["instructions"]
        select = records[2]["operations"][0]
        self.assertEqual(select["opcode"], "select")

        def signed_half(root):
            return _op("sext", 32, _op("extract", 16, _reg(root), value=0))
        select["inputs"] = [signed_half("rsi"), signed_half("rax")]
        result = reconstruct_function(function, "x86_64", microcode=records)
        self.assertNotRegex(result.pseudoc, r"\? \(int32_t\)|: \(int32_t\)")
        output = SimpleNamespace(pseudoc=result.pseudoc, reconstruction=result.reconstruction, microcode=records)
        item = _leaf_case("cmov_signed_arms", "x86_64", output, function, 77)
        program = _leaf_program([item])
        for opt in ("-O0", "-O2"):
            with self.subTest(opt=opt):
                _assert_same_values(self, [int(line, 16) for line in _run_c(program, opt)], item["expected"])


# ---------------------------------------------------------------------------
# 2b. 流水线级：x86 宽乘/宽除写回完整 rax/rdx、MUL/IMUL 的 CF/OF——参考模型与真实 CPU
# ---------------------------------------------------------------------------

_MASK64 = (1 << 64) - 1
_WIDE_SOURCE = {8: "cl", 16: "cx", 32: "ecx", 64: "rcx"}
_WIDE_MEMORY = {8: "byte ptr [rcx]", 16: "word ptr [rcx]", 32: "dword ptr [rcx]", 64: "qword ptr [rcx]"}


def _sx(value, width):
    value &= (1 << width) - 1
    return value - (1 << width) if value >> (width - 1) else value


def _x86_wide(op, width, rax, rdx, source):
    """按 Intel SDM 执行单操作数 MUL/IMUL/DIV/IDIV：返回 (rax, rdx, CF=OF)；#DE（除数为 0、商溢出）时返回 None。

    8 位：AX = AL * src，或 AL、AH = AX ÷ src 的商、余数（rdx 不变）；16 位写 AX、DX 的低 16 位（其余位保留）；
    32 位写 EAX、EDX 并清零高 32 位；64 位写 RAX、RDX。DIV/IDIV 之后标志未定义（记为 None）。不调用项目代码。"""
    mask = (1 << width) - 1
    source &= mask
    overflow = None
    if op in {"mul", "imul"}:
        low_input = rax & mask
        product = low_input * source if op == "mul" else _sx(low_input, width) * _sx(source, width)
        product &= (1 << 2 * width) - 1
        low, high = product & mask, product >> width
        overflow = high != 0 if op == "mul" else _sx(product, 2 * width) != _sx(low, width)
    else:
        dividend = rax & 0xffff if width == 8 else ((rdx & mask) << width) | (rax & mask)
        if source == 0:
            return None
        if op == "div":
            quotient, remainder = divmod(dividend, source)
            if quotient > mask:
                return None
        else:
            numerator, divisor = _sx(dividend, 2 * width), _sx(source, width)
            quotient = abs(numerator) // abs(divisor)
            if (numerator < 0) != (divisor < 0):
                quotient = -quotient
            remainder = numerator - quotient * divisor
            if not -(1 << (width - 1)) <= quotient < 1 << (width - 1):
                return None
        low, high = quotient & mask, remainder & mask
    if width == 8:
        rax = (rax & ~0xffff & _MASK64) | high << 8 | low
    elif width == 16:
        rax, rdx = (rax & ~0xffff & _MASK64) | low, (rdx & ~0xffff & _MASK64) | high
    else:
        rax, rdx = low, high
    return rax, rdx, overflow


def _signed_overflow(value, width):
    return not -(1 << (width - 1)) <= value < 1 << (width - 1)


def _x86_pipeline_cases():
    """[(名字, 指令序列, 参考 (a, b, c) -> 返回值或 None（#DE）, 是否要求完整 64 位返回)]：a/b/c 为 rdi/rsi/rdx 入参。

    宽运算先把 rax = a、rdx = b、rcx = c 就位（内存源时 c 是指针，所指单元的值为 c），执行后返回完整的 rax 或 rdx。"""
    cases = []
    for op in ("div", "idiv", "mul", "imul"):
        for width in (8, 16, 32, 64):
            for source in ("reg", "mem"):
                for result in ("rax", "rdx"):
                    operand = _WIDE_SOURCE[width] if source == "reg" else _WIDE_MEMORY[width]
                    texts = (["mov rax, rdi", "mov rcx, rdx", "mov rdx, rsi", f"{op} {operand}"]
                             + (["mov rax, rdx"] if result == "rdx" else []) + ["ret"])

                    def reference(a, b, c, op=op, width=width, index=0 if result == "rax" else 1):
                        out = _x86_wide(op, width, a, b, c)
                        return None if out is None else out[index]
                    cases.append((f"w_{op}{width}_{source}_{result}", texts, reference, True))
    # CF/OF：MUL/IMUL 之后的 seto/setc/setno/setnc。
    for op in ("mul", "imul"):
        for width in (8, 16, 32, 64):
            for code in ("o", "c", "no", "nc"):
                texts = ["mov rax, rdi", "mov rcx, rsi", f"{op} {_WIDE_SOURCE[width]}", f"set{code} al", "movzx eax, al", "ret"]

                def reference(a, b, c, op=op, width=width, code=code):
                    overflow = _x86_wide(op, width, a, c, b)[2]
                    return int(overflow if code in {"o", "c"} else not overflow)
                cases.append((f"f_{op}{width}_{code}", texts, reference, False))
    # 双/三操作数 IMUL：CF = OF = 带符号乘积超出 W 位。
    for width, text, immediate in ((64, "imul rax, rsi", None), (32, "imul eax, esi", None), (16, "imul ax, si", None),
                                   (32, "imul eax, esi, 1000", 1000), (16, "imul ax, si, 300", 300)):
        for code in ("o", "nc"):
            texts = ["mov rax, rdi", text, f"set{code} al", "movzx eax, al", "ret"]

            def reference(a, b, c, width=width, immediate=immediate, code=code):
                left = _sx(b, width) if immediate is not None else _sx(a, width)
                right = immediate if immediate is not None else _sx(b, width)
                overflow = _signed_overflow(left * right, width)
                return int(overflow if code == "o" else not overflow)
            cases.append((f"f_imul{width}_{'i' if immediate else 'r'}_{code}", texts, reference, False))
    # 带符号扩展的结果写 32 位寄存器（清零高位）后读完整 64 位；两臂都来自带符号扩展的条件移动。
    cases += [
        ("s_movsx32", ["movsx ecx, dx", "mov rax, rcx", "ret"], lambda a, b, c: _sx(c, 16) & 0xffffffff, True),
        ("s_movsx32b", ["mov eax, edi", "movsx eax, al", "add rax, rsi", "ret"],
         lambda a, b, c: ((_sx(a, 8) & 0xffffffff) + b) & _MASK64, True),
        ("s_cmov", ["movsx eax, di", "movsx ecx, si", "test edx, edx", "cmovs eax, ecx", "ret"],
         lambda a, b, c: (_sx(b, 16) if _sx(c, 32) < 0 else _sx(a, 16)) & 0xffffffff, False),
        # 商与余数都无人使用：#DE 仍必须发生（商的调用保留为语句）。
        ("t_div64_unused", ["mov rax, rdi", "mov rcx, rsi", "xor edx, edx", "div rcx", "mov eax, 7", "ret"],
         lambda a, b, c: None if b == 0 else 7, False),
        ("t_idiv32_unused", ["mov eax, edi", "cdq", "idiv esi", "mov eax, 7", "ret"],
         lambda a, b, c: None if b & 0xffffffff == 0 or (a & 0xffffffff, b & 0xffffffff) == (0x80000000, 0xffffffff)
         else 7, False),
        ("t_div8_unused", ["mov eax, edi", "mov ecx, esi", "div cl", "mov eax, 7", "ret"],
         lambda a, b, c: None if _x86_wide("div", 8, a, 0, b) is None else 7, False),
    ]
    return cases


_PIPELINE_VALUES = (0, 1, 2, 3, 7, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000, 0xffff, 0x7fffffff, 0x80000000, 0xffffffff,
                    0x7fffffffffffffff, 0x8000000000000000, 0xffffffffffffffff, 0x123456789abcdef0,
                    0xfedcba9876543210, 0xfffffffffffffff9)


def _pipeline_inputs():
    """共用输入表（a, b, c）：边界值的组合（含除数 0、-1、商溢出、乘积溢出）加固定种子的随机值。"""
    values = _PIPELINE_VALUES
    rows = [(a, b, c) for a in values for b in values[::3] for c in values[::2]]
    rng = random.Random(20261004)
    rows += [(rng.getrandbits(64), rng.getrandbits(64) >> rng.choice((0, 32, 48, 63)), rng.getrandbits(64))
             for _ in range(64)]
    return rows


_PIPELINE_BUILT = []


def _pipeline_functions():
    """流水线为每个用例生成的可读 C 与调用信息（缓存）：[(名字, 指令, 参考, 文本, 实参表达式, 指针单元类型, 返回位宽)]。"""
    if _PIPELINE_BUILT:
        return _PIPELINE_BUILT[0]
    built = []
    for name, texts, reference, full in _x86_pipeline_cases():
        output = generate_pseudoc(fn(*_rows("x86_64", texts), name=name, pseudoc_context={"kind": "elf"}),
                                  "x86_64", style="readable")
        text = output.pseudoc
        match = re.search(r"^(\S+)\s+" + name + r"\(([^)]*)\) \{$", text, re.M)
        assert match, text
        return_width = {"uint8_t": 8, "int8_t": 8, "uint16_t": 16, "int16_t": 16, "uint32_t": 32, "int32_t": 32,
                        "uint64_t": 64, "int64_t": 64}[match.group(1)]
        cell, arguments = None, []
        for item in output.reconstruction["parameters"]:
            root = item["storage"].split(":", 1)[-1]
            value = {"rdi": "a", "rsi": "b", "rdx": "c"}[root]
            if item["type"].endswith("*"):
                cell = item["type"][:-1].strip()
                arguments.append(f"&cell")
            else:
                arguments.append(value)
        built.append((name, texts, reference, full, output, ", ".join(arguments), cell, return_width))
    _PIPELINE_BUILT.append(built)
    return built


def _pipeline_program(functions, rows, hardware):
    """可读 C 函数（hardware 时另加执行同一指令序列的汇编函数）与逐行调用：陷入（__builtin_trap 的 SIGILL/SIGTRAP，
    真实 CPU #DE 的 SIGFPE）用 sigsetjmp 捕获。hardware 为假时打印每次调用的结果（T 表示陷入）；为真时在 C 中比对
    两者（结果按函数返回类型的宽度比较，陷入必须一致），打印不一致与统计。"""
    parts = ["#define _XOPEN_SOURCE 700", pseudoc_prelude(), "#include <setjmp.h>", "#include <signal.h>",
             "#include <stdio.h>"]
    parts.extend(output.pseudoc for _, _, _, _, output, _, _, _ in functions)
    table = ",\n".join("    {" + ", ".join(f"{value:#x}ULL" for value in row) + "}" for row in rows)
    parts.append(f"static const unsigned long long fangida_inputs[][3] = {{\n{table}\n}};")
    parts.append("static sigjmp_buf fangida_env;\n"
                 "static void fangida_on_trap(int s) { (void)s; siglongjmp(fangida_env, 1); }\n"
                 "static long fangida_ok, fangida_fails;")
    calls = []
    for name, texts, _, _, _, arguments, cell, return_width in functions:
        mask = f"{(1 << return_width) - 1:#x}ULL"
        setup = f"{cell} cell = ({cell})c; " if cell else ""
        pseudo = f"{{ {setup}result = (uint64_t){name}({arguments}); }}"
        if not hardware:
            parts.append(
                f"static void run_{name}(void) {{\n"
                f"    for (unsigned i = 0; i < sizeof fangida_inputs / sizeof *fangida_inputs; i++) {{\n"
                f"        uint64_t a = fangida_inputs[i][0], b = fangida_inputs[i][1], c = fangida_inputs[i][2];\n"
                f"        volatile uint64_t result = 0;\n"
                f"        (void)a; (void)b; (void)c;\n"
                f"        if (sigsetjmp(fangida_env, 1)) {{ printf(\"T\\n\"); continue; }}\n"
                f"        {pseudo}\n"
                f"        printf(\"%llx\\n\", (unsigned long long)(result & {mask}));\n"
                f"    }}\n}}")
        else:
            body = "\\n".join(texts)
            parts.append(f'__asm__(".text\\n.p2align 4\\n.intel_syntax noprefix\\n.globl fangida_hw_{name}\\n'
                         f'fangida_hw_{name}:\\n{body}\\n.att_syntax prefix\\n");\n'
                         f'extern uint64_t fangida_hw_{name}(uint64_t, uint64_t, uint64_t) __asm__("fangida_hw_{name}");')
            hw_argument = "(uint64_t)(uintptr_t)&cell" if cell else "c"
            parts.append(
                f"static void run_{name}(void) {{\n"
                f"    for (unsigned i = 0; i < sizeof fangida_inputs / sizeof *fangida_inputs; i++) {{\n"
                f"        uint64_t a = fangida_inputs[i][0], b = fangida_inputs[i][1], c = fangida_inputs[i][2];\n"
                f"        volatile uint64_t result = 0, hw = 0; volatile int ht = 0, pt = 0;\n"
                f"        (void)a; (void)b; (void)c;\n"
                f"        if (sigsetjmp(fangida_env, 1)) ht = 1; else {{ {setup}hw = fangida_hw_{name}(a, b, {hw_argument}); }}\n"
                f"        if (sigsetjmp(fangida_env, 1)) pt = 1; else {pseudo}\n"
                f"        if (ht != pt || (!ht && ((hw ^ result) & {mask}))) {{ fangida_fails++;\n"
                f"            if (fangida_fails < 20) printf(\"MISMATCH {name} a=%llx b=%llx c=%llx hw=%llx/%d pc=%llx/%d\\n\",\n"
                f"                (unsigned long long)a, (unsigned long long)b, (unsigned long long)c,\n"
                f"                (unsigned long long)(hw & {mask}), ht, (unsigned long long)(result & {mask}), pt); }}\n"
                f"        else fangida_ok++;\n"
                f"    }}\n}}")
        calls.append(f"    run_{name}();")
    parts.append("int main(void) {\n    setvbuf(stdout, NULL, _IONBF, 0);\n"
                 "    signal(SIGILL, fangida_on_trap); signal(SIGFPE, fangida_on_trap);\n"
                 "#ifdef SIGTRAP\n    signal(SIGTRAP, fangida_on_trap);\n#endif\n"
                 + "\n".join(calls) +
                 ("\n    printf(\"ok=%ld fails=%ld\\n\", fangida_ok, fangida_fails);" if hardware else "")
                 + "\n    return 0;\n}\n")
    return "\n".join(parts)


class X86PipelineSemanticsTests(unittest.TestCase):
    """流水线生成的可读 C（宽乘/宽除写回、MUL/IMUL 的 CF/OF、带符号扩展后清零高位）与参考模型、真实 CPU 逐一对照。"""

    def test_pipeline_renders_every_case_without_placeholders(self):
        for name, texts, _, full, output, _, cell, return_width in _pipeline_functions():
            with self.subTest(name=name):
                self.assertTrue(output.reconstruction.get("complete"), output.pseudoc)
                self.assertNotRegex(output.pseudoc, r"unknown_value|unresolved_")
                if full:
                    # 读完整 64 位 rax/rdx：写回时的零扩展/部分写保留都在比对范围内。
                    self.assertEqual(return_width, 64, output.pseudoc)
                if any("ptr [rcx]" in text for text in texts):
                    # 内存源：指令只读一次内存，可读 C 也只能读一次（快照到临时变量后两个结果共用）。
                    self.assertIsNotNone(cell, output.pseudoc)
                    self.assertEqual(len(re.findall(r"\barg_\d+\[0\]", output.pseudoc)), 1, output.pseudoc)

    def test_idiv32_results_are_zero_extended_into_rax_and_rdx(self):
        # 回归点：x86_idiv_quo_32/x86_idiv_rem_32 返回 int32_t，写 eax/edx 时机器清零高 32 位，不能被符号扩展。
        text = _readable("x86_64", ["mov eax, edi", "cdq", "idiv esi", "shr rax, 32", "ret"])
        self.assertNotRegex(text, r"\(uint64_t\)x86_idiv_(?:quo|rem)_32\(")

    def test_pipeline_matches_reference_model(self):
        functions, rows = _pipeline_functions(), _pipeline_inputs()
        expected = []
        for _, _, reference, _, _, _, _, return_width in functions:
            mask = (1 << return_width) - 1
            for a, b, c in rows:
                value = reference(a, b, c)
                expected.append("T" if value is None else f"{value & mask:x}")
        program = _pipeline_program(functions, rows, hardware=False)
        for opt in ("-O0", "-O2"):
            with self.subTest(opt=opt):
                observed = _run_c(program, opt)
                _assert_same_values(self, observed, expected,
                                    lambda index: (functions[index // len(rows)][0], rows[index % len(rows)]))
                self.assertIn("T", observed)  # 除数为 0 与商溢出确实陷入

    @slow("编译运行硬件对照")
    @unittest.skipUnless(_can_run_x86(), "需要能编译运行 x86-64（x86-64 本机或 Rosetta 2）")
    def test_pipeline_matches_hardware(self):
        functions, rows = _pipeline_functions(), _pipeline_inputs()
        program = _pipeline_program(functions, rows, hardware=True)
        for opt in ("-O0", "-O2"):
            with self.subTest(opt=opt):
                lines = [line for line in _run_x86_opt(program, opt) if line]
                self.assertTrue(lines and lines[-1].startswith("ok="), lines[-20:])
                self.assertEqual(lines[-1], f"ok={len(functions) * len(rows)} fails=0", lines[-20:])

    def test_multiply_branch_conditions_match_reference(self):
        # MUL/IMUL 之后的条件分支（jo/jno/jb/jae/jc/jnc，CF = OF = 乘积溢出）：跳转返回 2、否则返回 1，
        # 与参考模型逐值比对（UBSan，-O0 与 -O2）。修复前这些分支是 unresolved_condition。
        from tests.test_flag_sources import _case
        _compiler()
        specs = []
        for op in ("mul", "imul"):
            for width, setters in ((8, ["mov eax, edi", f"{op} sil"]), (16, ["mov eax, edi", f"{op} si"]),
                                   (32, ["mov eax, edi", f"{op} esi"]), (64, ["mov rax, rdi", f"{op} rsi"])):
                for branch in ("jo", "jno", "jb", "jae", "jc", "jnc"):
                    def taken(a, b, op=op, width=width, branch=branch):
                        overflow = _x86_wide(op, width, a, 0, b)[2]
                        return overflow if branch in {"jo", "jb", "jc"} else not overflow
                    specs.append((f"mb_{op}{width}_{branch}", setters, branch, taken))
        for width, setter, immediate in ((32, "imul edi, esi", None), (64, "imul rdi, rsi", None),
                                         (16, "imul di, si", None), (32, "imul eax, edi, 1000", 1000)):
            for branch in ("jo", "jnc"):
                def taken(a, b, width=width, immediate=immediate, branch=branch):
                    product = _sx(a, width) * (immediate if immediate is not None else _sx(b, width))
                    overflow = _signed_overflow(product, width)
                    return overflow if branch == "jo" else not overflow
                specs.append((f"mb_imul{width}_{'i' if immediate else 'r'}_{branch}", [setter], branch, taken))
        values = _PIPELINE_VALUES
        definitions, calls, expected = [], [], []
        for name, setters, branch, taken in specs:
            output = _case("x86_64", name, setters, branch)
            with self.subTest(name=name):
                self.assertNotIn("unresolved_condition", output.pseudoc, output.pseudoc)
                self.assertRegex(output.pseudoc, r"[us]mul_overflow_(?:8|16|32|64)\(")
            definitions.append(output.pseudoc)
            arguments = ", ".join({"rdi": "a", "rsi": "b"}[item["storage"].split(":", 1)[-1]]
                                  for item in output.reconstruction["parameters"])
            calls.append(f"        printf(\"%u\\n\", (unsigned){name}({arguments}));")
            expected.extend(2 if taken(a, b) else 1 for a in values for b in values)
        table = ", ".join(f"{value:#x}ULL" for value in values)
        program = (pseudoc_prelude() + "\n#include <stdio.h>\n" + "\n".join(definitions)
                   + f"\nstatic const unsigned long long values[] = {{{table}}};\n"
                   + "int main(void) {\n" + "\n".join(
                       "    for (unsigned i = 0; i < sizeof values / sizeof *values; i++)\n"
                       "    for (unsigned j = 0; j < sizeof values / sizeof *values; j++) {\n"
                       "        uint64_t a = values[i], b = values[j]; (void)a; (void)b;\n" + call + "\n    }"
                       for call in calls) + "\n    return 0;\n}\n")
        for opt in ("-O0", "-O2"):
            with self.subTest(opt=opt):
                _assert_same_values(self, [int(line) for line in _run_c(program, opt)], expected)


# ---------------------------------------------------------------------------
# 2. x86 DIV/IDIV 精确渲染，并与真实硬件对照（Rosetta）
# ---------------------------------------------------------------------------

_HARDWARE_DIVISION = r"""
typedef unsigned long long ull;
static sigjmp_buf g_env;
static void on_sig(int s){ (void)s; siglongjmp(g_env, 1); }
#define HWU(W,T,ASM) static int hwu##W(T hi,T lo,T d,T*q,T*r){ if(sigsetjmp(g_env,1)){return 1;} T qq,rr; \
    __asm__ volatile(ASM " %[d]":"=a"(qq),"=d"(rr):"a"(lo),"d"(hi),[d]"r"(d):"cc"); *q=qq;*r=rr; return 0; }
HWU(16,uint16_t,"divw") HWU(32,uint32_t,"divl") HWU(64,uint64_t,"divq")
static int hwu8(uint8_t hi,uint8_t lo,uint8_t d,uint8_t*q,uint8_t*r){ if(sigsetjmp(g_env,1)){return 1;} uint16_t ax=((uint16_t)hi<<8)|lo; __asm__ volatile("divb %[d]":"=a"(ax):"a"(ax),[d]"r"(d):"cc"); *q=(uint8_t)ax;*r=(uint8_t)(ax>>8); return 0;}
#define HWI(W,T,ASM) static int hwi##W(T hi,T lo,T d,T*q,T*r){ if(sigsetjmp(g_env,1)){return 1;} T qq,rr; \
    __asm__ volatile(ASM " %[d]":"=a"(qq),"=d"(rr):"a"(lo),"d"(hi),[d]"r"(d):"cc"); *q=qq;*r=rr; return 0; }
HWI(16,uint16_t,"idivw") HWI(32,uint32_t,"idivl") HWI(64,uint64_t,"idivq")
static int hwi8(uint8_t hi,uint8_t lo,uint8_t d,uint8_t*q,uint8_t*r){ if(sigsetjmp(g_env,1)){return 1;} uint16_t ax=((uint16_t)hi<<8)|lo; __asm__ volatile("idivb %[d]":"=a"(ax):"a"(ax),[d]"r"(d):"cc"); *q=(uint8_t)ax;*r=(uint8_t)(ax>>8); return 0;}
#define HELP(W,T) static int help_u##W(T hi,T lo,T d,T*q,T*r){ if(sigsetjmp(g_env,1))return 1; *q=x86_udiv_quo_##W(hi,lo,d); *r=x86_udiv_rem_##W(hi,lo,d); return 0;} \
                  static int help_i##W(T hi,T lo,T d,T*q,T*r){ if(sigsetjmp(g_env,1))return 1; *q=x86_idiv_quo_##W(hi,lo,d); *r=x86_idiv_rem_##W(hi,lo,d); return 0;}
HELP(8,uint8_t) HELP(16,uint16_t) HELP(32,uint32_t) HELP(64,uint64_t)
#define CHECK(W,T,SU) do{ T hq,hr,wq,wr; int ht=help_##SU##W((T)hi,(T)lo,(T)d,&hq,&hr); int wt=hw##SU##W((T)hi,(T)lo,(T)d,&wq,&wr); \
    int ok=(ht==wt)&&(ht||(hq==wq&&hr==wr)); if(!ok){ fails++; if(fails<8) printf("MISMATCH %s%d hi=%llx lo=%llx d=%llx ht=%d wt=%d hq=%llx hr=%llx wq=%llx wr=%llx\n", #SU, W, (ull)hi,(ull)lo,(ull)d, ht,wt,(ull)hq,(ull)hr,(ull)wq,(ull)wr);} else ok_count++; }while(0)
int main(void){
    signal(SIGILL,on_sig); signal(SIGFPE,on_sig);
#ifdef SIGTRAP
    signal(SIGTRAP,on_sig);
#endif
    int fails=0; long ok_count=0;
    ull vals[]={0,1,2,3,7,0x7f,0x80,0xff,0x7fff,0x8000,0xffff,0x7fffffff,0x80000000,0xffffffff,
                0x7fffffffffffffffULL,0x8000000000000000ULL,0xffffffffffffffffULL,0x123456789abcdefULL};
    int n=sizeof(vals)/sizeof(*vals);
    for(int i=0;i<n;i++)for(int j=0;j<n;j++)for(int k=0;k<n;k++){ ull hi=vals[i],lo=vals[j],d=vals[k];
        CHECK(8,uint8_t,u); CHECK(8,uint8_t,i); CHECK(16,uint16_t,u); CHECK(16,uint16_t,i);
        CHECK(32,uint32_t,u); CHECK(32,uint32_t,i); CHECK(64,uint64_t,u); CHECK(64,uint64_t,i); }
    printf("ok=%ld fails=%d\n", ok_count, fails);
    return fails?1:0; }
"""


class X86WideDivisionTests(unittest.TestCase):
    def test_divide_wide_renders_precise_helpers(self):
        for mnemonic, kind in (("div", "udiv"), ("idiv", "idiv")):
            for register, width in (("cl", 8), ("cx", 16), ("ecx", 32), ("rcx", 64)):
                setup = "mov rax, rdi" if width == 64 else ("mov eax, edi" if width == 32 else "mov eax, edi")
                text = _readable("x86_64", [setup, "mov rcx, rsi", f"{mnemonic} {register}", "ret"], name="d")
                with self.subTest(mnemonic=mnemonic, width=width):
                    self.assertNotIn("unresolved_operation", text)
                    self.assertRegex(text, rf"x86_{kind}_quo_{width}\(")

    @slow("编译运行硬件对照")
    @unittest.skipUnless(_can_run_x86(), "需要能编译运行 x86-64（Rosetta/交叉工具链）")
    def test_wide_division_helpers_match_hardware(self):
        source = ("#define _XOPEN_SOURCE 700\n" + pseudoc_prelude()
                  + "\n#include <signal.h>\n#include <setjmp.h>\n#include <stdio.h>\n" + _HARDWARE_DIVISION)
        for opt in ("-O0", "-O2"):
            with self.subTest(opt=opt):
                lines = [line for line in _run_x86_opt(source, opt) if line]
                self.assertTrue(lines and lines[-1].startswith("ok="), lines)
                self.assertIn("fails=0", lines[-1], lines)


# ---------------------------------------------------------------------------
# 3. 单操作数 MUL/IMUL：高半、低半与 CF/OF
# ---------------------------------------------------------------------------

_HARDWARE_MULTIPLY = r"""
typedef unsigned long long ull;
#define FHI_U(W,T,DT) static T fhi_u##W(T a,T b){ return (T)(((DT)a*(DT)b)>>W); }
#define FHI_I(W,T,DT,SDT,ST) static T fhi_i##W(T a,T b){ return (T)((DT)((SDT)(ST)a*(SDT)(ST)b)>>W); }
FHI_U(8,uint8_t,uint16_t) FHI_U(16,uint16_t,uint32_t) FHI_U(32,uint32_t,uint64_t) FHI_U(64,uint64_t,__uint128_t)
FHI_I(8,uint8_t,uint16_t,__int128_t,int8_t) FHI_I(16,uint16_t,uint32_t,__int128_t,int16_t) FHI_I(32,uint32_t,uint64_t,__int128_t,int32_t) FHI_I(64,uint64_t,__uint128_t,__int128_t,int64_t)
#define HWMUL(NAME,INSN,T,REGH) static unsigned NAME(T a,T b,T*hi,T*lo){ T h,l; ull fl; \
  __asm__ volatile(INSN " %[b]\n\tpushfq\n\tpopq %[fl]":"=a"(l),"="REGH(h),[fl]"=r"(fl):"a"(a),[b]"r"(b):"cc"); *hi=h;*lo=l; return (unsigned)(fl&1); }
static unsigned hwmulu8(uint8_t a,uint8_t b,uint8_t*hi,uint8_t*lo){ uint16_t ax; ull fl; __asm__ volatile("mulb %[b]\n\tpushfq\n\tpopq %[fl]":"=a"(ax),[fl]"=r"(fl):"a"(a),[b]"r"(b):"cc"); *lo=(uint8_t)ax;*hi=(uint8_t)(ax>>8); return (unsigned)(fl&1); }
static unsigned hwimul8(uint8_t a,uint8_t b,uint8_t*hi,uint8_t*lo){ uint16_t ax; ull fl; __asm__ volatile("imulb %[b]\n\tpushfq\n\tpopq %[fl]":"=a"(ax),[fl]"=r"(fl):"a"(a),[b]"r"(b):"cc"); *lo=(uint8_t)ax;*hi=(uint8_t)(ax>>8); return (unsigned)(fl&1); }
HWMUL(hwmulu16,"mulw",uint16_t,"d") HWMUL(hwmulu32,"mull",uint32_t,"d") HWMUL(hwmulu64,"mulq",uint64_t,"d")
HWMUL(hwimul16,"imulw",uint16_t,"d") HWMUL(hwimul32,"imull",uint32_t,"d") HWMUL(hwimul64,"imulq",uint64_t,"d")
#define CK(W,T,ST,DT) do{ T a=(T)x,b=(T)y, hi,lo; \
  unsigned ucf=hwmulu##W(a,b,&hi,&lo); T fhu=fhi_u##W(a,b); T flo=(T)((DT)a*(DT)b); \
    if(hi!=fhu||lo!=flo){fails++; if(fails<6)printf("u%d hilo a=%llx b=%llx hw=%llx/%llx f=%llx/%llx\n",W,(ull)a,(ull)b,(ull)hi,(ull)lo,(ull)fhu,(ull)flo);} \
    else if(ucf != (hi!=0) || ucf != (unsigned)umul_overflow_##W(a,b)){fails++; if(fails<6)printf("u%d CF a=%llx b=%llx cf=%u hi=%llx\n",W,(ull)a,(ull)b,ucf,(ull)hi);} else ok++; \
  unsigned icf=hwimul##W(a,b,&hi,&lo); T fhi=fhi_i##W(a,b); T sx=(T)((ST)((T)lo)>>(W-1)); \
    if(hi!=fhi||lo!=flo){fails++; if(fails<6)printf("i%d hi a=%llx b=%llx hw=%llx f=%llx\n",W,(ull)a,(ull)b,(ull)hi,(ull)fhi);} \
    else if(icf != (hi != sx) || icf != (unsigned)smul_overflow_##W(a,b)){fails++; if(fails<6)printf("i%d OF a=%llx b=%llx cf=%u hi=%llx sx=%llx\n",W,(ull)a,(ull)b,icf,(ull)hi,(ull)sx);} else ok++; }while(0)
int main(void){ long ok=0; int fails=0;
  ull vals[]={0,1,2,3,0x7f,0x80,0xff,0x7fff,0x8000,0xffff,0x12345,0x7fffffff,0x80000000,0xffffffff,
              0x7fffffffffffffffULL,0x8000000000000000ULL,0xffffffffffffffffULL,0xdeadbeefcafeULL};
  int n=sizeof(vals)/sizeof(*vals);
  for(int i=0;i<n;i++)for(int j=0;j<n;j++){ ull x=vals[i],y=vals[j];
    CK(8,uint8_t,int8_t,uint16_t); CK(16,uint16_t,int16_t,uint32_t); CK(32,uint32_t,int32_t,uint64_t); CK(64,uint64_t,int64_t,__uint128_t);}
  printf("ok=%ld fails=%d\n", ok, fails); return fails?1:0; }
"""


class X86WideMultiplyTests(unittest.TestCase):
    def test_multiply_wide_renders_precise_high_half(self):
        # 单操作数 mul/imul 不再是 unresolved_operation：高半（rdx）精确渲染为 2W 位乘积的高位。
        high_u = _readable("x86_64", ["mov rax, rdi", "mul rsi", "mov rax, rdx", "ret"], name="m")
        self.assertNotIn("unresolved_operation", high_u)
        self.assertIn("(uint64_t)(((__uint128_t)arg_1 * (__uint128_t)arg_2) >> 64)", high_u)
        high_s = _readable("x86_64", ["mov rax, rdi", "mov rcx, rsi", "imul rcx", "mov rax, rdx", "ret"], name="m")
        self.assertNotIn("unresolved_operation", high_s)
        self.assertIn("(__int128_t)(int64_t)arg_1 * (__int128_t)(int64_t)arg_2", high_s)

    @unittest.skipUnless(_can_run_x86(), "需要能编译运行 x86-64（Rosetta/交叉工具链）")
    def test_multiply_high_and_flags_match_hardware(self):
        source = pseudoc_prelude() + "\n#include <stdio.h>\n" + _HARDWARE_MULTIPLY
        for opt in ("-O0", "-O2"):
            with self.subTest(opt=opt):
                lines = [line for line in _run_x86_opt(source, opt) if line]
                self.assertTrue(lines and lines[-1].startswith("ok="), lines)
                self.assertIn("fails=0", lines[-1], lines)

    @unittest.skipUnless(_can_run_x86(), "需要能编译运行 x86-64（Rosetta/交叉工具链）")
    def test_pipeline_multiply_high_matches_hardware_every_width(self):
        # 流水线为每个宽度实际渲染的高半（含 8 位 AH 经 rax 拼接的复杂路径）与真实硬件 mul/imul 逐一对照。
        snippets = {
            "mh_u8": "mov eax, edi;mov ecx, esi;mul cl;movzx eax, ah;ret",
            "mh_i8": "mov eax, edi;mov ecx, esi;imul cl;movsx eax, ah;ret",
            "mh_u16": "mov eax, edi;mov ecx, esi;mul cx;movzx eax, dx;ret",
            "mh_i16": "mov eax, edi;mov ecx, esi;imul cx;movsx eax, dx;ret",
            "mh_u32": "mov eax, edi;mov ecx, esi;mul ecx;mov eax, edx;ret",
            "mh_i32": "mov eax, edi;mov ecx, esi;imul ecx;mov eax, edx;ret",
        }
        defs = []
        for name, text in snippets.items():
            out = generate_pseudoc(fn(*_rows("x86_64", text.split(";")), name=name, pseudoc_context={"kind": "elf"}),
                                   "x86_64", style="readable")
            self.assertNotIn("unresolved_operation", out.pseudoc)
            defs.append(out.pseudoc)
        program = (pseudoc_prelude() + "\n#include <stdio.h>\n" + "\n".join(defs) + r'''
typedef unsigned long long ull;
int main(void){ int fails=0; ull v[]={0,1,2,0x7f,0x80,0xff,0x1234,0x7fff,0x8000,0xffff,0x12345,0x7fffffff,0x80000000,0xffffffff,0xdeadbeef};
 for(int i=0;i<15;i++)for(int j=0;j<15;j++){ ull a=v[i],b=v[j];
  uint16_t ax; __asm__("mulb %2":"=a"(ax):"a"((uint8_t)a),"r"((uint8_t)b):"cc"); unsigned hu8=(ax>>8)&0xff;
  uint16_t axs; __asm__("imulb %2":"=a"(axs):"a"((uint8_t)a),"r"((uint8_t)b):"cc"); int hi8=(int8_t)(axs>>8);
  uint16_t h,l; __asm__("mulw %3":"=a"(l),"=d"(h):"a"((uint16_t)a),"r"((uint16_t)b):"cc");
  uint16_t hs,ls; __asm__("imulw %3":"=a"(ls),"=d"(hs):"a"((uint16_t)a),"r"((uint16_t)b):"cc");
  uint32_t h2,l2; __asm__("mull %3":"=a"(l2),"=d"(h2):"a"((uint32_t)a),"r"((uint32_t)b):"cc");
  uint32_t hs2,ls2; __asm__("imull %3":"=a"(ls2),"=d"(hs2):"a"((uint32_t)a),"r"((uint32_t)b):"cc");
  if((unsigned)mh_u8(a,b)!=hu8){fails++;} if((int)mh_i8(a,b)!=hi8){fails++;}
  if((unsigned)mh_u16(a,b)!=h){fails++;} if((int)mh_i16(a,b)!=(int16_t)hs){fails++;}
  if((uint32_t)mh_u32(a,b)!=h2){fails++;} if((uint32_t)mh_i32(a,b)!=hs2){fails++;} }
 printf("fails=%d\n", fails); return fails?1:0; }
''')
        for opt in ("-O0", "-O2"):
            with self.subTest(opt=opt):
                lines = [line for line in _run_x86_opt(program, opt) if line]
                self.assertEqual(lines[-1], "fails=0", lines)


def _run_x86_opt(source, opt):
    """为 x86-64 编译（x86-64 本机或 Rosetta 2，可用时开 UBSan）并运行，返回标准输出行。"""
    compiler = shutil.which("cc") or shutil.which("clang")
    with tempfile.TemporaryDirectory() as tmp:
        path, binary = Path(tmp) / "c.c", Path(tmp) / "c"
        path.write_text(source)
        built = subprocess.run([compiler, *_x86_target(), "-std=c11", opt, "-w", *_x86_sanitizer_flags(), str(path),
                                "-o", str(binary)], capture_output=True, text=True)
        if built.returncode:
            raise AssertionError(built.stderr[-4000:])
        ran = subprocess.run([str(binary)], capture_output=True, text=True, timeout=300)
        if ran.returncode:
            raise AssertionError(f"exit {ran.returncode}: {ran.stdout[-2000:]}{ran.stderr[-2000:]}")
        return ran.stdout.split("\n")


# ---------------------------------------------------------------------------
# 4. 通用 udiv/urem/sdiv/srem 的 division_semantics 声明
# ---------------------------------------------------------------------------

_DIVISION_WIDTHS = (8, 16, 32, 64, 128)
_DIVISION_OPS = ("udiv", "urem", "sdiv", "srem")


def _divisor_operand(name, width):
    """width 位的寄存器操作数（64 位寄存器截断或零扩展）。"""
    register = _reg(name)
    return register if width == 64 else _op("truncate" if width < 64 else "zext", width, register)


def _render_declared(expression, semantics=""):
    """与 lower 相同：Expressions.division_semantics 为所在操作声明的语义，再 lift 并渲染。"""
    from types import SimpleNamespace
    variables = {name: SimpleNamespace(name=name, width=width, ctype=ctype) for name, width, ctype in _EXPRESSION_VARIABLES}
    expressions = Expressions(variables, None, 64)
    expressions.division_semantics = semantics
    return format_value(expressions.lift(expression, 0))


class DivisionSemanticsDeclarationTests(unittest.TestCase):
    """通用 udiv/sdiv/urem/srem 的架构语义由提升器在操作属性 division_semantics 中声明（"arm_zero"/"x86_fault"），
    表达式 name 字段的逐节点声明优先：evaluate 与渲染在每个宽度都按声明一致执行；"x86_fault" 与不声明相同（陷入）。"""

    @staticmethod
    def _expr(op, width, left, right, semantics=""):
        node = {"opcode": op, "width": width, "args": [left, right]}
        if semantics:
            node["name"] = semantics
        return node

    def test_evaluate_follows_declared_semantics(self):
        for width in _DIVISION_WIDTHS:
            smin, minus_one, zero, hundred = (_const(1 << (width - 1), width), _const(-1, width), _const(0, width),
                                              _const(100, width))
            for op in _DIVISION_OPS:
                dividend = smin if op.startswith("s") else hundred
                dividend_value = (1 << (width - 1)) if op.startswith("s") else 100
                with self.subTest(width=width, op=op):
                    # 默认（无声明）与 "x86_fault"：除以 0 求值为“未知”（渲染成会陷入的辅助函数）。
                    for kwargs, name in (({}, ""), ({"division_semantics": "x86_fault"}, ""), ({}, "x86_fault")):
                        with self.assertRaises(UnknownValue):
                            evaluate_expression(self._expr(op, width, dividend, zero, name), **kwargs)
                    # 声明 arm_zero（逐节点或操作级）：商为 0；余数为被除数（ARM 的 udiv/sdiv + msub）。
                    want = dividend_value if op.endswith("rem") else 0
                    self.assertEqual(evaluate_expression(self._expr(op, width, dividend, zero, "arm_zero")), want)
                    self.assertEqual(evaluate_expression(self._expr(op, width, dividend, zero),
                                                         division_semantics="arm_zero"), want)
                    # 逐节点声明优先于操作级声明。
                    with self.assertRaises(UnknownValue):
                        evaluate_expression(self._expr(op, width, dividend, zero, "x86_fault"), division_semantics="arm_zero")
            # 最小负数 / -1：ARM 得最小负数、取余得 0；默认与 x86_fault 溢出（未知）。
            self.assertEqual(evaluate_expression(self._expr("sdiv", width, smin, minus_one), division_semantics="arm_zero"),
                             1 << (width - 1))
            self.assertEqual(evaluate_expression(self._expr("srem", width, smin, minus_one), division_semantics="arm_zero"), 0)
            for kwargs in ({}, {"division_semantics": "x86_fault"}):
                with self.assertRaises(UnknownValue):
                    evaluate_expression(self._expr("sdiv", width, smin, minus_one), **kwargs)

    def test_rendering_follows_declared_semantics(self):
        for width in _DIVISION_WIDTHS:
            left, right = _divisor_operand("x0", width), _divisor_operand("x1", width)
            for op in _DIVISION_OPS:
                with self.subTest(width=width, op=op):
                    expression = self._expr(op, width, left, right)
                    arm = _render_declared(expression, "arm_zero")
                    self.assertIn(f"arm_{op}_{width}(", arm)
                    self.assertEqual(_render_expression(self._expr(op, width, left, right, "arm_zero")), arm)
                    for text in (_render_declared(expression, "x86_fault"), _render_declared(expression),
                                 _render_declared(self._expr(op, width, left, right, "x86_fault"), "arm_zero")):
                        self.assertRegex(text, rf"(?<!arm_){op}_{width}\(")
                        self.assertNotIn("arm_", text)
                    # 除数是可证明安全的非零常数时各语义相同：直接写 C 运算符。
                    constant = self._expr(op, width, left, _const(7, width))
                    self.assertNotRegex(_render_declared(constant, "arm_zero"), r"\w+_\d+\(")

    def test_arm_zero_rendering_matches_evaluate_every_width(self):
        _compiler()
        from tests.test_pseudoc_compilable import _expression_program
        names = [item[0] for item in _EXPRESSION_VARIABLES]
        values = (0, 1, 2, 7, 0x7f, 0x80, 0xff, 0x7fff, 0x8000, 0xffff, 0x7fffffff, 0x80000000, 0xffffffff,
                  0x7fffffffffffffff, 0x8000000000000000, 0xffffffffffffffff, 0xfffffffffffffff9)
        rows = [(a, b, 0, 0, 0) for a in values for b in values]
        items, expected = [], []
        for width in _DIVISION_WIDTHS:
            left, right = _divisor_operand("x0", width), _divisor_operand("x1", width)
            for op in _DIVISION_OPS:
                for declared in ("node", "operation"):
                    expression = self._expr(op, width, left, right, "arm_zero" if declared == "node" else "")
                    pieces = [expression] if width <= 64 else [_op("truncate", 64, expression),
                                                               _op("truncate", 64, _op("lshr", 128, expression, _const(64, 128)))]
                    for part, piece in enumerate(pieces):
                        wrapped = piece if piece["width"] == 64 else _op("zext", 64, piece)
                        text = _render_declared(wrapped, "" if declared == "node" else "arm_zero")
                        items.append((f"d_{op}{width}_{declared}_{part}", text, rows))
                        expected.extend(evaluate_expression(wrapped, dict(zip(names, row)), division_semantics="arm_zero")
                                        for row in rows)
        program = _expression_program(items)
        for opt in ("-O0", "-O2"):
            with self.subTest(opt=opt):
                _assert_same_values(self, [int(line, 16) for line in _run_c(program, opt)], expected)

    def test_trapping_semantics_trap_on_zero_and_overflow(self):
        # "x86_fault" 与不声明：除数为 0、带符号最小负数 / -1 时 __builtin_trap()（与 evaluate 的“未知”一致）。
        _compiler()
        definitions, calls, want = [], [], []
        for width in (8, 16, 32, 64):
            left, right = _divisor_operand("x0", width), _divisor_operand("x1", width)
            for op in _DIVISION_OPS:
                for semantics in ("", "x86_fault"):
                    name = f"t_{op}{width}_{semantics or 'none'}"
                    text = _render_declared(_op("zext", 64, self._expr(op, width, left, right)) if width < 64
                                            else self._expr(op, width, left, right), semantics)
                    definitions.append(f"static uint64_t {name}(uint64_t x0, uint64_t x1) {{ return (uint64_t)({text}); }}")
                    smin = 1 << (width - 1)
                    for a, b, traps in ((100, 0, True), (100, 7, False), (smin, (1 << width) - 1, op.startswith("s")),
                                        (smin, 3, False)):
                        calls.append(f"{name}({a:#x}ULL, {b:#x}ULL)")
                        want.append(_TRAPPED if traps else 0)
        source = pseudoc_prelude() + "\n" + "\n".join(definitions)
        self.assertEqual(_trap_statuses(source, calls), want)

    @staticmethod
    def _lifted_generic(texts, semantics, width=None):
        """AArch64 udiv/sdiv 提升后把专用 arm_* 改成通用 udiv/sdiv，并按“提升器”的方式在操作属性中声明语义；
        width 给出时改写为该宽度的通用除法（操作数截断、结果零扩展），检验 8/16 位经 lower 的渲染。"""
        function = fn(*_rows("arm64", texts), name="g", pseudoc_context={"kind": "elf"})
        records = lift_function(function, "arm64")["instructions"]
        for operation in records[0]["operations"]:
            expression = operation.get("expression")
            if not expression or not expression["opcode"].startswith("arm_"):
                continue
            generic = {**expression, "opcode": expression["opcode"].removeprefix("arm_")}
            if width is not None:
                generic = _op("zext", expression["width"],
                              {"opcode": generic["opcode"], "width": width,
                               "args": [_op("truncate", width, arg) for arg in expression["args"]]})
            operation["expression"] = generic
            operation["inputs"] = [generic]
            if semantics:
                operation.setdefault("attributes", {})["division_semantics"] = semantics
        return function, records

    def test_declared_semantics_flow_through_lowering(self):
        _compiler()
        program_parts, expected, calls = [pseudoc_prelude(), "#include <stdio.h>"], [], []
        trap_definitions, trap_calls, trap_want = [], [], []
        values = (0, 1, 7, 0x7f, 0x80, 0xff, 0x8000, 0xffff, 0x7fffffff, 0x80000000, 0xffffffff, 0xfffffff9,
                  0x7fffffffffffffff, 0x8000000000000000, 0xffffffffffffffff)
        for index, (texts, width) in enumerate(((["udiv w0, w0, w1", "ret"], None), (["sdiv x0, x0, x1", "ret"], None),
                                                (["sdiv w0, w0, w1", "ret"], 16), (["udiv w0, w0, w1", "ret"], 8))):
            for semantics in ("arm_zero", "x86_fault", ""):
                function, records = self._lifted_generic(texts, semantics, width)
                text = reconstruct_function(function, "arm64", microcode=records).pseudoc
                expression = records[0]["operations"][0]["expression"]
                op = texts[0].split()[0]
                effective = width or expression["width"]
                name = f"l{index}_{semantics or 'none'}"
                text = text.replace(" g(", f" {name}(", 1)
                with self.subTest(texts=texts, width=width, semantics=semantics):
                    if semantics == "arm_zero":
                        self.assertIn(f"arm_{op}_{effective}(", text)
                    else:
                        self.assertRegex(text, rf"(?<!arm_){op}_{effective}\(")
                        self.assertNotIn("arm_", text)
                if semantics == "arm_zero":
                    program_parts.append(text)
                    for a in values:
                        for b in values:
                            narrow = "(uint32_t)" if "w0" in texts[0] else ""
                            calls.append(f"    printf(\"%llx\\n\", (unsigned long long){narrow}{name}({a:#x}ULL, {b:#x}ULL));")
                            want = evaluate_expression(expression, {"x0": a, "x1": b}, division_semantics=semantics)
                            expected.append(want & 0xffffffff if narrow else want)
                else:
                    trap_definitions.append(text)
                    for a, b, traps in ((100, 0, True), (100, 7, False)):
                        trap_calls.append(f"{name}({a}U, {b}U)")
                        trap_want.append(_TRAPPED if traps else 0)
        program = "\n".join(program_parts) + "\nint main(void) {\n" + "\n".join(calls) + "\n    return 0;\n}\n"
        _assert_same_values(self, [int(line, 16) for line in _run_c(program)], expected)
        self.assertEqual(_trap_statuses(pseudoc_prelude() + "\n" + "\n".join(trap_definitions), trap_calls), trap_want)

    def test_microcode_analysis_follows_declared_semantics(self):
        # 微码分析（analyze_microcode 的常量事实）按所在操作声明的语义求值：赋值的表达式与比较的输入都一样。
        # 声明 "arm_zero" 时 100 / 0 = 0（可证明常量）；"x86_fault" 与不声明时除以 0 陷入，没有常量事实。
        function = fn(*_rows("arm64", ["mov w0, #100", "mov w1, #0", "udiv w2, w0, w1", "cmp w0, w1", "cset w3, eq",
                                       "ret"]), name="g", pseudoc_context={"kind": "elf"})
        lifted = lift_function(function, "arm64")["instructions"]
        for semantics in ("arm_zero", "x86_fault", ""):
            records = copy.deepcopy(lifted)
            divide, compare = records[2]["operations"][0], records[3]["operations"][0]
            generic = {**divide["expression"], "opcode": "udiv"}
            divide["expression"], divide["inputs"] = generic, [generic]
            # 比较的左操作数换成同一个通用除法（cmp (w0 / w1), #0 的形式），检验比较输入的求值。
            compare["inputs"] = [{**generic}, {"opcode": "constant", "width": 32, "value": 0}]
            if semantics:
                for operation in (divide, compare):
                    operation.setdefault("attributes", {})["division_semantics"] = semantics
            facts = analyze_microcode(records)["facts"]
            values = {fact["output"]: fact["value"] for fact in facts if fact["kind"] == "constant_assignment"}
            with self.subTest(semantics=semantics):
                if semantics == "arm_zero":
                    self.assertEqual((values.get("x2"), values.get("x3")), (0, 1))
                else:
                    self.assertNotIn("x2", values)
                    self.assertNotIn("x3", values)

    @unittest.skipUnless(platform.machine().lower() in {"arm64", "aarch64"} and shutil.which("cc"), "需要 AArch64 本机")
    def test_arm_helpers_match_hardware(self):
        # 前导的 arm_udiv/arm_sdiv 与 AArch64 UDIV/SDIV、arm_urem/arm_srem 与编译器的 udiv/sdiv + msub 序列在真实 CPU
        # 上逐一相同（除数为 0、最小负数 / -1）。
        program = pseudoc_prelude() + r"""
#include <stdio.h>
#define HW(W, R, T) \
static T hw_udiv##W(T a, T b) { T q; __asm__("udiv %" R "0, %" R "1, %" R "2" : "=r"(q) : "r"(a), "r"(b)); return q; } \
static T hw_sdiv##W(T a, T b) { T q; __asm__("sdiv %" R "0, %" R "1, %" R "2" : "=r"(q) : "r"(a), "r"(b)); return q; } \
static T hw_urem##W(T a, T b) { T q, r; __asm__("udiv %" R "0, %" R "2, %" R "3\n\tmsub %" R "1, %" R "0, %" R "3, %" R "2" \
    : "=&r"(q), "=r"(r) : "r"(a), "r"(b)); return r; } \
static T hw_srem##W(T a, T b) { T q, r; __asm__("sdiv %" R "0, %" R "2, %" R "3\n\tmsub %" R "1, %" R "0, %" R "3, %" R "2" \
    : "=&r"(q), "=r"(r) : "r"(a), "r"(b)); return r; }
HW(32, "w", uint32_t)
HW(64, "x", uint64_t)
int main(void) {
    unsigned long long v[] = {0, 1, 2, 3, 7, 0x7f, 0x80, 0xffff, 0x7fffffff, 0x80000000, 0xffffffff, 0xfffffff9,
                              0x7fffffffffffffffULL, 0x8000000000000000ULL, 0xffffffffffffffffULL, 0x123456789ULL};
    int n = sizeof v / sizeof *v, fails = 0;
    for (int i = 0; i < n; i++) for (int j = 0; j < n; j++) {
        uint32_t a = (uint32_t)v[i], b = (uint32_t)v[j]; uint64_t c = v[i], d = v[j];
        fails += arm_udiv_32(a, b) != hw_udiv32(a, b); fails += arm_sdiv_32(a, b) != hw_sdiv32(a, b);
        fails += arm_urem_32(a, b) != hw_urem32(a, b); fails += arm_srem_32(a, b) != hw_srem32(a, b);
        fails += arm_udiv_64(c, d) != hw_udiv64(c, d); fails += arm_sdiv_64(c, d) != hw_sdiv64(c, d);
        fails += arm_urem_64(c, d) != hw_urem64(c, d); fails += arm_srem_64(c, d) != hw_srem64(c, d);
    }
    printf("fails=%d\n", fails);
    return 0;
}
"""
        for opt in ("-O0", "-O2"):
            with self.subTest(opt=opt):
                self.assertEqual(_run_c(program, opt), ["fails=0"])


if __name__ == "__main__":
    unittest.main()
