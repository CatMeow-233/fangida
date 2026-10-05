"""可读伪 C 的前导（prelude）与可编译性：辅助函数语义、移位计数、占位声明与外部函数声明。

* 前导内容固定（哈希钉住）、与 PYTHONHASHSEED 无关，并能以 C11/C17/C2x 编译（-Wall -Wextra -Werror）；
* 每个可能渲染出的辅助名（{运算}_{W}、vec_*、pac*、x86_rep_*…）与占位名都在前导中有定义或声明；
* 前导里辅助函数的 C 定义与微码 evaluate 对随机与边界输入逐一相同（移位计数 0、W-1、W、W+1、0xff…）；
* 合成叶子函数（x86-64 / AArch64 / AArch32 的移位、循环移位、字节交换、除法）的可读 C 加前导编译运行，
  返回值与微码逐条执行（evaluate_expression + 条件标志）的结果逐一相同；
* 可读文本 + pseudoc_prelude(结果) 可以用 cc -fsyntax-only -std=c11 -Werror=implicit-function-declaration 编译；
* 微码表达式逐个渲染为 C 后编译运行，与 evaluate_expression 比对（计数上界、除法、窄位宽循环移位、归约实参…）。

编译运行时开启 UBSan（-fsanitize=undefined，编译器支持时），任何 C 未定义行为都会使测试失败。
本机没有 C 编译器时跳过编译与运行部分。
"""
from __future__ import annotations

import ast
import hashlib
import os
from pathlib import Path
import random
import re
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

from tests.test_lifter_gaps import _rows
from tests.test_pseudoc import function as fn, instruction as ins
from fangida.plugins.pseudoc import generate_pseudoc, pseudoc_prelude
from fangida.plugins.pseudoc.microcode import Expression, constant, evaluate_expression, lift_function
from fangida.plugins.pseudoc.microcode.conditions import evaluate_condition
from fangida.plugins.pseudoc.microcode.evaluate import UnknownValue, integer_flags, logic_flags
from fangida.plugins.pseudoc.microcode.lane_ops import LANE_OPCODES, PERMUTE_OPCODES, evaluate_lanes, evaluate_permute
from fangida.plugins.pseudoc.reconstruct import reconstruct_function
from fangida.plugins.pseudoc.reconstruct import prelude as prelude_module
from fangida.plugins.pseudoc.reconstruct.expressions import Expressions, format_value

_ROOT = Path(__file__).resolve().parents[1]
_MASK64 = (1 << 64) - 1
# 前导文本的 SHA-256：改动前导内容（含注释）时必须同步更新此值与 docs/reconstruction.md。
_PRELUDE_SHA256 = "da6dcbb4eb1861aa3e43c4322386621ec539efb09ba40679275a88869f47c223"
_COMPILE_FLAGS = ("-fsyntax-only", "-std=c11", "-Werror=implicit-function-declaration", "-Werror=int-conversion")


def _compiler():
    compiler = shutil.which("cc")
    if compiler is None:
        raise unittest.SkipTest("需要 C 编译器")
    return compiler


def _syntax_check(source, *flags):
    """cc -fsyntax-only 检查一段 C 源码；返回编译器输出（失败时抛出断言并附源码）。"""
    compiler = _compiler()
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "check.c"
        path.write_text(source)
        checked = subprocess.run([compiler, *_COMPILE_FLAGS, *flags, str(path)], capture_output=True, text=True)
        if checked.returncode:
            raise AssertionError(checked.stderr[-4000:] + "\n" + source[-3000:])
        return checked.stderr


_SANITIZE = ("-fsanitize=undefined", "-fno-sanitize-recover=undefined")
_SANITIZER_SUPPORT = []


def _sanitizer_flags():
    """本机编译器支持 UBSan 时返回其选项：运行时出现 C 未定义行为（越界移位、除以 0、带符号溢出…）即报错退出。"""
    if not _SANITIZER_SUPPORT:
        compiler = _compiler()
        with tempfile.TemporaryDirectory() as tmp:
            path, binary = Path(tmp) / "probe.c", Path(tmp) / "probe"
            path.write_text("int main(void) { return 0; }\n")
            built = subprocess.run([compiler, *_SANITIZE, str(path), "-o", str(binary)], capture_output=True, text=True)
            supported = not built.returncode and not subprocess.run([str(binary)], capture_output=True).returncode
        _SANITIZER_SUPPORT.append(_SANITIZE if supported else ())
    return _SANITIZER_SUPPORT[0]


def _run_c(source, *flags):
    """编译并在本机运行（支持时开启 UBSan，出现 C 未定义行为即失败），返回标准输出行。"""
    compiler = _compiler()
    with tempfile.TemporaryDirectory() as tmp:
        path, binary = Path(tmp) / "check.c", Path(tmp) / "check"
        path.write_text(source)
        built = subprocess.run([compiler, "-std=c11", "-O1", "-w", *_sanitizer_flags(), *flags, str(path), "-o", str(binary)],
                               capture_output=True, text=True)
        if built.returncode:
            raise AssertionError(built.stderr[-4000:])
        ran = subprocess.run([str(binary)], capture_output=True, text=True, timeout=300)
        if ran.returncode:
            raise AssertionError(f"exit {ran.returncode}: {ran.stderr[-2000:]}")
        return ran.stdout.split()


def _c_constant(value, width):
    """width 位常量的 C 表达式（128 位用两个 64 位半拼出）。"""
    if width in (8, 16, 32, 64):
        return f"(uint{width}_t){value:#x}ULL"
    return f"(((__uint128_t){value >> 64:#x}ULL << 64) | {value & _MASK64:#x}ULL)"


_PRINT128 = ("static void print128(__uint128_t v) { printf(\"%016llx%016llx\\n\", (unsigned long long)(v >> 64), "
             "(unsigned long long)v); }\n")


def _program(lines):
    return pseudoc_prelude() + "\n#include <stdio.h>\n" + _PRINT128 + "int main(void) {\n" + "\n".join(lines) + "\n    return 0;\n}\n"


def _print(expression):
    return f"    print128((__uint128_t)({expression}));"


# 子进程因 __builtin_trap()（SIGILL/SIGTRAP）退出时的状态；正常返回为 0，其它信号为 1000 + 信号编号
# （UBSan 报错后 abort 是 SIGABRT，x86 上 C 的除以 0 是 SIGFPE）。
_TRAPPED = 42


def _trap_statuses(source, calls):
    """在 source（前导与函数定义）之后逐个调用 calls：每个调用在子进程中执行，返回各子进程的退出状态。

    用 fork 隔离陷入；子进程用信号处理函数把 SIGILL/SIGTRAP 转成 _exit(42)（不产生崩溃报告）。
    """
    cases = "\n".join(f"    case {index}: result = (uint64_t)({call}); break;" for index, call in enumerate(calls))
    program = ("#define _XOPEN_SOURCE 700\n" + source + "\n#include <signal.h>\n#include <stdio.h>\n#include <sys/wait.h>\n"
               "#include <unistd.h>\n"
               f"static void on_trap(int signal_number) {{ (void)signal_number; _exit({_TRAPPED}); }}\n"
               "static void trap_case(int index) {\n    volatile uint64_t result = 0;\n    switch (index) {\n" + cases +
               "\n    default: break;\n    }\n    (void)result;\n}\n"
               "int main(void) {\n"
               f"    for (int i = 0; i < {len(calls)}; i++) {{\n"
               "        fflush(stdout);\n"
               "        pid_t child = fork();\n"
               "        if (child == 0) {\n"
               "            signal(SIGILL, on_trap);\n"
               "#ifdef SIGTRAP\n            signal(SIGTRAP, on_trap);\n#endif\n"
               "            trap_case(i);\n            _exit(0);\n        }\n"
               "        int status = 0;\n        waitpid(child, &status, 0);\n"
               "        printf(\"%d\\n\", WIFEXITED(status) ? WEXITSTATUS(status) : 1000 + WTERMSIG(status));\n"
               "    }\n    return 0;\n}\n")
    return [int(line) for line in _run_c(program)]


# ---------------------------------------------------------------------------
# 微码表达式逐个渲染为 C（Expressions.lift + format_value），与 evaluate_expression 比对
# ---------------------------------------------------------------------------

# 寄存器变量：名字、宽度、C 类型（p0 是被推断为指针的寄存器，h0/b0 是窄类型的变量）。
_EXPRESSION_VARIABLES = (("x0", 64, "uint64_t"), ("x1", 64, "uint64_t"), ("h0", 16, "uint16_t"), ("b0", 8, "uint8_t"),
                         ("p0", 64, "uint32_t *"))


def _reg(name, width=64):
    return {"opcode": "register", "width": width, "name": name}


def _const(value, width):
    return {"opcode": "constant", "width": width, "value": value % (1 << width)}


def _op(opcode, width, *args, value=None):
    node = {"opcode": opcode, "width": width, "args": list(args)}
    if value is not None:
        node["value"] = value
    return node


def _render_expression(expression):
    variables = {name: SimpleNamespace(name=name, width=width, ctype=ctype) for name, width, ctype in _EXPRESSION_VARIABLES}
    return format_value(Expressions(variables, None, 64).lift(expression, 0))


def _expression_arguments(row):
    """一行输入写成表达式函数的实参（指针变量按地址值转换）。"""
    return ", ".join(f"({ctype})(uintptr_t){value:#x}ULL" if ctype.endswith("*") else f"({ctype}){value:#x}ULL"
                     for value, (_, _, ctype) in zip(row, _EXPRESSION_VARIABLES))


def _expression_program(items, prefix="", main=True):
    """items：[(函数名, 64 位表达式的 C 文本, 输入行)]。每个表达式写成一个以寄存器变量为参数的函数，逐行调用并打印；
    main 为假时只生成前导与函数定义（prefix 放在前导之后，如测试用的外部函数）。"""
    parameters = ", ".join(f"{ctype}{'' if ctype.endswith('*') else ' '}{name}" for name, _, ctype in _EXPRESSION_VARIABLES)
    parts, calls = [pseudoc_prelude(), prefix, "#include <stdio.h>"], []
    for name, text, rows in items:
        parts.append(f"static uint64_t {name}({parameters}) {{ return (uint64_t)({text}); }}")
        if not main:
            continue
        table = ",\n".join("    {" + ", ".join(f"{value:#x}ULL" for value in row) + "}" for row in rows)
        parts.append(f"static const unsigned long long inputs_{name}[][{len(_EXPRESSION_VARIABLES)}] = {{\n{table}\n}};")
        arguments = ", ".join(f"({ctype})(uintptr_t)inputs_{name}[i][{index}]" if ctype.endswith("*") else
                              f"({ctype})inputs_{name}[i][{index}]" for index, (_, _, ctype) in enumerate(_EXPRESSION_VARIABLES))
        calls.append(f"    for (unsigned i = 0; i < sizeof inputs_{name} / sizeof *inputs_{name}; i++)\n"
                     f"        printf(\"%llx\\n\", (unsigned long long){name}({arguments}));")
    if not main:
        return "\n".join(parts) + "\n"
    return "\n".join(parts) + "\nint main(void) {\n" + "\n".join(calls) + "\n    return 0;\n}\n"


def _branch_rows(architecture, texts):
    """_rows 并为跳转/调用补上分支信息（目标为操作数中的地址）。"""
    rows = _rows(architecture, texts)
    for row in rows:
        if row["mnemonic"] in {"jmp", "jne", "je", "b.eq"}:
            target = int(row["operands"][0], 0)
            row["branch_info"] = {"kind": "jump", "target": target, "conditional": row["mnemonic"] != "jmp"}
        if row["mnemonic"] == "call":
            row["branch_info"] = {"kind": "call", "target": int(row["operands"][0], 0), "conditional": False}
    return rows


# ---------------------------------------------------------------------------
# 微码逐条执行（测试用参考实现）：只支持叶子函数，内存只允许栈
# ---------------------------------------------------------------------------

_REGISTERS = {"x86_64": ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"),
              "arm64": tuple(f"x{i}" for i in range(31)), "arm": tuple(f"r{i}" for i in range(13)) + ("r14",)}
_STACK_POINTER = {"x86_64": "rsp", "arm64": "sp", "arm": "r13"}
_RETURN = {"x86_64": "rax", "arm64": "x0", "arm": "r0"}


class _Unsupported(Exception):
    pass


class _Machine:
    """寄存器、条件标志与栈内存；表达式交给 evaluate_expression 求值（load/address 先换成常量）。"""

    def __init__(self, architecture, registers):
        self.bits = 32 if architecture == "arm" else 64
        self.mask = (1 << self.bits) - 1
        self.sp = _STACK_POINTER[architecture]
        self.top = 0x7ffef0000000 if self.bits == 64 else 0x7ff00000
        self.registers = {**registers, self.sp: self.top}
        self.memory, self.flags = {}, {}
        if architecture == "x86_64":
            self.store(self.top, 0xdead0000, 64)  # 返回地址

    def _check(self, address, size):
        if not self.top - (1 << 20) <= address <= self.top + 64 - size:
            raise _Unsupported("non-stack memory")

    def store(self, address, value, width):
        self._check(address, width // 8)
        for index in range(width // 8):
            self.memory[address + index] = (value >> (8 * index)) & 0xff

    def load(self, address, width):
        self._check(address, width // 8)
        try:
            return sum(self.memory[address + index] << (8 * index) for index in range(width // 8))
        except KeyError as error:
            raise _Unsupported("uninitialized stack read") from error

    def address(self, text, registers=None):
        registers = self.registers if registers is None else registers

        def visit(node):
            if isinstance(node, ast.Name) and node.id in registers:
                return registers[node.id]
            if isinstance(node, ast.Constant) and type(node.value) is int:
                return node.value
            if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
                return -visit(node.operand)
            if isinstance(node, ast.BinOp) and type(node.op) in {ast.Add, ast.Sub, ast.Mult}:
                left, right = visit(node.left), visit(node.right)
                return left + right if isinstance(node.op, ast.Add) else left - right if isinstance(node.op, ast.Sub) else left * right
            raise _Unsupported("address")
        return visit(ast.parse(str(text), mode="eval").body) & self.mask

    def resolve(self, expression):
        opcode = expression.get("opcode")
        if opcode == "load":
            return {"opcode": "constant", "width": expression["width"],
                    "value": self.load(self.evaluate(expression["args"][0]), expression["width"])}
        if opcode == "address":
            return {"opcode": "constant", "width": expression["width"], "value": self.address(expression.get("name", ""))}
        if expression.get("args"):
            return {**expression, "args": [self.resolve(arg) for arg in expression["args"]]}
        return expression

    def evaluate(self, expression):
        values = dict(self.registers)
        values.update(("flags." + name, int(bool(known))) for name, known in self.flags.items() if known is not None)
        try:
            return int(evaluate_expression(self.resolve(expression), values))
        except UnknownValue as error:
            raise _Unsupported(str(error)) from error

    def write(self, operation, value):
        attributes = operation.get("attributes", {})
        width = attributes.get("destination_width", operation.get("width", 0))
        storage, shift = attributes.get("storage_width", width), attributes.get("bit_offset", 0)
        if attributes.get("zero_upper") or width >= storage and not shift:
            self.registers[operation["output"]] = value & ((1 << width) - 1)
        else:
            mask = ((1 << width) - 1) << shift
            self.registers[operation["output"]] = (self.registers[operation["output"]] & ~mask) | ((value << shift) & mask)

    def condition(self, predicate):
        if predicate.get("kind") in {"zero_test", "bit_test"}:
            source = self.evaluate(predicate["value"])
            if predicate["kind"] == "bit_test":
                source = source >> self.evaluate(predicate["bit"]) & 1
            return source == 0 if predicate["relation"] == "eq" else source != 0
        taken = evaluate_condition(predicate, flags=self.flags)
        if taken is None:
            raise _Unsupported("unknown flags")
        return taken


def run_microcode(records, entry, architecture, registers, max_steps=20000):
    """逐条执行微码到 return，返回返回寄存器的值。"""
    machine = _Machine(architecture, registers)
    rows = {row["addr"]: (index, row) for index, row in enumerate(records)}
    pc = entry
    for _ in range(max_steps):
        index, row = rows[pc]
        if not row.get("supported"):
            raise _Unsupported("opaque")
        snapshot = dict(machine.registers)
        next_pc = records[index + 1]["addr"] if index + 1 < len(records) else pc + row["size"]
        handled = False
        for operation in row["operations"]:
            opcode, attributes, inputs = operation["opcode"], operation.get("attributes", {}), operation.get("inputs", ())
            if opcode == "assign":
                machine.write(operation, machine.evaluate(operation["expression"]))
            elif opcode == "store":
                machine.store(machine.evaluate(inputs[0]), machine.evaluate(inputs[1]), operation["width"])
            elif opcode == "stack_push":
                value = machine.evaluate(inputs[0])
                machine.registers[machine.sp] = (machine.registers[machine.sp] + attributes["delta"]) & machine.mask
                machine.store(machine.registers[machine.sp], value, operation["width"])
            elif opcode == "stack_pop":
                value = machine.load(machine.registers[machine.sp], operation["width"])
                machine.registers[machine.sp] = (machine.registers[machine.sp] + attributes["delta"]) & machine.mask
                machine.registers[attributes["destination"]] = value
            elif opcode == "address_writeback":
                address = machine.address(attributes["address"], snapshot)
                if attributes.get("mode") == "post_index":
                    address += int(str(attributes["offset"]).lstrip("#"), 0)
                machine.registers[operation["output"]] = address & machine.mask
            elif opcode == "compare":
                handled = True
                left, right = (machine.evaluate(item) for item in inputs)
                machine.flags = integer_flags(attributes["flag_family"], "sub", left, right, operation["width"])
            elif opcode in {"flags_add", "flags_sub", "compare_add", "flags_logic", "test"} and not attributes.get("carry"):
                handled = True
                values = [machine.evaluate(item) for item in inputs]
                family = attributes.get("family", attributes.get("flag_family", "x86"))
                if opcode in {"flags_logic", "test"}:
                    result = values[0] if opcode == "flags_logic" else values[0] & values[1]
                    machine.flags = logic_flags(family, result, operation["width"], previous=machine.flags,
                                                arm32=row.get("architecture") == "arm")
                    if attributes.get("shifter_carry") == "unknown":
                        machine.flags["C"] = None
                else:
                    machine.flags = integer_flags(family, "sub" if opcode == "flags_sub" else "add", values[0], values[1],
                                                  operation["width"])
            elif opcode.startswith("flags_") or opcode in {"compare_add", "test"}:
                handled = True
                machine.flags = {}
            elif opcode in {"select", "set_condition"}:
                taken = machine.condition(attributes["condition"])
                if opcode == "set_condition":
                    value = attributes.get("true_value", 1) if taken else 0
                else:
                    value = machine.evaluate(inputs[0 if taken else 1])
                    action = attributes.get("false_operation") if not taken else None
                    value = value + 1 if action == "csinc" else ~value if action == "csinv" else -value if action == "csneg" else value
                machine.write(operation, value & ((1 << operation["width"]) - 1))
            elif opcode == "branch":
                if machine.condition(attributes["condition"]):
                    next_pc = attributes["target"]
                elif attributes.get("fallthrough") is not None:
                    next_pc = attributes["fallthrough"]
            elif opcode == "jump" and type(attributes.get("target")) is int:
                next_pc = attributes["target"]
            elif opcode == "return":
                return machine.registers[_RETURN[architecture]]
            elif opcode != "nop":
                raise _Unsupported(opcode)
        if row.get("flag_effect", "unknown") not in {"preserve", "partial_non_condition"} and not handled:
            machine.flags = {}
        pc = next_pc
    raise _Unsupported("step budget")


# ---------------------------------------------------------------------------
# 合成叶子函数
# ---------------------------------------------------------------------------

def _synthetic_cases():
    x86, a64, a32 = [], [], []
    for width, (a, c) in {32: ("eax", "ecx"), 64: ("rax", "rcx"), 16: ("ax", "cx"), 8: ("al", "cl")}.items():
        for mnemonic in ("shl", "shr", "sar", "rol", "ror"):
            x86.append((f"x86_{mnemonic}{width}_cl", ["mov rax, rdi", "mov rcx, rsi", f"{mnemonic} {a}, cl", "ret"]))
            for amount in (1, width - 1):
                x86.append((f"x86_{mnemonic}{width}_i{amount}", ["mov rax, rdi", f"{mnemonic} {a}, {amount}", "ret"]))
    x86 += [("x86_bswap32", ["mov eax, edi", "bswap eax", "ret"]), ("x86_bswap64", ["mov rax, rdi", "bswap rax", "ret"]),
            ("x86_mix", ["mov eax, edi", "mov ecx, esi", "sar eax, cl", "rol eax, 5", "ror eax, cl", "bswap eax", "ret"])]
    for register, width in (("w", 32), ("x", 64)):
        for mnemonic in ("lsl", "lsr", "asr", "ror"):
            a64.append((f"a64_{mnemonic}{width}_reg", [f"{mnemonic} {register}0, {register}0, {register}1", "ret"]))
            for amount in (1, width - 1):
                a64.append((f"a64_{mnemonic}{width}_i{amount}", [f"{mnemonic} {register}0, {register}0, #{amount}", "ret"]))
        for mnemonic in ("udiv", "sdiv"):
            a64.append((f"a64_{mnemonic}{width}", [f"{mnemonic} {register}0, {register}0, {register}1", "ret"]))
        a64.append((f"a64_rev{width}", [f"rev {register}0, {register}1", "ret"]))
        a64.append((f"a64_mix{width}", [f"asr {register}2, {register}0, {register}1", f"ror {register}3, {register}2, {register}1",
                                        f"rev {register}3, {register}3", f"add {register}0, {register}3, {register}2", "ret"]))
    a64.append(("a64_divmix", ["sdiv x2, x0, x1", "udiv w3, w0, w1", "add x0, x2, x3", "ret"]))
    for mnemonic in ("lsl", "lsr", "asr", "ror"):
        a32.append((f"a32_{mnemonic}_reg", [f"{mnemonic} r0, r0, r1", "bx lr"]))
    for mnemonic, amount in (("lsl", 31), ("lsr", 32), ("asr", 32), ("lsr", 1), ("asr", 31), ("ror", 5), ("lsl", 1)):
        a32.append((f"a32_{mnemonic}_i{amount}", [f"{mnemonic} r0, r0, #{amount}", "bx lr"]))
    a32 += [("a32_rev", ["rev r0, r0", "bx lr"]), ("a32_udiv", ["udiv r0, r0, r1", "bx lr"]),
            ("a32_sdiv", ["sdiv r0, r0, r1", "bx lr"]), ("a32_shift_chain", ["lsl r2, r0, r1", "lsr r3, r2, r1", "asr r0, r3, r1", "bx lr"])]
    return {"x86_64": x86, "arm64": a64, "arm": a32}


_BOUNDARY = (0, 1, 2, 3, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 0xfe, 0xff, 0x100, 0x101,
             0x7fff, 0x8000, 0xffff, 0x10000)
_SCALAR = re.compile(r"(u?)int(8|16|32|64)_t")


def _type_width(ctype):
    match = _SCALAR.fullmatch(ctype or "")
    return (int(match.group(2)), match.group(1) != "u") if match else None


def _extend(value, width, signed, bits):
    if signed and value >> (width - 1) & 1:
        value -= 1 << width
    return value & ((1 << bits) - 1)


def _inputs(widths, seed, count=48):
    """每个参数：边界值（含计数 0、W-1、W、W+1、0xff 等）、全 1、最高位与随机值的组合。"""
    rng = random.Random(seed)
    pools = []
    for width in widths:
        top = (1 << width) - 1
        pools.append((sorted({value & top for value in _BOUNDARY + (top, top - 1, top >> 1, (top >> 1) + 1,
                                                                     width - 1, width, width + 1)}), top))
    def pick(pool, top):
        return rng.choice(pool) if rng.random() < 0.6 else rng.getrandbits(top.bit_length()) & top
    rows = {tuple(pool[0] for pool, _ in pools), tuple(top for _, top in pools)}
    # 每个参数的每个边界值至少出现一次（其余参数取边界或随机值），保证计数覆盖 0、W-1、W、W+1、0xff 等。
    for position, (pool, _) in enumerate(pools):
        for value in pool:
            rows.add(tuple(value if index == position else pick(*item) for index, item in enumerate(pools)))
    while len(rows) < count:
        rows.add(tuple(pick(*item) for item in pools))
    return sorted(rows)


def _leaf_case(name, architecture, output, function, seed):
    """一个可比对的叶子函数：参数类型、输入与微码执行得到的期望返回值。"""
    report = output.reconstruction
    match = re.search(r"^(\S+)\s+" + name + r"\(([^)]*)\) \{$", output.pseudoc, re.M)
    returned = _type_width(match.group(1))
    parameters = [(item["name"], item["storage"].split(":", 1)[-1], item["type"]) for item in report["parameters"]]
    assert re.findall(r"\barg_\d+\b", match.group(2)) == [item[0] for item in parameters], output.pseudoc
    kinds = [_type_width(ctype) for _, _, ctype in parameters]
    bits = 32 if architecture == "arm" else 64
    rng = random.Random(seed + 1)
    garbage = {root: rng.getrandbits(bits) for root in _REGISTERS[architecture]}
    cases, expected = [], []
    for row in _inputs([width for width, _ in kinds], seed):
        state = dict(garbage)
        for (_, root, _), value, (width, signed) in zip(parameters, row, kinds):
            state[root] = _extend(value, width, signed, bits)
        result = run_microcode(list(output.microcode), function["start"], architecture, state)
        cases.append(row)
        expected.append(_extend(result & ((1 << returned[0]) - 1), returned[0], returned[1], 64))
    return {"name": name, "types": [ctype for _, _, ctype in parameters], "cases": cases, "expected": expected,
            "text": output.pseudoc}


def _leaf_program(items):
    """把多个叶子函数与各自的输入表放进一个程序：逐个调用并打印返回值。"""
    parts = [pseudoc_prelude(), "#include <stdio.h>"]
    calls = []
    for item in items:
        parts.append(item["text"])
        width = max(len(item["types"]), 1)
        rows = ",\n".join("    {" + (", ".join(f"{value:#x}ULL" for value in case) or "0") + "}" for case in item["cases"])
        parts.append(f"static const unsigned long long inputs_{item['name']}[][{width}] = {{\n{rows}\n}};")
        arguments = ", ".join(f"({ctype})inputs_{item['name']}[i][{index}]" for index, ctype in enumerate(item["types"]))
        calls.append(f"    for (unsigned i = 0; i < sizeof inputs_{item['name']} / sizeof *inputs_{item['name']}; i++)\n"
                     f"        printf(\"%llx\\n\", (unsigned long long)(uint64_t){item['name']}({arguments}));")
    return "\n".join(parts) + "\nint main(void) {\n" + "\n".join(calls) + "\n    return 0;\n}\n"


# ---------------------------------------------------------------------------
# 测试
# ---------------------------------------------------------------------------

class PreludeContentTests(unittest.TestCase):
    def test_prelude_is_fixed_and_pinned(self):
        text = pseudoc_prelude()
        self.assertEqual(text, prelude_module.prelude_text())
        self.assertEqual(text, pseudoc_prelude(None))
        from fangida.plugins.pseudoc.reconstruct import pseudoc_prelude as reconstruct_prelude
        self.assertEqual(text, reconstruct_prelude())
        self.assertTrue(text.startswith("/* fangida 可读伪 C 前导（版本 1）"))
        self.assertIn("#ifndef FANGIDA_PSEUDOC_PRELUDE", text)
        self.assertEqual(hashlib.sha256(text.encode()).hexdigest(), _PRELUDE_SHA256)

    def test_public_api_is_exported(self):
        import fangida.plugins.pseudoc as package
        self.assertIn("pseudoc_prelude", package.__all__)
        self.assertIn("pseudoc_prelude", __import__("fangida.plugins.pseudoc.reconstruct", fromlist=["__all__"]).__all__)
        for name in ("generate_pseudoc", "PseudocodeResult", "DEFAULT_PSEUDOC"):
            self.assertIn(name, package.__all__)

    def test_every_renderable_helper_and_placeholder_is_declared(self):
        text, names = pseudoc_prelude(), prelude_module.prelude_names()

        def declared(name):
            return re.search(rf"(?:\b{re.escape(name)}\(|#define {re.escape(name)}\(|FANGIDA_LANE_\w+\({re.escape(name)},)", text)
        # lifters 报告列出的辅助名（docs/microcode.md“新增表达式与辅助名”）与本任务的标量辅助函数。
        documented = ["vec_add8_128", "vec_sub16_64", "vec_mul32_128", "vec_cmeq8_128", "vec_cmhi64_128", "vec_cmhs32_64",
                      "vec_cmgt16_128", "vec_cmge8_64", "vec_cmtst32_128", "vec_umax8_128", "vec_umin16_64", "vec_smax32_128",
                      "vec_smin64_128", "vec_ushl16_128", "vec_sshl64_128", "vec_neg16_128", "vec_abs8_64", "vec_shl32_128",
                      "vec_lshr64_128", "vec_ashr16_64", "vec_narrow16_64", "vec_narrow32_64", "vec_narrow64_64",
                      "vec_zext8_128", "vec_sext16_128", "vec_zext32_128", "vec_sext8_64", "vec_addv8_8", "vec_umaxv16_16",
                      "vec_uminv32_32", "vec_smaxv8_8", "vec_sminv16_16", "vec_addv64_64", "vec_signmask8_32",
                      "vec_signmask32_32", "vec_signmask64_32", "pacia_64", "pacib_64", "pacda_64", "pacdb_64", "autia_64",
                      "autib_64", "autda_64", "autdb_64", "xpaci_64", "xpacd_64", "pacga_64", "__arm_rsr64", "__arm_wsr64",
                      *(f"x86_rep_{kind}{width}" for kind in ("stos", "movs") for width in (8, 16, 32, 64)),
                      *(f"{op}_{width}" for op in ("shl", "lshr", "ashr", "rol", "ror") for width in (8, 16, 32, 64, 128)),
                      "bswap_128", "arm_sdiv_32", "arm_sdiv_64", "arm_udiv_32", "arm_udiv_64",
                      "arm_urem_32", "arm_urem_64", "arm_srem_32", "arm_srem_64",
                      *(f"arm_{op}_{width}" for op in ("udiv", "urem", "sdiv", "srem") for width in (8, 16, 128)),
                      *(f"{kind}mul_overflow_{width}" for kind in ("u", "s") for width in (8, 16, 32, 64)),
                      *(f"{op}_{width}" for op in ("udiv", "urem", "sdiv", "srem") for width in (8, 16, 32, 64, 128)),
                      *(f"{op}_{width}" for op in ("x86_udiv_quo", "x86_udiv_rem", "x86_idiv_quo", "x86_idiv_rem")
                        for width in (8, 16, 32, 64)),
                      # AArch64 获取/释放访存（ldar/ldapr/stlr 系列）的原子访问辅助。
                      *(f"{op}_{width}" for op in ("arm_load_acquire", "arm_load_acquire_pc", "arm_store_release")
                        for width in (8, 16, 32, 64))]
        placeholders = ["unknown_value", "unknown_arguments", "unresolved_operation", "unresolved_condition",
                        "unresolved_fallthrough", "unresolved_stack_address", "unresolved_control_flow", "unresolved_result",
                        "initialize_unknown_bytes", "handler_dependent_value", "unknown_return_upper8",
                        "unknown_return_upper16", "unknown_return_upper32", "tail_transfer", "indirect_call", "trap",
                        "arm64_supervisor_call", "__machine_state_region__", "isunordered"]
        for name in documented + placeholders:
            with self.subTest(name=name):
                self.assertIn(name, names)
                self.assertTrue(declared(name), name)
        # 占位只声明：没有函数体。
        for name in placeholders[:-2]:
            with self.subTest(placeholder=name):
                self.assertNotRegex(text, rf"\b{name}\([^)]*\)\s*\{{")

    def test_every_lane_opcode_width_combination_has_a_definition(self):
        names = prelude_module.prelude_names()
        for opcode, (family, _, lane) in LANE_OPCODES.items():
            widths = {"binary": [w for w in (8, 16, 32, 64, 128) if w >= lane and w % lane == 0],
                      "unary": [w for w in (8, 16, 32, 64, 128) if w >= lane and w % lane == 0],
                      "shift": [w for w in (8, 16, 32, 64, 128) if w >= lane and w % lane == 0],
                      "reduce": [lane], "signmask": [8, 16, 32, 64],
                      "narrow": [w for w in (8, 16, 32, 64) if (2 * w) % lane == 0 and w % (lane // 2) == 0],
                      "widen": [w for w in (16, 32, 64, 128) if w % (2 * lane) == 0]}[family]
            self.assertTrue(widths, opcode)
            for width in widths:
                self.assertIn(f"{opcode}_{width}", names)

    def test_prelude_compiles_cleanly_in_every_standard(self):
        compiler = _compiler()
        targets = [()] + ([("-arch", "x86_64"), ("-arch", "arm64")] if sys.platform == "darwin" else [])
        with tempfile.TemporaryDirectory() as tmp:
            header = Path(tmp) / "fangida_prelude.h"
            header.write_text(pseudoc_prelude())
            source = Path(tmp) / "use.c"
            # 头文件可以重复包含（包含保护）。
            source.write_text('#include "fangida_prelude.h"\n#include "fangida_prelude.h"\nint main(void) { return 0; }\n')
            for target in targets:
                for standard in ("c11", "gnu11", "c17", "c2x"):
                    with self.subTest(target=target, standard=standard):
                        checked = subprocess.run([compiler, *target, f"-std={standard}", "-Wall", "-Wextra", "-Werror",
                                                  "-fsyntax-only", str(source)], capture_output=True, text=True)
                        if checked.returncode and "unknown target" not in checked.stderr:
                            self.fail(checked.stderr[-3000:])

    def test_output_is_identical_across_hash_seeds(self):
        script = ("import hashlib\n"
                  "from fangida.plugins.pseudoc import generate_pseudoc, pseudoc_prelude\n"
                  "from tests.test_pseudoc import function as fn\n"
                  "from tests.test_lifter_gaps import _rows\n"
                  "out = generate_pseudoc(fn(*_rows('arm', ['lsl r2, r0, r1', 'ror r3, r2, r1', 'asr r0, r3, #32', 'bx lr']),"
                  " name='f', pseudoc_context={'kind': 'elf'}), 'arm', style='readable')\n"
                  "calls = generate_pseudoc(fn(*_rows('x86_64', ['call 0x40', 'mov rdi, rax', 'call 0x80', 'ret']), name='g',"
                  " pseudoc_context={'kind': 'elf'}), 'x86_64', style='readable')\n"
                  "print(hashlib.sha256((pseudoc_prelude() + out.pseudoc + pseudoc_prelude(calls)).encode()).hexdigest())\n")
        outputs = set()
        for seed in ("0", "1", "4242"):
            result = subprocess.run([sys.executable, "-c", script], cwd=_ROOT, capture_output=True, text=True,
                                    env={**os.environ, "PYTHONHASHSEED": seed}, timeout=120)
            self.assertEqual(result.returncode, 0, result.stderr)
            outputs.add(result.stdout)
        self.assertEqual(len(outputs), 1)


class ExternalDeclarationTests(unittest.TestCase):
    def _calls(self):
        rows = [ins(0, "mov", "rdi", "0x10"), ins(1, "call", "0x100", kind="call", target=0x100),
                ins(2, "mov", "rdi", "rax"), ins(3, "call", "0x200", kind="call", target=0x200),
                ins(4, "mov", "rdi", "rax"), ins(5, "call", "0x300", kind="call", target=0x300), ins(6, "ret", kind="return")]
        context = {"kind": "elf", "callees": {0x200: {"name": "strlen"}, 0x300: {"name": "helper_function"}}}
        return generate_pseudoc(fn(*rows, name="caller", pseudoc_context=context), "x86_64", style="readable")

    def test_report_lists_external_functions_and_prelude_declares_them(self):
        output = self._calls()
        externals = {item["name"]: item for item in output.reconstruction["external_functions"]}
        self.assertEqual(set(externals), {"unknown_function", "strlen", "helper_function"})
        self.assertEqual(externals["strlen"]["source"], "known_prototype")
        self.assertEqual(externals["strlen"]["return_type"], "size_t")
        self.assertIsNone(externals["helper_function"]["parameters"])
        text = pseudoc_prelude(output)
        self.assertTrue(text.startswith(pseudoc_prelude()))
        self.assertIn("size_t strlen(const char *str);", text)
        self.assertIn("uint64_t helper_function(FANGIDA_ANY_ARGUMENTS);", text)
        self.assertIn("uint64_t unknown_function(FANGIDA_ANY_ARGUMENTS);", text)
        # 结果对象、报告、流水线函数记录与文本本身都可以作为来源。
        record = {"pseudoc": output.pseudoc, "pseudoc_reconstruction": output.reconstruction}
        self.assertEqual(pseudoc_prelude(record), text)
        self.assertEqual(pseudoc_prelude(output.reconstruction), text)
        from_text = pseudoc_prelude(output.pseudoc)
        self.assertIn("size_t strlen(const char *str);", from_text)
        self.assertIn("uint64_t helper_function(FANGIDA_ANY_ARGUMENTS);", from_text)
        with self.assertRaises(TypeError):
            pseudoc_prelude(42)
        _syntax_check(text + "\n" + output.pseudoc + "\n")
        _syntax_check(from_text + "\n" + output.pseudoc + "\n")
        _syntax_check(text + "\n" + output.pseudoc + "\n", "-std=c2x")

    def test_own_name_and_prelude_names_are_not_redeclared(self):
        rows = [ins(0, "call", "0x0", kind="call", target=0), ins(1, "ret", kind="return")]
        output = generate_pseudoc(fn(*rows, name="self_call", pseudoc_context={"kind": "elf"}), "x86_64", style="readable")
        names = {item["name"] for item in output.reconstruction["external_functions"]}
        self.assertNotIn("self_call", names)
        self.assertNotIn("unknown_arguments", names)

    def test_old_reports_without_the_field_fall_back_to_text(self):
        output = self._calls()
        old = {key: value for key, value in output.reconstruction.items() if key != "external_functions"}
        self.assertEqual(pseudoc_prelude({"pseudoc": output.pseudoc, "pseudoc_reconstruction": old}),
                         pseudoc_prelude(output.pseudoc))
        # 文本里的编译器内建与前导中的辅助函数不会被当作外部函数重新声明。
        swapped = generate_pseudoc(fn(*_rows("arm", ["rev r0, r0", "lsl r0, r0, r1", "bx lr"]), name="swap_shift",
                                      pseudoc_context={"kind": "elf"}), "arm", style="readable").pseudoc
        self.assertIn("__builtin_bswap32(", swapped)
        self.assertEqual(pseudoc_prelude(swapped), pseudoc_prelude())
        _syntax_check(pseudoc_prelude(swapped) + "\n" + swapped + "\n")

    def test_text_source_declares_functions_referenced_only_by_address(self):
        # 尾转移的目标只以函数名（地址）出现、不以调用形式出现：只传文本时也要声明，与传报告的结果相同。
        rows = [ins(0, "mov", "rdi", "rsi"), ins(1, "call", "0x100", kind="call", target=0x100), ins(2, "mov", "rdi", "rax"),
                ins(3, "jmp", "0x200", kind="jump", target=0x200)]
        rows[3]["branch_info"] = {"kind": "jump", "target": 0x200, "conditional": False}
        context = {"kind": "elf", "callees": {0x100: {"name": "strlen"}, 0x200: {"name": "next_stage"}}}
        output = generate_pseudoc(fn(*rows, name="forwarder", pseudoc_context=context), "x86_64", style="readable")
        self.assertIn("tail_transfer(next_stage, ", output.pseudoc)
        sources = {item["name"]: item["source"] for item in output.reconstruction["external_functions"]}
        self.assertEqual(sources, {"next_stage": "address_only", "strlen": "known_prototype"})
        from_text = pseudoc_prelude(output.pseudoc)
        self.assertIn("void next_stage(FANGIDA_ANY_ARGUMENTS);", from_text)
        self.assertEqual(from_text, pseudoc_prelude(output))
        _syntax_check(from_text + "\n" + output.pseudoc + "\n")

    def test_text_source_matches_report_names_for_varied_outputs(self):
        # 局部变量、参数、extern 全局、goto 标号、机器状态片段名与类型名都不是外部函数：
        # 只传文本时声明的名字与报告的 external_functions 相同，且都能编译。
        fixtures = [("x86_64", ["mov eax, dword ptr [0x601000]", "test eax, eax", "jne 0x0", "ret"]),
                    ("x86_64", ["mov rax, rdi", "mov ecx, dword ptr [rdi]", "test esi, esi", "je 0x5", "rdrand rax",
                                "mov eax, dword ptr [rax+4]", "add eax, ecx", "ret"]),
                    ("arm64", ["svc #0", "ret"]), ("arm64", ["ldr w2, [x1]", "svc #0", "cmp x0, #0", "b.eq 0x18",
                                                              "ldr w0, [x1]", "ret", "ldr w0, [x1, #4]", "ret"]),
                    ("x86_64", ["mov rax, rdi", "call 0x40", "mov rdi, rax", "jmp 0x80"])]
        for architecture, texts in fixtures:
            output = generate_pseudoc(fn(*_branch_rows(architecture, texts), name="varied", pseudoc_context={"kind": "elf"}),
                                      architecture, style="readable")
            with self.subTest(texts=texts):
                reported = {item["name"] for item in output.reconstruction["external_functions"]}
                from_text = {item["name"] for item in prelude_module._externals_of(output.pseudoc)}
                self.assertEqual(from_text, reported, output.pseudoc)
                _syntax_check(pseudoc_prelude(output.pseudoc) + "\n" + output.pseudoc + "\n")


class RenderingTests(unittest.TestCase):
    @staticmethod
    def _readable(architecture, texts, name="f"):
        return generate_pseudoc(fn(*_rows(architecture, texts), name=name, pseudoc_context={"kind": "elf"}),
                                architecture, style="readable").pseudoc

    def test_masked_counts_stay_plain_c_operators(self):
        x86 = self._readable("x86_64", ["mov eax, edi", "mov ecx, esi", "shl eax, cl", "ret"])
        self.assertIn("arg_1 << (", x86)
        a64 = self._readable("arm64", ["asr w0, w0, w1", "ret"])
        self.assertIn("(uint32_t)((int32_t)arg_1 >> (arg_2 & 0x1f))", a64)
        for text in (x86, a64):
            self.assertNotRegex(text, r"\b(?:shl|lshr|ashr)_\d+\(")

    def test_counts_that_may_reach_the_width_call_defined_helpers(self):
        self.assertIn("shl_32(arg_1, arg_2 & 0xff)", self._readable("arm", ["lsl r0, r0, r1", "bx lr"]))
        self.assertIn("lshr_32(arg_1, 32)", self._readable("arm", ["lsr r0, r0, #32", "bx lr"]))
        self.assertIn("ashr_32(arg_1, 32)", self._readable("arm", ["asr r0, r0, #32", "bx lr"]))
        self.assertIn("ror_32(arg_1, arg_2 & 0xff)", self._readable("arm", ["ror r0, r0, r1", "bx lr"]))
        # 旧的未定义名字（ashr_32 写成通用回退、x >> 32）不再出现。
        self.assertNotIn(">> 32", self._readable("arm", ["lsr r0, r0, #32", "bx lr"]))

    def test_rotations_byte_swaps_and_divisions(self):
        self.assertIn("(arg_1 >> 1) | (arg_1 << 31)", self._readable("arm64", ["ror w0, w0, #1", "ret"]))
        self.assertIn("ror_64(arg_1, arg_2 & 0x3f)", self._readable("arm64", ["ror x0, x0, x1", "ret"]))
        self.assertIn("__builtin_bswap32(", self._readable("arm64", ["rev w0, w0", "ret"]))
        self.assertIn("__builtin_bswap64(", self._readable("x86_64", ["mov rax, rdi", "bswap rax", "ret"]))
        self.assertIn("arm_sdiv_64(arg_1, arg_2)", self._readable("arm64", ["sdiv x0, x0, x1", "ret"]))
        self.assertIn("arm_udiv_32(arg_1, arg_2)", self._readable("arm", ["udiv r0, r0, r1", "bx lr"]))

    def test_narrow_left_shift_is_truncated_to_its_width(self):
        text = self._readable("x86_64", ["mov rax, rdi", "mov rcx, rsi", "shl al, cl", "ret"])
        self.assertIn("(uint8_t)((uint32_t)(uint8_t)arg_1 << ", text)

    def test_placeholders_compile_with_pointer_destinations(self):
        rows = [ins(0, "mov", "eax", "dword ptr [rdi]"), ins(1, "call", "0x100", kind="call", target=0x100),
                ins(2, "mov", "eax", "dword ptr [rdi+4]"), ins(3, "ret", kind="return")]
        output = generate_pseudoc(fn(*rows, name="unknown_base", pseudoc_context={"kind": "elf"}), "x86_64", style="readable")
        self.assertIn("((uint32_t *)unknown_value())[1]", output.pseudoc)
        _syntax_check(pseudoc_prelude(output) + "\n" + output.pseudoc + "\n")

    def test_pointer_variables_and_pointer_operands_get_explicit_casts(self):
        """占位写入指针变量时显式转换（初值、赋值、handler_dependent_value）；被推断为指针的操作数传给整数辅助
        函数（循环移位、字节交换、算术右移、ARM 除法）时显式转为整数。缺少转换时 -Werror=int-conversion 报错。"""
        cases = [
            # 未初始化的寄存器（rbx）当指针用：指针变量的初值
            ("x86_64", ["mov eax, dword ptr [rbx]", "ret"], r"^    uint32_t \* ptr = \(uint32_t \*\)unknown_value\(\);$"),
            # 未识别指令（rdrand）写入的指针变量：赋值
            ("x86_64", ["mov rax, rdi", "mov ecx, dword ptr [rdi]", "test esi, esi", "je 0x5", "rdrand rax",
                        "mov eax, dword ptr [rax+4]", "add eax, ecx", "ret"], r"^        ptr = \(uint32_t \*\)unknown_value\(\);$"),
            # 系统调用后由处理程序决定的指针寄存器
            ("arm64", ["ldr w2, [x1]", "svc #0", "cmp x0, #0", "b.eq 0x18", "ldr w0, [x1]", "ret", "ldr w0, [x1, #4]", "ret"],
             r'\(\(uint32_t \*\)handler_dependent_value\(4, "x1"\)\)\[1\]'),
            ("x86_64", ["mov edx, dword ptr [rdi]", "ror rdi, cl", "mov rax, rdi", "ret"], r"ror_64\(\(uint64_t\)arg_1, "),
            ("x86_64", ["mov edx, dword ptr [rdi]", "bswap rdi", "mov rax, rdi", "ret"], r"__builtin_bswap64\(\(uint64_t\)arg_1\)"),
            ("arm", ["ldr r2, [r0]", "asr r0, r0, r1", "bx lr"], r"ashr_32\(\(uint32_t\)arg_1, arg_2 & 0xff\)"),
            ("arm64", ["ldr w2, [x0]", "udiv x0, x0, x1", "ret"], r"arm_udiv_64\(\(uint64_t\)arg_1, arg_2\)"),
        ]
        for architecture, texts, pattern in cases:
            output = generate_pseudoc(fn(*_branch_rows(architecture, texts), name="pointer_casts", pseudoc_context={"kind": "elf"}),
                                      architecture, style="readable")
            with self.subTest(texts=texts):
                self.assertRegex(output.pseudoc, re.compile(pattern, re.M))
                _syntax_check(pseudoc_prelude(output) + "\n" + output.pseudoc + "\n")

    @staticmethod
    def _replaced(architecture, texts, opcode, value=None, field=None, right=None):
        """把单条 add 指令微码的表达式换成 opcode（只有渲染层可以见到的运算，如 sdiv/insert）；right 替换第二个操作数。"""
        function = fn(*_rows(architecture, texts), name="f", pseudoc_context={"kind": "elf"})
        records = lift_function(function, architecture)["instructions"]
        operation = records[0]["operations"][0]
        expression = dict(operation["expression"])
        expression["opcode"] = opcode
        if right is not None:
            expression["args"] = [expression["args"][0], right]
        if value is not None:
            expression["value"] = value
            expression["args"] = [expression["args"][0], {"opcode": "extract", "width": field, "domain": "bitvector",
                                                          "args": [expression["args"][1]["args"][0]], "value": 0}]
        records[0] = {**records[0], "operations": [{**operation, "expression": expression, "inputs": [expression]}]}
        return function, records, expression

    def test_unsigned_and_signed_division_render_as_c_operators_and_match_microcode(self):
        """除数是非零常数（带符号时也不是 -1）时写成 C 的 / 、%；除数可能为 0 或 -1 时调用前导的 udiv_W/urem_W/
        sdiv_W/srem_W。结果与微码逐一相同；微码不定义结果的输入（除以 0、带符号溢出）陷入，而不是 C 未定义行为。"""
        values = (0, 1, 2, 3, 7, 0x7f, 0x80, 0xff, 0x7fffffff, 0x80000000, 0x80000001, 0xfffffffe, 0xffffffff,
                  0x7fffffffffffffff, 0x8000000000000000, 0xfffffffffffffffe, _MASK64, 0x123456789abcdef)
        lines, expected, traps = [], [], []
        sources = []
        for register, width in (("w", 32), ("x", 64)):
            mask = (1 << width) - 1
            for opcode in ("udiv", "urem", "sdiv", "srem"):
                operator = "/" if "div" in opcode else "%"
                # 寄存器除数：可能为 0（及 -1），调用陷入的辅助函数。
                function, records, expression = self._replaced("arm64", [f"add {register}0, {register}0, {register}1", "ret"], opcode)
                name = f"{opcode}{width}"
                text = reconstruct_function({**function, "name": name}, "arm64", microcode=records).pseudoc
                self.assertIn(f"{opcode}_{width}(arg_1, arg_2)", text)
                self.assertNotIn(f" {operator} ", text)
                sources.append(text)
                for left in values:
                    for right in values:
                        call = f"{name}({left & mask:#x}ULL, {right & mask:#x}ULL)"
                        try:
                            want = evaluate_expression(expression, {"x0": left, "x1": right})
                        except UnknownValue:
                            # 除数为 0、带符号溢出：机器陷入，微码不定义结果。每个函数取 2 个除以 0 的输入与全部溢出输入
                            # （每次陷入经信号传递约需 20 毫秒）。
                            if right & mask or sum(f"{name}(" in item and item.endswith(", 0x0ULL)") for item in traps) < 2:
                                traps.append(call)
                            continue
                        lines.append(f"    printf(\"%llx\\n\", (unsigned long long){call});")
                        expected.append(want)
                # 非零常数除数（带符号时也不是 -1）：C 的 / 、%（带符号除法先转为带符号类型）。
                for divisor in (7, -7):
                    function, records, expression = self._replaced(
                        "arm64", [f"add {register}0, {register}0, {register}1", "ret"], opcode, right=_const(divisor, width))
                    constant_name = f"{name}_by_{'minus_' if divisor < 0 else ''}7"
                    text = reconstruct_function({**function, "name": constant_name}, "arm64", microcode=records).pseudoc
                    self.assertIn(f" {operator} ", text)
                    self.assertNotRegex(text, rf"\b{opcode}_{width}\(")
                    sources.append(text)
                    for left in values:
                        want = evaluate_expression(expression, {"x0": left})
                        lines.append(f"    printf(\"%llx\\n\", (unsigned long long){constant_name}({left & mask:#x}ULL));")
                        expected.append(want)
        source = pseudoc_prelude() + "\n#include <stdio.h>\n" + "\n".join(sources) + "\nint main(void) {\n" + "\n".join(lines) + "\n    return 0;\n}\n"
        self.assertEqual([int(line, 16) for line in _run_c(source)], expected)
        self.assertGreaterEqual(len(traps), 20)
        self.assertEqual(_trap_statuses(pseudoc_prelude() + "\n" + "\n".join(sources), traps), [_TRAPPED] * len(traps))

    def test_insert_expands_to_c_operators(self):
        function, records, expression = self._replaced("arm64", ["add w0, w0, w1", "ret"], "insert", value=8, field=8)
        text = reconstruct_function({**function, "name": "insert_byte"}, "arm64", microcode=records).pseudoc
        self.assertNotIn("insert_32(", text)
        self.assertIn("0xffff00ff", text)
        values = (0, 1, 0xff, 0x100, 0xdeadbeef, 0xffffffff, 0x12345678)
        lines, expected = [], []
        for left in values:
            for right in values:
                lines.append(f"    printf(\"%llx\\n\", (unsigned long long)insert_byte({left:#x}U, {right:#x}U));")
                expected.append(evaluate_expression(expression, {"x0": left, "x1": right}))
        source = pseudoc_prelude() + "\n#include <stdio.h>\n" + text + "\nint main(void) {\n" + "\n".join(lines) + "\n    return 0;\n}\n"
        self.assertEqual([int(line, 16) for line in _run_c(source)], expected)


class HelperSemanticsTests(unittest.TestCase):
    """前导里的 C 定义与微码 evaluate 逐一比对。"""

    def test_shift_and_rotate_helpers_match_microcode(self):
        rng = random.Random(1)
        lines, expected = [], []
        for width in (8, 16, 32, 64, 128):
            top = (1 << width) - 1
            values = sorted({0, 1, top, top >> 1, (top >> 1) + 1, 0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a & top,
                             *(rng.getrandbits(width) for _ in range(3))})
            counts = sorted({0, 1, width - 1, width, width + 1, 2 * width - 1, 2 * width, 0xff, 0x100, 0x101, 31, 32, 33,
                             63, 64, 65, 127, 128, 129, 1 << 32, (1 << 32) + 1, 1 << 63, _MASK64})
            for op in ("shl", "lshr", "ashr", "rol", "ror"):
                for value in values:
                    for count in counts:
                        lines.append(_print(f"{op}_{width}({_c_constant(value, width)}, {count:#x}ULL)"))
                        expected.append(evaluate_expression(Expression(op, width, (constant(value, width), constant(count, 64)))))
        self.assertEqual([int(line, 16) for line in _run_c(_program(lines))], expected)

    def test_byte_swaps_and_arm_divisions_match_microcode(self):
        rng = random.Random(2)
        lines, expected = [], []
        for width in (16, 32, 64, 128):
            for value in (0, 1, 0x0102030405060708090a0b0c0d0e0f10 & ((1 << width) - 1), *(rng.getrandbits(width) for _ in range(4))):
                call = f"bswap_128({_c_constant(value, 128)})" if width == 128 else f"__builtin_bswap{width}({_c_constant(value, width)})"
                lines.append(_print(call))
                expected.append(evaluate_expression(Expression("bswap", width, (constant(value, width),))))
        for width in (32, 64):
            top = (1 << width) - 1
            values = (0, 1, 2, 3, 7, top, top - 1, 1 << (width - 1), (1 << (width - 1)) - 1, (1 << (width - 1)) + 1,
                      *(rng.getrandbits(width) for _ in range(3)))
            for op in ("arm_udiv", "arm_sdiv"):
                for left in values:
                    for right in values:
                        lines.append(_print(f"{op}_{width}({_c_constant(left, width)}, {_c_constant(right, width)})"))
                        expected.append(evaluate_expression(Expression(op, width, (constant(left, width), constant(right, width)))))
        self.assertEqual([int(line, 16) for line in _run_c(_program(lines))], expected)

    def test_trapping_division_helpers_match_microcode_and_trap(self):
        """udiv_W/urem_W/sdiv_W/srem_W（W = 8～128）：有定义的输入与微码相同；除以 0、带符号溢出时陷入。"""
        rng = random.Random(4)
        lines, expected, traps = [], [], []
        for width in (8, 16, 32, 64, 128):
            top = (1 << width) - 1
            values = sorted({0, 1, 2, 3, 7, top, top - 1, 1 << (width - 1), (1 << (width - 1)) - 1, (1 << (width - 1)) + 1,
                             *(rng.getrandbits(width) for _ in range(2))})
            for op in ("udiv", "urem", "sdiv", "srem"):
                for left in values:
                    for right in values:
                        call = f"{op}_{width}({_c_constant(left, width)}, {_c_constant(right, width)})"
                        try:
                            want = evaluate_expression(Expression(op, width, (constant(left, width), constant(right, width))))
                        except UnknownValue:
                            if right or left in (0, top):  # 除以 0 只取被除数 0 与全 1，带符号溢出全部检查
                                traps.append(call)
                            continue
                        lines.append(_print(call))
                        expected.append(want)
        self.assertEqual([int(line, 16) for line in _run_c(_program(lines))], expected)
        self.assertEqual(_trap_statuses(pseudoc_prelude(), traps), [_TRAPPED] * len(traps))

    def test_every_lane_helper_matches_evaluate_lanes(self):
        rng = random.Random(3)

        def pattern(lane, width):
            boundary = [0, 1, (1 << lane) - 1, 1 << (lane - 1), (1 << (lane - 1)) - 1, 0x80 & ((1 << lane) - 1), 0xff, 0x7f, 0xc1,
                        lane - 1, lane, lane + 1]
            value = 0
            for index in range(max(width // lane, 1)):
                item = rng.choice(boundary) if rng.random() < 0.6 else rng.getrandbits(lane)
                value |= (item & ((1 << lane) - 1)) << (index * lane)
            return value & ((1 << width) - 1)
        lines, expected = [], []
        for name in prelude_module.lane_helper_names():
            opcode, width = name.rsplit("_", 1)
            width = int(width)
            if opcode in PERMUTE_OPCODES:
                # 跨通道重排/饱和打包：两个 128 位源，结果 128 位。
                _, _, lane = PERMUTE_OPCODES[opcode]
                for _ in range(4):
                    a, b = pattern(lane, 128), pattern(lane, 128)
                    call = f"{name}({_c_constant(a, 128)}, {_c_constant(b, 128)})"
                    lines.append(_print(call))
                    expected.append(evaluate_permute(opcode, 128, [a, b], (128, 128)) & ((1 << 128) - 1))
                continue
            family, _, lane = LANE_OPCODES[opcode]
            for _ in range(4):
                if family == "binary":
                    a, b = pattern(lane, width), pattern(lane, width)
                    call, args, widths = f"{name}({_c_constant(a, width)}, {_c_constant(b, width)})", [a, b], (width, width)
                elif family == "unary":
                    a = pattern(lane, width)
                    call, args, widths = f"{name}({_c_constant(a, width)})", [a], (width,)
                elif family == "shift":
                    a, n = pattern(lane, width), rng.choice([0, 1, lane - 1, lane, lane + 1, 0xff, 0x100, rng.getrandbits(64)])
                    call, args, widths = f"{name}({_c_constant(a, width)}, {n:#x}ULL)", [a, n], (width, 64)
                elif family == "narrow":
                    a = pattern(lane, 2 * width)
                    call, args, widths = f"{name}({_c_constant(a, 2 * width)})", [a], (2 * width,)
                elif family == "widen":
                    a = pattern(lane, width // 2)
                    call, args, widths = f"{name}({_c_constant(a, width // 2)})", [a], (width // 2,)
                elif family == "reduce":
                    source = rng.choice([64, 128])
                    a = pattern(lane, source)
                    call, args, widths = f"{name}({_c_constant(a, source)})", [a], (source,)
                else:  # signmask：参数宽度不超过 W 位能容纳的通道数
                    source = 128 if width >= 128 // lane else width * lane
                    a = pattern(lane, source)
                    call, args, widths = f"{name}({_c_constant(a, 128)})", [a], (source,)
                lines.append(_print(call))
                expected.append(evaluate_lanes(opcode, width, args, widths) & ((1 << width) - 1))
        self.assertEqual([int(line, 16) for line in _run_c(_program(lines))], expected)

    def test_x86_string_helpers_write_elements_in_ascending_order(self):
        lines = ["    unsigned char buffer[64];",
                 "    for (int i = 0; i < 64; i++) buffer[i] = (unsigned char)i;",
                 "    x86_rep_stos32((uint64_t)(uintptr_t)(buffer + 4), 0xa1b2c3d4ULL, 3);",
                 # 重叠复制按元素升序逐个进行：源在目的之前时不是 memmove 的结果。
                 "    x86_rep_movs16((uint64_t)(uintptr_t)(buffer + 34), (uint64_t)(uintptr_t)(buffer + 32), 4);",
                 "    x86_rep_movs64((uint64_t)(uintptr_t)(buffer + 48), (uint64_t)(uintptr_t)(buffer + 4), 1);",
                 "    x86_rep_stos8((uint64_t)(uintptr_t)(buffer + 60), 0x1ff, 2);",
                 "    for (int i = 0; i < 64; i++) printf(\"%x\\n\", buffer[i]);"]
        memory = list(range(64))
        for index in range(3):
            memory[4 + 4 * index:8 + 4 * index] = [0xd4, 0xc3, 0xb2, 0xa1]
        for index in range(4):
            memory[34 + 2 * index:36 + 2 * index] = memory[32 + 2 * index:34 + 2 * index]
        memory[48:56] = memory[4:12]
        memory[60:62] = [0xff, 0xff]
        self.assertEqual([int(line, 16) for line in _run_c(_program(lines))], memory)

    def test_pointer_authentication_helpers_round_trip_on_pauth_hosts(self):
        probe = subprocess.run([_compiler(), "-dM", "-E", "-x", "c", "-"], input="", capture_output=True, text=True)
        if "__ARM_FEATURE_PAUTH" not in probe.stdout or "__aarch64__" not in probe.stdout:
            raise unittest.SkipTest("本机编译目标不是实现 PAuth 的 AArch64")
        lines = ["    uint64_t p = (uint64_t)(uintptr_t)&p, m = 0x1234;",
                 "    printf(\"%d\\n\", autia_64(pacia_64(p, m), m) == p);",
                 "    printf(\"%d\\n\", autdb_64(pacdb_64(p, m), m) == p);",
                 "    printf(\"%d\\n\", xpaci_64(pacia_64(p, m)) == p);",
                 "    printf(\"%d\\n\", (pacga_64(p, m) & 0xffffffffULL) == 0);"]
        self.assertEqual(_run_c(_program(lines)), ["1", "1", "1", "1"])


class ExpressionSemanticsTests(unittest.TestCase):
    """微码表达式经 Expressions.lift + format_value 渲染为 C，编译运行（UBSan）后与 evaluate_expression 逐一比对。"""

    def test_rendered_expressions_match_microcode(self):
        t0, t1 = _op("truncate", 32, _reg("x0")), _op("truncate", 32, _reg("x1"))

        def shl32(count):
            return _op("zext", 64, _op("shl", 32, t0, count))
        cases = {
            # 计数上界：or 组合后再相加可以达到 46（不能按两侧较大者估计）。
            "or_then_add_count": shl32(_op("add", 32, _op("or", 32, _op("and", 32, t1, _const(16, 32)),
                                                          _op("and", 32, t1, _const(15, 32))),
                                           _op("and", 32, t1, _const(15, 32)))),
            # 常数右移后的计数：(x & 127) >> 1 可以达到 63。
            "shifted_count": shl32(_op("lshr", 32, _op("and", 32, t1, _const(127, 32)), _const(1, 32))),
            # 带符号扩展后的计数：(uint32_t)(int8_t)x >> 3 可以很大（负数转为无符号）。
            "sign_extended_count": shl32(_op("lshr", 32, _op("sext", 32, _op("truncate", 8, _reg("x1"))), _const(3, 32))),
            # 已证明在范围内的计数：保持 C 运算符（对照）。
            "masked_count": shl32(_op("and", 32, t1, _const(31, 32))),
            "masked_sum_count": _op("zext", 64, _op("lshr", 32, t0, _op("add", 32, _op("and", 32, t1, _const(15, 32)),
                                                                     _op("and", 32, _op("lshr", 32, t1, _const(8, 32)), _const(15, 32))))),
            # 常数除数写成 C 的 / 、%：带符号扩展的被除数仍按无符号除。
            "udiv_sign_extended": _op("zext", 64, _op("udiv", 32, _op("sext", 32, _op("truncate", 16, _reg("x0"))), _const(3, 32))),
            "urem_sign_extended": _op("zext", 64, _op("urem", 32, _op("sext", 32, _op("truncate", 16, _reg("x0"))), _const(10, 32))),
            "sdiv_constant": _op("zext", 64, _op("sdiv", 32, t0, _const(-7, 32))),
            # 常数除数 -1：最小负数 / -1 溢出，仍调用陷入的 sdiv_W（C 的 / 此时未定义）。
            "sdiv_by_minus_one": _op("zext", 64, _op("sdiv", 32, t0, _const(-1, 32))),
            "srem64_constant": _op("srem", 64, _reg("x0"), _const(7, 64)),
            # 除数可能为 0 或 -1：调用陷入的辅助函数（除数不为 0；带符号溢出的输入另行检查陷入）。
            "udiv_register": _op("udiv", 64, _reg("x0"), _op("or", 64, _reg("x1"), _const(1, 64))),
            "sdiv_register": _op("zext", 64, _op("sdiv", 16, _op("truncate", 16, _reg("x0")), _op("or", 16, _reg("h0", 16), _const(2, 16)))),
            # 窄类型变量的常数循环移位：写成两次移位后截回原宽度。
            "rol16_variable": _op("zext", 64, _op("rol", 16, _reg("h0", 16), _const(3, 16))),
            "ror8_variable": _op("zext", 64, _op("ror", 8, _reg("b0", 8), _const(3, 8))),
            "ror32_constant_count": _op("zext", 64, _op("ror", 32, t0, _const(37, 32))),
            # 归约的实参写成确切宽度：常数按 64 位计 8 个通道（0x1010101 的高 4 个字节为 0）。
            "uminv_constant": _op("zext", 64, _op("vec_uminv8", 8, _const(0x1010101, 64))),
            "smaxv_register": _op("zext", 64, _op("vec_smaxv16", 16, _reg("x1"))),
            # 被推断为指针的寄存器传给整数辅助函数：显式转为整数（地址值不变）。
            "ror_pointer": _op("ror", 64, _reg("p0"), _op("and", 64, _reg("x1"), _const(63, 64))),
            "ashr_pointer": _op("ashr", 64, _reg("p0"), _reg("x1")),
            "bswap_pointer": _op("bswap", 64, _reg("p0")),
        }
        items, expected, traps = [], [], []
        for index, (name, expression) in enumerate(cases.items()):
            text = _render_expression(expression)
            rows, trapping = [], []
            # 另加 32/16 位最小负数（带符号除法溢出）的输入行。
            extra = [(0x80000000, 0x1f, 0x8000, 0x80, 0x1000), (0xffffffff80000000, _MASK64, 0xffff, 0xff, 0)]
            for row in _inputs([width for _, width, _ in _EXPRESSION_VARIABLES], 100 + index, count=72) + extra:
                try:
                    want = evaluate_expression(expression, dict(zip((item[0] for item in _EXPRESSION_VARIABLES), row)))
                except UnknownValue:
                    trapping.append(f"{name}({_expression_arguments(row)})")  # 带符号溢出：机器陷入，微码不定义结果
                    continue
                rows.append(row)
                expected.append(want)
            items.append((name, text, rows))
            traps.extend(trapping[:3])
        texts = {name: text for name, text, _ in items}
        # 计数可能达到宽度时调用辅助函数，已证明在范围内时保持 C 运算符。
        for name in ("or_then_add_count", "shifted_count", "sign_extended_count"):
            self.assertIn("shl_32(", texts[name], name)
        self.assertIn(" << (", texts["masked_count"])
        self.assertNotRegex(texts["masked_sum_count"], r"\blshr_32\(")
        self.assertIn(" / 3", texts["udiv_sign_extended"])
        self.assertIn("udiv_64(", texts["udiv_register"])
        self.assertIn("sdiv_16(", texts["sdiv_register"])
        self.assertIn("sdiv_32(", texts["sdiv_by_minus_one"])
        self.assertIn("(uint16_t)((uint32_t)h0 << 3 | (uint32_t)h0 >> 13)", texts["rol16_variable"])
        self.assertIn("vec_uminv8_8((uint64_t)0x1010101)", texts["uminv_constant"])
        self.assertIn("ror_64((uint64_t)p0, ", texts["ror_pointer"])
        program = _expression_program(items)
        _syntax_check(program)
        self.assertEqual([int(line, 16) for line in _run_c(program)], expected)
        # 微码不定义结果的输入（最小负数除以 -1）陷入，而不是 C 未定义行为。
        self.assertTrue(any(call.startswith("sdiv_by_minus_one(") for call in traps))
        self.assertEqual(_trap_statuses(_expression_program(items, main=False), traps), [_TRAPPED] * len(traps))

    def test_counts_from_calls_follow_the_declared_return_type(self):
        """调用（占位、外部函数）的值是声明的返回类型：前导里 handler_dependent_value 等返回 uint64_t，即使调用
        节点记为 uint8_t 也不能按 0..255 证明计数范围。这里用返回 uint64_t 的外部函数，计数调用 shl_32，UBSan 下无未定义行为。"""
        from fangida.plugins.pseudoc.reconstruct.model import Value
        x0 = Value("variable", 64, name="x0", ctype="uint64_t")
        call = Value("call", 8, (x0,), name="external_value", ctype="uint8_t")
        count = Value("cast", 32, (Value("lshr", 8, (call, Value("constant", 8, number=3, ctype="uint8_t")), ctype="uint8_t"),),
                      ctype="uint32_t")
        shift = Value("shl", 32, (Value("cast", 32, (x0,), ctype="uint32_t"), count), ctype="uint32_t")
        text = format_value(shift)
        self.assertTrue(text.startswith("shl_32("), text)
        rows = _inputs([width for _, width, _ in _EXPRESSION_VARIABLES], 300, count=48)
        program = _expression_program([("call_count", text, rows)],
                                      prefix="static uint64_t external_value(uint64_t value) { return value; }")
        _syntax_check(program)
        self.assertEqual(len(_run_c(program)), len(rows))

    def test_count_bounds_follow_the_c_rendering_of_narrow_values(self):
        """窄于 32 位的取反、取负、加、乘在可读 C 中截回原宽度（见 _format）：其值落在 uint8_t/uint16_t 范围内，
        可据此证明移位计数小于宽度，因此 (narrow >> 3)、(narrow % 10) 等计数直接写成 C 的 <<、>> 运算符，
        不再调用 shl_32/lshr_32。截回使渲染与微码逐位一致，这里编译运行（UBSan）并与 evaluate_expression 逐一比对。"""
        t0, b1 = _op("truncate", 32, _reg("x0")), _op("truncate", 8, _reg("x1"))
        h1 = _op("truncate", 16, _reg("x1"))
        counts = {
            "not8": _op("lshr", 8, _op("not", 8, b1), _const(3, 8)),
            "neg8": _op("lshr", 8, _op("neg", 8, b1), _const(3, 8)),
            "add8": _op("lshr", 8, _op("add", 8, b1, _op("truncate", 8, _reg("x0"))), _const(3, 8)),
            "mul16": _op("lshr", 16, _op("mul", 16, h1, h1), _const(11, 16)),
            "and_not8": _op("lshr", 8, _op("and", 8, _op("not", 8, b1), _op("not", 8, _op("truncate", 8, _reg("x0")))), _const(3, 8)),
            "urem_not8": _op("urem", 8, _op("not", 8, b1), _const(10, 8)),
        }
        items, expected = [], []
        for index, (name, count) in enumerate(counts.items()):
            for operation in ("shl", "lshr"):
                expression = _op("zext", 64, _op(operation, 32, t0, _op("zext", 32, count)))
                text = _render_expression(expression)
                symbol = "<<" if operation == "shl" else ">>"
                with self.subTest(count=name, operation=operation):
                    # 截回原宽度后计数已证明 < 32：写成 C 运算符，不再出现越界移位的辅助函数。
                    self.assertNotRegex(text, r"\b(?:shl|lshr)_32\(")
                    self.assertIn(f" {symbol} ", text)
                    # 窄运算自身截回原宽度（(uint8_t)/(uint16_t) 转换）。
                    self.assertRegex(text, r"\(uint(?:8|16)_t\)\(")
                rows = _inputs([width for _, width, _ in _EXPRESSION_VARIABLES], 200 + index, count=48)
                for row in rows:
                    expected.append(evaluate_expression(expression, dict(zip((item[0] for item in _EXPRESSION_VARIABLES), row))))
                items.append((f"{operation}_{name}", text, rows))
        program = _expression_program(items)
        _syntax_check(program)
        self.assertEqual([int(line, 16) for line in _run_c(program)], expected)


class LeafFunctionSemanticsTests(unittest.TestCase):
    """合成叶子函数：可读 C + 前导编译运行，与微码逐条执行的返回值逐一比对。"""

    def test_synthetic_leaf_functions_match_microcode_execution(self):
        items, seed = [], 7
        for architecture, cases in _synthetic_cases().items():
            for name, texts in cases:
                function = fn(*_rows(architecture, texts), name=name, pseudoc_context={"kind": "elf"})
                output = generate_pseudoc(function, architecture, style="readable")
                with self.subTest(name=name):
                    self.assertTrue(output.reconstruction.get("complete"), output.pseudoc)
                    self.assertNotRegex(output.pseudoc, r"unknown_value|unresolved_")
                    seed += 1
                    items.append(_leaf_case(name, architecture, output, function, seed))
        self.assertGreaterEqual(len(items), 100)
        expected = [value for item in items for value in item["expected"]]
        cases = sum(len(item["cases"]) for item in items)
        self.assertGreaterEqual(cases, 4000)
        # 每个移位/循环移位函数的计数参数都覆盖 0、W-1、W、W+1 与 0xff。
        for item in items:
            if item["name"].endswith(("_cl", "_reg")):
                counts = {case[1] for case in item["cases"]}
                width = int(re.search(r"(\d+)_(?:cl|reg)$", item["name"]).group(1)) if re.search(r"\d+_(?:cl|reg)$", item["name"]) else 32
                self.assertTrue({0, width - 1, width, width + 1, 0xff} <= counts, item["name"])
        program = _leaf_program(items)
        _syntax_check(program, "-Wall", "-Werror", "-Wno-unused-variable")
        observed = [int(line, 16) for line in _run_c(program)]
        self.assertEqual(len(observed), len(expected))
        index = 0
        for item in items:
            for case, want in zip(item["cases"], item["expected"]):
                self.assertEqual(observed[index], want, (item["name"], case, item["text"]))
                index += 1


class CompileTests(unittest.TestCase):
    def test_placeholder_heavy_outputs_compile_with_their_prelude(self):
        fixtures = {
            "x86_64": [["mov rax, rdi", "call 0x40", "mov rdi, rax", "jmp 0x80"],
                       ["test edi, edi", "jne 0x3", "ud2", "ret"]],
            "arm64": [["mrs x0, tpidr_el0", "msr tpidr_el0, x1", "ret"],
                      ["svc #0", "ret"], ["paciasp", "pacda x0, x1", "autda x0, x2", "ret"],
                      ["cmp x0, x1", "b.eq 0x10", "ret"]],
            "arm": [["lsl r0, r0, r1", "lsr r0, r0, #32", "bx lr"]],
        }
        for architecture, cases in fixtures.items():
            for index, texts in enumerate(cases):
                rows = _rows(architecture, texts)
                for row in rows:
                    if row["mnemonic"] in {"jmp", "jne", "b.eq"}:
                        target = int(row["operands"][0], 0)
                        row["branch_info"] = {"kind": "jump", "target": target, "conditional": row["mnemonic"] != "jmp"}
                    if row["mnemonic"] == "call":
                        row["branch_info"] = {"kind": "call", "target": int(row["operands"][0], 0), "conditional": False}
                function = fn(*rows, name=f"placeholders_{architecture}_{index}", pseudoc_context={"kind": "elf"})
                output = generate_pseudoc(function, architecture, style="readable")
                with self.subTest(architecture=architecture, texts=texts):
                    _syntax_check(pseudoc_prelude(output) + "\n" + output.pseudoc + "\n")


if __name__ == "__main__":
    unittest.main()
