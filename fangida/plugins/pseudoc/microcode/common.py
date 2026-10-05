"""Shared semantic operand and effect helpers for category-specific lifters."""
from __future__ import annotations

import re
from collections.abc import Mapping
from functools import lru_cache
from typing import Any

from .ir import Expression, MicroOperation, LiftedInstruction, constant

# 预编译：与原先 re.fullmatch 的字符串模式一致（无标志位）。
_IMMEDIATE = re.compile(r"-?(?:0x[0-9a-fA-F]+|[0-9]+)")
_FLAG_READERS = frozenset({"select", "set_condition", "carry_input", "rotate_carry"})


@lru_cache(maxsize=1024)
def _register_value(bits: int, root: str, register_bits: int, shift: int) -> Expression:
    # 纯函数：寄存器读取表达式只由存储宽度与寄存器切片决定；Expression 不可变，可共享。
    if root == "zero":
        return constant(0, register_bits)
    source = Expression("register", bits, name=root)
    return (source if register_bits == bits else
            Expression("extract", register_bits, (source,), value=shift))


@lru_cache(maxsize=16384)
def _immediate_value(raw: str, width: int) -> Expression:
    return constant(int(raw, 16 if "0x" in raw.lower() else 10), width)


def value(op, operand: str, width: int | None = None) -> Expression:
    register = op.register(operand)
    if register is not None:
        bits = op.bits
        root, register_bits, shift = register.root, register.bits, register.shift
        if (type(bits) is int and type(root) is str and type(register_bits) is int and type(shift) is int):
            return _register_value(bits, root, register_bits, shift)
        if root == "zero":
            return constant(0, register_bits)
        source = Expression("register", bits, name=root)
        return (source if register_bits == bits else
                Expression("extract", register_bits, (source,), value=shift))
    raw = operand.lstrip("#$").strip()
    if _IMMEDIATE.fullmatch(raw):
        immediate_width = width or op.bits
        if type(immediate_width) is int and type(raw) is str:
            return _immediate_value(raw, immediate_width)
        return constant(int(raw, 16 if "0x" in raw.lower() else 10), immediate_width)
    if "[" in operand:
        return Expression("load", op.width(operand, width),
                          (Expression("address", op.bits, name=op.address(operand)),))
    raise ValueError("Unsupported semantic operand")


def resize(expression: Expression, width: int, *, signed: bool = False) -> Expression:
    if expression.width == width:
        return expression
    return Expression("truncate" if expression.width > width else "sext" if signed else "zext", width, (expression,))


def assignment(op, destination: str, expression: Expression, *, opcode: str = "assign") -> MicroOperation:
    register = op.register(destination)
    if register is None:
        return MicroOperation("store", op.width(destination, expression.width),
            (Expression("address", op.bits, name=op.address(destination)), expression),
            attributes={"effect": "write", "endianness": "architecture"})
    expression = resize(expression, register.bits)
    attributes = {"destination_width": register.bits, "storage_width": op.bits,
                  "bit_offset": register.shift, "zero_upper": register.bits == 32 and op.bits == 64}
    if register.root == "zero":
        return MicroOperation("discard", register.bits, (expression,))
    return MicroOperation(opcode, register.bits, (expression,), register.root, expression, attributes)


def roots(expressions: tuple[Expression, ...]) -> tuple[str, ...]:
    result = set()
    def visit(expr):
        if expr.opcode in {"register", "float_register"}:
            result.add(expr.name)
        for arg in expr.args:
            visit(arg)
    for expression in expressions:
        visit(expression)
    return tuple(sorted(result))


def _collect(expr: Expression, names: set) -> bool:
    """One walk: add register roots to *names*; report whether a load occurs."""
    opcode = expr.opcode
    load = opcode == "load"
    if opcode == "register" or opcode == "float_register":
        names.add(expr.name)
    for arg in expr.args:
        if _collect(arg, names):
            load = True
    return load


# 快照寄存器名（Capstone 的 regs_access 结果）到 microcode 寄存器根的规范化。
# 只产出 microcode 已使用的根：通用寄存器、sp、flags，以及 x86 xmmN / AArch64 vN 向量根；
# 程序计数器、零寄存器、段/系统/x87/MMX/AArch32 VFP 等未建模的寄存器不计入。
_SNAPSHOT_FLAGS = {"x86": frozenset({"rflags", "eflags", "flags"}), "arm64": frozenset({"nzcv"}),
                   "arm": frozenset({"cpsr", "apsr", "apsr_nzcv"})}
_SNAPSHOT_X86_VECTOR = re.compile(r"[xyz]mm([0-9]|[12][0-9]|3[01])")
# b/h/s/d/q/v 与 SVE 的 zN 都是同一个 V 寄存器的视图（zN 的低 128 位即 vN）。
_SNAPSHOT_A64_VECTOR = re.compile(r"[bhsdqvz]([0-9]|[12][0-9]|3[01])")
# Capstone 的 AArch32 默认语法把 r9/r10/r12 打印为 sb/sl/ip。
_SNAPSHOT_ARM_ALIASES = {"sb": "r9", "sl": "r10", "ip": "r12"}


def snapshot_root(architecture: str, op, name: Any) -> str | None:
    """单个快照寄存器名对应的 microcode 根；不建模的寄存器返回 None。"""
    if type(name) is not str:
        return None
    token = name.lower().strip()
    family = "x86" if architecture.startswith("x86") else architecture
    if token in _SNAPSHOT_FLAGS.get(family, ()):
        return "flags"
    if family == "x86":
        match = _SNAPSHOT_X86_VECTOR.fullmatch(token)
        if match:
            return "xmm" + match[1]
    elif family == "arm64":
        match = _SNAPSHOT_A64_VECTOR.fullmatch(token)
        if match:
            return "v" + match[1]
    elif family == "arm":
        token = _SNAPSHOT_ARM_ALIASES.get(token, token)
    register = op.register(token)
    if register is None or register.root == "zero":
        return None
    return register.root


def snapshot_roots(architecture: str, op, names: Any) -> tuple[str, ...]:
    """快照 reads/writes 列表规范化后的根（排序、去重）；非列表输入视为空。"""
    if not isinstance(names, (list, tuple)):
        return ()
    roots = {snapshot_root(architecture, op, name) for name in names}
    roots.discard(None)
    return tuple(sorted(roots))


def lifted(context, row: Mapping[str, Any], category: str, statements: list[str],
           operations: list[MicroOperation], *, flag_effect: str = "preserve",
           memory_effect: str | None = None, supported: bool = True,
           extra_reads: tuple[str, ...] = (), extra_writes: tuple[str, ...] = ()) -> LiftedInstruction:
    # extra_reads/extra_writes（可选）：额外并入的寄存器根下界，例如 opaque 回退时来自指令快照的读写集。
    # 单次遍历操作列表：同时收集寄存器根、是否含 load、输出与属性副作用
    # （原实现分别遍历 4 次并对输入递归两次）；reads/writes 最终排序输出，
    # 集合插入顺序不影响结果。
    reads: set = set()
    writes: set = set()
    has_load = reads_flags = has_store = False
    for operation in operations:
        for expr in operation.inputs:
            if _collect(expr, reads):
                has_load = True
        output = operation.output
        if output is not None:
            writes.add(output)
        attributes = operation.attributes
        if attributes or type(attributes) is not dict:
            writes.update(attributes.get("outputs", ()))
            reads.update(attributes.get("preserved_inputs", ()))
            if attributes.get("exceptions") == "fp_environment" or attributes.get("rounding") == "fp_environment":
                reads.add("fp_environment")
        opcode = operation.opcode
        if opcode in _FLAG_READERS or (opcode == "branch" and attributes.get("uses_flags")):
            reads_flags = True
        elif opcode == "store":
            has_store = True
    operands = getattr(context, "current_operands", None)
    if operands is not None:
        reads.update(operands.reads)
        writes.update(operands.writes)
    if extra_reads:
        reads.update(extra_reads)
    if extra_writes:
        writes.update(extra_writes)
    if flag_effect != "preserve":
        writes.add("flags")
        context.flags = True
    if reads_flags:
        reads.add("flags")
    if memory_effect is None:
        memory_effect = "read_write" if has_load and has_store else "read" if has_load else "write" if has_store else "none"
    return LiftedInstruction(row["addr"], row["size"], str(row["mnemonic"]), context.architecture,
        category, tuple(operations), tuple(statements), tuple(sorted(reads)), tuple(sorted(writes)),
        flag_effect, memory_effect, supported)


def binary(opcode: str, width: int, left: Expression, right: Expression) -> Expression:
    return Expression(opcode, width, (resize(left, width), resize(right, width)))
