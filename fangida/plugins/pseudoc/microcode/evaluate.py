"""Bitvector expression evaluation; no source bytes or assembly interpreter."""
from __future__ import annotations

from collections.abc import Mapping
import math
import struct

from .ir import POINTER_AUTH_OPCODES, Expression
from .lane_ops import LANE_OPCODES, PERMUTE_OPCODES, evaluate_lanes, evaluate_permute


class UnknownValue(ValueError):
    """Insufficient evidence, undefined result or an effectful operation."""


def signed(value: int, width: int) -> int:
    value &= (1 << width) - 1
    return value - (1 << width) if value & (1 << (width - 1)) else value


# 通用 udiv/sdiv/urem/srem 的架构语义（产生它的提升器在操作属性 division_semantics 中声明）：
# * "x86_fault"：除数为 0 或带符号商溢出（最小负数 / -1）时机器陷入（#DE），没有结果——与不声明时相同；
# * "arm_zero"：AArch64/AArch32 UDIV/SDIV 语义——除数为 0 商为 0、最小负数 / -1 商为最小负数（不陷入）；
#   取余按 ARM 编译器的 udiv/sdiv + msub 序列 a - (a / b) * b，除数为 0 时余数为被除数、最小负数对 -1 取余为 0。
DIVISION_SEMANTICS = frozenset({"x86_fault", "arm_zero"})
_GENERIC_DIVISION = frozenset({"udiv", "sdiv", "urem", "srem"})


def declared_division_semantics(source) -> str:
    """规范化的除法语义声明：source 为操作属性（映射）或声明字符串；无声明或不认识时返回空串（默认陷入）。"""
    if isinstance(source, Mapping):
        source = source.get("division_semantics")
    return source if isinstance(source, str) and source in DIVISION_SEMANTICS else ""


def evaluate_expression(expression: Expression | dict, values: Mapping[str, int | float] | None = None,
                        *, division_semantics: str | None = None) -> int | float:
    """求值位向量表达式。division_semantics（可选）为所在操作声明的除法语义（见 DIVISION_SEMANTICS），
    作用于其中没有逐节点声明（表达式 name 字段）的通用 udiv/sdiv/urem/srem；不传时保持默认（陷入即未知）。"""
    expr = Expression.from_dict(expression) if isinstance(expression, dict) else expression
    if not 1 <= expr.width <= 512:
        raise ValueError("Invalid expression width")
    values = {} if values is None else values
    mask, opcode = (1 << expr.width) - 1, expr.opcode
    if opcode == "constant":
        return int(expr.value) & mask
    if opcode == "float_constant":
        return float(expr.value)
    if opcode == "register":
        if expr.name not in values:
            raise UnknownValue(f"Unknown register: {expr.name}")
        return int(values[expr.name]) & mask
    if opcode == "float_register":
        if expr.name not in values:
            raise UnknownValue(f"Unknown floating register: {expr.name}")
        return float(values[expr.name])
    if opcode in {"load", "unknown", "call", "address"}:
        raise UnknownValue(f"Cannot evaluate effectful/symbolic operation: {opcode}")
    if opcode == "system_register":
        # 系统寄存器读取（mrs）：只有调用方给出该寄存器的值（以寄存器名为键）时才能求值。
        if expr.name not in values:
            raise UnknownValue(f"Unknown system register: {expr.name}")
        return int(values[expr.name]) & mask
    if opcode in POINTER_AUTH_OPCODES:
        raise UnknownValue("Pointer authentication depends on keys and PAuth configuration")
    if opcode in {"signed_to_float", "unsigned_to_float", "float_to_signed", "float_to_unsigned", "float_resize"}:
        raise UnknownValue("Floating conversion requires architecture rounding/exception state")
    if division_semantics is None:
        args = [evaluate_expression(arg, values) for arg in expr.args]
    else:
        args = [evaluate_expression(arg, values, division_semantics=division_semantics) for arg in expr.args]
    if opcode in {"fadd", "fsub", "fmul", "fdiv"}:
        left, right = map(float, args)
        if opcode == "fdiv" and right == 0:
            # IEEE exceptions/rounding depend on FP control state.
            raise UnknownValue("Floating division needs FP control/exception state")
        # 直接分支计算，避免每次调用构造四个 lambda 的字典（结果相同）。
        if opcode == "fadd":
            result = left + right
        elif opcode == "fsub":
            result = left - right
        elif opcode == "fmul":
            result = left * right
        else:
            result = left / right
        if expr.width == 32:
            try:
                result = struct.unpack("<f", struct.pack("<f", result))[0]
            except OverflowError:
                result = math.copysign(math.inf, result)
        return result
    args = [int(arg) for arg in args]
    if opcode in {"zext", "truncate"}:
        return args[0] & mask
    if opcode == "sext":
        return signed(args[0], expr.args[0].width) & mask
    if opcode == "extract":
        return (args[0] >> int(expr.value or 0)) & mask
    if opcode == "insert":
        shift = int(expr.value or 0)
        inserted_mask = ((1 << expr.args[1].width) - 1) << shift
        return ((args[0] & ~inserted_mask) | (args[1] << shift)) & mask
    if opcode == "select":
        return args[1 if args[0] else 2] & mask
    if opcode == "not":
        return ~args[0] & mask
    if opcode == "neg":
        return -args[0] & mask
    if opcode in {"add", "sub", "mul", "and", "or", "xor"}:
        left, right = args
        if opcode == "add":
            return (left + right) & mask
        if opcode == "sub":
            return (left - right) & mask
        if opcode == "mul":
            return (left * right) & mask
        if opcode == "and":
            return (left & right) & mask
        if opcode == "or":
            return (left | right) & mask
        return (left ^ right) & mask
    if opcode in {"shl", "lshr", "ashr", "rol", "ror"}:
        left, count = args
        if count < 0:
            raise UnknownValue("Negative shift count")
        if opcode in {"rol", "ror"}:
            count %= expr.width
            if not count:
                return left & mask
            return (((left << count) | (left >> (expr.width - count))) if opcode == "rol" else
                    ((left >> count) | (left << (expr.width - count)))) & mask
        if count >= expr.width:
            return mask if opcode == "ashr" and signed(left, expr.width) < 0 else 0
        return ((left << count) if opcode == "shl" else
                (signed(left, expr.width) >> count) if opcode == "ashr" else (left >> count)) & mask
    if opcode in {"udiv", "sdiv", "urem", "srem", "arm_udiv", "arm_sdiv"}:
        left, right = args
        # 架构语义：arm_* 专用 opcode，或通用 udiv/sdiv/urem/srem 声明了 "arm_zero"（逐节点声明在表达式 name
        # 字段，优先；否则取所在操作的 division_semantics）时按 ARM 语义（除数为 0 商为 0，最小负数除以 -1
        # 不溢出；取余为 a - (a / b) * b，除数为 0 时得被除数）；"x86_fault" 与不声明相同：除数为 0、带符号
        # 溢出时机器陷入，求值为“未知”，与渲染成会 __builtin_trap() 的辅助函数一致。
        declared = expr.name if expr.name in DIVISION_SEMANTICS else (division_semantics or "")
        arm = opcode.startswith("arm_") or (opcode in _GENERIC_DIVISION and declared == "arm_zero")
        operation = opcode.removeprefix("arm_")
        if operation.startswith("s"):
            left, right = signed(left, expr.width), signed(right, expr.width)
        if right == 0:
            if arm:
                # ARM：商为 0；余数 a - 0 * b 即被除数。
                return left & mask if operation.endswith("rem") else 0
            raise UnknownValue("Division by zero")
        quotient = abs(left) // abs(right)
        if (left < 0) != (right < 0):
            quotient = -quotient
        if operation.startswith("s") and not -(1 << (expr.width - 1)) <= quotient < (1 << (expr.width - 1)) and not arm:
            raise UnknownValue("Signed division overflow")
        return (left - quotient * right if opcode.endswith("rem") else quotient) & mask
    if opcode == "bswap":
        if expr.width % 8:
            raise UnknownValue("Byte swap requires byte-aligned width")
        return int.from_bytes(args[0].to_bytes(expr.width // 8, "little"), "big")
    if opcode in LANE_OPCODES:
        # 按通道的 SIMD 整数运算（见 lane_ops.py）。
        return evaluate_lanes(opcode, expr.width, args, tuple(arg.width for arg in expr.args)) & mask
    if opcode in PERMUTE_OPCODES:
        # 跨通道重排与饱和打包（pshufb、packss/packus，见 lane_ops.py）。
        return evaluate_permute(opcode, expr.width, args, tuple(arg.width for arg in expr.args)) & mask
    raise UnknownValue(f"Unsupported micro-operation: {opcode}")


def integer_flags(family: str, operation: str, left: int, right: int, width: int,
                  *, carry: int = 0) -> dict[str, bool]:
    """Compute fixed-width add/sub flags; ARM subtraction uses no-borrow C."""
    if family not in {"x86", "arm"} or operation not in {"add", "sub"} or not 1 <= width <= 128:
        raise ValueError("Invalid integer flag operation")
    mask, sign = (1 << width) - 1, 1 << (width - 1)
    left, right = left & mask, right & mask
    raw = left + right + carry if operation == "add" else left - right - carry
    result = raw & mask
    carry_flag = raw > mask if operation == "add" else raw < 0
    signed_raw = signed(left, width) + signed(right, width) + carry if operation == "add" else signed(left, width) - signed(right, width) - carry
    overflow = not -sign <= signed_raw < sign
    if family == "arm":
        return {"N": bool(result & sign), "Z": result == 0,
                "C": carry_flag if operation == "add" else not carry_flag, "V": overflow}
    return {"SF": bool(result & sign), "ZF": result == 0, "CF": carry_flag, "OF": overflow,
            "PF": (result & 0xff).bit_count() % 2 == 0,
            "AF": bool((left ^ right ^ result) & 0x10)}


def floating_flags(family: str, left: float, right: float) -> dict[str, bool]:
    unordered = math.isnan(left) or math.isnan(right)
    if family == "x86":
        return {"ZF": unordered or left == right, "CF": unordered or left < right,
                "PF": unordered, "OF": False, "SF": False, "AF": False}
    if family == "arm":
        return {"N": not unordered and left < right, "Z": not unordered and left == right,
                "C": unordered or left >= right, "V": unordered}
    raise ValueError("Unknown floating flag family")


def logic_flags(family: str, result: int, width: int, *, previous=None, arm32=False) -> dict[str, bool | None]:
    result &= (1 << width) - 1
    negative = bool(result & (1 << (width - 1)))
    if family == "x86":
        return {"ZF": result == 0, "SF": negative, "PF": (result & 0xff).bit_count() % 2 == 0,
                "CF": False, "OF": False, "AF": None}
    if family == "arm":
        previous = previous or {}
        return {"N": negative, "Z": result == 0,
                "C": previous.get("C") if arm32 else False, "V": previous.get("V") if arm32 else False}
    raise ValueError("Unknown logic flag family")
