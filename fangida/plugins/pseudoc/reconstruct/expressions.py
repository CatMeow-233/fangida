"""Typed source expressions and safe parsing of saved address expressions."""
from __future__ import annotations

import ast
from dataclasses import replace

from .model import Value
from .stack import parse_address, _address_tree
from .types import integer_type
from ..microcode.evaluate import DIVISION_SEMANTICS
from ..microcode.ir import IMPURE_OPCODES, POINTER_AUTH_OPCODES
from ..microcode.lane_ops import LANE_OPCODES, PERMUTE_OPCODES

# 可读 C 中渲染为整数原型辅助调用的微码 opcode（pacia_64(p, m)、vec_add32_128(a, b)…，原型见
# docs/microcode.md“新增表达式与辅助名”）；其中可能陷入的（aut*：FEAT_FPAC 下认证失败会陷入）
# 即使结果无人使用也不能删除。
_INTEGER_HELPERS = POINTER_AUTH_OPCODES | frozenset(LANE_OPCODES) | frozenset(PERMUTE_OPCODES)
_TRAPPING_HELPERS = _INTEGER_HELPERS & IMPURE_OPCODES
# 前导（prelude.py）为这些宽度定义了标量辅助函数 shl_W/lshr_W/ashr_W/rol_W/ror_W。
_HELPER_WIDTHS = frozenset({8, 16, 32, 64, 128})
# 写成 C 运算符或前导辅助函数的标量运算；被推断为指针的操作数显式转为整数（地址不变）。
_SCALAR_OPERATIONS = frozenset({"ashr", "rol", "ror", "bswap", "udiv", "urem", "sdiv", "srem", "arm_udiv", "arm_sdiv"})
_UNSIGNED_DIVISION = {"udiv": "/", "urem": "%"}
_SIGNED_DIVISION = {"sdiv": "/", "srem": "%"}


def cast(value, ctype, width):
    if value.ctype == ctype:
        return value
    if value.op == "cast" and value.args[0].ctype == ctype and value.width >= width and value.args[0].width == width:
        return value.args[0]
    return Value("cast", width, (value,), ctype=ctype)


def byte_address(value, bits):
    if "*" in value.ctype:
        return cast(value, "uintptr_t", bits)
    return replace(value, args=tuple(byte_address(arg, bits) for arg in value.args))


def format_value(value):
    """把源码表达式渲染为 C 文本：按 C 优先级只加必要的括号，常量按用途选十/十六进制。

    结果仍是可编译的 C：位运算/移位与算术混用、逻辑与/或混用时保留括号（也避免
    -Wparentheses 告警）；窄于 32 位的算术先显式转为 uint32_t，避免 C 的整型提升
    把无符号运算变成有符号溢出。
    """
    return _format(value)[0]


# C 运算符优先级（数值越大结合越紧）。
_PRIMARY, _UNARY = 16, 15
_NEGATIVE_LITERAL = 12
_BINARY = {"mul": ("*", 13), "add": ("+", 12), "sub": ("-", 12), "shl": ("<<", 11), "lshr": (">>", 11),
           "and": ("&", 8), "xor": ("^", 7), "or": ("|", 6)}
_COMPARISON = {"<": 10, "<=": 10, ">": 10, ">=": 10, "==": 9, "!=": 9}
_LOGICAL = {"logical_and": ("&&", 5), "logical_or": ("||", 4)}
_SELECT = 3
_ARITHMETIC = frozenset({"add", "sub", "mul"})
_BITWISE = frozenset({"and", "or", "xor"})
# 窄于 32 位时按 C 整数提升计算、结果只有 W 位的运算：渲染后必须截回原宽度，否则高位会外泄。
_NARROW_ARITH = frozenset({"add", "sub", "mul", "neg", "not"})
# 传给“同宽度窄算术子表达式”的提示：其截回由外层统一完成（模 2^W 下加/减/乘/取反/取非可结合），
# 避免链式窄算术每一层都加 (uintW_t) 转换。只在确实是同宽度窄算术子表达式时传入，不会落到常量上。
_NARROW_DEFER = "__narrow_defer__"
_ELEMENT_BYTES = {"char": 1, "int8_t": 1, "uint8_t": 1, "int16_t": 2, "uint16_t": 2, "int32_t": 4, "uint32_t": 4,
                  "int64_t": 8, "uint64_t": 8}
# 这些调用的首个实参是代码/数据地址，总用十六进制显示。
_ADDRESS_CALLS = frozenset({"tail_transfer", "unresolved_fallthrough", "handler_dependent_value"})
_ESCAPES = {"\n": "\\n", "\t": "\\t", "\r": "\\r", "\a": "\\a", "\b": "\\b", "\f": "\\f", "\v": "\\v",
            "\"": "\\\"", "\\": "\\\\"}


def c_string_literal(text):
    """C 字符串字面量：常见转义、其余控制字符用三位八进制（不会吞掉后续字符），保留可打印的非 ASCII 字符。"""
    out, previous = ['"'], ""
    for character in text:
        code = ord(character)
        if character in _ESCAPES:
            out.append(_ESCAPES[character])
        elif character == "?" and previous == "?":
            out.append("\\?")  # 避免三字符组（trigraph）
        elif 0x20 <= code < 0x7f or (code >= 0x80 and character.isprintable()):
            out.append(character)
        elif code < 0x100:
            out.append(f"\\{code:03o}")
        else:
            out.append(f"\\U{code:08x}")
        previous = character
    out.append('"')
    return "".join(out)


def _prefer_hex(number, hint):
    if number <= 9:
        return False
    if hint in {"bitwise", "address"}:
        return True
    if hint == "count" or number < 256:
        return False
    # 较小的整百数（100、1000、3600…）与整百万数按十进制更自然；地址等大数一律十六进制。
    if number < 100000 and number % 100 == 0 and number % 256:
        return False
    return not (number % 1000000 == 0 and number < 10 ** 12)


def format_number(number, width=64, hint=None):
    """整数常量文本：小整数十进制；掩码/地址/较大常量十六进制；负数带符号；超出 int 范围加 U/ULL。"""
    if type(number) is not int:
        return str(number)
    if number < 0:
        magnitude = -number
        if width and magnitude == 1 << (width - 1) or not _prefer_hex(magnitude, hint):
            return str(number)
        return "-" + hex(magnitude)
    text = hex(number) if _prefer_hex(number, hint) else str(number)
    if number > 0x7fffffff:
        text += "ULL" if width > 32 else "U"
    return text


def _signed_constant(value):
    """常量按其宽度解释为有符号数（无符号类型的高位置位视为负数）。"""
    number, width = value.number, value.width
    if type(number) is not int or not width or width < 32:
        return None
    if number >= 1 << (width - 1):
        number -= 1 << width
    return number


def _wide_constant(value):
    """超出 64 位字面量范围的 128 位常量：C 没有这种字面量，用高低两个 64 位半拼出（值不变）。"""
    number = value.number % (1 << value.width)
    text = f"(((__uint128_t){hex(number >> 64)}ULL << 64) | {hex(number & ((1 << 64) - 1))}ULL)"
    return f"((__int128_t){text})" if (value.ctype or "").startswith("__int128") else text


def _unsigned_literal(value, text, width):
    """左移的常量左操作数：非负、能用后缀表示时写成 1U / 1ULL，其余（负数、128 位）显式转换为 uintW_t。"""
    number = value.number
    if type(number) is int and 0 <= number < 1 << 64 and width in {32, 64} and not text.startswith("("):
        suffix = "U" if width == 32 else "ULL"
        return text if text.endswith(("U", "ULL")) and (width == 32) == (not text.endswith("ULL")) else text.rstrip("UL") + suffix
    return _cast_text(integer_type(width), value, "bitwise")


def _wrap(text, precedence, minimum):
    return text if precedence >= minimum else f"({text})"


def _operand(value, parent_op, parent_precedence, side, hint=None):
    text, precedence = _format(value, hint)
    child_op = value.op
    if precedence > parent_precedence:
        # 优先级足够时，位运算/移位与其它二元运算混用仍加括号，便于阅读。
        if precedence < _UNARY and child_op in _BINARY and (
                parent_op in _BITWISE and child_op != parent_op or
                parent_op in {"shl", "lshr"} and child_op in _ARITHMETIC | _BITWISE):
            return f"({text})"
        if parent_op == "logical_or" and child_op == "logical_and":
            return f"({text})"
        return text
    if precedence == parent_precedence and side == "left" and (child_op == parent_op or (
            child_op in _ARITHMETIC and parent_op in _ARITHMETIC) or child_op in _COMPARISON_OPS and parent_op in _COMPARISON_OPS):
        return text if child_op not in _COMPARISON_OPS else f"({text})"
    return f"({text})"


_COMPARISON_OPS = frozenset({"compare"})


def _cast_text(ctype, value, hint=None):
    text, precedence = _format(value, "address" if ctype.endswith("*") else hint)
    if precedence >= _PRIMARY or value.op == "cast":
        return f"({ctype}){text}"
    return f"({ctype})({text})"


_UNSIGNED_TYPES = {"bool": 1, "uint8_t": 8, "uint16_t": 16, "uint32_t": 32, "uint64_t": 64, "size_t": 64,
                   "uintptr_t": 64, "__uint128_t": 128}
_SIGNED_TYPES = {"int8_t": 8, "int16_t": 16, "int32_t": 32, "int64_t": 64, "__int128_t": 128}


_UINT32_MAX = (1 << 32) - 1
# 渲染结果总在其 C 类型范围内的值：声明了类型的存储（变量、内存读取），以及渲染为显式转换或调用返回
# uintW_t 的前导辅助函数（ashr/rol/ror/bswap/带符号除法/ARM 除法/按通道运算/PAC）。
_RANGED_OPS = frozenset({"variable", "load", "index", "slot_access", "ashr", "rol", "ror", "bswap", "sdiv", "srem",
                         "arm_udiv", "arm_sdiv"}) | _INTEGER_HELPERS
# 上界由操作数推出的运算（其余运算，如调用、占位 unknown_value()，无法证明）。
_DERIVED_BOUND_OPS = frozenset({"cast", "and", "or", "xor", "add", "sub", "mul", "shl", "lshr", "not", "neg", "select",
                                "udiv", "urem"})


def _count_bound(value, depth=0):
    """移位计数渲染成 C 之后的取值上界（同时证明非负）；无法证明时返回 None。

    只用于决定移位能否直接写成 C 的 <<、>>：计数已证明小于宽度时没有未定义行为，否则调用前导中
    按微码语义定义的辅助函数（计数 >= 宽度时得 0 或符号填充）。上界按 C 渲染后的实际值计算：窄于 32 位的
    加、减、乘、左移、取反、取非都截回原宽度（见 _format），因此落在 [0, 2^W)，可用其类型范围作上界；
    逻辑右移按 uint32_t 计算、不额外截回，但据被移数上界收紧；占位 unknown_value() 与外部调用返回声明的类型，
    这些仍不能用 uint8_t/uint16_t 的类型范围作上界。
    """
    if depth > 16:
        return None
    op, args, width = value.op, value.args, value.width or 0
    if op == "constant":
        return value.number if type(value.number) is int and value.number >= 0 else None
    if op in {"compare", "logical_and", "logical_or", "logical_not"}:
        return 1  # C 的比较与逻辑运算结果为 int 0/1
    if op in _RANGED_OPS:
        return _type_bound(value)
    if op not in _DERIVED_BOUND_OPS:
        return None
    bounds = [_count_bound(arg, depth + 1) for arg in args]
    if op == "cast" and args:
        ctype = value.ctype
        if ctype in _UNSIGNED_TYPES:
            limit = (1 << _UNSIGNED_TYPES[ctype]) - 1
            return limit if bounds[0] is None else min(bounds[0], limit)
        if ctype in _SIGNED_TYPES and bounds[0] is not None and bounds[0] < 1 << (_SIGNED_TYPES[ctype] - 1):
            return bounds[0]
        return None
    if op == "and" and len(args) == 2:
        known = [bound for bound in bounds if bound is not None]
        # 与非负数按位与：结果非负且不超过该数（另一侧即使是负数也一样）。
        return min(known) if known else None
    if op in {"or", "xor"} and len(args) == 2:
        return (1 << max(bounds).bit_length()) - 1 if None not in bounds else None
    if op == "select" and len(args) == 3:
        return max(bounds[1:]) if None not in bounds[1:] else None
    if op in {"udiv", "urem"} and len(args) == 2:
        # 非负数相除：商与余数都不超过被除数，余数小于正的常数除数（辅助函数 udiv_W 的结果同样如此）。
        if None in bounds:
            return None
        if op == "urem" and args[1].op == "constant" and type(args[1].number) is int and args[1].number > 0:
            return min(bounds[0], args[1].number - 1)
        return bounds[0]
    if op in {"neg", "not"} and width in {8, 16}:
        # 8/16 位的取反/取非在可读 C 中截回原宽度（见 _format），结果落在 [0, 2^W)。
        return (1 << width) - 1
    if op in {"add", "sub", "mul", "shl", "lshr"} and len(args) == 2 and width < 32:
        # 窄运算渲染为 (uint32_t)a op (uint32_t)b（见 _format）。8/16 位的加/减/乘与左移截回原宽度，
        # 结果落在 [0, 2^W)；逻辑右移不额外截回，但其被移数若是窄算术则已截回，故仍可据操作数上界收紧。
        if op in {"add", "sub", "mul", "shl"} and width in {8, 16}:
            return (1 << width) - 1
        if op == "lshr":
            left = _UINT32_MAX if bounds[0] is None else min(bounds[0], _UINT32_MAX)
            count = args[1]
            return left >> min(count.number, 128) if count.op == "constant" and type(count.number) is int and count.number >= 0 else left
        left, right = (_UINT32_MAX if bound is None else min(bound, _UINT32_MAX) for bound in bounds)
        if op == "add":
            return min(left + right, _UINT32_MAX)
        if op == "mul":
            return min(left * right, _UINT32_MAX)
        return _UINT32_MAX
    if op == "lshr" and len(args) == 2:
        # 逻辑右移不增大非负的被移数（计数越界时辅助函数 lshr_W 得 0）。
        if bounds[0] is None:
            return None
        count = args[1]
        return bounds[0] >> min(count.number, 128) if count.op == "constant" and type(count.number) is int and count.number >= 0 else bounds[0]
    if op in {"add", "sub", "mul", "shl", "not", "neg"} and value.ctype in _UNSIGNED_TYPES and width >= 32:
        # W >= 32 位的无符号运算（lift 把操作数转换为结果类型 uintW_t）：结果在 [0, 2^W) 内；加法不回绕时为两数之和。
        operands = args[:1] if op == "shl" else args
        if any(arg.ctype != value.ctype for arg in operands):
            return None
        limit = _type_bound(value)
        if op == "add" and None not in bounds:
            return min(sum(bounds), limit)
        return limit
    return None


def _type_bound(value):
    """按值的 C 类型给出的上界：无符号类型为 2^N - 1；带符号、指针或未知类型无法证明非负。

    只能用于渲染结果确实具有该类型的值（_RANGED_OPS 或 W >= 32 的无符号运算），见 _count_bound。
    """
    width = _UNSIGNED_TYPES.get(value.ctype)
    return (1 << width) - 1 if width else None


def _signed_operand(value, width):
    """按 width 位带符号整数解释的操作数文本（一元表达式）：已是该类型时不再重复转换。"""
    signed, unsigned = integer_type(width, True), integer_type(width)
    if value.ctype == signed:
        text, precedence = _format(value, "bitwise")
        return _wrap(text, precedence, _UNARY)
    if value.op == "cast" and value.ctype == unsigned and value.args[0].ctype == signed and value.args[0].width == width:
        text, precedence = _format(value.args[0], "bitwise")
        return _wrap(text, precedence, _UNARY)
    return _cast_text(signed, value, "bitwise")


def _helper_call(name, args, hints=()):
    texts = [_format(arg, hints[index] if index < len(hints) else None)[0] for index, arg in enumerate(args)]
    return f"{name}({', '.join(texts)})", _PRIMARY


def _shift_in_range(count, width):
    """计数已证明小于有效宽度（窄于 32 位的运算在 C 中按 32 位进行）。"""
    bound = _count_bound(count)
    return bound is not None and bound < max(width, 32)


def _defers(value, parent_width):
    """value 是与外层同宽度的窄算术子表达式（8/16 位的 add/sub/mul/neg/not）：
    其截回可以推迟到外层统一完成（模 2^W 下这些运算可结合/可分配，只在最外层截一次即可）。"""
    return value.width == parent_width and value.width in {8, 16} and value.op in _NARROW_ARITH


def _scalar_operation(value, hint):
    """ashr/rol/ror/bswap/除法：标准 C 表达式或前导中有精确定义的辅助函数；None 表示走通用回退。"""
    op, args, width = value.op, value.args, value.width
    unsigned = integer_type(width)
    if op == "ashr" and len(args) == 2 and width in _HELPER_WIDTHS:
        if _shift_in_range(args[1], width):
            # 带符号类型的右移（GCC/Clang 为算术右移）；计数已证明在范围内。
            count = _operand(args[1], "lshr", _BINARY["lshr"][1], "right", "count")
            return f"({unsigned})({_signed_operand(args[0], width)} >> {count})", _UNARY
        return _helper_call(f"ashr_{width}", args, ("bitwise", "count"))
    if op in {"rol", "ror"} and len(args) == 2 and width in _HELPER_WIDTHS:
        count, operand = args[1], args[0]
        if (count.op == "constant" and type(count.number) is int and count.number >= 0 and operand.op == "variable"
                and operand.ctype == unsigned):
            # 常数计数、操作数是变量：写成两次移位（计数取模后在 1..W-1 内，没有越界移位）。
            amount = count.number % width
            if not amount:
                return operand.name, _PRIMARY
            first, second = (">>", "<<") if op == "ror" else ("<<", ">>")
            if width < 32:
                return (f"({unsigned})((uint32_t){operand.name} {first} {amount} | "
                        f"(uint32_t){operand.name} {second} {width - amount})"), _UNARY
            return f"({operand.name} {first} {amount}) | ({operand.name} {second} {width - amount})", _BINARY["or"][1]
        return _helper_call(f"{op}_{width}", args, ("bitwise", "count"))
    if op == "bswap" and len(args) == 1:
        if width in {16, 32, 64}:
            return _helper_call(f"__builtin_bswap{width}", args, ("bitwise",))
        if width == 128:
            return _helper_call("bswap_128", args, ("bitwise",))
        return None
    if op in _UNSIGNED_DIVISION and len(args) == 2:
        if width in _HELPER_WIDTHS and not _safe_divisor(args[1], width, False):
            # 除数可能为 0（C 的 / 、% 未定义）：声明了 ARM 语义（division_semantics="arm_zero"）时调用
            # arm_udiv_W/arm_urem_W（除数为 0 商为 0、余数为被除数），否则调用除数为 0 时陷入的 udiv_W/urem_W
            # （"x86_fault" 与不声明相同）；两者都与 evaluate 一致。除数是非零常数时各语义相同，写成运算符。
            return _helper_call(f"arm_{op}_{width}" if value.name == "arm_zero" else f"{op}_{width}", args)
        operator = _UNSIGNED_DIVISION[op]
        left = _operand(args[0], op, _BINARY["mul"][1], "left")
        right = _operand(args[1], op, _BINARY["mul"][1], "right")
        return f"{left} {operator} {right}", _BINARY["mul"][1]
    if op in _SIGNED_DIVISION and len(args) == 2 and width in _HELPER_WIDTHS:
        if not _safe_divisor(args[1], width, True):
            # 除数可能为 0 或 -1（最小负数 / -1 溢出）：声明了 ARM 语义时调用 arm_sdiv_W/arm_srem_W（不陷入），
            # 否则调用除数为 0 或带符号溢出时陷入的 sdiv_W/srem_W。
            return _helper_call(f"arm_{op}_{width}" if value.name == "arm_zero" else f"{op}_{width}", args)
        operator = _SIGNED_DIVISION[op]
        return f"({unsigned})({_signed_operand(args[0], width)} {operator} {_signed_operand(args[1], width)})", _UNARY
    return None


_SIGNED_CTYPES = frozenset({"int8_t", "int16_t", "int32_t", "int64_t", "__int128_t", "char", "signed char",
                            "short", "int", "long", "long long"})


def _signed_value(value):
    """值的 C 类型是否为带符号整数：扩展到更宽类型时 C 做符号扩展。"""
    return value.ctype in _SIGNED_CTYPES


def unsigned_arms(arms, width):
    """条件选择的两臂：带符号类型的臂转为 width 位无符号类型。

    C 的 c ? a : b 按两臂的通常算术转换取结果类型；一臂为带符号类型时结果可能是负的 int，再扩展到更宽的
    类型（存入 64 位变量、作实参/返回值）就会符号扩展，而微码 select 只有 W 位、零扩展。两臂都转为
    uintW_t 后结果非负，与微码逐位一致。"""
    unsigned = integer_type(width)
    return tuple(cast(arm, unsigned, width) if _signed_value(arm) else arm for arm in arms)


def _safe_divisor(divisor, width, signed):
    """除数是非零常数（带符号除法还要求不是 -1）：此时 C 的 / 、% 没有未定义行为，可以直接写运算符。"""
    if divisor.op != "constant" or type(divisor.number) is not int:
        return False
    number = divisor.number % (1 << width)
    return number != 0 and not (signed and number == (1 << width) - 1)


def _format(value, hint=None):
    """(文本, 优先级)。"""
    op, args = value.op, value.args
    if op in {"variable", "global", "function"}:
        return value.name, _PRIMARY
    if op == "constant":
        if type(value.number) is int and value.width > 64 and not -(1 << 63) <= value.number < 1 << 64:
            return _wide_constant(value), _PRIMARY
        text = format_number(value.number, value.width, hint)
        return text, _NEGATIVE_LITERAL if text.startswith("-") else _PRIMARY
    if op == "string_literal":
        # PE 宽字符串（UTF-16LE）写成 L"..."。
        return ("L" if value.ctype == "const wchar_t *" else "") + c_string_literal(value.name), _PRIMARY
    if op == "unknown":
        return "unknown_value()", _PRIMARY
    if op == "cast":
        return _cast_text(value.ctype, args[0], hint), _UNARY
    if op in {"shl", "lshr"} and len(args) == 2 and value.width in _HELPER_WIDTHS and not _shift_in_range(args[1], value.width):
        # 计数可能 >= 宽度（如 AArch32 寄存器移位取 Rs 低 8 位、LSR #32）：C 的 <<、>> 此时未定义，
        # 改为调用前导中按微码语义定义的 shl_W/lshr_W（计数 >= 宽度时结果为 0）。
        return _helper_call(f"{op}_{value.width}", args, ("bitwise", "count"))
    if op in _SCALAR_OPERATIONS:
        rendered = _scalar_operation(value, hint)
        if rendered is not None:
            return rendered
    if op in _BINARY:
        operator, precedence = _BINARY[op]
        # 算术运算的操作数不继承“地址”提示：p + 52 中的 52 是偏移量。
        left_hint = "bitwise" if op in _BITWISE or op in {"shl", "lshr"} else None
        right_hint = "count" if op in {"shl", "lshr"} else "bitwise" if op in _BITWISE else None
        if value.width < 32 and op in {"add", "sub", "mul", "shl", "lshr"}:
            # C promotes uint16_t to signed int: multiplication and shifts
            # can otherwise overflow before the final narrowing conversion.
            left_defer = _NARROW_DEFER if op in _ARITHMETIC and _defers(args[0], value.width) else left_hint
            right_defer = _NARROW_DEFER if op in _ARITHMETIC and _defers(args[1], value.width) else right_hint
            text = f"{_cast_text('uint32_t', args[0], left_defer)} {operator} {_cast_text('uint32_t', args[1], right_defer)}"
            if op == "shl" and value.width in {8, 16}:
                # 微码左移的结果只有 W 位：按 32 位移位后截回 W 位（否则并入部分寄存器、参与比较等更宽的
                # 上下文时，移出 W 位的高位会外泄；计数已证明 < 32，见上面的范围检查）。
                return f"({integer_type(value.width)})({text})", _UNARY
            if op in _ARITHMETIC and value.width in {8, 16}:
                # 微码加/减/乘的结果只有 W 位：按 uint32_t 算完后截回原宽度，否则溢出/借位的高位会外泄到
                # 对高位敏感的上下文（比较、右移、扩展、存入更宽变量、作实参/返回值、指针运算、移位计数等）。
                # 作为同宽度窄算术的直接子表达式时由外层统一截回（见 _NARROW_DEFER），不重复转换。
                if hint == _NARROW_DEFER:
                    return text, precedence
                return f"({integer_type(value.width)})({text})", _UNARY
            return text, precedence
        right = args[1]
        if op in {"add", "sub"} and right.op == "constant":
            signed = _signed_constant(right)
            if signed is not None and signed < 0 and signed != -(1 << (right.width - 1)):
                # x + 0xff..fb 与 x - 5 在无符号模运算（宽度 >= 32）下相同。
                operator = "-" if op == "add" else "+"
                left = _operand(args[0], op, precedence, "left", left_hint)
                return f"{left} {operator} {format_number(-signed, right.width, right_hint)}", precedence
        if op in {"add", "sub"} and right.op == "neg" and right.args[0].op == "constant" and type(right.args[0].number) is int and right.args[0].number >= 0:
            # x + -(c) 写作 x - c（模运算下相同）。
            operator = "-" if op == "add" else "+"
            left = _operand(args[0], op, precedence, "left", left_hint)
            return f"{left} {operator} {format_number(right.args[0].number, right.args[0].width, right_hint)}", precedence
        left = _operand(args[0], op, precedence, "left", left_hint)
        if op == "shl" and args[0].op == "constant" and value.width in _HELPER_WIDTHS:
            # a << n 的结果类型是 a 提升后的类型：常量左操作数写成 int 字面量时，结果是 int（1 << 31 溢出是
            # 未定义行为，64 位的 1 << 40 更是按 int 计算）。写成该宽度的无符号常量（1U、1ULL）。
            left = _unsigned_literal(args[0], left, value.width)
        right_text = _operand(right, op, precedence, "right", right_hint)
        return f"{left} {operator} {right_text}", precedence
    if op in {"neg", "not", "logical_not"}:
        symbol = "-" if op == "neg" else "~" if op == "not" else "!"
        narrow = op in {"neg", "not"} and value.width in {8, 16}
        # neg 的操作数继承父提示（去掉截回标记）；not 的操作数按位运算显示常量。
        base_hint = "bitwise" if op == "not" else (None if hint == _NARROW_DEFER else hint)
        inner_hint = _NARROW_DEFER if narrow and _defers(args[0], value.width) else base_hint
        text, precedence = _format(args[0], inner_hint)
        rendered = symbol + _wrap(text, precedence, _PRIMARY)
        if narrow and hint != _NARROW_DEFER:
            # 窄位宽的取反/取非在 C 中按 int 计算（~y、-y 可能是更宽的值甚至为负）：截回原宽度。
            return f"({integer_type(value.width)})({rendered})", _UNARY
        return rendered, _UNARY
    if op == "compare":
        precedence = _COMPARISON.get(value.name, 9)
        left = _operand(args[0], op, precedence, "left")
        right = _operand(args[1], op, precedence, "right")
        return f"{left} {value.name} {right}", precedence
    if op in _LOGICAL:
        operator, precedence = _LOGICAL[op]
        left = _operand(args[0], op, precedence, "left")
        right = _operand(args[1], op, precedence, "right")
        return f"{left} {operator} {right}", precedence
    if op == "select":
        condition, condition_precedence = _format(args[0])
        condition = condition if condition_precedence >= 9 else f"({condition})"
        true, true_precedence = _format(args[1], hint)
        false, false_precedence = _format(args[2], hint)
        return f"{condition} ? {_wrap(true, true_precedence, _SELECT + 1)} : {_wrap(false, false_precedence, _SELECT + 1)}", _SELECT
    if op == "load":
        address = args[0]
        if address.op == "cast" and address.args and address.args[0].op == "constant" and address.ctype.endswith("*"):
            address = address.args[0]  # *(uint32_t *)((uint64_t *)0x1000) 与 *(uint32_t *)0x1000 相同
        pointer, precedence = _format(address, "address")
        return f"*({integer_type(value.width)} *){_wrap(pointer, precedence, _PRIMARY)}", _UNARY
    if op == "index":
        if (args[0].op == "cast" and args[0].args and args[0].args[0].op == "constant" and args[0].ctype.endswith("*")
                and type(args[0].args[0].number) is int and args[1].op == "constant" and type(args[1].number) is int):
            # ((T *)0x1000)[k] 写作 *(T *)(0x1000 + k * sizeof(T))（固定地址的读写）。
            size = _ELEMENT_BYTES.get(args[0].ctype[:-1].strip().removeprefix("const "))
            if size is not None or args[1].number == 0:
                address = Value("constant", args[0].args[0].width, number=args[0].args[0].number + args[1].number * (size or 0))
                return f"*({args[0].ctype}){_format(address, 'address')[0]}", _UNARY
        if args[0].op == "unknown":
            # 基址是占位 unknown_value()（前导中声明为返回整数）：写成元素类型的指针再下标（只为可编译）。
            element = value.ctype if value.ctype and "*" not in value.ctype else integer_type(value.width)
            return f"(({element} *)unknown_value())[{_format(args[1])[0]}]", _PRIMARY
        base, precedence = _format(args[0], "address")
        return f"{_wrap(base, precedence, _PRIMARY)}[{_format(args[1])[0]}]", _PRIMARY
    if op == "slot_access":
        return f"*({integer_type(value.width)} *)&{value.name}[{value.number}]", _UNARY
    if op == "address_of":
        text, precedence = _format(args[0])
        return "&" + _wrap(text, precedence, _PRIMARY), _UNARY
    if op == "call":
        hints = ("address",) if value.name in _ADDRESS_CALLS else ()
        texts = [_format(arg, hints[index] if index < len(hints) else None)[0] for index, arg in enumerate(args)]
        if value.name == "handler_dependent_value" and "*" in (value.ctype or ""):
            # 占位在前导中声明为返回整数：写入指针变量时显式转换（只为可编译，不赋予语义）。
            return f"({value.ctype}){value.name}({', '.join(texts)})", _UNARY
        return f"{value.name}({', '.join(texts)})", _PRIMARY
    if op == "string":
        import json
        return json.dumps(value.name, ensure_ascii=True), _PRIMARY
    if op in LANE_OPCODES and LANE_OPCODES[op][0] == "reduce":
        # 归约的通道数由实参宽度决定（前导中的宏按实参类型的 sizeof 计算）：实参写成确切宽度的类型。
        texts = [_cast_text(integer_type(arg.width), arg) if arg.op == "constant" or arg.ctype != integer_type(arg.width)
                 else _format(arg)[0] for arg in args]
        return f"{op}_{value.width}({', '.join(texts)})", _PRIMARY
    return f"{op}_{value.width}({', '.join(_format(arg)[0] for arg in args)})", _PRIMARY


class Expressions:
    def __init__(self, variables, frame, bits):
        self.variables, self.frame, self.bits = variables, frame, bits
        self.globals = {}
        self.unresolved = []
        self.call_names = {}
        # 当前操作声明的通用除法语义（操作属性 division_semantics，见 microcode/evaluate.py）；
        # lower 在处理每条操作前设置，lift 把它交给没有逐节点声明的 udiv/sdiv/urem/srem。
        self.division_semantics = ""

    def variable(self, root):
        variable = self.variables[root]
        return Value("variable", variable.width, name=variable.name, ctype=variable.ctype)

    def frame_address(self, offset):
        slot = self.frame.slot(offset, 8)
        if not slot:
            self.unresolved.append({"kind":"stack_address_extent"})
            return Value("call", self.bits, name="unresolved_stack_address", ctype="uint8_t *", effect=True)
        storage = Value("variable", slot["size"] * 8, name=slot["name"], ctype="uint8_t *" if slot["overlap"] else integer_type(slot["size"]*8))
        base = storage if slot["overlap"] else Value("address_of",self.bits,(storage,),ctype=storage.ctype+" *")
        if offset != slot["offset"]:
            base = Value("add",self.bits,(cast(base,"uint8_t *",self.bits),Value("constant",self.bits,number=offset-slot["offset"])),ctype="uint8_t *")
        return base

    def address(self, expression):
        tree = _address_tree(expression.get("name", ""))
        def visit(node):
            if isinstance(node, ast.Name) and node.id in self.variables:
                return self.variable(node.id)
            if isinstance(node, ast.Constant) and type(node.value) is int:
                return Value("constant", self.bits, number=node.value, ctype=integer_type(self.bits))
            if isinstance(node, ast.UnaryOp):
                value = visit(node.operand)
                return Value("neg", self.bits, (value,)) if isinstance(node.op, ast.USub) else value
            if isinstance(node, ast.BinOp):
                return Value({ast.Add: "add", ast.Sub: "sub", ast.Mult: "mul"}[type(node.op)], self.bits, (visit(node.left), visit(node.right)))
            return Value("unknown", self.bits)
        return visit(tree)

    def memory(self, address, width, at):
        offset = self.frame.offset(at, address)
        slot = self.frame.slot(offset, width) if offset is not None else None
        if slot:
            if not slot["overlap"] and slot["size"] * 8 == width:
                return Value("variable", width, name=slot["name"], ctype=integer_type(width), effect=slot.get("escaped",False))
            return Value("slot_access", width, name=slot["name"], number=offset - slot["offset"], effect=slot.get("escaped",False))
        if address.get("opcode") == "add" and len(address.get("args", ())) == 2:
            base, offset = address["args"]
            if base.get("opcode") == "register" and base.get("name") in self.variables:
                pointer = self.variable(base["name"])
                size = width // 8
                index = offset if size == 1 else None
                if offset.get("opcode") == "shl" and len(offset.get("args", ())) == 2:
                    count = offset["args"][1]
                    if count.get("opcode") == "constant" and 1 << count["value"] == size:
                        index = offset["args"][0]
                if index is not None and pointer.ctype == integer_type(width) + " *":
                    return Value("index", width, (pointer, self.lift(index, at)), ctype=integer_type(width), effect=True)
        pointer = self.address(address) if address.get("opcode") == "address" else self.lift(address, at)
        if pointer.op == "constant":
            key = int(pointer.number) & ~0xfff
            name = self.globals.setdefault(key, f"global_{len(self.globals) + 1}")
            base = Value("global", self.bits, name=name, ctype="uint8_t *")
            displacement = Value("constant", self.bits, number=int(pointer.number) - key)
            return Value("index", width, (base, displacement), ctype="uint8_t", effect=True) if width == 8 else Value("load", width,
                (Value("add", self.bits, (base, displacement)),), ctype=integer_type(width), effect=True)
        if pointer.op == "variable" and pointer.ctype == integer_type(width) + " *":
            return Value("index", width, (pointer, Value("constant", width, number=0)), ctype=integer_type(width), effect=True)
        if pointer.op in {"add", "sub"}:
            base, displacement = pointer.args
            if base.ctype == integer_type(width) + " *":
                size = width // 8
                index = None
                if displacement.op == "constant" and displacement.number % size == 0:
                    index = Value("constant", self.bits, number=displacement.number // size * (-1 if pointer.op == "sub" else 1))
                if pointer.op == "add" and displacement.op == "mul" and displacement.args[1].op == "constant" and displacement.args[1].number == size:
                    index = displacement.args[0]
                if index is not None:
                    return Value("index", width, (base, index), ctype=integer_type(width), effect=True)
            # The microcode address is in bytes, while C pointer addition is
            # in elements. Retain byte units for mixed or unaligned accesses.
            pointer = byte_address(pointer, self.bits)
        elif pointer.op in {"mul", "shl", "and", "or", "xor"} and any("*" in arg.ctype for arg in pointer.args):
            # 指针参与乘法/移位/位运算在 C 中不合法：按字节地址（uintptr_t）计算，数值不变。
            pointer = byte_address(pointer, self.bits)
        return Value("load", width, (pointer,), ctype=integer_type(width), effect=True)

    def lift(self, expression, at):
        op, width = expression["opcode"], expression.get("width", self.bits)
        args = expression.get("args", ())
        ctype = integer_type(width)
        if op in {"register", "float_register"}:
            return self.variable(expression["name"]) if expression["name"] in self.variables else Value("unknown", width)
        if op in {"constant", "float_constant"}:
            return Value("constant", width, number=expression["value"], ctype="float" if expression.get("domain") == "floating" and width == 32 else "double" if expression.get("domain") == "floating" else ctype)
        if op == "address":
            offset = self.frame.offset(at, expression)
            if offset is not None:
                slot = self.frame.slot(offset, 8)
                if slot:
                    storage = Value("variable", slot["size"] * 8, name=slot["name"],
                                    ctype="uint8_t *" if slot["overlap"] else integer_type(slot["size"] * 8))
                    base = storage if slot["overlap"] else Value("address_of", self.bits, (storage,), ctype=storage.ctype + " *")
                    if offset != slot["offset"]:
                        base = Value("add", self.bits, (cast(base, "uint8_t *", self.bits), Value("constant", self.bits, number=offset - slot["offset"])), ctype="uint8_t *")
                    return base
                self.unresolved.append({"address": at, "kind": "stack_address_extent"})
                return Value("call", self.bits, name="unresolved_stack_address", ctype="uint8_t *", effect=True)
            address = self.address(expression)
            if address.op in {"add", "sub", "mul"}:
                address = byte_address(address, self.bits)
            return address
        if op == "load":
            return self.memory(args[0], width, at)
        if op == "system_register":
            # AArch64 系统寄存器读取（mrs）：写成带寄存器名的 ACLE 读取 __arm_rsr64("tpidr_el0")。
            # 计数器、FPSR 等每次读取可能不同，标为有副作用，不参与复制传播与死代码删除。
            name = Value("string_literal", name=str(expression.get("name", "")), ctype="const char *")
            return Value("call", width, (name,), name="__arm_rsr64", ctype=ctype, effect=True)
        values = tuple(self.lift(arg, at) for arg in args)
        if op in {"extract", "truncate", "sext", "zext"}:
            value = values[0]
            if op == "extract" and expression.get("value", 0):
                value = Value("lshr", value.width, (value, Value("constant", width, number=expression["value"])))
            if op == "sext":
                value = cast(value, integer_type(args[0]["width"], True), args[0]["width"])
                return cast(value, integer_type(width, True), width)
            if op == "zext" and _signed_value(value) and args[0]["width"] < width:
                # 零扩展：带符号类型的值（如 sext 的结果）直接转换成更宽的类型时 C 做符号扩展，先转为同宽度无符号。
                value = cast(value, integer_type(args[0]["width"]), args[0]["width"])
            return cast(value, ctype, width)
        if op == "insert" and len(values) == 2:
            # 位段插入：(a & ~(掩码 << s)) | ((uintW_t)b << s)；写成 C 运算符（s + 段宽 <= W，没有越界移位）。
            shift, field = int(expression.get("value", 0) or 0), args[1]["width"]
            mask = (((1 << field) - 1) << shift) & ((1 << width) - 1)
            kept = Value("and", width, (cast(values[0], ctype, width), Value("constant", width, number=((1 << width) - 1) ^ mask, ctype=ctype)), ctype=ctype)
            placed = cast(cast(values[1], integer_type(field), field), ctype, width)
            if shift:
                placed = Value("shl", width, (placed, Value("constant", width, number=shift, ctype=ctype)), ctype=ctype)
            return Value("or", width, (kept, placed), ctype=ctype)
        if op in {"add", "sub", "mul", "and", "or", "xor", "shl", "lshr", "not", "neg"}:
            values = tuple(cast(value, ctype, width) for value in values)
        if op == "select" and len(values) == 3:
            values = (values[0],) + unsigned_arms(values[1:], width)
        if op in _UNSIGNED_DIVISION:
            # 无符号除法写成 C 的 / 、%：操作数必须是无符号 W 位类型。
            values = tuple(cast(value, ctype, width) for value in values)
        elif op in _SCALAR_OPERATIONS:
            # 写成前导辅助函数或 C 运算符的操作数：指针（含数组退化）显式转为整数，地址不变。
            values = tuple(cast(value, integer_type(arg.get("width", width)), arg.get("width", width)) if "*" in (value.ctype or "") else value
                           for value, arg in zip(values, args))
        if op in {"sdiv", "udiv", "srem", "urem"}:
            # 架构语义：逐节点声明（微码表达式 name 字段）优先，否则取所在操作的 division_semantics（见上）。
            # 记在 Value.name 中随值传递，渲染据此选择 arm_*（"arm_zero"）或陷入辅助（"x86_fault"/不声明），
            # 与 evaluate 一致。ARM 语义的除法不会陷入，是纯运算（可删除、可传播）；其余可能陷入，保留副作用。
            name = expression.get("name", "")
            semantics = name if name in DIVISION_SEMANTICS else self.division_semantics
            return Value(op, width, values, name=semantics, ctype=ctype, effect=semantics != "arm_zero")
        if op in _INTEGER_HELPERS:
            # 整数原型的辅助调用：被推断为指针的实参显式转为整数；aut* 可能陷入，标为有副作用。
            values = tuple(self.integer_argument(value) for value in values)
            return Value(op, width, values, ctype=ctype, effect=op in _TRAPPING_HELPERS)
        return Value(op, width, values, ctype=ctype, effect=expression.get("domain") == "floating")

    def integer_argument(self, value):
        """整数原型辅助函数（x86_rep_*、pac*/aut*、vec_*）的实参：指针（含数组退化）显式转换为
        指针宽度的无符号整数（与 -Wint-conversion 兼容，地址不变），其余值原样返回。"""
        if "*" in (value.ctype or ""):
            return cast(value, integer_type(self.bits), self.bits)
        return value
