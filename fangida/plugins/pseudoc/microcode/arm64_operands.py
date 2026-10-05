"""A64 arithmetic/logical operand forms over already decoded text operands."""
from __future__ import annotations

import re

from .common import value
from .ir import Expression, constant

# 模块级预编译正则（与原字符串模式及标志位一致）。
_UNSIGNED_IMMEDIATE = re.compile(r"#?(?:0[xX][0-9a-fA-F]+|[0-9]+)")
_SHIFT_MODIFIER = re.compile(r"(lsl|lsr|asr|ror)\s+(#?(?:0[xX][0-9a-fA-F]+|[0-9]+))")
_EXTEND_MODIFIER = re.compile(r"([us]xt[bwhx])(?:\s+(#?(?:0[xX][0-9a-fA-F]+|[0-9]+)))?")
_EXTEND_PREFIX = re.compile(r"[us]xt")
_LSL_MODIFIER = re.compile(r"lsl\s+(#?(?:0[xX][0-9a-fA-F]+|[0-9]+))")


def _unsigned_immediate(token):
    if _UNSIGNED_IMMEDIATE.fullmatch(token) is None:
        raise ValueError("A64 operand requires an unsigned immediate")
    raw = token.lstrip("#")
    return int(raw, 16 if raw.lower().startswith("0x") else 10)


def register_operand(op, token, width, *, allow_sp=False, allow_zero=True, read=True):
    register = op.register(token)
    if (register is None or register.bits != width or width not in {32, 64} or
            register.root == "sp" and not allow_sp or
            register.root == "zero" and not allow_zero):
        raise ValueError("Invalid A64 register operand")
    return (op.read(token, width) if read else token), value(op, token, width)


def shifted_register(op, token, modifier, width, *, rotate=False):
    text, expression = register_operand(op, token, width)
    kind, amount = "lsl", 0
    if modifier is not None:
        match = _SHIFT_MODIFIER.fullmatch(modifier.lower())
        if match is None:
            raise ValueError("Invalid A64 register shift")
        kind, amount = match[1], _unsigned_immediate(match[2])
    if amount >= width or kind == "ror" and not rotate:
        raise ValueError("A64 shift is not encodable for this operand form")
    attributes = {"operand_form": "shifted_register", "shift": kind, "shift_amount": amount}
    if not amount:
        return text, expression, attributes
    count = constant(amount, width)
    if kind in {"lsl", "lsr"}:
        opcode = "shl" if kind == "lsl" else "lshr"
        expression = Expression(opcode, width, (expression, count))
    else:
        # Expand sign-fill and rotation into portable fixed-width primitives.
        # No shift by the storage width occurs, including the zero-count case.
        source = expression
        upper = source if kind == "ror" else Expression("neg", width, (
            Expression("lshr", width, (source, constant(width - 1, width))),))
        expression = Expression("or", width, (
            Expression("lshr", width, (source, count)),
            Expression("shl", width, (upper, constant(width - amount, width))),
        ))
    opcode = {"lsl": "shl", "lsr": "lshr", "asr": "ashr", "ror": "ror"}[kind]
    return f"bitvector_{opcode}{width}({text}, {amount})", expression, attributes


def extended_register(op, token, modifier, width):
    match = _EXTEND_MODIFIER.fullmatch(modifier.lower())
    if match is None:
        raise ValueError("Invalid A64 register extension")
    extension = match[1]
    amount = _unsigned_immediate(match[2]) if match[2] else 0
    if amount > 4:
        raise ValueError("A64 extended-register shift exceeds four bits")
    source_width = 64 if width == 64 and extension.endswith("x") else 32
    text, expression = register_operand(op, token, source_width)
    extension_width = min(width, {"b": 8, "h": 16, "w": 32, "x": 64}[extension[-1]])
    if expression.width != extension_width:
        expression = Expression("truncate", extension_width, (expression,))
    signed = extension.startswith("s")
    if extension_width != width:
        expression = Expression("sext" if signed else "zext", width, (expression,))
    if amount:
        expression = Expression("shl", width, (expression, constant(amount, width)))
    text = f"(uint{width}_t)({'int' if signed else 'uint'}{extension_width}_t)({text})"
    if amount:
        text = f"bitvector_shl{width}({text}, {amount})"
    return text, expression, {"operand_form": "extended_register", "extension": extension,
                              "shift": "lsl", "shift_amount": amount}


def arithmetic_operand(op, token, modifier, width, *, extension_alias=False):
    """Register shifts or an imm12 optionally shifted left by 12 bits."""
    if op.register(token) is not None:
        if modifier and _EXTEND_PREFIX.match(modifier.lower()):
            return extended_register(op, token, modifier, width)
        if extension_alias:
            # LSL with an SP operand names the UXTX/UXTW extended encoding,
            # whose shift range is 0..4 rather than the shifted GPR range.
            amount = 0
            if modifier is not None:
                match = _LSL_MODIFIER.fullmatch(modifier.lower())
                if match is None:
                    raise ValueError("A64 SP arithmetic requires an extended register")
                amount = _unsigned_immediate(match[1])
            extension = "uxtx" if width == 64 else "uxtw"
            return extended_register(op, token, f"{extension} #{amount}", width)
        return shifted_register(op, token, modifier, width)
    immediate = _unsigned_immediate(token)
    shift = 0
    if modifier is not None:
        match = _LSL_MODIFIER.fullmatch(modifier.lower())
        if match is None:
            raise ValueError("A64 immediate supports only LSL #0 or #12")
        shift = _unsigned_immediate(match[1])
        if shift not in {0, 12} or immediate > 0xfff:
            raise ValueError("Invalid A64 shifted imm12")
        immediate <<= shift
    elif immediate > 0xfff:
        # Decoders may normalize the shifted immediate into its final value.
        if immediate & 0xfff or immediate >> 12 > 0xfff:
            raise ValueError("Immediate is not representable as A64 imm12")
        shift = 12
    return hex(immediate), constant(immediate, width), {
        "operand_form": "immediate", "shift": "lsl", "shift_amount": shift,
    }
