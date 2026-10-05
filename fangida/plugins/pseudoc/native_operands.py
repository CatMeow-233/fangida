"""Interpret textual operands in an existing IR; never decode instruction bytes."""
from __future__ import annotations

import re
from dataclasses import dataclass
from collections.abc import Mapping
from functools import lru_cache
from typing import Any

# 模块级预编译正则：语义与原先 re.fullmatch/re.match/re.sub 的字符串模式完全相同，
# 只是省去每次调用 re._compile 的缓存查找开销。
_IDENTIFIER_UNSAFE = re.compile(r"[^a-zA-Z0-9_]")
_X86_EXTENDED_REGISTER = re.compile(r"r(8|9|1[0-5])([dwb]?)")
_ARM64_GENERAL_REGISTER = re.compile(r"[xw]([0-9]|[12][0-9]|30)")
_ARM_GENERAL_REGISTER = re.compile(r"r([0-9]|1[0-4])")
_MEMORY_WIDTH_PREFIX = re.compile(r"(byte|word|dword|qword)\s+(?:ptr\s+)?", re.I)
_MEMORY_OPERAND = re.compile(r"(?:byte|word|dword|qword)?\s*(?:ptr\s+)?\[([^\]]+)\]", re.I)
_ADDRESS_CHARACTERS = re.compile(r"[a-zA-Z0-9_+*\-\s]+")
_ADDRESS_NUMBER = re.compile(r"(?:0x[0-9a-fA-F]+|[0-9]+)")
_ADDRESS_TOKEN = re.compile(r"0x[0-9a-fA-F]+|[a-zA-Z_][a-zA-Z0-9_]*|[0-9]+")
_SIGNED_IMMEDIATE = re.compile(r"-?(?:0x[0-9a-fA-F]+|[0-9]+)")
_MEMORY_WIDTHS = {"byte": 8, "word": 16, "dword": 32, "qword": 64}
_X86_REGISTER_FAMILIES = (
    ("rax", "eax", "ax", "al", "ah"), ("rbx", "ebx", "bx", "bl", "bh"),
    ("rcx", "ecx", "cx", "cl", "ch"), ("rdx", "edx", "dx", "dl", "dh"),
    ("rsi", "esi", "si", "sil", ""), ("rdi", "edi", "di", "dil", ""),
    ("rsp", "esp", "sp", "spl", ""), ("rbp", "ebp", "bp", "bpl", ""),
)
# 缓存上限：均为输入完全决定的纯函数，键为不可变字符串/整数元组，结果为不可变对象。
_OPERAND_CACHE_SIZE = 16384


@lru_cache(maxsize=4096)
def _identifier_cached(text: str, fallback: str) -> str:
    name = _IDENTIFIER_UNSAFE.sub("_", text)
    if not name or name[0].isdigit():
        name = fallback + "_" + name
    return name


def identifier(value: object, fallback: str = "function") -> str:
    text = str(value)[:64]
    if type(fallback) is str:
        # 结果只由截断后的文本与 fallback 决定（纯函数，返回不可变字符串）。
        return _identifier_cached(text, fallback)
    name = _IDENTIFIER_UNSAFE.sub("_", text)
    if not name or name[0].isdigit():
        name = fallback + "_" + name
    return name


def _split_text(text: str) -> list[str]:
    parts, start, depth = [], 0, 0
    for index, char in enumerate(text):
        depth += char in "[("
        depth -= char in "])"
        if char == "," and depth == 0:
            parts.append(text[start:index].strip())
            start = index + 1
    if text[start:].strip():
        parts.append(text[start:].strip())
    return parts


@lru_cache(maxsize=_OPERAND_CACHE_SIZE)
def _split_text_cached(text: str) -> tuple[str, ...]:
    return tuple(_split_text(text))


def split_operands(row: Mapping[str, Any]) -> list[str]:
    raw = row.get("operands", ())
    # map(str, raw) 与原生成器表达式逐项调用 str() 的顺序和异常完全相同，只是更快。
    text = raw if isinstance(raw, str) else ", ".join(map(str, raw))
    if type(text) is str:
        # 缓存保存不可变元组；每次返回新列表，调用方就地修改不会污染缓存。
        return list(_split_text_cached(text))
    return _split_text(text)


@dataclass(frozen=True)
class Register:
    root: str
    bits: int
    shift: int = 0


def _parse_register(architecture: str, bits: int, value: str) -> Register | None:
    """Pure textual register lookup; identical to the historical method body."""
    token = value.lower().strip()
    if architecture.startswith("x86"):
        for wide, dword, word, low, high in _X86_REGISTER_FAMILIES:
            if token and token in (wide, dword, word, low, high):
                if bits == 32 and token == wide:
                    return None
                width = {wide: 64, dword: 32, word: 16, low: 8, high: 8}[token]
                return Register(wide if bits == 64 else dword, width, 8 if token == high else 0)
        match = _X86_EXTENDED_REGISTER.fullmatch(token)
        if match and bits == 64:
            return Register("r" + match[1], {"": 64, "d": 32, "w": 16, "b": 8}[match[2]])
    elif architecture == "arm64":
        token = {"fp": "x29", "lr": "x30"}.get(token, token)
        if token in {"xzr", "wzr"}:
            return Register("zero", 64 if token == "xzr" else 32)
        if token in {"sp", "wsp"}:
            return Register("sp", 64 if token == "sp" else 32)
        if _ARM64_GENERAL_REGISTER.fullmatch(token):
            return Register("x" + token[1:], 64 if token[0] == "x" else 32)
    elif architecture == "arm":
        token = {"sp": "r13", "lr": "r14", "fp": "r11"}.get(token, token)
        if _ARM_GENERAL_REGISTER.fullmatch(token):
            return Register(token, 32)
    return None


# Register 为冻结数据类，可在多次调用之间安全共享。
_register_cached = lru_cache(maxsize=_OPERAND_CACHE_SIZE)(_parse_register)


def _memory_width(value: str) -> int | None:
    match = _MEMORY_WIDTH_PREFIX.match(value)
    return _MEMORY_WIDTHS[match[1].lower()] if match else None


@lru_cache(maxsize=_OPERAND_CACHE_SIZE)
def _operand_width(architecture: str, bits: int, value: str) -> int | None:
    """Register width, else explicit memory width, else None (caller default)."""
    register = _register_cached(architecture, bits, value)
    if register is not None:
        return register.bits
    return _memory_width(value)


@lru_cache(maxsize=_OPERAND_CACHE_SIZE)
def _immediate_token(value: str) -> str | None:
    token = value.lstrip("#$").strip()
    return token if _SIGNED_IMMEDIATE.fullmatch(token) else None


# 地址模板片段类型：文本原样输出、RIP/EIP 相对地址、寄存器读取、不支持的寄存器。
_TEXT, _NEXT_PC, _REGISTER, _BAD_REGISTER = 0, 1, 2, 3


@lru_cache(maxsize=_OPERAND_CACHE_SIZE)
def _address_template(architecture: str, bits: int, value: str) -> tuple:
    """Parse a memory operand once into ordered text/register pieces.

    The returned tuple is either ``("error", message)`` for validation
    failures raised before any side effect, or ``("ok", pieces)``.  Pieces are
    replayed in source order so register-read side effects and the position of
    a late "Unsupported address register" failure stay exactly as before.
    """
    match = _MEMORY_OPERAND.fullmatch(value)
    if match is None:
        return ("error", "Unsupported memory operand")
    expression = " ".join(match[1].replace(",", " + ").replace("#", "").split())
    # Only integer/register address expressions; segment overrides,
    # writeback and shifted ARM indices remain opaque instructions.
    if not _ADDRESS_CHARACTERS.fullmatch(expression):
        return ("error", "Unsupported address expression")
    pieces: list[tuple] = []
    position = 0
    x86 = architecture.startswith("x86")
    for found in _ADDRESS_TOKEN.finditer(expression):
        if found.start() > position:
            pieces.append((_TEXT, expression[position:found.start()]))
        token = found[0]
        if _ADDRESS_NUMBER.fullmatch(token):
            pieces.append((_TEXT, token))
        elif token.lower() in {"rip", "eip"} and x86:
            pieces.append((_NEXT_PC, None))
        else:
            register = _register_cached(architecture, bits, token)
            pieces.append((_BAD_REGISTER, None) if register is None else (_REGISTER, register))
        position = found.end()
    if position < len(expression):
        pieces.append((_TEXT, expression[position:]))
    # 合并相邻纯文本片段，减少重放时的拼接次数（输出文本不变）。
    merged: list[tuple] = []
    for piece in pieces:
        if piece[0] == _TEXT and merged and merged[-1][0] == _TEXT:
            merged[-1] = (_TEXT, merged[-1][1] + piece[1])
        else:
            merged.append(piece)
    return ("ok", tuple(merged))


class Operands:
    def __init__(self, architecture: str, row: Mapping[str, Any], registers: set[str]):
        self.architecture, self.row, self.registers = architecture, row, registers
        self.bits = 64 if architecture in {"x86_64", "arm64"} else 32
        self.reads: set[str] = set()
        self.writes: set[str] = set()

    def register(self, value: str) -> Register | None:
        if type(value) is str and type(self.architecture) is str and type(self.bits) is int:
            return _register_cached(self.architecture, self.bits, value)
        # 非常规输入走未缓存路径，保持原有异常类型（例如 AttributeError）。
        return _parse_register(self.architecture, self.bits, value)

    def width(self, value: str, default: int | None = None) -> int:
        if type(value) is str and type(self.architecture) is str and type(self.bits) is int:
            width = _operand_width(self.architecture, self.bits, value)
            return width if width is not None else (default or self.bits)
        register = self.register(value)
        if register is not None:
            return register.bits
        match = re.match(r"(byte|word|dword|qword)\s+(?:ptr\s+)?", value, re.I)
        return {"byte": 8, "word": 16, "dword": 32, "qword": 64}[match[1].lower()] if match else (default or self.bits)

    def read_register(self, register: Register) -> str:
        if register.root == "zero":
            return "0"
        self.registers.add(register.root)
        self.reads.add(register.root)
        value = register.root if not register.shift else f"({register.root} >> {register.shift})"
        return value if register.bits == self.bits else f"(uint{register.bits}_t){value}"

    def address(self, value: str) -> str:
        if not (type(value) is str and type(self.architecture) is str and type(self.bits) is int):
            return self._address_uncached(value)
        status, pieces = _address_template(self.architecture, self.bits, value)
        if status == "error":
            raise ValueError(pieces)
        output = []
        for kind, payload in pieces:
            if kind == _TEXT:
                output.append(payload)
            elif kind == _REGISTER:
                output.append(self.read_register(payload))
            elif kind == _NEXT_PC:
                output.append(hex(self.row["addr"] + self.row["size"]))
            else:
                raise ValueError("Unsupported address register")
        return "".join(output)

    def _address_uncached(self, value: str) -> str:
        match = re.fullmatch(r"(?:byte|word|dword|qword)?\s*(?:ptr\s+)?\[([^\]]+)\]", value, re.I)
        if match is None:
            raise ValueError("Unsupported memory operand")
        expression = " ".join(match[1].replace(",", " + ").replace("#", "").split())
        # Only integer/register address expressions; segment overrides,
        # writeback and shifted ARM indices remain opaque instructions.
        if not re.fullmatch(r"[a-zA-Z0-9_+*\-\s]+", expression):
            raise ValueError("Unsupported address expression")
        def replace(match: re.Match[str]) -> str:
            token = match[0]
            if re.fullmatch(r"(?:0x[0-9a-fA-F]+|[0-9]+)", token):
                return token
            if token.lower() in {"rip", "eip"} and self.architecture.startswith("x86"):
                return hex(self.row["addr"] + self.row["size"])
            register = self.register(token)
            if register is None:
                raise ValueError("Unsupported address register")
            return self.read_register(register)
        return re.sub(r"0x[0-9a-fA-F]+|[a-zA-Z_][a-zA-Z0-9_]*|[0-9]+", replace, expression)

    def read(self, value: str, width: int | None = None) -> str:
        register = self.register(value)
        if register is not None:
            return self.read_register(register)
        if type(value) is str:
            token = _immediate_token(value)
            if token is not None:
                return token
        else:
            token = value.lstrip("#$").strip()
            if re.fullmatch(r"-?(?:0x[0-9a-fA-F]+|[0-9]+)", token):
                return token
        return f"load{self.width(value, width)}({self.address(value)})"

    def write(self, value: str, expression: str, width: int | None = None) -> str:
        register = self.register(value)
        if register is None:
            return f"store{self.width(value, width)}({self.address(value)}, {expression});"
        if register.root == "zero":
            return f"(void)({expression}); /* zero-register write discarded */"
        self.registers.add(register.root)
        self.writes.add(register.root)
        if register.bits == self.bits:
            return f"{register.root} = {expression};"
        if register.bits == 32 and self.bits == 64:
            return f"{register.root} = (uint32_t)({expression});"
        self.reads.add(register.root)  # Partial writes preserve the remaining bits.
        mask = ((1 << register.bits) - 1) << register.shift
        inserted = f"(uint{register.bits}_t)({expression})"
        if register.shift:
            inserted = f"((uint{self.bits}_t){inserted} << {register.shift})"
        return f"{register.root} = ({register.root} & ~{hex(mask)}ULL) | {inserted};"
