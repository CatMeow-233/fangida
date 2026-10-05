"""伪 C 代码视图的纯函数：分词高亮、函数头、可跳转符号、查找与终端排版。

本模块只读取已完成的函数记录（``pseudoc``、``machine_pseudoc``、
``pseudoc_reconstruction``、``xrefs_out`` 等字段）和 GUI 已有的结果表，
不导入 Tk、Loader、处理器或伪 C 插件，也不重新生成伪代码。桌面视图
（``pseudocode_view.py``）与终端浏览器（``tui.py``）共用这里的规则，
因此无显示环境也能对全部展示逻辑做单元测试。

偏移约定：所有 span 都是代码字符串内的字符偏移 ``[start, end)``；
Tk 索引由 :func:`text_index` 按行列换算。
"""
from __future__ import annotations

from bisect import bisect_right
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
import re
from typing import Any


# ---------------------------------------------------------------------------
# 词法分类
# ---------------------------------------------------------------------------

#: 高亮使用的全部 tag 名称；GUI 按这个顺序配置颜色（后配置的优先级更高）。
HIGHLIGHT_TAGS = ("type", "keyword", "number", "function", "label", "string", "comment")

KEYWORDS = frozenset((
    "if", "else", "while", "for", "do", "switch", "case", "default", "break",
    "continue", "return", "goto", "sizeof", "struct", "union", "enum", "typedef",
    "static", "extern", "const", "volatile", "register", "inline", "restrict",
    # 字节码提纲可能出现的 Java 关键字，只影响颜色。
    "new", "throw", "try", "catch", "finally", "instanceof", "this", "super",
))
TYPE_NAMES = frozenset((
    "void", "char", "short", "int", "long", "float", "double", "signed", "unsigned",
    "bool", "_Bool", "boolean", "byte", "wchar_t", "size_t", "ssize_t", "ptrdiff_t",
    "uintptr_t", "intptr_t", "off_t", "va_list", "FILE",
))
LITERAL_NAMES = frozenset(("NULL", "nullptr", "true", "false", "null"))

_TOKEN = re.compile(r"""
    (?P<comment>/\*.*?(?:\*/|\Z)|//[^\n]*)
  | (?P<string>"(?:[^"\\\n]|\\.)*(?:"|$))
  | (?P<char>'(?:[^'\\\n]|\\.){1,8}')
  | (?P<labeldef>^[ \t]*(?P<labelname>[A-Za-z_][\w]*)[ \t]*:(?!:))
  | (?P<number>\b(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)[uUlLfF]*\b)
  | (?P<ident>[A-Za-z_$][\w$]*)
""", re.S | re.M | re.X)
_TYPE_SUFFIX = re.compile(r"\w+_t\Z")
_HEX_IN_TEXT = re.compile(r"\b0[xX][0-9a-fA-F]{3,16}\b")
_ADDRESS_NAME = re.compile(
    r"(?:sub|loc|fde|entry_window|L|unk|off|byte|word|dword|qword|data|str|stub|j)_([0-9A-Fa-f]{3,16})\Z")
_SIGNATURE = re.compile(
    r"^[ \t]*(?!(?:if|while|for|switch|return|else)\b)"
    r"(?P<ret>[A-Za-z_][\w \t\*]*?[\s\*])(?P<name>[A-Za-z_][\w$]*)[ \t]*\((?P<params>[^;{}]*)\)[ \t]*\{?[ \t]*$",
    re.M)
_BUDGET_MARKERS = ("budget exhausted", "omitted by inspection limit", "预算用尽")
#: 伪 C 生成器的辅助调用；它们的字符串实参是指令名或寄存器名，不是程序字符串。
_HELPER_PREFIXES = ("unresolved_", "symbolic_", "asm_", "machine_", "unknown_", "opaque_")

#: 小于此值的十进制常量不视为地址：它们几乎都是计数、偏移或位掩码。
MIN_DECIMAL_ADDRESS = 0x10000


@dataclass(frozen=True, slots=True)
class Span:
    """一段高亮：``tag`` 是 HIGHLIGHT_TAGS 之一。"""

    tag: str
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class Token:
    """词法单元；kind 为 comment/string/char/labeldef/number/ident。"""

    kind: str
    start: int
    end: int
    text: str


@dataclass(frozen=True, slots=True)
class CodeModel:
    """一次分词得到的全部信息；同一段代码只计算一次（见 analyze_code 缓存）。"""

    code: str
    spans: tuple[Span, ...]
    tokens: tuple[Token, ...]
    labels: Mapping[str, int]          # 标签名 → 定义处（标签名）的起始偏移
    line_starts: tuple[int, ...]


def _classify_identifier(code: str, token: Token, previous: Token | None) -> str | None:
    name = token.text
    if name in KEYWORDS:
        return "keyword"
    if name in LITERAL_NAMES:
        return "number"
    if previous is not None and previous.kind == "ident":
        if previous.text == "goto":
            return "label"
        if previous.text in {"struct", "union", "enum"}:
            return "type"
    if name in TYPE_NAMES or _TYPE_SUFFIX.match(name):
        return "type"
    # 标识符后（可隔空白）紧跟 "(" 视为函数名；类型和关键字已在上面排除。
    position = token.end
    length = len(code)
    while position < length and code[position] in " \t":
        position += 1
    if position < length and code[position] == "(":
        return "function"
    return None


@lru_cache(maxsize=64)
def analyze_code(code: str) -> CodeModel:
    """对伪 C 文本分词，返回高亮区间、词法单元和标签定义。

    结果按代码字符串缓存；GUI 在函数之间来回切换或重复查找时不再重复分词。
    """
    if not isinstance(code, str):
        raise TypeError("code 必须是字符串")
    spans: list[Span] = []
    tokens: list[Token] = []
    labels: dict[str, int] = {}
    previous: Token | None = None
    for match in _TOKEN.finditer(code):
        kind = match.lastgroup
        if kind == "labelname":  # 命名子组不会作为 lastgroup 出现，此处仅防御。
            kind = "labeldef"
        if kind == "labeldef":
            start, end = match.span("labelname")
            name = match.group("labelname")
            token = Token("labeldef", start, end, name)
            if name in KEYWORDS:  # "default:" 等关键字不是标签
                spans.append(Span("keyword", start, end))
                token = Token("ident", start, end, name)
            else:
                spans.append(Span("label", start, end))
                labels.setdefault(name, start)
            tokens.append(token)
            previous = token
            continue
        start, end = match.span()
        token = Token(kind or "", start, end, match.group())
        tokens.append(token)
        if kind == "comment":
            spans.append(Span("comment", start, end))
            continue  # 注释不改变上一个有效词法单元
        if kind in {"string", "char"}:
            spans.append(Span("string", start, end))
        elif kind == "number":
            spans.append(Span("number", start, end))
        elif kind == "ident":
            tag = _classify_identifier(code, token, previous)
            if tag is not None:
                spans.append(Span(tag, start, end))
        previous = token
    line_starts = [0]
    position = code.find("\n")
    while position >= 0:
        line_starts.append(position + 1)
        position = code.find("\n", position + 1)
    return CodeModel(code, tuple(spans), tuple(tokens), labels, tuple(line_starts))


def highlight_spans(code: str) -> tuple[Span, ...]:
    """返回按起点排序的高亮区间。"""
    return analyze_code(code).spans


def group_spans(spans: Iterable[Span]) -> dict[str, list[tuple[int, int]]]:
    """按 tag 分组，GUI 可对每个 tag 一次性批量 tag_add。"""
    grouped: dict[str, list[tuple[int, int]]] = {}
    for span in spans:
        grouped.setdefault(span.tag, []).append((span.start, span.end))
    return grouped


def text_index(line_starts: Sequence[int], offset: int) -> str:
    """把字符偏移换算为 Tk Text 的 ``行.列`` 索引（行从 1 开始）。"""
    line = bisect_right(line_starts, offset) - 1
    line = max(0, line)
    return f"{line + 1}.{offset - line_starts[line]}"


def index_offset(line_starts: Sequence[int], line: int, column: int) -> int:
    """text_index 的逆运算；越界行列被夹到代码范围内。"""
    if not line_starts:
        return 0
    line = min(max(1, line), len(line_starts))
    return line_starts[line - 1] + max(0, column)


# ---------------------------------------------------------------------------
# 符号上下文与跳转目标
# ---------------------------------------------------------------------------

def _int(value: Any) -> int | None:
    return value if type(value) is int and 0 <= value <= 0xFFFFFFFFFFFFFFFF else None


def _function_address(record: Mapping[str, Any]) -> int | None:
    for key in ("start", "location", "code_offset", "address"):
        address = _int(record.get(key))
        if address is not None:
            return address
    return None


@dataclass(frozen=True)
class SymbolContext:
    """整个分析结果共享的只读符号表；每次载入结果构建一次。"""

    names: Mapping[int, str]              # 地址 → 显示名（函数、导入、导出）
    symbols: Mapping[str, int]            # 唯一名称 → 地址
    string_values: Mapping[int, str]      # 字符串地址 → 内容
    string_addresses: Mapping[str, int]   # 唯一字符串内容 → 地址
    function_starts: frozenset[int]
    pseudocode_starts: frozenset[int]
    ranges: tuple[tuple[int, int], ...]   # 合并后的区段范围 [start, end)

    def address_kind(self, value: int) -> str | None:
        """地址证据：function / string / section；未知返回 None。"""
        if value in self.function_starts:
            return "function"
        if value in self.string_values:
            return "string"
        if value in self.names:
            return "function"
        index = bisect_right(self.ranges, (value, 0xFFFFFFFFFFFFFFFFF)) - 1
        if index >= 0 and self.ranges[index][0] <= value < self.ranges[index][1]:
            return "section"
        return None


EMPTY_CONTEXT = SymbolContext({}, {}, {}, {}, frozenset(), frozenset(), ())


def build_symbol_context(*, functions: Iterable[Mapping[str, Any]] = (),
                         imports: Iterable[Mapping[str, Any]] = (),
                         exports: Iterable[Mapping[str, Any]] = (),
                         strings: Iterable[Mapping[str, Any]] = (),
                         sections: Iterable[Mapping[str, Any]] = (),
                         pseudocode: Iterable[Mapping[str, Any]] = ()) -> SymbolContext:
    """从已完成结果表建立符号上下文；只读记录，不保留记录引用。"""
    names: dict[int, str] = {}
    by_name: dict[str, set[int]] = {}
    starts: set[int] = set()
    for source, is_function in ((functions, True), (exports, False), (imports, False)):
        for record in source:
            if not isinstance(record, Mapping):
                continue
            address = _function_address(record) if is_function else _int(record.get("address"))
            name = record.get("name")
            if address is None or not isinstance(name, str) or not name:
                continue
            if is_function:
                starts.add(address)
            names.setdefault(address, name)
            by_name.setdefault(name, set()).add(address)
            # Mach-O 符号常带下划线前缀；伪 C 中通常不带。
            if name.startswith("_") and len(name) > 1 and not name.startswith("__"):
                by_name.setdefault(name[1:], set()).add(address)
    symbols = {name: next(iter(addresses)) for name, addresses in by_name.items()
               if len(addresses) == 1}
    values: dict[int, str] = {}
    value_addresses: dict[str, set[int]] = {}
    for record in strings:
        if not isinstance(record, Mapping) or not isinstance(record.get("value"), str):
            continue
        space = record.get("address_space")
        if space not in (None, "native", "ram", "virtual"):
            continue
        declared = [record.get("address")]
        for key in ("addresses", "data_addresses"):
            if isinstance(record.get(key), (list, tuple)):
                declared.extend(record[key])
        addresses = {address for address in declared if _int(address) is not None}
        for address in addresses:
            values.setdefault(address, record["value"])
        if addresses:
            value_addresses.setdefault(record["value"], set()).update(addresses)
    string_addresses = {value: min(addresses) for value, addresses in value_addresses.items()
                        if len(addresses) == 1}
    ranges: list[tuple[int, int]] = []
    for section in sections:
        if not isinstance(section, Mapping):
            continue
        start, size = _int(section.get("address")), _int(section.get("size"))
        if start is None or not size:
            continue
        ranges.append((start, min(start + size, 1 << 64)))
    ranges.sort()
    merged: list[tuple[int, int]] = []
    for start, end in ranges:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    pseudo_starts = {address for address in (_function_address(row) for row in pseudocode
                                             if isinstance(row, Mapping)) if address is not None}
    return SymbolContext(names, symbols, values, string_addresses, frozenset(starts),
                         frozenset(pseudo_starts), tuple(merged))


@dataclass(frozen=True, slots=True)
class JumpTarget:
    """代码中可双击跳转的一段文本。

    kind：function（已知函数或调用目标）、global（重建出的全局对象）、
    address（十六进制地址或带地址后缀的名称）、string（字符串字面量）、
    label（同一函数内的 goto 标签）。label 使用 ``label_offset`` 定位，
    其余使用 ``address``。
    """

    start: int
    end: int
    kind: str
    text: str
    address: int | None = None
    name: str = ""
    label_offset: int | None = None


def _reconstruction(function: Mapping[str, Any]) -> Mapping[str, Any]:
    value = function.get("pseudoc_reconstruction")
    return value if isinstance(value, Mapping) else {}


def _records(value: Any) -> list[Mapping[str, Any]]:
    """只接受记录列表；损坏或旧格式的字段按空列表处理，显示不因此失败。"""
    if not isinstance(value, (list, tuple)):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def code_function_name(code: str) -> str:
    """伪 C 文本自身声明的函数名（可能与列表中的记录名不同）。"""
    match = _SIGNATURE.search(code or "")
    return match.group("name") if match else ""


def function_symbols(function: Mapping[str, Any] | None,
                     context: SymbolContext | None = None,
                     code: str | None = None) -> dict[str, tuple[str, int]]:
    """当前函数可解析的名称：名称 → (kind, 地址)。

    调用证据（``pseudoc_reconstruction.calls``）比全局唯一名称更具体，
    因此覆盖同名的全局符号；伪 C 自身的函数名指向函数入口。
    """
    context = context or EMPTY_CONTEXT
    result: dict[str, tuple[str, int]] = {name: ("function", address)
                                          for name, address in context.symbols.items()}
    if not isinstance(function, Mapping):
        return result
    reconstruction = _reconstruction(function)
    for item in _records(reconstruction.get("globals")):
        if isinstance(item.get("name"), str) and _int(item.get("address")) is not None:
            result[item["name"]] = ("global", item["address"])
    for call in _records(reconstruction.get("calls")):
        if isinstance(call.get("name"), str) and _int(call.get("target")) is not None:
            result[call["name"]] = ("function", call["target"])
    start = _function_address(function)
    if start is not None:
        for name in (code_function_name(code or ""), function.get("name")):
            if isinstance(name, str) and name:
                result[name] = ("function", start)
    return result


_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "\\": "\\", '"': '"', "'": "'",
            "a": "\a", "b": "\b", "f": "\f", "v": "\v", "e": "\x1b", "?": "?"}


def c_unescape(literal: str) -> str:
    """把 C 字符串字面量（含或不含引号）还原为字符串内容。"""
    if len(literal) >= 2 and literal[0] == literal[-1] and literal[0] in "\"'":
        literal = literal[1:-1]
    elif literal[:1] == '"':
        literal = literal[1:]
    result: list[str] = []
    index = 0
    while index < len(literal):
        char = literal[index]
        if char != "\\" or index + 1 >= len(literal):
            result.append(char)
            index += 1
            continue
        following = literal[index + 1]
        if following in "xX":
            digits = re.match(r"[0-9a-fA-F]{1,2}", literal[index + 2:])
            if digits:
                result.append(chr(int(digits.group(), 16)))
                index += 2 + len(digits.group())
                continue
        if following in "01234567":
            digits = re.match(r"[0-7]{1,3}", literal[index + 1:])
            assert digits is not None  # following 本身就是八进制数字
            result.append(chr(int(digits.group(), 8)))
            index += 1 + len(digits.group())
            continue
        result.append(_ESCAPES.get(following, following))
        index += 2
    return "".join(result)


def _numeric_value(text: str) -> tuple[int, bool] | None:
    stripped = text.rstrip("uUlLfF")
    try:
        if stripped[:2].lower() == "0x":
            return int(stripped, 16), True
        if stripped.isdigit():
            return int(stripped, 10), False
    except ValueError:
        return None
    return None


def jump_targets(code: str, function: Mapping[str, Any] | None = None,
                 context: SymbolContext | None = None) -> tuple[JumpTarget, ...]:
    """提取可跳转的函数名、地址、字符串字面量和 goto 标签。

    没有上下文时只认可十六进制常量（≥ 0x1000）和本函数的标签/调用证据；
    有上下文时，十六进制常量须落在已知区段、函数或字符串上，十进制常量
    只有恰好是函数入口或字符串地址时才可跳转，避免把普通整数误当地址。
    """
    model = analyze_code(code)
    symbols = function_symbols(function, context, code)
    targets: list[JumpTarget] = []

    def address_target(token: Token, value: int, hexadecimal: bool) -> JumpTarget | None:
        if context is None:
            if hexadecimal and value >= 0x1000:
                return JumpTarget(token.start, token.end, "address", token.text, value)
            return None
        kind = context.address_kind(value)
        if kind is None or (not hexadecimal and (value < MIN_DECIMAL_ADDRESS or kind == "section")):
            return None
        return JumpTarget(token.start, token.end, "address", token.text, value,
                          context.names.get(value, context.string_values.get(value, "")))

    previous: Token | None = None
    for token in model.tokens:
        if token.kind == "comment":
            # 机器视图的 /* 0x... */ 注释是逐指令的地址标记。
            for match in _HEX_IN_TEXT.finditer(token.text):
                value = int(match.group(), 16)
                inner = Token("number", token.start + match.start(), token.start + match.end(), match.group())
                target = address_target(inner, value, True)
                if target is not None:
                    targets.append(target)
            continue
        if token.kind == "number":
            parsed = _numeric_value(token.text)
            if parsed is not None:
                target = address_target(token, *parsed)
                if target is not None:
                    targets.append(target)
        elif token.kind == "string" and context is not None:
            value = c_unescape(token.text)
            address = context.string_addresses.get(value)
            if address is not None:
                targets.append(JumpTarget(token.start, token.end, "string", token.text, address, value))
        elif token.kind == "ident":
            name = token.text
            is_goto = previous is not None and previous.kind == "ident" and previous.text == "goto"
            if name in model.labels and (is_goto or name not in symbols):
                if is_goto:
                    targets.append(JumpTarget(token.start, token.end, "label", name,
                                              label_offset=model.labels[name], name=name))
            elif name in symbols and name not in KEYWORDS:
                kind, address = symbols[name]
                display = context.names.get(address, name) if context is not None else name
                targets.append(JumpTarget(token.start, token.end, kind, name, address, display))
            else:
                match = _ADDRESS_NAME.match(name)
                if match is not None:
                    value = int(match.group(1), 16)
                    if name in model.labels and not is_goto:
                        pass  # 标签定义本身不跳转
                    elif context is None or context.address_kind(value) is not None:
                        targets.append(JumpTarget(token.start, token.end, "address", name, value,
                                                  context.names.get(value, "") if context else ""))
        elif token.kind == "labeldef":
            pass
        if token.kind != "comment":
            previous = token
    targets.sort(key=lambda item: item.start)
    return tuple(targets)


def target_at(targets: Sequence[JumpTarget], offset: int) -> JumpTarget | None:
    """返回覆盖 offset 的跳转目标；offset 恰在末尾时也算命中（光标在词尾）。"""
    if not targets:
        return None
    starts = [item.start for item in targets]
    index = bisect_right(starts, offset) - 1
    for candidate in (index, index - 1):
        if 0 <= candidate < len(targets):
            item = targets[candidate]
            if item.start <= offset < item.end or (offset == item.end and candidate == index):
                return item
    return None


_IDENTIFIER = re.compile(r"[A-Za-z_$][\w$]*")


def identifier_at(code: str, offset: int) -> tuple[int, int, str] | None:
    """光标处的标识符（用于高亮同名出现）。"""
    if not code or offset < 0:
        return None
    line_start = code.rfind("\n", 0, offset) + 1
    line_end = code.find("\n", offset)
    line_end = len(code) if line_end < 0 else line_end
    for match in _IDENTIFIER.finditer(code, line_start, line_end):
        if match.start() <= offset <= match.end():
            if match.group()[0].isdigit():
                return None
            return match.start(), match.end(), match.group()
        if match.start() > offset:
            break
    return None


def occurrence_spans(code: str, word: str, *, limit: int = 2000) -> tuple[tuple[int, int], ...]:
    """同一标识符在代码中的全部出现（整词匹配，最多 limit 处）。"""
    if not word or not _IDENTIFIER.fullmatch(word):
        return ()
    pattern = re.compile(r"(?<![\w$])" + re.escape(word) + r"(?![\w$])")
    result = []
    for match in pattern.finditer(code):
        result.append(match.span())
        if len(result) >= limit:
            break
    return tuple(result)


def find_in_code(code: str, query: str, start: int = 0, *, wrap: bool = False
                 ) -> tuple[int, int] | None:
    """不区分大小写地查找纯文本；返回原代码中的 ``(start, end)``。"""
    if not query or not isinstance(code, str):
        return None
    pattern = re.compile(re.escape(query), re.IGNORECASE)
    match = pattern.search(code, max(0, start))
    if match is None and wrap and start > 0:
        match = pattern.search(code, 0)
    return match.span() if match else None


# ---------------------------------------------------------------------------
# 函数头
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class CallEntry:
    name: str                 # 伪 C 中的调用名
    target: int | None
    resolved: str             # 目标在结果中的名称（与 name 相同则为空）
    count: int
    kind: str                 # call / tail_transfer / indirect / import（经已核实指针槽位调用的导入函数）
    slot: int | None = None   # kind 为 import（或经槽位的尾跳转）时的导入指针槽位地址


@dataclass(frozen=True, slots=True)
class StringEntry:
    value: str
    address: int | None


@dataclass(frozen=True)
class PseudocodeHeader:
    name: str
    address: int | None
    code_name: str
    signature: str
    signature_complete: bool | None
    producer: str
    style: str
    machine_available: bool
    calls: tuple[CallEntry, ...]
    strings: tuple[StringEntry, ...]
    truncated: bool
    status: str
    reasons: tuple[str, ...]
    notes: tuple[str, ...]
    line_count: int


@dataclass(frozen=True)
class HeaderText:
    """格式化后的函数头文本、可点击链接和各行的语义 tag。"""

    text: str
    links: tuple[JumpTarget, ...]
    spans: tuple[Span, ...]


def code_for_style(function: Mapping[str, Any], style: str = "readable") -> tuple[str, str]:
    """返回 (实际视图, 代码)。请求机器视图但没有 machine_pseudoc 时回退到可读视图。"""
    readable = function.get("pseudoc") or function.get("pseudo_c")
    readable = readable if isinstance(readable, str) else ""
    machine = function.get("machine_pseudoc")
    if style == "machine" and isinstance(machine, str) and machine:
        return "machine", machine
    return "readable", readable


def _type_declaration(ctype: str, name: str) -> str:
    if "[" in ctype:
        base, extent = ctype.split("[", 1)
        return f"{base.rstrip()} {name}[{extent}"
    return f"{ctype} {name}"


def function_signature(function: Mapping[str, Any], code: str = "") -> str:
    """优先使用重建证据中的参数和返回类型，其次取伪 C 首个函数声明行。"""
    reconstruction = _reconstruction(function)
    code_name = code_function_name(code) or str(function.get("name") or "function")
    parameters = reconstruction.get("parameters")
    return_type = reconstruction.get("return_type")
    if isinstance(return_type, str) and return_type and isinstance(parameters, list):
        declared = [_type_declaration(str(item.get("type", "int64_t")), str(item.get("name", f"arg_{index + 1}")))
                    for index, item in enumerate(_records(parameters))]
        return f"{return_type} {code_name}({', '.join(declared) or 'void'})"
    match = _SIGNATURE.search(code or "")
    if match:
        params = " ".join(match.group("params").split())
        return f"{' '.join(match.group('ret').split())} {match.group('name')}({params})"
    return ""


def _call_entries(function: Mapping[str, Any], context: SymbolContext | None) -> tuple[CallEntry, ...]:
    names = context.names if context is not None else {}
    counts: Counter[tuple[str, int | None, str]] = Counter()
    order: list[tuple[str, int | None, str]] = []
    slots: dict[tuple[str, int | None, str], int] = {}
    calls = _records(_reconstruction(function).get("calls"))
    if calls:
        for call in calls:
            target = _int(call.get("target"))
            slot = _int(call.get("import_slot")) if target is None else None
            name = str(call.get("name") or (names.get(target) if target is not None else "") or "indirect_call")
            kind = "tail_transfer" if call.get("kind") == "tail_transfer" else (
                "call" if target is not None else "import" if slot is not None else "indirect")
            key = (name, target, kind)
            if key not in counts:
                order.append(key)
            if slot is not None:
                slots.setdefault(key, slot)
            counts[key] += 1
    else:
        # 没有重建证据（Ghidra、字节码或旧快照）时退回已完成的调用 xref。
        for xref in _records(function.get("xrefs_out")):
            if xref.get("kind") != "call":
                continue
            target = _int(xref.get("dst"))
            name = names.get(target, f"sub_{target:x}") if target is not None else "indirect_call"
            key = (name, target, "call" if target is not None else "indirect")
            if key not in counts:
                order.append(key)
            counts[key] += 1
    result = []
    for name, target, kind in order:
        resolved = names.get(target, "") if target is not None else ""
        result.append(CallEntry(name, target, resolved if resolved and resolved != name else "",
                                counts[(name, target, kind)], kind, slots.get((name, target, kind))))
    return tuple(result)


def _string_entries(function: Mapping[str, Any], code: str,
                    context: SymbolContext | None, limit: int = 64,
                    machine_code: str = "") -> tuple[StringEntry, ...]:
    """引用的字符串：可读伪 C 中的字面量、指向字符串的常量和数据 xref。

    机器视图里的字符串字面量是寄存器名（symbolic_input("x0")），不计入；
    但机器视图中直接指向字符串的常量仍会被识别。
    """
    seen: dict[str, int | None] = {}
    for source, literals in ((code, True), (machine_code, False)):
        if not source or len(seen) >= limit:
            continue
        previous: Token | None = None
        for token in analyze_code(source).tokens:
            helper_argument = (previous is not None and previous.kind == "ident"
                               and previous.text.startswith(_HELPER_PREFIXES)
                               and source[previous.end:token.start].strip() == "(")
            if token.kind != "comment":
                previous = token
            if token.kind == "string" and literals and not helper_argument:
                value = c_unescape(token.text)
                if value not in seen:
                    seen[value] = context.string_addresses.get(value) if context is not None else None
            elif token.kind == "number" and context is not None and context.string_values:
                parsed = _numeric_value(token.text)
                if (parsed is not None and parsed[0] in context.string_values
                        and (parsed[1] or parsed[0] >= MIN_DECIMAL_ADDRESS)):
                    value = context.string_values[parsed[0]]
                    seen.setdefault(value, parsed[0])
            if len(seen) >= limit:
                break
    if context is not None and context.string_values:
        for xref in _records(function.get("xrefs_out")):
            if len(seen) >= limit:
                break
            if _int(xref.get("dst")) in context.string_values:
                seen.setdefault(context.string_values[xref["dst"]], xref["dst"])
    return tuple(StringEntry(value, address) for value, address in seen.items())


_UNRESOLVED_TEXT = {
    "call_signature": "{count} 处调用的参数未能确定",
    "call_return_upper_bits": "{count} 处调用返回值的高位扩展未知",
    "condition": "{count} 个分支条件未能还原",
    "system_transition": "{count} 处系统调用或异常转移（效果取决于处理程序）",
    "stack_address_extent": "{count} 处栈地址范围不确定",
    "fp_environment_operation": "{count} 处浮点运算依赖舍入/异常环境（写成占位函数）",
    "memory_order": "{count} 处带内存序的栈槽访问写成普通读写",
}


def _reasons(function: Mapping[str, Any], code: str) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    reconstruction = _reconstruction(function)
    reasons: list[str] = []
    notes: list[str] = []
    budget = any(marker in code for marker in _BUDGET_MARKERS)
    truncated = bool(function.get("pseudoc_truncated"))
    unresolved = _records(reconstruction.get("unresolved"))
    if budget:
        reasons.append("文本或指令预算用尽，输出被截断")
    # 目标已知的尾跳转（重建时已核实的导入函数或已命名函数）不是未解析的控制流，单独说明。
    named = [item for item in unresolved if item.get("kind") == "control_flow_target"
             and (item.get("import_name") or item.get("target_name"))]
    flows = Counter(str(item.get("transfer_kind") or "unknown") for item in unresolved
                    if item.get("kind") == "control_flow_target"
                    and not (item.get("import_name") or item.get("target_name")))
    if flows:
        details = "、".join(f"{kind}×{count}" if count > 1 else kind for kind, count in flows.most_common())
        reasons.append(f"{sum(flows.values())} 个未解析的控制流目标（{details}）")
    if named:
        targets = list(dict.fromkeys(str(item.get("import_name") or item.get("target_name")) for item in named))
        notes.append(f"{len(named)} 处尾跳转到已知函数（{'、'.join(targets[:4])}{'…' if len(targets) > 4 else ''}）")
        frontier = (function.get("cfg") or {}).get("frontier") if isinstance(function.get("cfg"), Mapping) else None
        sources = {item.get("from") for item in _records(frontier)}
        if truncated and not flows and sources <= {item.get("address") for item in named}:
            # CFG 出口全部是到已知目标的尾跳转：截断标记只来自这些出口，不是快照缺失。
            truncated = False
    regions = [item for item in unresolved if item.get("kind") == "machine_state_region"]
    regions = regions or _records(reconstruction.get("machine_regions"))
    if regions:
        count = len(regions)
        reasons.append(f"{count} 段保留为机器状态语义，未还原成 C")
    incoming = sum(1 for item in unresolved if item.get("kind") in {"incoming_value", "incoming_stack_value"})
    if incoming:
        reasons.append(f"{incoming} 个值依赖未知的入口寄存器或栈内容")
    failures = [item for item in unresolved if item.get("kind") == "reconstruction_failure"]
    if failures:
        reasons.append(f"源码重建失败（{failures[0].get('error', 'error')}），当前为机器视图")
    known = {"control_flow_target", "machine_state_region", "incoming_value",
             "incoming_stack_value", "reconstruction_failure"}
    other = Counter(str(item.get("kind") or "unknown") for item in unresolved if item.get("kind") not in known)
    for kind, count in other.items():
        template = _UNRESOLVED_TEXT.get(kind)
        if kind == "operation":
            mnemonics = list(dict.fromkeys(str(item.get("mnemonic")) for item in unresolved
                                           if item.get("kind") == "operation" and item.get("mnemonic")))
            suffix = f"（{'、'.join(mnemonics[:4])}{'…' if len(mnemonics) > 4 else ''}）" if mnemonics else ""
            reasons.append(f"{count} 条指令未能翻译成 C{suffix}")
        elif template is not None:
            reasons.append(template.format(count=count))
        else:
            reasons.append(f"其它未解析证据：{kind}×{count}")
    if truncated and not budget and not flows:
        frontier = (function.get("cfg") or {}).get("frontier") if isinstance(function.get("cfg"), Mapping) else None
        reasons.append("控制流未完全恢复（CFG 存在未解析出口或分析窗口限制）"
                       if frontier or not reconstruction else "输出被截断或控制流未完全恢复")
    gotos = reconstruction.get("residual_gotos")
    if type(gotos) is int and gotos > 0:
        reasons.append(f"{gotos} 个标签未能结构化，保留 goto")
    if function.get("microcode_complete") is False:
        notes.append("部分指令语义未被微码覆盖（见机器视图）")
    if reconstruction.get("signature_complete") is False:
        notes.append("签名按 ABI 默认推断（参数个数和类型未经调用点证实）")
    has_gotos = type(gotos) is int and gotos > 0
    incomplete = bool(truncated or flows or regions or incoming or failures or other)
    # 重建结果只因“到已知目标的尾跳转”而标为不完整（例如导入桩）：按完整显示，原因见说明。
    explained = bool(named) and len(named) == len(unresolved) and not truncated
    if budget or (truncated and not flows and not regions):
        status = "截断"
    elif incomplete or (reconstruction.get("complete") is False and not has_gotos and not explained):
        status = "不完整"
    elif has_gotos:
        status = "含 goto"
    else:
        status = "完整"
    return status, tuple(reasons), tuple(notes)


def status_flags(function: Mapping[str, Any]) -> str:
    """函数列表“状态”列的简短标记：完整 / 含 goto / 不完整 / 截断。"""
    code = function.get("pseudoc") if isinstance(function.get("pseudoc"), str) else ""
    return _reasons(function, code)[0]


def build_header(function: Mapping[str, Any], *, style: str = "readable",
                 context: SymbolContext | None = None) -> PseudocodeHeader:
    """汇总代码区顶部需要的函数信息；只读取记录字段。"""
    actual, code = code_for_style(function, style)
    readable = function.get("pseudoc") if isinstance(function.get("pseudoc"), str) else code
    status, reasons, notes = _reasons(function, readable)
    reconstruction = _reconstruction(function)
    signature_complete = reconstruction.get("signature_complete")
    machine = function.get("machine_pseudoc")
    return PseudocodeHeader(
        name=str(function.get("name") or "未命名函数"),
        address=_function_address(function),
        code_name=code_function_name(readable),
        signature=function_signature(function, readable),
        signature_complete=signature_complete if isinstance(signature_complete, bool) else None,
        producer=str(function.get("pseudoc_producer") or "analyzer"),
        style=actual,
        machine_available=isinstance(machine, str) and bool(machine),
        calls=_call_entries(function, context),
        strings=_string_entries(function, readable, context,
                                machine_code=code if actual == "machine" else ""),
        truncated=bool(function.get("pseudoc_truncated")),
        status=status, reasons=reasons, notes=notes,
        line_count=code.count("\n") + 1 if code else 0)


STYLE_LABELS = {"readable": "可读视图", "machine": "机器视图"}


def _quote(value: str, limit: int = 60) -> str:
    escaped = (value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
               .replace("\r", "\\r").replace("\t", "\\t"))
    escaped = "".join(char if char.isprintable() else f"\\x{ord(char):02x}" for char in escaped)
    if len(escaped) > limit:
        escaped = escaped[:limit - 1] + "…"
    return f'"{escaped}"'


def format_header(header: PseudocodeHeader, *, prefix: str = "", max_calls: int = 16,
                  max_strings: int = 10) -> HeaderText:
    """生成函数头文本，并给出调用和字符串的链接区间（偏移相对于返回文本）。"""
    parts: list[str] = []
    links: list[JumpTarget] = []
    spans: list[Span] = []
    position = 0

    def emit(text: str, tag: str | None = None, link: JumpTarget | None = None) -> None:
        nonlocal position
        if tag:
            spans.append(Span(tag, position, position + len(text)))
        if link is not None:
            links.append(JumpTarget(position, position + len(text), link.kind, text,
                                    link.address, link.name))
        parts.append(text)
        position += len(text)

    def line_start(label: str) -> None:
        emit(prefix)
        emit(label, "header_label")

    # 第 1 行：名称、地址、视图、生成器
    emit(prefix)
    emit(header.name, "header_name")
    if header.address is not None:
        emit("  @ ")
        emit(f"{header.address:#x}", "number",
             JumpTarget(0, 0, "address", "", header.address, header.name))
    emit(f"  ·  {STYLE_LABELS.get(header.style, header.style)}  ·  {header.producer}")
    if header.code_name and header.code_name != header.name:
        emit(f"  ·  伪 C 中名为 {header.code_name}")
    emit("\n")
    # 第 2 行：签名
    line_start("签名：")
    emit(header.signature or "（未知）", "header_signature")
    if header.signature_complete is False:
        emit("  （按 ABI 推断）", "header_note")
    emit("\n")
    # 第 3 行：调用
    line_start("调用：")
    if not header.calls:
        emit("无", "header_note")
    for index, call in enumerate(header.calls[:max_calls]):
        if index:
            emit("，")
        if call.target is not None:
            emit(call.name, "function", JumpTarget(0, 0, "function", "", call.target,
                                                   call.resolved or call.name))
            if call.resolved:
                emit(f"→{call.resolved}")
            # 名称已含地址（sub_100000870）时不再重复显示地址。
            if f"{call.target:x}" not in (call.name + call.resolved).lower():
                emit(f" @ {call.target:#x}")
        elif call.slot is not None:
            # 经已核实指针槽位（IAT/GOT）调用的导入函数：链接到槽位地址。
            emit(call.name, "function", JumpTarget(0, 0, "address", "", call.slot, call.name))
            emit("（导入）" if call.kind != "tail_transfer" else "（导入，尾跳转）")
        else:
            emit(call.name, "function")
            emit("（间接）" if call.kind != "tail_transfer" else "（间接尾跳转）")
        if call.kind == "tail_transfer" and call.target is not None:
            emit("（尾跳转）")
        if call.count > 1:
            emit(f" ×{call.count}")
    if len(header.calls) > max_calls:
        emit(f"，… 共 {len(header.calls)} 个目标", "header_note")
    emit("\n")
    # 第 4 行：字符串
    line_start("字符串：")
    if not header.strings:
        emit("无", "header_note")
    for index, item in enumerate(header.strings[:max_strings]):
        if index:
            emit("，")
        link = (JumpTarget(0, 0, "string", "", item.address, item.value)
                if item.address is not None else None)
        emit(_quote(item.value), "string", link)
    if len(header.strings) > max_strings:
        emit(f"，… 共 {len(header.strings)} 个", "header_note")
    emit("\n")
    # 第 5 行：状态与原因
    line_start("状态：")
    status_tag = "header_ok" if header.status == "完整" else "header_warning"
    emit(header.status, status_tag)
    if header.reasons:
        emit(" —— " + "；".join(header.reasons), "header_warning")
    emit("\n")
    if header.notes:
        line_start("说明：")
        emit("；".join(header.notes), "header_note")
        emit("\n")
    return HeaderText("".join(parts), tuple(links), tuple(spans))


def header_text(header: PseudocodeHeader, *, prefix: str = "") -> str:
    return format_header(header, prefix=prefix).text


def no_pseudocode_message(stats: Mapping[str, Any] | None = None, kind: str = "") -> str:
    """结果中没有任何伪代码时的说明文字（GUI 与 TUI 共用）。"""
    stats = stats if isinstance(stats, Mapping) else {}
    lines = ["当前结果没有伪代码。"]
    if stats.get("pseudoc_budget_exhausted"):
        lines.append("伪 C 预算已用尽（最多 128 个函数、共 524288 个字符）。")
    elif stats.get("semantic_functions") == 0 or stats.get("semantic_cancelled"):
        lines.append("本次分析没有恢复出可生成伪 C 的函数，或分析已被取消。")
    if kind in {"apk", "jar"}:
        lines.append("APK/JAR 的方法伪代码随字节码分析生成，可在函数列表中确认方法是否已解析。")
    else:
        lines.append("快速分析不生成伪 C；请使用常规分析或完整分析（--full）重新打开文件。")
    lines.append("伪代码视图只浏览已有结果，不会隐式重新分析。")
    return "\n".join(lines)


def placeholder_message(rows: int, *, generate_hint: bool = False) -> str:
    """有伪代码但尚未选择函数时的提示；generate_hint 时说明可按需生成（GUI 使用）。"""
    message = (f"共 {rows} 个函数有伪代码。从左侧列表选择函数；在汇编视图按 Tab/F5 打开当前函数。\n"
               "双击代码中的函数名或地址跳转，Shift+双击跳到反汇编，Esc 返回；Ctrl+F 查找，F3/Ctrl+T 查找下一处。")
    if generate_hint:
        message += "\n其它函数：选中后按 Ctrl+F5（或点击“生成伪代码”）在后台按需生成。"
    return message


# ---------------------------------------------------------------------------
# 配色
# ---------------------------------------------------------------------------

#: 代码区配色。默认深色，与流程图画布一致；颜色只依赖 tag 名称，便于测试。
CODE_PALETTES: dict[str, dict[str, str]] = {
    "dark": {
        "background": "#1e2028", "foreground": "#d8dee9", "header_background": "#262a35",
        "select_background": "#3b4f73", "insert": "#d8dee9", "current_line": "#2a2e3a",
        "keyword": "#569cd6", "type": "#4ec9b0", "number": "#b5cea8", "string": "#ce9178",
        "comment": "#6a9955", "function": "#dcdcaa", "label": "#c586c0",
        "header_name": "#ffffff", "header_label": "#8a93a6", "header_signature": "#d8dee9",
        "header_note": "#8a93a6", "header_warning": "#e5a550", "header_ok": "#89d185",
        "find": "#806000", "occurrence": "#3a4152", "flash": "#2e5a3a", "link": "#7fb4ff",
    },
    "light": {
        "background": "#ffffff", "foreground": "#1f2328", "header_background": "#f3f4f6",
        "select_background": "#b6d3f5", "insert": "#1f2328", "current_line": "#f2f6fc",
        "keyword": "#0000c0", "type": "#267f99", "number": "#098658", "string": "#a31515",
        "comment": "#6a737d", "function": "#795e26", "label": "#af00db",
        "header_name": "#000000", "header_label": "#57606a", "header_signature": "#1f2328",
        "header_note": "#57606a", "header_warning": "#b35900", "header_ok": "#1a7f37",
        "find": "#ffd54f", "occurrence": "#fff3b0", "flash": "#c8e6c9", "link": "#0550ae",
    },
}


def code_palette(name: str = "dark") -> dict[str, str]:
    """返回配色副本；未知名称回退到深色。"""
    return dict(CODE_PALETTES.get(name, CODE_PALETTES["dark"]))


# ---------------------------------------------------------------------------
# 终端排版
# ---------------------------------------------------------------------------

#: ANSI 颜色（终端高亮）；只在 TTY 且未设置 NO_COLOR 时使用。
ANSI_COLORS = {"keyword": "\x1b[34m", "type": "\x1b[36m", "string": "\x1b[31m",
               "number": "\x1b[32m", "comment": "\x1b[90m", "function": "\x1b[33m",
               "label": "\x1b[35m"}
ANSI_RESET = "\x1b[0m"


def ansi_highlight(code: str) -> str:
    """用 ANSI 转义序列为终端输出着色；不改变任何可见字符。"""
    pieces: list[str] = []
    position = 0
    for span in highlight_spans(code):
        color = ANSI_COLORS.get(span.tag)
        if color is None or span.start < position:
            continue
        pieces.append(code[position:span.start])
        pieces.append(color + code[span.start:span.end] + ANSI_RESET)
        position = span.end
    pieces.append(code[position:])
    return "".join(pieces)


def render_listing(function: Mapping[str, Any], *, style: str = "readable",
                   context: SymbolContext | None = None, color: bool = False,
                   width: int = 78) -> str:
    """终端中单个函数的完整伪代码：注释形式的函数头 + 原样代码。"""
    header = build_header(function, style=style, context=context)
    _, code = code_for_style(function, style)
    rule = "=" * width
    head = format_header(header, prefix="// ").text
    body = ansi_highlight(code) if color else code
    if color:
        head = ANSI_COLORS["comment"] + head.rstrip("\n").replace("\n", ANSI_RESET + "\n" + ANSI_COLORS["comment"]) + ANSI_RESET + "\n"
    return f"{rule}\n{head}{'-' * width}\n{body.rstrip()}\n"


def select_functions(functions: Sequence[Mapping[str, Any]], query: str | None = None
                     ) -> list[Mapping[str, Any]]:
    """按名称或地址选择有伪代码的函数；地址可命中入口或已解码指令内部。"""
    available = [item for item in functions if isinstance(item, Mapping)
                 and isinstance(item.get("pseudoc") or item.get("pseudo_c"), str)
                 and (item.get("pseudoc") or item.get("pseudo_c"))]
    if not query:
        return available
    text = query.strip()
    address = None
    if re.fullmatch(r"0[xX][0-9a-fA-F]+|[0-9]+", text):
        address = int(text, 16 if text.lower().startswith("0x") else 10)
    if address is not None:
        exact = [item for item in available if _function_address(item) == address]
        if exact:
            return exact
        inside = []
        for item in available:
            for block in _records(item.get("blocks")):
                if any(_int(row.get("addr")) is not None
                       and row["addr"] <= address < row["addr"] + (_int(row.get("size")) or 1)
                       for row in _records(block.get("instructions"))):
                    inside.append(item)
                    break
        return inside
    exact = [item for item in available if item.get("name") == text
             or code_function_name(item.get("pseudoc") or "") == text]
    if exact:
        return exact
    folded = text.casefold()
    return [item for item in available if folded in str(item.get("name", "")).casefold()]
