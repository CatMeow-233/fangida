"""伪 C 的只读数据引用：把常量地址解释为只读字符串字面量或已命名的函数。

职责边界：
- 地址→文件偏移只使用 Loader 已声明的节映射（result.metadata["sections"]）；
  本模块不识别文件格式、不解析容器结构、不解码指令，也不产生交叉引用。
- 字符串字节只在伪 C 渲染真正遇到某个常量时，按需从同一输入文件的已映射只读节
  中有界读取（每次最多 MAX_STRING_BYTES，总次数 MAX_LOOKUPS）；文件不可用或大小
  与分析时不一致时整体停用，此时常量保持数值形式。
- 只认可以 NUL 结尾、内容可打印（允许常见转义字符）的字符串；可写数据节中的
  字节可能在运行时改变，不当作字面量。
"""
from __future__ import annotations

import os
from bisect import bisect_right
from collections.abc import Iterable, Mapping
from typing import Any

MAX_STRING_BYTES = 1024
MAX_LOOKUPS = 16384
_MAX_ADDRESS = (1 << 64) - 1
# 允许出现在字面量中的控制字符：\a \b \t \n \v \f \r 与 ESC。
_ALLOWED_CONTROLS = frozenset("\a\b\t\n\v\f\r\x1b")
_GENERATED_PREFIXES = ("sub_", "function_", "entry_window_", "recovered_function")


def _unsigned(value: Any) -> bool:
    return type(value) is int and 0 <= value <= _MAX_ADDRESS


def _string_kind(section: Mapping[str, Any], kind: str) -> str | None:
    """节能否承载只读字符串："literals"（字面量池，允许短串/串中地址）、"rodata" 或 None。"""
    if section.get("executable") or section.get("file_backed") is False:
        return None
    if section.get("type") == 8 or section.get("allocated") is False or section.get("mapped") is False:
        return None
    name = str(section.get("name", ""))
    if kind == "macho":
        if section.get("section_type") == 2:  # S_CSTRING_LITERALS
            return "literals"
        if section.get("segment") == "__TEXT":
            return "rodata"
        return None
    if kind == "elf":
        if name.startswith(".rodata.str"):
            return "literals"
        if name == ".rodata" or name.startswith(".rodata.") or name == ".rodata1":
            return "rodata"
        return None
    if kind == "pe":
        flags = section.get("section_flags")
        if type(flags) is int and not flags & 0x80000000 and flags & 0x40:
            return "literals" if name == ".rdata" else "rodata"
        return None
    return None


class DataReferences:
    """按需解析常量地址；接口与 dict 相同：get(address) → 描述字典或 None。

    返回值：
    - {"kind": "string", "value": str, "address": int, "section": str}
      （PE 的 UTF-16LE 宽字符串另带 "encoding": "utf-16le"，伪 C 中写成 L"..."）
    - {"kind": "function", "name": str, "address": int}
    """

    def __init__(self, sections: Iterable[Mapping[str, Any]] = (), *, kind: str = "",
                 path: str | os.PathLike[str] | None = None, size: int | None = None,
                 functions: Mapping[int, str] | None = None) -> None:
        ranges = []
        executable = []
        for section in sections:
            if not isinstance(section, Mapping):
                continue
            address, offset = section.get("address"), section.get("offset")
            length = section.get("file_size", section.get("size"))
            if not all(map(_unsigned, (address, offset, length))) or not length or not address:
                continue
            virtual_size = section.get("virtual_size")
            if _unsigned(virtual_size) and virtual_size:
                length = min(length, virtual_size)
            if section.get("executable"):
                executable.append((address, address + length))
                continue
            role = _string_kind(section, kind)
            if role is not None:
                ranges.append((address, address + length, offset, role, str(section.get("name", ""))))
        ranges.sort()
        self._ranges = tuple(ranges)
        self._starts = tuple(item[0] for item in ranges)
        self._executable = tuple(sorted(executable))
        self._functions = {address: name for address, name in (functions or {}).items()
                           if _unsigned(address) and isinstance(name, str) and name
                           and not name.startswith(_GENERATED_PREFIXES)}
        self._kind = kind
        self._path = os.fspath(path) if path is not None else None
        self._size = size if type(size) is int else None
        self._handle = None
        self._disabled = self._path is None or not self._ranges
        self._cache: dict[int, dict[str, Any] | None] = {}
        self._lookups = 0

    @classmethod
    def from_result(cls, result: Any, names: Mapping[int, str] | None = None) -> DataReferences:
        metadata = getattr(result, "metadata", {}) or {}
        return cls(metadata.get("sections", ()) or (), kind=str(getattr(result, "kind", "")),
                   path=getattr(result, "path", None), size=metadata.get("size_bytes"), functions=names)

    # -- 资源管理 ---------------------------------------------------------
    def close(self) -> None:
        handle, self._handle = self._handle, None
        if handle is not None:
            try:
                handle.close()
            except OSError:
                pass

    def __enter__(self) -> DataReferences:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _read(self, offset: int, length: int) -> bytes | None:
        if self._disabled:
            return None
        try:
            if self._handle is None:
                if not os.path.isfile(self._path):
                    self._disabled = True
                    return None
                if self._size is not None and os.path.getsize(self._path) != self._size:
                    # 文件在分析后被替换：不能用当前字节解释旧分析结果。
                    self._disabled = True
                    return None
                self._handle = open(self._path, "rb")
            self._handle.seek(offset)
            return self._handle.read(length)
        except OSError:
            self._disabled = True
            self.close()
            return None

    # -- 查询 ---------------------------------------------------------------
    def __contains__(self, address: object) -> bool:
        return self.get(address) is not None

    def get(self, address: object, default: Any = None) -> Any:
        if not _unsigned(address):
            return default
        if address in self._cache:
            value = self._cache[address]
            return default if value is None else value
        if self._lookups >= MAX_LOOKUPS:
            return default
        self._lookups += 1
        value = self._resolve(address)
        self._cache[address] = value
        return default if value is None else value

    def _executable_address(self, address: int) -> bool:
        position = bisect_right(self._executable, (address, _MAX_ADDRESS)) - 1
        return position >= 0 and self._executable[position][0] <= address < self._executable[position][1]

    def _resolve(self, address: int) -> dict[str, Any] | None:
        name = self._functions.get(address)
        if name is not None and (not self._executable or self._executable_address(address)):
            return {"kind": "function", "name": name, "address": address}
        position = bisect_right(self._starts, address) - 1
        if position < 0:
            return None
        start, end, offset, role, section = self._ranges[position]
        if not start <= address < end:
            return None
        at = offset + address - start
        limit = min(MAX_STRING_BYTES, end - address)
        if role == "rodata" and address > start:
            # 普通只读数据：地址必须是字符串开头（前一字节为 NUL），避免把数据表中间当作字符串。
            previous = self._read(at - 1, 1)
            if previous != b"\0":
                return None
        data = self._read(at, limit)
        if not data:
            return None
        before = None
        if self._kind == "pe":
            # PE 的 .rdata 不是纯字符串池（还有导入表、展开信息、常量表等），而且常有 UTF-16LE
            # 宽字符串：地址必须是字符串开头，不能落在宽字符串中间。
            # 取地址之前的两个字节；落在节开头之前的部分按 NUL 处理。
            missing = min(2, address - start) if address >= start else 0
            previous = self._read(at - missing, missing) if missing else b""
            before = b"\0" * (2 - missing) + (previous or b"")
            if len(before) != 2:
                return None
        if self._kind == "pe" and _looks_utf16(data):
            # Windows 常用 UTF-16LE 宽字符串（L"..."）：按窄串解码只会得到首字符，必须整体识别或放弃。
            if address % 2 or before != b"\0\0":
                return None
            text = decode_wide_literal(data)
            if text is None:
                return None
            return {"kind": "string", "value": text, "address": address, "section": section, "encoding": "utf-16le"}
        terminator = data.find(b"\0")
        if terminator < 0:
            return None
        raw = data[:terminator]
        if role == "rodata" and len(raw) < 2:
            return None
        if before is not None:
            # PE 窄字符串：前一字节是 NUL（字符串开头）、非空，且不是宽字符串中间的单个字符。
            if before[1] != 0 or not raw or (len(raw) == 1 and 0x20 <= before[0] < 0x7f):
                return None
        text = decode_literal(raw)
        if text is None:
            return None
        return {"kind": "string", "value": text, "address": address, "section": section}


def _looks_utf16(data: bytes) -> bool:
    """开头至少两个 UTF-16LE 的 ASCII 字符（高字节为 0）：例如 b"m\\0s\\0"。"""
    return (len(data) >= 4 and data[1] == 0 and data[3] == 0 and
            0x20 <= data[0] < 0x7f and 0x20 <= data[2] < 0x7f)


def decode_wide_literal(data: bytes) -> str | None:
    """UTF-16LE、以 2 字节 NUL 结尾、全部可打印（允许常见转义控制字符）时返回文本，否则 None。"""
    for end in range(0, len(data) - 1, 2):
        if data[end] == 0 and data[end + 1] == 0:
            break
    else:
        return None
    if end < 4:
        return None
    try:
        text = data[:end].decode("utf-16-le")
    except UnicodeDecodeError:
        return None
    for character in text:
        if not character.isprintable() and character not in _ALLOWED_CONTROLS:
            return None
    return text


def decode_literal(raw: bytes) -> str | None:
    """严格 UTF-8 解码且只含可打印字符与常见转义控制字符时返回文本，否则 None。"""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    for character in text:
        if not character.isprintable() and character not in _ALLOWED_CONTROLS:
            return None
    return text
