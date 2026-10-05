"""Bounded PE import/export, ELF dynamic-symbol and Mach-O nlist extraction.

The input may be only a prefix of the file. Every table, pointer, and string is
resolved within that prefix; malformed optional metadata produces warnings and
never causes the main container analysis to fail.
"""
from __future__ import annotations

import struct
from typing import Any

from .binary import BinaryFormatError, BinaryImage


MAX_DESCRIPTORS = 1024
MAX_SYMBOLS = 10000
MAX_NAME_BYTES = 512
MAX_ELF_SECTIONS = 4096


def _read(data: bytes, offset: int, fmt: str) -> tuple[Any, ...] | None:
    size = struct.calcsize(fmt)
    if offset < 0 or offset > len(data) or size > len(data) - offset:
        return None
    return struct.unpack_from(fmt, data, offset)


def _cstring(data: bytes, offset: int, end: int) -> str | None:
    if offset < 0 or offset >= end or end > len(data):
        return None
    terminator = data.find(b"\0", offset, min(end, offset + MAX_NAME_BYTES + 1))
    if terminator < 0:
        return None
    return data[offset:terminator].decode("utf-8", "replace") or None


def _pe_window(data: bytes, image: BinaryImage, rva: int) -> tuple[int, int] | None:
    """Return file offset and contiguous, file-backed bytes at an RVA."""
    if rva < 0 or image.image_base is None:
        return None
    for section in image.sections:
        address = section.get("address")
        raw_offset = section.get("offset")
        raw_size = section.get("size")
        virtual_size = section.get("virtual_size")
        if not all(isinstance(v, int) and v >= 0 for v in
                   (address, raw_offset, raw_size, virtual_size)):
            continue
        relative = rva - (address - image.image_base)
        # The virtual tail of a section has no bytes in the input file.
        if relative < 0 or relative >= min(raw_size, virtual_size or raw_size):
            continue
        offset = raw_offset + relative
        if offset >= len(data):
            return None
        return offset, min(raw_size - relative, len(data) - offset)
    return None


def _pe_name(data: bytes, image: BinaryImage, rva: int) -> str | None:
    window = _pe_window(data, image, rva)
    return _cstring(data, window[0], window[0] + window[1]) if window else None


def _pe_directory(data: bytes, index: int) -> tuple[int, int] | None:
    dos = _read(data, 0x3c, "<I")
    if dos is None:
        return None
    pe_offset = dos[0]
    if data[pe_offset:pe_offset + 4] != b"PE\0\0":
        return None
    coff = _read(data, pe_offset + 4, "<HHIIIHH")
    if coff is None:
        return None
    optional_offset, optional_size = pe_offset + 24, coff[5]
    if optional_offset > len(data) or optional_size > len(data) - optional_offset:
        return None
    magic = _read(data, optional_offset, "<H")
    if magic is None or magic[0] not in {0x10b, 0x20b}:
        return None
    directory_offset = 112 if magic[0] == 0x20b else 96
    number_offset = 108 if magic[0] == 0x20b else 92
    if optional_size < directory_offset + (index + 1) * 8:
        return None
    count = _read(data, optional_offset + number_offset, "<I")
    if count is None or count[0] <= index:
        return None
    return _read(data, optional_offset + directory_offset + 8 * index, "<II")


def _pe_imports(data: bytes, image: BinaryImage, warnings: list[str]) -> list[dict[str, Any]]:
    directory = _pe_directory(data, 1)
    if directory is None or directory[0] == 0 or directory[1] == 0:
        return []
    rva, size = directory
    window = _pe_window(data, image, rva)
    if window is None or size < 20:
        warnings.append("PE import directory is outside scanned file-backed sections")
        return []
    offset, available = window
    declared = size // 20
    count = min(declared, available // 20, MAX_DESCRIPTORS)
    if count < declared:
        warnings.append("PE import descriptors truncated or capped")
    imports: list[dict[str, Any]] = []
    scanned_thunks = 0
    terminated = False
    for i in range(count):
        descriptor = _read(data, offset + 20 * i, "<IIIII")
        if descriptor is None:
            break
        lookup_rva, _timestamp, _forwarder_chain, name_rva, iat_rva = descriptor
        if descriptor == (0, 0, 0, 0, 0):
            terminated = True
            break
        library = _pe_name(data, image, name_rva)
        lookup = _pe_window(data, image, lookup_rva or iat_rva)
        if library is None or lookup is None or iat_rva == 0:
            warnings.append(f"PE import descriptor {i} has an unmapped name or thunk table")
            continue
        thunk_offset, thunk_available = lookup
        stride, fmt = (8, "<Q") if image.bits == 64 else (4, "<I")
        bit = 1 << (image.bits - 1)
        count_thunks = min(thunk_available // stride, MAX_SYMBOLS - scanned_thunks)
        if count_thunks == 0:
            warnings.append(f"PE import thunks capped at {MAX_SYMBOLS} entries")
            break
        thunk_terminated = False
        for j in range(count_thunks):
            scanned_thunks += 1
            value = _read(data, thunk_offset + j * stride, fmt)
            if value is None:
                break
            thunk = value[0]
            if thunk == 0:
                thunk_terminated = True
                break
            iat_slot = _pe_window(data, image, iat_rva + j * stride)
            if iat_slot is None or iat_slot[1] < stride:
                warnings.append(f"PE import descriptor {i} has an unmapped IAT slot")
                break
            symbol: dict[str, Any] = {"library": library,
                                      "address": image.image_base + iat_rva + j * stride,
                                      "source": "pe-import"}
            if thunk & bit:
                symbol["ordinal"] = thunk & 0xffff
                symbol["name"] = f"#{symbol['ordinal']}"
            else:
                hint_name = _pe_window(data, image, thunk)
                if hint_name is None or hint_name[1] < 3:
                    warnings.append(f"PE import descriptor {i} has an unmapped hint/name")
                    continue
                hint = _read(data, hint_name[0], "<H")
                name = _cstring(data, hint_name[0] + 2, hint_name[0] + hint_name[1])
                if hint is None or name is None:
                    warnings.append(f"PE import descriptor {i} has an unterminated name")
                    continue
                symbol["name"] = name
                symbol["hint"] = hint[0]
            imports.append(symbol)
        if not thunk_terminated:
            warnings.append(f"PE import descriptor {i} thunk table truncated or capped")
        if scanned_thunks >= MAX_SYMBOLS:
            warnings.append(f"PE import thunks capped at {MAX_SYMBOLS} entries")
            break
    if not terminated:
        warnings.append("PE import descriptor terminator is outside scan or declared directory")
    return imports


def _pe_table(data: bytes, image: BinaryImage, rva: int, stride: int,
              declared: int, warnings: list[str], label: str) -> tuple[int, int]:
    window = _pe_window(data, image, rva)
    if window is None:
        if declared:
            warnings.append(f"PE {label} table is unmapped")
        return 0, 0
    count = min(declared, window[1] // stride, MAX_SYMBOLS)
    if count < declared:
        warnings.append(f"PE {label} table truncated or capped")
    return window[0], count


def _pe_exports(data: bytes, image: BinaryImage, warnings: list[str]) -> list[dict[str, Any]]:
    directory = _pe_directory(data, 0)
    if directory is None or directory[0] == 0 or directory[1] == 0:
        return []
    directory_rva, directory_size = directory
    window = _pe_window(data, image, directory_rva)
    if window is None or window[1] < 40 or directory_size < 40:
        warnings.append("PE export directory is outside scanned file-backed sections")
        return []
    fields = _read(data, window[0], "<IIHHIIIIIII")
    if fields is None:
        return []
    (_flags, _timestamp, _major, _minor, _name_rva, base, nfuncs, nnames,
     funcs_rva, names_rva, ordinals_rva) = fields
    funcs_offset, funcs_count = _pe_table(data, image, funcs_rva, 4, nfuncs, warnings, "export address")
    names_offset, names_count = _pe_table(data, image, names_rva, 4, nnames, warnings, "export name")
    ordinals_offset, ordinals_count = _pe_table(data, image, ordinals_rva, 2, nnames, warnings, "export ordinal")
    named: dict[int, list[str]] = {}
    for i in range(min(names_count, ordinals_count)):
        name_rva = _read(data, names_offset + 4 * i, "<I")
        ordinal_index = _read(data, ordinals_offset + 2 * i, "<H")
        if name_rva is None or ordinal_index is None or ordinal_index[0] >= nfuncs:
            warnings.append("PE export name has an invalid ordinal index")
            continue
        name = _pe_name(data, image, name_rva[0])
        if name is None:
            warnings.append("PE export name is unmapped or unterminated")
            continue
        named.setdefault(ordinal_index[0], []).append(name)
    exports: list[dict[str, Any]] = []
    for i in range(funcs_count):
        address_rva = _read(data, funcs_offset + 4 * i, "<I")
        if address_rva is None or address_rva[0] == 0:  # Sparse EAT slots.
            continue
        ordinal = base + i
        forwarded = directory_rva <= address_rva[0] < directory_rva + directory_size
        forwarder = _pe_name(data, image, address_rva[0]) if forwarded else None
        if forwarded and forwarder is None:
            warnings.append(f"PE export ordinal {ordinal} has an invalid forwarder")
            continue
        for name in named.get(i, [f"#{ordinal}"]):
            symbol: dict[str, Any] = {"name": name, "ordinal": ordinal,
                                      "address": None if forwarded else image.image_base + address_rva[0],
                                      "source": "pe-export"}
            if forwarder is not None:
                symbol["forwarder"] = forwarder
            exports.append(symbol)
            if len(exports) >= MAX_SYMBOLS:
                warnings.append(f"PE exports capped at {MAX_SYMBOLS} entries")
                return exports
    return exports


def _elf_symbols(data: bytes, image: BinaryImage, warnings: list[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    bits, order = image.bits, "<" if image.endian == "little" else ">"
    if bits not in {32, 64} or image.endian not in {"little", "big"}:
        return [], []
    header_fmt = order + ("HHIIIIIHHHHHH" if bits == 32 else "HHIQQQIHHHHHH")
    header = _read(data, 16, header_fmt)
    if header is None:
        return [], []
    _type, _machine, _version, _entry, _phoff, shoff, _flags, _ehsize, _phentsize, _phnum, shentsize, shnum, _shstrndx = header
    section_fmt = order + ("IIIIIIIIII" if bits == 32 else "IIQQQQIIQQ")
    minimum = struct.calcsize(section_fmt)
    if not shnum or not shoff:
        return [], []  # Dynamic segment fallback is not currently implemented.
    if (shnum > MAX_ELF_SECTIONS or shentsize < minimum or shoff > len(data) or
            (shnum - 1) * shentsize + minimum > len(data) - shoff):
        warnings.append("ELF dynamic symbols unavailable: section table exceeds scan budget")
        return [], []
    sections = [_read(data, shoff + i * shentsize, section_fmt) for i in range(shnum)]
    imports: list[dict[str, Any]] = []
    exports: list[dict[str, Any]] = []
    scanned_symbols = 0
    seen: set[tuple[str, str, int | None]] = set()
    symbol_fmt = order + ("IIIBBH" if bits == 32 else "IBBHQQ")
    symbol_size = struct.calcsize(symbol_fmt)
    for section in sections:
        if section is None or section[1] != 11:  # SHT_DYNSYM only.
            continue
        offset, size, link, stride = section[4], section[5], section[6], section[9]
        if (link >= len(sections) or sections[link] is None or sections[link][1] != 3 or
                stride < symbol_size or size % stride):
            warnings.append("Malformed ELF dynamic symbol descriptor")
            continue
        strings_offset, strings_size = sections[link][4:6]
        if (offset > len(data) or size > len(data) - offset or
                strings_offset > len(data) or strings_size > len(data) - strings_offset):
            warnings.append("ELF dynamic symbols or names exceed scan budget")
            continue
        count = min(size // stride, MAX_SYMBOLS - scanned_symbols)
        if count < size // stride:
            warnings.append(f"ELF dynamic symbols capped at {MAX_SYMBOLS} entries")
        bad_name = False
        for i in range(count):
            scanned_symbols += 1
            record = _read(data, offset + i * stride, symbol_fmt)
            if record is None:
                break
            if bits == 32:
                name_offset, value, _size, info, other, section_index = record
            else:
                name_offset, info, other, section_index, value, _size = record
            binding, symbol_type = info >> 4, info & 15
            if binding not in {1, 2, 10} or symbol_type not in {0, 1, 2, 6, 10}:
                continue  # Global/weak/unique: NOTYPE, OBJECT, FUNC, TLS, IFUNC.
            if name_offset >= strings_size:
                bad_name = True
                continue
            name = _cstring(data, strings_offset + name_offset, strings_offset + strings_size)
            if name is None:
                bad_name = True
                continue
            imported = section_index == 0
            if not imported and (section_index >= len(sections) and section_index < 0xff00):
                continue
            if not imported and other & 3 in {1, 2}:  # Internal/hidden definitions.
                continue
            source = "elf-dynsym"
            key = ("import" if imported else "export", name, None if imported else value)
            if key in seen:
                continue
            seen.add(key)
            item: dict[str, Any] = {"name": name,
                                    "address": None if imported else value,
                                    "source": source,
                                    "binding": {1: "global", 2: "weak", 10: "unique"}[binding],
                                    "kind": {0: "notype", 1: "object", 2: "function", 6: "tls", 10: "ifunc"}[symbol_type]}
            (imports if imported else exports).append(item)
        if bad_name:
            warnings.append("ELF dynamic symbols contain invalid or unterminated names")
    return imports, exports


def _macho_symbols(data: bytes, image: BinaryImage, warnings: list[str]
                   ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Mach-O 导入/导出复用加载器的 nlist/间接符号表解析，避免两套实现。

    导入是未定义的外部符号：address 为其 GOT/la_symbol_ptr 指针槽位（与 PE 的 IAT
    槽位语义一致），stub_address 为 __stubs/__auth_stubs 中对应的桩。加载器已把符号表
    本身的警告写入 image.warnings，这里只返回导入/导出列表自身的截断警告。
    """
    from ...loaders.macho import read_macho_symbols
    try:
        table = read_macho_symbols(data)
    except BinaryFormatError as exc:
        warnings.append(f"Mach-O imports/exports unavailable: {exc}")
        return [], []
    if table.get("fat_slice_offset") != image.fat_slice_offset:
        warnings.append("Mach-O imports/exports unavailable: fat slice differs from loaded image")
        return [], []
    warnings.extend(table["symbol_warnings"])
    return table["imports"], table["exports"]


def parse_symbols(data: bytes, image: BinaryImage) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """Return (imports, exports, warnings) from metadata present in the scan.

    PE uses the import/export data directories and file-backed section RVAs.
    ELF uses SHT_DYNSYM plus its linked string table when section headers exist.
    Mach-O uses LC_SYMTAB/LC_DYSYMTAB (undefined externals become imports with
    their stub and pointer-slot addresses; defined externals become exports).
    """
    warnings: list[str] = []
    if image.format == "pe":
        return _pe_imports(data, image, warnings), _pe_exports(data, image, warnings), warnings
    if image.format == "elf":
        imports, exports = _elf_symbols(data, image, warnings)
        return imports, exports, warnings
    if image.format == "macho":
        imports, exports = _macho_symbols(data, image, warnings)
        return imports, exports, warnings
    return [], [], warnings
