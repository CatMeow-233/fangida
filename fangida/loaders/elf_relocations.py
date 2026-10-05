"""Bounded ELF dynamic-symbol relocation metadata, without code analysis.

The caller supplies the container's already scanned section headers. REL
implicit addends remain unknown: decoding them needs a relocation-type
contract, which this generic metadata reader does not invent. Multiple
records at one address are retained as separate evidence.
"""
from __future__ import annotations

import struct
from typing import Any

from .common import MAX_SECTIONS, MAX_SYMBOLS

MAX_RELOCATIONS = 65536
MAX_NAME_BYTES = 256
MAX_WARNINGS = 64


def _range(data: bytes, offset: int, size: int) -> bool:
    return (type(offset) is int and type(size) is int and offset >= 0 and size >= 0
            and offset <= len(data) and size <= len(data) - offset)


def recover_dynamic_relocations(data: bytes, sections: list[tuple[Any, ...]],
                                bits: int, order: str, *, section_names=(),
                                file_type=3,
                                max_relocations=MAX_RELOCATIONS,
                                max_symbols=MAX_SYMBOLS,
                                max_name_bytes=MAX_NAME_BYTES) -> tuple[list[dict[str, Any]], list[str]]:
    """Read named REL/RELA references to linked DYNSYM records.

    ``address`` is the ELF r_offset value (a virtual address in ET_DYN/EXEC).
    ``got_address`` is present only for a slot inside a declared .got section;
    no instruction decoder or fixed PLT entry layout is used here. A symbol's
    raw value is retained even when undefined; it is not a resolved runtime
    function address. Budget exhaustion returns a bounded prefix and warnings.
    """
    if bits not in (32, 64) or order not in ("<", ">"):
        raise ValueError("ELF relocation class or byte order is unsupported")
    for value, limit, label in ((max_relocations, MAX_RELOCATIONS, "relocation"),
                                (max_symbols, MAX_SYMBOLS, "symbol"),
                                (max_name_bytes, MAX_NAME_BYTES, "name")):
        if type(value) is not int or value < 0 or value > limit or label == "name" and value == 0:
            raise ValueError(f"Invalid ELF {label} scan budget")
    warnings, seen_warnings = [], set()

    def warn(message):
        if message not in seen_warnings and len(warnings) < MAX_WARNINGS:
            seen_warnings.add(message)
            warnings.append(message)

    if len(sections) > MAX_SECTIONS:
        warn("ELF relocation section scan capped at section budget")
    scanned = sections[:MAX_SECTIONS]
    symbol_fmt = order + ("IIIBBH" if bits == 32 else "IBBHQQ")
    symbol_minimum = struct.calcsize(symbol_fmt)
    tables, symbols, records = {}, {}, []
    scanned_records = 0

    def table(index):
        if index in tables:
            return tables[index]
        result = None
        if type(index) is int and 0 <= index < len(scanned):
            section = scanned[index]
            if len(section) >= 10 and section[1] == 11:
                offset, size, link, stride = section[4], section[5], section[6], section[9]
                if (type(stride) is int and stride >= symbol_minimum and _range(data, offset, size)
                        and size % stride == 0 and type(link) is int and 0 <= link < len(scanned)):
                    strings = scanned[link]
                    if len(strings) >= 10 and strings[1] == 3 and _range(data, strings[4], strings[5]):
                        result = (offset, size // stride, stride, strings[4], strings[5])
        if result is None:
            warn("Malformed ELF relocation-linked dynamic symbol/string table")
        tables[index] = result
        return result

    def symbol(table_index, symbol_index, descriptor):
        key = (table_index, symbol_index)
        if key in symbols:
            return symbols[key]
        offset, count, stride, string_offset, string_size = descriptor
        if symbol_index >= count:
            warn("ELF relocation symbol index exceeds linked table")
            return None
        if len(symbols) >= max_symbols:
            warn("ELF relocation symbol lookup budget exhausted")
            return None
        unpacked = struct.unpack_from(symbol_fmt, data, offset + symbol_index * stride)
        if bits == 32:
            name_offset, value, size, info, other, section_index = unpacked
        else:
            name_offset, info, other, section_index, value, size = unpacked
        result = None
        if 0 < section_index < 0xff00 and section_index >= len(scanned):
            warn("ELF relocation symbol section index exceeds section table")
        elif name_offset == 0:
            pass  # Legitimate unnamed symbol; it gives no function identity.
        elif name_offset >= string_size:
            warn("ELF relocation symbol name exceeds linked string table")
        else:
            start = string_offset + name_offset
            raw = data[start:start + min(max_name_bytes, string_size - name_offset)]
            terminator = raw.find(b"\0")
            if terminator < 0:
                warn("ELF relocation symbol name is unterminated or exceeds name budget")
            elif terminator:
                binding = info >> 4
                result = {"symbol_name": raw[:terminator].decode("utf-8", "replace"),
                          "symbol_value": value, "symbol_size": size,
                          "symbol_type": info & 15, "binding": binding,
                          "binding_name": {0: "local", 1: "global", 2: "weak"}.get(binding, "other"),
                          "visibility": other & 7, "symbol_other": other,
                          "symbol_section_index": section_index,
                          "symbol_defined": section_index != 0,
                          "symbol_section_index_extended": section_index == 0xffff}
        symbols[key] = result
        return result

    # Names annotate container evidence; they are not a PLT layout heuristic.
    got_ranges = []
    for index, section in enumerate(scanned):
        name = section_names[index] if index < len(section_names) else ""
        if (name in {".got", ".got.plt"} and len(section) >= 10 and section[2] & 2
                and type(section[3]) is int and type(section[5]) is int and section[3] >= 0 and section[5] > 0):
            got_ranges.append((section[3], section[5]))

    for section_index, section in enumerate(scanned):
        if len(section) < 10 or section[1] not in {4, 9}:
            continue
        offset, size, link, stride = section[4], section[5], section[6], section[9]
        relocation_fmt = order + ("II" if bits == 32 else "QQ")
        explicit = section[1] == 4
        if explicit:
            relocation_fmt += "i" if bits == 32 else "q"
        minimum = struct.calcsize(relocation_fmt)
        if type(stride) is not int or stride < minimum or not _range(data, offset, size) or size % stride:
            warn("Malformed or truncated ELF dynamic relocation table")
            continue
        if type(link) is int and 0 <= link < len(scanned) and len(scanned[link]) >= 10 and scanned[link][1] == 2:
            continue  # Valid ordinary SYMTAB relocations are not dynamic metadata.
        descriptor = table(link)
        if descriptor is None:
            continue
        count = size // stride
        remaining = max_relocations - scanned_records
        if count > remaining:
            warn("ELF dynamic relocation scan budget exhausted")
        for index in range(min(count, remaining)):
            position = offset + index * stride
            unpacked = struct.unpack_from(relocation_fmt, data, position)
            address, info = unpacked[:2]
            symbol_index = info >> (8 if bits == 32 else 32)
            kind = info & (0xff if bits == 32 else 0xffffffff)
            scanned_records += 1
            if symbol_index == 0:
                continue  # No named dynamic symbol; do not infer one from bytes.
            metadata = symbol(link, symbol_index, descriptor)
            if metadata is None:
                continue
            section_name = section_names[section_index] if section_index < len(section_names) else ""
            records.append({**metadata, "address": address, "relocation_address": address,
                            "address_kind": "virtual_address" if file_type in {2, 3} else "section_offset",
                            "got_address": address if file_type in {2, 3} and any(start <= address and address - start <= length - bits // 8
                                                           for start, length in got_ranges) else None,
                            "type": kind, "relocation_type": kind,
                            "symbol_index": symbol_index, "symbol_table_index": link,
                            "target_section_index": section[7],
                            "addend": unpacked[2] if explicit else None,
                            "explicit_addend": explicit, "source": "rela" if explicit else "rel",
                            "symbol_source": "dynsym", "relocation_section": section_name,
                            "relocation_section_index": section_index,
                            "relocation_index": index, "record_offset": position})
        if count > remaining:
            break
    return records, warnings
