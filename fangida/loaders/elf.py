"""ELF container loading and declared function-symbol metadata."""
from __future__ import annotations

import struct
from typing import Any

from .common import MAX_SECTIONS, MAX_SEGMENTS, MAX_SYMBOLS, _name, _table, _unpack
from .models import BinaryFormatError, BinaryImage
from .interfaces import LoaderMatch


def _elf(data: bytes) -> BinaryImage:
    if len(data) < 16:
        raise BinaryFormatError("Truncated ELF identification")
    bits = {1: 32, 2: 64}.get(data[4])
    endian = {1: "little", 2: "big"}.get(data[5])
    if bits is None or endian is None:
        raise BinaryFormatError("Unsupported ELF class or byte order")
    order = "<" if endian == "little" else ">"
    header = order + ("HHIIIIIHHHHHH" if bits == 32 else "HHIQQQIHHHHHH")
    (file_type, machine, _version, entry, phoff, shoff, _flags, _ehsize,
     phentsize, phnum, shentsize, shnum, shstrndx) = _unpack(data, 16, header)
    arch = {62: "x86_64", 183: "arm64", 3: "x86", 40: "arm"}.get(machine, f"elf-machine-{machine}")
    image = BinaryImage("elf", arch, bits, endian, entry_address=entry)
    image.image_base = 0 if file_type == 2 else None
    section_fmt = order + ("IIIIIIIIII" if bits == 32 else "IIQQQQIIQQ")
    segment_fmt = order + ("IIIIIIII" if bits == 32 else "IIQQQQQQ")
    section_size = struct.calcsize(section_fmt)
    segment_size = struct.calcsize(segment_fmt)
    sections: list[tuple[Any, ...]] = []
    if shnum == 0 and shoff:
        image.warnings.append("Extended ELF section count is not supported")
    elif shnum and not _table(data, shoff, shentsize, shnum, section_size, MAX_SECTIONS):
        image.warnings.append("Section table exceeds scan budget or safety limits")
    else:
        sections = [_unpack(data, shoff + i * shentsize, section_fmt) for i in range(shnum)]
    names = b""
    if sections and shstrndx < len(sections):
        strsec = sections[shstrndx]
        start, size = strsec[4], strsec[5]
        if start <= len(data) and size <= len(data) - start:
            names = data[start:start + size]
        else:
            image.warnings.append("Section names exceed scan budget")
    elif sections and shstrndx != 0:
        image.warnings.append("Invalid section name index")
    for index, section in enumerate(sections):
        nameoff, section_type, flags, address, offset, size = section[:6]
        executable = bool(flags & 0x4)
        image.sections.append({
            "name": _name(names, nameoff) or f"section_{index}",
            "address": address, "offset": offset, "size": size,
            "type": section_type, "executable": executable,
            "allocated": bool(flags & 0x2), "file_backed": section_type != 8 and size > 0,
            "file_size": size if section_type != 8 else 0,
            # ELF 节头只声明 SHF_WRITE；读取权限由覆盖该节的 PT_LOAD 给出。
            # 可重定位对象或未被加载段覆盖的节没有可推断的运行时读取权限。
            "section_writable": bool(flags & 0x1),
            "writable": bool(flags & 0x1), "readable": None,
            "permissions_source": "section",
        })
        if image.entry_offset is None and section_type != 8 and address <= entry < address + size:
            image.entry_offset = offset + entry - address
    _elf_symbols(data, image, sections, bits, order)
    from .elf_relocations import recover_dynamic_relocations
    image.dynamic_relocations, relocation_warnings = recover_dynamic_relocations(
        data, sections, bits, order, file_type=file_type,
        section_names=[section["name"] for section in image.sections])
    image.warnings.extend(relocation_warnings)
    load_permissions: list[tuple[int, int, int]] = []
    if phnum and not _table(data, phoff, phentsize, phnum, segment_size, MAX_SEGMENTS):
        image.warnings.append("Program header table exceeds scan budget or safety limits")
    else:
        for i in range(phnum):
            segment = _unpack(data, phoff + i * phentsize, segment_fmt)
            if bits == 32:
                ptype, offset, address, _physical, filesize, _memsize, flags, _align = segment
            else:
                ptype, flags, offset, address, _physical, filesize, _memsize, _align = segment
            if ptype == 1 and address <= entry < address + filesize:
                image.entry_offset = offset + entry - address
            if ptype == 1:
                load_permissions.append((address, address + _memsize, flags))
            if ptype == 1 and not sections:
                image.sections.append({"name": f"segment_{i}", "address": address,
                                       "offset": offset, "size": filesize, "type": "PT_LOAD",
                                       "executable": bool(flags & 1), "allocated": True,
                                       "file_backed": filesize > 0, "file_size": filesize,
                                       "readable": bool(flags & 4), "writable": bool(flags & 2),
                                       "permissions_source": "segment"})
    if sections:
        for section in image.sections:
            if not section["allocated"] or not section["size"]:
                continue
            start = section["address"]
            end = start + section["size"]
            if not any(low <= start and end <= high for low, high, _flags in load_permissions):
                continue
            permissions = [flags for low, high, flags in load_permissions
                           if low < end and start < high]
            # 重叠加载段只要一个声明可写就保留写入可能，不能据只读节头推断常量。
            section["writable"] = any(flags & 2 for flags in permissions)
            section["permissions_source"] = "segment"
            readable = {bool(flags & 4) for flags in permissions}
            if len(readable) == 1:
                section["readable"] = readable.pop()
    if entry and image.entry_offset is None:
        image.warnings.append("Entry point does not map to scanned loadable content")
    return image


def _elf_symbols(data: bytes, image: BinaryImage, sections: list[tuple[Any, ...]],
                 bits: int, order: str) -> None:
    """Recover only explicitly defined STT_FUNC records in executable sections."""
    fmt = order + ("IIIBBH" if bits == 32 else "IBBHQQ")
    minimum = struct.calcsize(fmt)
    seen: set[tuple[int, str]] = set()
    for section in sections:
        if section[1] not in {2, 11}:  # SHT_SYMTAB, SHT_DYNSYM
            continue
        source = "symtab" if section[1] == 2 else "dynsym"
        offset, size, link, stride = section[4], section[5], section[6], section[9]
        if link >= len(sections) or stride < minimum or size % stride:
            image.warnings.append(f"Malformed ELF {source} descriptor")
            continue
        string_offset, string_size = sections[link][4:6]
        if (offset > len(data) or size > len(data) - offset or
                string_offset > len(data) or string_size > len(data) - string_offset):
            image.warnings.append(f"ELF {source} exceeds scan budget")
            continue
        strings = data[string_offset:string_offset + string_size]
        count = min(size // stride, MAX_SYMBOLS)
        if size // stride > MAX_SYMBOLS:
            image.warnings.append(f"ELF {source} capped at {MAX_SYMBOLS} entries")
        for index in range(count):
            symbol = _unpack(data, offset + index * stride, fmt)
            if bits == 32:
                nameoff, address, func_size, info, _other, shndx = symbol
            else:
                nameoff, info, _other, shndx, address, func_size = symbol
            if info & 0xF != 2 or shndx == 0 or shndx >= len(sections):
                continue
            if not sections[shndx][2] & 0x4:  # SHF_EXECINSTR
                continue
            name = _name(strings, nameoff)
            if not name or (address, name) in seen:
                continue
            seen.add((address, name))
            image.functions.append({"name": name, "start": address, "size": func_size,
                                    "source": source, "blocks": [], "cfg": {"edges": []},
                                    "xrefs_in": [], "xrefs_out": []})
    image.functions.sort(key=lambda function: (function["start"], function["name"]))


class ELFLoader:
    name = "elf"
    extensions = {".elf": "elf"}

    def probe(self, data: bytes, path: object = None) -> LoaderMatch | None:
        return LoaderMatch("elf") if data.startswith(b"\x7fELF") else None

    def load(self, data: bytes, kind: str = "elf") -> BinaryImage:
        return _elf(data)


load_elf = _elf
ElfLoader = ELFLoader


def recover_function_ranges(data: bytes, image: BinaryImage) -> tuple[list[dict[str, Any]], list[str]]:
    """Explicitly recover declared unwind ranges and initialization roots.

    This opt-in operation does not alter the image or the legacy ELF parser.
    Unwind ranges are compiler declarations, not a count of semantic functions.
    """
    from .elf_unwind import recover_function_ranges as recover
    return recover(data, image)


def recover_code_pointers(data: bytes, image: BinaryImage) -> tuple[list[dict[str, Any]], list[str]]:
    """Recover relocation-backed data pointers whose value lands in code.

    附加的只读操作，不修改 ``image``，也不解码指令。返回的候选只经容器结构过滤
    （指针目标落在可执行区域内），是否接受为函数入口由分析核心按完整证据规则决定。
    """
    from .elf_pointers import recover_code_pointers as recover
    return recover(data, image)
