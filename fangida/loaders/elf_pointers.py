"""Bounded recovery of ELF relocation-backed data pointers into code.

容器结构解析属于 Loader：本模块只读取 ELF 的动态重定位表，取出“写入某个数据
槽位、而其值指向可执行区域”的指针，作为候选函数入口交给分析核心。它不解码任何
指令、不恢复 CFG，也不判断候选是否真的是函数——这样的指针既可能来自虚表、JNI
方法表、回调表、函数指针数组，也可能是跳转表项或混淆分支表项。裁决（按相邻槽位
组成的指针表做表级证据判定）全部由分析核心在拥有解码快照与首轮 CFG 之后施加。
这里只提供“指针存放地址 + 重定位类型/编码 + 目标地址”的可审计证据；槽位落在
.init_array/.fini_array/.preinit_array 中的候选另带 ``structure`` 证据。

REL 与 RELR 的隐式加数从槽位当前内容读取（按 Loader 的节映射换算文件偏移）；RELA
使用显式加数。支持 SHT_RELA/SHT_REL、SHT_RELR（19）与 Android 的 SHT_ANDROID_RELR、
APS2 打包的 SHT_ANDROID_REL/RELA；畸形或无法解析的表产生明确告警。GLOB_DAT/ABS
只接受指向本地已定义符号、且符号值落在可执行区域内的项：普通 REL/RELA 中的这类项来自
Loader 的 dynamic_relocations，APS2 打包表中的这类项经该节 sh_link 指向的动态符号表读取。
"""
from __future__ import annotations

import struct
from bisect import bisect_right
from typing import Any

from .common import MAX_SECTIONS
from .models import BinaryImage

MAX_POINTER_RELOCATIONS = 1 << 20
MAX_WARNINGS = 64

# 重定位节类型：标准 RELA/REL/RELR 与 Android 打包格式（APS2 编码的 REL/RELA、RELR）。
_SHT_RELA, _SHT_REL, _SHT_RELR = 4, 9, 19
_SHT_ANDROID_REL, _SHT_ANDROID_RELA, _SHT_ANDROID_RELR = 0x60000001, 0x60000002, 0x6fffff00
_RELOCATION_SECTION_TYPES = frozenset({_SHT_RELA, _SHT_REL, _SHT_RELR, _SHT_ANDROID_REL,
                                       _SHT_ANDROID_RELA, _SHT_ANDROID_RELR})
# 容器声明的函数指针数组节（SHT_INIT_ARRAY/FINI_ARRAY/PREINIT_ARRAY）。
_ARRAY_TYPES = {14: "init_array", 15: "fini_array", 16: "preinit_array"}
# APS2 分组标志（bionic linker_reloc_iterators.h）。
_GROUPED_BY_INFO, _GROUPED_BY_OFFSET_DELTA, _GROUPED_BY_ADDEND, _GROUP_HAS_ADDEND = 1, 2, 4, 8

# 每种架构的（RELATIVE, GLOB_DAT, 绝对宽指针）重定位类型号。绝对类型是指向符号或
# 直接写入链接期地址的 64/32 位数据重定位（R_*_64 / R_386_32 / R_ARM_ABS32）。
_RELATIVE = {"x86_64": 8, "x86": 8, "arm64": 1027, "arm": 23}
_GLOB_DAT = {"x86_64": 6, "x86": 6, "arm64": 1025, "arm": 21}
_ABSOLUTE = {"x86_64": 1, "x86": 1, "arm64": 257, "arm": 2}


class _ExecutableIndex:
    """可执行区域的只读区间索引；成员判断用二分查找。"""

    def __init__(self, image: BinaryImage, data_size: int) -> None:
        spans: list[tuple[int, int]] = []
        for section in image.sections:
            if not section.get("executable") or section.get("type") == 8:
                continue
            address, offset, size = (section.get(key) for key in ("address", "offset", "size"))
            if any(type(value) is not int or value < 0 for value in (address, offset, size)):
                continue
            available = min(size, max(0, data_size - offset))
            if available > 0:
                spans.append((address, address + available))
        spans.sort()
        self._starts = [start for start, _ in spans]
        self._ends = [end for _, end in spans]

    def contains(self, address: int) -> bool:
        if type(address) is not int:
            return False
        position = bisect_right(self._starts, address) - 1
        return position >= 0 and address < self._ends[position]


def _offset_for_address(image: BinaryImage, data_size: int, address: int) -> int | None:
    """把一个虚拟地址换算成文件偏移（只用 Loader 已声明、且有文件字节的节）。"""
    for section in image.sections:
        if section.get("type") == 8:
            continue
        start, offset, size = (section.get(key) for key in ("address", "offset", "size"))
        if any(type(value) is not int or value < 0 for value in (start, offset, size)):
            continue
        available = min(size, max(0, data_size - offset))
        if start <= address < start + available:
            return offset + address - start
    return None


def _relr_slots(words, bits: int):
    """展开 SHT_RELR 位图编码，逐个产出被相对重定位的槽位地址。

    偶数项是地址（该处一个槽位，随后基址前移一个指针宽度）；奇数项是位图，第 1..bits-1
    位依次对应基址起的连续槽位，每个位图之后基址前移 (bits-1) 个指针宽度。
    """
    width = bits // 8
    base: int | None = None
    for word in words:
        if word & 1 == 0:
            yield word
            base = word + width
            continue
        if base is None:
            raise ValueError("bitmap entry precedes an address entry")
        bitmap, slot = word >> 1, base
        while bitmap:
            if bitmap & 1:
                yield slot
            bitmap >>= 1
            slot += width
        base += (bits - 1) * width


def _android_packed(raw: bytes, bits: int, explicit: bool):
    """解码 Android APS2 打包重定位，逐项产出 (r_offset, r_info, r_addend)。

    格式：魔数 "APS2"，随后是 SLEB128 序列——重定位总数、初始 r_offset，再按组给出
    组大小、组标志与按标志共享的 offset 增量/r_info/addend 增量。REL（无显式加数）
    的组不允许带加数。所有读取都在输入字节内做边界检查，越界或不一致时抛出 ValueError。
    """
    if raw[:4] != b"APS2":
        raise ValueError("missing APS2 magic")
    position = 4
    limit = len(raw)

    def sleb() -> int:
        nonlocal position
        value = shift = 0
        while True:
            if position >= limit:
                raise ValueError("truncated SLEB128 value")
            byte = raw[position]
            position += 1
            value |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                break
            if shift > 70:
                raise ValueError("overlong SLEB128 value")
        if byte & 0x40:
            value -= 1 << shift
        return value

    mask = (1 << bits) - 1
    count, offset = sleb(), sleb()
    if count < 0:
        raise ValueError("negative relocation count")
    info = addend = delta = 0
    produced = 0
    while produced < count:
        group_size, flags = sleb(), sleb()
        if group_size <= 0:
            raise ValueError("empty relocation group")
        has_addend = bool(flags & _GROUP_HAS_ADDEND)
        if has_addend and not explicit:
            raise ValueError("REL group carries addends")
        if flags & _GROUPED_BY_OFFSET_DELTA:
            delta = sleb()
        if flags & _GROUPED_BY_INFO:
            info = sleb()
        if has_addend and flags & _GROUPED_BY_ADDEND:
            addend += sleb()
        elif not has_addend:
            addend = 0
        for _ in range(group_size):
            if produced >= count:
                break
            offset += delta if flags & _GROUPED_BY_OFFSET_DELTA else sleb()
            if not flags & _GROUPED_BY_INFO:
                info = sleb()
            if has_addend and not flags & _GROUPED_BY_ADDEND:
                addend += sleb()
            produced += 1
            yield offset & mask, info & ((1 << 64) - 1), addend & mask


def recover_code_pointers(data: bytes, image: BinaryImage) -> tuple[list[dict[str, Any]], list[str]]:
    """返回指向可执行区域的重定位候选指针，以及告警。

    每个候选：``{"target": 代码地址, "source": "data_pointer",
    "evidence": {"pointer_address": 槽位虚拟地址, "relocation_type": 类型号,
    "relocation": "relative"/"glob_dat"/"absolute"}}``，RELATIVE 另带 ``encoding``，
    槽位在 init/fini 数组中时另带 ``structure``。候选只经边界与范围过滤，是否接受为
    函数入口由分析核心按表级证据规则决定。此操作不修改 ``image``。
    """
    warnings: list[str] = []

    def warn(message: str) -> None:
        if len(warnings) < MAX_WARNINGS and message not in warnings:
            warnings.append(message)

    if image.format != "elf" or image.bits not in (32, 64) or image.endian not in ("little", "big"):
        return [], ["ELF code-pointer recovery requires a supported ELF image"]
    if len(data) < 18 or data[:4] != b"\x7fELF":
        return [], ["ELF code-pointer recovery requires ELF file bytes"]
    file_type = int.from_bytes(data[16:18], image.endian)
    if file_type not in (2, 3):
        return [], ["ELF code-pointer recovery requires a linked executable or shared object"]

    architecture = image.architecture
    relative_type = _RELATIVE.get(architecture)
    glob_dat_type = _GLOB_DAT.get(architecture)
    absolute_type = _ABSOLUTE.get(architecture)
    if relative_type is None:
        return [], [f"ELF code-pointer recovery does not model {architecture} relocations"]

    executable = _ExecutableIndex(image, len(data))
    pointer_size = image.bits // 8
    order = "<" if image.endian == "little" else ">"
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[int, int]] = set()

    structures: list[tuple[int, int, str]] = []

    def emit(target: int, pointer_address: int, relocation_type: int, kind: str,
             encoding: str | None = None) -> None:
        if not executable.contains(target):
            return
        key = (target, pointer_address)
        if key in seen:
            return
        seen.add(key)
        # ARM 的函数指针用 bit0 选择 Thumb ISA；目标地址对齐到指令边界，另记原始值。
        thumb = architecture == "arm" and bool(target & 1)
        start = target & ~1 if thumb else target
        if not executable.contains(start):
            return
        candidate = {"target": start, "source": "data_pointer",
                     "evidence": {"pointer_address": pointer_address,
                                  "relocation_type": relocation_type, "relocation": kind}}
        if encoding is not None:
            # 新增证据字段：重定位表的编码（rela/rel/relr/android_rela/android_rel/android_relr）。
            candidate["evidence"]["encoding"] = encoding
        structure = next((name for low, high, name in structures
                          if low <= pointer_address < high), None)
        if structure is not None:
            candidate["evidence"]["structure"] = structure
        if thumb:
            candidate["isa_mode"] = "thumb"
            candidate["evidence"]["raw_value"] = target
        candidates.append(candidate)

    # --- 1. RELATIVE：必须自读重定位表取加数/槽位内容（Loader 的 dynamic_relocations
    #        只保留带命名符号的项，加数在那里不可用）。支持 SHT_RELA/SHT_REL、SHT_RELR
    #        （含 Android 的 SHT_ANDROID_RELR）与 Android APS2 打包重定位；无法解析的
    #        表给出明确告警，不再静默忽略。---
    budget = {"scanned": 0}

    def admit() -> bool:
        if budget["scanned"] >= MAX_POINTER_RELOCATIONS:
            warn("ELF code-pointer relocation scan budget exhausted")
            return False
        budget["scanned"] += 1
        return True

    def slot_value(place: int) -> int | None:
        slot = _offset_for_address(image, len(data), place)
        if slot is None or slot + pointer_size > len(data):
            return None
        return int.from_bytes(data[slot:slot + pointer_size], image.endian)

    def relative(place: int, info: int, addend: int | None, encoding: str) -> None:
        symbol_index = info >> (8 if image.bits == 32 else 32)
        relocation_type = info & (0xff if image.bits == 32 else 0xffffffff)
        if relocation_type != relative_type or symbol_index != 0:
            return
        value = (addend & mask) if addend is not None else slot_value(place)
        if value is not None:
            emit(value, place, relocation_type, "relative", encoding)

    symbol_fmt = order + ("IIIBBH" if image.bits == 32 else "IBBHQQ")
    symbol_size = struct.calcsize(symbol_fmt)

    def defined_symbol(headers: list[tuple[int, ...]], link: int, symbol_index: int) -> int | None:
        """读取打包重定位节 sh_link 指向的 SHT_DYNSYM 中第 symbol_index 项：已定义时返回符号值。

        Loader 的 dynamic_relocations 只读普通 REL/RELA，APS2 打包表里的 GLOB_DAT/ABS 由这里
        按同一规则（本地已定义符号）补上；越界或类型不符时返回 None，不臆测。
        """
        if type(link) is not int or not 0 <= link < len(headers) or headers[link][1] != 11:
            return None
        table_offset, table_size, entry_size = headers[link][4], headers[link][5], headers[link][9]
        position = table_offset + symbol_index * entry_size
        if (type(entry_size) is not int or entry_size < symbol_size or symbol_index <= 0
                or (symbol_index + 1) * entry_size > table_size or position + symbol_size > len(data)):
            return None
        record = struct.unpack_from(symbol_fmt, data, position)
        value, section_index = (record[1], record[5]) if image.bits == 32 else (record[4], record[3])
        return value if section_index != 0 else None

    def symbolic(headers: list[tuple[int, ...]], link: int, place: int, info: int,
                 addend: int | None, encoding: str) -> None:
        # 只接受 GLOB_DAT 与绝对宽指针；REL 形式的隐式加数与 Loader 路径一致按 0 处理。
        symbol_index = info >> (8 if image.bits == 32 else 32)
        relocation_type = info & (0xff if image.bits == 32 else 0xffffffff)
        if symbol_index == 0 or relocation_type not in (glob_dat_type, absolute_type):
            return
        value = defined_symbol(headers, link, symbol_index)
        if value is None:
            return
        emit((value + (addend or 0)) & mask, place, relocation_type,
             "glob_dat" if relocation_type == glob_dat_type else "absolute", encoding)

    mask = (1 << image.bits) - 1
    try:
        section_header = struct.unpack_from(
            order + ("HHIIIIIHHHHHH" if image.bits == 32 else "HHIQQQIHHHHHH"), data, 16)
        shoff, section_stride, section_count = section_header[5], section_header[10], section_header[11]
        section_fmt = order + ("IIIIIIIIII" if image.bits == 32 else "IIQQQQIIQQ")
        minimum = struct.calcsize(section_fmt)
        if section_count > MAX_SECTIONS:
            warn("ELF relocation section scan capped at section budget")
            section_count = MAX_SECTIONS
        if section_stride < minimum or shoff < 0 or shoff + section_count * section_stride > len(data):
            raise ValueError("relocation section table is unavailable")
        headers = [struct.unpack_from(section_fmt, data, shoff + index * section_stride)
                   for index in range(section_count)]
        # 容器声明的函数指针结构（.init_array/.fini_array/.preinit_array）：槽位落在其中的
        # 候选带 ``structure`` 证据，分析核心据此视为声明结构。
        structures.extend((header[3], header[3] + header[5], _ARRAY_TYPES[header[1]])
                          for header in headers if header[1] in _ARRAY_TYPES and header[5] > 0)
        relocation_fmt = order + ("II" if image.bits == 32 else "QQ")
        addend_fmt = order + ("IIi" if image.bits == 32 else "QQq")
        for header in headers:
            section_type, offset, size, entry_size = header[1], header[4], header[5], header[9]
            if section_type not in _RELOCATION_SECTION_TYPES:
                continue
            if offset < 0 or offset + size > len(data):
                warn("Malformed or truncated ELF relocation table")
                continue
            if budget["scanned"] >= MAX_POINTER_RELOCATIONS:
                warn("ELF code-pointer relocation scan budget exhausted")
                break
            if section_type in (_SHT_RELA, _SHT_REL):
                explicit = section_type == _SHT_RELA
                fmt = addend_fmt if explicit else relocation_fmt
                entry_minimum = struct.calcsize(fmt)
                if type(entry_size) is not int or entry_size < entry_minimum or size % entry_size:
                    warn("Malformed or truncated ELF relocation table")
                    continue
                for position in range(offset, offset + size, entry_size):
                    if not admit():
                        break
                    record = struct.unpack_from(fmt, data, position)
                    relative(record[0], record[1], record[2] if explicit else None, "rel" + ("a" if explicit else ""))
            elif section_type in (_SHT_RELR, _SHT_ANDROID_RELR):
                encoding = "relr" if section_type == _SHT_RELR else "android_relr"
                if size % pointer_size:
                    warn(f"Malformed ELF {encoding} relocation table")
                    continue
                words = (int.from_bytes(data[position:position + pointer_size], image.endian)
                         for position in range(offset, offset + size, pointer_size))
                try:
                    for place in _relr_slots(words, image.bits):
                        if not admit():
                            break
                        value = slot_value(place)
                        if value is not None:
                            emit(value, place, relative_type, "relative", encoding)
                except ValueError as exc:
                    warn(f"Malformed ELF {encoding} relocation table: {exc}")
            else:
                explicit = section_type == _SHT_ANDROID_RELA
                encoding = "android_rela" if explicit else "android_rel"
                try:
                    for place, info, addend in _android_packed(data[offset:offset + size],
                                                                image.bits, explicit):
                        if not admit():
                            break
                        relative(place & mask, info, addend if explicit else None, encoding)
                        # 打包表里带符号的 GLOB_DAT/ABS（普通表由下方 Loader 路径处理）。
                        symbolic(headers, header[6], place & mask, info,
                                 addend if explicit else None, encoding)
                except ValueError as exc:
                    warn(f"ELF {encoding} packed relocations unavailable: {exc}")
    except (struct.error, ValueError) as exc:
        warn(f"ELF RELATIVE code pointers unavailable: {exc}")

    # --- 2. GLOB_DAT / 绝对宽指针：复用 Loader 已解析的命名动态重定位，只接受指向
    #        本地已定义符号、符号值落在可执行区域内的项（加数通常为 0）。---
    for record in image.dynamic_relocations or ():
        if not isinstance(record, dict):
            continue
        relocation_type = record.get("relocation_type", record.get("type"))
        if relocation_type not in (glob_dat_type, absolute_type):
            continue
        if record.get("address_kind", "virtual_address") != "virtual_address":
            continue
        if not record.get("symbol_defined"):
            continue
        value = record.get("symbol_value")
        if type(value) is not int:
            continue
        addend = record.get("addend") or 0
        target = (value + addend) & ((1 << image.bits) - 1)
        place = record.get("address")
        if type(place) is not int:
            continue
        emit(target, place, relocation_type,
             "glob_dat" if relocation_type == glob_dat_type else "absolute")
    return candidates, warnings
