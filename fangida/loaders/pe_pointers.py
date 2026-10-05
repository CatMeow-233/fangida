"""Bounded recovery of PE declared function starts and code pointers.

容器结构解析属于 Loader：本模块只读取 PE 的数据目录与节表，取出容器自身声明的
函数起点与指向代码的指针，交给分析核心做候选。不解码指令、不恢复 CFG、不修改镜像。
来源：
  * ``.pdata`` 的 RUNTIME_FUNCTION 起点，按 COFF Machine 区分格式：x64 为 12 字节
    （Begin, End, UnwindInfo）；ARM64/ARM32 为 8 字节（Begin, UnwindData），UnwindData
    低 2 位非 0 时是打包展开数据、直接给出函数长度，为 0 时指向 .xdata（能可靠读出首字
    才取长度，否则大小未知）。其它 Machine 不解析并告警；
  * 导出表 AddressOfFunctions 中指向可执行节的 RVA；
  * 基址重定位（DIR64 / HIGHLOW）写入处存放的、指向可执行节的绝对地址。它们可能是函数
    指针表、虚表，也可能是 switch 跳转表项或指令操作数——这里不做区分，只给出逐槽位的
    可审计证据（``recover_code_pointers``），由分析核心按表级证据裁决。
所有地址都在输入字节内做边界检查，畸形的可选结构只产生告警。
"""
from __future__ import annotations

import struct
from bisect import bisect_right
from typing import Any

from .common import MAX_SECTIONS
from .models import BinaryImage

MAX_RUNTIME_FUNCTIONS = 1 << 20
MAX_EXPORTS = 1 << 20
MAX_RELOCATION_BLOCKS = 1 << 16
MAX_WARNINGS = 64
_RUNTIME_FUNCTION_SIZE = 12  # BeginAddress, EndAddress, UnwindInfoAddress（均为 RVA）
# COFF Machine → (.pdata 项大小, 函数长度单位字节)。x64 的项自带 EndAddress，单位不适用；
# ARM64 的长度以 4 字节为单位，ARM32（Thumb-2，ARMNT）以 2 字节为单位。
_MACHINE_AMD64 = 0x8664
_MACHINE_ARM64 = 0xAA64
_MACHINE_ARMNT = 0x1C4
_PDATA_LAYOUT = {_MACHINE_AMD64: (12, 0), _MACHINE_ARM64: (8, 4), _MACHINE_ARMNT: (8, 2)}


def _machine(data: bytes) -> int | None:
    """读取 COFF 文件头的 Machine 字段；头部不可用时返回 None。"""
    try:
        peoff, = struct.unpack_from("<I", data, 0x3c)
        if data[peoff:peoff + 4] != b"PE\0\0":
            return None
        machine, = struct.unpack_from("<H", data, peoff + 4)
        return machine
    except struct.error:
        return None


def _packed_or_xdata_length(data: bytes, sections: "_SectionMap", unwind: int,
                            unit: int) -> tuple[int | None, str]:
    """ARM64/ARM32 .pdata 第二字的函数长度：返回 (字节长度或 None, 证据类型)。

    低 2 位为 1/2：打包展开数据，第 2–12 位是以 ``unit`` 字节为单位的函数长度；
    低 2 位为 0：整字是 .xdata 的 RVA，其首字第 0–17 位是同单位的函数长度（.xdata 必须
    落在有文件字节的节内才读取）；低 2 位为 3：保留编码，长度未知。
    """
    flag = unwind & 3
    if flag in (1, 2):
        length = ((unwind >> 2) & 0x7FF) * unit
        return (length or None), "packed"
    if flag == 3:
        return None, "reserved"
    offset = sections.offset_for_rva(unwind)
    if offset is None or offset + 4 > len(data):
        return None, "xdata_unavailable"
    header, = struct.unpack_from("<I", data, offset)
    length = (header & 0x3FFFF) * unit
    return (length or None), "xdata"


class _SectionMap:
    """RVA ↔ 文件偏移映射与可执行区域成员判断（只用有文件字节的节）。"""

    def __init__(self, image: BinaryImage, data_size: int) -> None:
        base = image.image_base or 0
        self._base = base
        spans: list[tuple[int, int, int]] = []   # (rva, rva_end_backed, offset)
        exec_spans: list[tuple[int, int]] = []    # (va, va_end_backed)
        for section in image.sections:
            address, offset, size = (section.get(key) for key in ("address", "offset", "size"))
            if any(type(value) is not int or value < 0 for value in (address, offset, size)):
                continue
            available = min(size, max(0, data_size - offset))
            if available <= 0:
                continue
            rva = address - base
            spans.append((rva, rva + available, offset))
            if section.get("executable"):
                exec_spans.append((address, address + available))
        spans.sort()
        self._rva_starts = [item[0] for item in spans]
        self._rva = spans
        exec_spans.sort()
        self._exec_starts = [item[0] for item in exec_spans]
        self._exec = exec_spans

    def offset_for_rva(self, rva: int) -> int | None:
        if type(rva) is not int or rva < 0:
            return None
        position = bisect_right(self._rva_starts, rva) - 1
        if position >= 0:
            start, end, offset = self._rva[position]
            if rva < end:
                return offset + rva - start
        return None

    def executable_va(self, address: int) -> bool:
        if type(address) is not int:
            return False
        position = bisect_right(self._exec_starts, address) - 1
        return position >= 0 and address < self._exec[position][1]


def _data_directory(data: bytes, index: int) -> tuple[int, int] | None:
    """返回第 ``index`` 个数据目录的 (RVA, 大小)，越界或缺失返回 None。"""
    try:
        peoff, = struct.unpack_from("<I", data, 0x3c)
        if data[peoff:peoff + 4] != b"PE\0\0":
            return None
        optoff = peoff + 24
        magic, = struct.unpack_from("<H", data, optoff)
        directory_base = optoff + (112 if magic == 0x20b else 96)
        count_offset = optoff + (108 if magic == 0x20b else 92)
        count, = struct.unpack_from("<I", data, count_offset)
        if index >= count:
            return None
        entry = directory_base + index * 8
        if entry + 8 > len(data):
            return None
        rva, size = struct.unpack_from("<II", data, entry)
        return (rva, size) if rva else None
    except struct.error:
        return None


def recover_function_ranges(data: bytes, image: BinaryImage) -> tuple[list[dict[str, Any]], list[str]]:
    """Return PE declared function starts and relocation-backed code pointers.

    不修改 ``image``，不解码指令。声明来源（``pdata``、``export``）给出函数起点；
    ``data_pointer`` 给出重定位写入的代码指针候选，由分析核心按完整证据规则裁决。
    """
    warnings: list[str] = []

    def warn(message: str) -> None:
        if len(warnings) < MAX_WARNINGS and message not in warnings:
            warnings.append(message)

    if image.format != "pe":
        return [], ["PE function range recovery requires a PE image"]
    base = image.image_base or 0
    sections = _SectionMap(image, len(data))
    roots: dict[int, dict[str, Any]] = {}

    def declare(address: int, size: int | None, source: str, evidence: dict[str, Any]) -> None:
        if not sections.executable_va(address):
            return
        existing = roots.get(address)
        if existing is None:
            roots[address] = {"name": f"{source}_{address:x}", "start": address, "size": size,
                              "source": source, "sources": [source],
                              "boundary_known": size is not None,
                              "boundary_scope": source if size is not None else None,
                              "evidence": evidence, "blocks": [], "cfg": {"edges": []},
                              "xrefs_in": [], "xrefs_out": []}
        else:
            if source not in existing["sources"]:
                existing["sources"].append(source)
            if existing.get("size") is None and size is not None:
                existing.update(size=size, boundary_known=True, boundary_scope=source)

    # --- 1. .pdata RUNTIME_FUNCTION 起点（异常目录）。项格式由 COFF Machine 决定：
    #        x64 为 12 字节，ARM64/ARM32 为 8 字节；其它 Machine 不解析，只告警。---
    exception = _data_directory(data, 3)
    machine = _machine(data)
    layout = _PDATA_LAYOUT.get(machine) if machine is not None else None
    if exception is not None and layout is None:
        warn(f"PE exception directory for machine "
             f"{'unknown' if machine is None else hex(machine)} is not parsed")
    elif exception is not None:
        entry_size, unit = layout
        rva, size = exception
        offset = sections.offset_for_rva(rva)
        count = size // entry_size
        if offset is None:
            warn("PE exception directory is outside file-backed sections")
        elif count > MAX_RUNTIME_FUNCTIONS:
            warn("PE .pdata capped at scan budget")
            count = MAX_RUNTIME_FUNCTIONS
        if offset is not None:
            for index in range(count):
                position = offset + index * entry_size
                if position + entry_size > len(data):
                    warn("PE .pdata exceeds file bytes")
                    break
                if entry_size == _RUNTIME_FUNCTION_SIZE:
                    begin, end, _unwind = struct.unpack_from("<III", data, position)
                    if not begin:
                        continue
                    span = end - begin if end > begin else None
                    declare(base + begin, span, "pdata",
                            {"runtime_function_rva": begin, "unwind_info_rva": _unwind})
                    continue
                begin, unwind = struct.unpack_from("<II", data, position)
                # ARM32 的 BeginAddress 第 0 位标记 Thumb，指令边界是去掉该位后的地址。
                start = begin & ~1 if machine == _MACHINE_ARMNT else begin
                if not start:
                    continue
                span, encoding = _packed_or_xdata_length(data, sections, unwind, unit)
                evidence = {"runtime_function_rva": begin, "unwind_data": unwind,
                            "unwind_encoding": encoding}
                declare(base + start, span, "pdata", evidence)
                if machine == _MACHINE_ARMNT and base + start in roots:
                    roots[base + start].setdefault("isa_mode", "thumb")

    # --- 2. 导出表 AddressOfFunctions：指向可执行节的导出 RVA。---
    export = _data_directory(data, 0)
    if export is not None:
        rva, _size = export
        offset = sections.offset_for_rva(rva)
        if offset is None or offset + 40 > len(data):
            warn("PE export directory is outside file-backed sections")
        else:
            # IMAGE_EXPORT_DIRECTORY: +20 NumberOfFunctions, +28 AddressOfFunctions（RVA）。
            number, _names, address_rva = struct.unpack_from("<III", data, offset + 20)
            table = sections.offset_for_rva(address_rva)
            if table is None:
                warn("PE export address table is outside file-backed sections")
            elif number > MAX_EXPORTS:
                warn("PE export table capped at scan budget")
                number = MAX_EXPORTS
            if table is not None:
                for index in range(number):
                    position = table + index * 4
                    if position + 4 > len(data):
                        warn("PE export address table exceeds file bytes")
                        break
                    function_rva, = struct.unpack_from("<I", data, position)
                    if function_rva:
                        declare(base + function_rva, None, "export",
                                {"export_rva": function_rva, "ordinal_index": index})

    # --- 3. 基址重定位（DIR64 / HIGHLOW）：写入处存放的指向代码的绝对地址。---
    for pointer_address, pointer, kind in _base_relocation_pointers(data, image, sections, warn):
        declare(pointer, None, "data_pointer",
                {"pointer_address": pointer_address, "relocation": kind})
    return [roots[start] for start in sorted(roots)], warnings


def _base_relocation_pointers(data: bytes, image: BinaryImage, sections: _SectionMap, warn):
    """逐槽位产出基址重定位（DIR64 / HIGHLOW）写入的、指向可执行节的绝对地址。

    产出 ``(槽位虚拟地址, 指针值, "dir64"/"highlow")``，按重定位块与项的原始顺序；同一个
    目标可以出现在多个槽位（例如跳转表的缺省分支），这里不去重。
    """
    relocation = _data_directory(data, 5)
    if relocation is None:
        return
    base = image.image_base or 0
    rva, size = relocation
    offset = sections.offset_for_rva(rva)
    if offset is None:
        warn("PE base relocation directory is outside file-backed sections")
        return
    cursor, end = offset, min(len(data), offset + size)
    blocks = 0
    while cursor + 8 <= end:
        if blocks >= MAX_RELOCATION_BLOCKS:
            warn("PE base relocation scan capped at block budget")
            break
        blocks += 1
        page_rva, block_size = struct.unpack_from("<II", data, cursor)
        if block_size < 8 or cursor + block_size > end:
            warn("PE base relocation block is truncated")
            break
        entries = (block_size - 8) // 2
        for index in range(entries):
            entry, = struct.unpack_from("<H", data, cursor + 8 + index * 2)
            kind, page_offset = entry >> 12, entry & 0xFFF
            pointer_size = 8 if kind == 10 else 4 if kind == 3 else 0
            if pointer_size == 0:
                continue
            slot = sections.offset_for_rva(page_rva + page_offset)
            if slot is None or slot + pointer_size > len(data):
                continue
            pointer = int.from_bytes(data[slot:slot + pointer_size], "little")
            if sections.executable_va(pointer):
                yield base + page_rva + page_offset, pointer, "dir64" if kind == 10 else "highlow"
        cursor += block_size


def recover_code_pointers(data: bytes, image: BinaryImage) -> tuple[list[dict[str, Any]], list[str]]:
    """逐槽位返回基址重定位写入的代码指针候选，以及告警（不去重、不解码、不修改镜像）。

    每个候选：``{"target": 代码地址, "source": "data_pointer",
    "evidence": {"pointer_address": 槽位虚拟地址, "relocation": "dir64"/"highlow"}}``，
    与 ELF 读取器同形。分析核心据槽位地址把相邻槽位归为“指针表”做表级裁决。
    """
    warnings: list[str] = []

    def warn(message: str) -> None:
        if len(warnings) < MAX_WARNINGS and message not in warnings:
            warnings.append(message)

    if image.format != "pe":
        return [], ["PE code-pointer recovery requires a PE image"]
    sections = _SectionMap(image, len(data))
    candidates = [{"target": pointer, "source": "data_pointer",
                   "evidence": {"pointer_address": pointer_address, "relocation": kind}}
                  for pointer_address, pointer, kind
                  in _base_relocation_pointers(data, image, sections, warn)]
    return candidates, warnings
