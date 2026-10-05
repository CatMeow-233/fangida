"""只读使用已完成的容器映射声明；不解析文件、不解码、不生成引用。"""
from __future__ import annotations

from bisect import bisect_right
from collections.abc import Iterable, Mapping
from typing import Any

_MAX_ADDRESS = (1 << 64) - 1


def _unsigned(value: Any) -> bool:
    return type(value) is int and 0 <= value <= _MAX_ADDRESS


class NativeAddressMap:
    """文件字节的零到多虚拟地址映射；重叠映射不能随机选一个。"""

    def __init__(self, sections: Iterable[Mapping[str, Any]], *, kind: str = "") -> None:
        ranges = []
        if kind not in {"apk", "dex", "jar", "class"}:
            for section in sections:
                if not isinstance(section, Mapping):
                    continue
                offset, address = section.get("offset"), section.get("address")
                size = section.get("file_size", section.get("size"))
                if not all(map(_unsigned, (offset, address, size))) or size == 0:
                    continue
                if (section.get("type") == 8 or section.get("file_backed") is False or
                        section.get("allocated") is False or section.get("mapped") is False):
                    continue
                # 旧 ELF 快照未记录 SHF_ALLOC；地址为零的非执行节不能当成已映射内容。
                if (kind == "elf" and address == 0 and not section.get("executable") and
                        section.get("allocated") is not True and section.get("mapped") is not True):
                    continue
                virtual_size = section.get("virtual_size")
                if _unsigned(virtual_size) and virtual_size:
                    size = min(size, virtual_size)
                if offset + size > _MAX_ADDRESS + 1 or address + size > _MAX_ADDRESS + 1:
                    continue
                ranges.append((offset, offset + size, address))
        ranges.sort()
        self._ranges = tuple(ranges)
        self._starts = tuple(start for start, _, _ in ranges)
        maximum = 0
        ends = []
        for _, end, _ in ranges:
            maximum = max(maximum, end)
            ends.append(maximum)
        self._ends = tuple(ends)

    def addresses_for_offset(self, offset: int) -> tuple[int, ...]:
        return tuple(address for address, _ in self.ranges_for_offset(offset, 1))

    def ranges_for_offset(self, offset: int, length: int) -> tuple[tuple[int, int], ...]:
        """返回 VA 和该映射内实际可用字节数，不越过文件支持的映射边界。"""
        if not _unsigned(offset):
            raise ValueError("offset must be a non-negative 64-bit integer")
        if not _unsigned(length):
            raise ValueError("length must be a non-negative 64-bit integer")
        position = bisect_right(self._starts, offset) - 1
        addresses: dict[int, int] = {}
        while position >= 0 and self._ends[position] > offset:
            start, end, address = self._ranges[position]
            if start <= offset < end:
                target = address + offset - start
                addresses[target] = max(addresses.get(target, 0), min(length, end - offset))
            position -= 1
        return tuple(sorted(addresses.items()))


def native_addresses_for_offset(offset: int, sections: Iterable[Mapping[str, Any]], *,
                                kind: str = "") -> tuple[int, ...]:
    """兼容旧结果的便捷查询；批量查询应复用 NativeAddressMap。"""
    return NativeAddressMap(sections, kind=kind).addresses_for_offset(offset)
