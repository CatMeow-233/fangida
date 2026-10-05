"""插件只读使用已完成的映射声明；不解析容器、不解码指令。"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
from pathlib import Path
from time import monotonic

from ...addresses import NativeAddressMap

MAX_SOURCE_BYTES = 128 * 1024 * 1024
MAX_CONTEXT_BYTES = 8 * 1024 * 1024


class MemoryEvidenceError(ValueError):
    def __init__(self, kind: str, address: int, size: int, reason: str):
        self.dependency = {"kind": kind, "address": address, "width": size * 8,
                           "reason": reason, "role": "target"}
        super().__init__(reason)


class PluginStopped(ValueError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def check_budget(deadline=None, cancel=None):
    if cancel is not None and bool(cancel() if callable(cancel) else cancel.is_set()):
        raise PluginStopped("cancelled")
    if deadline is not None and monotonic() >= deadline:
        raise PluginStopped("budget_exceeded")


def unsigned(value):
    return type(value) is int and 0 <= value < 1 << 64


class MemoryImage:
    """严格区分文件初值、只读字节和调用方提供的运行时字节。"""

    def __init__(self, snapshot: Mapping, source_path=None, *, memory=(), deadline=None, cancel=None):
        self.deadline, self.cancel = deadline, cancel
        check_budget(deadline, cancel)
        metadata = snapshot.get("metadata", {})
        self.sections = tuple(section for section in metadata.get("sections", ())
                              if isinstance(section, Mapping))
        self.kind = snapshot.get("kind", metadata.get("format", ""))
        self.data = None
        self.source_sha256 = None
        self.source_verified = False
        self.provided = []
        self.reads = []
        total = 0
        for record in memory:
            check_budget(deadline, cancel)
            if not isinstance(record, Mapping) or not unsigned(record.get("address")):
                raise ValueError("运行时内存需要 address 和 data")
            data = record.get("data")
            if isinstance(data, str):
                try:
                    data = bytes.fromhex(data)
                except ValueError as exc:
                    raise ValueError("运行时内存 data 必须是字节或十六进制字符串") from exc
            if not isinstance(data, bytes) or not data or record["address"] + len(data) > 1 << 64:
                raise ValueError("运行时内存字节范围无效")
            total += len(data)
            if total > MAX_CONTEXT_BYTES:
                raise ValueError("运行时内存超过 8 MiB 预算")
            start, end = record["address"], record["address"] + len(data)
            if any(start < other["address"] + len(other["data"]) and other["address"] < end
                   for other in self.provided):
                raise ValueError("运行时内存快照不允许互相重叠")
            self.provided.append({"address": start, "data": data,
                "writable": True, "executable": bool(record.get("executable", False)), "origin": "provided"})
        if source_path is not None:
            path = Path(source_path).expanduser().resolve(strict=True)
            if not path.is_file() or path.stat().st_size > MAX_SOURCE_BYTES:
                raise ValueError("原文件必须是最多 128 MiB 的普通文件")
            blocks, digest, length = [], hashlib.sha256(), 0
            with path.open("rb") as stream:
                while True:
                    check_budget(deadline, cancel)
                    block = stream.read(min(1024 * 1024, MAX_SOURCE_BYTES + 1 - length))
                    if not block:
                        break
                    blocks.append(block)
                    digest.update(block)
                    length += len(block)
                    if length > MAX_SOURCE_BYTES:
                        raise ValueError("原文件超过读取预算")
            check_budget(deadline, cancel)
            data = b"".join(blocks)
            if len(data) > MAX_SOURCE_BYTES:
                raise ValueError("原文件超过读取预算")
            self.source_sha256 = digest.hexdigest()
            expected = metadata.get("source_sha256")
            if expected is None:
                database = metadata.get("analysis_database", {})
                expected = database.get("source_sha256") if isinstance(database, Mapping) else None
            if expected is not None:
                if not isinstance(expected, str) or self.source_sha256 != expected.lower():
                    raise ValueError("原文件指纹与分析快照不一致，请重新分析")
                self.source_verified = True
            self.data = data
        self.relocations = tuple(record for record in metadata.get("dynamic_relocations", ())
                                 if isinstance(record, Mapping) and record.get("address_kind", "virtual_address") == "virtual_address")

    def _mapping(self, address, size):
        matches = []
        for section in self.sections:
            check_budget(self.deadline, self.cancel)
            start, offset = section.get("address"), section.get("offset")
            if not unsigned(start) or not unsigned(offset) or address < start:
                continue
            position = offset + address - start
            if not unsigned(position):
                continue
            mapping = NativeAddressMap((section,), kind=self.kind)
            if (address, size) not in mapping.ranges_for_offset(position, size):
                continue
            if self.data is not None and position + size <= len(self.data):
                matches.append((position, section))
        if len(matches) != 1:
            raise MemoryEvidenceError("unmapped_memory" if not matches else "ambiguous_memory", address, size,
                                      "读取范围没有唯一的文件字节映射")
        return matches[0]

    def read_static(self, address, size):
        check_budget(self.deadline, self.cancel)
        if not unsigned(address) or type(size) is not int or not 1 <= size <= 64 or address + size > 1 << 64:
            raise ValueError("无效的内存读取")
        for record in self.provided:
            check_budget(self.deadline, self.cancel)
            offset = address - record["address"]
            if 0 <= offset and offset + size <= len(record["data"]):
                self.reads.append((address, size))
                return record["data"][offset:offset + size], "provided"
        if self.data is None:
            raise MemoryEvidenceError("memory_read", address, size, "原文件字节不可用")
        offset, section = self._mapping(address, size)
        if any(unsigned(record.get("address")) and address < record["address"] + 8
               and record["address"] < address + size for record in self.relocations):
            raise MemoryEvidenceError("runtime_relocation", address, size, "该指针槽位由运行时链接器写入")
        if section.get("writable") is True:
            raise MemoryEvidenceError("writable_memory", address, size, "文件中可写区域的初值不能代表运行时参数")
        if section.get("writable") is not False or section.get("readable") is not True:
            raise MemoryEvidenceError("memory_permissions_unknown", address, size, "没有可证明的只读映射权限")
        self.reads.append((address, size))
        return self.data[offset:offset + size], "file"

    def segments(self, instructions, dependencies=()):
        """仅映射相关代码页和相关读取区域，避免为大程序复制整个映像。"""
        points = [(row["addr"], row.get("size", 4)) for row in instructions if unsigned(row.get("addr"))]
        points.extend(self.reads)
        points.extend((dep["address"], max(1, min(64, dep.get("width", 64) // 8)))
                      for dep in dependencies if unsigned(dep.get("address")))
        regions = {}
        if self.data is not None:
            for address, size in points:
                check_budget(self.deadline, self.cancel)
                try:
                    _, section = self._mapping(address, size)
                except MemoryEvidenceError:
                    continue
                start = max(section["address"], address & ~0xfff)
                available = section.get("file_size", section.get("size", 0))
                virtual = section.get("virtual_size")
                if type(virtual) is int and virtual > 0:
                    available = min(available, virtual)
                end = min(section["address"] + available, (address + size + 0xfff) & ~0xfff)
                offset = section["offset"] + start - section["address"]
                end = min(end, start + len(self.data) - offset)
                if end <= start:
                    continue
                key = (start, end)
                regions[key] = {"address": start, "data": self.data[offset:offset + end - start],
                    "writable": section.get("writable"), "readable": section.get("readable"),
                    "executable": bool(section.get("executable")), "origin": "file"}
        # 链接器会改写的槽位作为未知运行时字节覆盖；不让文件中的零值变成目标。
        for record in self.relocations:
            check_budget(self.deadline, self.cancel)
            address = record.get("address")
            if unsigned(address) and any(start <= address < end for start, end in regions):
                try:
                    offset, _ = self._mapping(address, 8)
                except MemoryEvidenceError:
                    continue
                regions[(address, address + 8)] = {"address": address, "data": self.data[offset:offset + 8],
                    "writable": True, "executable": False, "origin": "file"}
        return [*regions.values(), *self.provided]
