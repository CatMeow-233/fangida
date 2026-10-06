"""Lazy SQLite storage plugin for portable analysis databases.

The original input is never embedded.  A compressed instruction pool is shared
by CFGs, per-function listings and full disassembly, while collection chunks
provide paging without materialising an entire analysis snapshot.
"""
from __future__ import annotations

from bisect import bisect_left
from collections import OrderedDict
from contextlib import contextmanager
from dataclasses import fields
from itertools import islice
import json
import math
from operator import itemgetter, le
import os
from pathlib import Path
import sqlite3
from threading import Lock
from typing import Any, Iterator, Mapping
import weakref
import zlib

from ..models import AnalysisResult
from ..project import (COLLECTIONS, MAX_PAGE_SIZE, PROJECT_SCHEMA_VERSION,
                       ProjectStore, SourceChangedError, _DIGEST_RE, _now,
                       _source_path, fingerprint)
from ..storage import StorageError, StorageSchemaError

FORMAT = "fangida.analysis_db"
STORAGE_SCHEMA_VERSION = 1
CHUNK_ITEMS = 512
MAX_CHUNK_BYTES = 128 * 1024 * 1024
_REF = "$fdb_instruction"
_LITERAL = "$fdb_literal"
_POOL = "__instructions__"
_MANIFEST = "__manifest__"
# JSON 标量的精确类型：pack/expand 对它们原样返回，热循环里内联判断可省掉一次函数调用。
# typing.Mapping 的 isinstance 要经过 typing/abc 两层 __instancecheck__，非常慢，
# 因此先用精确类型快速分支，其余对象仍走原来的 isinstance 判断链，语义不变。
_SCALARS = frozenset({str, int, float, bool, type(None)})
# 读回时在指令记录之间共享的子字典（与解码工作进程 share_records 的字典部分相同）。
_SHARED_PARTS = ("branch_info", "arch_meta")


_BYTECODE_KINDS = frozenset({"apk", "dex", "jar", "class"})
_ADDR = itemgetter("addr")


def _full_listing_records(payload: Mapping[str, Any], metadata: Mapping[str, Any]
                          ) -> list[Any] | None:
    """原生完整分析的快速路径：合并结果就是 full_disassembly 本身时返回它的副本，否则返回 None。

    完整分析里函数、块中的指令就是 full_disassembly 中同地址的同一对象，按 (source, 地址)
    合并、排序后的结果与 full_disassembly 的对象和顺序完全相同。这里只核对这一点，不为每条
    指令建 (source, 地址) 元组键和排序键（il2cpp 规模约 5 GiB 的瞬时峰值）。核对按块二分定位
    一次，之后用游标顺序比对身份。任何条件不满足都返回 None，由调用方走通用合并，结果不变。
    """
    if (payload.get("kind") in _BYTECODE_KINDS or payload.get("instructions") is not None
            or metadata.get("instructions") is not None):
        return None
    full = metadata.get("full_disassembly")
    if type(full) is not list:
        return None
    previous = -1
    for record in full:
        # 原实现以 (str(source), 地址) 为键：普通 dict、不带 source、addr 为严格递增的非负整数时，
        # 每条记录各占一个键，合并后的顺序就是列表顺序。
        if type(record) is not dict:
            return None
        address = record.get("addr")
        if type(address) is not int or address <= previous or "source" in record:
            return None
        previous = address
    count = len(full)

    def located(value: Any) -> int | None:
        """value 会被原实现收集时，返回它在 full 中同地址的位置；不收集时返回 -1；无法判定时返回 None。"""
        if type(value) is not dict:
            # 非 dict 的 Mapping 少见，保守回退；其它对象原实现直接跳过。
            return None if isinstance(value, Mapping) else -1
        address = value.get("addr", value.get("address", value.get("offset")))
        if type(address) is not int or address < 0:
            return -1
        if "source" in value:
            return None
        position = bisect_left(full, address, key=_ADDR)
        if position >= count or full[position]["addr"] != address:
            return None
        return position

    # metadata.disassembly 先于 full_disassembly 收集，同键会被 full 中的记录覆盖：只要求地址都在 full 中。
    listing = metadata.get("disassembly")
    if isinstance(listing, list):
        cursor = 0
        for value in listing:
            if cursor < count and value is full[cursor]:
                cursor += 1
                continue
            position = located(value)
            if position is None:
                return None
            if position >= 0:
                cursor = position + 1

    def shared(values: Any) -> bool:
        """函数、块中的指令后于 full 收集并覆盖同键：必须是 full 中同地址的同一对象。"""
        if not isinstance(values, list):
            return True
        cursor = 0
        for value in values:
            if cursor < count and value is full[cursor]:
                cursor += 1
                continue
            position = located(value)
            if position is None or (position >= 0 and full[position] is not value):
                return False
            if position >= 0:
                cursor = position + 1
        return True

    for function in payload.get("functions", []):
        if type(function) is not dict and not isinstance(function, Mapping):
            continue
        if not shared(function.get("instructions")) or not shared(function.get("disassembly")):
            return None
        blocks = function.get("blocks", [])
        if isinstance(blocks, list):
            for block in blocks:
                if (type(block) is dict or isinstance(block, Mapping)) and not shared(
                        block.get("instructions")):
                    return None
    return list(full)


def _disassembly_records(payload: Mapping[str, Any], metadata: Mapping[str, Any]) -> list[Any]:
    """Merge existing listings only; storage never decodes missing instructions."""
    fast = _full_listing_records(payload, metadata)
    if fast is not None:
        return fast
    # 按 source 分组、以整数地址为键，不为每条指令建 (source, 地址) 元组键；
    # 后写覆盖与按 (地址, source) 排序的输出与原来的元组键实现相同。
    grouped: dict[str, dict[int, Mapping[str, Any]]] = {}

    def collect(values: Any, source: str = "") -> None:
        if not isinstance(values, list):
            return
        for value in values:
            if type(value) is not dict and not isinstance(value, Mapping):
                continue
            address = value.get("addr", value.get("address", value.get("offset")))
            if type(address) is not int or address < 0:
                continue
            if source and "source" not in value:
                value = {**value, "source": source}
            key = str(value.get("source", ""))
            bucket = grouped.get(key)
            if bucket is None:
                bucket = grouped[key] = {}
            bucket[address] = value

    for values in (payload.get("instructions"), metadata.get("disassembly"),
                   metadata.get("full_disassembly"), metadata.get("instructions")):
        collect(values)
    bytecode = payload.get("kind") in _BYTECODE_KINDS
    for function in payload.get("functions", []):
        if type(function) is not dict and not isinstance(function, Mapping):
            continue
        source = str(function.get("source", "")) if bytecode else ""
        collect(function.get("instructions"), source)
        collect(function.get("disassembly"), source)
        blocks = function.get("blocks", [])
        if isinstance(blocks, list):
            for block in blocks:
                if type(block) is dict or isinstance(block, Mapping):
                    collect(block.get("instructions"), source)
    if len(grouped) <= 1:
        return [bucket[address] for bucket in grouped.values() for address in sorted(bucket)]
    return [grouped[source][address] for address, source in sorted(
        (address, source) for source, bucket in grouped.items() for address in bucket)]


def _json_bytes(value: Any) -> bytes:
    try:
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False,
                             separators=(",", ":")).encode("utf-8")
    except (ValueError, TypeError, RecursionError) as error:
        raise StorageError("Analysis contains unsupported or excessively nested JSON data") from error
    if len(encoded) > MAX_CHUNK_BYTES:
        raise StorageError("Analysis chunk exceeds the supported size limit")
    return encoded


def _import_annotations(value: Any, content_hash: str) -> dict[str, dict[int, str]]:
    result: dict[str, dict[int, str]] = {"renames": {}, "comments": {}}
    if value is None:
        return result
    if not isinstance(value, Mapping) or not isinstance(value.get("sha256"), str):
        raise StorageError("Saved user annotations require their source SHA-256")
    if value["sha256"] != content_hash:
        raise SourceChangedError("Annotation source hash differs from the original input")
    for kind in ("renames", "comments"):
        values = value.get(kind, {})
        if not isinstance(values, Mapping):
            raise StorageError(f"Saved {kind} must be a mapping")
        for key, text in values.items():
            if type(key) is int:
                address = key
            elif isinstance(key, str) and key.isascii() and key.isdecimal():
                try:
                    address = int(key)
                except ValueError as error:
                    raise StorageError("Invalid saved annotation address") from error
            else:
                raise StorageError("Saved annotation addresses must be unsigned integers")
            try:
                ProjectStore._address(address)
            except ValueError as error:
                raise StorageError("Invalid saved annotation address") from error
            if kind == "renames":
                valid = (isinstance(text, str) and bool(text) and len(text) <= 512
                         and not any(character in text for character in "\r\n\0"))
            else:
                valid = isinstance(text, str) and len(text) <= 16_384 and "\0" not in text
            if not valid:
                raise StorageError(f"Invalid saved {kind} value")
            if address in result[kind] and result[kind][address] != text:
                raise StorageError("Conflicting saved annotation addresses")
            if text:
                result[kind][address] = text
    return result


def _decode_chunk(row: sqlite3.Row, expected_count: int) -> list[Any]:
    size = row["raw_size"]
    if type(size) is not int or not 0 < size <= MAX_CHUNK_BYTES:
        raise StorageSchemaError("Invalid decompressed chunk size")
    try:
        decoder = zlib.decompressobj()
        raw = decoder.decompress(row["data"], size + 1)
        if (len(raw) != size or not decoder.eof or decoder.unused_data
                or decoder.unconsumed_tail):
            raise StorageSchemaError("Corrupt or oversized compressed chunk")
        def invalid_constant(value: str) -> None:
            raise ValueError(f"Invalid JSON constant: {value}")
        values = json.loads(raw, parse_constant=invalid_constant)
    except (zlib.error, UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise StorageSchemaError("Invalid compressed analysis JSON") from error
    if not isinstance(values, list) or len(values) != expected_count:
        raise StorageSchemaError("Analysis chunk item count is inconsistent")
    return values


def _same_json(left: Any, right: Any) -> bool:
    """严格比较两个 JSON 解码值：类型、键顺序与值都相同。

    == 会把 1、1.0 与 True，0.0 与 -0.0 视为相等，用它决定共享会改变值的类型或序列化结果。
    """
    if left is right:
        return True
    kind = type(left)
    if kind is not type(right):
        return False
    if kind is dict:
        if len(left) != len(right):
            return False
        for (left_key, left_item), (right_key, right_item) in zip(left.items(), right.items()):
            if left_key != right_key or not _same_json(left_item, right_item):
                return False
        return True
    if kind is list:
        return len(left) == len(right) and all(map(_same_json, left, right))
    if kind is float:
        return left == right and math.copysign(1.0, left) == math.copysign(1.0, right)
    return left == right


def _same_reference(candidate: dict[str, Any], entry: dict[str, Any]) -> bool:
    """_same_json 的快速版本：平坦的 xref 字典只用 C 层比较，含嵌套容器或零值时再逐项严格比较。"""
    if candidate != entry or list(candidate) != list(entry):
        return False
    types = list(map(type, candidate.values()))
    if types != list(map(type, entry.values())):
        return False
    if dict in types or list in types or 0.0 in candidate.values():
        return _same_json(candidate, entry)
    return True


def _reshare_references(payload: dict[str, Any]) -> None:
    """重新打开后，让函数 xrefs_in/xrefs_out 里的元素重新指向值相同的顶层 xrefs 字典。

    新分析里这些列表与顶层 xrefs 共享同一批字典；入库时各处分别内联编码，读回后每次出现
    都是独立的新字典（il2cpp 规模约多 3.5 GiB）。这里只恢复同值字典的别名：按 src 二分找到
    候选，类型、键顺序与值都相同才替换，找不到就保留原字典。值不变；xref 字典创建后不再被
    原地修改（标注叠加只改带整数 address/start/addr 的字典，xref 没有这些键）。
    """
    references = payload.get("xrefs")
    functions = payload.get("functions")
    if type(references) is not list or not references or type(functions) is not list:
        return
    source_of = itemgetter("src")
    candidates = references
    if not all(type(reference) is dict and type(reference.get("src")) is int
               for reference in references):
        candidates = [reference for reference in references
                      if type(reference) is dict and type(reference.get("src")) is int]
    sources = list(map(source_of, candidates))
    if not all(map(le, sources, islice(sources, 1, None))):
        # 完整分析的 xrefs 已按 src 升序；其它来源先按 src 稳定排序（只排列指针，不复制字典）。
        candidates = sorted(candidates, key=source_of)
        sources = list(map(source_of, candidates))
    count = len(candidates)
    if not count:
        return
    for function in functions:
        if type(function) is not dict:
            continue
        for key in ("xrefs_in", "xrefs_out"):
            entries = function.get(key)
            if type(entries) is not list:
                continue
            for position, entry in enumerate(entries):
                if type(entry) is not dict:
                    continue
                source = entry.get("src")
                if type(source) is not int:
                    continue
                index = bisect_left(sources, source)
                while index < count and sources[index] == source:
                    candidate = candidates[index]
                    if candidate is entry:
                        break
                    if _same_reference(candidate, entry):
                        entries[position] = candidate
                        break
                    index += 1


class _Encoder:
    """Borrow input records; copy only the current bounded serialization chunk."""

    def __init__(self, annotations: dict[str, dict[int, str]] | None = None) -> None:
        self.instructions: list[Mapping[str, Any]] = []
        # 地址 -> 指令池下标。绝大多数地址只有一条记录，只存一个 int；同地址出现不同记录时
        # 才升级为下标列表。记录本身从 self.instructions 取，不再为每条指令保存
        # [(index, record)] 列表和二元组（il2cpp 规模保存期间约省 4 GiB 常驻内存）。
        self.by_address: dict[int, int | list[int]] = {}
        self.current_instruction: int | None = None
        self.dependencies: dict[int, set[int]] = {}
        self.annotations = annotations

    def reference(self, index: int) -> dict[str, int]:
        if self.current_instruction is not None:
            if self.current_instruction == index:
                raise StorageError("Analysis contains cyclic instruction records")
            self.dependencies.setdefault(self.current_instruction, set()).add(index)
        return {_REF: index}

    def pack(self, value: Any) -> Any:
        kind = type(value)
        if kind in _SCALARS:
            return value
        if kind is dict or (kind is not list and kind is not tuple and isinstance(value, Mapping)):
            if (type(value.get("addr")) is int and type(value.get("size")) is int
                    and isinstance(value.get("mnemonic"), str)):
                address = value["addr"]
                instructions = self.instructions
                found = self.by_address.get(address)
                if found is not None:
                    # 与原来逐个比较 [(index, record)] 的次序和判定相同：先比身份，再比值。
                    for index in ((found,) if type(found) is int else found):
                        previous = instructions[index]
                        if previous is value or previous == value:
                            return self.reference(index)
                index = len(instructions)
                instructions.append(value)
                if found is None:
                    self.by_address[address] = index
                elif type(found) is int:
                    self.by_address[address] = [found, index]
                else:
                    found.append(index)
                return self.reference(index)
            return self.pack_mapping(value)
        if kind is list or kind is tuple or isinstance(value, (list, tuple)):
            pack = self.pack
            return [item if type(item) in _SCALARS else pack(item) for item in value]
        return value

    def pack_mapping(self, value: Mapping[str, Any]) -> dict[str, Any]:
        if self.annotations:
            address = value.get("address", value.get("start", value.get("addr")))
            restored = None
            if type(address) is int:
                name = self.annotations["renames"].get(address)
                if (name is not None and value.get("name") == name
                        and "original_name" in value):
                    restored = dict(value)
                    restored["name"] = restored.pop("original_name")
                comment = self.annotations["comments"].get(address)
                if comment is not None and value.get("comment") == comment:
                    if restored is None:
                        restored = dict(value)
                    if "original_comment" in restored:
                        restored["comment"] = restored.pop("original_comment")
                    else:
                        restored.pop("comment", None)
            if restored is not None:
                value = restored
        pack = self.pack
        packed = {key: (item if type(item) in _SCALARS else pack(item))
                  for key, item in value.items()}
        # Escape literal user data which resembles an internal reference.
        if len(packed) == 1 and (_REF in packed or _LITERAL in packed):
            return {_LITERAL: packed}
        return packed

    def instruction(self, index: int) -> dict[str, Any]:
        self.current_instruction = index
        try:
            return self.pack_mapping(self.instructions[index])
        finally:
            self.current_instruction = None

    def validate_dependencies(self) -> None:
        states: dict[int, int] = {}
        for root in self.dependencies:
            if states.get(root) == 2:
                continue
            stack = [(root, False)]
            while stack:
                index, leaving = stack.pop()
                if leaving:
                    states[index] = 2
                    continue
                if states.get(index) == 1:
                    raise StorageError("Analysis contains cyclic instruction records")
                if states.get(index) == 2:
                    continue
                states[index] = 1
                stack.append((index, True))
                stack.extend((child, False) for child in self.dependencies.get(index, ()))


class _Reader:
    def __init__(self, connection: sqlite3.Connection, snapshot_id: int) -> None:
        self.connection, self.snapshot_id = connection, snapshot_id
        self.collections: dict[str, sqlite3.Row] = {}
        self.chunks: OrderedDict[tuple[str, int], list[Any]] = OrderedDict()
        self.instructions: dict[int, dict[str, Any]] = {}
        self.resolving: set[int] = set()
        # JSON 解码为每次出现都新建字符串和字典，分析结果中经 share_records 共享的助记符、
        # 操作数、寄存器名与 arch_meta/branch_info 读回后各占一份（每条指令约多 650 字节）。
        # 两个规范表只在本次读取内有效，reader 释放后随之释放。
        self._strings: dict[str, str] = {}
        self._shared: dict[tuple[Any, ...], dict[str, Any]] = {}

    @staticmethod
    def _part_marker(key: str, value: Any) -> tuple[Any, ...] | None:
        """可共享子字典的规范键（未检查可哈希性）；不参与共享时返回 None。

        只共享平坦字典，并排除带整数 address/start/addr 的字典：存储层 _overlay 与界面的标注
        叠加只原地修改这类字典。键顺序与值的类型都计入规范键，1、1.0 与 True 不会混用；
        含浮点数的不共享（0.0 与 -0.0 相等但序列化不同）。引用与转义字面量按原路径展开。
        """
        if (type(value) is not dict or (len(value) == 1 and (_REF in value or _LITERAL in value))
                or type(value.get("address", value.get("start", value.get("addr")))) is int):
            return None
        types = tuple(map(type, value.values()))
        if float in types:
            return None
        return (key, tuple(value.items()), types)

    def _expand_instruction(self, record: Any) -> Any:
        """展开一条指令池记录；值相同的 branch_info/arch_meta 复用同一个已展开的字典。

        规则与解码工作进程的 share_records 相同，只共享内容全部可哈希（不含嵌套字典、列表）
        的平坦字典。在原始 JSON 记录上判定，重复的子字典不再逐个展开。值、类型和键顺序都不变。
        """
        if (type(record) is not dict or type(record.get("addr")) is not int
                or type(record.get("size")) is not int or type(record.get("mnemonic")) is not str):
            return self.expand(record)
        shared = self._shared
        reused: dict[str, dict[str, Any]] = {}
        pending: list[tuple[str, tuple[Any, ...]]] = []
        for key in _SHARED_PARTS:
            marker = self._part_marker(key, record.get(key))
            if marker is None:
                continue
            try:
                canonical = shared.get(marker)
            except TypeError:
                continue  # 含列表、字典等不可哈希的值（如 memory_references）：保留独立对象
            if canonical is None:
                pending.append((key, marker))
            else:
                reused[key] = canonical
        expand, strings = self.expand, self._strings.setdefault
        instruction = {key: (strings(item, item) if type(item) is str
                             else item if type(item) in _SCALARS
                             else reused[key] if key in reused else expand(item))
                       for key, item in record.items()}
        for key, marker in pending:
            # 展开期间嵌套的指令可能已登记同一规范键：沿用先登记的对象。
            instruction[key] = shared.setdefault(marker, instruction[key])
        return instruction

    def descriptor(self, collection: str) -> sqlite3.Row:
        if collection not in self.collections:
            row = self.connection.execute(
                "SELECT * FROM fdb_collections WHERE snapshot_id=? AND collection=?",
                (self.snapshot_id, collection)).fetchone()
            if row is None:
                raise StorageSchemaError(f"Missing analysis collection: {collection}")
            count, chunks = row["item_count"], row["chunk_count"]
            if (type(count) is not int or count < 0 or type(chunks) is not int
                    or chunks != (count + CHUNK_ITEMS - 1) // CHUNK_ITEMS):
                raise StorageSchemaError("Invalid analysis collection count")
            self.collections[collection] = row
        return self.collections[collection]

    def items(self, collection: str, offset: int, limit: int, *, expand: bool = True
              ) -> list[Any]:
        descriptor = self.descriptor(collection)
        if descriptor["alias"] is not None:
            target = descriptor["alias"]
            if (collection != "disassembly" or target not in {
                    "metadata.disassembly", "metadata.full_disassembly"}
                    or target == collection or self.descriptor(target)["alias"] is not None
                    or self.descriptor(target)["item_count"] != descriptor["item_count"]):
                raise StorageSchemaError("Invalid analysis collection alias")
            return self.items(target, offset, limit, expand=expand)
        stop = min(offset + limit, descriptor["item_count"])
        values: list[Any] = []
        if offset >= stop:
            return values
        for chunk_index in range(offset // CHUNK_ITEMS, (stop - 1) // CHUNK_ITEMS + 1):
            key = (collection, chunk_index)
            if key in self.chunks:
                chunk = self.chunks[key]
                self.chunks.move_to_end(key)
            else:
                row = self.connection.execute(
                    "SELECT * FROM fdb_chunks WHERE snapshot_id=? AND collection=? AND chunk_index=?",
                    (self.snapshot_id, collection, chunk_index)).fetchone()
                expected = min(CHUNK_ITEMS, descriptor["item_count"] - chunk_index * CHUNK_ITEMS)
                if (row is None or row["ordinal_start"] != chunk_index * CHUNK_ITEMS
                        or row["item_count"] != expected):
                    raise StorageSchemaError("Missing or inconsistent analysis chunk")
                chunk = _decode_chunk(row, expected)
                self.chunks[key] = chunk
                if len(self.chunks) > 8:
                    self.chunks.popitem(last=False)
            start = max(0, offset - chunk_index * CHUNK_ITEMS)
            end = min(len(chunk), stop - chunk_index * CHUNK_ITEMS)
            for item in chunk[start:end]:
                values.append(self.expand(item) if expand else item)
        return values

    def _pool_record(self, index: int) -> Any:
        """读取一条指令池原始记录；块已在 LRU 中时直接取，等价于 items(_POOL, index, 1)。"""
        key = (_POOL, index // CHUNK_ITEMS)
        chunk = self.chunks.get(key)
        if chunk is None:
            return self.items(_POOL, index, 1, expand=False)[0]
        self.chunks.move_to_end(key)
        return chunk[index - key[1] * CHUNK_ITEMS]

    def expand(self, value: Any) -> Any:
        if isinstance(value, dict):
            if len(value) == 1 and _REF in value:
                index = value[_REF]
                if type(index) is int:
                    # 已解析的指令只可能来自通过边界检查的索引；共享引用直接复用。
                    cached = self.instructions.get(index)
                    if cached is not None:
                        return cached
                if (type(index) is not int or index < 0
                        or index >= self.descriptor(_POOL)["item_count"]):
                    raise StorageSchemaError("Invalid instruction reference")
                if index in self.resolving:
                    raise StorageSchemaError("Cyclic instruction references")
                if index not in self.instructions:
                    self.resolving.add(index)
                    try:
                        record = self._pool_record(index)
                        instruction = self._expand_instruction(record)
                        if not isinstance(instruction, dict):
                            raise StorageSchemaError("Invalid instruction pool record")
                        self.instructions[index] = instruction
                    finally:
                        self.resolving.remove(index)
                return self.instructions[index]
            if len(value) == 1 and _LITERAL in value:
                literal = value[_LITERAL]
                if not isinstance(literal, dict):
                    raise StorageSchemaError("Invalid escaped literal")
                return {key: self.expand(item) for key, item in literal.items()}
            # 字符串值换成本次读取内的规范实例（不可变，共享安全）；其余标量原样保留。
            expand, strings = self.expand, self._strings.setdefault
            return {key: (strings(item, item) if type(item) is str
                          else item if type(item) in _SCALARS else expand(item))
                    for key, item in value.items()}
        if isinstance(value, list):
            expand, strings = self.expand, self._strings.setdefault
            items = [strings(item, item) if type(item) is str
                     else item if type(item) in _SCALARS else expand(item) for item in value]
            # 推导式按追加增长并预留容量（1~4 项都分配 4 个槽位）；切片得到容量恰好的新列表。
            # 每条记录仍各有自己的列表，不在记录之间共享可变列表。
            return items[:] if items else items
        return value


class SQLiteAnalysisDatabase:
    """Snapshot-addressed database; opening never invokes source analysis."""

    @property
    def fresh_snapshots(self) -> bool:
        """可选协议属性：get_snapshot 每次返回全新且不再被引用的对象图，调用方可直接接管。

        子类可能缓存或复用快照，因此只有本类自身作此保证；未声明的提供者视为 False。
        """
        return type(self) is SQLiteAnalysisDatabase

    # Reuse transaction and annotation-address rules without exposing legacy
    # source-addressed cache operations on this distinct storage interface.
    _transaction = ProjectStore._transaction
    _sync_file = staticmethod(ProjectStore._sync_file)
    _snapshot_id = staticmethod(ProjectStore._snapshot_id)
    _address = staticmethod(ProjectStore._address)
    history = ProjectStore.history

    def __init__(self, database: str | Path, *, read_only: bool = False,
                 create: bool = False) -> None:
        if type(read_only) is not bool or type(create) is not bool:
            raise ValueError("read_only and create must be boolean")
        if read_only and create:
            raise ValueError("A read-only database cannot be created")
        self.path = Path(database).expanduser().resolve()
        self.read_only, self._closed = read_only, False
        if not self.path.exists():
            if not create:
                raise FileNotFoundError(f"Analysis database does not exist: {self.path}")
            self.path.parent.mkdir(parents=True, exist_ok=True)
            try:
                descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                # A concurrent creator must finish before we consider its format.
                raise StorageError(f"Database was created concurrently: {self.path}") from None
            os.close(descriptor)
            try:
                self._create_database()
            except Exception:
                for suffix in ("", "-wal", "-shm"):
                    Path(f"{self.path}{suffix}").unlink(missing_ok=True)
                raise
        self._validate_database()

    def _check_open(self) -> None:
        if self._closed:
            raise StorageError("Analysis database is closed")

    @contextmanager
    def _connect(self, *, read_only: bool = False) -> Iterator[sqlite3.Connection]:
        self._check_open()
        effective_read_only = read_only or self.read_only
        mode = "ro" if effective_read_only else "rw"
        try:
            connection = sqlite3.connect(f"{self.path.as_uri()}?mode={mode}", uri=True,
                                         timeout=15, isolation_level=None)
            try:
                connection.row_factory = sqlite3.Row
                connection.execute("PRAGMA foreign_keys=ON")
                connection.execute("PRAGMA busy_timeout=15000")
                if effective_read_only:
                    connection.execute("PRAGMA query_only=ON")
                yield connection
            finally:
                connection.close()
        except sqlite3.Error as error:
            raise StorageError(f"Analysis database operation failed: {error}") from error

    def _require_write(self) -> None:
        self._check_open()
        if self.read_only:
            raise StorageError("Analysis database is read-only")

    def _create_database(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("BEGIN IMMEDIATE")
            try:
                ProjectStore._create_v1(connection)
                ProjectStore._migrate_v2(connection)
                connection.execute(f"PRAGMA user_version={PROJECT_SCHEMA_VERSION}")
                connection.execute("CREATE TABLE fdb_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                connection.executemany("INSERT INTO fdb_meta(key,value) VALUES (?,?)", [
                    ("format", FORMAT), ("storage_schema_version", str(STORAGE_SCHEMA_VERSION)),
                    ("chunk_items", str(CHUNK_ITEMS)), ("created_at", _now())])
                connection.execute("""CREATE TABLE fdb_collections (
                    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
                    collection TEXT NOT NULL, item_count INTEGER NOT NULL,
                    chunk_count INTEGER NOT NULL, alias TEXT,
                    PRIMARY KEY(snapshot_id, collection))""")
                connection.execute("""CREATE TABLE fdb_chunks (
                    snapshot_id INTEGER NOT NULL, collection TEXT NOT NULL,
                    chunk_index INTEGER NOT NULL, ordinal_start INTEGER NOT NULL,
                    item_count INTEGER NOT NULL, raw_size INTEGER NOT NULL, data BLOB NOT NULL,
                    PRIMARY KEY(snapshot_id, collection, chunk_index),
                    FOREIGN KEY(snapshot_id, collection)
                        REFERENCES fdb_collections(snapshot_id, collection) ON DELETE CASCADE)""")
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def _validate_database(self) -> None:
        if not self.path.is_file():
            raise StorageSchemaError("Analysis database is not a regular file")
        with self.path.open("rb") as stream:
            if stream.read(16) != b"SQLite format 3\x00":
                raise StorageSchemaError("File is not a Fangida SQLite analysis database")
        required = {
            "files": {"id", "path", "content_hash", "size", "updated_at"},
            "snapshots": {"id", "file_id", "content_hash", "status", "result_schema",
                          "created_at", "result_json", "invalidated_at"},
            "snapshot_entries": {"snapshot_id", "collection", "ordinal", "value_json"},
            "annotations": {"file_id", "content_hash", "address", "kind", "value", "updated_at"},
            "fdb_meta": {"key", "value"},
            "fdb_collections": {"snapshot_id", "collection", "item_count", "chunk_count", "alias"},
            "fdb_chunks": {"snapshot_id", "collection", "chunk_index", "ordinal_start",
                           "item_count", "raw_size", "data"},
        }
        try:
            with self._connect(read_only=True) as connection:
                if connection.execute("PRAGMA user_version").fetchone()[0] != PROJECT_SCHEMA_VERSION:
                    raise StorageSchemaError("Unsupported base project schema version")
                tables = {row["name"] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'")}
                for table, columns in required.items():
                    if table not in tables:
                        raise StorageSchemaError(f"Missing analysis database table: {table}")
                    actual = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
                    if not columns.issubset(actual):
                        raise StorageSchemaError(f"Invalid analysis database table: {table}")
                metadata = dict(connection.execute("SELECT key,value FROM fdb_meta"))
                if metadata.get("format") != FORMAT:
                    raise StorageSchemaError("File is not a Fangida analysis database")
                if metadata.get("storage_schema_version") != str(STORAGE_SCHEMA_VERSION):
                    raise StorageSchemaError("Unsupported analysis storage schema version")
                if metadata.get("chunk_items") != str(CHUNK_ITEMS):
                    raise StorageSchemaError("Unsupported analysis chunk layout")
        except StorageSchemaError:
            raise
        except StorageError as error:
            raise StorageSchemaError("Cannot validate analysis database schema") from error

    @staticmethod
    def _collection(connection: sqlite3.Connection, snapshot_id: int, collection: str,
                    count: int, *, alias: str | None = None) -> None:
        connection.execute("""INSERT INTO fdb_collections
            (snapshot_id,collection,item_count,chunk_count,alias) VALUES (?,?,?,?,?)""",
            (snapshot_id, collection, count, (count + CHUNK_ITEMS - 1) // CHUNK_ITEMS, alias))

    @staticmethod
    def _chunk(connection: sqlite3.Connection, snapshot_id: int, collection: str,
               chunk_index: int, values: list[Any]) -> None:
        raw = _json_bytes(values)
        connection.execute("""INSERT INTO fdb_chunks
            (snapshot_id,collection,chunk_index,ordinal_start,item_count,raw_size,data)
            VALUES (?,?,?,?,?,?,?)""", (snapshot_id, collection, chunk_index,
                chunk_index * CHUNK_ITEMS, len(values), len(raw), zlib.compress(raw, level=1)))

    def save_analysis(self, source_path: str | Path, result: AnalysisResult | Mapping[str, Any],
                      *, expected_hash: str | None = None) -> int:
        try:
            return self._save_analysis(source_path, result, expected_hash=expected_hash)
        except RecursionError as error:
            raise StorageError("Analysis contains cyclic or excessively nested data") from error

    def _save_analysis(self, source_path: str | Path, result: AnalysisResult | Mapping[str, Any],
                       *, expected_hash: str | None = None) -> int:
        self._require_write()
        source = _source_path(source_path)
        for candidate in (self.path, Path(f"{self.path}-wal"), Path(f"{self.path}-shm")):
            if candidate.exists() and source.samefile(candidate):
                raise StorageError("Original input must be separate from the analysis database and sidecars")
        content_hash, size = fingerprint(source)
        if expected_hash is not None:
            if not isinstance(expected_hash, str) or not _DIGEST_RE.fullmatch(expected_hash):
                raise ValueError("expected_hash must be a lowercase SHA-256 hex digest")
            if expected_hash != content_hash:
                raise SourceChangedError(f"Source changed during analysis: {source}")
        if isinstance(result, AnalysisResult):
            payload = {item.name: getattr(result, item.name) for item in fields(result)}
        elif isinstance(result, Mapping):
            payload = dict(result)
        else:
            raise TypeError("result must be an AnalysisResult or a mapping")
        if not isinstance(payload.get("status"), str) or not isinstance(payload.get("schema_version"), str):
            raise ValueError("result requires status and schema_version strings")
        metadata = payload.get("metadata", {})
        if not isinstance(metadata, Mapping):
            raise ValueError("metadata must be a mapping")
        imported_annotations = _import_annotations(metadata.get("user_annotations"), content_hash)
        top_collections = {key: payload[key] for key in COLLECTIONS - {"disassembly"} if key in payload}
        metadata_collections = {f"metadata.{key}": metadata[key]
                                for key in ("disassembly", "full_disassembly") if key in metadata}
        collections = {**top_collections, **metadata_collections}
        for key, values in collections.items():
            if not isinstance(values, list):
                raise ValueError(f"{key} must be a list")
        disassembly_records = _disassembly_records(payload, metadata)
        light = {key: value for key, value in payload.items() if key not in top_collections}
        light["metadata"] = {key: value for key, value in metadata.items()
                             if key not in {"disassembly", "full_disassembly", "analysis_database", "user_annotations"}}
        encoder = _Encoder(imported_annotations if any(imported_annotations.values()) else None)
        manifest = {"payload": encoder.pack(light), "collections": list(collections),
                    "format": FORMAT, "storage_schema_version": STORAGE_SCHEMA_VERSION}
        # Validate lightweight fields before beginning any mutation.
        _json_bytes([manifest])
        with self._transaction() as connection:
            file_id = self._sync_file(connection, source, content_hash, size)
            cursor = connection.execute("""INSERT INTO snapshots
                (file_id,content_hash,status,result_schema,created_at,result_json) VALUES (?,?,?,?,?,?)""",
                (file_id, content_hash, payload["status"], payload["schema_version"], _now(),
                 json.dumps({"format": FORMAT, "storage_schema_version": STORAGE_SCHEMA_VERSION,
                             "source_size": size})))
            snapshot_id = int(cursor.lastrowid)
            for kind, values in imported_annotations.items():
                annotation_kind = "rename" if kind == "renames" else "comment"
                connection.executemany("""INSERT INTO annotations
                    (file_id,content_hash,address,kind,value,updated_at) VALUES (?,?,?,?,?,?)
                    ON CONFLICT(file_id,content_hash,address,kind)
                    DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at""",
                    ((file_id, content_hash, self._address(address), annotation_kind, text, _now())
                     for address, text in values.items()))
            for name, values in collections.items():
                self._collection(connection, snapshot_id, name, len(values))
                for start in range(0, len(values), CHUNK_ITEMS):
                    self._chunk(connection, snapshot_id, name, start // CHUNK_ITEMS,
                                [encoder.pack(value) for value in values[start:start + CHUNK_ITEMS]])
            for name in COLLECTIONS - {"disassembly"}:
                if name not in collections:
                    self._collection(connection, snapshot_id, name, 0)
            disassembly_alias = None
            for candidate in ("metadata.full_disassembly", "metadata.disassembly"):
                if candidate in collections and disassembly_records == collections[candidate]:
                    disassembly_alias = candidate
                    break
            self._collection(connection, snapshot_id, "disassembly", len(disassembly_records),
                             alias=disassembly_alias)
            if disassembly_alias is None:
                for start in range(0, len(disassembly_records), CHUNK_ITEMS):
                    self._chunk(connection, snapshot_id, "disassembly", start // CHUNK_ITEMS,
                                [encoder.pack(value) for value in disassembly_records[start:start + CHUNK_ITEMS]])
            self._collection(connection, snapshot_id, _MANIFEST, 1)
            self._chunk(connection, snapshot_id, _MANIFEST, 0, [manifest])
            # Pool records are serialized once; a rare nested instruction can
            # append to the pool while its containing record is being packed.
            pool_count = len(encoder.instructions)
            self._collection(connection, snapshot_id, _POOL, pool_count)
            start = 0
            while start < len(encoder.instructions):
                values: list[Any] = []
                while len(values) < CHUNK_ITEMS and start + len(values) < len(encoder.instructions):
                    values.append(encoder.instruction(start + len(values)))
                self._chunk(connection, snapshot_id, _POOL, start // CHUNK_ITEMS, values)
                start += len(values)
            if pool_count != len(encoder.instructions):
                pool_count = len(encoder.instructions)
                connection.execute("UPDATE fdb_collections SET item_count=?,chunk_count=? "
                                   "WHERE snapshot_id=? AND collection=?",
                                   (pool_count, (pool_count + CHUNK_ITEMS - 1) // CHUNK_ITEMS,
                                    snapshot_id, _POOL))
            encoder.validate_dependencies()
            if fingerprint(source) != (content_hash, size):
                raise SourceChangedError(f"Source changed during save: {source}")
            return snapshot_id

    @staticmethod
    def _snapshot(connection: sqlite3.Connection, snapshot_id: int | None) -> sqlite3.Row:
        if snapshot_id is None:
            row = connection.execute("""SELECT s.*,f.path AS source_path,f.size AS source_size
                FROM snapshots s JOIN files f ON s.file_id=f.id ORDER BY s.id DESC LIMIT 1""").fetchone()
        else:
            ProjectStore._snapshot_id(snapshot_id)
            row = connection.execute("""SELECT s.*,f.path AS source_path,f.size AS source_size
                FROM snapshots s JOIN files f ON s.file_id=f.id WHERE s.id=?""", (snapshot_id,)).fetchone()
        if row is None:
            raise KeyError(f"Unknown snapshot: {snapshot_id}")
        try:
            descriptor = json.loads(row["result_json"])
        except (ValueError, TypeError) as error:
            raise StorageSchemaError("Invalid analysis snapshot descriptor") from error
        if (not isinstance(descriptor, dict) or descriptor.get("format") != FORMAT
                or descriptor.get("storage_schema_version") != STORAGE_SCHEMA_VERSION
                or type(descriptor.get("source_size")) is not int or descriptor["source_size"] < 0):
            raise StorageSchemaError("Unsupported analysis snapshot descriptor")
        return row

    @staticmethod
    def _annotations(connection: sqlite3.Connection, snapshot: sqlite3.Row) -> dict[str, Any]:
        result: dict[str, Any] = {"sha256": snapshot["content_hash"], "renames": {}, "comments": {}}
        for row in connection.execute("""SELECT address,kind,value FROM annotations
                WHERE file_id=? AND content_hash=? ORDER BY address,kind""",
                (snapshot["file_id"], snapshot["content_hash"])):
            try:
                address = int(row["address"], 16)
            except (ValueError, TypeError) as error:
                raise StorageSchemaError("Invalid annotation address") from error
            if not 0 <= address <= 0xFFFFFFFFFFFFFFFF or row["kind"] not in {"rename", "comment"}:
                raise StorageSchemaError("Invalid annotation record")
            key = "renames" if row["kind"] == "rename" else "comments"
            result[key][address] = row["value"]
        return result

    @staticmethod
    def _overlay(value: Any, annotations: dict[str, Any], seen: set[int] | None = None) -> None:
        if seen is None:
            seen = set()
        if isinstance(value, (dict, list)):
            identity = id(value)
            if identity in seen:
                return
            seen.add(identity)
        if isinstance(value, dict):
            address = value.get("address", value.get("start", value.get("addr")))
            if type(address) is int:
                if address in annotations["renames"] and "name" in value:
                    value.setdefault("original_name", value["name"])
                    value["name"] = annotations["renames"][address]
                if address in annotations["comments"]:
                    if "comment" in value:
                        value.setdefault("original_comment", value["comment"])
                    value["comment"] = annotations["comments"][address]
            for item in list(value.values()):
                SQLiteAnalysisDatabase._overlay(item, annotations, seen)
        elif isinstance(value, list):
            for item in value:
                SQLiteAnalysisDatabase._overlay(item, annotations, seen)

    def get_snapshot(self, snapshot_id: int | None = None) -> dict[str, Any]:
        try:
            return self._get_snapshot(snapshot_id)
        except RecursionError as error:
            raise StorageSchemaError("Analysis database contains excessively nested data") from error

    def _get_snapshot(self, snapshot_id: int | None = None) -> dict[str, Any]:
        with self._connect(read_only=True) as connection:
            connection.execute("BEGIN")
            snapshot = self._snapshot(connection, snapshot_id)
            reader = _Reader(connection, snapshot["id"])
            manifest = reader.items(_MANIFEST, 0, 1)[0]
            if (not isinstance(manifest, dict) or manifest.get("format") != FORMAT
                    or manifest.get("storage_schema_version") != STORAGE_SCHEMA_VERSION
                    or not isinstance(manifest.get("payload"), dict)
                    or not isinstance(manifest.get("collections"), list)
                    or not isinstance(manifest["payload"].get("metadata"), dict)):
                raise StorageSchemaError("Invalid analysis snapshot manifest")
            payload = manifest["payload"]
            for name in manifest["collections"]:
                if not isinstance(name, str) or name not in COLLECTIONS | {
                        "metadata.disassembly", "metadata.full_disassembly"}:
                    raise StorageSchemaError("Invalid snapshot collection")
                values = reader.items(name, 0, reader.descriptor(name)["item_count"])
                if name.startswith("metadata."):
                    payload["metadata"][name.removeprefix("metadata.")] = values
                else:
                    payload[name] = values
            annotations = self._annotations(connection, snapshot)
            if annotations["renames"] or annotations["comments"]:
                self._overlay(payload, annotations)
            # 在叠加标注之后进行，候选与元素都已是最终值。
            _reshare_references(payload)
            metadata = payload.setdefault("metadata", {})
            metadata["user_annotations"] = {"sha256": annotations["sha256"],
                "renames": {str(key): value for key, value in annotations["renames"].items()},
                "comments": {str(key): value for key, value in annotations["comments"].items()}}
            metadata["analysis_database"] = {"path": str(self.path), "snapshot_id": snapshot["id"],
                "format": FORMAT, "source_sha256": snapshot["content_hash"],
                "source_size": json.loads(snapshot["result_json"])["source_size"],
                "read_only": self.read_only}
            return payload

    def page(self, snapshot_id: int, collection: str, *, offset: int = 0,
             limit: int = 100) -> dict[str, Any]:
        try:
            return self._page(snapshot_id, collection, offset=offset, limit=limit)
        except RecursionError as error:
            raise StorageSchemaError("Analysis database contains excessively nested data") from error

    def _page(self, snapshot_id: int, collection: str, *, offset: int = 0,
              limit: int = 100) -> dict[str, Any]:
        self._snapshot_id(snapshot_id)
        if collection not in COLLECTIONS:
            raise ValueError(f"Unknown collection: {collection}")
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= MAX_PAGE_SIZE:
            raise ValueError("invalid collection pagination")
        with self._connect(read_only=True) as connection:
            connection.execute("BEGIN")
            snapshot = self._snapshot(connection, snapshot_id)
            reader = _Reader(connection, snapshot_id)
            total = reader.descriptor(collection)["item_count"]
            items = reader.items(collection, offset, limit)
            annotations = self._annotations(connection, snapshot)
            if annotations["renames"] or annotations["comments"]:
                self._overlay(items, annotations)
            following = offset + len(items)
            return {"items": items, "total": total,
                    "next_offset": following if following < total else None}

    def annotations(self, snapshot_id: int) -> dict[str, Any]:
        self._snapshot_id(snapshot_id)
        with self._connect(read_only=True) as connection:
            connection.execute("BEGIN")
            return self._annotations(connection, self._snapshot(connection, snapshot_id))

    def _set_snapshot_annotation(self, snapshot_id: int, address: int, kind: str, value: str) -> None:
        self._snapshot_id(snapshot_id)
        address_hex = self._address(address)
        with self._transaction() as connection:
            snapshot = self._snapshot(connection, snapshot_id)
            if value == "":
                connection.execute("DELETE FROM annotations WHERE file_id=? AND content_hash=? AND address=? AND kind=?",
                                   (snapshot["file_id"], snapshot["content_hash"], address_hex, kind))
            else:
                connection.execute("""INSERT INTO annotations
                    (file_id,content_hash,address,kind,value,updated_at) VALUES (?,?,?,?,?,?)
                    ON CONFLICT(file_id,content_hash,address,kind)
                    DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at""",
                    (snapshot["file_id"], snapshot["content_hash"], address_hex, kind, value, _now()))

    def rename_symbol(self, snapshot_id: int, address: int, name: str) -> None:
        if not isinstance(name, str) or not name or len(name) > 512 or any(char in name for char in "\r\n\0"):
            raise ValueError("name must be a non-empty, single-line string of at most 512 characters")
        self._set_snapshot_annotation(snapshot_id, address, "rename", name)

    def set_comment(self, snapshot_id: int, address: int, text: str) -> None:
        if not isinstance(text, str) or len(text) > 16_384 or "\0" in text:
            raise ValueError("comment must be a string of at most 16384 characters")
        self._set_snapshot_annotation(snapshot_id, address, "comment", text)

    def info(self) -> dict[str, Any]:
        with self._connect(read_only=True) as connection:
            latest = connection.execute("SELECT MAX(id) FROM snapshots").fetchone()[0]
            return {"path": str(self.path), "format": FORMAT,
                    "storage_schema_version": STORAGE_SCHEMA_VERSION, "read_only": self.read_only,
                    "snapshot_count": connection.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0],
                    "latest_snapshot_id": latest,
                    "source_count": connection.execute("SELECT COUNT(*) FROM files").fetchone()[0],
                    "stores_original_binary": False,
                    "codec": "zlib-json-shared-instructions", "chunk_items": CHUNK_ITEMS}

    def close(self) -> None:
        self._closed = True

    def __enter__(self) -> SQLiteAnalysisDatabase:
        self._check_open()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


class PluginImpl:
    name = "sqlite_storage"
    version = "0.1.0"

    def __init__(self) -> None:
        self._databases: weakref.WeakSet[SQLiteAnalysisDatabase] = weakref.WeakSet()
        self._lock = Lock()
        self._closed = False

    def capabilities(self) -> tuple[str, ...]:
        return ("analysis_database", "snapshots", "annotations", "pagination", "read_only")

    def open_database(self, path: str | Path, *, read_only: bool = False,
                      create: bool = False) -> SQLiteAnalysisDatabase:
        with self._lock:
            if self._closed:
                raise StorageError("Storage plugin is closed")
            database = SQLiteAnalysisDatabase(path, read_only=read_only, create=create)
            self._databases.add(database)
            return database

    def teardown(self) -> None:
        with self._lock:
            for database in tuple(self._databases):
                database.close()
            self._databases.clear()
            self._closed = True
