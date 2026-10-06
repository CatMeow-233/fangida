"""与界面工具包无关的导航历史和已完成分析结果索引。

这里只读取 GUI 结果记录；不导入 Loader、处理器、插件或 Tk，不解码、不
复制指令图。调用方负责在结果完成后建索引，并在切换分析结果时重建索引。
"""
from __future__ import annotations

from array import array
from bisect import bisect_left, bisect_right
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import re
from typing import Any

from ..addresses import NativeAddressMap


_SPACE_ALIASES = {"ram": "native", "virtual": "native", "virtual_address": "native",
                  "fileoffset": "file_offset", "offset": "file_offset"}


def _space(value: str) -> str:
    return _SPACE_ALIASES.get(value, value)


@dataclass(frozen=True, slots=True)
class Location:
    """地址始终带空间和容器身份；原生符号来源标签不属于容器身份。"""

    address: int
    source: str = ""
    address_space: str = "native"

    def __post_init__(self) -> None:
        if type(self.address) is not int or not 0 <= self.address <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("地址必须是非负的 64 位整数")
        if not isinstance(self.source, str) or not isinstance(self.address_space, str):
            raise TypeError("source 和 address_space 必须是字符串")
        if not self.address_space:
            raise ValueError("地址空间不能为空")
        object.__setattr__(self, "address_space", _space(self.address_space))


class NavigationHistory:
    """线性历史；新访问会截断前进分支，连续相同位置不会新增历史。"""

    def __init__(self) -> None:
        self._entries: list[Location] = []
        self._cursor = -1

    @property
    def current(self) -> Location | None:
        return self._entries[self._cursor] if self._cursor >= 0 else None

    @property
    def cursor(self) -> int:
        return self._cursor

    @property
    def entries(self) -> tuple[Location, ...]:
        return tuple(self._entries)

    @property
    def can_back(self) -> bool:
        return self._cursor > 0

    @property
    def can_forward(self) -> bool:
        return 0 <= self._cursor < len(self._entries) - 1

    def visit(self, location: Location) -> Location:
        if not isinstance(location, Location):
            raise TypeError("历史位置必须是 Location")
        if location == self.current:
            return location
        del self._entries[self._cursor + 1:]
        self._entries.append(location)
        self._cursor += 1
        return location

    def back(self) -> Location | None:
        if not self.can_back:
            return None
        self._cursor -= 1
        return self.current

    def forward(self) -> Location | None:
        if not self.can_forward:
            return None
        self._cursor += 1
        return self.current

    def reset(self, location: Location | None = None) -> None:
        if location is not None and not isinstance(location, Location):
            raise TypeError("历史位置必须是 Location")
        self._entries.clear()
        self._cursor = -1
        if location is not None:
            self.visit(location)


@dataclass(frozen=True, slots=True)
class NavigationTarget:
    """只包含行定位信息，原记录仍由调用方的 rows 或 cfgs 持有。"""

    table: str
    row_index: int
    location: Location
    field: str = ""
    name: str = ""
    cfg_index: int | None = None


@dataclass(frozen=True, slots=True)
class ReferenceTarget:
    table: str
    row_index: int
    src: Location
    dst: Location | None
    kind: str = ""
    target: str = ""


class UnknownLocationError(ValueError):
    pass


class AmbiguousLocationError(ValueError):
    def __init__(self, message: str, candidates: Sequence[Location], *,
                 targets: Sequence[NavigationTarget] = ()) -> None:
        self.candidates = tuple(candidates)
        self.targets = tuple(targets)
        labels = ", ".join(f"{item.address_space}:{item.source or '<主文件>'}:"
                           f"{item.address:#x}" for item in self.candidates)
        super().__init__(f"{message}：{labels}")


def _address(value: Any) -> int | None:
    return value if type(value) is int and 0 <= value <= 0xFFFFFFFFFFFFFFFF else None


_MAX_ADDRESS = 0xFFFFFFFFFFFFFFFF
_new_object = object.__new__
_set_field = object.__setattr__
_NATIVE = ("", "native")
_BYTECODE_KINDS = frozenset({"apk", "dex", "jar", "class"})


def _trusted_location(address: int, source: str, space: str) -> Location:
    """索引内部构造 Location：地址已经 _address 校验、空间已经 _space 规范化，跳过重复校验。

    与 Location(address, source, space) 得到的对象逐字段相同（相等、哈希一致）。
    """
    location = _new_object(Location)
    _set_field(location, "address", address)
    _set_field(location, "source", source)
    _set_field(location, "address_space", space)
    return location


def _is_mapping(value: Any) -> bool:
    return type(value) is dict or isinstance(value, Mapping)


def _is_sequence(value: Any) -> bool:
    return type(value) in (list, tuple) or (isinstance(value, Sequence) and not isinstance(value, (str, bytes)))


def _block_spans(block: Mapping[str, Any]) -> tuple[tuple[int, int], ...]:
    """一个块内全部有效指令的 [起点, 终点) 合并结果；没有有效指令时为空。"""
    instructions = block.get("instructions", ())
    if not _is_sequence(instructions):
        return ()
    spans: list[tuple[int, int]] = []
    append = spans.append
    for instruction in instructions:
        if type(instruction) is not dict and not isinstance(instruction, Mapping):
            continue
        address = instruction.get("addr")
        if type(address) is not int or not 0 <= address <= _MAX_ADDRESS:
            continue
        size = instruction.get("size")
        if type(size) is not int or not 0 < size <= _MAX_ADDRESS:
            size = 1  # 与 _address(size) or 1 相同
        append((address, address + size))
    if not spans:
        return ()
    spans.sort()
    merged = [spans[0]]
    for start, end in spans[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end:
            if end > last_end:
                merged[-1] = (last_start, end)
        else:
            merged.append((start, end))
    return tuple(merged)


def _merge_spans(spans: list[tuple[int, int]], index: int) -> list[tuple[int, int, int]]:
    """排序并合并相交或相接的区间，附上所属行号（与原逐条合并规则相同）。"""
    spans.sort()
    merged: list[tuple[int, int, int]] = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]), index)
        else:
            merged.append((start, end, index))
    return merged


def _record_context(record: Mapping[str, Any], table: str, kind: str
                    ) -> tuple[str, str]:
    meta = record.get("arch_meta")
    meta = meta if isinstance(meta, Mapping) else {}
    explicit = record.get("address_space", meta.get("address_space"))
    bytecode = ("code_offset" in record or record.get("kind") in {"dex", "jvm", "class"}
                or meta.get("arch") in {"dex", "jvm"}
                or kind in {"apk", "dex", "jar", "class"})
    space = _space(str(explicit)) if explicit else (
        "file_offset" if bytecode or table in {"Strings", "API Calls"} else "native")
    source = str(meta.get("container_member", record.get("source", ""))) if bytecode else ""
    # Explicit foreign/container contexts are allowed even in a native result.
    if explicit and space != "native":
        source = str(meta.get("container_member", record.get("source", "")))
    return source, space


class _RowAddresses:
    """反汇编行的地址只读序列视图：第 i 项就是 rows[i]["addr"]，供 bisect 与切片使用。

    只在全部行都是普通行、地址合法且非递减时使用：此时按 (地址, 行号, 字段) 排序的点
    恰好就是行本身的顺序，不必再为每条指令保存地址、行号和 (行号, 字段) 元组。
    """

    __slots__ = ("_rows",)

    def __init__(self, rows: Sequence[Mapping[str, Any]]) -> None:
        self._rows = rows

    def __len__(self) -> int:
        return len(self._rows)

    def __getitem__(self, index: Any) -> Any:
        if type(index) is slice:
            return [record["addr"] for record in self._rows[index]]
        return self._rows[index]["addr"]


class _RowFields:
    """与 _RowAddresses 对应的 (行号, "addr") 只读序列视图。"""

    __slots__ = ("_rows",)

    def __init__(self, rows: Sequence[Mapping[str, Any]]) -> None:
        self._rows = rows

    def __len__(self) -> int:
        return len(self._rows)

    def __getitem__(self, index: Any) -> Any:
        length = len(self._rows)
        if type(index) is slice:
            return [(row, "addr") for row in range(*index.indices(length))]
        if index < 0:
            index += length
        if not 0 <= index < length:
            raise IndexError("row index out of range")
        return (index, "addr")


def _plain_sorted_disassembly(records: Sequence[Any]) -> bool:
    """全部行都是精确 dict 的普通行（上下文只取决于表名和结果类型）、addr 合法且非递减。

    普通行的判定与 AddressIndex._index_disassembly 逐行处理时相同。
    """
    previous = 0
    for record in records:
        if (type(record) is not dict or "address_space" in record or "code_offset" in record
                or "kind" in record or "source" in record):
            return False
        meta = record.get("arch_meta")
        if meta is not None and (type(meta) is not dict or "address_space" in meta
                                 or "arch" in meta or "container_member" in meta):
            return False
        address = record.get("addr")
        if type(address) is not int or not previous <= address <= _MAX_ADDRESS:
            return False
        previous = address
    return True


def _sorted_pairs(keys: list[int], shift: int) -> tuple[array, array]:
    """把 (地址 << shift | 行号) 排序后拆成地址数组和行号数组（与按 (地址, 行号) 排序相同）。"""
    keys.sort()
    mask = (1 << shift) - 1
    return array("Q", (key >> shift for key in keys)), array("q", (key & mask for key in keys))


class _XrefPoints:
    """全部是普通原生行的 Xrefs 表：src、dst 端点按 (地址, 行号) 排序存放在定长数组中。

    取代每条 xref 的两个点、两个 Location、一个 ReferenceTarget 和 _incoming/_outgoing 的
    字典项；查询时用 bisect 取出行号，再现造（并按行号缓存）与原实现相等的对象。
    """

    __slots__ = ("rows", "src_addresses", "src_rows", "dst_addresses", "dst_rows")

    def __init__(self, rows: Sequence[Any], src_addresses: array, src_rows: array,
                 dst_addresses: array, dst_rows: array) -> None:
        self.rows = rows
        self.src_addresses = src_addresses
        self.src_rows = src_rows
        self.dst_addresses = dst_addresses
        self.dst_rows = dst_rows

    def __bool__(self) -> bool:
        return bool(self.src_rows) or bool(self.dst_rows)

    def at(self, address: int) -> list[tuple[int, str]]:
        """该地址上的 (行号, 字段)，顺序与原 (地址, 行号, 字段) 排序相同（同一行 dst 在 src 前）。"""
        found = [(row, "src") for row in self.src_rows[
            bisect_left(self.src_addresses, address):bisect_right(self.src_addresses, address)]]
        found.extend((row, "dst") for row in self.dst_rows[
            bisect_left(self.dst_addresses, address):bisect_right(self.dst_addresses, address)])
        found.sort()
        return found

    def has_incoming(self, address: int) -> bool:
        """是否有 dst 为该地址、src 也合法的行（原实现中即 _incoming 里有该目标）。"""
        rows = self.rows
        for row in self.dst_rows[bisect_left(self.dst_addresses, address):
                                 bisect_right(self.dst_addresses, address)]:
            if _address(rows[row].get("src")) is not None:
                return True
        return False


class _CfgBlocks:
    """CFG 块表：(CFG 下标, 块下标, 块起点) 存在并行的定长数组里，查询时才构造 Location。

    按下标读取时返回与原 (cfg_index, block_index, Location) 三元组相等的值。
    """

    __slots__ = ("_cfgs", "_blocks", "_addresses", "_contexts")

    def __init__(self, count: int) -> None:
        self._cfgs = array("q")
        self._blocks = array("q")
        self._addresses = array("Q")
        self._contexts: list[tuple[str, str] | None] = [None] * count  # 每个 CFG 的 (source, space)

    def __len__(self) -> int:
        return len(self._cfgs)

    def set_context(self, cfg_index: int, context: tuple[str, str]) -> None:
        self._contexts[cfg_index] = context

    def append(self, cfg_index: int, block_index: int, address: int) -> None:
        self._cfgs.append(cfg_index)
        self._blocks.append(block_index)
        self._addresses.append(address)

    def __getitem__(self, identifier: int) -> tuple[int, int, Location]:
        cfg_index = self._cfgs[identifier]
        source, space = self._contexts[cfg_index]
        return (cfg_index, self._blocks[identifier],
                _trusted_location(self._addresses[identifier], source, space))


class _Intervals:
    """按最大结束位置剪枝，保留重叠函数而不随机选择其中一个。"""

    def __init__(self, values: Sequence[tuple[int, int, int]]) -> None:
        ordered = sorted(values)
        self.values = tuple(ordered)
        self.starts = tuple(item[0] for item in ordered)
        maximum = 0
        prefixes = []
        for _, end, _ in ordered:
            maximum = max(maximum, end)
            prefixes.append(maximum)
        self.maximum_ends = tuple(prefixes)

    def at(self, address: int) -> tuple[int, ...]:
        cursor = bisect_right(self.starts, address) - 1
        found: set[int] = set()
        while cursor >= 0 and self.maximum_ends[cursor] > address:
            start, end, index = self.values[cursor]
            if start <= address < end:
                found.add(index)
            cursor -= 1
        return tuple(sorted(found))


class _PackedIntervals(_Intervals):
    """与 _Intervals 查询结果相同，但起点、终点、标识和前缀最大终点存放在定长数组里。

    每个区间 32 字节，而不是一个三元组、一个新建的终点 int 和三个 tuple 槽位。
    """

    def __init__(self, values: Sequence[tuple[int, int, int]]) -> None:
        ordered = sorted(values)
        self.starts = array("Q", (item[0] for item in ordered))
        self.ends = array("Q", (item[1] for item in ordered))
        self.identifiers = array("q", (item[2] for item in ordered))
        maximum = 0
        prefixes = array("Q")
        for end in self.ends:
            if end > maximum:
                maximum = end
            prefixes.append(maximum)
        self.maximum_ends = prefixes

    def at(self, address: int) -> tuple[int, ...]:
        starts, ends, maximum_ends = self.starts, self.ends, self.maximum_ends
        cursor = bisect_right(starts, address) - 1
        found: set[int] = set()
        while cursor >= 0 and maximum_ends[cursor] > address:
            if starts[cursor] <= address < ends[cursor]:
                found.add(self.identifiers[cursor])
            cursor -= 1
        return tuple(sorted(found))


def _packed_intervals(values: Sequence[tuple[int, int, int]]) -> _Intervals:
    """数组装得下（终点不超过 64 位）时用 _PackedIntervals，否则保持原 _Intervals。"""
    try:
        return _PackedIntervals(values)
    except OverflowError:
        return _Intervals(values)


class AddressIndex:
    """已完成 GUI rows 的地址索引；只借用记录引用，不克隆整份 IR。

    地址查询返回真实指令起点。命中指令中间时，查询的 Location 和返回
    NavigationTarget.location 会不同，界面可据此明确提示对齐。
    """

    def __init__(self, rows: Mapping[str, Sequence[Mapping[str, Any]]],
                 cfgs: Sequence[Mapping[str, Any]] = (), *, kind: str = "") -> None:
        self._rows = rows
        self._cfgs = cfgs
        self.kind = kind
        self._native_addresses = NativeAddressMap(rows.get("Sections", ()), kind=kind)
        grouped: dict[tuple[str, str], dict[str, list[tuple[int, int, str]]]] = defaultdict(
            lambda: defaultdict(list))
        self._symbols: dict[str, list[NavigationTarget]] = defaultdict(list)
        section_ranges: dict[tuple[str, str], list[tuple[int, int, int]]] = defaultdict(list)
        function_ranges: dict[tuple[str, str], list[tuple[int, int, int]]] = defaultdict(list)
        self._incoming: dict[Location, list[ReferenceTarget]] = defaultdict(list)
        self._outgoing: dict[Location, list[ReferenceTarget]] = defaultdict(list)
        self._string_locations: dict[int, tuple[tuple[str, Location], ...]] = {}
        self._string_spans: list[tuple[int, str, Location]] = []
        string_ranges: dict[tuple[str, str], list[tuple[int, int, int]]] = defaultdict(list)
        self._string_references: dict[int, list[ReferenceTarget]] = defaultdict(list)
        for index, record in enumerate(rows.get("Strings", ())):
            if not isinstance(record, Mapping):
                continue
            spans = self._string_row_spans(record)
            locations = tuple((field, location) for field, location, _ in spans)
            self._string_locations[id(record)] = locations
            for field, location, size in spans:
                if not size:
                    continue
                identifier = len(self._string_spans)
                self._string_spans.append((index, field, location))
                string_ranges[(location.source, location.address_space)].append(
                    (location.address, min(location.address + size, 1 << 64), identifier))
        self._strings = {key: _Intervals(values) for key, values in string_ranges.items()}
        # 全部是普通原生行的 Xrefs 表改用排序数组（见 _index_xrefs）；None 表示按原实现逐行索引。
        self._xref_points: _XrefPoints | None = None
        # 按行号缓存现造的 Xrefs ReferenceTarget：同一行在 outgoing、incoming 和字符串引用中
        # 始终是同一个对象（与原实现共享同一对象的语义相同）。
        self._xref_references: dict[int, ReferenceTarget] = {}
        self._cfg_blocks = _CfgBlocks(len(cfgs))
        self._cfg_ranges: dict[tuple[str, str], _Intervals] = {}
        self._cfg_functions: dict[int, list[int]] = defaultdict(list)
        self._function_cfg: dict[int, tuple[int, ...]] = {}
        self._block_cache: dict[int, tuple[tuple[int, int], ...]] = {}
        for table, records in rows.items():
            if table == "Disassembly":
                self._index_disassembly(records, grouped, kind)
                continue
            if table == "Xrefs" and self._index_xrefs(records, grouped):
                continue
            for index, record in enumerate(records):
                if not isinstance(record, Mapping):
                    continue
                row_locations = self._row_locations(table, record)
                for field, location in row_locations:
                    grouped[(location.source, location.address_space)][table].append(
                        (location.address, index, field))
                    if table == "Sections":
                        size = _address(record.get("size"))
                        if size:
                            section_ranges[(location.source, location.address_space)].append(
                                (location.address, location.address + size, index))
                if table == "Xrefs":
                    endpoints = dict(row_locations)
                    source, target = endpoints.get("src"), endpoints.get("dst")
                    if source is not None and target is not None:
                        reference = ReferenceTarget("Xrefs", index, source, target,
                                                    str(record.get("kind", "")))
                        self._outgoing[source].append(reference)
                        self._incoming[target].append(reference)
                    continue
                # 字符串可以同时有多个真实加载地址；其行不作为命名函数索引。
                if table == "Strings":
                    name = record.get("name")
                    if isinstance(name, str) and name:
                        preferred = tuple(item for item in row_locations if item[0] == "address")
                        for field, location in preferred or row_locations:
                            target = NavigationTarget(table, index, location, field=field, name=name)
                            self._symbols[name].append(target)
                            descriptor = record.get("descriptor")
                            if isinstance(descriptor, str) and descriptor:
                                self._symbols[name + descriptor].append(target)
                    continue
                location = self.location_for_row(table, index)
                if location is None:
                    continue
                name = record.get("name")
                if isinstance(name, str) and name:
                    target = NavigationTarget(table, index, location, name=name)
                    self._symbols[name].append(target)
                    descriptor = record.get("descriptor")
                    if isinstance(descriptor, str) and descriptor:
                        self._symbols[name + descriptor].append(target)
                if table == "Functions":
                    context = (location.source, location.address_space)
                    function_ranges[context].extend(self._function_ranges(
                        record, index, location, self._block_cache))
        self._points: dict[tuple[str, str], dict[str, tuple[
            tuple[int, ...], tuple[tuple[int, str], ...]]]] = {}
        for context, tables in grouped.items():
            self._points[context] = {}
            for table, values in tables.items():
                if type(values) is not list:
                    # 快速路径已给出最终结构（反汇编行视图或 xref 数组），保持表的插入顺序。
                    self._points[context][table] = values
                    continue
                # 元素恰为 (地址, 行号, 字段) 三元组，自然排序与按这三项排序相同。
                values.sort()
                self._points[context][table] = (
                    tuple(value[0] for value in values),
                    tuple((value[1], value[2]) for value in values))
        self._sections = {key: _Intervals(value) for key, value in section_ranges.items()}
        self._functions = {key: _Intervals(value) for key, value in function_ranges.items()}
        self._index_cfgs()
        self._index_references()
        self._index_string_references()
        del self._block_cache  # 只在建索引期间使用

    @staticmethod
    def _index_disassembly(records: Sequence[Any], grouped: Any, kind: str) -> None:
        """大表仅保存地址、行号和字段，不为每条 IR 分配 Location。

        没有空间/容器元数据的行（原生结果几乎全部如此）上下文只取决于表名和结果类型，
        只计算一次；其余行仍逐行调用 _record_context，结果与逐行计算相同。
        """
        plain_context = _record_context({}, "Disassembly", kind)
        if type(records) in (list, tuple) and records and _plain_sorted_disassembly(records):
            # 全部是普通行、地址合法且非递减（完整分析的 full_disassembly 即如此）：排序后的点
            # 恰好按行号排列，地址序列与 (行号, 字段) 序列都可以由行本身给出，不再逐条保存。
            # 首行就是普通行，分组在与逐行处理相同的时机建立，表的插入顺序不变。
            grouped[plain_context]["Disassembly"] = (_RowAddresses(records), _RowFields(records))
            return
        plain_points = None  # 首条普通行出现时才建分组，保持与逐行处理相同的分组插入顺序
        for index, record in enumerate(records):
            if type(record) is dict:
                meta = record.get("arch_meta")
                plain = ("address_space" not in record and "code_offset" not in record
                         and "kind" not in record and "source" not in record
                         and (meta is None or (type(meta) is dict and "address_space" not in meta
                                               and "arch" not in meta and "container_member" not in meta)))
            elif isinstance(record, Mapping):
                plain = False
            else:
                continue
            address = record.get("addr")
            if plain and type(address) is int and 0 <= address <= _MAX_ADDRESS:
                if plain_points is None:
                    plain_points = grouped[plain_context]["Disassembly"]
                plain_points.append((address, index, "addr"))
                continue
            source, space = _record_context(record, "Disassembly", kind)
            for field in ("addr", "address", "offset"):
                address = _address(record.get(field))
                if address is not None:
                    grouped[(source, space)]["Disassembly"].append((address, index, field))
                    break

    def _index_xrefs(self, records: Sequence[Any], grouped: Any) -> bool:
        """全部是普通原生行时，把 Xrefs 的端点建成排序数组并返回 True；否则不改任何状态并返回 False。

        普通原生行：精确 dict，结果不是字节码容器，且没有 arch_meta、address_space、code_offset、
        src_space、dst_space 键，kind 为 str（或缺省）且不是 dex/jvm/class。此时 _record_context
        与 _row_locations 给出的两个端点一定是 ("", "native") 上下文，与逐行计算相同。
        不满足条件（例如带端点空间的 Ghidra 合并行）时整张表按原实现逐行索引。
        """
        if self.kind in _BYTECODE_KINDS or type(records) not in (list, tuple):
            return False
        shift = max(1, len(records).bit_length())
        src_addresses, src_rows = array("Q"), array("q")
        src_sorted = True
        previous = 0
        destinations: list[int] = []
        add_destination = destinations.append
        for row, record in enumerate(records):
            if type(record) is not dict:
                if isinstance(record, Mapping):
                    return False
                continue  # 与原实现相同：非映射行没有端点
            if ("arch_meta" in record or "address_space" in record or "code_offset" in record
                    or "src_space" in record or "dst_space" in record):
                return False
            kind = record.get("kind")
            if kind is not None and (type(kind) is not str or kind in {"dex", "jvm", "class"}):
                return False
            address = record.get("src")
            if type(address) is int and 0 <= address <= _MAX_ADDRESS:
                if address < previous:
                    src_sorted = False
                previous = address
                src_addresses.append(address)
                src_rows.append(row)
            address = record.get("dst")
            if type(address) is int and 0 <= address <= _MAX_ADDRESS:
                add_destination(address << shift | row)
        if not src_sorted:
            # 引用通常已按 src 排序；否则按 (地址, 行号) 重新排序。
            src_addresses, src_rows = _sorted_pairs(
                [address << shift | row for address, row in zip(src_addresses, src_rows)], shift)
        dst_addresses, dst_rows = _sorted_pairs(destinations, shift)
        del destinations
        points = _XrefPoints(records, src_addresses, src_rows, dst_addresses, dst_rows)
        self._xref_points = points
        if points:
            # 与逐行处理相同：表内出现第一个合法端点时才建立分组（Xrefs 只有原生上下文）。
            grouped[_NATIVE]["Xrefs"] = points
        return True

    def _xref_reference(self, row: int) -> ReferenceTarget | None:
        """第 row 行的 ReferenceTarget（两个端点都合法时）；同一行始终返回同一个对象。"""
        reference = self._xref_references.get(row)
        if reference is None:
            record = self._xref_points.rows[row]
            source, target = _address(record.get("src")), _address(record.get("dst"))
            if source is None or target is None:
                return None
            reference = self._xref_references.setdefault(row, ReferenceTarget(
                "Xrefs", row, _trusted_location(source, "", "native"),
                _trusted_location(target, "", "native"), str(record.get("kind", ""))))
        return reference

    def _xref_range(self, addresses: array, rows: array, address: int) -> list[ReferenceTarget]:
        """该地址上的 Xrefs 引用（按行号顺序），只含两个端点都合法的行，与原 _outgoing/_incoming 相同。"""
        found = []
        for row in rows[bisect_left(addresses, address):bisect_right(addresses, address)]:
            reference = self._xref_reference(row)
            if reference is not None:
                found.append(reference)
        return found

    def _string_row_locations(self, record: Mapping[str, Any]
                              ) -> tuple[tuple[str, Location], ...]:
        return tuple((field, location) for field, location, _ in self._string_row_spans(record))

    def _string_row_spans(self, record: Mapping[str, Any]
                          ) -> tuple[tuple[str, Location, int], ...]:
        source, space = _record_context(record, "Strings", self.kind)
        size = _address(record.get("byte_length", record.get("length"))) or 1
        metadata = record.get("arch_meta")
        metadata = metadata if isinstance(metadata, Mapping) else {}
        explicit = record.get("address_space", metadata.get("address_space"))
        bytecode = (self.kind in {"apk", "dex", "jar", "class"}
                    or record.get("kind") in {"dex", "jvm", "class"}
                    or metadata.get("arch") in {"dex", "jvm"}
                    or "code_offset" in record)
        offset = _address(record.get("offset"))
        if bytecode or explicit and _space(str(explicit)) != "native":
            # 成员偏移仅属于该成员，不能套用外层原生 section 的映射。
            field = "offset" if offset is not None else "address"
            address = offset if offset is not None else _address(record.get("address"))
            return ((field, Location(address, source, space), size),) if address is not None else ()
        addresses: set[int] = set()
        address = _address(record.get("address"))
        if address is not None:
            addresses.add(address)
        declared = record.get("addresses", ())
        if isinstance(declared, Sequence) and not isinstance(declared, (str, bytes)):
            addresses.update(value for value in declared if _address(value) is not None)
        lengths: dict[int, int] = {}
        if "address_ranges" in record:
            declared_ranges = record["address_ranges"]
            if isinstance(declared_ranges, Sequence) and not isinstance(declared_ranges, (str, bytes)):
                for item in declared_ranges:
                    if (not isinstance(item, Sequence) or isinstance(item, (str, bytes))
                            or len(item) != 2):
                        continue
                    target, available = item
                    if _address(target) is not None and _address(available) is not None and available:
                        lengths[target] = max(lengths.get(target, 0), available)
            addresses.update(lengths)
        elif addresses:
            # 显式 VA 的旧快照保留其原声明范围；新增范围声明则优先使用实际映射字节数。
            lengths = {target: size for target in addresses}
        elif offset is not None:
            # 旧数据库只有 offset；范围在 file_size / virtual_size 末尾截断。
            lengths = dict(self._native_addresses.ranges_for_offset(offset, size))
            addresses.update(lengths)
        result = [("address", Location(value), lengths.get(value, 0)) for value in sorted(addresses)]
        if offset is not None:
            result.append(("offset", Location(offset, "", "file_offset"), size))
        return tuple(result)

    def _row_locations(self, table: str, record: Mapping[str, Any]
                       ) -> tuple[tuple[str, Location], ...]:
        if table == "Strings":
            return self._string_locations.get(id(record), ())
        source, space = _record_context(record, table, self.kind)
        if table == "Xrefs":
            result = []
            for field in ("src", "dst"):
                address = _address(record.get(field))
                if address is not None:
                    endpoint_space = _space(str(record.get(field + "_space", space)))
                    endpoint_source = (str(record.get(field + "_source", record.get("source", source)))
                                       if endpoint_space != "native" else "")
                    # 地址已校验、空间已规范化：用受信任构造，结果与 Location(...) 相同。
                    result.append((field, _trusted_location(address, endpoint_source, endpoint_space)))
            return tuple(result)
        fields = {"Functions": ("location", "start", "code_offset", "file_offset"),
                  "Disassembly": ("addr", "address", "offset"),
                  "Strings": ("offset",), "Sections": ("address", "offset"),
                  "Imports": ("address",), "Exports": ("address",),
                  "API Calls": ("addr",), "Pseudocode": ("start",)}.get(table, ())
        result = []
        for field in fields:
            address = _address(record.get(field))
            if address is not None:
                actual_space = "file_offset" if table == "Sections" and field == "offset" else space
                result.append((field, _trusted_location(address, source, actual_space)))
                if table != "Sections":
                    break
        return tuple(result)

    def location_for_row(self, table: str, index: int, field: str | None = None
                         ) -> Location | None:
        records = self._rows.get(table, ())
        if type(index) is not int or not 0 <= index < len(records):
            return None
        record = records[index]
        if not isinstance(record, Mapping):
            return None
        locations = self._row_locations(table, record)
        if table == "Strings":
            preferred = tuple(location for key, location in locations
                              if key == (field or "address"))
            if len(preferred) > 1:
                raise AmbiguousLocationError("该字符串有多个加载地址，请指定目标地址", preferred)
            if preferred:
                return preferred[0]
        return next((location for key, location in locations if field is None or field == key), None)

    def locations_for_row(self, table: str, index: int, field: str | None = None
                          ) -> tuple[Location, ...]:
        """读取该行所有明确的地址别名，保留多映射身份而不选择其中一个。"""
        records = self._rows.get(table, ())
        if type(index) is not int or not 0 <= index < len(records):
            return ()
        record = records[index]
        if not isinstance(record, Mapping):
            return ()
        return tuple(location for key, location in self._row_locations(table, record)
                     if field is None or key == field)

    @staticmethod
    def _function_ranges(record: Mapping[str, Any], index: int, location: Location,
                         block_cache: dict[int, tuple[tuple[int, int], ...]] | None = None
                         ) -> list[tuple[int, int, int]]:
        spans: list[tuple[int, int]] = [(location.address, location.address + 1)]
        found = False
        blocks = record.get("blocks", ())
        if _is_sequence(blocks):
            for block in blocks:
                if not _is_mapping(block):
                    continue
                # 完整分析里 CFG 与函数表共享同一批块对象：每个块的指令范围只算一次。
                cached = block_cache.get(id(block)) if block_cache is not None else None
                if cached is None:
                    cached = _block_spans(block)
                    if block_cache is not None:
                        block_cache[id(block)] = cached
                if cached:
                    found = True
                    spans.extend(cached)
        if not found:
            size = _address(record.get("size"))
            if size:
                spans.append((location.address, location.address + size))
            bytecode_length = _address(record.get("bytecode_length"))
            if bytecode_length:
                start = (_address(record.get("code_offset")) or location.address) + (
                    16 if record.get("kind") == "dex" else 0)
                spans.append((start, start + bytecode_length))
            listing = record.get("disassembly", ())
            if isinstance(listing, Sequence) and not isinstance(listing, (str, bytes)):
                for instruction in listing:
                    if isinstance(instruction, Mapping):
                        address = _address(instruction.get("addr"))
                        if address is not None:
                            spans.append((address, address + (_address(instruction.get("size")) or 1)))
        return _merge_spans(spans, index)

    def _index_cfgs(self) -> None:
        block_cache = self._block_cache
        blocks_table = self._cfg_blocks
        contexts: dict[tuple[str, str], tuple[str, str]] = {}
        by_entry: dict[Location, list[int]] = defaultdict(list)
        ranges: dict[tuple[str, str], list[tuple[int, int, int]]] = defaultdict(list)
        for cfg_index, cfg in enumerate(self._cfgs):
            if not isinstance(cfg, Mapping):
                continue
            context = _record_context(cfg, "Functions", self.kind)
            context = contexts.setdefault(context, context)  # 各 CFG 共用相同的上下文元组
            blocks_table.set_context(cfg_index, context)
            source, space = context
            start = _address(cfg.get("start"))
            if start is not None:
                by_entry[Location(start, source, space)].append(cfg_index)
            graph = cfg.get("graph", {})
            if not isinstance(graph, Mapping):
                continue
            blocks = graph.get("blocks", ())
            if not isinstance(blocks, Sequence) or isinstance(blocks, (str, bytes)):
                continue
            for block_index, block in enumerate(blocks):
                if not isinstance(block, Mapping):
                    continue
                address = _address(block.get("start"))
                instructions = block.get("instructions", ())
                if address is None and isinstance(instructions, Sequence):
                    address = next((_address(record.get("addr")) for record in instructions
                                    if isinstance(record, Mapping) and _address(record.get("addr")) is not None), None)
                if address is not None:
                    identifier = len(blocks_table)
                    blocks_table.append(cfg_index, block_index, address)
                    cached = block_cache.get(id(block))
                    if cached is None:
                        cached = block_cache[id(block)] = _block_spans(block)
                    # 与 _function_ranges({"blocks": [block]}, ...) 相同：块起点加块内指令范围。
                    ranges[(source, space)].extend(_merge_spans(
                        [(address, address + 1), *cached], identifier))
        for index, record in enumerate(self._rows.get("Functions", ())):
            location = self.location_for_row("Functions", index)
            if location is None:
                continue
            matches = by_entry.get(location, ())
            if matches:
                self._function_cfg[index] = tuple(matches)
                for cfg_index in matches:
                    self._cfg_functions[cfg_index].append(index)
        self._cfg_ranges = {key: _packed_intervals(values) for key, values in ranges.items()}

    def _target(self, table: str, index: int, field: str = "", *,
                location: Location | None = None) -> NavigationTarget:
        location = location or self.location_for_row(table, index, field or None)
        assert location is not None
        record = self._rows[table][index]
        cfgs = self._function_cfg.get(index, ()) if table == "Functions" else ()
        return NavigationTarget(table, index, location, field, str(record.get("name", "")),
                                cfgs[0] if len(cfgs) == 1 else None)

    def find_targets(self, location: Location, *, table: str | None = None
                     ) -> tuple[NavigationTarget, ...]:
        context = (location.source, location.address_space)
        tables = self._points.get(context, {})
        targets = []
        for name, points in tables.items():
            if table is not None and name != table:
                continue
            if type(points) is _XrefPoints:
                for index, field in points.at(location.address):
                    targets.append(self._target(name, index, field, location=location))
                continue
            addresses, records = points
            begin, end = bisect_left(addresses, location.address), bisect_right(addresses, location.address)
            for index, field in records[begin:end]:
                targets.append(self._target(name, index, field, location=location))
            if begin == end and name == "Disassembly" and begin:
                # Walk equal-start records to preserve any duplicate evidence.
                actual = addresses[begin - 1]
                for index, field in records[bisect_left(addresses, actual):begin]:
                    size = _address(self._rows[name][index].get("size")) or 1
                    if actual <= location.address < actual + size:
                        targets.append(self._target(name, index, field))
        if table is None or table == "Strings":
            intervals = self._strings.get(context)
            existing = {(target.table, target.row_index, target.location) for target in targets}
            for identifier in intervals.at(location.address) if intervals else ():
                index, field, string_location = self._string_spans[identifier]
                key = ("Strings", index, string_location)
                if key not in existing:
                    targets.append(self._target("Strings", index, field, location=string_location))
                    existing.add(key)
        if table is None or table == "CFG":
            intervals = self._cfg_ranges.get(context)
            for identifier in intervals.at(location.address) if intervals else ():
                cfg_index, block_index, block_location = self._cfg_blocks[identifier]
                targets.append(NavigationTarget("CFG", block_index, block_location, "start",
                                                str(self._cfgs[cfg_index].get("name", "")), cfg_index))
        return tuple(targets)

    def find_functions(self, location: Location) -> tuple[NavigationTarget, ...]:
        intervals = self._functions.get((location.source, location.address_space))
        matches = set(intervals.at(location.address)) if intervals else set()
        cfg_intervals = self._cfg_ranges.get((location.source, location.address_space))
        for identifier in cfg_intervals.at(location.address) if cfg_intervals else ():
            matches.update(self._cfg_functions.get(self._cfg_blocks[identifier][0], ()))
        return tuple(self._target("Functions", index) for index in sorted(matches))

    def function_at(self, location: Location) -> NavigationTarget | None:
        matches = self.find_functions(location)
        if len(matches) > 1:
            names = ", ".join(item.name or f"行 {item.row_index}" for item in matches)
            raise AmbiguousLocationError(f"该位置属于多个函数（{names}）",
                                         [item.location for item in matches], targets=matches)
        return matches[0] if matches else None

    def locations(self, address: int, *, source: str | None = None,
                  address_space: str | None = None) -> tuple[Location, ...]:
        Location(address)  # 统一边界和类型校验
        space = _space(address_space) if address_space is not None else None
        found = []
        contexts = set(self._points) | set(self._cfg_ranges)
        for context in contexts:
            member, context_space = context
            if source is not None and source != member or space is not None and space != context_space:
                continue
            location = Location(address, member, context_space)
            if (self.find_targets(location) or self.find_functions(location)
                    or context in self._sections and self._sections[context].at(address)):
                found.append(location)
        return tuple(sorted(found, key=lambda item: (item.address_space, item.source, item.address)))

    def resolve(self, query: str | int | Location, *, source: str | None = None,
                address_space: str | None = None) -> Location:
        """解析十进制/0x 地址或精确符号；缺失和歧义都明确抛异常。"""
        if isinstance(query, Location):
            source, address_space, query = query.source, query.address_space, query.address
        if type(query) is int:
            matches = self.locations(query, source=source, address_space=address_space)
        elif isinstance(query, str):
            text = query.strip()
            if re.fullmatch(r"0[xX][0-9a-fA-F]+|[0-9]+", text):
                address = int(text, 16 if text.lower().startswith("0x") else 10)
                matches = self.locations(address, source=source, address_space=address_space)
            else:
                space = _space(address_space) if address_space is not None else None
                matches = tuple(dict.fromkeys(item.location for item in self._symbols.get(text, ())
                    if (source is None or source == item.location.source)
                    and (space is None or space == item.location.address_space)))
        else:
            raise TypeError("导航查询必须是地址、符号字符串或 Location")
        if not matches:
            raise UnknownLocationError(f"未找到地址或符号：{query}")
        if len(matches) != 1:
            raise AmbiguousLocationError("地址或符号存在歧义，请选择容器和地址空间", matches)
        return matches[0]

    def _index_references(self) -> None:
        for index, record in enumerate(self._rows.get("API Calls", ())):
            source = self.location_for_row("API Calls", index)
            if source is None:
                continue
            name = str(record.get("target", ""))
            descriptor = record.get("descriptor", "")
            symbol = name + descriptor if isinstance(descriptor, str) else name
            named = self._symbols.get(symbol, ()) or self._symbols.get(name, ())
            targets = tuple(dict.fromkeys(item.location for item in named
                                         if item.table == "Functions"))
            target = targets[0] if len(targets) == 1 else None
            reference = ReferenceTarget("API Calls", index, source, target,
                                        str(record.get("kind", "direct_call")), name)
            self._outgoing[source].append(reference)
            if target is not None:
                self._incoming[target].append(reference)

    def incoming(self, location: Location) -> tuple[ReferenceTarget, ...]:
        references = list(self._incoming.get(location, ()))
        points = self._xref_points
        if points is not None and location.source == "" and location.address_space == "native":
            # 原实现先索引 Xrefs、后追加 API Calls：同一目标上 Xrefs 引用排在前面。
            references[:0] = self._xref_range(points.dst_addresses, points.dst_rows, location.address)
        seen = {(item.table, item.row_index) for item in references}
        intervals = self._strings.get((location.source, location.address_space))
        for identifier in intervals.at(location.address) if intervals else ():
            for reference in self._string_references.get(identifier, ()):
                identity = (reference.table, reference.row_index)
                if identity not in seen:
                    references.append(reference)
                    seen.add(identity)
        return tuple(references)

    def _index_string_references(self) -> None:
        points = self._xref_points
        if points is not None:
            self._index_compact_string_references(points)
            return
        for destination, references in self._incoming.items():
            intervals = self._strings.get((destination.source, destination.address_space))
            for identifier in intervals.at(destination.address) if intervals else ():
                self._string_references[identifier].extend(references)

    def _index_compact_string_references(self, points: _XrefPoints) -> None:
        """与原实现按 _incoming 插入顺序扩展的结果相同。

        原 _incoming 的目标顺序：先是各 Xrefs 目标按首次出现的行号（只计两个端点都合法的行），
        每个目标先放它的 Xrefs 引用、再放同一位置的 API Calls 引用；之后才是只出现在 API Calls
        中的目标。这里只为落在字符串区间内的目标现造（并缓存）引用对象。
        """
        intervals = self._strings.get(_NATIVE)
        addresses, rows = points.dst_addresses, points.dst_rows
        if intervals is not None and addresses:
            hits = []
            cursor, count = 0, len(addresses)
            while cursor < count:
                address = addresses[cursor]
                following = bisect_right(addresses, address, cursor)
                identifiers = intervals.at(address)
                if identifiers:
                    references = []
                    for row in rows[cursor:following]:
                        reference = self._xref_reference(row)
                        if reference is not None:
                            references.append(reference)
                    if references:
                        hits.append((references[0].row_index, address, identifiers, references))
                cursor = following
            hits.sort(key=lambda item: item[0])  # 各目标首行互不相同
            for _, address, identifiers, references in hits:
                references.extend(self._incoming.get(_trusted_location(address, "", "native"), ()))
                for identifier in identifiers:
                    self._string_references[identifier].extend(references)
        for destination, references in self._incoming.items():
            # 此时 _incoming 只含 API Calls 引用；原生目标若也是 Xrefs 目标，已随上面一起处理。
            if (destination.source == "" and destination.address_space == "native"
                    and points.has_incoming(destination.address)):
                continue
            context = self._strings.get((destination.source, destination.address_space))
            for identifier in context.at(destination.address) if context else ():
                self._string_references[identifier].extend(references)

    def outgoing(self, location: Location) -> tuple[ReferenceTarget, ...]:
        points = self._xref_points
        if points is not None and location.source == "" and location.address_space == "native":
            references = self._xref_range(points.src_addresses, points.src_rows, location.address)
            references.extend(self._outgoing.get(location, ()))
            return tuple(references)
        return tuple(self._outgoing.get(location, ()))
