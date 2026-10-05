"""已完成结果的只读指令索引：一次排序去重，翻页与按 source 过滤复用，不调用解码器。

_instruction_entries 等名字在调用时经 _facade() 向门面查找，门面上的补丁（例如
测试统计索引构建次数）照旧生效。
"""
from __future__ import annotations

from typing import Any

from . import _facade


def _entry_source(entry: Any, default: Any) -> Any:
    # 延迟副本 (function, item) 的 source 恒取自函数，与旧实现复制出的字典一致。
    if type(entry) is tuple:
        return entry[0].get("source", "")
    return entry.get("source", default)


def _entry_record(entry: Any) -> dict[str, Any]:
    # 函数级缺少 source 的指令在输出时才复制：每次响应仍是新字典，且反映原记录的当前内容。
    if type(entry) is tuple:
        function, item = entry
        return {"source": function.get("source", ""), **item}
    return entry


def _instruction_entries(snapshot: dict[str, Any]) -> tuple[list[Any], list[int]]:
    """按 (source, address) 排序去重，返回条目与对应地址；_instructions 与分页索引共用。

    条目是原指令字典，或函数级缺少 source 时的 (function, item) 延迟副本。
    """
    m = _facade()
    records: list[Any] = []
    metadata = snapshot.get("metadata", {})
    for source in (snapshot.get("instructions"), metadata.get("disassembly"),
                   metadata.get("full_disassembly"), metadata.get("instructions")):
        if isinstance(source, list):
            records.extend(item for item in source if isinstance(item, dict))
    for function in snapshot.get("functions", []):
        if not isinstance(function, dict):
            continue
        for field in ("instructions", "disassembly"):
            if isinstance(function.get(field), list):
                records.extend(((function, item) if "source" not in item else item)
                               for item in function[field] if isinstance(item, dict))
        for block in function.get("blocks", []):
            if isinstance(block, dict) and isinstance(block.get("instructions"), list):
                records.extend(item for item in block["instructions"] if isinstance(item, dict))
    by_address: dict[tuple[str, int], Any] = {}
    for entry in records:
        address = m._record_address(entry[1] if type(entry) is tuple else entry,
                                    "address", "addr", "offset")
        if address is not None:
            by_address[(str(m._entry_source(entry, "")), address)] = entry
    ordered = sorted(by_address.items())
    return [entry for _, entry in ordered], [key[1] for key, _ in ordered]


def _instructions(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    m = _facade()
    entries, _ = m._instruction_entries(snapshot)
    return [m._entry_record(entry) for entry in entries]


# dict.get(key, []) 每次返回新列表，无法按身份比较，签名里用此哨兵表示"键不存在"。
_ABSENT = object()


def _instruction_watch(snapshot: Any) -> tuple[list[Any], list[int]] | None:
    """列出 _instruction_entries 读取的全部容器（按身份）及列表长度，作为索引有效性签名。

    只接受普通 dict/list 结构；遇到子类、元组或 None 等非常规容器返回 None，调用方改走
    不缓存路径，从而原样保留旧语义与异常。逐条指令记录不进签名：会话内没有原地改写
    记录地址或 source 的路径，而逐条检查会让每次翻页重新退化为 O(指令数)。
    """
    if type(snapshot) is not dict:
        return None
    # 哨兵同样经门面取得（与本模块的 _ABSENT 是同一对象），函数体保持与拆分前一致。
    _ABSENT = _facade()._ABSENT
    metadata =snapshot.get("metadata", _ABSENT)
    functions = snapshot.get("functions", _ABSENT)
    fields = {} if metadata is _ABSENT else metadata
    if type(fields) is not dict or (functions is not _ABSENT and type(functions) is not list):
        return None
    watched = [snapshot.get("instructions"), metadata, fields.get("disassembly"),
               fields.get("full_disassembly"), fields.get("instructions"), functions]
    for function in () if functions is _ABSENT else functions:
        watched.append(function)
        if not isinstance(function, dict):
            continue
        if type(function) is not dict:
            return None
        blocks = function.get("blocks", _ABSENT)
        watched += (function.get("instructions"), function.get("disassembly"),
                    function.get("source", _ABSENT), blocks)
        if blocks is _ABSENT:
            continue
        if type(blocks) is not list:
            return None
        for block in blocks:
            watched.append(block)
            if isinstance(block, dict):
                if type(block) is not dict:
                    return None
                watched.append(block.get("instructions"))
    return watched, [len(value) for value in watched if isinstance(value, list)]


class _InstructionView:
    """只读的有序指令条目；runs 是地址不降的连续区间，起始地址过滤可逐区间二分。"""

    __slots__ = ("entries", "addresses", "runs")

    def __init__(self, entries: list[Any], addresses: list[int]) -> None:
        self.entries, self.addresses = entries, addresses
        # 不同 source 之间地址会回落；每个区间内 ">= start" 的条目恰好是一个后缀。
        bounds = [0, *(index for index, (previous, current)
                       in enumerate(zip(addresses, addresses[1:]), 1) if current < previous),
                  len(addresses)]
        self.runs = list(zip(bounds, bounds[1:])) if addresses else []

    def page(self, start: int | None, offset: int, limit: int) -> dict[str, Any]:
        """等价于旧实现先按地址过滤整表再 _page，但只取出当前页。"""
        m = _facade()
        if start is None:
            selected, total = self.entries[offset:offset + limit], len(self.entries)
        else:
            tails = [(first, high) for low, high in self.runs
                     if (first := m.bisect_left(self.addresses, start, low, high)) < high]
            total = sum(high - first for first, high in tails)
            selected, skip = [], offset
            for first, high in tails:
                if skip >= high - first:
                    skip -= high - first
                    continue
                selected.extend(self.entries[first + skip:min(high, first + skip + limit - len(selected))])
                skip = 0
                if len(selected) >= limit:
                    break
        following = offset + len(selected)
        return {"items": [m._entry_record(entry) for entry in selected], "total": total,
                "next_offset": following if following < total else None}


_EMPTY_VIEW = _InstructionView([], [])


class _InstructionIndex:
    """一个已打开结果的只读指令索引：排序只做一次，翻页和按 source 过滤复用。"""

    __slots__ = ("snapshot", "watched", "lengths", "view", "_by_source")

    def __init__(self, snapshot: dict[str, Any], watch: tuple[list[Any], list[int]] | None) -> None:
        m = _facade()
        entries, addresses = m._instruction_entries(snapshot)
        self.snapshot = snapshot
        # 强引用签名中的对象，缓存存活期间它们的身份不可能被新对象复用，is 比较才可靠。
        self.watched, self.lengths = watch if watch is not None else ([], [])
        self.view = m._InstructionView(entries, addresses)
        self._by_source: dict[str, _InstructionView] | bool | None = None

    def current(self, snapshot: dict[str, Any], watch: tuple[list[Any], list[int]] | None) -> bool:
        return (watch is not None and self.snapshot is snapshot and
                len(watch[0]) == len(self.watched) and watch[1] == self.lengths and
                all(map(_facade().is_, watch[0], self.watched)))

    def source_view(self, source: str) -> _InstructionView:
        m = _facade()
        if self._by_source is None:
            self._by_source = self._group_sources()
        if self._by_source is False or type(source) is not str:
            # 罕见情形（记录 source 不是 str/None，或查询是 str 子类）：逐条用 == 比较，与旧实现一致。
            matched = [(entry, address) for entry, address in zip(self.view.entries, self.view.addresses)
                       if m._entry_source(entry, None) == source]
            return m._InstructionView([entry for entry, _ in matched], [address for _, address in matched])
        return self._by_source.get(source, m._EMPTY_VIEW)

    def _group_sources(self) -> dict[str, _InstructionView] | bool:
        m = _facade()
        # source 缺失（None）的记录不会等于任何 str 查询；其它非 str 值交给逐条比较。
        grouped: dict[str, tuple[list[Any], list[int]]] = {}
        for entry, address in zip(self.view.entries, self.view.addresses):
            raw = m._entry_source(entry, None)
            if raw is None:
                continue
            if type(raw) is not str:
                return False
            bucket = grouped.setdefault(raw, ([], []))
            bucket[0].append(entry)
            bucket[1].append(address)
        return {source: m._InstructionView(*bucket) for source, bucket in grouped.items()}
