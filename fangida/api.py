"""Public snapshot API for scripts and embedding; no code sandbox is implied."""
from __future__ import annotations
from bisect import bisect_left
from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping
import json
from . import _json_stream
from .dispatcher import AnalysisService
from .models import AnalysisResult

_BYTECODE_KINDS = frozenset({"apk", "dex", "jar", "class"})


class _UnindexedDisassembly(Exception):
    """快照里有非精确 dict 记录或非 str 的 source：有序索引无法保证与逐次扫描完全一致。"""


class AnalysisView:
    def __init__(self, result: AnalysisResult) -> None:
        self._snapshot = (deepcopy(vars(result)) if type(result) is AnalysisResult and
                          result.stats.get("full_analysis") else deepcopy(result.to_dict()))

    @classmethod
    def from_snapshot(cls, snapshot: Mapping[str, Any]) -> AnalysisView:
        """Create an isolated view of persisted evidence, preserving new fields."""
        return cls._snapshot_view(snapshot, copy_snapshot=True)

    @classmethod
    def _from_owned_snapshot(cls, snapshot: dict[str, Any]) -> AnalysisView:
        """Consume a fresh internal snapshot whose previous owner is finished.

        GUI workers may transfer their newly decoded database graph rather
        than duplicate it. Public constructors and getters still copy data;
        this private path must never borrow an externally owned snapshot.
        """
        if type(snapshot) is not dict:
            raise TypeError("owned snapshot must be a plain dictionary")
        return cls._snapshot_view(snapshot, copy_snapshot=False)

    @classmethod
    def _from_owned_result(cls, result: AnalysisResult) -> AnalysisView:
        """Consume a completed native full result from a private GUI service."""
        if type(result) is AnalysisResult and result.stats.get("full_analysis"):
            return cls._from_owned_snapshot(dict(vars(result)))
        return cls(result)

    @classmethod
    def _snapshot_view(cls, snapshot: Mapping[str, Any], *, copy_snapshot: bool) -> AnalysisView:
        if not isinstance(snapshot, Mapping):
            raise TypeError("snapshot must be a mapping")
        for field in ("path", "kind", "analyzer", "status", "schema_version"):
            if not isinstance(snapshot.get(field), str):
                raise ValueError(f"snapshot requires string field: {field}")
        for field in ("metadata", "stats"):
            if not isinstance(snapshot.get(field, {}), Mapping):
                raise ValueError(f"snapshot field must be a mapping: {field}")
        for field in ("functions", "strings", "imports", "exports", "xrefs", "warnings"):
            if not isinstance(snapshot.get(field, []), list):
                raise ValueError(f"snapshot field must be a list: {field}")
        view = cls.__new__(cls)
        view._snapshot = deepcopy(dict(snapshot)) if copy_snapshot else snapshot
        for field in ("metadata", "stats"):
            view._snapshot.setdefault(field, {})
        for field in ("functions", "strings", "imports", "exports", "xrefs", "warnings"):
            view._snapshot.setdefault(field, [])
        return view

    def snapshot(self) -> dict[str, Any]:
        return deepcopy(self._snapshot)

    def functions(self) -> list[dict[str, Any]]:
        return deepcopy(self._snapshot["functions"])

    def strings(self) -> list[dict[str, Any]]:
        return deepcopy(self._snapshot["strings"])

    def xrefs(self, address: int | None = None, *, source: str | None = None,
              address_space: str | None = None) -> list[dict[str, Any]]:
        xrefs = self._snapshot["xrefs"]
        def matches(entry):
            for side in ("src", "dst"):
                if address is not None and entry.get(side) != address:
                    continue
                if source is not None and entry.get(side + "_source", entry.get("source")) != source:
                    continue
                if address_space is not None and entry.get(side + "_address_space", entry.get("address_space")) != address_space:
                    continue
                return True
            return False
        return deepcopy([entry for entry in xrefs if matches(entry)])

    def microcode(self, address: int, offset: int = 0, limit: int = 100, *,
                  source: str | None = None, address_space: str | None = None,
                  category: str | None = None) -> dict[str, Any]:
        """Read a page of persisted semantic IR without decoding the source."""
        from .plugins.pseudoc.snapshot import microcode_page
        return microcode_page(self._snapshot, address, offset=offset, limit=limit,
                              source=source, address_space=address_space, category=category)

    def microcode_facts(self, address: int, offset: int = 0, limit: int = 100, *,
                        source: str | None = None, address_space: str | None = None,
                        kind: str | None = None) -> dict[str, Any]:
        from .plugins.pseudoc.snapshot import microcode_facts_page
        return microcode_facts_page(self._snapshot, address, offset=offset, limit=limit,
                                   source=source, address_space=address_space, kind=kind)

    def disassembly(self, start: int, limit: int = 100) -> list[dict[str, Any]]:
        if type(start) is not int or start < 0:
            raise ValueError("start must be a non-negative integer")
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        index = self._disassembly_index()
        if index is None:
            return self._scan_disassembly(start, limit)
        addresses, instructions, sources = index
        first = bisect_left(addresses, start)
        # slice.indices 与原先的 records[:limit] 做同样的类型检查与截断（如浮点 limit 抛 TypeError）。
        count = slice(None, limit).indices(len(addresses) - first)[1]
        records: list[dict[str, Any]] = []
        for position in range(first, first + count):
            # 与逐次扫描相同：先浅复制原记录，再补上所属方法的 source。
            record = dict(instructions[position])
            source = sources[position]
            if source and "source" not in record:
                record["source"] = source
            records.append(record)
        return deepcopy(records)

    def _disassembly_index(self) -> tuple[list[int], list[dict[str, Any]], list[str]] | None:
        """惰性构建一次全部指令的有序只读索引；None 表示需逐次扫描。

        视图快照在构造后不再被修改（公开方法都返回副本，私有接管路径的原持有者也已
        结束使用），因此索引可以一直复用；翻页只需二分定位起点并复制 limit 条记录。
        """
        index = getattr(self, "_disassembly_cache", None)
        if index is None:
            try:
                index = self._build_disassembly_index()
            except _UnindexedDisassembly:
                index = False
            # 并发首次调用最多重复构建一次，结果相同；属性赋值本身是原子的。
            self._disassembly_cache = index
        return index or None

    def _build_disassembly_index(self) -> tuple[list[int], list[dict[str, Any]], list[str]]:
        # 与 _scan_disassembly(0, ...) 的收集顺序、去重键和排序键逐项一致；start>0 的
        # 结果正是其中地址 >= start 的后缀（去重键含地址，过滤不会改变哪条记录胜出）。
        indexed: dict[tuple[str, int], tuple[dict[str, Any], str]] = {}

        def collect(records: Any, source: str = "") -> None:
            if not isinstance(records, list):
                return
            for instruction in records:
                if not isinstance(instruction, dict):
                    continue
                address = instruction.get("addr", instruction.get("address", instruction.get("offset")))
                if type(address) is not int or address < 0:
                    continue
                if type(instruction) is not dict:
                    raise _UnindexedDisassembly
                if "source" in instruction:
                    own = instruction["source"]
                    if type(own) is not str:
                        raise _UnindexedDisassembly
                    key = own
                else:
                    key = source
                indexed[(key, address)] = (instruction, source)
        collect(self._snapshot["metadata"].get("disassembly"))
        collect(self._snapshot["metadata"].get("full_disassembly"))
        for function in self._snapshot["functions"]:
            if not isinstance(function, dict):
                continue
            source = str(function.get("source", "")) if self._snapshot["kind"] in _BYTECODE_KINDS else ""
            collect(function.get("disassembly"), source)
            for block in function.get("blocks", []):
                if isinstance(block, dict):
                    collect(block.get("instructions"), source)
        ordered = sorted(indexed, key=lambda key: (key[1], key[0]))
        entries = [indexed[key] for key in ordered]
        return ([key[1] for key in ordered], [entry[0] for entry in entries],
                [entry[1] for entry in entries])

    def _scan_disassembly(self, start: int, limit: int) -> list[dict[str, Any]]:
        # The entry window is only a preview; semantic blocks may cover many
        # more functions. Prefer their richer records when addresses overlap.
        indexed: dict[tuple[str, int], dict[str, Any]] = {}
        def collect(records: Any, source: str = "") -> None:
            if not isinstance(records, list):
                return
            for instruction in records:
                if not isinstance(instruction, dict):
                    continue
                address = instruction.get("addr", instruction.get("address", instruction.get("offset")))
                if type(address) is not int or address < start:
                    continue
                record = dict(instruction)
                if source and "source" not in record:
                    record["source"] = source
                indexed[(str(record.get("source", "")), address)] = record
        collect(self._snapshot["metadata"].get("disassembly"))
        collect(self._snapshot["metadata"].get("full_disassembly"))
        for function in self._snapshot["functions"]:
            if not isinstance(function, dict):
                continue
            source = str(function.get("source", "")) if self._snapshot["kind"] in {"apk", "dex", "jar", "class"} else ""
            collect(function.get("disassembly"), source)
            for block in function.get("blocks", []):
                if isinstance(block, dict):
                    collect(block.get("instructions"), source)
        records = sorted(indexed.values(), key=lambda item: (int(item.get("addr", item.get("address", item.get("offset", 0)))), str(item.get("source", ""))))
        return deepcopy(records[:limit])

    def export_json(self, destination: str | Path) -> Path:
        path = Path(destination).expanduser().resolve()
        payload = _indented_json(self._snapshot) + "\n"
        path.write_text(payload, encoding="utf-8")
        return path


def _indented_json(value: Any) -> str:
    """等价于 json.dumps(value, indent=2, ensure_ascii=False)，先完整生成字符串再由调用方写入。

    3.11/3.12 的 C 编码器不支持 indent，json.dumps 会退回逐 token 的纯 Python 生成器；
    此时改用分块编码器生成同一段文本。3.13+ 保持 json.dumps 不变。
    """
    return _json_stream.dumps(value, indent=2, ensure_ascii=False)


def _shared_snapshot(view: AnalysisView) -> dict[str, Any]:
    """包内只读调用方（CLI 导出、终端浏览）使用的快照，调用方不得修改返回值。

    未覆写 snapshot() 的视图直接返回内部快照（其内容与 snapshot() 的深拷贝相同），
    省去一次整图复制；子类、替身或其他对象仍走各自的 snapshot()。
    """
    if isinstance(view, AnalysisView) and getattr(type(view), "snapshot", None) is AnalysisView.snapshot:
        snapshot = getattr(view, "_snapshot", None)
        if snapshot is not None:
            return snapshot
    return view.snapshot()


def open_file(path: str | Path, service: AnalysisService | None = None,
              full_analysis: bool | None = None) -> AnalysisView:
    options = {} if full_analysis is None else {"full_analysis": full_analysis}
    if service is not None:
        return AnalysisView(service.analyze(path, **options))
    with AnalysisService() as temporary:
        return AnalysisView(temporary.analyze(path, **options))


def open_database(path: str | Path, snapshot_id: int | None = None, *,
                  manager=None, storage_plugin: str = "sqlite_storage") -> AnalysisView:
    """Open saved analysis without the source binary or any new analysis."""
    from .storage import database_session
    with database_session(path, manager=manager, storage_plugin=storage_plugin) as database:
        snapshot = database.get_snapshot(snapshot_id)
        # 只有明确声明 fresh_snapshots 为 True 的提供者（内置 SQLite 存储：每次返回全新且
        # 不再被引用的对象图）才直接接管，省去一次整图深拷贝；`is True` 排除 Mock 等替身。
        # 其他提供者可能在 close() 时清空或事后复用快照，仍按原约定复制。
        if type(snapshot) is dict and getattr(database, "fresh_snapshots", False) is True:
            return AnalysisView._from_owned_snapshot(snapshot)
        return AnalysisView.from_snapshot(snapshot)
