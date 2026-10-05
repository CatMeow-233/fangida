"""分析数据库工具：打开/创建、关闭、历史、分页、注释，以及保存结果与持久化注释。

每个方法对应 McpServer.call_tool 分派表中的一个或一组工具名；参数校验顺序、错误文本、
返回结构与写权限检查和拆分前逐字一致。异常由 call_tool 统一转换为工具错误。
"""
from __future__ import annotations

from typing import Any

from . import _facade


class DatabaseToolsMixin:
    """数据库句柄相关工具；依赖宿主 McpServer 的会话状态与 _database/_pagination 等方法。"""

    def _tool_open_database(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        # open_database 与 create_database 共用；创建时总是可写。
        return _facade()._result(self._open_database(arguments.get("path"),
            create=name == "create_database",
            read_only=False if name == "create_database" else arguments.get("read_only", True)))

    def _tool_close_database(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        store = self._database(arguments)
        store.close()
        del self._databases[arguments["database"]]
        return _facade()._result({"closed": True})

    def _tool_database_history(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        store = self._database(arguments)
        offset, limit = self._pagination(arguments)
        path = arguments.get("path")
        if path is not None and (not isinstance(path, str) or not path):
            raise ValueError("path must be a non-empty string")
        return _facade()._result(store.history(path, offset=offset, limit=limit))

    def _tool_database_page(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        m = _facade()
        store = self._database(arguments)
        offset, limit = self._pagination(arguments)
        include_details = arguments.get("include_details", True)
        if type(include_details) is not bool:
            raise ValueError("include_details must be boolean")
        collection = arguments.get("collection")
        page = store.page(arguments.get("snapshot_id"), collection, offset=offset, limit=limit)
        if not include_details and collection == "functions":
            # 存储页不保证携带 kind；函数自身的 code_offset/kind/空间元数据足以
            # 区分现有字节码记录。没有这些标记的记录按既有原生摘要规则投影。
            # 绝不为概要恢复整个快照，也不改写存储提供者持有的页面。
            kind = page.get("kind", "")
            kind = kind if isinstance(kind, str) else ""
            page = {**page, "items": [m._function_summary(item, kind) for item in page["items"]]}
        return m._result(page)

    def _tool_database_annotations(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        m = _facade()
        store = self._database(arguments)
        annotations = store.annotations(arguments.get("snapshot_id"))
        offset, limit = self._pagination(arguments)
        items = [{"address": address, "kind": kind, "value": value}
                 for kind, field in (("rename", "renames"), ("comment", "comments"))
                 for address, value in annotations[field].items()]
        items.sort(key=lambda item: (item["address"], item["kind"]))
        return m._result({"sha256": annotations["sha256"], **m._page(items, offset, limit)})

    def _tool_open_database_snapshot(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        m = _facade()
        store = self._database(arguments)
        if len(self._snapshots) >= m.MAX_OPEN_FILES:
            raise ValueError(f"session is limited to {m.MAX_OPEN_FILES} open files")
        snapshot = store.get_snapshot(arguments.get("snapshot_id"))
        handle = m.uuid4().hex
        self._snapshots[handle] = snapshot
        snapshot_id = snapshot.get("metadata", {}).get("analysis_database", {}).get("snapshot_id")
        return m._result({"handle": handle, "database": arguments["database"],
                          "snapshot_id": snapshot_id, "path": snapshot.get("path"),
                          "kind": snapshot.get("kind"), "status": snapshot.get("status")})

    def _tool_save_to_database(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        m = _facade()
        store = self._database(arguments)
        if not self.allow_writes:
            return m._tool_error("Persistent database writes are disabled")
        snapshot = self._snapshot(arguments)
        path = snapshot.get("path")
        if not isinstance(path, str) or not path:
            raise ValueError("snapshot has no source path")
        provenance = self._snapshot_sources.get(arguments.get("handle"))
        if provenance is not None and self._source_signature(provenance[0]) != provenance[1]:
            raise ValueError("Source changed after analysis; analyze the current source before saving")
        metadata = snapshot.get("metadata", {})
        expected_hash = metadata.get("analysis_database", {}).get("source_sha256") or metadata.get("source_sha256")
        if expected_hash is None:
            if provenance is None:
                raise ValueError("Snapshot has no verified source identity; reopen the source before saving")
            expected_hash, _ = m.fingerprint(path)
            if self._source_signature(provenance[0]) != provenance[1]:
                raise ValueError("Source changed while preparing the database save")
        try:
            snapshot_id = store.save_analysis(path, snapshot, expected_hash=expected_hash)
        finally:
            # 存储插件拿到的是会话快照本身；保守失效，防止插件原地改写后索引过期。
            self._instruction_indexes.pop(arguments["handle"], None)
        return m._result({"saved": True, "snapshot_id": snapshot_id,
                          "path": path, "scope": "analysis_database"})

    def _tool_database_annotate(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        # database_rename_symbol 与 database_set_comment 共用：先校验句柄，再检查写权限。
        m = _facade()
        store = self._database(arguments)
        if not self.allow_writes:
            return m._tool_error("Persistent database writes are disabled")
        address = m._address(arguments.get("address"))
        snapshot_id = arguments.get("snapshot_id")
        if name == "database_rename_symbol":
            store.rename_symbol(snapshot_id, address, arguments.get("name"))
            return m._result({"saved": True, "kind": "rename", "address": address,
                              "scope": "database_annotation"})
        store.set_comment(snapshot_id, address, arguments.get("text"))
        return m._result({"saved": True, "kind": "comment", "address": address,
                          "scope": "database_annotation"})
