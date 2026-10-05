"""项目数据库工具：打开/创建、关闭、历史、分页、快照载入、注释，以及分析入库与持久化注释。

每个方法对应 McpServer.call_tool 分派表中的一个或一组工具名；参数校验顺序、错误文本、
返回结构与写权限检查和拆分前逐字一致。异常由 call_tool 统一转换为工具错误。
"""
from __future__ import annotations

from typing import Any

from . import _facade


class ProjectToolsMixin:
    """项目句柄相关工具；依赖宿主 McpServer 的会话状态与 _project/_pagination 等方法。"""

    def _tool_open_project(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        # open_project 与 create_project 共用；创建先检查写权限。
        m = _facade()
        if name == "create_project" and not self.allow_writes:
            return m._tool_error("Persistent project writes are disabled")
        return m._result(self._open_project(arguments.get("path"),
                                            create=name == "create_project"))

    def _tool_close_project(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self._project(arguments)
        del self._projects[arguments["project"]]
        return _facade()._result({"closed": True})

    def _tool_project_history(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        store = self._project(arguments)
        offset, limit = self._pagination(arguments)
        path = arguments.get("path")
        if path is not None and (not isinstance(path, str) or not path):
            raise ValueError("path must be a non-empty string")
        return _facade()._result(store.history(path, offset=offset, limit=limit))

    def _tool_project_page(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        store = self._project(arguments)
        offset, limit = self._pagination(arguments)
        return _facade()._result(store.page(arguments.get("snapshot_id"),
                                            arguments.get("collection"),
                                            offset=offset, limit=limit))

    def _tool_open_project_snapshot(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        m = _facade()
        store = self._project(arguments)
        if len(self._snapshots) >= m.MAX_OPEN_FILES:
            raise ValueError(f"session is limited to {m.MAX_OPEN_FILES} open files")
        snapshot_id = arguments.get("snapshot_id")
        snapshot = store.get_snapshot(snapshot_id)
        handle = m.uuid4().hex
        self._snapshots[handle] = snapshot
        return m._result({"handle": handle, "snapshot_id": snapshot_id,
                          "path": snapshot.get("path"), "kind": snapshot.get("kind"),
                          "status": snapshot.get("status")})

    def _tool_project_annotations(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        m = _facade()
        store = self._project(arguments)
        path = arguments.get("path")
        if not isinstance(path, str) or not path:
            raise ValueError("path must be a non-empty string")
        annotations = store.annotations(path)
        offset, limit = self._pagination(arguments)
        items = [{"address": address, "kind": kind, "value": value}
                 for kind, field in (("rename", "renames"), ("comment", "comments"))
                 for address, value in annotations[field].items()]
        items.sort(key=lambda item: (item["address"], item["kind"]))
        return m._result({"sha256": annotations["sha256"], **m._page(items, offset, limit)})

    def _tool_analyze_to_project(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        m = _facade()
        store = self._project(arguments)
        if not self.allow_writes:
            return m._tool_error("Persistent project writes are disabled")
        path = arguments.get("path")
        if not isinstance(path, str) or not path:
            raise ValueError("path must be a non-empty string")
        full_analysis = arguments.get("full_analysis")
        full = self.settings.full_analysis if full_analysis is None else full_analysis
        max_bytes = arguments.get("max_bytes", None if full else self.settings.max_bytes)
        if max_bytes is not None and (type(max_bytes) is not int or not 1 <= max_bytes <= m.MAX_SCAN_BYTES):
            raise ValueError(f"max_bytes must be between 1 and {m.MAX_SCAN_BYTES}")
        use_ghidra = arguments.get("use_ghidra")
        deep_analysis = arguments.get("deep_analysis")
        if any(value is not None and type(value) is not bool
               for value in (use_ghidra, deep_analysis, full_analysis)):
            raise ValueError("use_ghidra, deep_analysis and full_analysis must be boolean")
        expected_hash, _ = m.fingerprint(path)
        options = {} if full_analysis is None else {"full_analysis": full_analysis}
        result = self.service.analyze(path, max_bytes=max_bytes,
                                      use_ghidra=use_ghidra,
                                      deep_analysis=deep_analysis, **options)
        if result.status == "error":
            return m._tool_error("Analysis failed: " + "; ".join(result.warnings))
        snapshot_id = store.save_analysis(path, result, expected_hash=expected_hash)
        return m._result({"snapshot_id": snapshot_id, "path": result.path,
                          "kind": result.kind, "status": result.status,
                          "warnings": result.warnings})

    def _tool_project_annotate(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        # project_rename_symbol 与 project_set_comment 共用：句柄、写权限、路径依次校验。
        m = _facade()
        store = self._project(arguments)
        if not self.allow_writes:
            return m._tool_error("Persistent project writes are disabled")
        path = arguments.get("path")
        if not isinstance(path, str) or not path:
            raise ValueError("path must be a non-empty string")
        address = m._address(arguments.get("address"))
        if name == "project_rename_symbol":
            store.rename_symbol(path, address, arguments.get("name"))
            return m._result({"saved": True, "kind": "rename", "address": address,
                              "scope": "project_annotation"})
        store.set_comment(path, address, arguments.get("text"))
        return m._result({"saved": True, "kind": "comment", "address": address,
                          "scope": "project_annotation"})
