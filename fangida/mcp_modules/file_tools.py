"""会话结果工具：open_file，以及基于结果句柄的函数、摘要、反汇编、CFG、xref、导出与改名。

每个方法对应 McpServer.call_tool 分派表中的一个工具名；参数校验顺序、错误文本、
返回结构与写权限检查和拆分前逐字一致。异常由 call_tool 统一转换为工具错误。
"""
from __future__ import annotations

import re
from typing import Any

from . import _facade


class FileToolsMixin:
    """结果句柄相关工具；依赖宿主 McpServer 的会话状态与 _snapshot/_pagination 等方法。"""

    def _tool_open_file(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        m = _facade()
        full_analysis = arguments.get("full_analysis")
        if full_analysis is not None and type(full_analysis) is not bool:
            raise ValueError("full_analysis must be boolean")
        full = self.settings.full_analysis if full_analysis is None else full_analysis
        path, max_bytes = arguments.get("path"), arguments.get("max_bytes", None if full else self.settings.max_bytes)
        if not isinstance(path, str) or not path:
            raise ValueError("path must be a non-empty string")
        if max_bytes is not None and (type(max_bytes) is not int or
                not 1 <= max_bytes <= m.MAX_SCAN_BYTES):
            raise ValueError(f"max_bytes must be between 1 and {m.MAX_SCAN_BYTES}")
        if len(self._snapshots) >= m.MAX_OPEN_FILES:
            raise ValueError(f"session is limited to {m.MAX_OPEN_FILES} open files")
        use_ghidra = arguments.get("use_ghidra")
        if use_ghidra is not None and type(use_ghidra) is not bool:
            raise ValueError("use_ghidra must be boolean")
        deep_analysis = arguments.get("deep_analysis")
        if deep_analysis is not None and type(deep_analysis) is not bool:
            raise ValueError("deep_analysis must be boolean")
        options = {} if full_analysis is None else {"full_analysis": full_analysis}
        source_path = str(m.Path(path).expanduser().resolve())
        try:
            source_signature = self._source_signature(source_path)
        except OSError:
            # Keep old duck-typed analysis services usable; only saving
            # to a database requires independently verified identity.
            source_signature = None
        analyzed = self.service.analyze(m.Path(path), max_bytes=max_bytes,
                                        use_ghidra=use_ghidra,
                                        deep_analysis=deep_analysis, **options)
        if (self.own_completed_results and type(analyzed) is m.AnalysisResult and
                analyzed.kind in {"elf", "pe", "macho"} and
                analyzed.stats.get("full_analysis") is True and analyzed.status != "error"):
            # 独立 stdio 服务接管已经完成的私有结果；只建立顶层字典，
            # IR/CFG 继续共用原指令记录。没有此显式约定时仍走旧副本路径。
            snapshot = dict(vars(analyzed))
        else:
            snapshot = (m.deepcopy(vars(analyzed)) if type(analyzed) is m.AnalysisResult and
                        analyzed.stats.get("full_analysis") else m.AnalysisView(analyzed).snapshot())
        if snapshot["status"] == "error":
            return m._tool_error("Analysis failed: " + "; ".join(snapshot.get("warnings", [])))
        handle = m.uuid4().hex
        self._snapshots[handle] = snapshot
        if source_signature is not None:
            try:
                unchanged = self._source_signature(source_path) == source_signature
            except OSError:
                unchanged = False
            if unchanged:
                self._snapshot_sources[handle] = (source_path, source_signature)
        return m._result({"handle": handle, "path": snapshot["path"], "kind": snapshot["kind"],
                          "status": snapshot["status"], "warnings": snapshot.get("warnings", [])})

    def _tool_close_file(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self._snapshot(arguments)
        del self._snapshots[arguments["handle"]]
        self._snapshot_sources.pop(arguments["handle"], None)
        self._instruction_indexes.pop(arguments["handle"], None)
        getattr(self, "_pseudoc_contexts", {}).pop(arguments["handle"], None)
        return _facade()._result({"closed": True})

    def _tool_list_functions(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        m = _facade()
        snapshot = self._snapshot(arguments)
        offset, limit = self._pagination(arguments)
        include_details = arguments.get("include_details", True)
        if type(include_details) is not bool:
            raise ValueError("include_details must be boolean")
        functions = snapshot.get("functions", [])
        page = m._page(functions, offset, limit)
        if not include_details:
            page["items"] = [m._function_summary(item, snapshot.get("kind", "")) for item in page["items"]]
        return m._result({"available": bool(functions), **page,
                          "status": snapshot["status"]})

    def _tool_analysis_summary(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        m = _facade()
        snapshot = self._snapshot(arguments)
        return m._result(m._analysis_summary(snapshot))

    def _tool_get_disasm(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        m = _facade()
        snapshot = self._snapshot(arguments)
        offset, limit = self._pagination(arguments)
        start = m._address(arguments["address"]) if "address" in arguments else None
        index = self._instruction_index(arguments["handle"], snapshot)
        if not index.view.entries:
            return m._tool_error("Disassembly is unavailable for this analysis result")
        source = arguments.get("source")
        view = index.view
        if source is not None:
            if not isinstance(source, str):
                raise ValueError("source must be a string")
            view = index.source_view(source)
        return m._result({"available": True, **view.page(start, offset, limit)})

    def _tool_get_cfg(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        m = _facade()
        snapshot = self._snapshot(arguments)
        offset, limit = self._pagination(arguments)
        return m._result(m._cfg_page(snapshot, arguments, offset, limit))

    def _tool_xref_query(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        m = _facade()
        snapshot = self._snapshot(arguments)
        offset, limit = self._pagination(arguments)
        address = m._address(arguments.get("address"))
        direction = arguments.get("direction", "both")
        if direction not in ("to", "from", "both"):
            raise ValueError("direction must be to, from, or both")
        xrefs = snapshot.get("xrefs", [])
        if not xrefs:
            return m._tool_error("Cross-reference analysis is unavailable for this result")
        source, address_space = arguments.get("source"), arguments.get("address_space")
        for field, value in (("source", source), ("address_space", address_space)):
            if value is not None and not isinstance(value, str):
                raise ValueError(field + " must be a string")
        def matches(item):
            return isinstance(item, dict) and any(
                direction in (alias, "both") and m._record_address(item, side, alias) == address and
                (source is None or item.get(side + "_source", item.get("source")) == source) and
                (address_space is None or item.get(side + "_address_space", item.get("address_space")) == address_space)
                for side, alias in (("dst", "to"), ("src", "from")))
        matching = [item for item in xrefs if matches(item)]
        return m._result({"available": True, "address": address, "direction": direction,
                          **m._page(matching, offset, limit)})

    def _tool_list_api_calls(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        m = _facade()
        snapshot = self._snapshot(arguments)
        offset, limit = self._pagination(arguments)
        calls = snapshot.get("metadata", {}).get("api_calls", [])
        if not isinstance(calls, list) or not calls:
            return m._tool_error("Direct API call evidence is unavailable for this result")
        return m._result({"available": True, **m._page(calls, offset, limit)})

    def _tool_export_result(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        m = _facade()
        snapshot = self._snapshot(arguments)
        offset, limit = self._pagination(arguments)
        exported = {key: value for key, value in snapshot.items()
                    if key not in ("functions", "strings", "imports", "exports", "xrefs", "instructions")}
        exported["pages"] = {key: m._page(snapshot[key], offset, limit)
                             for key in ("functions", "strings", "imports", "exports", "xrefs", "instructions")
                             if isinstance(snapshot.get(key), list)}
        if isinstance(exported.get("metadata", {}).get("api_calls"), list):
            exported["metadata"] = {**exported["metadata"],
                                    "api_calls": m._page(exported["metadata"]["api_calls"], offset, limit)}
        if isinstance(exported.get("metadata", {}).get("disassembly"), list):
            exported["metadata"] = {**exported["metadata"],
                                    "disassembly": m._page(exported["metadata"]["disassembly"], offset, limit)}
        ghidra = exported.get("metadata", {}).get("ghidra")
        if isinstance(ghidra, dict) and isinstance(ghidra.get("pcode"), list):
            exported["metadata"]["ghidra"] = {**ghidra, "pcode": m._page(ghidra["pcode"], offset, limit)}
        return m._result(exported)

    def _tool_rename_symbol(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        m = _facade()
        snapshot = self._snapshot(arguments)
        if not self.allow_writes:
            # 未开启写入时与未登记的工具一样：先校验句柄，再报告不可用。
            return m._tool_error("Tool unavailable")
        address = m._address(arguments.get("address"))
        new_name = arguments.get("name")
        if not isinstance(new_name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]{0,255}", new_name):
            raise ValueError("name must be a valid identifier of at most 256 characters")
        for function in snapshot.get("functions", []):
            if isinstance(function, dict) and m._record_address(function, "address", "start", "addr") == address:
                old_name = function.get("name")
                function["name"] = new_name
                # 会话快照被原地改写，按约定失效该句柄的派生索引。
                self._instruction_indexes.pop(arguments["handle"], None)
                return m._result({"address": address, "old_name": old_name, "name": new_name,
                                  "scope": "session_snapshot"})
        return m._tool_error(f"No identified function starts at address {address:#x}")

    def _tool_unavailable(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        # 旧实现对未登记的名字同样先校验结果句柄，句柄有效时才报告工具不可用。
        self._snapshot(arguments)
        return _facade()._tool_error("Tool unavailable")
