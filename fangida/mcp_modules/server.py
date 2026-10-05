"""MCP 会话状态与 JSON-RPC 分派；各工具实现按领域放在 *_tools 混入模块。

call_tool 按工具名查表分派到处理方法，统一把可预期异常转换为模型可见的工具错误。
未登记的名字与拆分前一样先校验结果句柄，再报告 "Tool unavailable"。
"""
from __future__ import annotations

from pathlib import Path
import sqlite3
from typing import Any

# Path、ProjectStore、Settings、_InstructionIndex 在此仅用于注解（保持 get_type_hints 可解析）；
# 运行时一律经门面查找，补丁 fangida.mcp_server 上的同名对象即可生效。
from ..project import ProjectStore
from ..settings import Settings
from . import _facade
from .database_tools import DatabaseToolsMixin
from .file_tools import FileToolsMixin
from .instruction_index import _InstructionIndex
from .project_tools import ProjectToolsMixin
from .pseudoc_tools import PseudocToolsMixin

# 工具名 -> 处理方法名；同组工具共用一个方法时，方法按 name 区分具体行为。
_TOOL_HANDLERS = {
    "open_database": "_tool_open_database", "create_database": "_tool_open_database",
    "close_database": "_tool_close_database", "database_history": "_tool_database_history",
    "database_page": "_tool_database_page", "database_annotations": "_tool_database_annotations",
    "open_database_snapshot": "_tool_open_database_snapshot",
    "save_to_database": "_tool_save_to_database",
    "database_rename_symbol": "_tool_database_annotate", "database_set_comment": "_tool_database_annotate",
    "open_project": "_tool_open_project", "create_project": "_tool_open_project",
    "close_project": "_tool_close_project", "project_history": "_tool_project_history",
    "project_page": "_tool_project_page", "open_project_snapshot": "_tool_open_project_snapshot",
    "project_annotations": "_tool_project_annotations", "analyze_to_project": "_tool_analyze_to_project",
    "project_rename_symbol": "_tool_project_annotate", "project_set_comment": "_tool_project_annotate",
    "open_file": "_tool_open_file", "simplify_micro_expression": "_tool_simplify_micro_expression",
    "close_file": "_tool_close_file", "list_functions": "_tool_list_functions",
    "analysis_summary": "_tool_analysis_summary", "get_disasm": "_tool_get_disasm",
    "get_cfg": "_tool_get_cfg", "get_pseudoc": "_tool_get_pseudoc",
    "get_microcode": "_tool_get_microcode", "get_microcode_facts": "_tool_get_microcode_facts",
    "xref_query": "_tool_xref_query", "list_api_calls": "_tool_list_api_calls",
    "export_result": "_tool_export_result", "rename_symbol": "_tool_rename_symbol",
}


class McpServer(DatabaseToolsMixin, ProjectToolsMixin, FileToolsMixin, PseudocToolsMixin):
    """State for one connection; file handles are process-local.

    ``own_completed_results`` is opt-in for a private service whose native
    full results are relinquished after completion, as in the agent's stdio
    child process. The default retains isolation from externally owned results.
    """

    def __init__(self, allow_writes: bool = False, settings: Settings | None = None, *,
                 own_completed_results: bool = False) -> None:
        if type(own_completed_results) is not bool:
            raise ValueError("own_completed_results must be boolean")
        m = _facade()
        self.own_completed_results = own_completed_results
        self.settings = settings or m.load_settings()
        self.allow_writes = allow_writes or self.settings.mcp_allow_writes
        self.service = m.AnalysisService(settings=self.settings)
        self._snapshots: dict[str, dict[str, Any]] = {}
        self._projects: dict[str, ProjectStore] = {}
        self._databases: dict[str, Any] = {}
        self._snapshot_sources: dict[str, tuple[str, tuple[int, ...]]] = {}
        # 按句柄惰性缓存的指令索引；结果被替换、结构变化或会话改写时重建。
        self._instruction_indexes: dict[str, _InstructionIndex] = {}
        # 按句柄缓存的按需伪 C 上下文（get_pseudoc generate）；只在本会话内存在，不写数据库。
        self._pseudoc_contexts: dict[str, Any] = {}
        self._initialized = False
        self._ready = False

    def close(self) -> None:
        self._snapshots.clear()
        self._snapshot_sources.clear()
        self._instruction_indexes.clear()
        getattr(self, "_pseudoc_contexts", {}).clear()
        self._projects.clear()
        first_error: BaseException | None = None
        try:
            for store in tuple(self._databases.values()):
                try:
                    store.close()
                except BaseException as exc:
                    if first_error is None:
                        first_error = exc
        finally:
            self._databases.clear()
            try:
                self.service.close()
            except BaseException as exc:
                if first_error is None:
                    first_error = exc
        if first_error is not None:
            raise first_error

    @staticmethod
    def _source_signature(path: str | Path) -> tuple[int, ...]:
        stat = _facade().Path(path).stat()
        return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)

    def _database(self, arguments: dict[str, Any]) -> Any:
        handle = arguments.get("database")
        if not isinstance(handle, str) or handle not in self._databases:
            raise ValueError("unknown database handle; call open_database first")
        return self._databases[handle]

    def _open_database(self, path: Any, *, create: bool = False,
                       read_only: bool = True) -> dict[str, Any]:
        m = _facade()
        if not isinstance(path, str) or not path:
            raise ValueError("path must be a non-empty string")
        if type(read_only) is not bool:
            raise ValueError("read_only must be boolean")
        if (create or not read_only) and not self.allow_writes:
            raise ValueError("Persistent database writes are disabled")
        if len(self._databases) >= m.MAX_OPEN_DATABASES:
            raise ValueError(f"session is limited to {m.MAX_OPEN_DATABASES} open databases")
        plugin = self.service.manager.load_storage("sqlite_storage")
        store = plugin.open_database(path, read_only=read_only, create=create)
        try:
            info = store.info()
        except BaseException:
            store.close()
            raise
        handle = m.uuid4().hex
        self._databases[handle] = store
        return {"database": handle, "path": str(store.path), "created": create,
                "read_only": store.read_only, "info": info}

    def _snapshot(self, arguments: dict[str, Any]) -> dict[str, Any]:
        handle = arguments.get("handle")
        if not isinstance(handle, str) or handle not in self._snapshots:
            raise ValueError("unknown file handle; call open_file first")
        return self._snapshots[handle]

    def _instruction_index(self, handle: str, snapshot: dict[str, Any]) -> _InstructionIndex:
        """返回句柄对应结果的指令索引，签名不符（换了结果或增删了指令容器）时重建。"""
        m = _facade()
        watch = m._instruction_watch(snapshot)
        cached = self._instruction_indexes.get(handle)
        if cached is not None and cached.current(snapshot, watch):
            return cached
        index = m._InstructionIndex(snapshot, watch)
        if watch is None:
            # 非常规结构不缓存，每次按旧语义重建。
            self._instruction_indexes.pop(handle, None)
            return index
        # 顺带清掉已不在会话中的句柄，缓存不会比打开的结果活得更久。
        for stale in tuple(self._instruction_indexes):
            if stale not in self._snapshots:
                self._instruction_indexes.pop(stale, None)
        self._instruction_indexes[handle] = index
        return index

    def _project(self, arguments: dict[str, Any]) -> ProjectStore:
        handle = arguments.get("project")
        if not isinstance(handle, str) or handle not in self._projects:
            raise ValueError("unknown project handle; call open_project first")
        return self._projects[handle]

    def _open_project(self, path: Any, *, create: bool = False) -> dict[str, Any]:
        m = _facade()
        if not isinstance(path, str) or not path:
            raise ValueError("path must be a non-empty string")
        if len(self._projects) >= m.MAX_OPEN_PROJECTS:
            raise ValueError(f"session is limited to {m.MAX_OPEN_PROJECTS} open projects")
        database = m.Path(path).expanduser().resolve()
        if create:
            if database.exists():
                raise ValueError("project database already exists; call open_project")
        else:
            if not database.is_file():
                raise ValueError("project database does not exist; creation requires write access")
        # The read-only constructor uses SQLite mode=ro/query_only and performs
        # no migration, journal changes, or parent-directory creation.
        store = m.ProjectStore(database, read_only=not self.allow_writes)
        handle = m.uuid4().hex
        self._projects[handle] = store
        return {"project": handle, "path": str(store.path), "created": create}

    @staticmethod
    def _pagination(arguments: dict[str, Any]) -> tuple[int, int]:
        m = _facade()
        offset, limit = arguments.get("offset", 0), arguments.get("limit", 100)
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise ValueError("offset must be a non-negative integer")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= m.MAX_PAGE_SIZE:
            raise ValueError(f"limit must be an integer between 1 and {m.MAX_PAGE_SIZE}")
        return offset, limit

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Run one tool, returning content or a model-visible execution error."""
        m = _facade()
        try:
            method = _TOOL_HANDLERS.get(name, "_tool_unavailable")
        except TypeError:
            # 不可哈希的名字在旧实现的逐项比较中不匹配任何工具，同样走兜底处理。
            method = "_tool_unavailable"
        try:
            return getattr(self, method)(name, arguments)
        except (OSError, ValueError, KeyError, TypeError, m.ProjectError, sqlite3.Error) as exc:
            return m._tool_error(str(exc))

    def handle(self, message: Any) -> dict[str, Any] | None:
        """Dispatch one JSON-RPC message; notifications have no response."""
        m = _facade()
        if not isinstance(message, dict):
            return m._error(None, -32600, "Invalid Request")
        request_id = message.get("id")
        notification = "id" not in message
        if message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
            return m._error(request_id, -32600, "Invalid Request")
        if not notification and (request_id is None or isinstance(request_id, bool) or
                                 not isinstance(request_id, (str, int))):
            return m._error(None, -32600, "Invalid Request")
        method = message["method"]
        if notification:
            if method == "notifications/initialized" and self._initialized:
                self._ready = True
            return None
        params = message.get("params", {})
        if not isinstance(params, dict):
            return m._error(request_id, -32602, "params must be an object")
        if method == "initialize":
            if self._initialized:
                return m._error(request_id, -32600, "Already initialized")
            if not isinstance(params.get("protocolVersion"), str):
                return m._error(request_id, -32602, "protocolVersion is required")
            version = params["protocolVersion"] if params["protocolVersion"] in m.SUPPORTED_VERSIONS else m.PROTOCOL_VERSION
            self._initialized = True
            return m._response(request_id, {"protocolVersion": version, "capabilities": {"tools": {}},
                                            "serverInfo": {"name": "fangida", "version": "0.4.0"}})
        if method == "ping":
            return m._response(request_id, {})
        if method == "server/discover":
            # A modern client can probe this optional RPC before trying the
            # legacy handshake; a standard method-not-found prompts fallback.
            return m._error(request_id, -32601, "Method not found: server/discover")
        if not self._ready:
            return m._error(request_id, -32000, "Initialize the MCP session first")
        if method == "tools/list":
            if "cursor" in params:
                return m._error(request_id, -32602, "No further tools page")
            return m._response(request_id, {"tools": m._tools(self.allow_writes)})
        if method == "tools/call":
            name, arguments = params.get("name"), params.get("arguments", {})
            if not isinstance(name, str) or not isinstance(arguments, dict):
                return m._error(request_id, -32602, "name and object arguments are required")
            if name not in {tool["name"] for tool in m._tools(self.allow_writes)}:
                return m._error(request_id, -32602, f"Unknown tool: {name}")
            return m._response(request_id, self.call_tool(name, arguments))
        return m._error(request_id, -32601, f"Method not found: {method}")
