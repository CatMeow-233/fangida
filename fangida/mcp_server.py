"""MCP stdio server backed by the shared dispatcher and analysis snapshots.

兼容门面：实现已拆分到 fangida.mcp_modules，本模块保留全部旧导入路径、名字与
fangida-mcp 脚本入口。拆分后的实现在调用时经本模块查找依赖与辅助名字，因此对本模块
名字的补丁（例如 deepcopy、AnalysisService、_instruction_entries、McpServer、serve）
与拆分前一样生效。

- protocol：协议版本、会话资源上限与 JSON-RPC 响应构造
- schema：工具清单与输入 schema
- results：工具结果、分页、地址解析与快照摘要/CFG 投影
- instruction_index：只读指令索引与分页视图
- server：McpServer 会话状态、工具分派与 JSON-RPC 处理
- database_tools / project_tools / file_tools / pseudoc_tools：按领域划分的工具实现
- stdio：stdio 传输 serve 与命令行入口 main
"""
from __future__ import annotations

# 以下导入同时是再导出：旧代码与测试从本模块取用或补丁这些名字，
# mcp_modules 中的实现也在调用时经本模块查找它们。
import argparse  # noqa: F401
from bisect import bisect_left  # noqa: F401
from copy import deepcopy  # noqa: F401
import json  # noqa: F401
from operator import is_  # noqa: F401
import re  # noqa: F401
import sqlite3  # noqa: F401
import sys  # noqa: F401
from pathlib import Path  # noqa: F401
from typing import Any, BinaryIO  # noqa: F401
from uuid import uuid4  # noqa: F401

from .api import AnalysisView  # noqa: F401
from .dispatcher import AnalysisService  # noqa: F401
from .models import AnalysisResult  # noqa: F401
from .project import COLLECTIONS, ProjectError, ProjectStore, fingerprint  # noqa: F401
from .settings import Settings, load_settings  # noqa: F401
from .mcp_modules.protocol import (  # noqa: F401
    MAX_MESSAGE_BYTES, MAX_OPEN_DATABASES, MAX_OPEN_FILES, MAX_OPEN_PROJECTS, MAX_PAGE_SIZE,
    MAX_SCAN_BYTES, PROTOCOL_VERSION, SUPPORTED_VERSIONS, _error, _response)
from .mcp_modules.schema import _schema, _tools  # noqa: F401
from .mcp_modules.results import (  # noqa: F401
    _CFG_SPACE_ALIASES, _SUMMARY_TEXT, _SUMMARY_WARNINGS, _address, _analysis_summary,
    _block_instruction_count, _cfg_context, _cfg_page, _function_summary, _page, _record_address,
    _result, _tool_error)
from .mcp_modules.instruction_index import (  # noqa: F401
    _ABSENT, _EMPTY_VIEW, _InstructionIndex, _InstructionView, _entry_record, _entry_source,
    _instruction_entries, _instruction_watch, _instructions)
from .mcp_modules.server import McpServer  # noqa: F401
from .mcp_modules.stdio import main, serve  # noqa: F401


if __name__ == "__main__":
    raise SystemExit(main())
