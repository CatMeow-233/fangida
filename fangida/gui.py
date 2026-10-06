"""Optional desktop browser for Fangida analysis snapshots.

Tk is imported only when the GUI is launched, so the package remains usable
on headless machines. Analysis runs off the Tk thread; widget updates do not.

兼容门面：实现已按职责拆分到 fangida.gui_modules 下的模块——
constants（常量与列定义）、adapters（只读结果适配）、operations（分析与存储操作）、
browser 与 browser_*（_Browser 控制器及其 mixin）、launcher（launch 与 main）。
本模块保留拆分前的全部模块级名字（含私有名字和被导入的名字），旧导入路径、
``fangida-gui`` 入口与 ``python -m fangida.gui`` 均不变。子模块在调用时经本模块查找
原模块级名字（见 gui_modules.facade），因此对 fangida.gui 打的补丁或重新赋值仍作用于实现。
"""
from __future__ import annotations

# 拆分前在本模块导入的名字：保持导入路径与补丁目标（如 fangida.gui.threading.Thread）。
import argparse
import json
import os
import queue
import re
import sys
import threading
from dataclasses import replace
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .api import AnalysisView
from .dispatcher import AnalysisService
from .loaders import identify_file
from .plugins.manager import PluginManager
from .project import SourceChangedError, fingerprint
from .settings import load_settings

# 常量与表格列定义。
from .gui_modules.constants import (
    ANALYSIS_MODE_LABELS,
    DEFAULT_THREADS,
    HEX_BYTES_PER_ROW,
    HEX_PAGE_ROWS,
    MAX_CFG_BLOCKS,
    MAX_HEX_ROWS,
    PSEUDOCODE_LIST_COLUMNS,
    TABLE_COLUMNS,
    TABLE_PAGE_ROWS,
    _PSEUDOCODE_LIST_WIDTHS,
)
# 只读结果适配。
from .gui_modules.adapters import (
    _cfg_graphs_snapshot,
    _display,
    _extra_display_tables,
    _file_identity,
    _full_tables,
    _summary_snapshot,
    cfg_block_rows,
    cfg_graphs,
    hex_page,
    parse_seek_offset,
    summary_text,
    table_data,
)
# 分析与存储操作。
from .gui_modules.operations import (
    _Loaded,
    _analyze_file,
    _annotate_database_view,
    _annotate_owned_view,
    _annotation_index,
    _annotation_targets,
    _apply_annotation,
    _database_view,
    _hex_source,
    _prepare,
    _prepare_tables,
    _pseudocode_context,
    _save_database_view,
    _verified_hex_source,
)
# Tk 控制器与启动入口。
from .gui_modules.browser import _Browser
from .gui_modules.launcher import launch, main
# 按需伪 C（新增名字）：gui_modules 不直接导入插件，经门面 _gui().PseudocContext 取得。
from .plugins.pseudoc.on_demand import PseudocContext

# gui_modules 不直接导入 api（见 tests/test_gui_workbench.py 的依赖检查），由门面把注解用到的
# AnalysisView 注入相应子模块，使 typing.get_type_hints 对搬走的函数与类和拆分前一样可解析。
# 循环变量随后删除，门面的模块级名字集合不变。
for _annotated in ("adapters", "operations", "browser_jobs"):
    setattr(sys.modules[f"{__package__}.gui_modules.{_annotated}"], "AnalysisView", AnalysisView)
del _annotated

if __name__ == "__main__":
    raise SystemExit(main())
