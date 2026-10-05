"""桌面浏览器控制器 _Browser：由按职责拆分的 mixin 组合而成。

本模块只保留构造（建立窗口布局与全部状态）和关闭；其余方法按职责位于 browser_* 模块。
mixin 不定义 __init__、__slots__ 或类属性，_Browser 仍可用 object.__new__(_Browser) 构造。
"""
from __future__ import annotations

import queue
from pathlib import Path
from typing import Any

from .browser_cfg import _CfgViewMixin
from .browser_hex import _HexViewMixin
from .browser_jobs import _JobsMixin
from .browser_layout import _LayoutMixin
from .browser_options import _AnalysisOptionsMixin
from .browser_pages import _TablePagesMixin
from .browser_storage import _StorageMixin
from .facade import _gui
from .operations import _Loaded

# gui_modules 不直接导入 api、dispatcher、plugins 等分析实现（见 tests/test_gui_workbench.py 的依赖检查）：
# 构造函数里的属性注解（含 AnalysisView、_Loaded）不求值，运行时需要的 AnalysisView 由工作线程的结果提供。
# 运行时引用的原 fangida.gui 模块级名字（函数、类、常量及 Path 等导入的名字）一律经门面 _gui() 查找，
# 对门面打的补丁因此仍作用于实现，与拆分前一致。


# 各 mixin 的方法名互不重复，组合顺序不影响方法解析。
class _Browser(_LayoutMixin, _HexViewMixin, _CfgViewMixin, _AnalysisOptionsMixin,
               _JobsMixin, _StorageMixin, _TablePagesMixin):
    """Tk controller; all of its methods except _worker run on the UI thread."""

    def __init__(self, root: Any, tk: Any, ttk: Any, filedialog: Any,
                 messagebox: Any, max_bytes: int | None,
                 use_ghidra: bool | None, deep_analysis: bool | None,
                 semantic_threads: int | None = None,
                 full_analysis: bool = False,
                 database_path: str | Path | None = None,
                 storage_plugin: str = "sqlite_storage") -> None:
        self.root = root
        self.tk = tk
        self.ttk = ttk
        self.filedialog = filedialog
        self.messagebox = messagebox
        self.max_bytes = max_bytes
        self.use_ghidra = use_ghidra
        self.deep_analysis = deep_analysis
        self.semantic_threads = semantic_threads
        # 打开文件对话框里关闭多线程时为 1；None 表示沿用配置文件中的总线程预算。
        self.analyze_threads: int | None = None
        self.full_analysis = full_analysis
        self._standard_max_bytes = max_bytes
        self._standard_deep_analysis = True if deep_analysis is False else deep_analysis
        self.database_path = database_path
        self.storage_plugin = storage_plugin
        # 标注用的地址索引（只读结构）：同一快照上的多次重命名/注释复用，避免每次遍历整个快照。
        self._annotation_cache: dict[str, Any] = {}
        self._busy = False
        self._messages: queue.SimpleQueue[tuple[int, _Loaded | Exception]] = queue.SimpleQueue()
        self._generation = 0
        self._closed = False
        self._view: AnalysisView | None = None
        self._tables: dict[str, Any] = {}
        self._details: dict[str, Any] = {}
        self._rows: dict[str, list[dict[str, Any]]] = {}
        self._tabs: dict[str, Any] = {}
        self._table_pages: dict[str, int] = {}
        self._table_tokens: dict[str, int] = {}
        self._table_loaded: set[str] = set()
        self._table_page_status: dict[str, Any] = {}
        self._table_page_numbers: dict[str, Any] = {}
        self._table_previous: dict[str, Any] = {}
        self._table_next: dict[str, Any] = {}
        self._hex_path: Path | None = None
        self._hex_identity: tuple[int, int, int, int, int] | None = None
        self._hex_previous: int | None = None
        self._hex_next: int | None = None
        self._cfgs: list[dict[str, Any]] = []
        self._cfg_rows: list[dict[str, Any]] = []
        self._cfg_dirty = False
        self.table_page_rows = _gui().TABLE_PAGE_ROWS
        self.table_columns = _gui().TABLE_COLUMNS

        root.title("Fangida — Binary Analysis")
        root.geometry("1100x720")
        root.minsize(720, 460)
        root.protocol("WM_DELETE_WINDOW", self.close)

        toolbar = ttk.Frame(root, padding=(8, 8, 8, 4))
        toolbar.pack(fill="x")
        self.open_button = ttk.Button(toolbar, text="打开文件…", command=self.open_dialog)
        self.open_button.pack(side="left")
        self.open_database_button = ttk.Button(toolbar, text="打开数据库…",
                                                command=self.open_database_dialog)
        self.open_database_button.pack(side="left", padx=(8, 0))
        self.save_database_button = ttk.Button(toolbar, text="保存数据库…",
                                                command=self.save_database, state="disabled")
        self.save_database_button.pack(side="left", padx=(8, 0))
        self.export_button = ttk.Button(toolbar, text="导出 JSON…", command=self.export_json,
                                        state="disabled")
        self.export_button.pack(side="left", padx=(8, 0))
        self.file_label = ttk.Label(toolbar, text="选择二进制文件或分析数据库", width=36)
        self.file_label.pack(side="left", padx=16, fill="x", expand=True)

        self.analysis_mode_status = tk.StringVar(
            value=f"下次打开：{self._next_open_label()}（打开文件时可选择）")
        ttk.Label(root, textvariable=self.analysis_mode_status, padding=(8, 0, 8, 4)).pack(
            fill="x")

        annotation_bar = ttk.Frame(root, padding=(8, 0, 8, 4))
        annotation_bar.pack(fill="x")
        self.rename_button = ttk.Button(annotation_bar, text="重命名函数…",
                                         command=lambda: self.workbench.registry.execute("rename_symbol"),
                                         state="disabled")
        self.rename_button.pack(side="left")
        self.comment_button = ttk.Button(annotation_bar, text="添加注释…",
                                          command=lambda: self.workbench.registry.execute("set_comment"),
                                          state="disabled")
        self.comment_button.pack(side="left", padx=(8, 0))
        ttk.Label(annotation_bar, text="名称和注释直接保存到数据库").pack(
            side="left", padx=12)

        from .workspace import Workspace
        self.workspace = Workspace(root, tk, ttk,
            lambda index: self.workbench.sidebar_open(index),
            lambda index: self.workbench.sidebar_select(index))
        notebook = self.workspace.notebook
        self.notebook = notebook
        overview = ttk.Frame(notebook)
        notebook.add(overview, text=self._tab_caption("Overview"))
        self.summary = tk.Text(overview, wrap="word", font="TkFixedFont", state="disabled")
        summary_scroll = ttk.Scrollbar(overview, orient="vertical", command=self.summary.yview)
        self.summary.configure(yscrollcommand=summary_scroll.set)
        self.summary.pack(side="left", fill="both", expand=True)
        summary_scroll.pack(side="right", fill="y")
        for name, columns in _gui().TABLE_COLUMNS.items():
            if name == "Pseudocode":
                self._make_pseudocode_tab(notebook, name, columns)
            else:
                self._make_table(notebook, name, columns)
        self._make_hex_tab(notebook)
        self._make_cfg_tab(notebook)
        notebook.bind("<<NotebookTabChanged>>", lambda _event: self._show_selected_tab())

        self.status = tk.StringVar(value="Ready")
        self.address_status = tk.StringVar(value="当前位置：—")
        ttk.Label(root, textvariable=self.address_status, anchor="w", padding=(8, 2)).pack(fill="x")
        ttk.Label(root, textvariable=self.status, relief="sunken", anchor="w",
                  padding=(8, 4)).pack(fill="x")
        from .controller import WorkbenchController
        self.workbench = WorkbenchController(self)
        for name, tree in self._tables.items():
            self.workbench.bind_table(name, tree)
        self.workspace.log("打开文件时选择分析模式；G 跳转，X 查看引用，Space 切换流程图。")
        root.after(50, self._drain)

    def close(self) -> None:
        self._closed = True
        if hasattr(self, "workbench"):
            self.workbench.close()
        self.root.destroy()
