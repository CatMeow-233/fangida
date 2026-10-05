"""工作区布局与函数侧栏，仅负责展示，不调用分析器。"""
from __future__ import annotations

from typing import Any, Callable


SIDEBAR_PAGE_ROWS = 250
VIEW_LABELS = {
    "Overview": "概览", "Sections": "区段", "Functions": "函数",
    "Disassembly": "汇编", "Strings": "字符串", "Imports": "导入",
    "Exports": "导出", "API Calls": "API调用", "Pseudocode": "伪代码",
    "Xrefs": "交叉引用", "Hex": "字节", "CFG": "流程图",
}


def view_label(name: str) -> str:
    """缩短显示标题；结果表的原始键保持不变。"""
    return VIEW_LABELS.get(name, name)


class FunctionSidebar:
    """过滤与分页只改变显示索引，原函数记录保持只读。"""

    def __init__(self, parent: Any, tk: Any, ttk: Any,
                 on_open: Callable[[int], None],
                 on_select: Callable[[int], None] | None = None) -> None:
        self.frame = ttk.LabelFrame(parent, text="函数", padding=5)
        self._tk, self._ttk = tk, ttk
        self._on_open, self._on_select = on_open, on_select
        self._rows: list[dict[str, Any]] = []
        self._indices: list[int] = []
        self._page = 0
        self._filter_job: Any = None
        self.query = tk.StringVar()
        ttk.Label(self.frame, text="按名称或地址筛选").pack(anchor="w", pady=(0, 3))
        self.entry = ttk.Entry(self.frame, textvariable=self.query)
        self.entry.pack(fill="x", pady=(0, 5))
        self.entry.bind("<KeyRelease>", self._schedule_filter)
        self.entry.bind("<Escape>", self._clear_filter)
        body = ttk.Frame(self.frame)
        body.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(body, columns=("address", "name"),
                                show="headings", selectmode="browse")
        self.tree.heading("address", text="地址")
        self.tree.heading("name", text="函数名")
        self.tree.column("address", width=105, minwidth=70, stretch=False)
        self.tree.column("name", width=180, minwidth=100)
        scroll = ttk.Scrollbar(body, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", lambda _event: self.open_selected())
        self.tree.bind("<Return>", lambda _event: self.open_selected())
        self.tree.bind("<ButtonRelease-1>", lambda _event: self._selection_changed())
        self.tree.bind("<KeyRelease>", lambda event: self._selection_changed()
                       if event.keysym in {"Up", "Down", "Home", "End", "Prior", "Next"} else None)
        controls = ttk.Frame(self.frame)
        controls.pack(fill="x", pady=(5, 0))
        controls.columnconfigure(0, weight=1, uniform="pages")
        controls.columnconfigure(1, weight=1, uniform="pages")
        self.previous = ttk.Button(controls, text="上一页",
                                   command=lambda: self.change_page(-1))
        self.previous.grid(row=0, column=0, sticky="ew", padx=(0, 2))
        self.next = ttk.Button(controls, text="下一页",
                               command=lambda: self.change_page(1))
        self.next.grid(row=0, column=1, sticky="ew", padx=(2, 0))
        self.count = tk.StringVar(value="暂无函数")
        self.count_label = ttk.Label(controls, textvariable=self.count, anchor="center")
        self.count_label.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(4, 0))

    def set_rows(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows
        self._page = 0
        self._apply_filter()

    def _schedule_filter(self, _event: Any = None) -> None:
        if self._filter_job is not None:
            self.frame.after_cancel(self._filter_job)
        self._filter_job = self.frame.after(120, self._apply_filter)

    def _clear_filter(self, _event: Any = None) -> str:
        self.query.set("")
        self._apply_filter()
        self.tree.focus_set()
        return "break"

    def _apply_filter(self) -> None:
        self._filter_job = None
        query = self.query.get().strip().casefold()
        self._indices = [index for index, row in enumerate(self._rows)
                         if not query or query in str(row.get("name", "")).casefold()
                         or query in self._address(row).casefold()]
        self._page = 0
        self._render()

    @staticmethod
    def _address(row: dict[str, Any]) -> str:
        address = row.get("start", row.get("code_offset", row.get("location")))
        return f"{address:#x}" if type(address) is int else str(address or "—")

    def _render(self) -> None:
        self.tree.delete(*self.tree.get_children())
        total = len(self._indices)
        last = max(0, (total - 1) // SIDEBAR_PAGE_ROWS)
        self._page = max(0, min(self._page, last))
        start = self._page * SIDEBAR_PAGE_ROWS
        for index in self._indices[start:start + SIDEBAR_PAGE_ROWS]:
            row = self._rows[index]
            self.tree.insert("", "end", iid=str(index),
                             values=(self._address(row), row.get("name", "?")))
        self.count.set(f"{total} 个 · {self._page + 1}/{last + 1} 页")
        self.previous.configure(state="normal" if self._page else "disabled")
        self.next.configure(state="normal" if self._page < last else "disabled")

    def change_page(self, direction: int) -> None:
        self._page += direction
        self._render()

    def open_selected(self) -> str:
        selected = self.tree.selection()
        if selected:
            self._on_open(int(selected[0]))
        return "break"

    def _selection_changed(self) -> None:
        selected = self.tree.selection()
        if selected and self._on_select is not None:
            self._on_select(int(selected[0]))

    def select_index(self, index: int) -> bool:
        try:
            position = self._indices.index(index)
        except ValueError:
            return False
        page = position // SIDEBAR_PAGE_ROWS
        if page != self._page:
            self._page = page
            self._render()
        item = str(index)
        self.tree.selection_set(item)
        self.tree.focus(item)
        self.tree.see(item)
        return True


class Workspace:
    """函数侧栏、中央视图、输出区域各自拥有独立容器。"""

    def __init__(self, parent: Any, tk: Any, ttk: Any,
                 on_function_open: Callable[[int], None],
                 on_function_select: Callable[[int], None] | None = None) -> None:
        self.frame = ttk.PanedWindow(parent, orient="vertical")
        self.frame.pack(fill="both", expand=True, padx=8, pady=4)
        body = ttk.PanedWindow(self.frame, orient="horizontal")
        self.sidebar = FunctionSidebar(body, tk, ttk, on_function_open, on_function_select)
        self.notebook = ttk.Notebook(body)
        body.add(self.sidebar.frame, weight=1)
        body.add(self.notebook, weight=4)
        output = ttk.LabelFrame(self.frame, text="输出", padding=4)
        self.output = tk.Text(output, height=4, wrap="word", font="TkFixedFont",
                              state="disabled", takefocus=True)
        self.output.pack(fill="both", expand=True)
        self.frame.add(body, weight=9)
        self.frame.add(output, weight=1)

    def log(self, text: str) -> None:
        self.output.configure(state="normal")
        self.output.insert("end", text.rstrip() + "\n")
        lines = int(self.output.index("end-1c").split(".")[0])
        if lines > 300:
            self.output.delete("1.0", f"{lines - 300}.0")
        self.output.see("end")
        self.output.configure(state="disabled")
