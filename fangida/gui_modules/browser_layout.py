"""_Browser 的界面构建部分：结果表与分页控件、伪代码视图、标签标题、文本区和详情面板。"""
from __future__ import annotations

import json
from typing import Any

from .facade import _gui

# 运行时引用的原 fangida.gui 模块级名字（函数、类、常量及 Path 等导入的名字）一律经门面 _gui() 查找，
# 对门面打的补丁因此仍作用于实现，与拆分前一致。


class _LayoutMixin:
    """结果表、伪代码标签页与详情面板的构建和显示；只在 Tk 线程调用。"""

    def _make_table(self, notebook: Any, name: str,
                    columns: tuple[tuple[str, str, int], ...]) -> None:
        frame = self.ttk.Frame(notebook)
        notebook.add(frame, text=self._tab_caption(name))
        self._tabs[name] = frame
        self._make_table_controls(frame, name)
        pane = self.ttk.PanedWindow(frame, orient="vertical")
        pane.pack(fill="both", expand=True)
        top = self.ttk.Frame(pane)
        bottom = self.ttk.Frame(pane)
        pane.add(top, weight=4)
        pane.add(bottom, weight=1)
        tree = self._make_table_tree(top, name, columns)
        self.ttk.Label(bottom, text="当前位置详情").pack(anchor="w")
        detail = self.tk.Text(bottom, wrap="none", height=7, font="TkFixedFont", state="disabled")
        detail.pack(fill="both", expand=True)
        self._tables[name] = tree
        self._details[name] = detail

    def _make_table_controls(self, parent: Any, name: str, *, compact: bool = False) -> None:
        """分页控件；compact 用于伪代码视图左侧较窄的函数列表。"""
        controls = self.ttk.Frame(parent, padding=(6, 4))
        controls.pack(fill="x", side="bottom" if compact else "top")
        previous = self.ttk.Button(controls, text="上一页", state="disabled",
                                   command=lambda tab=name: self._change_table_page(tab, -1))
        following = self.ttk.Button(controls, text="下一页", state="disabled",
                                    command=lambda tab=name: self._change_table_page(tab, 1))
        self._table_previous[name] = previous
        self._table_next[name] = following
        page_number = self.tk.StringVar(value="1")
        self._table_page_numbers[name] = page_number
        page_label = self.ttk.Label(controls, text="页码：")
        page_entry = self.ttk.Entry(controls, textvariable=page_number, width=8)
        page_entry.bind("<Return>", lambda _event, tab=name: self._jump_table_page(tab))
        jump = self.ttk.Button(controls, text="跳转",
                               command=lambda tab=name: self._jump_table_page(tab))
        page_status = self.tk.StringVar(value="暂无数据")
        self._table_page_status[name] = page_status
        status = self.ttk.Label(controls, textvariable=page_status)
        if compact:
            for column in range(3):
                controls.columnconfigure(column, weight=1)
            previous.grid(row=0, column=0, sticky="ew", padx=(0, 2))
            following.grid(row=0, column=1, sticky="ew", padx=2)
            jump.grid(row=0, column=2, sticky="ew", padx=(2, 0))
            page_label.grid(row=1, column=0, sticky="w", pady=(4, 0))
            page_entry.grid(row=1, column=1, columnspan=2, sticky="ew", pady=(4, 0))
            status.grid(row=2, column=0, columnspan=3, sticky="w", pady=(4, 0))
            return
        previous.pack(side="left")
        following.pack(side="left", padx=(4, 10))
        page_label.pack(side="left")
        page_entry.pack(side="left", padx=4)
        jump.pack(side="left")
        status.pack(side="left", padx=12)

    def _make_table_tree(self, parent: Any, name: str,
                         columns: tuple[tuple[str, str, int], ...], *,
                         display: tuple[str, ...] | None = None,
                         widths: dict[str, int] | None = None) -> Any:
        keys = tuple(key for key, _, _ in columns)
        tree = self.ttk.Treeview(parent, columns=keys, show="headings", selectmode="browse")
        for key, heading, width in columns:
            tree.heading(key, text=heading)
            tree.column(key, width=(widths or {}).get(key, width), minwidth=60, stretch=True)
        if display is not None:
            tree.configure(displaycolumns=display)
        vertical = self.ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        horizontal = self.ttk.Scrollbar(parent, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)
        tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        tree.bind("<<TreeviewSelect>>", lambda _event, tab=name: self._show_detail(tab))
        return tree

    def _make_pseudocode_tab(self, notebook: Any, name: str,
                             columns: tuple[tuple[str, str, int], ...]) -> None:
        """伪代码标签页：左侧有伪 C 的函数列表，右侧函数头与大代码区。

        仍登记到 _tables/_details/_rows 和分页状态中，导航、查找、跳转与
        记录选择沿用原有表格路径；_details["Pseudocode"] 就是代码区。
        """
        from .pseudocode_view import PseudocodeView
        frame = self.ttk.Frame(notebook)
        notebook.add(frame, text=self._tab_caption(name))
        self._tabs[name] = frame
        view = PseudocodeView(
            frame, self.tk, self.ttk,
            on_activate=lambda target, disassembly: self.workbench.activate_pseudocode_target(
                target, disassembly=disassembly),
            on_status=self._pseudocode_hover_status,
            on_xrefs=lambda address: self.workbench.pseudocode_xrefs(address),
            on_mode_change=self._pseudocode_mode_changed,
            on_generate=self._pseudocode_generate_clicked)
        view.frame.pack(fill="both", expand=True)
        self.pseudocode_view = view
        self._make_table_controls(view.list_frame, name, compact=True)
        holder = self.ttk.Frame(view.list_frame)
        holder.pack(fill="both", expand=True)
        tree = self._make_table_tree(holder, name, columns, display=_gui().PSEUDOCODE_LIST_COLUMNS,
                                     widths=_gui()._PSEUDOCODE_LIST_WIDTHS)
        self._tables[name] = tree
        self._details[name] = view.code
        view.show_message("打开二进制文件或分析数据库后，在此浏览已有伪代码。")

    def _pseudocode_hover_status(self, text: str) -> None:
        """悬停在可跳转文本上时提示目标；离开后恢复原状态栏文字。"""
        status = getattr(self, "status", None)
        if status is None:
            return
        saved = getattr(self, "_status_before_hover", None)
        if text:
            if saved is None:
                self._status_before_hover = (status.get(), text)
            else:
                self._status_before_hover = (saved[0], text)
            status.set(text)
        elif saved is not None:
            self._status_before_hover = None
            if status.get() == saved[1]:  # 期间状态栏被其它操作更新时不覆盖
                status.set(saved[0])

    def _pseudocode_generate_clicked(self) -> None:
        """伪代码视图的“生成伪代码”按钮：与 Ctrl+F5 / 视图菜单共用同一命令。"""
        workbench = getattr(self, "workbench", None)
        if workbench is None or not workbench.registry.execute("generate_pseudocode"):
            status = getattr(self, "status", None)
            if status is not None:
                status.set("先打开原生二进制结果，并在函数列表或反汇编中选中一个函数（分析进行中不可生成）")

    def _pseudocode_mode_changed(self) -> None:
        """可读/机器视图切换后重新显示当前选择的函数。"""
        view = getattr(self, "pseudocode_view", None)
        if view is None:
            return
        record = self._selected_record("Pseudocode")
        if record is not None:
            selected = self._tables["Pseudocode"].selection()
            view.show(record, (self._generation, int(selected[0])))
        view.code.focus_set()

    def _tab_caption(self, name: str, count: int | None = None) -> str:
        if hasattr(self, "workspace"):
            from .workspace import VIEW_LABELS
            return VIEW_LABELS.get(name, name)
        # Preserve labels for callers constructing the legacy controller.
        return f"{name} ({count})" if count is not None else name

    def _set_text(self, widget: Any, value: str) -> None:
        view = getattr(self, "pseudocode_view", None)
        if view is not None and widget is view.code:
            view.replace_text(value)  # 同样只读写入，并让函数头回到提示状态
            return
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        widget.configure(state="disabled")

    def _show_detail(self, name: str) -> None:
        selected = self._tables[name].selection()
        if not selected:
            return
        index = int(selected[0])
        rows = self._rows.get(name, [])
        if index < len(rows):
            view = getattr(self, "pseudocode_view", None)
            if name == "Pseudocode" and view is not None:
                # 代码区显示完整伪 C（带高亮和函数头），而不是挤在表格单元格里。
                view.show(rows[index], (self._generation, index))
            else:
                from .records import display_text
                detail = display_text(name, rows[index])
                self._set_text(self._details[name], detail if detail is not None else
                               json.dumps(rows[index], indent=2, ensure_ascii=False) + "\n")
            if hasattr(self, "workbench"):
                self.workbench.record_selected(name, index)
