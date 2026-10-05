"""_Browser 的控制流图视图：流程图、基本块列表与块地址跳转。"""
from __future__ import annotations

from typing import Any

from .facade import _gui

# 运行时引用的原 fangida.gui 模块级名字（函数、类、常量及 Path 等导入的名字）一律经门面 _gui() 查找，
# 对门面打的补丁因此仍作用于实现，与拆分前一致。


class _CfgViewMixin:
    """CFG 标签页的构建、函数与基本块选择和跳转；只在 Tk 线程调用。"""

    def _make_cfg_tab(self, notebook: Any) -> None:
        frame = self.ttk.Frame(notebook, padding=6)
        self._cfg_tab = frame
        notebook.add(frame, text=self._tab_caption("CFG"))
        controls = self.ttk.Frame(frame)
        controls.pack(fill="x", pady=(0, 6))
        self.ttk.Label(controls, text="函数：").pack(side="left")
        self.cfg_selection = self.tk.StringVar()
        self.cfg_choice = self.ttk.Combobox(controls, textvariable=self.cfg_selection,
                                             state="disabled", width=40)
        self.cfg_choice.pack(side="left", padx=(5, 14))
        self.cfg_choice.bind("<<ComboboxSelected>>", lambda _event: self._cfg_selected())
        self.ttk.Label(controls, text="块地址：").pack(side="left")
        self.cfg_address = self.tk.StringVar()
        entry = self.ttk.Entry(controls, textvariable=self.cfg_address, width=16)
        entry.pack(side="left", padx=5)
        entry.bind("<Return>", lambda _event: self.jump_cfg())
        self.cfg_jump = self.ttk.Button(controls, text="跳转", command=self.jump_cfg,
                                         state="disabled")
        self.cfg_jump.pack(side="left")
        self.cfg_status = self.tk.StringVar(value="No control-flow graph available")
        self.ttk.Label(frame, textvariable=self.cfg_status).pack(anchor="w", pady=(0, 4))
        views = self.ttk.Notebook(frame)
        self._cfg_views = views
        views.pack(fill="both", expand=True)
        from .graph import GraphView
        self.graph_view = GraphView(views, self.tk, self.ttk,
            on_navigate=lambda address: self.workbench.graph_navigate(address),
            on_select=lambda address: self.workbench.graph_select(address))
        views.add(self.graph_view.frame, text="流程图")
        legacy = self.ttk.Frame(views)
        views.add(legacy, text="基本块列表")
        pane = self.ttk.PanedWindow(legacy, orient="vertical")
        pane.pack(fill="both", expand=True)
        top = self.ttk.Frame(pane)
        bottom = self.ttk.Frame(pane)
        pane.add(top, weight=3)
        pane.add(bottom, weight=2)
        columns = ("start", "count", "successors", "frontier")
        tree = self.ttk.Treeview(top, columns=columns, show="headings", selectmode="browse")
        for name, title, width in (("start", "Block", 150), ("count", "Instructions", 110),
                                   ("successors", "Successors", 300),
                                   ("frontier", "Unresolved paths", 140)):
            tree.heading(name, text=title)
            tree.column(name, width=width, minwidth=80, stretch=True)
        vertical = self.ttk.Scrollbar(top, orient="vertical", command=tree.yview)
        horizontal = self.ttk.Scrollbar(top, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        top.columnconfigure(0, weight=1)
        top.rowconfigure(0, weight=1)
        tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        self.ttk.Label(bottom, text="Instructions and outgoing paths").pack(anchor="w")
        self.cfg_detail = self.tk.Text(bottom, wrap="none", height=10,
                                        font="TkFixedFont", state="disabled")
        self.cfg_detail.pack(fill="both", expand=True)
        tree.bind("<<TreeviewSelect>>", lambda _event: self._show_cfg_block())
        tree.bind("<ButtonRelease-1>", lambda _event: self._cfg_block_selected())
        tree.bind("<KeyRelease>", lambda event: self._cfg_block_selected()
                  if event.keysym in {"Up", "Down", "Home", "End", "Prior", "Next"} else None)
        self.cfg_tree = tree

    def _show_cfg(self) -> None:
        self._cfg_dirty = False
        self.cfg_tree.delete(*self.cfg_tree.get_children())
        self._cfg_rows = []
        self._set_text(self.cfg_detail, "")
        index = self.cfg_choice.current()
        if index < 0 or index >= len(self._cfgs):
            self.cfg_status.set("No control-flow graph available")
            self.cfg_jump.configure(state="disabled")
            if hasattr(self, "graph_view"):
                self.graph_view.set_cfg({})
            return
        graph = self._cfgs[index]["graph"]
        if hasattr(self, "graph_view"):
            selected = self.workbench.current.address if self.workbench.current else None
            self.graph_view.set_cfg(graph, selected_address=selected)
        self._cfg_rows = _gui().cfg_block_rows(graph)
        for row_index, row in enumerate(self._cfg_rows):
            self.cfg_tree.insert("", "end", iid=str(row_index), values=(
                f"{row['start']:#x}", row["instruction_count"],
                ", ".join(f"{target:#x}" for target in row["successors"]),
                len(row["frontier"])))
        graph_blocks = graph.get("blocks") or []
        graph_frontier = graph.get("frontier") or []
        truncated = len(graph_blocks) > _gui().MAX_CFG_BLOCKS
        self.cfg_status.set(f"{len(self._cfg_rows)} blocks shown" +
                            (f" (limited to {_gui().MAX_CFG_BLOCKS})" if truncated else "") +
                            (" · incomplete analysis" if graph.get("complete") is False else "") +
                            f" · {len(graph_frontier)} unresolved paths")
        if hasattr(self, "graph_view"):
            self.cfg_status.set(f"流程图包含 {len(graph_blocks)} 个块 · "
                f"基本块列表显示 {len(self._cfg_rows)} 个" +
                (" · 分析不完整" if graph.get("complete") is False else "") +
                f" · {len(graph_frontier)} 条未解析路径")
        self.cfg_jump.configure(state="normal" if self._cfg_rows else "disabled")
        if self._cfg_rows:
            address = (self.graph_view.selected_address if hasattr(self, "graph_view")
                       else self._cfg_rows[0]["start"])
            self._select_cfg_list_block(address)

    def _select_cfg_list_block(self, address: int | None) -> bool:
        block = self.graph_view.layout.block_for_address(address) if hasattr(self, "graph_view") else None
        start = block.start if block is not None else address
        for index, row in enumerate(self._cfg_rows):
            if row["start"] == start:
                item = str(index)
                self.cfg_tree.selection_set(item)
                self.cfg_tree.focus(item)
                self.cfg_tree.see(item)
                self._show_cfg_block()
                return True
        selected = self.cfg_tree.selection()
        if selected:
            self.cfg_tree.selection_remove(*selected)
        self._set_text(self.cfg_detail, "当前基本块超出列表显示范围；请在流程图中查看。\n")
        return False

    def _cfg_selected(self) -> None:
        self._show_cfg()
        if hasattr(self, "workbench"):
            address = self.graph_view.selected_address
            if type(address) is int:
                self.workbench.graph_select(address)

    def _cfg_block_selected(self) -> None:
        self._show_cfg_block()
        selected = self.cfg_tree.selection()
        if selected and hasattr(self, "workbench"):
            index = int(selected[0])
            if 0 <= index < len(self._cfg_rows):
                address = self._cfg_rows[index]["start"]
                self.graph_view.select_address(address)
                self.workbench.graph_select(address)

    def _show_cfg_block(self) -> None:
        selected = self.cfg_tree.selection()
        if not selected:
            return
        index = int(selected[0])
        if index >= len(self._cfg_rows):
            return
        row = self._cfg_rows[index]
        lines = [f"Block {row['start']:#x}", ""]
        for instruction in row["instructions"]:
            if not isinstance(instruction, dict):
                continue
            address = instruction.get("addr")
            location = f"{address:#x}" if isinstance(address, int) else "?"
            operands = instruction.get("operands", [])
            detail = ", ".join(map(str, operands)) if isinstance(operands, (list, tuple)) else str(operands)
            lines.append(f"{location}  {instruction.get('mnemonic', '?')} {detail}".rstrip())
        if not row["instructions"]:
            lines.append("Instructions unavailable")
        lines.append("\nOutgoing paths:")
        for edge in row["outgoing"]:
            target = edge.get("dst")
            lines.append(f"  {edge.get('kind', 'edge')} → " +
                         (f"{target:#x}" if isinstance(target, int) else str(target)))
        if not row["outgoing"]:
            lines.append("  No recorded edges")
        for item in row["frontier"]:
            target = item.get("to")
            lines.append("  unresolved → " +
                         (f"{target:#x}" if isinstance(target, int) else str(target)) +
                         f" ({item.get('reason', 'unknown')})")
        self._set_text(self.cfg_detail, "\n".join(lines) + "\n")

    def jump_cfg(self) -> None:
        try:
            address = _gui().parse_seek_offset(self.cfg_address.get())
        except ValueError as exc:
            self.cfg_status.set(str(exc))
            return
        if hasattr(self, "graph_view") and self.graph_view.select_address(address):
            self.workbench.graph_select(address)
            if not self._select_cfg_list_block(address):
                self._cfg_views.select(self.graph_view.frame)
                self.cfg_status.set(f"已在流程图定位 {address:#x}；该基本块超出列表的 {_gui().MAX_CFG_BLOCKS} 块显示上限")
            return
        for index, row in enumerate(self._cfg_rows):
            if row["start"] == address:
                item = str(index)
                self.cfg_tree.selection_set(item)
                self.cfg_tree.focus(item)
                self.cfg_tree.see(item)
                self._show_cfg_block()
                return
        self.cfg_status.set(f"Block {address:#x} is outside this graph")
