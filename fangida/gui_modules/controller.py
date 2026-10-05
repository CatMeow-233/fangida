"""导航与命令协调器；只消费完成的显示记录，不启动解码或 xref 分析。"""
from __future__ import annotations

import re
from typing import Any

from .commands import CommandRegistry, IDA_COMMANDS, PSEUDOCODE_COMMANDS
from .navigation import AddressIndex, Location, NavigationHistory, UnknownLocationError
from .shortcuts import ShortcutBinder, shortcut_label


class WorkbenchController:
    def __init__(self, browser: Any) -> None:
        self.browser = browser
        self.history = NavigationHistory()
        self.index: AddressIndex | None = None
        self._source_key: tuple[Any, ...] | None = None
        self._serial = 0
        self._selecting = False
        self._operand = False
        self._programmatic_selection: tuple[str, int] | None = None
        self._unresolved_selection = False
        self._find_query = ""
        self._find_table = ""
        self._find_position = -1
        self._search_serial = 0
        self.registry = CommandRegistry()
        actions = {
            "open_file": browser.open_dialog,
            "save_database": browser.save_database,
            "jump_address": self.jump_dialog,
            "jump_name": self.jump_dialog,
            "jump_entry": self.jump_entry,
            "xrefs_operand": lambda: self.show_xrefs("incoming", operand=True),
            "xrefs_incoming": lambda: self.show_xrefs("incoming"),
            "xrefs_outgoing": lambda: self.show_xrefs("outgoing"),
            "follow": self.follow,
            "back": self.back,
            "forward": self.forward,
            "toggle_graph": self.toggle_graph,
            "rename_symbol": self.rename,
            "set_comment": self.comment,
            "show_strings": lambda: self.show_table("Strings"),
            "show_sections": lambda: self.show_table("Sections"),
            "show_functions": self.show_functions,
            "show_pseudocode": self.show_pseudocode,
            "find": self.find_dialog,
            "find_next": self.find_next,
            "show_shortcuts": self.show_shortcuts,
            "generate_pseudocode": self.generate_pseudocode,
        }
        for command in IDA_COMMANDS + PSEUDOCODE_COMMANDS:
            if command.id in actions:
                self.registry.register(command, actions[command.id],
                                       lambda command_id=command.id: self.enabled(command_id))
        self.binder = ShortcutBinder(browser.root, self.registry)
        self.binder.bind_all()
        self._make_menus()
        self._context = browser.tk.Menu(browser.root, tearoff=False,
                                        postcommand=lambda: self._update_menu(self._context))
        for command_id in ("follow", "xrefs_operand", "xrefs_incoming", "xrefs_outgoing",
                           "rename_symbol", "set_comment", "toggle_graph"):
            self._add_menu_command(self._context, command_id)

    def enabled(self, command_id: str) -> bool:
        browser = self.browser
        if browser._closed:
            return False
        if command_id == "show_shortcuts":
            return True
        if command_id == "open_file":
            return not browser._busy
        if browser._busy or browser._view is None:
            return False
        if self._unresolved_selection and command_id in {
                "follow", "xrefs_operand", "xrefs_incoming", "xrefs_outgoing",
                "rename_symbol", "set_comment", "toggle_graph"}:
            return False
        if command_id in {"rename_symbol", "set_comment"}:
            info = browser._database_info()
            kind = browser._view._snapshot.get("kind")
            # 没有数据库也可用：执行时会先引导保存为 .fdb（见 _Browser._annotate）。
            return (not info.get("read_only") and self.current is not None
                    and kind not in {"apk", "jar"}
                    and self.current.address_space == ("file_offset" if kind in {"dex", "class"} else "native"))
        if command_id == "generate_pseudocode":
            # 只对原生 x86/x86_64/arm/arm64 结果按需生成；生成在后台进行，不占用忙碌状态。
            snapshot = browser._view._snapshot
            return (self.current is not None and snapshot.get("kind") not in {"apk", "dex", "jar", "class"}
                    and snapshot.get("metadata", {}).get("architecture") in {"x86", "x86_64", "arm", "arm64"})
        if command_id == "back":
            return self.history.can_back
        if command_id == "forward":
            return self.history.can_forward
        return True

    @property
    def current(self) -> Location | None:
        return self.history.current

    def _add_menu_command(self, menu: Any, command_id: str) -> None:
        command = self.registry.get(command_id)
        if command is None:
            return
        menu.add_command(label=command.label, accelerator=shortcut_label(command),
                         command=lambda: self.registry.execute(command_id))
        if not hasattr(menu, "_fangida_commands"):
            menu._fangida_commands = []
        menu._fangida_commands.append((menu.index("end"), command_id))

    def _update_menu(self, menu: Any) -> None:
        for index, command_id in getattr(menu, "_fangida_commands", ()):
            menu.entryconfigure(index, state="normal" if self.enabled(command_id) else "disabled")

    def _make_menus(self) -> None:
        tk, root = self.browser.tk, self.browser.root
        menubar = tk.Menu(root)
        groups = (
            ("文件", ("open_file", "save_database")),
            ("编辑", ("rename_symbol", "set_comment", "find", "find_next")),
            ("跳转", ("jump_address", "jump_name", "jump_entry", "follow", "back", "forward",
                       "xrefs_operand", "xrefs_incoming", "xrefs_outgoing")),
            ("视图", ("toggle_graph", "show_pseudocode", "generate_pseudocode", "show_functions",
                       "show_sections", "show_strings")),
            ("帮助", ("show_shortcuts",)),
        )
        for label, command_ids in groups:
            menu = tk.Menu(menubar, tearoff=False)
            menu.configure(postcommand=lambda current_menu=menu: self._update_menu(current_menu))
            for command_id in command_ids:
                self._add_menu_command(menu, command_id)
            menubar.add_cascade(label=label, menu=menu)
        root.configure(menu=menubar)
        self.menubar = menubar

    def bind_table(self, name: str, tree: Any) -> None:
        tree.bind("<ButtonRelease-1>", lambda event: self._click_record(name, event), add="+")
        tree.bind("<Double-1>", lambda _event: self._double_click(name), add="+")
        tree.bind("<Button-3>", lambda event: self.context_menu(name, event), add="+")
        tree.bind("<Control-Button-1>", lambda event: self.context_menu(name, event), add="+")
        tree.bind("<KeyRelease>", lambda event: self._key_record(name, event), add="+")

    def reset(self) -> None:
        self.index = None
        self.history.reset()
        self._source_key = None
        self._serial += 1
        self._search_serial += 1
        self._find_query = ""
        self._find_position = -1
        self._operand = False
        self._unresolved_selection = False
        self.browser.workspace.sidebar.set_rows([])
        self.browser.address_status.set("当前位置：—")
        self.browser.graph_view.set_cfg({})

    def load(self, loaded: Any) -> None:
        snapshot = loaded.view._snapshot
        metadata = snapshot.get("metadata", {})
        db_info = metadata.get("analysis_database", {})
        source_key = (loaded.path, loaded.kind)
        preserve = source_key == self._source_key and self.current is not None
        old_current = self.current if preserve else None
        # 重命名/注释后重新载入时，若用户正在看伪代码，则留在伪代码视图。
        in_pseudocode = preserve and self._pseudocode_selected()
        if not preserve:
            self.history.reset()
        self._source_key = source_key
        self._unresolved_selection = False
        self.index = getattr(loaded, "navigation_index", None) or AddressIndex(
            self.browser._rows, self.browser._cfgs, kind=loaded.kind)
        self._serial += 1
        self.browser.workspace.sidebar.set_rows(self.browser._rows.get("Functions", []))
        self.browser.workspace.log(f"已载入 {loaded.kind.upper()}：{loaded.path}")
        self.browser.workspace.log(f"{len(self.browser._rows.get('Functions', []))} 个分析根 / 函数，"
                                   f"{len(self.browser._rows.get('Disassembly', []))} 条指令，"
                                   f"{len(self.browser._rows.get('Xrefs', []))} 条引用")
        if old_current is not None:
            if in_pseudocode and self.open_pseudocode(old_current, remember=False):
                return
            self.navigate(old_current, remember=False)
            return
        first = self.index.location_for_row("Disassembly", 0)
        if first is not None:
            self.navigate(first)
        else:
            self.show_table("Functions")

    def _click_record(self, name: str, event: Any) -> None:
        tree = self.browser._tables[name]
        row = tree.identify_row(event.y)
        if row:
            self._programmatic_selection = None
            self._operand = name == "Disassembly" and tree.identify_column(event.x) == "#4"
            self.record_selected(name, int(row))

    def _key_record(self, name: str, event: Any) -> None:
        if event.keysym in {"Up", "Down", "Home", "End", "Prior", "Next"}:
            self._programmatic_selection = None
            self._operand = False
            selected = self.browser._tables[name].selection()
            if selected:
                self.record_selected(name, int(selected[0]))

    def record_selected(self, name: str, index: int) -> None:
        if (self._selecting or self.index is None or self.browser._busy or
                self._programmatic_selection == (name, index)):
            return
        try:
            location = self.index.location_for_row(name, index)
        except ValueError as exc:
            # 多映射字符串不能悄悄沿用上一行的地址查看引用或修改名称。
            self._unresolved_selection = True
            self.browser.status.set(str(exc))
            self._update_address()
            return
        self._unresolved_selection = False
        if location is not None:
            self._search_serial += 1
            self.history.visit(location)
            self._update_address()

    def sidebar_select(self, index: int) -> None:
        self._programmatic_selection = None
        self.record_selected("Functions", index)

    def sidebar_open(self, index: int) -> None:
        if self.index is None:
            return
        location = self.index.location_for_row("Functions", index)
        if location is not None:
            self.navigate(location)

    def _double_click(self, name: str) -> str:
        self._operand = name == "Disassembly"
        if name == "Functions":
            selected = self.browser._tables[name].selection()
            if selected:
                self.sidebar_open(int(selected[0]))
        else:
            self.follow()
        return "break"

    def context_menu(self, name: str, event: Any) -> str:
        tree = self.browser._tables[name]
        row = tree.identify_row(event.y)
        if row:
            self._programmatic_selection = None
            tree.selection_set(row)
            tree.focus(row)
            tree.focus_set()
            self.record_selected(name, int(row))
        self._context.tk_popup(event.x_root, event.y_root)
        return "break"

    def _update_address(self) -> None:
        if self._unresolved_selection:
            self.browser.address_status.set("当前选择存在地址歧义；请跳转到具体加载地址")
            return
        location = self.current
        text = f"当前位置：{location.address:#x} · {location.address_space}" if location else "当前位置：—"
        if location and location.source:
            text += f" · {location.source}"
        self.browser.address_status.set(text)

    def show_table(self, name: str) -> None:
        tab = self.browser._tabs.get(name)
        if tab is not None:
            self.browser.notebook.select(tab)
            self.browser._show_selected_tab()
            self.browser._tables[name].focus_set()

    def show_functions(self) -> None:
        self.browser.workspace.sidebar.entry.focus_set()
        self.browser.workspace.sidebar.entry.selection_range(0, "end")

    def _select_row(self, name: str, index: int, serial: int, generation: int,
                    token: int, attempts: int = 0) -> None:
        browser = self.browser
        if (browser._closed or serial != self._serial or generation != browser._generation
                or token != browser._table_tokens.get(name)):
            return
        tree = browser._tables[name]
        item = str(index)
        if tree.exists(item):
            self._selecting = True
            try:
                self._programmatic_selection = (name, index)
                tree.selection_set(item)
                tree.focus(item)
                tree.see(item)
                tree.focus_set()
                browser._show_detail(name)
            finally:
                self._selecting = False
        elif attempts < 30:
            browser.root.after(5, self._select_row, name, index, serial, generation, token, attempts + 1)

    def select_row(self, name: str, index: int) -> None:
        browser = self.browser
        self.show_table(name)
        page_rows = browser.table_page_rows
        start = index // page_rows * page_rows
        if browser._table_pages.get(name) != start or name not in browser._table_loaded:
            browser._render_table_page(name, start)
        self._serial += 1
        self._select_row(name, index, self._serial, browser._generation, browser._table_tokens[name])

    def navigate(self, location: Location, *, remember: bool = True) -> bool:
        if self.index is None or self.browser._busy:
            return False
        self._search_serial += 1
        targets = self.index.find_targets(location, table="Disassembly")
        if not targets:
            targets = self.index.find_targets(location)
            priority = {"CFG": 0, "Functions": 1, "Pseudocode": 2, "Imports": 3,
                        "Exports": 4, "API Calls": 5, "Strings": 6, "Sections": 7, "Xrefs": 8}
            targets = tuple(sorted(targets, key=lambda target: priority.get(target.table, 20)))
        if not targets:
            offset = self.file_offset(location)
            if offset is not None and self.browser._hex_path is not None:
                self._unresolved_selection = False
                if remember:
                    self.history.visit(location)
                self._update_address()
                self.browser.notebook.select(self.browser._hex_tab)
                self.browser._show_hex_page(offset)
                self.browser.hex_text.focus_set()
                return True
            self.browser.status.set(f"当前结果没有位置 {location.address:#x} 的记录")
            return False
        target = targets[0]
        self._unresolved_selection = False
        if remember:
            self.history.visit(target.location)
        self._operand = False
        self._update_address()
        if target.table == "CFG":
            self.browser.cfg_choice.current(target.cfg_index)
            self.browser._show_cfg()
            self.browser.notebook.select(self.browser._cfg_tab)
            self.browser.graph_view.select_address(location.address)
            self.browser.graph_view.canvas.focus_set()
            return True
        self.select_row(target.table, target.row_index)
        if target.location.address != location.address:
            item = "字符串" if target.table == "Strings" else "指令"
            self.browser.status.set(f"{location.address:#x} 位于{item}内部，已定位到 {target.location.address:#x}")
        try:
            function = self.index.function_at(target.location)
        except ValueError:
            function = None
        if function is not None:
            self._selecting = True
            try:
                self.browser.workspace.sidebar.select_index(function.row_index)
            finally:
                self._selecting = False
            if function.cfg_index is not None:
                self.browser.cfg_choice.current(function.cfg_index)
                self.browser._cfg_dirty = True
        return True

    def file_offset(self, location: Location) -> int | None:
        kind = self.browser._view._snapshot.get("kind", "")
        if location.source and kind in {"apk", "jar"}:
            return None  # 成员偏移不能作为 ZIP 容器的文件偏移。
        if location.address_space == "file_offset":
            return location.address if not location.source or kind in {"dex", "class"} else None
        if location.address_space != "native":
            return None
        offsets = set()
        for section in self.browser._rows.get("Sections", []):
            start, offset, size = (section.get(key) for key in ("address", "offset", "size"))
            if (any(type(value) is not int for value in (start, offset, size))
                    or section.get("file_backed") is False or section.get("type") in {8, "NOBITS", "SHT_NOBITS"}):
                continue
            for key in ("file_size", "filesize", "raw_size"):
                if type(section.get(key)) is int:
                    size = min(size, section[key])
            if start <= location.address < start + size:
                offsets.add(offset + location.address - start)
        return next(iter(offsets)) if len(offsets) == 1 else None

    def jump_dialog(self) -> None:
        if self.index is None:
            return
        from tkinter import simpledialog
        value = simpledialog.askstring("跳转", "输入地址（0x 十六进制）或符号名：",
                                       initialvalue=f"{self.current.address:#x}" if self.current else "",
                                       parent=self.browser.root)
        if value is None:
            return
        try:
            context = self.current if re.fullmatch(r"0[xX][0-9a-fA-F]+|[0-9]+", value.strip()) else None
            try:
                location = self.index.resolve(value, source=context.source if context else None,
                                              address_space=context.address_space if context else None)
            except UnknownLocationError:
                if context is None:
                    raise
                # A numeric address first uses the current space. Only a
                # globally unique target is a valid fallback across spaces.
                location = self.index.resolve(value)
        except ValueError as exc:
            self.browser.messagebox.showerror("无法跳转", str(exc), parent=self.browser.root)
            return
        self.navigate(location)

    def jump_entry(self) -> None:
        if self.index is None:
            return
        metadata = self.browser._view._snapshot.get("metadata", {})
        entry = metadata.get("entry_address", metadata.get("entry"))
        if entry is None:
            entry = metadata.get("entry_cfg", {}).get("entry")
        if isinstance(entry, dict):
            entry = entry.get("address")
        if type(entry) is int:
            self.navigate(Location(entry))
        else:
            for index, function in enumerate(self.browser._rows.get("Functions", [])):
                if function.get("source") in {"entry", "entry_window"} or "entry" in function.get("sources", ()):
                    location = self.index.location_for_row("Functions", index)
                    if location is not None:
                        self.navigate(location)
                        return
            self.browser.status.set("当前结果没有可导航的入口地址")

    def _selected(self) -> tuple[str, dict[str, Any] | None]:
        selected_tab = self.browser.notebook.select()
        for name, tab in self.browser._tabs.items():
            if str(tab) == selected_tab:
                return name, self.browser._selected_record(name)
        return "", None

    def _operand_location(self) -> Location | None:
        name, record = self._selected()
        if record and name == "Disassembly" and self.current:
            branch = record.get("branch_info") or {}
            target = branch.get("target")
            if type(target) is int:
                return Location(target, self.current.source, self.current.address_space)
            references = record.get("arch_meta", {}).get("memory_references", ())
            if len(references) == 1 and type(references[0]) is int:
                return Location(references[0], self.current.source, self.current.address_space)
        return self.current

    def follow(self) -> None:
        if self._unresolved_selection:
            self.browser.status.set("当前选择存在地址歧义；请先跳转到具体加载地址")
            return
        name, record = self._selected()
        location = self.current
        if name == "Xrefs" and record and self.index:
            selected = self.browser._tables[name].selection()
            location = self.index.location_for_row(name, int(selected[0]), field="dst") if selected else None
        elif name == "Disassembly":
            location = self._operand_location()
            if location == self.current and self.index and self.current:
                destinations = {reference.dst for reference in self.index.outgoing(self.current)
                                if reference.dst is not None}
                if len(destinations) == 1:
                    location = next(iter(destinations))
                elif len(destinations) > 1:
                    self.show_xrefs("outgoing")
                    return
        elif name == "API Calls" and self.index and self.current:
            destinations = {reference.dst for reference in self.index.outgoing(self.current)
                            if reference.dst is not None}
            if len(destinations) == 1:
                location = next(iter(destinations))
            elif len(destinations) > 1:
                self.show_xrefs("outgoing")
                return
        elif name == "Functions" and record and self.index:
            selected = self.browser._tables[name].selection()
            location = self.index.location_for_row(name, int(selected[0])) if selected else None
        elif name == "Pseudocode":
            # 代码区光标位于函数名、地址、字符串或标签上时，回车跟随该目标。
            target = self._pseudocode_target()
            if target is not None and self.activate_pseudocode_target(target):
                return
        if location is not None:
            self.navigate(location)

    def back(self) -> None:
        location = self.history.back()
        if location is not None:
            self._revisit(location)

    def forward(self) -> None:
        location = self.history.forward()
        if location is not None:
            self._revisit(location)

    def _revisit(self, location: Location) -> None:
        """后退/前进：在伪代码视图中优先回到对应函数的伪代码。"""
        if self._pseudocode_selected():
            view = getattr(self.browser, "pseudocode_view", None)
            focus_code = view is not None and view.has_focus()
            if self.open_pseudocode(location, remember=False, focus_code=focus_code):
                return
        self.navigate(location, remember=False)

    def show_xrefs(self, direction: str, *, operand: bool = False) -> None:
        if self._unresolved_selection:
            self.browser.status.set("当前选择存在地址歧义；请先跳转到具体加载地址")
            return
        location = self._operand_location() if operand and self._operand else self.current
        if operand:
            target = self._pseudocode_target()
            if target is not None and target.address is not None:
                location = self._pseudocode_location(target.address)
        if location is None or self.index is None:
            return
        references = self.index.incoming(location) if direction == "incoming" else self.index.outgoing(location)
        self._choose_references(references, location, direction)

    def _choose_references(self, references: Any, location: Location, direction: str) -> None:
        browser = self.browser
        title = "引用到" if direction == "incoming" else "引用自"
        dialog = browser.tk.Toplevel(browser.root)
        dialog.title(f"{title} {location.address:#x}")
        dialog.transient(browser.root)
        dialog.geometry("760x390")
        browser.ttk.Label(dialog, text=f"{title} {location.address:#x} · {len(references)} 条引用",
                          padding=8).pack(anchor="w")
        tree = browser.ttk.Treeview(dialog, columns=("src", "dst", "kind"), show="headings")
        for key, label in (("src", "来源地址"), ("dst", "目标地址"), ("kind", "类型")):
            tree.heading(key, text=label)
            tree.column(key, width=180)
        tree.pack(fill="both", expand=True, padx=8)
        page = [0]
        status = browser.tk.StringVar()
        controls = browser.ttk.Frame(dialog, padding=8)
        controls.pack(fill="x")
        def render() -> None:
            tree.delete(*tree.get_children())
            for index in range(page[0], min(page[0] + 250, len(references))):
                reference = references[index]
                tree.insert("", "end", iid=str(index), values=(
                    f"{reference.src.address:#x} · {reference.src.source}",
                    f"{reference.dst.address:#x} · {reference.dst.source}" if reference.dst else reference.target,
                    reference.kind))
            status.set(f"{page[0] + 1 if references else 0}–{min(page[0] + 250, len(references))} / {len(references)}")
            children = tree.get_children()
            if children:
                tree.selection_set(children[0])
        def change_page(delta: int) -> None:
            page[0] = max(0, min(page[0] + delta * 250,
                                max(0, (len(references) - 1) // 250 * 250)))
            render()
        def follow_reference(_event: Any = None) -> str:
            selected = tree.selection()
            if selected and self.index:
                target = references[int(selected[0])]
                destination = target.src if direction == "incoming" else target.dst
                if destination:
                    dialog.destroy()
                    self.navigate(destination)
                else:
                    status.set(f"目标 {target.target} 没有已解析地址")
            return "break"
        browser.ttk.Button(controls, text="上一页", command=lambda: change_page(-1)).pack(side="left")
        browser.ttk.Button(controls, text="下一页", command=lambda: change_page(1)).pack(side="left", padx=4)
        browser.ttk.Label(controls, textvariable=status).pack(side="left", padx=8)
        browser.ttk.Button(controls, text="跳转", command=follow_reference).pack(side="right")
        browser.ttk.Button(controls, text="关闭", command=dialog.destroy).pack(side="right", padx=8)
        tree.bind("<Return>", follow_reference)
        tree.bind("<Double-1>", follow_reference)
        dialog.bind("<Escape>", lambda _event: dialog.destroy())
        render()
        dialog.grab_set()
        tree.focus_set()

    def graph_navigate(self, address: int) -> None:
        self.graph_select(address)
        current = self.current
        self.navigate(Location(address, current.source if current else "",
                               current.address_space if current else "native"))

    def graph_select(self, address: int) -> None:
        self._search_serial += 1
        index = self.browser.cfg_choice.current()
        source, space = "", "native"
        if 0 <= index < len(self.browser._cfgs):
            cfg = self.browser._cfgs[index]
            if self.browser._view._snapshot.get("kind") in {"apk", "dex", "jar", "class"}:
                source = cfg.get("source", "")
                space = cfg.get("address_space", "file_offset")
        self.history.visit(Location(address, source, space))
        self._update_address()

    def toggle_graph(self) -> None:
        browser = self.browser
        if str(browser._cfg_tab) == browser.notebook.select():
            if self.current:
                self.navigate(self.current, remember=False)
            else:
                self.show_table("Disassembly")
            return
        if self.current is None or self.index is None:
            return
        try:
            function = self.index.function_at(self.current)
        except ValueError as exc:
            browser.status.set(str(exc))
            return
        if function is None or function.cfg_index is None:
            browser.status.set("当前位置没有已生成的 CFG")
            return
        browser.cfg_choice.current(function.cfg_index)
        browser._show_cfg()
        browser.notebook.select(browser._cfg_tab)
        browser.graph_view.select_address(self.current.address)
        browser.graph_view.canvas.focus_set()

    def rename(self) -> None:
        if self.index is None or self.current is None or not self.enabled("rename_symbol"):
            return
        try:
            function = self.index.function_at(self.current)
        except ValueError as exc:
            self.browser.status.set(str(exc))
            return
        if function is None:
            self.browser.status.set("当前位置没有可重命名的函数")
            return
        self.select_row(function.table, function.row_index)
        # Selection may be on a later page; wait for the same guarded insert.
        serial, generation = self._serial, self.browser._generation
        def rename_when_ready(attempts: int = 0) -> None:
            if serial != self._serial or generation != self.browser._generation:
                return
            selected = self.browser._tables[function.table].selection()
            if selected == (str(function.row_index),):
                self.browser.rename_symbol()
            elif attempts < 30:
                self.browser.root.after(5, rename_when_ready, attempts + 1)
        rename_when_ready()

    def comment(self) -> None:
        if self.current is None or not self.enabled("set_comment"):
            return
        browser = self.browser
        from tkinter import simpledialog
        annotations = browser._view._snapshot.get("metadata", {}).get("user_annotations", {})
        comments = annotations.get("comments", {})
        initial = comments.get(str(self.current.address), comments.get(self.current.address, ""))
        text = simpledialog.askstring("注释", f"{self.current.address:#x} 的注释（留空删除）：",
                                      initialvalue=initial, parent=browser.root)
        if text is not None:
            browser._annotate("set_comment", address=self.current.address, value=text)

    def show_pseudocode(self) -> None:
        browser = self.browser
        if browser.notebook.select() == str(browser._tabs.get("Pseudocode", "")):
            if self.current:
                self.navigate(self.current, remember=False)
            return
        if not browser._rows.get("Pseudocode"):
            # 之前按需生成过当前函数的伪代码时直接显示。
            if self.current is not None and self._open_generated(self.current, remember=False):
                return
            browser.status.set("当前结果没有伪代码；此快捷键只浏览已有结果，按 Ctrl+F5 可为当前函数按需生成")
            return
        self.show_table("Pseudocode")
        if self.index and self.current:
            targets = self.index.find_targets(self.current, table="Pseudocode")
            if not targets:
                try:
                    function = self.index.function_at(self.current)
                except ValueError:
                    function = None
                if function is not None:
                    targets = self.index.find_targets(function.location, table="Pseudocode")
            if targets:
                self.select_row("Pseudocode", targets[0].row_index)
            elif not self._open_generated(self.current, remember=False):
                browser.status.set(f"{self.current.address:#x} 所在函数没有伪代码；"
                                   f"左侧列出全部 {len(browser._rows['Pseudocode'])} 个有伪代码的函数；"
                                   "按 Ctrl+F5 可按需生成")

    # ------------------------------------------------------------------ 伪代码视图
    def _pseudocode_selected(self) -> bool:
        tab = self.browser._tabs.get("Pseudocode") if hasattr(self.browser, "_tabs") else None
        try:
            return tab is not None and self.browser.notebook.select() == str(tab)
        except Exception:
            return False  # 窗口关闭后 notebook 已销毁会抛 TclError；视为不在伪代码页，调用方回退普通跳转

    def _pseudocode_target(self) -> Any:
        """伪代码标签页且代码区有焦点时，返回光标处的跳转目标。"""
        view = getattr(self.browser, "pseudocode_view", None)
        if view is None or not self._pseudocode_selected() or not view.has_focus():
            return None
        return view.target_at_insert()

    def _pseudocode_location(self, address: int) -> Location:
        # 字节码伪代码的地址属于当前成员和文件偏移空间；原生地址使用默认空间。
        current = self.current
        kind = self.browser._view._snapshot.get("kind") if self.browser._view is not None else ""
        if current is not None and kind in {"apk", "dex", "jar", "class"}:
            return Location(address, current.source, current.address_space)
        return Location(address)

    def open_pseudocode(self, location: Location, *, remember: bool = True,
                        focus_code: bool = False) -> bool:
        """若 location 是某个有伪代码函数的入口，则在伪代码视图打开它。"""
        if self.index is None or self.browser._busy:
            return False
        targets = self.index.find_targets(location, table="Pseudocode")
        if not targets:
            # 分析时没有生成、但本次会话按需生成过的函数。
            return self._open_generated(location, remember=remember, focus_code=focus_code, exact=True)
        target = targets[0]
        self._search_serial += 1
        self._unresolved_selection = False
        if remember:
            self.history.visit(target.location)
        self._operand = False
        self._update_address()
        self.select_row("Pseudocode", target.row_index)
        try:
            function = self.index.function_at(target.location)
        except ValueError:
            function = None
        if function is not None:
            self._selecting = True
            try:
                self.browser.workspace.sidebar.select_index(function.row_index)
            finally:
                self._selecting = False
        view = getattr(self.browser, "pseudocode_view", None)
        if focus_code and view is not None:
            view.code.focus_set()
        return True

    # ------------------------------------------------------------------ 按需生成伪代码
    def _function_for(self, location: Location) -> Any:
        if self.index is None:
            return None
        try:
            return self.index.function_at(location)
        except ValueError:
            return None

    def generate_pseudocode(self) -> None:
        """为当前位置所在函数按需生成伪代码（后台线程）；已有伪代码时直接打开。"""
        browser = self.browser
        current = self.current
        if current is None:
            return
        function = self._function_for(current)
        if function is None:
            browser.status.set(f"{current.address:#x} 不在已识别的函数内；先在函数列表或反汇编中选中一个函数")
            return
        if self.open_pseudocode(function.location):
            return  # 分析时已生成或本次会话已按需生成
        request = getattr(browser, "request_pseudocode", None)
        if request is not None:
            request(function.location.address, getattr(function, "name", "") or "")

    def _open_generated(self, location: Location, *, remember: bool = True, focus_code: bool = False,
                        exact: bool = False) -> bool:
        """在伪代码视图显示本次会话按需生成的伪代码；exact 时 location 必须是函数入口。"""
        browser = self.browser
        lookup = getattr(browser, "generated_pseudocode", None)
        view = getattr(browser, "pseudocode_view", None)
        if lookup is None or view is None or browser._busy:
            return False
        row = lookup(location.address)
        if row is None and not exact:
            function = self._function_for(location)
            if function is not None:
                location = function.location
                row = lookup(location.address)
        if row is None:
            return False
        self._search_serial += 1
        self._unresolved_selection = False
        if remember:
            self.history.visit(location)
        self._operand = False
        self._update_address()
        tab = browser._tabs.get("Pseudocode")
        if tab is not None and not self._pseudocode_selected():
            browser.notebook.select(tab)
        if "Pseudocode" in browser._tables and "Pseudocode" not in browser._table_loaded:
            # 标签页切换事件稍后才处理：先加载左侧列表，避免首次加载时清空刚显示的代码。
            browser._render_table_page("Pseudocode", browser._table_pages.get("Pseudocode", 0))
        selected = browser._tables["Pseudocode"].selection() if "Pseudocode" in browser._tables else ()
        if selected:
            browser._tables["Pseudocode"].selection_remove(*selected)
        view.show(row, ("generated", browser._generation, location.address))
        browser.status.set(f"按需生成的伪代码：{row.get('name', '')} @ {location.address:#x}")
        if focus_code:
            view.code.focus_set()
        return True

    def activate_pseudocode_target(self, target: Any, *, disassembly: bool = False) -> bool:
        """处理伪代码中的跳转：函数/地址优先打开伪代码，其次反汇编或其它视图。"""
        view = getattr(self.browser, "pseudocode_view", None)
        if getattr(target, "kind", "") == "label":
            return bool(view is not None and view.activate(target))
        address = getattr(target, "address", None)
        if type(address) is not int or self.index is None:
            return False
        location = self._pseudocode_location(address)
        if not disassembly and target.kind != "string" and self.open_pseudocode(
                location, focus_code=view is not None and view.has_focus()):
            return True
        return self.navigate(location)

    def pseudocode_xrefs(self, address: int) -> None:
        """伪代码右键菜单：查看引用到某个目标地址的位置。"""
        if self.index is None:
            return
        location = self._pseudocode_location(address)
        self._choose_references(self.index.incoming(location), location, "incoming")

    def _find_pseudocode(self) -> None:
        """在代码区查找；当前函数没有更多匹配时继续查找后续有伪代码的函数。"""
        from .pseudocode import code_for_style, find_in_code
        browser = self.browser
        view = browser.pseudocode_view
        rows = browser._rows.get("Pseudocode", [])
        raw = getattr(self, "_find_raw", "")
        query = raw if raw and raw.casefold() == self._find_query else self._find_query
        if view.row is not None:
            found = view.find_next(query)
            if found is not None:
                browser.status.set(f"找到：{view.row.get('name', '')} 第 {view.line_of(found[0])} 行 · "
                                   "F3/Ctrl+T 查找下一处")
                return
        if not rows:
            browser.status.set("当前结果没有伪代码")
            return
        selected = browser._tables["Pseudocode"].selection()
        current = int(selected[0]) if selected and view.row is not None else -1
        style = view.mode.get()
        for step in range(1, len(rows) + 1):
            index = (current + step) % len(rows)
            if find_in_code(code_for_style(rows[index], style)[1], query) is None:
                continue
            if index == current:
                found = view.find_next(query, from_start=True)
                if found is not None:
                    browser.status.set(f"已回到开头：{view.row.get('name', '')} 第 "
                                       f"{view.line_of(found[0])} 行")
                    return
                continue
            view.pending_find = query
            self.select_row("Pseudocode", index)
            self._programmatic_selection = None
            self.record_selected("Pseudocode", index)
            browser.status.set(f"在 {rows[index].get('name', '')} 中找到 · F3/Ctrl+T 查找下一处")
            return
        browser.status.set("未在任何伪代码中找到匹配文本")

    def find_dialog(self) -> None:
        name, _record = self._selected()
        if not name:
            name = "Disassembly"
        from tkinter import simpledialog
        prompt = ("在伪代码中查找文本（不区分大小写，依次查找后续函数）：" if name == "Pseudocode"
                  else f"在 {name} 中查找文本：")
        query = simpledialog.askstring("查找", prompt,
                                       initialvalue=self._find_query, parent=self.browser.root)
        if query is not None:
            self._find_query, self._find_table, self._find_position = query.casefold(), name, -1
            self._find_raw = query
            self.find_next()

    def find_next(self) -> None:
        if not self._find_query:
            self.find_dialog()
            return
        if self._find_table == "Pseudocode" and getattr(self.browser, "pseudocode_view", None) is not None:
            self._search_serial += 1
            self._find_pseudocode()
            return
        rows = self.browser._rows.get(self._find_table, [])
        self._search_serial += 1
        search_serial, generation = self._search_serial, self.browser._generation
        keys = tuple(column[0] for column in self.browser.table_columns.get(self._find_table, ()))
        self.browser.status.set("正在查找…")
        def scan(step: int) -> None:
            if (self.browser._closed or generation != self.browser._generation
                    or search_serial != self._search_serial):
                return
            stop = min(step + 500, len(rows) + 1)
            for current_step in range(step, stop):
                index = (self._find_position + current_step) % len(rows)
                if any(self._find_query in str(rows[index].get(key, "")).casefold() for key in keys):
                    self._find_position = index
                    self.select_row(self._find_table, index)
                    self._programmatic_selection = None
                    self.record_selected(self._find_table, index)
                    self.browser.status.set(f"找到第 {index + 1} 条记录 · 再按 Ctrl+T 查找下一条")
                    return
            if stop <= len(rows):
                self.browser.root.after(1, scan, stop)
            else:
                self.browser.status.set("未找到匹配文本")
        scan(1)

    def show_shortcuts(self) -> None:
        lines = ["IDA 风格导航快捷键", ""]
        lines.extend(f"{shortcut_label(command):18} {command.label}" for command in self.registry.commands())
        lines.extend(("", "输入框内保留正常输入；模态窗口不触发后台命令。",
                      "重命名和注释需要可写的已保存数据库。"))
        self.browser.messagebox.showinfo("快捷键", "\n".join(lines), parent=self.browser.root)

    def close(self) -> None:
        self._serial += 1
        self.binder.close()
