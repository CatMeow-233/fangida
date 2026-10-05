"""伪代码标签页的 Tk 适配层：左侧函数列表容器、右侧函数头与可滚动代码区。

所有文本规则（分词、高亮区间、函数头、跳转目标、查找）都在纯函数模块
``pseudocode.py`` 中；这里只负责控件、tag 和事件。本模块不导入 Loader、
处理器或分析插件，只显示已完成结果中的 ``pseudoc`` / ``machine_pseudoc``。
"""
from __future__ import annotations

from typing import Any, Callable, Mapping

from .pseudocode import (HIGHLIGHT_TAGS, EMPTY_CONTEXT, JumpTarget, SymbolContext, analyze_code,
                         build_header, code_for_style, code_palette, find_in_code,
                         format_header, group_spans, identifier_at, jump_targets,
                         occurrence_spans, target_at, text_index)

#: 每次 tag_add 传入的区间对数上限，避免超长 Tcl 命令。
_TAG_BATCH = 1500
_MAX_HEADER_LINES = 8


def _add_ranges(widget: Any, tag: str, ranges: list[tuple[int, int]],
                line_starts: tuple[int, ...]) -> None:
    """一次 Tcl 调用为多个区间添加同一个 tag。"""
    for begin in range(0, len(ranges), _TAG_BATCH):
        indexes: list[str] = []
        for start, end in ranges[begin:begin + _TAG_BATCH]:
            indexes.append(text_index(line_starts, start))
            indexes.append(text_index(line_starts, end))
        if indexes:
            widget.tag_add(tag, *indexes)


class PseudocodeView:
    """伪代码专用视图。

    ``list_frame`` 留给调用方放置函数列表（gui.py 复用原有分页表格）；
    ``code`` 是只读代码区（也作为原 ``_details["Pseudocode"]`` 详情控件）；
    ``header`` 显示函数头。回调：

    - ``on_activate(target, disassembly)``：双击/回车/右键菜单跳转到函数或地址；
    - ``on_status(text)``：在状态栏提示；
    - ``on_xrefs(address)``：查看引用到某个地址；
    - ``on_mode_change()``：切换可读/机器视图后由调用方重新显示当前函数；
    - ``on_generate()``（可选）：工具栏“生成伪代码”按钮，为没有伪 C 的当前函数按需生成。
    """

    def __init__(self, parent: Any, tk: Any, ttk: Any, *,
                 on_activate: Callable[[JumpTarget, bool], Any] | None = None,
                 on_status: Callable[[str], None] | None = None,
                 on_xrefs: Callable[[int], None] | None = None,
                 on_mode_change: Callable[[], None] | None = None,
                 palette: str = "dark",
                 on_generate: Callable[[], Any] | None = None) -> None:
        self.tk, self.ttk = tk, ttk
        self.on_activate = on_activate
        self.on_status = on_status
        self.on_xrefs = on_xrefs
        self.on_mode_change = on_mode_change
        self.on_generate = on_generate
        self.colors = code_palette(palette)
        self.context: SymbolContext = EMPTY_CONTEXT
        self._context_factory: Callable[[], SymbolContext] | None = None
        self.row: Mapping[str, Any] | None = None
        self.key: Any = None
        self.style = "readable"
        self.code_text = ""
        self._line_starts: tuple[int, ...] = (0,)
        self._targets: tuple[JumpTarget, ...] = ()
        self._header_links: tuple[JumpTarget, ...] = ()
        self._header_line_starts: tuple[int, ...] = (0,)
        self._hover: tuple[str, int, int] | None = None
        self._find_end = 0
        self.pending_find: str | None = None
        self._positions: dict[Any, tuple[float, str]] = {}
        self._placeholder = ""
        self._menu_target: JumpTarget | None = None

        self.frame = ttk.PanedWindow(parent, orient="horizontal")
        self.list_frame = ttk.Frame(self.frame)
        self.frame.add(self.list_frame, weight=1)
        ttk.Label(self.list_frame, text="有伪代码的函数", padding=(6, 4, 6, 0)).pack(anchor="w")
        right = ttk.Frame(self.frame)
        self.frame.add(right, weight=4)
        self.right = right

        toolbar = ttk.Frame(right, padding=(6, 4))
        toolbar.pack(fill="x")
        ttk.Label(toolbar, text="视图：").pack(side="left")
        self.mode = tk.StringVar(master=right, value="readable")
        self.readable_button = ttk.Radiobutton(toolbar, text="可读伪 C", value="readable",
                                               variable=self.mode, command=self._mode_changed)
        self.readable_button.pack(side="left")
        self.machine_button = ttk.Radiobutton(toolbar, text="机器伪 C", value="machine",
                                              variable=self.mode, command=self._mode_changed,
                                              state="disabled")
        self.machine_button.pack(side="left", padx=(6, 0))
        self.show_header = tk.BooleanVar(master=right, value=True)
        ttk.Checkbutton(toolbar, text="函数头", variable=self.show_header,
                        command=self._toggle_header).pack(side="left", padx=(14, 0))
        # 没有伪 C 的函数：按需生成（后台进行，由调用方的命令体系处理）。
        self.generate_button = None
        if on_generate is not None:
            self.generate_button = ttk.Button(toolbar, text="生成伪代码", command=on_generate)
            self.generate_button.pack(side="left", padx=(14, 0))
        self.info = tk.StringVar(master=right, value="")
        ttk.Label(toolbar, textvariable=self.info, anchor="e").pack(side="right")

        colors = self.colors
        self.header = tk.Text(right, height=5, wrap="word", font="TkFixedFont", state="disabled",
                              relief="flat", borderwidth=0, padx=10, pady=6, cursor="arrow",
                              background=colors["header_background"], foreground=colors["foreground"],
                              selectbackground=colors["select_background"],
                              highlightthickness=0, takefocus=False)
        self.header.pack(fill="x")
        body = ttk.Frame(right)
        body.pack(fill="both", expand=True)
        self._body = body
        self.code = tk.Text(body, wrap="none", font="TkFixedFont", state="disabled", undo=False,
                            padx=10, pady=6, background=colors["background"],
                            foreground=colors["foreground"], insertbackground=colors["insert"],
                            selectbackground=colors["select_background"],
                            inactiveselectbackground=colors["select_background"],
                            highlightthickness=0, borderwidth=0, takefocus=True)
        vertical = ttk.Scrollbar(body, orient="vertical", command=self.code.yview)
        horizontal = ttk.Scrollbar(body, orient="horizontal", command=self.code.xview)
        self.code.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        body.columnconfigure(0, weight=1)
        body.rowconfigure(0, weight=1)
        self.code.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        self._configure_tags()
        self._bind_events()
        self._sash_placed = False
        self.frame.bind("<Configure>", self._place_sash, add="+")
        self.header.bind("<Configure>", lambda _event: self._fit_header(), add="+")
        self._menu = tk.Menu(self.code, tearoff=False)
        self._menu.add_command(label="打开（伪代码优先）", command=lambda: self._menu_activate(False))
        self._menu.add_command(label="跳转到反汇编", command=lambda: self._menu_activate(True))
        self._menu.add_command(label="查看引用到此目标", command=self._menu_xrefs)
        self._menu.add_separator()
        self._menu.add_command(label="复制选中文本", command=self.copy_selection)
        self._menu.add_command(label="复制全部伪代码", command=self.copy_all)
        self.show_message("")

    # ------------------------------------------------------------------ 配置
    def _configure_tags(self) -> None:
        colors = self.colors
        for widget in (self.code, self.header):
            widget.tag_configure("current_line", background=colors["current_line"])
            widget.tag_configure("occurrence", background=colors["occurrence"])
            for tag in HIGHLIGHT_TAGS:
                widget.tag_configure(tag, foreground=colors[tag])
            widget.tag_configure("hover", underline=True)
            widget.tag_configure("flash", background=colors["flash"])
            widget.tag_configure("find", background=colors["find"], foreground="#ffffff")
        for tag in ("header_name", "header_label", "header_signature", "header_note",
                    "header_warning", "header_ok"):
            self.header.tag_configure(tag, foreground=colors[tag])
        self.header.tag_configure("header_link", foreground=colors["link"])
        # 后配置的 tag 优先级更高：查找、悬停覆盖语法颜色，当前行在最底层。
        self.code.tag_lower("current_line")
        self.code.tag_lower("occurrence")
        self.code.tag_raise("find")
        self.code.tag_raise("sel")

    def _bind_events(self) -> None:
        code, header = self.code, self.header
        # 禁用状态的 Text 在 X11/macOS 点击时不会自动获得焦点；显式获取，
        # 以便方向键移动光标、回车跟随、Ctrl+F 在代码区查找。
        code.bind("<Button-1>", lambda _event: code.focus_set(), add="+")
        code.bind("<ButtonRelease-1>", lambda _event: self._cursor_moved(), add="+")
        code.bind("<KeyRelease>", self._key_released, add="+")
        code.bind("<Motion>", lambda event: self._hover_at(code, event), add="+")
        code.bind("<Leave>", lambda _event: self._clear_hover(), add="+")
        code.bind("<Double-1>", lambda event: self._double_click(event, False), add="+")
        code.bind("<Shift-Double-1>", lambda event: self._double_click(event, True), add="+")
        for sequence in ("<Button-3>", "<Control-Button-1>"):
            code.bind(sequence, self._popup, add="+")
        try:
            if str(code.tk.call("tk", "windowingsystem")) == "aqua":
                code.bind("<Button-2>", self._popup, add="+")
        except Exception:
            pass
        header.bind("<Motion>", lambda event: self._hover_at(header, event), add="+")
        header.bind("<Leave>", lambda _event: self._clear_hover(), add="+")
        header.bind("<ButtonRelease-1>", self._header_click, add="+")

    def _place_sash(self, event: Any) -> None:
        """首次获得尺寸时把函数列表限制在约 26% 宽度，让代码区占据主要空间。"""
        if self._sash_placed or getattr(event, "width", 0) < 200:
            return
        self._sash_placed = True
        width = int(event.width)
        try:
            self.frame.sashpos(0, max(200, min(300, width * 26 // 100)))
        except Exception:
            pass

    def _toggle_header(self) -> None:
        if self.show_header.get():
            self.header.pack(fill="x", before=self._body)
        else:
            self.header.pack_forget()

    def _fit_header(self) -> None:
        """按实际折行后的显示行数设置函数头高度（2～8 行，更多内容可滚动）。"""
        header = self.header
        try:
            counted = header.tk.call(header._w, "count", "-displaylines", "1.0", "end-1c")
            lines = int(counted) + 1
        except Exception:
            lines = int(str(header.index("end-1c")).split(".")[0])
        lines = max(2, min(_MAX_HEADER_LINES, lines))
        if int(header.cget("height")) != lines:
            header.configure(height=lines)

    # ------------------------------------------------------------------ 数据
    def set_context(self, context: SymbolContext | None = None, *,
                    factory: Callable[[], SymbolContext] | None = None) -> None:
        """更换符号上下文；factory 在首次显示代码时才调用（延迟构建）。"""
        self.context = context if context is not None else EMPTY_CONTEXT
        self._context_factory = None if context is not None else factory
        self._positions.clear()
        self.invalidate()

    def _ensure_context(self) -> SymbolContext:
        if self._context_factory is not None:
            factory, self._context_factory = self._context_factory, None
            try:
                self.context = factory()
            except Exception:
                self.context = EMPTY_CONTEXT  # 符号增强可选；失败时只少了跳转链接
        return self.context

    def invalidate(self) -> None:
        """代码区被外部清空或重写；下次 show 必须重新渲染。"""
        self.key = None

    def replace_text(self, value: str) -> None:
        """gui.py 的 _set_text 写入代码区时走这里：保存滚动位置并清除函数状态。

        写入后控件内容与旧 ``_set_text`` 完全相同（只读、原样文本），
        但不再对应某个函数，因此函数头回到提示信息。
        """
        self._save_position()
        self.invalidate()
        self.row = None
        self.code_text = value
        self._targets = ()
        self._find_end = 0
        self._line_starts = analyze_code(value).line_starts if value else (0,)
        self._clear_hover()
        code = self.code
        code.configure(state="normal")
        code.delete("1.0", "end")
        code.insert("1.0", value)
        code.configure(state="disabled")
        if not value:
            self._write_header(self._placeholder, (), ())
            self.info.set("")

    def show_message(self, message: str) -> None:
        """设置无选择时的提示（例如没有伪代码的原因），并立即显示在函数头区域。"""
        self._placeholder = message
        if self.row is None:
            self._write_header(message, (), ())

    # ------------------------------------------------------------------ 显示
    def show(self, row: Mapping[str, Any], key: Any = None) -> None:
        """显示一个函数；同一 key 和视图已显示时不重复渲染。"""
        requested = self.mode.get()
        if key is not None and key == self.key and row is self.row and requested == self.style:
            self._run_pending_find()
            return
        self._save_position()
        context = self._ensure_context()
        style, code = code_for_style(row, requested)
        machine_available = isinstance(row.get("machine_pseudoc"), str) and bool(row.get("machine_pseudoc"))
        self.machine_button.configure(state="normal" if machine_available else "disabled")
        self.row, self.key, self.style = row, key, style
        self.code_text = code
        model = analyze_code(code)
        self._line_starts = model.line_starts
        widget = self.code
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", code)
        for tag, ranges in group_spans(model.spans).items():
            _add_ranges(widget, tag, ranges, model.line_starts)
        widget.configure(state="disabled")
        self._targets = jump_targets(code, row, context)
        self._find_end = 0
        self._clear_hover()
        header = build_header(row, style=style, context=context)
        formatted = format_header(header)
        self._write_header(formatted.text, formatted.links, formatted.spans)
        note = "" if style == requested else "（无机器视图，显示可读视图）"
        if row.get("pseudoc_on_demand"):
            note += " · 按需生成"
        self.info.set(f"{header.line_count} 行 · {header.status}{note}")
        position = self._positions.get((key, style))
        if position is not None:
            widget.yview_moveto(position[0])
            widget.mark_set("insert", position[1])
        else:
            widget.yview_moveto(0.0)
            widget.mark_set("insert", "1.0")
        self._cursor_moved(update_occurrences=False)
        self._run_pending_find()

    def _write_header(self, text: str, links: tuple[JumpTarget, ...], spans: tuple[Any, ...]) -> None:
        header = self.header
        header.configure(state="normal")
        header.delete("1.0", "end")
        header.insert("1.0", text.rstrip("\n"))
        starts = analyze_code(text).line_starts if text else (0,)
        for tag, ranges in group_spans(spans).items():
            _add_ranges(header, tag, ranges, starts)
        if links:
            _add_ranges(header, "header_link", [(item.start, item.end) for item in links], starts)
        header.configure(state="disabled")
        self._header_links = links
        self._header_line_starts = starts
        self._fit_header()

    def _save_position(self) -> None:
        if self.key is None or self.row is None:
            return
        try:
            first = float(self.code.yview()[0])
            insert = str(self.code.index("insert"))
        except Exception:
            return
        self._positions[(self.key, self.style)] = (first, insert)
        if len(self._positions) > 256:
            self._positions.pop(next(iter(self._positions)))

    def _mode_changed(self) -> None:
        if self.on_mode_change is not None:
            self.on_mode_change()
        elif self.row is not None:
            self.show(self.row, self.key)

    # ------------------------------------------------------------------ 位置换算
    def _offset(self, widget: Any, index: str) -> int:
        line, column = (int(part) for part in str(widget.index(index)).split("."))
        starts = self._line_starts if widget is self.code else self._header_line_starts
        if not starts:
            return 0
        line = min(max(1, line), len(starts))
        return starts[line - 1] + column

    def offset_at_insert(self) -> int:
        return self._offset(self.code, "insert")

    def target_at_insert(self) -> JumpTarget | None:
        """光标处的跳转目标（回车跟随、X 查看引用使用）。"""
        if not self._targets:
            return None
        return target_at(self._targets, self.offset_at_insert())

    def _target_at_event(self, widget: Any, event: Any) -> JumpTarget | None:
        offset = self._offset(widget, f"@{event.x},{event.y}")
        # "@x,y" 返回最近字符；只有指针确实落在字符框内才算命中。
        try:
            box = widget.bbox(f"@{event.x},{event.y}")
        except Exception:
            box = None
        if (not box or not box[0] <= event.x <= box[0] + box[2] + 1
                or not box[1] <= event.y <= box[1] + box[3] + 1):
            return None
        targets = self._targets if widget is self.code else self._header_links
        item = target_at(targets, offset)
        if item is not None and item.start <= offset < item.end:
            return item
        return None

    def has_focus(self) -> bool:
        try:
            return self.code.focus_get() is self.code
        except Exception:
            return False

    # ------------------------------------------------------------------ 事件
    def _describe(self, target: JumpTarget, *, header: bool = False) -> str:
        click = "单击" if header else "双击"
        if target.kind == "label":
            return f"{click}跳到标签 {target.text}"
        if target.address is None:
            return ""
        what = {"string": "字符串", "global": "全局对象", "address": "地址"}.get(target.kind, "函数")
        label = target.name or target.text
        if target.kind == "string":
            label = target.text if len(target.text) <= 50 else target.text[:49] + "…"
        has_code = target.address in self.context.pseudocode_starts
        action = (f"{click}打开伪代码" + ("" if header else "，Shift+双击查看反汇编")) if has_code else f"{click}跳转"
        return f"{what} {label} @ {target.address:#x} · {action}"

    def _hover_at(self, widget: Any, event: Any) -> None:
        target = self._target_at_event(widget, event)
        key = (str(widget), target.start, target.end) if target is not None else None
        if key == self._hover:
            return
        self._clear_hover()
        if target is None:
            return
        starts = self._line_starts if widget is self.code else self._header_line_starts
        widget.tag_add("hover", text_index(starts, target.start), text_index(starts, target.end))
        widget.configure(cursor="hand2")
        self._hover = key
        if self.on_status is not None:
            self.on_status(self._describe(target, header=widget is self.header))

    def _clear_hover(self) -> None:
        if self._hover is None:
            return
        self._hover = None
        for widget, cursor in ((self.code, "xterm"), (self.header, "arrow")):
            widget.tag_remove("hover", "1.0", "end")
            widget.configure(cursor=cursor)
        if self.on_status is not None:
            self.on_status("")  # 调用方恢复悬停前的状态栏文字

    def _key_released(self, event: Any) -> None:
        if getattr(event, "keysym", "") in {"Up", "Down", "Left", "Right", "Home", "End",
                                             "Prior", "Next"}:
            self._cursor_moved()

    def _cursor_moved(self, *, update_occurrences: bool = True) -> None:
        code = self.code
        code.tag_remove("current_line", "1.0", "end")
        code.tag_add("current_line", "insert linestart", "insert lineend+1c")
        if not update_occurrences:
            code.tag_remove("occurrence", "1.0", "end")
            return
        self.highlight_occurrences()

    def highlight_occurrences(self) -> int:
        """高亮光标处标识符的全部出现，返回出现次数。"""
        code = self.code
        code.tag_remove("occurrence", "1.0", "end")
        found = identifier_at(self.code_text, self.offset_at_insert()) if self.code_text else None
        if found is None:
            return 0
        spans = occurrence_spans(self.code_text, found[2])
        if len(spans) > 1:
            _add_ranges(code, "occurrence", list(spans), self._line_starts)
        return len(spans)

    def _double_click(self, event: Any, disassembly: bool) -> str | None:
        target = self._target_at_event(self.code, event)
        if target is None:
            return None  # 保留 Text 默认的选词行为
        self.activate(target, disassembly=disassembly)
        return "break"

    def _header_click(self, event: Any) -> str | None:
        target = self._target_at_event(self.header, event)
        if target is None:
            return None
        self.activate(target, disassembly=False)
        return "break"

    def activate(self, target: JumpTarget, *, disassembly: bool = False) -> bool:
        """执行跳转：标签在本函数内定位，其余交给调用方的导航。"""
        if target.kind == "label" and target.label_offset is not None:
            self.goto_offset(target.label_offset, length=len(target.text))
            return True
        if self.on_activate is None:
            return False
        return bool(self.on_activate(target, disassembly))

    def goto_offset(self, offset: int, *, length: int = 0) -> None:
        """滚动到偏移处并短暂高亮（用于 goto 标签与查找结果）。"""
        start = text_index(self._line_starts, offset)
        code = self.code
        code.mark_set("insert", start)
        code.see(start)
        code.tag_remove("flash", "1.0", "end")
        code.tag_add("flash", f"{start} linestart", f"{start} lineend+1c")
        code.after(900, lambda: self._remove_tag("flash"))
        self._cursor_moved()

    def _remove_tag(self, tag: str) -> None:
        try:
            self.code.tag_remove(tag, "1.0", "end")
        except Exception:
            pass  # 控件已销毁

    def _popup(self, event: Any) -> str:
        self.code.focus_set()
        self._menu_target = self._target_at_event(self.code, event)
        if self._menu_target is None:
            self.code.mark_set("insert", f"@{event.x},{event.y}")
            self._menu_target = self.target_at_insert()
        target = self._menu_target
        addressed = target is not None and (target.address is not None or target.kind == "label")
        for index in (0, 1):
            self._menu.entryconfigure(index, state="normal" if addressed else "disabled")
        self._menu.entryconfigure(2, state="normal" if target is not None and target.address is not None
                                  and self.on_xrefs is not None else "disabled")
        self._menu.tk_popup(event.x_root, event.y_root)
        return "break"

    def _menu_activate(self, disassembly: bool) -> None:
        if self._menu_target is not None:
            self.activate(self._menu_target, disassembly=disassembly)

    def _menu_xrefs(self) -> None:
        target = self._menu_target
        if target is not None and target.address is not None and self.on_xrefs is not None:
            self.on_xrefs(target.address)

    def copy_selection(self) -> None:
        try:
            text = self.code.get("sel.first", "sel.last")
        except Exception:
            return
        self.code.clipboard_clear()
        self.code.clipboard_append(text)

    def copy_all(self) -> None:
        if self.code_text:
            self.code.clipboard_clear()
            self.code.clipboard_append(self.code_text)

    # ------------------------------------------------------------------ 查找
    def find_next(self, query: str, *, from_start: bool = False) -> tuple[int, int] | None:
        """在当前代码中从上次匹配之后查找；找到后选中、滚动并返回区间。"""
        if not self.code_text or not query:
            return None
        start = 0 if from_start else self._find_end
        found = find_in_code(self.code_text, query, start)
        if found is None:
            return None
        self._find_end = found[1] if found[1] > found[0] else found[0] + 1
        begin, end = (text_index(self._line_starts, value) for value in found)
        code = self.code
        code.tag_remove("find", "1.0", "end")
        code.tag_remove("sel", "1.0", "end")
        code.tag_add("find", begin, end)
        code.tag_add("sel", begin, end)
        code.mark_set("insert", begin)
        code.see(begin)
        self._cursor_moved(update_occurrences=False)
        return found

    def line_of(self, offset: int) -> int:
        return int(text_index(self._line_starts, offset).split(".")[0])

    def _run_pending_find(self) -> None:
        query, self.pending_find = self.pending_find, None
        if query:
            self.find_next(query, from_start=True)
