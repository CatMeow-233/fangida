"""_Browser 的表格分页：按页分批插入行，切换标签页时才渲染当前页。"""
from __future__ import annotations

from .facade import _gui

# 运行时引用的原 fangida.gui 模块级名字（函数、类、常量及 Path 等导入的名字）一律经门面 _gui() 查找，
# 对门面打的补丁因此仍作用于实现，与拆分前一致。


class _TablePagesMixin:
    """结果表的分页状态、翻页、跳页与分批插入；只在 Tk 线程调用。"""

    def _restart_table_rows(self) -> None:
        # Preserve the page selected before a failed storage edit. Hidden tabs
        # stay empty until selected; all records remain in _rows for export and
        # subsequent pages.
        loaded = set(getattr(self, "_table_loaded", self._tables))
        for name, tree in self._tables.items():
            tree.delete(*tree.get_children())
            self._set_text(self._details[name], "")
            rows = self._rows.get(name, [])
            self._tabs[name].master.tab(self._tabs[name],
                                       text=self._tab_caption(name, len(rows) if rows else None))
        if not hasattr(self, "_table_loaded"):
            # Retain the original controller's direct batch entry point for
            # callers that construct it without the new optional page state.
            for name in loaded:
                self._insert_chunk(name, self._generation, 0)
            return
        self._table_loaded.clear()
        self._show_selected_tab()

    def _reset_table_pages(self) -> None:
        self._table_pages = {name: 0 for name in self._tables}
        self._table_tokens = {name: token + 1 for name, token in
                              getattr(self, "_table_tokens", {}).items()}
        self._table_loaded = set()
        for name in self._tables:
            self._update_table_page_controls(name)

    def _show_selected_tab(self) -> None:
        if self._closed:
            return
        notebook = getattr(self, "notebook", None)
        if notebook is None:
            return
        selected = notebook.select()
        for name, tab in self._tabs.items():
            if str(tab) == selected:
                if name not in self._table_loaded:
                    self._render_table_page(name, self._table_pages.get(name, 0))
                return
        if (getattr(self, "_cfg_dirty", False) and
                str(getattr(self, "_cfg_tab", "")) == selected):
            self._cfg_dirty = False
            self._show_cfg()

    def _update_table_page_controls(self, name: str) -> None:
        total = len(self._rows.get(name, []))
        start = getattr(self, "_table_pages", {}).get(name, 0)
        end = min(start + _gui().TABLE_PAGE_ROWS, total)
        page_count = max(1, (total + _gui().TABLE_PAGE_ROWS - 1) // _gui().TABLE_PAGE_ROWS)
        page_number = start // _gui().TABLE_PAGE_ROWS + 1
        if name in getattr(self, "_table_page_status", {}):
            self._table_page_status[name].set(
                f"{start + 1 if total else 0}–{end} / {total} 条 · "
                f"第 {page_number}/{page_count} 页")
        if name in getattr(self, "_table_page_numbers", {}):
            self._table_page_numbers[name].set(str(page_number))
        if name in getattr(self, "_table_previous", {}):
            self._table_previous[name].configure(state="normal" if start else "disabled")
        if name in getattr(self, "_table_next", {}):
            self._table_next[name].configure(state="normal" if end < total else "disabled")

    def _render_table_page(self, name: str, start: int) -> None:
        rows = self._rows.get(name, [])
        last = ((len(rows) - 1) // _gui().TABLE_PAGE_ROWS) * _gui().TABLE_PAGE_ROWS if rows else 0
        start = min(max(0, start // _gui().TABLE_PAGE_ROWS * _gui().TABLE_PAGE_ROWS), last)
        self._table_pages[name] = start
        token = self._table_tokens.get(name, 0) + 1
        self._table_tokens[name] = token
        self._table_loaded.add(name)
        tree = self._tables[name]
        tree.delete(*tree.get_children())
        self._set_text(self._details[name], "")
        self._update_table_page_controls(name)
        self._insert_chunk(name, self._generation, start, token)

    def _change_table_page(self, name: str, direction: int) -> None:
        self._render_table_page(name, self._table_pages.get(name, 0) +
                                direction * _gui().TABLE_PAGE_ROWS)

    def _jump_table_page(self, name: str) -> None:
        try:
            page = int(self._table_page_numbers[name].get())
            page_count = max(1, (len(self._rows.get(name, [])) + _gui().TABLE_PAGE_ROWS - 1) //
                              _gui().TABLE_PAGE_ROWS)
            if not 1 <= page <= page_count:
                raise ValueError
        except (ValueError, TypeError):
            self._table_page_status[name].set("请输入范围内的页码")
            return
        self._render_table_page(name, (page - 1) * _gui().TABLE_PAGE_ROWS)

    def _insert_chunk(self, name: str, generation: int, start: int,
                       page_token: int | None = None) -> None:
        if self._closed or generation != self._generation:
            return
        if page_token is not None and page_token != self._table_tokens.get(name):
            return
        rows = self._rows[name]
        tree = self._tables[name]
        keys = tuple(column[0] for column in _gui().TABLE_COLUMNS[name])
        page_start = getattr(self, "_table_pages", {}).get(name, 0)
        end = min(page_start + _gui().TABLE_PAGE_ROWS, len(rows))
        navigation = getattr(getattr(self, "workbench", None), "index", None)
        hidden = {"pseudoc"} if name == "Pseudocode" else ()
        for index in range(start, min(start + 200, end)):
            row = rows[index]
            values = []
            for key in keys:
                if key in hidden:
                    values.append("")  # 完整伪 C 在代码区显示，隐藏列不再复制大文本
                    continue
                value = row.get(key)
                if name == "Pseudocode" and key == "start" and value is None:
                    value = row.get("code_offset")  # 字节码方法以代码偏移定位
                if name == "Strings" and key == "address":
                    if navigation is not None:
                        value = tuple(location.address for location in
                                      navigation.locations_for_row(name, index, field="address"))
                    elif value is None:
                        value = row.get("addresses")
                values.append(_gui()._display(value, key))
            tree.insert("", "end", iid=str(index), values=tuple(values))
        if start + 200 < end:
            if page_token is None:
                self.root.after(1, self._insert_chunk, name, generation, start + 200)
            else:
                self.root.after(1, self._insert_chunk, name, generation, start + 200, page_token)
