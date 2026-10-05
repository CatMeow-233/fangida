"""_Browser 的数据库与标注操作：保存分析数据库、重命名函数、添加注释和导出 JSON。"""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from .facade import _gui

# 运行时引用的原 fangida.gui 模块级名字（函数、类、常量及 Path 等导入的名字）一律经门面 _gui() 查找，
# 对门面打的补丁因此仍作用于实现，与拆分前一致。


class _StorageMixin:
    """保存数据库与写入标注；写入在存储线程执行，结果经 _drain 回到 Tk 线程。"""

    def _start_storage_edit(self, operation: str, path: str | Path | None = None,
                            address: int | None = None, value: str = "") -> None:
        if self._view is None or self._busy or self._closed:
            return
        if operation in {"rename_symbol", "set_comment", "save_then_rename_symbol", "save_then_set_comment"}:
            if self._database_info().get("read_only"):
                self.messagebox.showerror("无法写入", "当前数据库为只读。")
                return
            if self._view._snapshot.get("kind") in {"apk", "jar"}:
                self.messagebox.showerror("无法写入", "当前数据库标注按整数地址存储，"
                    "尚不能区分 APK/JAR 的成员。此位置暂不支持写入标注。")
                return
        self._generation += 1
        self._set_busy(True)
        self.status.set("正在保存分析数据库并写入标注…" if operation.startswith("save_then_") else
                        "Saving analysis database…")
        threading.Thread(target=self._database_worker,
                         args=(self._generation, operation, path, None, self._view, address, value),
                         daemon=True, name="fangida-gui-storage").start()

    def _annotate(self, operation: str, *, address: int, value: str) -> None:
        """写入名字/注释；当前结果还没有分析数据库时，先询问并保存为 .fdb，再写入。"""
        if self._view is None or self._busy or self._closed:
            return
        if self._database_info().get("path"):
            self._start_storage_edit(operation, address=address, value=value)
            return
        source = _gui().Path(str(self._view._snapshot.get("path", ""))).expanduser()
        if not source.is_file():
            self.messagebox.showerror("无法保存标注", "名字和注释保存在分析数据库中，首次保存需要原始文件，"
                                      f"但找不到：{source}")
            return
        if not self.messagebox.askyesno("需要分析数据库",
                "名字和注释保存在分析数据库（.fdb）中，当前结果还没有保存。\n"
                "现在把分析结果保存为数据库，然后写入这条标注吗？"):
            return
        path = self.filedialog.asksaveasfilename(title="保存分析数据库", initialdir=str(source.parent),
                   initialfile=source.name + ".fdb", defaultextension=".fdb",
                   filetypes=(("Fangida analysis database", "*.fdb"), ("All files", "*.*")))
        if path:
            self._start_storage_edit("save_then_" + operation, path, address=address, value=value)

    def save_database(self) -> None:
        if self._view is None or self._busy:
            return
        info = self._database_info()
        if info.get("path"):
            self.status.set(f"Names and comments are already saved in {info['path']}")
            return
        source = self._view._snapshot.get("path", "")
        if not _gui().Path(source).expanduser().is_file():
            self.messagebox.showerror("Save database failed",
                "The original source is required to verify the first saved snapshot. "
                "Open an existing database to browse or annotate without the source.")
            return
        path = self.filedialog.asksaveasfilename(title="Save analysis database",
                   defaultextension=".fdb", filetypes=(("Fangida analysis database", "*.fdb"),
                                                      ("All files", "*.*")))
        if path:
            self._start_storage_edit("save", path)

    def _selected_record(self, name: str) -> dict[str, Any] | None:
        selected = self._tables[name].selection()
        rows = self._rows.get(name, [])
        if selected and int(selected[0]) < len(rows):
            return rows[int(selected[0])]
        return None

    def rename_symbol(self) -> None:
        if self._view is None or self._busy:
            return
        record = self._selected_record("Functions")
        address = record.get("start", record.get("code_offset")) if record else None
        if type(address) is not int:
            self.messagebox.showinfo("Rename symbol", "Select an addressed function in Functions first")
            return
        from tkinter import simpledialog
        name = simpledialog.askstring("Rename function", f"Name at {address:#x}:",
                                       initialvalue=record.get("name", ""), parent=self.root)
        if name is not None:
            self._annotate("rename_symbol", address=address, value=name)

    def set_comment(self) -> None:
        if self._view is None or self._busy:
            return
        from tkinter import simpledialog
        selected_tab = self.notebook.select()
        address = None
        for tab_name, tab in self._tabs.items():
            if str(tab) != selected_tab:
                continue
            record = self._selected_record(tab_name)
            if record:
                for key in ("start", "addr", "address", "code_offset", "src"):
                    if type(record.get(key)) is int:
                        address = record[key]
                        break
        value = simpledialog.askstring("Comment address", "Address (decimal or 0x hex):",
                                        initialvalue=f"{address:#x}" if address is not None else "",
                                        parent=self.root)
        if value is None:
            return
        try:
            address = _gui().parse_seek_offset(value)
        except ValueError as exc:
            self.messagebox.showerror("Invalid address", str(exc))
            return
        text = simpledialog.askstring("Comment", f"Comment at {address:#x} (empty removes it):",
                                       parent=self.root)
        if text is not None:
            self._annotate("set_comment", address=address, value=text)

    def export_json(self) -> None:
        if self._view is None:
            return
        path = self.filedialog.asksaveasfilename(title="Export analysis JSON",
                                                  defaultextension=".json",
                                                  filetypes=(("JSON", "*.json"), ("All files", "*.*")))
        if not path:
            return
        try:
            saved = self._view.export_json(path)
        except OSError as exc:
            self.messagebox.showerror("Export failed", str(exc))
        else:
            self.status.set(f"Saved {saved}")
