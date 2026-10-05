"""_Browser 的十六进制视图：按文件偏移分页读取已校验的原始字节。"""
from __future__ import annotations

from typing import Any

from .facade import _gui

# 运行时引用的原 fangida.gui 模块级名字（函数、类、常量及 Path 等导入的名字）一律经门面 _gui() 查找，
# 对门面打的补丁因此仍作用于实现，与拆分前一致。


class _HexViewMixin:
    """十六进制标签页的构建、翻页与定位；只在 Tk 线程调用。"""

    def _make_hex_tab(self, notebook: Any) -> None:
        frame = self.ttk.Frame(notebook, padding=6)
        self._hex_tab = frame
        notebook.add(frame, text=self._tab_caption("Hex"))
        controls = self.ttk.Frame(frame)
        controls.pack(fill="x", pady=(0, 6))
        self.ttk.Label(controls, text="File offset (decimal or 0x hex):").pack(side="left")
        self.hex_offset = self.tk.StringVar(value="0x0")
        entry = self.ttk.Entry(controls, textvariable=self.hex_offset, width=18)
        entry.pack(side="left", padx=5)
        entry.bind("<Return>", lambda _event: self.seek_hex())
        self.hex_go = self.ttk.Button(controls, text="Go", command=self.seek_hex, state="disabled")
        self.hex_go.pack(side="left")
        self.hex_prev = self.ttk.Button(controls, text="Previous page", command=self.previous_hex,
                                        state="disabled")
        self.hex_prev.pack(side="left", padx=(14, 4))
        self.hex_next = self.ttk.Button(controls, text="Next page", command=self.next_hex,
                                        state="disabled")
        self.hex_next.pack(side="left")
        self.hex_range = self.tk.StringVar(value="Open a file to inspect its bytes")
        self.ttk.Label(frame, textvariable=self.hex_range).pack(anchor="w", pady=(0, 4))
        body = self.ttk.Frame(frame)
        body.pack(fill="both", expand=True)
        self.hex_text = self.tk.Text(body, wrap="none", font="TkFixedFont", state="disabled")
        vertical = self.ttk.Scrollbar(body, orient="vertical", command=self.hex_text.yview)
        horizontal = self.ttk.Scrollbar(body, orient="horizontal", command=self.hex_text.xview)
        self.hex_text.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        body.columnconfigure(0, weight=1)
        body.rowconfigure(0, weight=1)
        self.hex_text.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")

    def _show_hex_page(self, offset: int) -> None:
        if self._hex_path is None:
            return
        try:
            page = _gui().hex_page(self._hex_path, offset, expected_identity=self._hex_identity)
        except (OSError, ValueError) as exc:
            if isinstance(exc, OSError):
                self._hex_path = None
                self._hex_identity = None
                self.hex_go.configure(state="disabled")
            self._hex_previous = self._hex_next = None
            self.hex_prev.configure(state="disabled")
            self.hex_next.configure(state="disabled")
            self.hex_range.set(f"Hex view unavailable: {exc}")
            self._set_text(self.hex_text, f"Hex view unavailable: {exc}\n")
            self.status.set("Hex disabled; reopen the source or database"
                            if isinstance(exc, OSError) else "Hex read failed")
            return
        self._hex_previous, self._hex_next = page["previous_offset"], page["next_offset"]
        self.hex_offset.set(f"{page['start']:#x}")
        self.hex_prev.configure(state="normal" if self._hex_previous is not None else "disabled")
        self.hex_next.configure(state="normal" if self._hex_next is not None else "disabled")
        self.hex_range.set(f"File offset {page['start']:#x}–{page['end']:#x} "
                           f"of {page['size']:#x} bytes · 16 bytes per row")
        self._set_text(self.hex_text, page["text"])

    def seek_hex(self) -> None:
        if self._hex_path is None:
            return
        try:
            offset = _gui().parse_seek_offset(self.hex_offset.get())
        except ValueError as exc:
            self.hex_range.set(str(exc))
            return
        self._show_hex_page(offset)

    def previous_hex(self) -> None:
        if self._hex_previous is not None:
            self._show_hex_page(self._hex_previous)

    def next_hex(self) -> None:
        if self._hex_next is not None:
            self._show_hex_page(self._hex_next)
