"""_Browser 的分析选项：分析模式、多线程设置和打开文件时的选项对话框。"""
from __future__ import annotations

from pathlib import Path

from .facade import _gui

# 运行时引用的原 fangida.gui 模块级名字（函数、类、常量及 Path 等导入的名字）一律经门面 _gui() 查找，
# 对门面打的补丁因此仍作用于实现，与拆分前一致。


class _AnalysisOptionsMixin:
    """打开文件前选择分析模式与线程预算；取消对话框不改变任何设置。"""

    def open_dialog(self) -> None:
        if self._closed or self._busy or self.open_button.instate(["disabled"]):
            return
        path = self.filedialog.askopenfilename(title="Open a binary or Android file")
        if path and self._choose_analysis_options(path):
            self.open_file(path)

    def _analysis_mode_name(self) -> str:
        if self.full_analysis:
            return "full"
        return "fast" if self.deep_analysis is False else "standard"

    def _apply_analysis_mode(self, mode: str) -> None:
        """Apply an explicit GUI choice while preserving the bounded defaults."""
        if mode not in _gui().ANALYSIS_MODE_LABELS:
            raise ValueError(f"Unknown analysis mode: {mode}")
        if not hasattr(self, "_standard_max_bytes"):
            self._standard_max_bytes = self.max_bytes
            self._standard_deep_analysis = True if self.deep_analysis is False else self.deep_analysis
        self.full_analysis = mode == "full"
        self.max_bytes = None if self.full_analysis else self._standard_max_bytes
        self.deep_analysis = (True if self.full_analysis else False if mode == "fast"
                              else self._standard_deep_analysis)
        self._refresh_mode_status()

    def _threads_label(self) -> str:
        """下次分析的线程设置（状态栏用）。"""
        if getattr(self, "analyze_threads", None) == 1:
            return "单线程"
        if self.semantic_threads is None:
            return "多线程（按配置）"
        if self.semantic_threads == 1:
            return "单线程解码"
        return f"多线程 {self.semantic_threads}"

    def _next_open_label(self) -> str:
        return f"{_gui().ANALYSIS_MODE_LABELS[self._analysis_mode_name()]} · {self._threads_label()}"

    def _refresh_mode_status(self) -> None:
        mode_status = getattr(self, "analysis_mode_status", None)
        if mode_status is not None:
            mode_status.set(f"下次打开：{self._next_open_label()}（打开文件时可选择）")

    def _configured_threads(self, path: str | Path) -> int:
        """未在 GUI 中指定时实际生效的解码线程数（与 _analyze_file 读取同一份分层配置）。"""
        if self.semantic_threads is not None:
            return self.semantic_threads
        try:
            return _gui().load_settings(
                project_dir=_gui().Path(path).expanduser().resolve().parent).semantic_threads
        except (OSError, ValueError):
            return 1

    def _apply_thread_options(self, enabled: bool, threads: int) -> None:
        """应用对话框里的多线程选择。

        开启：解码线程数为 threads，总预算另含一个 xref 线程（由 _analyze_file 计算）；
        完整分析的指令解码按此线程数使用多个子进程并行。
        关闭：总预算为 1，解码与 xref 依次在同一线程执行（线程约束允许的唯一共用情形）。
        """
        if enabled:
            if type(threads) is not int or not 2 <= threads <= 16:
                raise ValueError("threads must be between 2 and 16")
            self.semantic_threads, self.analyze_threads = threads, None
        else:
            self.semantic_threads, self.analyze_threads = 1, 1
        self._refresh_mode_status()

    def _choose_analysis_options(self, path: str | Path) -> bool:
        """Choose the scope before dispatching work; cancelling changes nothing."""
        try:
            kind, _ = _gui().identify_file(path)
        except (OSError, ValueError) as exc:
            self.messagebox.showerror("无法打开文件", str(exc))
            return False
        full_supported = kind in {"elf", "pe", "macho", "apk", "dex", "jar", "class"}
        initial = self._analysis_mode_name()
        if initial == "full" and not full_supported:
            initial = "standard"
        dialog = self.tk.Toplevel(self.root)
        dialog.title("打开文件 · 分析选项")
        dialog.transient(self.root)
        dialog.resizable(False, False)
        body = self.ttk.Frame(dialog, padding=16)
        body.pack(fill="both", expand=True)
        self.ttk.Label(body, text=str(path), wraplength=480).pack(anchor="w", pady=(0, 12))
        mode = self.tk.StringVar(master=dialog, value=initial)
        choices = (
            ("standard", "使用当前扫描范围，按已有配置进行分析。"),
            ("fast", "使用当前扫描范围，跳过深入函数分析。"),
            ("full", ("通过独立 APK Analyzer 插件扫描所有字节码方法、CFG 和 xref；预算不足会标明未完成。"
                      if kind in {"apk", "dex", "jar", "class"} else
                      "扫描全部可执行区域，恢复函数、CFG 和 xref。")),
        )
        for value, description in choices:
            self.ttk.Radiobutton(body, text=_gui().ANALYSIS_MODE_LABELS[value], variable=mode,
                                 value=value,
                                 state="disabled" if value == "full" and not full_supported else "normal"
                                 ).pack(anchor="w")
            self.ttk.Label(body, text=description, wraplength=460).pack(
                anchor="w", padx=(24, 0), pady=(0, 10))
        if not full_supported:
            self.ttk.Label(body, text="此文件类型暂不支持完整分析，可选择常规或快速分析。",
                           wraplength=480).pack(anchor="w", pady=(0, 8))

        # 多线程分析：勾选后可选解码线程数；不勾选时解码与 xref 在同一线程依次执行。
        configured = self._configured_threads(path)
        multi_initial = configured > 1 and getattr(self, "analyze_threads", None) != 1
        fallback = max(2, min(16, _gui().DEFAULT_THREADS))
        multi = self.tk.StringVar(master=dialog, value="1" if multi_initial else "0")
        count = self.tk.StringVar(master=dialog, value=str(configured if multi_initial else fallback))
        threads_row = self.ttk.Frame(body)
        threads_row.pack(anchor="w", fill="x", pady=(4, 0))
        spin = self.ttk.Spinbox(threads_row, from_=2, to=16, increment=1, width=4, textvariable=count,
                                state="normal" if multi_initial else "disabled")

        def toggle_threads() -> None:
            spin.configure(state="normal" if multi.get() == "1" else "disabled")

        self.ttk.Checkbutton(threads_row, text="启用多线程分析", variable=multi, onvalue="1",
                             offvalue="0", command=toggle_threads).pack(side="left")
        self.ttk.Label(threads_row, text="线程数").pack(side="left", padx=(16, 4))
        spin.pack(side="left")
        self.ttk.Label(body, wraplength=460, text=(
            "完整分析时，指令解码按线程数分到多个子进程并行（约 3–5 倍）；交叉引用始终在独立线程中进行。"
            "关闭后解码与交叉引用在同一线程中依次执行，结果相同，只是更慢。")).pack(
            anchor="w", padx=(24, 0), pady=(0, 6))
        error = self.tk.StringVar(master=dialog, value="")
        self.ttk.Label(body, textvariable=error, wraplength=480).pack(anchor="w")
        selected: list[tuple[str, bool, int]] = []

        def confirm() -> None:
            choice = mode.get()
            if choice not in _gui().ANALYSIS_MODE_LABELS or (choice == "full" and not full_supported):
                return
            enabled = multi.get() == "1"
            threads = 1
            if enabled:
                try:
                    threads = int(str(count.get()).strip())
                except ValueError:
                    threads = 0
                if not 2 <= threads <= 16:
                    error.set("线程数须为 2–16 的整数。")
                    return
            selected.append((choice, enabled, threads))
            dialog.destroy()

        buttons = self.ttk.Frame(body)
        buttons.pack(fill="x", pady=(8, 0))
        self.ttk.Button(buttons, text="取消", command=dialog.destroy).pack(side="right")
        start = self.ttk.Button(buttons, text="开始分析", command=confirm)
        start.pack(side="right", padx=(0, 8))
        dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
        dialog.bind("<Escape>", lambda _event: dialog.destroy())
        dialog.bind("<Return>", lambda _event: confirm())
        dialog.grab_set()
        start.focus_set()
        self.root.wait_window(dialog)
        if not selected:
            return False
        choice, enabled, threads = selected[0]
        self._apply_analysis_mode(choice)
        if (enabled, threads if enabled else 1) != (multi_initial, configured if multi_initial else 1):
            # 只有用户改动了多线程选项时才覆盖；未改动时沿用原设置（含“按配置”）。
            self._apply_thread_options(enabled, threads)
        return True
