"""_Browser 的后台任务：打开文件或数据库、分析与存储工作线程、渐进式预览和结果投递。

工作线程只做分析、存储与结果准备，经 _messages 队列把结果交给 Tk 线程；_drain 在 Tk
线程中轮询队列并更新控件。分析、存储、_prepare 等原模块级名字在调用时经 fangida.gui 门面查找。
"""
from __future__ import annotations

import logging
import queue
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .facade import _gui
from .operations import _Loaded  # 仅用于注解（保持 typing.get_type_hints 可解析）

# gui_modules 不直接导入 api、dispatcher、plugins 等分析实现（见 tests/test_gui_workbench.py 的依赖检查）：
# 注解里的 AnalysisView 由 fangida.gui 门面注入本模块（保持 typing.get_type_hints 可解析）；
# 运行时引用的原 fangida.gui 模块级名字（AnalysisView、AnalysisService、PluginManager、Path 等导入的
# 名字，以及函数、类和常量）一律经门面 _gui() 查找，对门面打的补丁因此仍作用于实现，与拆分前一致。

_log = logging.getLogger(__name__)


@dataclass
class _GeneratedPseudocode:
    """后台按需生成伪代码的结果消息（经 _messages 队列交给 Tk 线程）。"""
    start: int
    row: dict[str, Any] | None = None
    error: Exception | None = None


@dataclass
class _PseudocodeJobs:
    """一次结果（generation）内的按需伪代码状态：上下文、已生成的行与进行中的请求。

    rows、pending 只在 Tk 线程读写；waiting、running、cancelled 由 lock 保护，Tk 线程与工作线程
    共用。每个结果至多一个工作线程（fangida-gui-pseudocode）按排队顺序逐个生成：连续请求多个
    函数时只排队，不再为每个请求新开线程（纯 Python 的生成会争 GIL 与上下文锁，界面会变卡）。
    """
    generation: int
    context: Any = None
    rows: dict[int, dict[str, Any]] = field(default_factory=dict)
    pending: set[int] = field(default_factory=set)
    #: 已请求、尚未开始生成的函数：(起点, 快照, 指令上限)；后请求的先生成（见 _next_pseudocode_job）。
    waiting: list[tuple[int, Any, int | None]] = field(default_factory=list)
    running: bool = False
    cancelled: bool = False
    lock: Any = field(default_factory=threading.Lock, repr=False, compare=False)


class _JobsMixin:
    """打开与结果投递在 Tk 线程；_worker、_start_preview、_preview_worker、_database_worker、
    _pseudocode_worker 在工作线程运行。"""

    def _database_info(self) -> dict[str, Any]:
        if self._view is None:
            return {}
        return self._view._snapshot.get("metadata", {}).get("analysis_database", {})

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        self.open_button.configure(state="disabled" if busy else "normal")
        self.open_database_button.configure(state="disabled" if busy else "normal")
        has_view = self._view is not None and not busy
        self.export_button.configure(state="normal" if has_view else "disabled")
        self.save_database_button.configure(state="normal" if has_view else "disabled")
        info = self._database_info()
        kind = self._view._snapshot.get("kind", "") if self._view is not None else ""
        # 没有数据库时也可用：点击后先引导保存为 .fdb，再写入标注。只读数据库与 APK/JAR 仍不可写。
        editable = has_view and not info.get("read_only") and kind not in {"apk", "jar"}
        self.rename_button.configure(state="normal" if editable else "disabled")
        self.comment_button.configure(state="normal" if editable else "disabled")

    def open_database_dialog(self) -> None:
        if self._busy:
            return
        path = self.filedialog.askopenfilename(title="Open analysis database",
                   filetypes=(("Fangida analysis database", "*.fdb"), ("All files", "*.*")))
        if path:
            self.open_database(path)

    def open_file(self, path: str | Path) -> None:
        if self._closed or self._busy:
            return
        generation = self._begin_open(path, f"{_gui().ANALYSIS_MODE_LABELS[self._analysis_mode_name()]}中…")
        worker = threading.Thread(target=self._worker, args=(generation, path), daemon=True,
                                  name="fangida-gui-analysis")
        worker.start()

    def _begin_open(self, path: str | Path, action: str) -> int:
        self._generation += 1
        generation = self._generation
        self._view = None
        # 旧结果的标注索引与按需伪代码状态都引用旧快照：不在这里释放的话，它们要等新结果显示后
        # 首次标注或生成伪代码时才被替换，整个新分析期间旧快照一直存活。两者都只是可重建的缓存
        # （标注索引按快照身份失效，伪代码状态按 generation 惰性重建），提前释放不改变行为。
        cache = getattr(self, "_annotation_cache", None)
        if cache is not None:
            cache.clear()
        jobs = getattr(self, "_pseudocode_job_state", None)
        if jobs is not None:
            # 与 _pseudocode_jobs 换代时相同：排队的请求不再生成；正在生成的那一个完成后，
            # 它的工作线程随即退出，发出的结果因 generation 不符被 _drain 丢弃。
            with jobs.lock:
                jobs.cancelled = True
                jobs.waiting.clear()
            self._pseudocode_job_state = None
        if hasattr(self, "workbench"):
            self.workbench.reset()
            self.workspace.log(f"{action} {path}")
        self._hex_path = None
        self._hex_identity = None
        self._hex_previous = self._hex_next = None
        self.hex_go.configure(state="disabled")
        self.hex_prev.configure(state="disabled")
        self.hex_next.configure(state="disabled")
        self.hex_range.set(action)
        self._set_text(self.hex_text, "")
        self._cfgs = []
        self._cfg_rows = []
        self._cfg_dirty = False
        self.cfg_choice.configure(state="disabled", values=())
        self.cfg_selection.set("")
        self.cfg_jump.configure(state="disabled")
        self.cfg_status.set(action)
        self.cfg_tree.delete(*self.cfg_tree.get_children())
        self._set_text(self.cfg_detail, "")
        self._set_busy(True)
        self.file_label.configure(text=str(path))
        self.status.set(f"{action} {_gui().Path(path).name}")
        self._set_text(self.summary, f"{action} {path}\n")
        for name, tree in self._tables.items():
            tree.delete(*tree.get_children())
            self._rows[name] = []
            self._set_text(self._details[name], "")
            self._tabs[name].master.tab(self._tabs[name], text=self._tab_caption(name))
        self._reset_table_pages()
        view = getattr(self, "pseudocode_view", None)
        if view is not None:
            view.set_context(None)
            view.show_message(f"{action} {path}")
        return generation

    def open_database(self, path: str | Path, snapshot_id: int | None = None) -> None:
        if self._closed or self._busy:
            return
        generation = self._begin_open(path, "Opening database…")
        worker = threading.Thread(target=self._database_worker,
                                  args=(generation, "open", path, snapshot_id), daemon=True,
                                  name="fangida-gui-storage")
        worker.start()

    def _worker(self, generation: int, path: str | Path) -> None:
        try:
            budget = getattr(self, "analyze_threads", None)
            options: dict[str, Any] = {"analyze_threads": budget} if budget is not None else {}
            if self.full_analysis:
                # 渐进式结果：解码完成就先显示反汇编和函数列表，CFG/xref/伪代码随后替换。
                options["on_preview"] = lambda preview: self._start_preview(generation, preview)
            view = _gui()._analyze_file(path, self.max_bytes, self.use_ghidra, self.deep_analysis,
                                        self.semantic_threads, self.full_analysis, **options)
            if self.database_path is not None:
                view = _gui()._save_database_view(view, self.database_path,
                                                   storage_plugin=self.storage_plugin)
            result: _Loaded | Exception = _gui()._prepare(view, share_completed=True)
        except Exception as exc:
            result = exc
        self._messages.put((generation, result))

    def _start_preview(self, generation: int, preview: Any) -> None:
        """在分析线程中被调用：只启动预览准备线程并立即返回，不阻塞分析。"""
        threading.Thread(target=self._preview_worker, args=(generation, preview), daemon=True,
                         name="fangida-gui-preview").start()

    def _preview_worker(self, generation: int, preview: Any) -> None:
        # 整个预览准备期间暂停自动循环 GC：后台线程里一旦触发完整回收，可能析构遗留的 Tk 对象，
        # 而 Tk 对象在非主线程析构时每个要等约 1 秒（tkinter 的线程限制）。与分析阶段同一机制。
        from .._gc import bulk_allocation
        try:
            with bulk_allocation():
                loaded = _gui()._prepare(_gui().AnalysisView._from_owned_result(preview),
                                         share_completed=True)
        except Exception:
            # 预览只是提前显示；失败时等待最终结果即可。只在预览（部分结果）上出现的缺陷不会在最终结果中
            # 重现，静默返回会让它无声消失，因此记 debug 日志备查。
            _log.debug("预览结果准备失败，等待最终结果", exc_info=True)
            return
        loaded.preview = True
        self._messages.put((generation, loaded))

    def _database_worker(self, generation: int, operation: str, path: str | Path | None,
                          snapshot_id: int | None = None, view: AnalysisView | None = None,
                          address: int | None = None, value: str = "") -> None:
        try:
            if operation == "open":
                loaded = _gui()._database_view(path, snapshot_id, storage_plugin=self.storage_plugin)
            elif operation == "save":
                loaded = _gui()._save_database_view(view, path, storage_plugin=self.storage_plugin)
            elif operation.startswith("save_then_"):
                # 还没有数据库：先把当前结果保存为 .fdb，再在新数据库上写入这条标注。
                saved = _gui()._save_database_view(view, path, storage_plugin=self.storage_plugin)
                loaded = _gui()._annotate_owned_view(saved, operation.removeprefix("save_then_"), address,
                                                     value, storage_plugin=self.storage_plugin,
                                                     cache=getattr(self, "_annotation_cache", None))
            else:
                loaded = _gui()._annotate_owned_view(view, operation, address, value,
                                                     storage_plugin=self.storage_plugin,
                                                     cache=getattr(self, "_annotation_cache", None))
            result: _Loaded | Exception = _gui()._prepare(loaded, share_completed=True)
        except Exception as exc:
            result = exc
        self._messages.put((generation, result))

    def _drain(self) -> None:
        if self._closed:
            return
        while True:
            try:
                generation, result = self._messages.get_nowait()
            except queue.Empty:
                break
            if generation != self._generation:
                continue
            if isinstance(result, _GeneratedPseudocode):
                # 按需生成的伪代码：不改变忙碌状态，也不重新载入结果。
                self._pseudocode_generated(result)
                continue
            preview = bool(getattr(result, "preview", False))
            if preview and getattr(self, "_completed_generation", None) == generation:
                continue  # 最终结果已先到达：迟到的预览直接丢弃
            if not preview:
                self._completed_generation = generation
            # 预览期间分析仍在进行：保持忙碌状态（不能打开、保存或编辑），但可以浏览。
            self._set_busy(preview)
            if isinstance(result, Exception):
                self.status.set("Operation failed")
                if self._view is None:
                    self._set_text(self.summary, f"Operation failed: {result}\n")
                else:
                    # Starting a storage edit invalidated the previous batch
                    # callbacks. Resume from the completed cached rows after
                    # failure without analysing or hashing the input again.
                    self._restart_table_rows()
                self.messagebox.showerror("Fangida operation failed", str(result))
                if hasattr(self, "workspace"):
                    self.workspace.log(f"操作失败：{result}")
                continue
            self._view = result.view
            self.status.set(f"{result.kind.upper()} · {result.status} · "
                            f"{_gui().Path(result.path).name}")
            if preview:
                self.status.set(f"预览 · 反汇编与函数列表可浏览，正在恢复 CFG、交叉引用和伪代码… · "
                                f"{_gui().Path(result.path).name}")
            info = self._database_info()
            if info.get("read_only"):
                self.status.set(self.status.get() + " · read-only database")
            self.file_label.configure(text=f"{_gui().Path(info['path']).name} · {_gui().Path(result.path).name}"
                                      if info.get("path") else str(result.path))
            self._hex_path = result.hex_path
            self._hex_identity = result.hex_identity
            self.hex_go.configure(state="normal" if self._hex_path is not None else "disabled")
            if self._hex_path is not None:
                self._show_hex_page(0)
            else:
                self._hex_previous = self._hex_next = None
                self.hex_prev.configure(state="disabled")
                self.hex_next.configure(state="disabled")
                self.hex_range.set(result.hex_unavailable)
                self._set_text(self.hex_text, result.hex_unavailable + "\n")
            self._cfgs = result.cfgs
            if self._cfgs:
                labels = [f"{item['name']} ({item['start']:#x})"
                          if isinstance(item.get("start"), int) else item["name"]
                          for item in self._cfgs]
                self.cfg_choice.configure(values=labels, state="readonly")
                self.cfg_choice.current(0)
                self._cfg_dirty = True
            else:
                self.cfg_status.set("CFG 正在恢复，完成后自动显示…" if preview else
                                    "No CFG in this result; inspect Overview for analysis limits")
            self._set_busy(preview)
            self._set_text(self.summary, result.summary)
            for name, tree in self._tables.items():
                tree.delete(*tree.get_children())
                self._rows[name] = []
                self._set_text(self._details[name], "")
                self._tabs[name].master.tab(self._tabs[name], text=self._tab_caption(name))
            for name, rows in result.tables.items():
                self._rows[name] = rows
                self._tabs[name].master.tab(self._tabs[name], text=self._tab_caption(name, len(rows)))
            self._load_pseudocode_view(result)
            self._reset_table_pages()
            self._show_selected_tab()
            if hasattr(self, "workbench"):
                self.workbench.load(result)
                current_mode = ("完整分析（预览，分析进行中）" if preview else
                                "完整分析" if result.view._snapshot.get("stats", {}).get("full_analysis") else "已保存 / 已完成结果")
                if preview:
                    self.workspace.log("预览已显示：完整结果稍后自动替换，当前浏览位置会保留")
                self.analysis_mode_status.set(
                    f"当前结果：{current_mode} · 下次打开：{self._next_open_label()}（打开时可选择）")
            if result.status == "error":
                self.messagebox.showerror("Fangida analysis failed",
                                          "\n".join(result.warnings) or
                                          "Analyzer returned an error. See Overview for details.")
        self.root.after(50, self._drain)

    def _load_pseudocode_view(self, result: _Loaded) -> None:
        """为新结果设置伪代码符号表与提示；符号表缺失时首次显示再建立。"""
        view = getattr(self, "pseudocode_view", None)
        if view is None:
            return
        from .pseudocode import no_pseudocode_message, placeholder_message
        rows = self._rows.get("Pseudocode", [])
        context = getattr(result, "pseudocode_context", None)
        tables = dict(self._rows)
        view.set_context(context, factory=None if context is not None
                         else (lambda: _gui()._pseudocode_context(tables)))
        snapshot = result.view._snapshot
        native = snapshot.get("metadata", {}).get("architecture") in {"x86", "x86_64", "arm", "arm64"}
        if rows:
            view.show_message(placeholder_message(len(rows), generate_hint=native))
        else:
            message = no_pseudocode_message(snapshot.get("stats", {}), result.kind)
            if native:
                message += "\n也可以选中函数后按 Ctrl+F5（或点击“生成伪代码”）为它按需生成。"
            view.show_message(message)

    # ------------------------------------------------------------------ 按需生成伪代码
    def _pseudocode_jobs(self) -> _PseudocodeJobs:
        """当前结果的按需伪代码状态；打开新结果或标注后（generation 变化）自动丢弃旧状态。"""
        jobs = getattr(self, "_pseudocode_job_state", None)
        if jobs is None or jobs.generation != self._generation:
            if jobs is not None:
                # 旧结果还在排队的请求不再生成；正在生成的那一个完成后，它的工作线程随即退出。
                with jobs.lock:
                    jobs.cancelled = True
                    jobs.waiting.clear()
            jobs = self._pseudocode_job_state = _PseudocodeJobs(self._generation)
        return jobs

    def generated_pseudocode(self, start: int) -> dict[str, Any] | None:
        """本次会话为当前结果按需生成的伪代码行（没有时返回 None）。"""
        if self._view is None:
            return None
        return self._pseudocode_jobs().rows.get(start)

    def request_pseudocode(self, start: int, name: str = "") -> bool:
        """在后台线程为起点为 start 的函数生成伪代码；界面在生成期间保持可操作。"""
        if self._closed or self._busy or self._view is None or type(start) is not int:
            return False
        jobs = self._pseudocode_jobs()
        label = name or f"{start:#x}"
        if start in jobs.rows:
            workbench = getattr(self, "workbench", None)
            if workbench is not None:
                workbench._open_generated(_gui_location(start))
            return True
        if start in jobs.pending:
            self.status.set(f"{label} 的伪代码正在后台生成…")
            return True
        if jobs.context is None:
            # 构造上下文不做分析；第一次生成时在工作线程中构建（名字、链接、签名与参数传播）。
            jobs.context = _gui().PseudocContext(self._view._snapshot)
        jobs.pending.add(start)
        limit = getattr(self, "pseudoc_max_instructions", None)
        with jobs.lock:
            others = len(jobs.waiting) + int(jobs.running)  # 其它尚未完成的请求（含正在生成的）
            jobs.waiting.append((start, self._view._snapshot, limit))
            spawn = not jobs.running
            jobs.running = True
        if spawn:
            # 每个结果至多一个工作线程：它逐个处理排队的请求，队列空了就退出。
            threading.Thread(target=self._pseudocode_queue_worker, args=(jobs,),
                             daemon=True, name="fangida-gui-pseudocode").start()
            self.status.set(f"正在后台生成 {label} 的伪代码…（界面可继续操作）")
        else:
            self.status.set(f"已排队生成 {label} 的伪代码（另有 {others} 个请求未完成）…（界面可继续操作）")
        if hasattr(self, "workspace"):
            self.workspace.log(f"按需生成伪代码：{label} @ {start:#x}")
        return True

    def _next_pseudocode_job(self, jobs: _PseudocodeJobs) -> tuple[int, Any, int | None] | None:
        """取下一个排队的请求；没有请求、结果已更换或窗口已关闭时登记线程退出并返回 None。

        后请求的先生成：用户通常停在最后请求的那个函数上，它的结果最先显示；更早的请求随后完成。
        """
        with jobs.lock:
            if jobs.cancelled or getattr(self, "_closed", False) or not jobs.waiting:
                jobs.running = False
                jobs.waiting.clear()
                return None
            return jobs.waiting.pop()

    def _pseudocode_queue_worker(self, jobs: _PseudocodeJobs) -> None:
        """工作线程：依次生成排队的函数（每个结果至多一个这样的线程）。"""
        try:
            while True:
                job = self._next_pseudocode_job(jobs)
                if job is None:
                    return
                start, snapshot, limit = job
                self._pseudocode_worker(jobs.generation, jobs.context, snapshot, start, limit)
        except BaseException:
            # _pseudocode_worker 自己捕获生成错误；这里只防止意外退出后队列再也没有线程处理。
            with jobs.lock:
                jobs.running = False
            raise

    def _pseudocode_worker(self, generation: int, context: Any, snapshot: dict[str, Any], start: int,
                           limit: int | None) -> None:
        """工作线程：只读取已完成快照生成伪 C，结果经 _messages 队列交给 Tk 线程。"""
        # 与预览准备相同：期间暂停自动循环 GC，避免在工作线程析构遗留的 Tk 对象。
        from .._gc import bulk_allocation
        from .records import generated_pseudocode_row
        try:
            if limit is None:
                try:
                    limit = _gui().load_settings().pseudoc_max_instructions
                except Exception:
                    limit = 512
            with bulk_allocation():
                function = next((item for item in snapshot.get("functions", ())
                                 if isinstance(item, dict) and item.get("start") == start
                                 and (item.get("blocks") or item.get("disassembly")
                                      or item.get("cfg", {}).get("blocks"))), None)
                if function is None:
                    raise ValueError(f"{start:#x} 处没有带指令的函数")
                generated = context.generate(function, max_instructions=limit)
                message = _GeneratedPseudocode(start, generated_pseudocode_row(function, generated))
        except Exception as exc:
            message = _GeneratedPseudocode(start, error=exc)
        self._messages.put((generation, message))

    def _pseudocode_generated(self, message: _GeneratedPseudocode) -> None:
        """Tk 线程：登记生成结果；当前位置仍在该函数时直接显示，否则在状态栏提示。"""
        jobs = self._pseudocode_jobs()
        jobs.pending.discard(message.start)
        if message.error is not None or message.row is None:
            self.status.set(f"生成伪代码失败：{message.error}")
            if hasattr(self, "workspace"):
                self.workspace.log(f"生成伪代码失败（{message.start:#x}）：{message.error}")
            return
        jobs.rows[message.start] = message.row
        name = message.row.get("name") or f"{message.start:#x}"
        workbench = getattr(self, "workbench", None)
        current = workbench.current if workbench is not None else None
        function = workbench._function_for(current) if workbench is not None and current is not None else None
        here = function is not None and function.location.address == message.start
        if workbench is not None and here and not self._busy:
            # 用户仍停在该函数：直接显示；已离开时不打断当前浏览，只提示。
            workbench._open_generated(function.location, remember=False)
        else:
            self.status.set(f"{name} 的伪代码已生成；回到该函数按 Tab/F5 查看")
        if hasattr(self, "workspace"):
            self.workspace.log(f"伪代码已生成：{name} @ {message.start:#x}")


def _gui_location(address: int) -> Any:
    from .navigation import Location
    return Location(address)
