"""已完成结果经过真实 Tk 工作区后的导航与快捷键整合验证。

窗口始终 withdraw；通过 Tcl 调用 Tk 登记的事件回调，不抢用户桌面的
真实键盘焦点。focus_get 仅在调用期间指向被测试的真实控件。
"""
from __future__ import annotations

import ast
from contextlib import ExitStack
from pathlib import Path
import re
import time
import unittest
from unittest.mock import Mock, patch

from fangida.api import AnalysisView
from fangida.gui import _Browser, TABLE_PAGE_ROWS, _prepare
from fangida.gui_modules.navigation import Location
from fangida.models import AnalysisResult


BASE = 0x1000
TARGET_INDEX = 1300
TARGET = BASE + TARGET_INDEX * 4


def _view(path="/nonexistent/fangida-workbench-fixture.elf", *, read_only=False,
          renamed=False):
    instructions = [{"addr": BASE + index * 4, "size": 4, "mnemonic": "nop",
                     "operands": [], "reads": [], "writes": [], "branch_info": {},
                     "arch_meta": {}}
                    for index in range(1602)]
    instructions[0].update(mnemonic="jmp", operands=[hex(TARGET)],
                           branch_info={"kind": "jump", "target": TARGET})
    functions = []
    for index, name in ((0, "entry"), (TARGET_INDEX, "renamed_target" if renamed else "target")):
        start = instructions[index]["addr"]
        functions.append({"start": start, "name": name, "size": 16,
            "blocks": [{"start": start, "instructions": instructions[index:index + 2],
                        "successors": [start + 8]},
                       {"start": start + 8, "instructions": instructions[index + 2:index + 4],
                        "successors": []}],
            "cfg": {"entry": start, "complete": True,
                    "edges": [{"src": start + 4, "dst": start + 8, "kind": "fallthrough"}],
                    "frontier": []}})
    return AnalysisView(AnalysisResult(path=path, kind="elf", analyzer="kkagent", status="partial",
        metadata={"entry_address": BASE, "architecture": "x86_64",
            "sections": [{"name": ".text", "address": BASE, "offset": 0,
                          "size": len(instructions) * 4, "executable": True}],
            "full_disassembly": instructions,
            "analysis_database": {"path": "/nonexistent/workbench-fixture.fdb",
                                  "read_only": read_only},
            "user_annotations": {"names": {str(TARGET): "renamed_target"} if renamed else {},
                                 "comments": {}}},
        functions=functions, strings=[{"offset": 3, "length": 5, "value": "hello"}],
        xrefs=[{"src": BASE, "dst": TARGET, "kind": "jmp"},
               {"src": BASE + 68 * 4, "dst": TARGET, "kind": "call"},
               {"src": TARGET + 4, "dst": TARGET + 8, "kind": "call"}],
        stats={"full_analysis": True}))


class GuiWorkbenchIntegrationTests(unittest.TestCase):
    def setUp(self):
        try:
            import tkinter as tk
            from tkinter import ttk
            self.root = tk.Tk()
        except Exception as exc:
            self.skipTest(f"当前环境无法创建 Tk 窗口：{exc}")
        self.root.withdraw()
        self.callback_errors = []
        self.root.report_callback_exception = lambda kind, value, tb: self.callback_errors.append(value)
        self.browser = _Browser(self.root, tk, ttk, Mock(), Mock(), None, False, True,
                                semantic_threads=2, full_analysis=True)
        self.addCleanup(self._close)
        self._load(_view())

    def _close(self):
        for identifier in self.root.tk.splitlist(self.root.tk.call("after", "info")):
            # Timers can belong to a Canvas or another child. Cancel only the
            # Tcl timer here; each widget releases its own Python commands at
            # destroy, avoiding deletion through the wrong owner's registry.
            self.root.tk.call("after", "cancel", identifier)
        self.browser.close()

    def _pump(self, predicate=None):
        import _tkinter
        deadline = time.monotonic() + 1.5
        remaining = 1000
        while True:
            handled = self.root.tk.dooneevent(_tkinter.DONT_WAIT)
            if self.callback_errors:
                self.fail(f"Tk 回调出现错误：{self.callback_errors!r}")
            if predicate is not None and predicate():
                return
            if predicate is None and not handled:
                return
            remaining -= 1
            if time.monotonic() >= deadline or not remaining:
                self.fail("Tk 导航未在限定时间内完成")
            time.sleep(0.002)

    def _load(self, view):
        with patch("fangida.gui._verified_hex_source", return_value=(None, "fixture has no source", None)):
            loaded = _prepare(view, share_completed=True)
        self.browser._messages.put((self.browser._generation, loaded))
        self.browser._drain()
        self._pump(lambda: self.browser._tables["Disassembly"].selection() != ())
        return loaded

    def _event(self, identifier, focus, *, keysym="", state=0):
        # Tk Misc._substitute 的 19 项标准事件替换参数。
        values = ("1", "0", "0", "0", "0", str(state), "0", "0", "0", "0", "",
                  "0", keysym, "0", str(focus), "2", "0", "0", "0")
        with patch.object(self.root, "focus_get", return_value=focus):
            result = self.root.tk.call(identifier, *values)
        self.assertEqual(self.callback_errors, [])
        # Tcl 从 Python 回调收到的 None 会字符串化；绑定脚本仅检查 break。
        return None if result == "None" else result

    def _key(self, sequence, focus=None, *, state=0):
        identifier = dict(self.browser.workbench.binder._bindings)[sequence]
        return self._event(identifier, focus or self.browser._tables["Disassembly"], state=state)

    def _binding(self, widget, sequence):
        script = widget.bind(sequence)
        match = re.search(r"\[([^\s]+)", script)
        self.assertIsNotNone(match, f"控件未绑定 {sequence}")
        return match.group(1)

    def _navigate(self, address):
        self.assertTrue(self.browser.workbench.navigate(Location(address)))
        expected = str((address - BASE) // 4)
        self._pump(lambda: self.browser._tables["Disassembly"].selection() == (expected,))

    def test_cross_page_navigation_and_old_generation_callbacks_cannot_override_new_source(self):
        browser, workbench = self.browser, self.browser.workbench
        callbacks = []
        with patch.object(self.root, "after", side_effect=lambda delay, callback, *args:
                          callbacks.append((callback, args)) or f"captured-{len(callbacks)}"):
            self.assertTrue(workbench.navigate(Location(TARGET)))
        self.assertEqual(browser._table_pages["Disassembly"], TABLE_PAGE_ROWS)
        self.assertLess(len(browser._tables["Disassembly"].get_children()), 1000)
        self.assertTrue(callbacks)
        old_generation = browser._generation
        browser._generation += 1
        self._load(_view("/nonexistent/other-workbench-fixture.elf"))
        for callback, args in callbacks:
            callback(*args)
        self._pump()
        self.assertEqual(browser._generation, old_generation + 1)
        self.assertEqual(workbench.current, Location(BASE))
        self.assertEqual(browser._tables["Disassembly"].selection(), ("0",))
        self.assertTrue(all(int(iid) < 1000 for iid in browser._tables["Disassembly"].get_children()))
        self._navigate(TARGET)
        self.assertEqual(browser._tables["Disassembly"].selection(), (str(TARGET_INDEX),))
        self.assertEqual(browser._table_pages["Disassembly"], 1000)

    def test_sidebar_double_click_branch_follow_and_history_restore(self):
        browser, workbench = self.browser, self.browser.workbench
        sidebar = browser.workspace.sidebar
        self.assertTrue(sidebar.select_index(1))
        self._event(self._binding(sidebar.tree, "<Double-1>"), sidebar.tree)
        self._pump(lambda: browser._tables["Disassembly"].selection() == (str(TARGET_INDEX),))
        self.assertEqual(workbench.current, Location(TARGET))
        self.assertEqual(browser.notebook.select(), str(browser._tabs["Disassembly"]))
        self._navigate(BASE)
        self.assertEqual(self._key("<Return>"), "break")
        self._pump(lambda: workbench.current == Location(TARGET) and
                   browser._tables["Disassembly"].selection() == (str(TARGET_INDEX),))
        self.assertEqual(self._key("<Escape>"), "break")
        self._pump(lambda: browser._tables["Disassembly"].selection() == ("0",))
        self.assertEqual(workbench.current, Location(BASE))
        self.assertEqual(self._key("<Control-Return>", state=4), "break")
        self._pump(lambda: browser._tables["Disassembly"].selection() == (str(TARGET_INDEX),))
        self.assertEqual(workbench.current, Location(TARGET))

    def test_graph_text_switch_preserves_address_without_running_analysis(self):
        self._navigate(TARGET + 4)
        browser, workbench = self.browser, self.browser.workbench
        current, history = workbench.current, workbench.history.entries
        with ExitStack() as stack:
            for target in ("fangida.gui._analyze_file", "fangida.gui.AnalysisService",
                           "fangida.processors.decoder.NativeDecoder.decode_bytes",
                           "fangida.processors.decoder.NativeDecoder.decode_bytes_fast",
                           "fangida.xrefs.XrefStage.run"):
                stack.enter_context(patch(target, side_effect=AssertionError("浏览结果不能启动分析")))
            self.assertEqual(self._key("<space>"), "break")
            self._pump()
            self.assertEqual(browser.notebook.select(), str(browser._cfg_tab))
            self.assertEqual(browser.graph_view.selected_address, TARGET + 4)
            self.assertEqual(len(browser.graph_view.layout.blocks), 2)
            self.assertEqual(workbench.current, current)
            self.assertEqual(self._key("<space>", browser.graph_view.canvas), "break")
            self._pump(lambda: browser._tables["Disassembly"].selection() == (str(TARGET_INDEX + 1),))
        self.assertEqual(browser.notebook.select(), str(browser._tabs["Disassembly"]))
        self.assertEqual(workbench.current, current)
        self.assertEqual(workbench.history.entries, history)

    def _xref_dialog(self):
        import tkinter as tk
        dialogs = [child for child in self.root.winfo_children() if isinstance(child, tk.Toplevel)]
        self.assertEqual(len(dialogs), 1)
        dialog = dialogs[0]
        trees = [child for child in dialog.winfo_children() if child.winfo_class() == "Treeview"]
        self.assertEqual(len(trees), 1)
        return dialog, trees[0]

    def test_incoming_outgoing_shortcuts_show_real_dialog_with_correct_direction(self):
        self._navigate(TARGET)
        self.assertEqual(self._key("<Control-x>", state=4), "break")
        dialog, tree = self._xref_dialog()
        self.assertEqual(dialog.title(), f"引用到 {TARGET:#x}")
        values = [tree.item(item, "values") for item in tree.get_children()]
        self.assertEqual(len(values), 2)
        self.assertEqual({row[0].split()[0] for row in values}, {hex(BASE), hex(BASE + 68 * 4)})
        self.assertTrue(all(row[1].split()[0] == hex(TARGET) for row in values))
        self.assertIsNotNone(self.root.grab_current())
        self.assertIn(self._key("<space>"), (None, ""))
        dialog.destroy()
        self._navigate(BASE)
        self.assertEqual(self._key("<Control-j>", state=4), "break")
        dialog, tree = self._xref_dialog()
        self.assertEqual(dialog.title(), f"引用自 {BASE:#x}")
        values = [tree.item(item, "values") for item in tree.get_children()]
        self.assertEqual(len(values), 1)
        self.assertEqual(values[0][0].split()[0], hex(BASE))
        self.assertEqual(values[0][1].split()[0], hex(TARGET))
        dialog.destroy()

    def test_real_entry_focus_keeps_single_key_input_and_readonly_database_cannot_edit(self):
        browser, workbench = self.browser, self.browser.workbench
        entry = browser.workspace.sidebar.entry
        history, selected_tab = workbench.history.entries, browser.notebook.select()
        with patch("tkinter.simpledialog.askstring", side_effect=AssertionError("输入框内不能触发命令")):
            for sequence in ("<KeyPress-g>", "<KeyPress-n>", "<space>", "<Tab>"):
                self.assertIn(self._key(sequence, entry), (None, ""))
        entry.insert(0, "g n ")
        self.assertEqual(entry.get(), "g n ")
        self.assertEqual(workbench.history.entries, history)
        self.assertEqual(browser.notebook.select(), selected_tab)
        self._load(_view(read_only=True))
        self.assertFalse(workbench.registry.is_enabled("rename_symbol"))
        self.assertFalse(workbench.registry.is_enabled("set_comment"))
        with patch.object(browser, "_start_storage_edit", side_effect=AssertionError("只读数据库不能写")), \
             patch("tkinter.simpledialog.askstring", side_effect=AssertionError("只读数据库不能开始编辑")):
            self.assertIn(self._key("<KeyPress-n>"), (None, ""))
            self.assertIn(self._key("<semicolon>"), (None, ""))
            # 已有数据库的 Save 是状态提示，不会重写只读快照。
            self._key("<Control-w>", state=4)
            pending, editable_entries = list(self.root.winfo_children()), 0
            while pending:
                child = pending.pop()
                pending.extend(child.winfo_children())
                if child.winfo_class() != "Menu" or not hasattr(child, "_fangida_commands"):
                    continue
                workbench._update_menu(child)
                for index, command_id in child._fangida_commands:
                    if command_id in {"rename_symbol", "set_comment"}:
                        editable_entries += 1
                        self.assertEqual(child.entrycget(index, "state"), "disabled")
                        child.invoke(index)
            self.assertGreaterEqual(editable_entries, 4)
        self.assertFalse(browser._busy)

    def test_annotation_refresh_keeps_history_and_new_source_resets_it(self):
        browser, workbench = self.browser, self.browser.workbench
        self._navigate(TARGET)
        old_history = workbench.history.entries
        browser._generation += 1
        self._load(_view(renamed=True))
        self.assertEqual(workbench.current, Location(TARGET))
        self.assertEqual(workbench.history.entries, old_history)
        self.assertEqual(browser.workspace.sidebar.tree.item("1", "values")[1], "renamed_target")
        browser._generation += 1
        self._load(_view("/nonexistent/replacement-workbench-fixture.elf"))
        self.assertEqual(workbench.history.entries, (Location(BASE),))
        self.assertFalse(workbench.history.can_back)


class GuiModuleDependencyTests(unittest.TestCase):
    def test_gui_modules_import_no_analysis_or_loading_implementation(self):
        directory = Path(__file__).resolve().parents[1] / "fangida" / "gui_modules"
        forbidden = {"api", "analyzer", "analyzers", "dispatcher", "core", "loaders",
                     "loader", "processors", "processor", "plugins", "native_bridge", "xrefs"}
        checked = []
        for source in sorted(directory.glob("*.py")):
            tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
            for node in ast.walk(tree):
                modules = ([alias.name for alias in node.names] if isinstance(node, ast.Import)
                           else [node.module or ""] if isinstance(node, ast.ImportFrom) else [])
                for module in modules:
                    components = set(module.split("."))
                    self.assertFalse(components & forbidden,
                        f"{source.name}:{node.lineno} 导入了分析／加载实现 {module}")
            checked.append(source.name)
        self.assertTrue({"commands.py", "shortcuts.py", "navigation.py", "graph.py",
                         "workspace.py", "controller.py"}.issubset(checked))


if __name__ == "__main__":
    unittest.main()
