"""工作区异步查找、已有伪代码定位与编辑守卫的整合验证。"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from fangida.api import AnalysisView
from fangida.gui_modules.navigation import AddressIndex, Location
from tests import test_gui_workbench as fixture


class GuiWorkbenchActionTests(unittest.TestCase):
    setUp = fixture.GuiWorkbenchIntegrationTests.setUp
    _close = fixture.GuiWorkbenchIntegrationTests._close
    _pump = fixture.GuiWorkbenchIntegrationTests._pump
    _load = fixture.GuiWorkbenchIntegrationTests._load
    _navigate = fixture.GuiWorkbenchIntegrationTests._navigate
    _xref_dialog = fixture.GuiWorkbenchIntegrationTests._xref_dialog
    _binding = fixture.GuiWorkbenchIntegrationTests._binding
    _event = fixture.GuiWorkbenchIntegrationTests._event

    def test_pseudocode_at_an_interior_instruction_selects_its_function(self):
        snapshot = fixture._view().snapshot()
        snapshot["functions"][0]["pseudoc"] = "void entry() {}\n"
        snapshot["functions"][1]["pseudoc"] = "void target() {}\n"
        self._load(AnalysisView.from_snapshot(snapshot))
        self._navigate(fixture.TARGET + 4)
        current = self.browser.workbench.current
        self.browser.workbench.show_pseudocode()
        tree = self.browser._tables["Pseudocode"]
        self._pump(lambda: tree.selection() == ("1",))
        self.assertEqual(self.browser._details["Pseudocode"].get("1.0", "end-1c"),
                         "void target() {}\n")
        self.assertEqual(self.browser.workbench.current, current)

    def test_navigation_cancels_an_old_find_batch(self):
        browser, workbench = self.browser, self.browser.workbench
        browser._rows["Disassembly"][fixture.TARGET_INDEX]["mnemonic"] = "late_match"
        workbench._find_query = "late_match"
        workbench._find_table = "Disassembly"
        workbench._find_position = -1
        callbacks = []
        with patch.object(self.root, "after", side_effect=lambda delay, callback, *args:
                          callbacks.append((callback, args)) or "captured-search"):
            workbench.find_next()
        self.assertTrue(callbacks)
        self._navigate(fixture.BASE + 4)
        for callback, args in callbacks:
            callback(*args)
        self._pump()
        self.assertEqual(workbench.current, Location(fixture.BASE + 4))
        self.assertEqual(browser._tables["Disassembly"].selection(), ("1",))
        self.assertEqual(workbench._find_position, -1)

    def test_direct_edit_actions_respect_readonly_and_container_guards(self):
        browser, workbench = self.browser, self.browser.workbench
        for kind, read_only in (("elf", True), ("apk", False), ("jar", False)):
            with self.subTest(kind=kind, read_only=read_only):
                snapshot = fixture._view(read_only=read_only).snapshot()
                snapshot["kind"] = kind
                self._load(AnalysisView.from_snapshot(snapshot))
                self.assertFalse(workbench.enabled("rename_symbol"))
                self.assertFalse(workbench.enabled("set_comment"))
                self.assertEqual(str(browser.rename_button["state"]), "disabled")
                self.assertEqual(str(browser.comment_button["state"]), "disabled")
                with patch.object(browser, "rename_symbol", side_effect=AssertionError("不能重命名")), \
                     patch("tkinter.simpledialog.askstring", side_effect=AssertionError("不能弹出编辑")):
                    workbench.rename()
                    workbench.comment()

    def test_toolbar_edits_use_current_location_instead_of_an_old_function_selection(self):
        browser, workbench = self.browser, self.browser.workbench
        workbench.select_row("Functions", 0)
        self._pump(lambda: browser._tables["Functions"].selection() == ("0",))
        self._navigate(fixture.TARGET + 4)
        self.assertEqual(browser._tables["Functions"].selection(), ("0",))
        with patch("tkinter.simpledialog.askstring", return_value="current_name"), \
             patch.object(browser, "_start_storage_edit") as edit:
            browser.rename_button.invoke()
            self._pump(lambda: edit.called)
            edit.assert_called_once_with("rename_symbol", address=fixture.TARGET, value="current_name")
        self.assertEqual(workbench.current, Location(fixture.TARGET + 4))
        with patch("tkinter.simpledialog.askstring", return_value="current_comment"), \
             patch.object(browser, "_start_storage_edit") as edit:
            browser.comment_button.invoke()
            edit.assert_called_once_with("set_comment", address=fixture.TARGET + 4, value="current_comment")

    def test_jump_from_a_string_resolves_a_global_unique_symbol_and_numeric_fallback(self):
        browser, workbench = self.browser, self.browser.workbench
        for value in ("target", hex(fixture.TARGET)):
            with self.subTest(query=value):
                self.assertTrue(workbench.navigate(Location(3, address_space="file_offset")))
                self._pump(lambda: browser._tables["Strings"].selection() == ("0",))
                with patch("tkinter.simpledialog.askstring", return_value=value):
                    workbench.jump_dialog()
                self._pump(lambda: browser._tables["Disassembly"].selection() == (str(fixture.TARGET_INDEX),))
                self.assertEqual(workbench.current, Location(fixture.TARGET))
                browser.messagebox.showerror.assert_not_called()

    def test_old_database_string_selection_shows_real_data_references_and_return_navigation(self):
        snapshot = fixture._view().snapshot()
        string_address = 0x5030
        snapshot["metadata"]["sections"].append({"name": ".rodata", "offset": 0x8000,
            "address": 0x5000, "size": 0x100, "file_size": 0x100, "allocated": True})
        snapshot["strings"] = [{"offset": 0x8030, "length": 10, "value": "hello data"}]
        snapshot["xrefs"].append({"src": fixture.BASE + 4, "dst": string_address + 2, "kind": "data"})
        self._load(AnalysisView.from_snapshot(snapshot))
        browser, workbench = self.browser, self.browser.workbench
        workbench.select_row("Strings", 0)
        self._pump(lambda: browser._tables["Strings"].selection() == ("0",))
        workbench._programmatic_selection = None
        workbench.record_selected("Strings", 0)
        self.assertEqual(workbench.current, Location(string_address))
        values = browser._tables["Strings"].item("0", "values")
        columns = [column[0] for column in browser.table_columns["Strings"]]
        self.assertEqual(values[columns.index("address")], hex(string_address))
        self.assertNotIn("address", browser._rows["Strings"][0])
        workbench.show_xrefs("incoming")
        dialog, tree = self._xref_dialog()
        row = tree.item(tree.get_children()[0], "values")
        self.assertEqual(row[0].split()[0], hex(fixture.BASE + 4))
        self.assertEqual(row[1].split()[0], hex(string_address + 2))
        self.assertEqual(row[2], "data")
        self.assertEqual(self._event(self._binding(tree, "<Return>"), tree, keysym="Return"), "break")
        self._pump(lambda: browser._tables["Disassembly"].selection() == ("1",))
        self.assertEqual(workbench.current, Location(fixture.BASE + 4))
        self.assertFalse(dialog.winfo_exists())
        workbench.follow()
        self._pump(lambda: browser._tables["Strings"].selection() == ("0",)
                   and browser.notebook.select() == str(browser._tabs["Strings"]))
        self.assertEqual(workbench.current, Location(string_address))
        self.assertIn("字符串内部", browser.status.get())

    def test_ambiguous_string_selection_cannot_query_previous_location(self):
        snapshot = fixture._view().snapshot()
        snapshot["strings"] = [{"offset": 0x8030, "addresses": [0x5030, 0x6030],
                                "address_space": "native", "length": 4, "value": "text"}]
        self._load(AnalysisView.from_snapshot(snapshot))
        browser, workbench = self.browser, self.browser.workbench
        previous = workbench.current
        workbench.select_row("Strings", 0)
        self._pump(lambda: browser._tables["Strings"].selection() == ("0",))
        workbench._programmatic_selection = None
        workbench.record_selected("Strings", 0)
        self.assertEqual(workbench.current, previous)
        self.assertFalse(workbench.enabled("xrefs_incoming"))
        self.assertFalse(workbench.enabled("set_comment"))
        self.assertIn("歧义", browser.address_status.get())
        with patch.object(workbench, "_choose_references", side_effect=AssertionError("不能引用上一行")):
            workbench.show_xrefs("incoming")
        self.assertTrue(workbench.navigate(Location(0x6032)))
        self._pump(lambda: browser._tables["Strings"].selection() == ("0",))
        self.assertEqual(workbench.current, Location(0x6030))
        self.assertTrue(workbench.enabled("xrefs_incoming"))
        columns = [column[0] for column in browser.table_columns["Strings"]]
        self.assertEqual(browser._tables["Strings"].item("0", "values")[columns.index("address")],
                         "0x5030, 0x6030")

    def test_global_symbol_ambiguity_is_reported_and_does_not_change_location(self):
        snapshot = fixture._view().snapshot()
        snapshot["functions"][0]["name"] = "target"
        self._load(AnalysisView.from_snapshot(snapshot))
        workbench = self.browser.workbench
        self.assertTrue(workbench.navigate(Location(3, address_space="file_offset")))
        history = workbench.history.entries
        with patch("tkinter.simpledialog.askstring", return_value="target"):
            workbench.jump_dialog()
        self.browser.messagebox.showerror.assert_called_once()
        self.assertIn("歧义", str(self.browser.messagebox.showerror.call_args))
        self.assertEqual(workbench.history.entries, history)

    def test_global_unique_symbol_can_resolve_another_container_member(self):
        workbench = self.browser.workbench
        workbench.index = AddressIndex({"Functions": [
            {"name": "first", "code_offset": 0x100, "source": "a.dex"},
            {"name": "second", "code_offset": 0x200, "source": "b.dex"}]}, kind="apk")
        workbench.history.reset(Location(0x100, "a.dex", "file_offset"))
        with patch("tkinter.simpledialog.askstring", return_value="second"), \
             patch.object(workbench, "navigate") as navigate:
            workbench.jump_dialog()
            navigate.assert_called_once_with(Location(0x200, "b.dex", "file_offset"))
        self.browser.messagebox.showerror.assert_not_called()

    def test_cfg_jump_button_and_initial_list_selection_match_the_current_block(self):
        browser, workbench = self.browser, self.browser.workbench
        self._navigate(fixture.TARGET + 8)
        workbench.toggle_graph()
        self._pump(lambda: browser.cfg_tree.selection() == ("1",))
        self.assertEqual(browser.cfg_tree.selection(), ("1",))
        self.assertIn(f"Block {fixture.TARGET + 8:#x}", browser.cfg_detail.get("1.0", "end"))
        browser._cfg_views.select(browser._cfg_views.tabs()[1])
        browser.cfg_address.set(hex(fixture.TARGET))
        browser.cfg_jump.invoke()
        self._pump(lambda: browser.cfg_tree.selection() == ("0",) and
                   workbench.current == Location(fixture.TARGET))
        self.assertEqual(browser.cfg_tree.selection(), ("0",))
        self.assertIn(f"Block {fixture.TARGET:#x}", browser.cfg_detail.get("1.0", "end"))
        self.assertEqual(workbench.current, Location(fixture.TARGET))
        self.assertEqual(browser.graph_view.selected_address, fixture.TARGET)

    def test_cfg_jump_beyond_list_limit_selects_the_complete_graph_without_a_stale_list_row(self):
        browser, workbench = self.browser, self.browser.workbench
        addresses = [fixture.BASE + index * 16 for index in range(2001)]
        browser._cfgs[0]["graph"] = {"entry": fixture.BASE, "blocks": [
            {"start": address, "instructions": [{"addr": address, "size": 1, "mnemonic": "ret"}],
             "successors": []} for address in addresses], "edges": [], "frontier": [], "complete": True}
        browser.cfg_choice.current(0)
        browser._show_cfg()
        browser.notebook.select(browser._cfg_tab)
        browser._cfg_views.select(browser._cfg_views.tabs()[1])
        browser.cfg_address.set(hex(addresses[-1]))
        browser.cfg_jump.invoke()
        self._pump(lambda: browser.graph_view.selected_address == addresses[-1] and
                   browser._cfg_views.select() == str(browser.graph_view.frame))
        self.assertEqual(len(browser._cfg_rows), 2000)
        self.assertEqual(len(browser.graph_view.layout.blocks), 2001)
        self.assertEqual(browser.cfg_tree.selection(), ())
        self.assertIn("超出列表", browser.cfg_detail.get("1.0", "end"))
        self.assertEqual(browser._cfg_views.select(), str(browser.graph_view.frame))
        self.assertEqual(workbench.current, Location(addresses[-1]))
        self.assertEqual(browser.graph_view.selected_address, addresses[-1])

    def test_manual_table_and_graph_selection_cancel_pending_find_batches(self):
        browser, workbench = self.browser, self.browser.workbench
        browser._rows["Disassembly"][fixture.TARGET_INDEX]["mnemonic"] = "late_match"
        for graph in (False, True):
            with self.subTest(graph=graph):
                self._navigate(fixture.BASE)
                workbench._find_query = "late_match"
                workbench._find_table = "Disassembly"
                workbench._find_position = -1
                callbacks = []
                with patch.object(self.root, "after", side_effect=lambda delay, callback, *args:
                                  callbacks.append((callback, args)) or "captured-search"):
                    workbench.find_next()
                self.assertTrue(callbacks)
                if graph:
                    workbench.toggle_graph()
                    browser.graph_view.select_address(fixture.BASE + 4)
                    browser.graph_view.on_select(fixture.BASE + 4)
                else:
                    workbench._programmatic_selection = None
                    browser._tables["Disassembly"].selection_set("1")
                    browser._tables["Disassembly"].focus("1")
                    workbench.record_selected("Disassembly", 1)
                for callback, args in callbacks:
                    callback(*args)
                self._pump(lambda: workbench.current == Location(fixture.BASE + 4))
                self.assertEqual(workbench.current, Location(fixture.BASE + 4))
                self.assertEqual(workbench._find_position, -1)


if __name__ == "__main__":
    unittest.main()
