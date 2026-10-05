"""没有分析数据库时的重命名/注释：按钮可用，先引导保存为 .fdb，再写入标注。

修复前：直接打开文件分析后没有数据库，“重命名函数…”“添加注释…”按钮与 n / ; 快捷键
都被静默禁用，界面没有任何提示。
"""
from __future__ import annotations

import queue
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fangida.api import AnalysisView
from fangida.gui import _Browser, _Loaded, _database_view, _prepare
from fangida.project import fingerprint
from tests import test_gui_workbench as fixture
from tests.test_storage_gui import _view as storage_view


def _run_worker(operation, database_path, view, address, value):
    browser = SimpleNamespace(storage_plugin="sqlite_storage", _messages=queue.SimpleQueue())
    worker = threading.Thread(target=_Browser._database_worker,
                              args=(browser, 3, operation, database_path, None, view, address, value))
    worker.start()
    worker.join(timeout=30)
    return browser._messages.get_nowait()


class SaveThenAnnotateWorkerTests(unittest.TestCase):
    def test_first_comment_and_rename_create_the_database_and_persist(self):
        for operation, field, value in (("save_then_set_comment", "comment", "首次注释"),
                                        ("save_then_rename_symbol", "name", "renamed_main")):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / "input"
                source.write_bytes(b"input bytes")
                database_path = Path(directory) / "input.fdb"
                view = storage_view(source)
                view._snapshot["metadata"]["source_sha256"] = fingerprint(source)[0]
                generation, loaded = _run_worker(operation, database_path, view, 0x1000, value)
                self.assertEqual(generation, 3)
                self.assertIsInstance(loaded, _Loaded, loaded)
                saved_path = Path(loaded.view._snapshot["metadata"]["analysis_database"]["path"])
                self.assertEqual(saved_path.resolve(), database_path.resolve())
                self.assertEqual(loaded.tables["Functions"][0][field], value)
                # 重新打开数据库（不需要原文件）：标注已持久化。
                source.unlink()
                reopened = _prepare(_database_view(database_path))
                self.assertEqual(reopened.tables["Functions"][0][field], value)

    def test_missing_source_reports_an_error_instead_of_a_partial_write(self):
        with tempfile.TemporaryDirectory() as directory:
            view = storage_view(Path(directory) / "missing")
            _, result = _run_worker("save_then_set_comment", Path(directory) / "x.fdb", view, 0x1000, "note")
            self.assertIsInstance(result, FileNotFoundError)


class InMemoryAnnotationEquivalenceTests(unittest.TestCase):
    def test_in_memory_annotations_match_a_full_database_reload(self):
        import json
        from fangida.api import AnalysisView
        from fangida.gui import _annotate_owned_view, _save_database_view
        from fangida.models import AnalysisResult
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input"
            source.write_bytes(b"input bytes")
            instructions = [{"addr": 0x1000, "mnemonic": "ret", "operands": [], "comment": "原始注释"},
                            {"addr": 0x1004, "mnemonic": "nop", "operands": []}]
            view = AnalysisView(AnalysisResult(str(source), "elf", "kkagent", "partial",
                metadata={"disassembly": instructions, "source_sha256": fingerprint(source)[0]},
                functions=[{"name": "main", "start": 0x1000, "comment": "函数原注释",
                            "blocks": [{"start": 0x1000, "instructions": instructions}], "cfg": {"entry": 0x1000}},
                           {"name": "helper", "start": 0x1004, "blocks": [], "cfg": {}}],
                xrefs=[{"src": 0x1000, "dst": 0x1004, "kind": "call"}]))
            database_path = Path(directory) / "input.fdb"
            current = _save_database_view(view, database_path)
            cache = {}
            for operation, address, value in (("rename_symbol", 0x1000, "renamed_main"), ("set_comment", 0x1000, "用户注释一"),
                                              ("set_comment", 0x1000, "用户注释二"), ("set_comment", 0x1004, "helper 注释"),
                                              ("rename_symbol", 0x1000, "renamed_again"), ("set_comment", 0x1000, ""),
                                              ("set_comment", 0x1004, "")):
                current = _annotate_owned_view(current, operation, address, value, cache=cache)
                reloaded = _database_view(database_path)

                def canonical(snapshot):
                    snapshot = json.loads(json.dumps(snapshot, sort_keys=True, default=str))
                    snapshot["metadata"].pop("analysis_database", None)
                    snapshot["metadata"].get("user_annotations", {}).pop("sha256", None)
                    return snapshot

                with self.subTest(operation=operation, address=hex(address), value=value):
                    self.assertEqual(canonical(current._snapshot), canonical(reloaded._snapshot))
            # 删除后恢复原始注释，重命名保留最后一次。
            functions = {item["start"]: item for item in current._snapshot["functions"]}
            self.assertEqual((functions[0x1000]["name"], functions[0x1000]["comment"]), ("renamed_again", "函数原注释"))
            self.assertNotIn("comment", functions[0x1004])


class RenamedPseudocodeTests(unittest.TestCase):
    def test_renamed_functions_appear_in_pseudocode_but_literals_and_comments_do_not_change(self):
        from fangida.gui_modules.records import apply_renames, extra_tables
        code = ('void caller(void) {\n    fde_1c658c(local_1 + 8);  // fde_1c658c 构造\n    log("fde_1c658c");\n'
                '    fde_1c658c_extra();\n    /* fde_1c658c */ x = fde_1c658c;\n}')
        self.assertEqual(apply_renames(code, {"fde_1c658c": "construct_string"}),
                         'void caller(void) {\n    construct_string(local_1 + 8);  // fde_1c658c 构造\n    log("fde_1c658c");\n'
                         '    fde_1c658c_extra();\n    /* fde_1c658c */ x = construct_string;\n}')
        snapshot = {"metadata": {}, "functions": [
            {"name": "construct_string", "original_name": "fde_1c658c", "start": 1,
             "pseudoc": "void fde_1c658c(void) {\n}", "machine_pseudoc": "void fde_1c658c(void) { }"},
            {"name": "caller", "start": 2, "pseudoc": code}]}
        rows = {row["start"]: row for row in extra_tables(snapshot)["Pseudocode"]}
        self.assertIn("construct_string(local_1 + 8)", rows[2]["pseudoc"])
        self.assertEqual(rows[1]["pseudoc"], "void construct_string(void) {\n}")
        self.assertEqual(rows[1]["machine_pseudoc"], "void construct_string(void) { }")
        self.assertEqual(snapshot["functions"][1]["pseudoc"], code, "快照原文不能被修改")


class AnnotationWithoutDatabaseGuiTests(unittest.TestCase):
    setUp = fixture.GuiWorkbenchIntegrationTests.setUp
    _close = fixture.GuiWorkbenchIntegrationTests._close
    _pump = fixture.GuiWorkbenchIntegrationTests._pump
    _load = fixture.GuiWorkbenchIntegrationTests._load

    def _load_without_database(self, source):
        snapshot = fixture._view(path=str(source)).snapshot()
        snapshot["metadata"].pop("analysis_database", None)
        self._load(AnalysisView.from_snapshot(snapshot))

    def test_buttons_are_enabled_and_offer_to_save_first(self):
        browser, workbench = self.browser, self.browser.workbench
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "sample.elf"
            source.write_bytes(b"fixture")
            self._load_without_database(source)
            self.assertTrue(workbench.enabled("rename_symbol"))
            self.assertTrue(workbench.enabled("set_comment"))
            self.assertEqual(str(browser.rename_button["state"]), "normal")
            self.assertEqual(str(browser.comment_button["state"]), "normal")
            target = str(Path(directory) / "sample.elf.fdb")
            with patch("tkinter.simpledialog.askstring", return_value="第一条注释"), \
                 patch.object(browser.messagebox, "askyesno", return_value=True) as ask, \
                 patch.object(browser.filedialog, "asksaveasfilename", return_value=target) as choose, \
                 patch.object(browser, "_start_storage_edit") as edit:
                browser.comment_button.invoke()
            ask.assert_called_once()
            self.assertEqual(choose.call_args.kwargs["initialfile"], "sample.elf.fdb")
            edit.assert_called_once_with("save_then_set_comment", target,
                                         address=workbench.current.address, value="第一条注释")

    def test_declining_to_save_writes_nothing(self):
        browser = self.browser
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "sample.elf"
            source.write_bytes(b"fixture")
            self._load_without_database(source)
            with patch("tkinter.simpledialog.askstring", return_value="x"), \
                 patch.object(browser.messagebox, "askyesno", return_value=False), \
                 patch.object(browser.filedialog, "asksaveasfilename", side_effect=AssertionError("不应选择路径")), \
                 patch.object(browser, "_start_storage_edit", side_effect=AssertionError("不应写入")):
                browser.comment_button.invoke()


if __name__ == "__main__":
    unittest.main()
