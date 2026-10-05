"""Storage UI integration checks without creating a desktop window."""
from copy import deepcopy
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
import json
import os
import queue
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from fangida.api import AnalysisView
from fangida.gui import (_Browser, _Loaded, _annotate_database_view, _database_view,
                         _analyze_file, _hex_source, _prepare, _save_database_view,
                         hex_page, main as gui_main)
from fangida.models import AnalysisResult
from fangida.project import SourceChangedError, fingerprint
from fangida.ui import main as cli_main


class _Database:
    def __init__(self, path, snapshot):
        self.path = str(path)
        self.snapshot = deepcopy(snapshot)
        self.saved = []
        self.edits = []
        self.read_only = False
        self.closed = 0
        self.threads = []

    def save_analysis(self, source, result, expected_hash=None):
        self.threads.append(threading.get_ident())
        self.saved.append((source, deepcopy(result), expected_hash))
        digest, size = fingerprint(source)
        self.snapshot = deepcopy(result)
        self.snapshot.setdefault("metadata", {})["analysis_database"] = {
            "path": self.path, "snapshot_id": 7, "format": "fangida-sqlite",
            "source_sha256": digest, "source_size": size, "read_only": False}
        return 7

    def get_snapshot(self, snapshot_id=None):
        self.threads.append(threading.get_ident())
        result = deepcopy(self.snapshot)
        result["metadata"].setdefault("analysis_database", {}).update(
            {"path": self.path, "snapshot_id": snapshot_id or 7, "read_only": self.read_only})
        return result

    def rename_symbol(self, snapshot_id, address, name):
        self.threads.append(threading.get_ident())
        self.edits.append(("rename", snapshot_id, address, name))
        for function in self.snapshot["functions"]:
            if function.get("start") == address:
                function["name"] = name

    def set_comment(self, snapshot_id, address, text):
        self.threads.append(threading.get_ident())
        self.edits.append(("comment", snapshot_id, address, text))
        self.snapshot["metadata"].setdefault("user_annotations", {}).setdefault("comments", {})[
            str(address)] = text

    def close(self):
        self.closed += 1


class _Manager:
    def __init__(self, database):
        self.database = database
        self.opens = []
        self.closed = 0

    def load_storage(self, name):
        self.name = name
        return self

    def open_database(self, path, *, read_only=False, create=False):
        self.opens.append((str(path), read_only, create))
        self.database.read_only = read_only
        return self.database

    def teardown(self):
        self.closed += 1


def _view(path):
    instructions = [{"addr": 0x1000, "mnemonic": "ret", "operands": []}]
    return AnalysisView(AnalysisResult(str(path), "elf", "kkagent", "partial",
        metadata={"disassembly": instructions},
        functions=[{"name": "main", "start": 0x1000,
                    "blocks": [{"start": 0x1000, "instructions": instructions}],
                    "cfg": {"entry": 0x1000, "complete": True}}],
        xrefs=[{"src": 0x1000, "dst": 0x2000, "kind": "call"}]))


class StorageGuiTests(unittest.TestCase):
    def test_real_storage_round_trip_and_annotations_without_source(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input"
            source.write_bytes(b"input bytes")
            database_path = Path(directory) / "sample.fdb"
            view = _view(source)
            view._snapshot["metadata"]["source_sha256"] = fingerprint(source)[0]
            with patch("fangida.gui._analyze_file", side_effect=AssertionError("reanalysis")):
                saved = _save_database_view(view, database_path)
                source.unlink()
                opened = _database_view(database_path)
                renamed = _annotate_database_view(opened, "rename_symbol", 0x1000, "recovered_main")
                _annotate_database_view(renamed, "set_comment", 0x1000, "离线注释")
                reopened = _prepare(_database_view(database_path))
            self.assertEqual(saved.functions()[0]["name"], "main")
            self.assertEqual(reopened.tables["Functions"][0]["name"], "recovered_main")
            self.assertEqual(reopened.tables["Functions"][0]["comment"], "离线注释")
            self.assertEqual(reopened.tables["Xrefs"][0]["dst"], 0x2000)
            self.assertEqual(reopened.cfgs[0]["graph"]["blocks"][0]["start"], 0x1000)
            self.assertIsNone(reopened.hex_path)

    def test_manual_save_rejects_changed_or_missing_source(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input"
            source.write_bytes(b"before")
            view = _view(source)
            view._snapshot["metadata"]["source_sha256"] = fingerprint(source)[0]
            source.write_bytes(b"after")
            with self.assertRaises(SourceChangedError):
                _save_database_view(view, Path(directory) / "changed.fdb")
            source.unlink()
            with patch("fangida.gui.PluginManager") as manager, self.assertRaises(FileNotFoundError):
                _save_database_view(view, Path(directory) / "missing.fdb")
            manager.assert_not_called()

    def test_gui_fingerprints_analysis_and_rejects_source_change_in_flight(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input"
            source.write_bytes(b"original")
            result = AnalysisResult(str(source), "elf", "kkagent", "partial")
            with patch("fangida.gui.AnalysisService") as constructor:
                service = constructor.return_value.__enter__.return_value
                service.analyze.return_value = result
                view = _analyze_file(source, None, None, None)
            self.assertEqual(view.snapshot()["metadata"]["source_sha256"], fingerprint(source)[0])
            def change(*args, **kwargs):
                source.write_bytes(b"changed")
                return result
            with patch("fangida.gui.AnalysisService") as constructor:
                constructor.return_value.__enter__.return_value.analyze.side_effect = change
                with self.assertRaisesRegex(SourceChangedError, "during analysis"):
                    _analyze_file(source, None, None, None)

    def test_save_completed_view_does_not_reanalyze(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input"
            source.write_bytes(b"example")
            path = Path(directory) / "analysis.fdb"
            view = _view(source)
            digest, _ = fingerprint(source)
            view._snapshot["metadata"]["source_sha256"] = digest
            database = _Database(path, view.snapshot())
            manager = _Manager(database)
            with patch("fangida.gui.PluginManager", return_value=manager), \
                 patch("fangida.gui._analyze_file", side_effect=AssertionError("reanalysis")):
                saved = _save_database_view(view, path)
            self.assertEqual(database.saved[0][2], digest)
            self.assertEqual(saved.functions()[0]["name"], "main")
            self.assertTrue(manager.opens[0][2])
            self.assertEqual(database.closed, 1)
            self.assertEqual(manager.closed, 1)

    def test_open_without_original_source_keeps_graph_and_xrefs(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "missing"
            path = Path(directory) / "analysis.fdb"
            path.touch()
            database = _Database(path, _view(source).snapshot())
            manager = _Manager(database)
            with patch("fangida.gui.PluginManager", return_value=manager), \
                 patch("fangida.gui._analyze_file", side_effect=AssertionError("reanalysis")):
                loaded = _prepare(_database_view(path))
            self.assertEqual(loaded.tables["Functions"][0]["name"], "main")
            self.assertEqual(loaded.tables["Xrefs"][0]["dst"], 0x2000)
            self.assertEqual(loaded.cfgs[0]["graph"]["blocks"][0]["start"], 0x1000)
            self.assertIsNone(loaded.hex_path)
            self.assertIn("not embedded", loaded.hex_unavailable)
            self.assertFalse(manager.opens[0][2])

    def test_annotation_persists_without_source_and_worker_avoids_ui_thread(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "analysis.fdb"
            view = _view(Path(directory) / "missing")
            view._snapshot["metadata"]["analysis_database"] = {
                "path": str(path), "snapshot_id": 7, "read_only": False}
            database = _Database(path, view.snapshot())
            manager = _Manager(database)
            browser = SimpleNamespace(storage_plugin="sqlite_storage", _messages=queue.SimpleQueue())
            main_thread = threading.get_ident()
            with patch("fangida.gui.PluginManager", return_value=manager):
                worker = threading.Thread(target=_Browser._database_worker,
                    args=(browser, 2, "rename_symbol", None, None, view, 0x1000, "renamed"))
                worker.start()
                worker.join(timeout=5)
                self.assertFalse(worker.is_alive())
            generation, loaded = browser._messages.get_nowait()
            self.assertEqual(generation, 2)
            self.assertIsInstance(loaded, _Loaded)
            self.assertEqual(loaded.tables["Functions"][0]["name"], "renamed")
            self.assertEqual(database.edits, [("rename", 7, 0x1000, "renamed")])
            self.assertTrue(database.threads)
            self.assertTrue(all(thread != main_thread for thread in database.threads))
            with patch("fangida.gui.PluginManager", return_value=manager):
                commented = _annotate_database_view(loaded.view, "set_comment", 0x1000, "note")
            self.assertEqual(database.edits[-1], ("comment", 7, 0x1000, "note"))
            self.assertEqual(commented.snapshot()["metadata"]["user_annotations"]["comments"]["4096"],
                             "note")

    def test_matching_source_required_for_hex(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input"
            source.write_bytes(b"original")
            snapshot = _view(source).snapshot()
            snapshot["metadata"]["analysis_database"] = {"source_sha256": fingerprint(source)[0]}
            self.assertEqual(_hex_source(snapshot)[0], source)
            source.write_bytes(b"changed")
            path, reason = _hex_source(snapshot)
            self.assertIsNone(path)
            self.assertIn("no longer matches", reason)

    def test_hex_rejects_same_inode_change_after_snapshot_open(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input"
            source.write_bytes(b"original")
            view = _view(source)
            view._snapshot["metadata"]["source_sha256"] = fingerprint(source)[0]
            prepared = _prepare(view)
            before = source.stat()
            source.write_bytes(b"changed!")
            # Restoring mtime does not make the changed file the verified input.
            os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns))
            self.assertEqual(source.stat().st_ino, before.st_ino)
            with self.assertRaisesRegex(OSError, "changed since verification"):
                hex_page(source, 0, expected_identity=prepared.hex_identity)
            # Existing callers that requested just a page retain their behavior.
            self.assertIn("|changed!|", hex_page(source, 0)["text"])

    def test_hex_gui_disables_after_stable_source_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input"
            source.write_bytes(b"original")
            view = _view(source)
            view._snapshot["metadata"]["analysis_database"] = {
                "source_sha256": fingerprint(source)[0]}
            prepared = _prepare(view)
            replacement = Path(directory) / "replacement"
            replacement.write_bytes(b"changed!")
            os.replace(replacement, source)
            displayed = []
            browser = SimpleNamespace(_hex_path=prepared.hex_path, _hex_identity=prepared.hex_identity,
                _hex_previous=0, _hex_next=16, hex_go=Mock(), hex_prev=Mock(), hex_next=Mock(),
                hex_offset=Mock(), hex_range=Mock(), hex_text=Mock(), status=Mock(),
                _set_text=lambda widget, text: displayed.append(text))
            _Browser._show_hex_page(browser, 0)
            self.assertIsNone(browser._hex_path)
            self.assertIsNone(browser._hex_identity)
            browser.hex_go.configure.assert_called_once_with(state="disabled")
            self.assertTrue(all("|changed!|" not in text for text in displayed))
            self.assertIn("reopen", browser.status.set.call_args.args[0])

    def test_hex_rejects_change_immediately_after_hashing(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input"
            source.write_bytes(b"original")
            snapshot = _view(source).snapshot()
            snapshot["metadata"]["analysis_database"] = {"source_sha256": fingerprint(source)[0]}
            def change_after_hash(path):
                result = fingerprint(path)
                source.write_bytes(b"changed!")
                return result
            with patch("fangida.gui.fingerprint", side_effect=change_after_hash):
                path, reason = _hex_source(snapshot)
            self.assertIsNone(path)
            self.assertIn("changed while verifying", reason)

    def test_source_change_during_hash_does_not_discard_database_results(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input"
            source.write_bytes(b"original")
            view = _view(source)
            view._snapshot["metadata"]["analysis_database"] = {
                "source_sha256": fingerprint(source)[0]}
            with patch("fangida.gui.fingerprint", side_effect=SourceChangedError("changed while hashing")):
                prepared = _prepare(view)
            self.assertIsNone(prepared.hex_path)
            self.assertIn("changed while hashing", prepared.hex_unavailable)
            self.assertEqual(prepared.tables["Functions"][0]["name"], "main")
            self.assertEqual(prepared.tables["Xrefs"][0]["dst"], 0x2000)

    def test_hex_rejects_change_during_page_read(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input"
            source.write_bytes(b"original")
            prepared = _prepare(_view(source))
            real_open = Path.open
            class ChangingReader:
                def __init__(self, stream):
                    self.stream = stream
                def __enter__(self):
                    return self
                def __exit__(self, *args):
                    self.stream.close()
                def fileno(self):
                    return self.stream.fileno()
                def seek(self, position):
                    self.stream.seek(position)
                def read(self, size):
                    data = self.stream.read(size)
                    with real_open(source, "wb") as output:
                        output.write(b"changed!")
                    return data
            def changed_open(path, *args, **kwargs):
                return ChangingReader(real_open(path, *args, **kwargs))
            with patch.object(Path, "open", changed_open), \
                 self.assertRaisesRegex(OSError, "changed while reading"):
                hex_page(source, 0, expected_identity=prepared.hex_identity)

    def test_read_only_database_opens_but_does_not_accept_edits(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "analysis.fdb"
            path.touch()
            path.chmod(0o444)
            database = _Database(path, _view(Path(directory) / "missing").snapshot())
            manager = _Manager(database)
            try:
                with patch("fangida.gui.PluginManager", return_value=manager):
                    view = _database_view(path)
                self.assertTrue(manager.opens[0][1])
                with self.assertRaisesRegex(ValueError, "read-only"):
                    _annotate_database_view(view, "rename_symbol", 0x1000, "name")
            finally:
                path.chmod(0o644)

    def test_gui_database_options_are_optional(self):
        with patch("fangida.gui.launch", return_value=0) as launch:
            self.assertEqual(gui_main(["--open-database", "saved.fdb", "--snapshot-id", "3"]), 0)
        launch.assert_called_once_with(None, max_bytes=None, use_ghidra=None, deep_analysis=None,
                                       semantic_threads=None, open_database_path=Path("saved.fdb"),
                                       snapshot_id=3)

    def test_failed_storage_edit_resumes_cached_table_batches(self):
        class Tree:
            def __init__(self):
                self.items = {}
            def get_children(self):
                return tuple(self.items)
            def delete(self, *items):
                for item in items:
                    del self.items[item]
            def insert(self, parent, index, *, iid, values):
                if iid in self.items:
                    raise AssertionError("Duplicate tree row from an obsolete callback")
                self.items[iid] = values
        tree = Tree()
        rows = [{"location": index, "name": f"function_{index}"} for index in range(601)]
        pending = []
        browser = _Browser.__new__(_Browser)
        browser._closed = False
        browser._busy = False
        browser._generation = 1
        browser._view = _view("missing")
        original_view = browser._view
        browser._tables = {"Functions": tree}
        browser._rows = {"Functions": rows}
        browser._details = {"Functions": Mock()}
        browser._tabs = {"Functions": SimpleNamespace(master=Mock())}
        browser._messages = queue.SimpleQueue()
        browser._set_busy = Mock()
        browser._set_text = Mock()
        browser.status = Mock()
        browser.summary = Mock()
        browser.messagebox = Mock()
        browser.root = Mock()
        browser.root.after.side_effect = lambda delay, callback, *args: pending.append(
            (delay, callback, args))
        browser._insert_chunk("Functions", 1, 0)
        self.assertEqual(len(tree.items), 200)
        old_callback = pending.pop(0)
        with patch("fangida.gui.threading.Thread"):
            browser._start_storage_edit("save", "failed.fdb")
        self.assertEqual(browser._generation, 2)
        old_callback[1](*old_callback[2])
        self.assertEqual(len(tree.items), 200)
        self.assertFalse(pending)
        browser._messages.put((2, RuntimeError("save failed")))
        with patch("fangida.gui._analyze_file", side_effect=AssertionError("reanalysis")), \
             patch("fangida.gui.fingerprint", side_effect=AssertionError("rehash")):
            browser._drain()
            self.assertIs(browser._view, original_view)
            self.assertIs(browser._rows["Functions"], rows)
            self.assertEqual(len(tree.items), 200)
            # Only row-insertion callbacks run; do not recurse into the polling loop.
            while pending:
                delay, callback, arguments = pending.pop(0)
                if delay == 1:
                    self.assertEqual(arguments[1], 2)
                    callback(*arguments)
            old_callback[1](*old_callback[2])
        self.assertEqual(len(tree.items), len(rows))
        self.assertEqual(tree.items["600"][1], "function_600")
        browser.messagebox.showerror.assert_called_once()
        self.assertEqual(browser._view.functions()[0]["name"], "main")

    def test_cli_database_opens_without_file_or_analysis(self):
        view = _view("missing")
        with patch("sys.argv", ["fangida", "--open-database", "saved.fdb"]), \
             patch("fangida.ui.open_database", return_value=view) as opener, \
             patch("fangida.ui.AnalysisService") as service, redirect_stdout(StringIO()) as output:
            self.assertEqual(cli_main(), 0)
        service.assert_not_called()
        opener.assert_called_once_with(Path("saved.fdb"), None)
        self.assertEqual(json.loads(output.getvalue())["functions"][0]["name"], "main")

    def test_cli_database_is_independent_from_legacy_project(self):
        result = AnalysisResult("input", "unknown", "kkagent", "partial")
        with patch("sys.argv", ["fangida", "input", "--database", "analysis.fdb",
                                  "--project", "legacy.sqlite"]), \
             patch("fangida.ui.AnalysisService") as service, redirect_stdout(StringIO()):
            service.return_value.__enter__.return_value.analyze.return_value = result
            self.assertEqual(cli_main(), 0)
        self.assertEqual(service.call_args.kwargs["database_path"], Path("analysis.fdb"))
        self.assertEqual(service.call_args.kwargs["project_path"], Path("legacy.sqlite"))

    def test_cli_still_requires_source_except_database_open(self):
        for arguments in ([], ["--database", "out.fdb"], ["input", "--open-database", "out.fdb"]):
            with self.subTest(arguments=arguments), patch("sys.argv", ["fangida", *arguments]), \
                 redirect_stderr(StringIO()), self.assertRaises(SystemExit) as error:
                cli_main()
            self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
