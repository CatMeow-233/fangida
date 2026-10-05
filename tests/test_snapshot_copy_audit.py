"""Check ownership boundaries around the GUI's private snapshot transfer."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import json
import tempfile
import unittest
from unittest.mock import patch

from fangida.api import AnalysisView
from fangida.gui import (_annotate_database_view, _database_view, _prepare,
                         _save_database_view, cfg_graphs, summary_text, table_data)
from fangida.models import AnalysisResult
from fangida.project import fingerprint
from fangida.plugins.sqlite_storage import SQLiteAnalysisDatabase


def _result(path: Path, count: int = 1005) -> AnalysisResult:
    instructions = [{"addr": 0x1000 + index, "size": 1, "mnemonic": "nop",
                     "operands": ["eax"], "branch_info": {"targets": []}}
                    for index in range(count)]
    graph = {"entry": 0x1000, "complete": True, "edges": [], "frontier": []}
    return AnalysisResult(str(path), "elf", "kkagent", "partial",
        metadata={"full_disassembly": instructions,
                  "disassembly": instructions[:1],
                  "sections": [{"name": ".text", "address": 0x1000}]},
        functions=[{"start": 0x1000, "name": "main", "cfg": graph,
                    "blocks": [{"start": 0x1000, "instructions": instructions,
                                "successors": []}]}],
        strings=[{"offset": 7, "value": "hello"}],
        imports=[{"name": "puts"}], exports=[{"name": "main", "address": 0x1000}],
        xrefs=[{"src": 0x1000, "dst": 0x2000, "kind": "call"}],
        stats={"full_analysis": True}, warnings=["Function recovery is incomplete"])


class SnapshotCopyAuditTests(unittest.TestCase):
    def test_public_construction_and_getters_keep_nested_isolation(self):
        result = _result(Path("missing"), 2)
        view = AnalysisView(result)
        result.metadata["full_disassembly"][0]["operands"].append("result mutation")
        self.assertEqual(view.disassembly(0x1000)[0]["operands"], ["eax"])
        supplied = view.snapshot()
        restored = AnalysisView.from_snapshot(supplied)
        supplied["metadata"]["full_disassembly"][0]["branch_info"]["targets"].append(99)
        self.assertEqual(restored.disassembly(0x1000)[0]["branch_info"]["targets"], [])
        baseline = restored.snapshot()
        detached = restored.snapshot()
        detached["metadata"]["sections"][0]["name"] = "changed"
        functions = restored.functions()
        functions[0]["blocks"][0]["instructions"][0]["mnemonic"] = "changed"
        restored.strings()[0]["value"] = "changed"
        restored.xrefs()[0]["kind"] = "changed"
        restored.disassembly(0x1000)[0]["operands"].append("changed")
        self.assertEqual(restored.snapshot(), baseline)

    def test_public_display_adapters_do_not_expose_the_private_graph(self):
        view = AnalysisView._from_owned_result(_result(Path("missing"), 2))
        baseline = view.snapshot()
        tables = table_data(view)
        tables["Functions"][0]["blocks"][0]["instructions"][0]["mnemonic"] = "changed"
        tables["Disassembly"][0]["operands"].append("changed")
        tables["Sections"][0]["name"] = "changed"
        graphs = cfg_graphs(view)
        graphs[0]["graph"]["blocks"][0]["instructions"][0]["mnemonic"] = "changed"
        self.assertEqual(view.snapshot(), baseline)

    def test_full_prepare_reads_owned_graph_without_whole_snapshot_copy(self):
        view = AnalysisView._from_owned_result(_result(Path("missing")))
        baseline = view.snapshot()
        expected_tables = table_data(view)
        expected_graphs = cfg_graphs(view)
        expected_summary = summary_text(view)
        with patch.object(view, "snapshot", side_effect=AssertionError("whole snapshot copied")), \
             patch("fangida.api.deepcopy", side_effect=AssertionError("public getter copied")):
            prepared = _prepare(view, share_completed=True)
        self.assertEqual(prepared.summary, expected_summary)
        self.assertEqual(prepared.cfgs, expected_graphs)
        for name, rows in expected_tables.items():
            if name != "Disassembly":
                self.assertEqual(prepared.tables[name], rows)
        self.assertEqual(prepared.tables["Disassembly"][:1000], expected_tables["Disassembly"])
        self.assertEqual(len(expected_tables["Disassembly"]), 1000)
        self.assertEqual(len(prepared.tables["Disassembly"]), 1005)
        self.assertEqual(prepared.tables["Disassembly"][-1]["addr"], 0x1000 + 1004)
        self.assertIs(prepared.tables["Disassembly"], view._snapshot["metadata"]["full_disassembly"])
        self.assertIsNot(prepared.tables["Functions"][0], view._snapshot["functions"][0])
        self.assertEqual(prepared.tables["Functions"][0]["location"], 0x1000)
        self.assertNotIn("location", view._snapshot["functions"][0])
        self.assertNotIn("blocks", view._snapshot["functions"][0]["cfg"])
        self.assertEqual(view.snapshot(), baseline)

    def test_default_prepare_retains_isolated_preview_for_existing_callers(self):
        view = AnalysisView._from_owned_result(_result(Path("missing")))
        baseline = view.snapshot()
        with patch.object(view, "snapshot", wraps=view.snapshot) as snapshots:
            prepared = _prepare(view)
        self.assertEqual(snapshots.call_count, 1)
        self.assertEqual(len(prepared.tables["Disassembly"]), 1000)
        self.assertEqual(prepared.tables["Disassembly"][-1]["addr"], 0x1000 + 999)
        prepared.tables["Disassembly"][0]["operands"].append("adapter mutation")
        prepared.tables["Functions"][0]["blocks"][0]["instructions"][0]["mnemonic"] = "changed"
        prepared.tables["Sections"][0]["name"] = "changed"
        prepared.cfgs[0]["graph"]["blocks"][0]["successors"].append(0x9999)
        prepared.warnings.append("adapter warning")
        self.assertEqual(view.snapshot(), baseline)

    def test_default_database_save_and_edits_leave_previous_views_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            source.write_bytes(b"raw source bytes")
            result = _result(source, 3)
            result.metadata["source_sha256"] = fingerprint(source)[0]
            view = AnalysisView._from_owned_result(result)
            before_save = view.snapshot()
            saved = _save_database_view(view, Path(directory) / "saved.fdb")
            self.assertEqual(view.snapshot(), before_save)
            before_edit = saved.snapshot()
            source.unlink()
            # Display readers may retain the completed old graph while the
            # storage worker constructs a separate annotated replacement.
            with ThreadPoolExecutor(max_workers=2) as workers:
                display = workers.submit(_prepare, saved)
                edit = workers.submit(_annotate_database_view, saved, "rename_symbol", 0x1000, "renamed")
                prepared, renamed = display.result(), edit.result()
            self.assertEqual(prepared.tables["Functions"][0]["name"], "main")
            self.assertEqual(saved.snapshot(), before_edit)
            before_comment = renamed.snapshot()
            commented = _annotate_database_view(renamed, "set_comment", 0x1000, "offline note")
            self.assertEqual(renamed.snapshot(), before_comment)
            self.assertEqual(commented.functions()[0]["name"], "renamed")
            self.assertEqual(commented.disassembly(0x1000)[0]["comment"], "offline note")
            self.assertEqual(commented.snapshot()["metadata"]["full_disassembly"][0]["comment"],
                             "offline note")
            self.assertNotIn("location", commented.snapshot()["functions"][0])

    def test_custom_provider_may_release_returned_snapshot_without_changing_view(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "custom.database"
            path.touch()
            supplied = AnalysisView(_result(Path(directory) / "missing", 2)).snapshot()
            baseline = deepcopy(supplied)
            database = SimpleNamespace(get_snapshot=lambda snapshot_id: supplied,
                                       close=lambda: supplied.clear())
            provider = SimpleNamespace(open_database=lambda *args, **kwargs: database)
            manager = SimpleNamespace(load_storage=lambda name: provider, teardown=lambda: None)
            with patch("fangida.gui.PluginManager", return_value=manager):
                view = _database_view(path, storage_plugin="custom_storage")
            self.assertEqual(supplied, {})
            self.assertEqual(view.snapshot(), baseline)

    def test_custom_provider_save_receives_a_detached_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            source.write_bytes(b"original bytes")
            result = _result(source, 2)
            result.metadata["source_sha256"], result.metadata["source_size"] = fingerprint(source)
            view = AnalysisView._from_owned_result(result)
            baseline = view.snapshot()
            persisted = []
            def save_analysis(source_path, snapshot, *, expected_hash):
                snapshot["metadata"]["full_disassembly"][0]["mnemonic"] = "provider mutation"
                persisted.append(snapshot)
                return 1
            database = SimpleNamespace(save_analysis=save_analysis,
                get_snapshot=lambda snapshot_id: persisted[0], close=lambda: persisted[0].clear())
            provider = SimpleNamespace(open_database=lambda *args, **kwargs: database)
            manager = SimpleNamespace(load_storage=lambda name: provider, teardown=lambda: None)
            with patch("fangida.gui.PluginManager", return_value=manager):
                saved = _save_database_view(view, Path(directory) / "custom", storage_plugin="custom_storage")
            self.assertEqual(view.snapshot(), baseline)
            self.assertEqual(saved.disassembly(0x1000)[0]["mnemonic"], "provider mutation")

    def test_unannotated_full_save_reuses_completed_graph_and_matches_saved_json(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            source.write_bytes(b"verified bytes")
            result = _result(source, 3)
            result.metadata["source_sha256"], result.metadata["source_size"] = fingerprint(source)
            result.metadata["full_disassembly"][0]["operands"] = ("eax", "ecx")
            view = AnalysisView._from_owned_result(result)
            baseline = view.snapshot()
            path = Path(directory) / "saved.fdb"
            with patch.object(SQLiteAnalysisDatabase, "get_snapshot",
                              side_effect=AssertionError("completed graph was reread")):
                saved = _save_database_view(view, path)
            self.assertEqual(view.snapshot(), baseline)
            self.assertIsNot(saved._snapshot, view._snapshot)
            self.assertIsNot(saved._snapshot["metadata"], view._snapshot["metadata"])
            self.assertIs(saved._snapshot["functions"], view._snapshot["functions"])
            self.assertIs(saved._snapshot["metadata"]["full_disassembly"],
                          view._snapshot["metadata"]["full_disassembly"])
            self.assertNotIn("analysis_database", view._snapshot["metadata"])
            database = SQLiteAnalysisDatabase(path)
            try:
                restored = database.get_snapshot()
            finally:
                database.close()
            # Native tuples may remain in the private GUI graph. JSON is the
            # persisted contract and must agree with an actual database read.
            self.assertEqual(json.loads(json.dumps(saved.snapshot())), restored)
            self.assertEqual(saved._snapshot["metadata"]["user_annotations"],
                             {"sha256": fingerprint(source)[0], "renames": {}, "comments": {}})
            detached = saved.functions()
            detached[0]["blocks"][0]["instructions"][0]["operands"] = ["public mutation"]
            self.assertEqual(view.snapshot(), baseline)
            self.assertEqual(saved.disassembly(0x1000)[0]["operands"], ("eax", "ecx"))

    def test_target_database_annotations_force_reread_and_override_unannotated_input(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            source.write_bytes(b"original bytes")
            result = _result(source, 2)
            result.metadata["source_sha256"], result.metadata["source_size"] = fingerprint(source)
            path = Path(directory) / "saved.fdb"
            database = SQLiteAnalysisDatabase(path, create=True)
            try:
                snapshot_id = database.save_analysis(source, result)
                database.rename_symbol(snapshot_id, 0x1000, "existing name")
                database.set_comment(snapshot_id, 0x1000, "existing comment")
            finally:
                database.close()
            view = AnalysisView._from_owned_result(result)
            baseline = view.snapshot()
            original = SQLiteAnalysisDatabase.get_snapshot
            with patch.object(SQLiteAnalysisDatabase, "get_snapshot", autospec=True,
                              side_effect=original) as reread:
                saved = _save_database_view(view, path)
            reread.assert_called_once()
            self.assertEqual(saved.functions()[0]["name"], "existing name")
            self.assertEqual(saved.disassembly(0x1000)[0]["comment"], "existing comment")
            self.assertEqual(view.snapshot(), baseline)

    def test_missing_or_invalid_provenance_keeps_database_reread(self):
        cases = ((None, True), (-1, True), (True, True), ("14", True), (14, False))
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            source.write_bytes(b"original bytes")
            digest, _ = fingerprint(source)
            for index, (size, has_hash) in enumerate(cases):
                with self.subTest(size=size, has_hash=has_hash):
                    result = _result(source, 2)
                    if has_hash:
                        result.metadata["source_sha256"] = digest
                    if size is not None:
                        result.metadata["source_size"] = size
                    view = AnalysisView._from_owned_result(result)
                    baseline = view.snapshot()
                    original = SQLiteAnalysisDatabase.get_snapshot
                    with patch.object(SQLiteAnalysisDatabase, "get_snapshot", autospec=True,
                                      side_effect=original) as reread:
                        saved = _save_database_view(view, Path(directory) / f"saved-{index}.fdb")
                    reread.assert_called_once()
                    self.assertEqual(view.snapshot(), baseline)
                    self.assertEqual(saved._snapshot["metadata"]["analysis_database"]["source_size"],
                                     len(b"original bytes"))

    def test_input_annotations_keep_database_reread_and_old_graph(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            source.write_bytes(b"original bytes")
            result = _result(source, 2)
            digest, size = fingerprint(source)
            result.metadata.update(source_sha256=digest, source_size=size,
                user_annotations={"sha256": digest, "renames": {"4096": "imported name"},
                                  "comments": {"4096": "imported comment"}})
            result.functions[0].update(name="imported name", original_name="main")
            view = AnalysisView._from_owned_result(result)
            baseline = view.snapshot()
            original = SQLiteAnalysisDatabase.get_snapshot
            with patch.object(SQLiteAnalysisDatabase, "get_snapshot", autospec=True,
                              side_effect=original) as reread:
                saved = _save_database_view(view, Path(directory) / "saved.fdb")
            reread.assert_called_once()
            self.assertEqual(saved.functions()[0]["name"], "imported name")
            self.assertEqual(saved.disassembly(0x1000)[0]["comment"], "imported comment")
            self.assertEqual(view.snapshot(), baseline)

    def test_verified_database_header_size_allows_unannotated_resave_without_reread(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            source.write_bytes(b"original bytes")
            result = _result(source, 2)
            digest, size = fingerprint(source)
            result.metadata.update(source_sha256=digest, source_size=size)
            view = AnalysisView._from_owned_result(result)
            saved = _save_database_view(view, Path(directory) / "first.fdb")
            supplied = saved.snapshot()
            supplied["metadata"].pop("source_size")
            supplied["metadata"].pop("source_sha256")
            reopened = AnalysisView.from_snapshot(supplied)
            baseline = reopened.snapshot()
            second_path = Path(directory) / "second.fdb"
            with patch.object(SQLiteAnalysisDatabase, "get_snapshot",
                              side_effect=AssertionError("verified graph was reread")):
                second = _save_database_view(reopened, second_path)
            self.assertEqual(reopened.snapshot(), baseline)
            self.assertEqual(second._snapshot["metadata"]["analysis_database"]["source_size"], size)
            self.assertEqual(second._snapshot["metadata"]["analysis_database"]["path"],
                             str(second_path.resolve()))


if __name__ == "__main__":
    unittest.main()
