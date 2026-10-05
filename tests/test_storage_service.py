"""Analysis completion and database restore use distinct plugin contracts."""
from pathlib import Path
import tempfile
import unittest

from fangida.api import AnalysisView, open_database
from fangida.dispatcher import AnalysisService
from fangida.models import AnalysisResult
from fangida.plugins.manager import PluginManager
from fangida.project import SourceChangedError, ProjectStore, ProjectSchemaError
from fangida.settings import Settings
from fangida.storage import database_session


class Analyzer:
    name, version = "fixture_analyzer", "1.0"

    def __init__(self, *, change_source=False):
        self.change_source = change_source
        self.calls = 0

    def capabilities(self):
        return ("fixture",)

    def analyze(self, task):
        self.calls += 1
        if self.change_source:
            Path(task.path).write_bytes(b"changed")
        ins = {"addr": 0x1000, "size": 1, "mnemonic": "ret", "operands": (),
               "reads": (), "writes": (), "branch_info": {"kind": "return"}, "arch_meta": {}}
        return AnalysisResult(task.path, task.kind, self.name, "partial",
                              metadata={"disassembly": [ins]},
                              functions=[{"start": 0x1000, "name": "original",
                                          "blocks": [{"start": 0x1000, "instructions": [ins]}],
                                          "cfg": {"edges": [], "complete": True}}])

    def teardown(self):
        pass


class StorageServiceTests(unittest.TestCase):
    def manager(self, analyzer):
        manager = PluginManager()
        manager.register(analyzer.name, lambda: analyzer, kinds=("elf",), replace_routes=True)
        return manager

    def test_service_saves_once_and_reopens_after_source_disappears(self):
        with tempfile.TemporaryDirectory() as directory:
            source, target = Path(directory) / "sample.elf", Path(directory) / "sample.fdb"
            source.write_bytes(b"\x7fELFfixture")
            analyzer = Analyzer()
            with AnalysisService(Settings(), manager=self.manager(analyzer), database_path=target) as service:
                result = service.analyze(source)
                snapshot_id = result.metadata["analysis_database"]["snapshot_id"]
                self.assertEqual(service.database.history()["total"], 1)
            self.assertEqual(analyzer.calls, 1)
            source.unlink()
            with database_session(target, read_only=False) as database:
                database.rename_symbol(snapshot_id, 0x1000, "renamed")
                database.set_comment(snapshot_id, 0x1000, "saved offline")
            registry = PluginManager()
            restored = open_database(target, manager=registry).snapshot()
            self.assertEqual(registry._loaded, {})
            registry.teardown()
            self.assertEqual(restored["functions"][0]["name"], "renamed")
            self.assertEqual(restored["functions"][0]["original_name"], "original")
            self.assertEqual(restored["functions"][0]["comment"], "saved offline")
            self.assertEqual(AnalysisView.from_snapshot(restored).disassembly(0x1000)[0]["comment"],
                             "saved offline")
            self.assertEqual(analyzer.calls, 1)

    def test_source_change_during_analysis_does_not_commit_a_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            source, target = Path(directory) / "sample.elf", Path(directory) / "sample.fdb"
            source.write_bytes(b"\x7fELFfixture")
            analyzer = Analyzer(change_source=True)
            with AnalysisService(Settings(), manager=self.manager(analyzer), database_path=target) as service:
                with self.assertRaises(SourceChangedError):
                    service.analyze(source)
                self.assertEqual(service.database.history()["total"], 0)

    def test_service_database_load_does_not_route_or_analyze(self):
        with tempfile.TemporaryDirectory() as directory:
            source, target = Path(directory) / "sample.elf", Path(directory) / "sample.fdb"
            source.write_bytes(b"\x7fELFfixture")
            analyzer = Analyzer()
            with AnalysisService(Settings(), manager=self.manager(analyzer), database_path=target) as service:
                service.analyze(source)
            with AnalysisService(Settings()) as service:
                restored = service.load_database(target)
                self.assertEqual(restored["analyzer"], "fixture_analyzer")
                self.assertEqual(service.manager._loaded, {})

    def test_original_project_and_database_cannot_write_the_same_file(self):
        with self.assertRaisesRegex(ValueError, "different paths"):
            AnalysisService(Settings(), project_path="same.fdb", database_path="same.fdb")

    def test_compact_storage_database_is_rejected_by_legacy_project_store(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "sample.fdb"
            with database_session(target, read_only=False, create=True):
                pass
            original = target.read_bytes()
            for read_only in (False, True):
                with self.assertRaisesRegex(ProjectSchemaError, "storage.plugin"):
                    ProjectStore(target, read_only=read_only)
            self.assertEqual(target.read_bytes(), original)

    def test_service_rejects_using_its_database_as_the_input(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "sample.fdb"
            with AnalysisService(Settings(), database_path=target) as service:
                with self.assertRaisesRegex(ValueError, "input binary"):
                    service.analyze(target)

    def test_snapshot_constructor_isolated_and_preserves_extension_fields(self):
        raw = AnalysisResult("input", "elf", "fixture", "partial").to_dict()
        raw["extension"] = {"nested": [1]}
        view = AnalysisView.from_snapshot(raw)
        raw["extension"]["nested"].append(2)
        self.assertEqual(view.snapshot()["extension"], {"nested": [1]})
        for field in ("path", "kind", "analyzer", "status", "schema_version"):
            bad = dict(raw)
            bad[field] = None
            with self.assertRaises(ValueError):
                AnalysisView.from_snapshot(bad)


if __name__ == "__main__":
    unittest.main()
