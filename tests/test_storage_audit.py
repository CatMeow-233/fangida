"""独立审查 compact 编码、损坏数据库拒绝及事务边界。"""
from __future__ import annotations

from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch
import zlib

from fangida.models import AnalysisResult
from fangida.dispatcher import AnalysisService
from fangida.plugins import sqlite_storage as backend
from fangida.plugins.sqlite_storage import SQLiteAnalysisDatabase
from fangida.settings import Settings
from fangida.storage import StorageError, StorageSchemaError, database_session


class StorageAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / "input"
        self.source.write_bytes(b"original fixture")
        self.path = Path(self.temp.name) / "analysis.fdb"
        self.database = SQLiteAnalysisDatabase(self.path, create=True)
        self.addCleanup(self.database.close)

    def result(self, **options):
        return AnalysisResult(str(self.source), "elf", "fixture", "partial", **options)

    def sql(self, command, arguments=()):
        with closing(sqlite3.connect(self.path)) as connection:
            with connection:
                connection.execute(command, arguments)

    def test_extension_dictionaries_literal_markers_and_distinct_same_address_ir_round_trip(self):
        first = {"addr": 1, "size": 1, "mnemonic": "nop", "source": "first",
                 "operands": (), "extra": {"$fdb_instruction": {"$fdb_literal": [2, 3]}}}
        second = {"addr": 1, "size": 1, "mnemonic": "ret", "source": "second"}
        nested = {"addr": 7, "size": 1, "mnemonic": "call", "nested": first}
        payload = self.result(metadata={"disassembly": [first, second, nested]},
                              functions=[{"start": 1, "name": "f", "blocks": [
                                  {"start": 1, "instructions": [first]}]}]).to_dict()
        payload["future_extension"] = {"$fdb_instruction": {"$fdb_literal": {"$fdb_instruction": 9}}}
        payload["metadata"]["future_extension"] = {"$fdb_literal": {"$fdb_instruction": "literal"}}
        expected = json.loads(json.dumps(payload))
        snapshot_id = self.database.save_analysis(self.source, payload)
        restored = self.database.get_snapshot(snapshot_id)
        restored["metadata"].pop("analysis_database")
        restored["metadata"].pop("user_annotations")
        self.assertEqual(restored, expected)
        restored["functions"][0]["blocks"][0]["instructions"][0]["mnemonic"] = "changed"
        self.assertEqual(self.database.get_snapshot(snapshot_id)["metadata"]["disassembly"][0]["mnemonic"], "nop")

    def test_annotations_are_isolated_by_source_content_and_old_snapshot_size(self):
        first = self.database.save_analysis(self.source, self.result(functions=[{"start": 1, "name": "first"}]))
        self.database.rename_symbol(first, 1, "renamed_first")
        self.database.set_comment(first, 1, "old bytes")
        original_size = self.source.stat().st_size
        self.source.write_bytes(b"new")
        second = self.database.save_analysis(self.source, self.result(functions=[{"start": 1, "name": "second"}]))
        self.assertEqual(self.database.annotations(second)["renames"], {})
        self.assertEqual(self.database.annotations(second)["comments"], {})
        self.assertEqual(self.database.get_snapshot(first)["functions"][0]["name"], "renamed_first")
        self.assertEqual(self.database.get_snapshot(first)["metadata"]["analysis_database"]["source_size"], original_size)
        self.assertEqual(self.database.get_snapshot(second)["metadata"]["analysis_database"]["source_size"], 3)
        self.source.unlink()
        self.database.set_comment(first, 1, "")
        self.assertEqual(self.database.annotations(first)["comments"], {})

    def test_source_cannot_be_database_or_hard_link(self):
        with self.assertRaises(StorageError):
            self.database.save_analysis(self.path, self.result())
        alias = Path(self.temp.name) / "linked-source"
        try:
            os.link(self.path, alias)
        except (NotImplementedError, OSError):
            self.skipTest("本环境无法创建硬链接")
        with self.assertRaises(StorageError):
            self.database.save_analysis(alias, self.result())
        self.assertEqual(self.database.history()["total"], 0)

    def test_source_cannot_be_database_sidecar(self):
        sidecar = Path(f"{self.path}-wal")
        sidecar.write_bytes(b"not an input")
        try:
            with self.assertRaises(StorageError):
                self.database.save_analysis(sidecar, self.result())
        finally:
            sidecar.unlink(missing_ok=True)

    def test_excessively_nested_extension_has_stable_error_and_no_commit(self):
        extension = {}
        current = extension
        for _ in range(1500):
            current["next"] = {}
            current = current["next"]
        payload = self.result().to_dict()
        payload["extension"] = extension
        with self.assertRaises(StorageError):
            self.database.save_analysis(self.source, payload)
        self.assertEqual(self.database.info()["snapshot_count"], 0)

    def test_cyclic_pooled_instruction_must_not_commit_unreadable_snapshot(self):
        instruction = {"addr": 1, "size": 1, "mnemonic": "ret"}
        instruction["self"] = instruction
        with self.assertRaises(StorageError):
            self.database.save_analysis(self.source, self.result(metadata={"disassembly": [instruction]}))
        self.assertEqual(self.database.history()["total"], 0)

    def test_mutually_recursive_pool_references_roll_back(self):
        first = {"addr": 1, "size": 1, "mnemonic": "ret"}
        second = {"addr": 2, "size": 1, "mnemonic": "ret"}
        first["peer"], second["peer"] = second, first
        with self.assertRaises(StorageError):
            self.database.save_analysis(self.source,
                self.result(metadata={"disassembly": [first, second]}))
        self.assertEqual(self.database.info()["snapshot_count"], 0)
        self.assertEqual(self.database.info()["source_count"], 0)

    def test_chunk_size_failure_rolls_back_source_sync_invalidation_and_snapshot(self):
        original = self.database.save_analysis(self.source, self.result())
        self.source.write_bytes(b"new input bytes")
        payload = self.result(functions=[{"start": 1, "name": "x" * 5000}])
        with patch.object(backend, "MAX_CHUNK_BYTES", 1024):
            with self.assertRaises(StorageError):
                self.database.save_analysis(self.source, payload)
        history = self.database.history()
        self.assertEqual(history["total"], 1)
        self.assertEqual(history["items"][0]["id"], original)
        self.assertIsNone(history["items"][0]["invalidated_at"])
        self.assertEqual(self.database.info()["source_count"], 1)

    def test_invalid_cross_collection_alias_is_rejected(self):
        snapshot_id = self.database.save_analysis(self.source,
            self.result(functions=[{"start": 1, "name": "f"}], warnings=["warning"]))
        self.sql("UPDATE fdb_collections SET alias='warnings' WHERE snapshot_id=? AND collection='functions'",
                 (snapshot_id,))
        with self.assertRaises(StorageSchemaError):
            self.database.page(snapshot_id, "functions")
        with self.assertRaises(StorageSchemaError):
            self.database.get_snapshot(snapshot_id)

    def test_nested_compressed_json_is_rejected_with_schema_error(self):
        snapshot_id = self.database.save_analysis(self.source, self.result())
        raw = b"[" * 1500 + b"0" + b"]" * 1500
        self.sql("UPDATE fdb_chunks SET data=?,raw_size=? WHERE snapshot_id=? AND collection='__manifest__'",
                 (zlib.compress(raw), len(raw), snapshot_id))
        with self.assertRaises(StorageSchemaError):
            self.database.get_snapshot(snapshot_id)

    def test_missing_chunk_and_oversized_raw_length_are_rejected(self):
        snapshot_id = self.database.save_analysis(self.source,
            self.result(functions=[{"start": 1, "name": "f"}]))
        self.sql("UPDATE fdb_chunks SET raw_size=? WHERE snapshot_id=? AND collection='functions'",
                 (backend.MAX_CHUNK_BYTES + 1, snapshot_id))
        with self.assertRaises(StorageSchemaError):
            self.database.page(snapshot_id, "functions")
        self.sql("DELETE FROM fdb_chunks WHERE snapshot_id=? AND collection='functions'", (snapshot_id,))
        with self.assertRaises(StorageSchemaError):
            self.database.page(snapshot_id, "functions")

    def test_future_storage_version_is_rejected_without_read_only_changes(self):
        self.sql("UPDATE fdb_meta SET value='999' WHERE key='storage_schema_version'")
        original = self.path.read_bytes(), self.path.stat().st_mtime_ns
        with self.assertRaises(StorageSchemaError):
            SQLiteAnalysisDatabase(self.path, read_only=True)
        self.assertEqual((self.path.read_bytes(), self.path.stat().st_mtime_ns), original)

    def test_function_only_and_empty_full_preview_ir_can_be_paged(self):
        instruction = {"addr": 1, "size": 1, "mnemonic": "ret"}
        for metadata, functions in (({}, [{"start": 1, "disassembly": [instruction]}]),
                                    ({"full_disassembly": [], "disassembly": [instruction]}, [])):
            with self.subTest(metadata=bool(metadata)):
                snapshot_id = self.database.save_analysis(self.source,
                    self.result(metadata=metadata, functions=functions))
                page = self.database.page(snapshot_id, "disassembly")
                self.assertEqual(page["total"], 1)
                self.assertEqual(page["items"][0]["mnemonic"], "ret")

    def test_service_database_close_failure_still_tears_down_manager(self):
        service = AnalysisService.__new__(AnalysisService)
        service.scheduler = Mock()
        service.database = Mock()
        service.database.close.side_effect = RuntimeError("database close failed")
        service.manager = Mock()
        with self.assertRaisesRegex(RuntimeError, "database close failed"):
            service.close()
        service.scheduler.shutdown.assert_called_once_with()
        service.manager.teardown.assert_called_once_with()

    def test_temporary_database_session_tears_down_manager_after_close_failure(self):
        registry = Mock()
        store = registry.load_storage.return_value.open_database.return_value
        store.close.side_effect = RuntimeError("database close failed")
        with patch("fangida.storage.PluginManager", return_value=registry):
            with self.assertRaisesRegex(RuntimeError, "database close failed"):
                with database_session(self.path):
                    pass
        registry.teardown.assert_called_once_with()

    def test_owned_manager_is_torn_down_after_database_initialization_failure(self):
        registry, scheduler = Mock(), Mock()
        registry.load_storage.return_value.open_database.side_effect = StorageError("cannot open database")
        with patch("fangida.dispatcher.PluginManager", return_value=registry), \
                patch("fangida.dispatcher.ResourceScheduler", return_value=scheduler):
            with self.assertRaisesRegex(StorageError, "cannot open database"):
                AnalysisService(Settings(), database_path=self.path)
        scheduler.shutdown.assert_called_once_with()
        registry.teardown.assert_called_once_with()

    def test_owned_manager_is_torn_down_after_legacy_project_initialization_failure(self):
        registry, scheduler = Mock(), Mock()
        with patch("fangida.dispatcher.PluginManager", return_value=registry), \
                patch("fangida.dispatcher.ResourceScheduler", return_value=scheduler), \
                patch("fangida.dispatcher.ProjectStore", side_effect=StorageError("cannot open project")):
            with self.assertRaisesRegex(StorageError, "cannot open project"):
                AnalysisService(Settings(), project_path=self.path)
        scheduler.shutdown.assert_called_once_with()
        registry.teardown.assert_called_once_with()

    def test_supplied_manager_is_preserved_after_database_initialization_failure(self):
        registry, scheduler = Mock(), Mock()
        registry.load_storage.return_value.open_database.side_effect = StorageError("cannot open database")
        with patch("fangida.dispatcher.ResourceScheduler", return_value=scheduler):
            with self.assertRaisesRegex(StorageError, "cannot open database"):
                AnalysisService(Settings(), manager=registry, database_path=self.path)
        scheduler.shutdown.assert_called_once_with()
        registry.teardown.assert_not_called()


if __name__ == "__main__":
    unittest.main()
