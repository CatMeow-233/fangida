"""Portable storage, bounded paging, isolation and durable annotation checks."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zlib

from fangida.models import AnalysisResult
from fangida.plugins.sqlite_storage import (CHUNK_ITEMS, FORMAT, MAX_CHUNK_BYTES,
                                            PluginImpl, SQLiteAnalysisDatabase)
from fangida.project import ProjectStore, SourceChangedError, fingerprint
from fangida.storage import StorageError, StorageSchemaError


@contextmanager
def sqlite_connection(path):
    connection = sqlite3.connect(path)
    try:
        with connection:
            yield connection
    finally:
        connection.close()


class StorageBackendTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.source = self.directory / "original.bin"
        self.source.write_bytes(b"an-original-file-which-is-not-embedded")
        self.path = self.directory / "analysis.fdb"
        self.plugin = PluginImpl()
        self.addCleanup(self.plugin.teardown)

    def result(self, count: int = 2) -> AnalysisResult:
        instructions = [{"addr": 0x1000 + index, "size": 1, "mnemonic": "ret",
                         "operands": [], "reads": [], "writes": [],
                         "branch_info": {"kind": "return"}, "arch_meta": {}}
                        for index in range(count)]
        return AnalysisResult(str(self.source), "elf", "kkagent", "partial",
            metadata={"disassembly": instructions[:1], "full_disassembly": instructions},
            functions=[{"address": 0x1000, "start": 0x1000, "name": "old_name",
                        "disassembly": [dict(item) for item in instructions],
                        "blocks": [{"instructions": [dict(item) for item in instructions]}]}],
            strings=[{"address": 0x5000, "value": "hello"}], warnings=["limited"])

    def database(self) -> SQLiteAnalysisDatabase:
        return self.plugin.open_database(self.path, create=True)

    def test_offline_reopen_and_consistent_annotation_overlay(self) -> None:
        database = self.database()
        identifier = database.save_analysis(self.source, self.result())
        self.source.unlink()
        database.rename_symbol(identifier, 0x1000, "user_name")
        database.set_comment(identifier, 0x1000, "function and instruction comment")
        database.set_comment(identifier, 0xFFFFFFFFFFFFFFF0, "outside recovered code")
        database.close()
        reopened = self.plugin.open_database(self.path)
        payload = reopened.get_snapshot()
        function = payload["functions"][0]
        self.assertEqual(function["name"], "user_name")
        self.assertEqual(function["original_name"], "old_name")
        self.assertEqual(function["comment"], "function and instruction comment")
        for record in (function["disassembly"][0], function["blocks"][0]["instructions"][0],
                       payload["metadata"]["full_disassembly"][0]):
            self.assertEqual(record["comment"], "function and instruction comment")
        self.assertEqual(reopened.page(identifier, "functions")["items"][0], function)
        self.assertEqual(reopened.page(identifier, "disassembly")["items"][0]["comment"],
                         "function and instruction comment")
        self.assertEqual(reopened.annotations(identifier)["comments"][0xFFFFFFFFFFFFFFF0],
                         "outside recovered code")
        self.assertEqual(payload["metadata"]["user_annotations"]["comments"][str(0xFFFFFFFFFFFFFFF0)],
                         "outside recovered code")
        self.assertEqual(payload["metadata"]["analysis_database"]["snapshot_id"], identifier)
        self.assertEqual(reopened.history(self.source)["total"], 1)
        reopened.set_comment(identifier, 0x1000, "")
        self.assertNotIn("comment", reopened.get_snapshot()["functions"][0])

    def test_shared_instruction_pool_roundtrip_and_no_duplicate_entries(self) -> None:
        original = self.result(count=CHUNK_ITEMS + 9)
        with patch.object(AnalysisResult, "to_dict", side_effect=AssertionError("deep copy forbidden")):
            identifier = self.database().save_analysis(self.source, original)
        database = self.plugin.open_database(self.path)
        restored = database.get_snapshot(identifier)
        restored["metadata"].pop("analysis_database")
        restored["metadata"].pop("user_annotations")
        self.assertEqual(restored, original.to_dict())
        with sqlite_connection(self.path) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM snapshot_entries").fetchone()[0], 0)
            count = connection.execute("SELECT item_count FROM fdb_collections "
                                       "WHERE collection='__instructions__'").fetchone()[0]
            self.assertEqual(count, CHUNK_ITEMS + 9)
            descriptor = connection.execute("SELECT result_json FROM snapshots").fetchone()[0]
            self.assertNotIn("mnemonic", descriptor)
            self.assertLess(len(descriptor), 200)
        self.assertFalse(database.info()["stores_original_binary"])

    def test_paging_reads_only_requested_chunks_and_applies_comments(self) -> None:
        database = self.database()
        identifier = database.save_analysis(self.source, self.result(count=3 * CHUNK_ITEMS))
        database.set_comment(identifier, 0x1000 + CHUNK_ITEMS, "boundary")
        with patch.object(database, "get_snapshot", side_effect=AssertionError("full load forbidden")):
            page = database.page(identifier, "disassembly", offset=CHUNK_ITEMS, limit=3)
        self.assertEqual(page["total"], 3 * CHUNK_ITEMS)
        self.assertEqual(page["next_offset"], CHUNK_ITEMS + 3)
        self.assertEqual(page["items"][0]["comment"], "boundary")
        self.assertEqual(database.page(identifier, "disassembly", offset=3 * CHUNK_ITEMS)["items"], [])
        self.assertEqual(database.page(identifier, "warnings")["items"], ["limited"])

    def test_read_only_never_creates_mutates_or_requires_source(self) -> None:
        with self.assertRaises(FileNotFoundError):
            self.plugin.open_database(self.path, read_only=True)
        with self.assertRaises(ValueError):
            self.plugin.open_database(self.path, read_only=True, create=True)
        identifier = self.database().save_analysis(self.source, self.result())
        self.source.unlink()
        reader = self.plugin.open_database(self.path, read_only=True)
        self.assertTrue(reader.get_snapshot()["metadata"]["analysis_database"]["read_only"])
        for operation in (lambda: reader.save_analysis(self.source, self.result()),
                          lambda: reader.rename_symbol(identifier, 0x1000, "new"),
                          lambda: reader.set_comment(identifier, 0x1000, "new")):
            with self.assertRaises(StorageError):
                operation()
        self.assertEqual(reader.page(identifier, "functions")["total"], 1)

    def test_explicit_create_does_not_accept_or_overwrite_other_formats(self) -> None:
        with self.assertRaises(FileNotFoundError):
            self.plugin.open_database(self.path)
        self.assertFalse(self.path.exists())
        self.path.write_bytes(b"not SQLite")
        for create in (False, True):
            with self.assertRaises(StorageSchemaError):
                self.plugin.open_database(self.path, create=create)
        self.assertEqual(self.path.read_bytes(), b"not SQLite")
        self.path.unlink()
        with sqlite_connection(self.path) as connection:
            connection.execute("CREATE TABLE harmless (value TEXT)")
        before = self.path.read_bytes()
        with self.assertRaises(StorageSchemaError):
            self.plugin.open_database(self.path, create=True)
        self.assertEqual(self.path.read_bytes(), before)

    def test_legacy_project_is_not_silently_migrated(self) -> None:
        legacy = ProjectStore(self.path)
        legacy.save_analysis(self.source, self.result())
        before = self.path.read_bytes()
        with self.assertRaises(StorageSchemaError):
            self.plugin.open_database(self.path, create=True)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(legacy.history()["total"], 1)

    def test_future_versions_rejected_without_modification(self) -> None:
        database = self.database()
        database.close()
        with sqlite_connection(self.path) as connection:
            connection.execute("UPDATE fdb_meta SET value='999' WHERE key='storage_schema_version'")
        before = self.path.read_bytes()
        for read_only in (False, True):
            with self.assertRaises(StorageSchemaError):
                self.plugin.open_database(self.path, read_only=read_only)
        self.assertEqual(self.path.read_bytes(), before)

    def test_base_future_version_and_missing_schema_rejected(self) -> None:
        self.database().close()
        with sqlite_connection(self.path) as connection:
            connection.execute("PRAGMA user_version=999")
        with self.assertRaises(StorageSchemaError):
            self.plugin.open_database(self.path)
        with sqlite_connection(self.path) as connection:
            connection.execute("PRAGMA user_version=2")
            connection.execute("DROP TABLE fdb_chunks")
        with self.assertRaises(StorageSchemaError):
            self.plugin.open_database(self.path)

    def test_source_change_rolls_back_all_chunks_and_file_mutations(self) -> None:
        database = self.database()
        identifier = database.save_analysis(self.source, self.result())
        before = fingerprint(self.source)
        with patch("fangida.plugins.sqlite_storage.fingerprint",
                   side_effect=[before, ("0" * 64, before[1])]):
            with self.assertRaises(SourceChangedError):
                database.save_analysis(self.source, self.result(count=CHUNK_ITEMS + 1))
        self.assertEqual(database.history()["total"], 1)
        self.assertEqual(database.get_snapshot()["metadata"]["analysis_database"]["snapshot_id"], identifier)
        with self.assertRaises(SourceChangedError):
            database.save_analysis(self.source, self.result(), expected_hash="0" * 64)
        with sqlite_connection(self.path) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(DISTINCT snapshot_id) FROM fdb_chunks").fetchone()[0], 1)

    def test_annotations_are_scoped_to_snapshot_hash_and_old_sizes_are_immutable(self) -> None:
        database = self.database()
        old_size = self.source.stat().st_size
        old = database.save_analysis(self.source, self.result())
        database.rename_symbol(old, 0x1000, "first_content")
        self.source.write_bytes(b"new")
        new = database.save_analysis(self.source, self.result())
        self.assertEqual(database.get_snapshot(old)["functions"][0]["name"], "first_content")
        self.assertEqual(database.get_snapshot(old)["metadata"]["analysis_database"]["source_size"], old_size)
        self.assertEqual(database.get_snapshot(new)["functions"][0]["name"], "old_name")
        self.assertEqual(database.get_snapshot(new)["metadata"]["analysis_database"]["source_size"], 3)
        self.assertIsNotNone(database.history()["items"][1]["invalidated_at"])

    def test_concurrent_connections_and_separate_process_offline_load(self) -> None:
        database = self.database()
        with ThreadPoolExecutor(max_workers=4) as executor:
            identifiers = list(executor.map(lambda _: database.save_analysis(self.source, self.result()), range(6)))
        self.assertEqual(len(set(identifiers)), 6)
        self.assertEqual(database.history()["total"], 6)
        self.source.unlink()
        code = ("import json,sys;from fangida.plugins.sqlite_storage import PluginImpl;"
                "p=PluginImpl();d=p.open_database(sys.argv[1],read_only=True);"
                "print(json.dumps({'name':d.get_snapshot()['functions'][0]['name'],"
                "'total':d.history()['total']}));p.teardown()")
        completed = subprocess.run([sys.executable, "-c", code, str(self.path)],
                                   capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(completed.stdout), {"name": "old_name", "total": 6})

    def test_corrupt_compression_count_and_oversized_length_are_rejected(self) -> None:
        database = self.database()
        identifier = database.save_analysis(self.source, self.result())
        with sqlite_connection(self.path) as connection:
            original = connection.execute("SELECT data,raw_size FROM fdb_chunks WHERE collection='__manifest__'").fetchone()
            connection.execute("UPDATE fdb_chunks SET raw_size=? WHERE collection='__manifest__'",
                               (MAX_CHUNK_BYTES + 1,))
        with self.assertRaises(StorageSchemaError):
            database.get_snapshot(identifier)
        with sqlite_connection(self.path) as connection:
            connection.execute("UPDATE fdb_chunks SET raw_size=?,data=? WHERE collection='__manifest__'", original[::-1])
            connection.execute("UPDATE fdb_chunks SET item_count=2 WHERE collection='__manifest__'")
        with self.assertRaises(StorageSchemaError):
            database.get_snapshot(identifier)
        with sqlite_connection(self.path) as connection:
            connection.execute("UPDATE fdb_chunks SET item_count=1,data=? WHERE collection='__manifest__'", (b"bad",))
        with self.assertRaises(StorageSchemaError):
            database.get_snapshot(identifier)

    def test_internal_markers_do_not_change_literal_user_data(self) -> None:
        result = self.result()
        result.metadata["literal"] = {"$fdb_instruction": 0}
        result.metadata["another_literal"] = {"$fdb_literal": {"$fdb_instruction": 99}}
        database = self.database()
        identifier = database.save_analysis(self.source, result)
        metadata = database.get_snapshot(identifier)["metadata"]
        self.assertEqual(metadata["literal"], result.metadata["literal"])
        self.assertEqual(metadata["another_literal"], result.metadata["another_literal"])

    def test_save_as_imports_editable_annotations_without_baking_or_copying_ir(self) -> None:
        result = self.result()
        result.functions[0]["comment"] = "analysis function comment"
        result.metadata["full_disassembly"][0]["comment"] = "analysis instruction comment"
        database = self.database()
        identifier = database.save_analysis(self.source, result)
        database.rename_symbol(identifier, 0x1000, "original_user_name")
        database.set_comment(identifier, 0x1000, "user comment")
        payload = database.get_snapshot(identifier)
        other = self.plugin.open_database(self.directory / "save-as.fdb", create=True)
        copied = other.save_analysis(self.source, payload)
        self.assertEqual(other.annotations(copied)["renames"][0x1000], "original_user_name")
        self.assertEqual(other.get_snapshot(copied)["functions"][0]["original_name"], "old_name")
        other.rename_symbol(copied, 0x1000, "edited_in_copy")
        other.set_comment(copied, 0x1000, "")
        restored = other.get_snapshot(copied)
        self.assertEqual(restored["functions"][0]["name"], "edited_in_copy")
        self.assertEqual(restored["functions"][0]["original_name"], "old_name")
        self.assertEqual(restored["functions"][0]["comment"], "analysis function comment")
        self.assertEqual(restored["metadata"]["full_disassembly"][0]["comment"], "analysis instruction comment")
        self.assertNotIn("comment", restored["functions"][0]["blocks"][0]["instructions"][0])
        self.assertEqual(payload["functions"][0]["name"], "original_user_name")
        self.assertEqual(payload["functions"][0]["comment"], "user comment")
        self.assertEqual(database.get_snapshot(identifier)["functions"][0]["name"], "original_user_name")

    def test_save_as_rejects_annotation_hash_mismatch_without_mutation(self) -> None:
        database = self.database()
        payload = self.result().to_dict()
        payload["metadata"]["user_annotations"] = {
            "sha256": "0" * 64, "renames": {"4096": "wrong_source"}, "comments": {}}
        with self.assertRaises(SourceChangedError):
            database.save_analysis(self.source, payload)
        self.assertEqual(database.history()["total"], 0)

    def test_empty_snapshot_and_validation(self) -> None:
        database = self.database()
        with self.assertRaises(KeyError):
            database.get_snapshot()
        self.assertIsNone(database.info()["latest_snapshot_id"])
        with self.assertRaises(ValueError):
            database.save_analysis(self.source, {"status": "partial", "schema_version": "1.0", "functions": {}})
        with self.assertRaises(ValueError):
            database.page(1, "functions", offset=True)
        with self.assertRaises(ValueError):
            database.rename_symbol(1, 0x1000, "bad\nname")
        with self.assertRaises(ValueError):
            database.set_comment(1, -1, "bad")
        self.assertEqual(database.history()["total"], 0)

    def test_teardown_and_context_close_live_databases(self) -> None:
        database = self.database()
        with self.plugin.open_database(self.path) as temporary:
            self.assertEqual(temporary.info()["format"], FORMAT)
        with self.assertRaises(StorageError):
            temporary.info()
        self.plugin.teardown()
        with self.assertRaises(StorageError):
            database.info()
        with self.assertRaises(StorageError):
            self.plugin.open_database(self.path)

    def test_storage_import_does_not_load_analysis_modules(self) -> None:
        code = ("import json,sys;from fangida.plugins.sqlite_storage import PluginImpl;"
                "print(json.dumps(sorted(name for name in sys.modules if name.startswith("
                "('fangida.core','fangida.loaders','fangida.processors','capstone')))))")
        completed = subprocess.run([sys.executable, "-c", code], capture_output=True,
                                   text=True, check=True)
        self.assertEqual(json.loads(completed.stdout), [])


if __name__ == "__main__":
    unittest.main()
