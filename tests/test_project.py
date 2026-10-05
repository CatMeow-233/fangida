"""Persistence and invalidation checks for the project database."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from fangida.models import AnalysisResult
from fangida.project import (ProjectError, ProjectSchemaError, ProjectStore, SourceChangedError,
                             fingerprint)


class ProjectStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / "sample.bin"
        self.source.write_bytes(b"binary-A")
        self.database = Path(self.temp.name) / "projects" / "sample.fangida"

    def result(self) -> AnalysisResult:
        return AnalysisResult(
            str(self.source), "elf", "kkagent", "partial",
            metadata={"disassembly": [{"addr": 0x1000, "mnemonic": "ret"}]},
            functions=[{"address": 0x1000, "name": "old"},
                       {"address": 0x2000, "name": "other"}],
            strings=[{"address": 0x5000, "value": "hello"}],
            warnings=["limited scan"])

    def test_reopen_page_and_content_scoped_annotations(self) -> None:
        store = ProjectStore(self.database)
        snapshot_id = store.save_analysis(self.source, self.result())
        store.rename_symbol(self.source, 0xFFFFFFFFFFFFFFF0, "renamed")
        store.set_comment(self.source, 0x1000, "explained\nwell")
        reopened = ProjectStore(self.database)
        self.assertEqual(reopened.load_analysis(self.source)["strings"][0]["value"], "hello")
        self.assertEqual(reopened.get_snapshot(snapshot_id)["functions"][0]["name"], "old")
        first_page = reopened.page(snapshot_id, "functions", limit=1)
        self.assertEqual(first_page["total"], 2)
        self.assertEqual(first_page["next_offset"], 1)
        self.assertEqual(reopened.page(snapshot_id, "functions", offset=1, limit=1)["items"][0]["name"], "other")
        self.assertEqual(reopened.page(snapshot_id, "disassembly")["items"][0]["mnemonic"], "ret")
        self.assertEqual(reopened.page(snapshot_id, "warnings")["items"], ["limited scan"])
        annotations = reopened.annotations(self.source)
        self.assertEqual(annotations["renames"][0xFFFFFFFFFFFFFFF0], "renamed")
        self.assertEqual(annotations["comments"][0x1000], "explained\nwell")
        self.assertEqual(reopened.history(self.source)["total"], 1)

    def test_changed_bytes_invalidate_even_with_same_file_size(self) -> None:
        store = ProjectStore(self.database)
        old_id = store.save_analysis(self.source, self.result())
        old_hash, _ = fingerprint(self.source)
        store.rename_symbol(self.source, 0x1000, "custom")
        self.source.write_bytes(b"binary-B")
        self.assertIsNone(store.load_analysis(self.source))
        self.assertEqual(store.annotations(self.source)["renames"], {})
        self.assertEqual(store.get_snapshot(old_id)["metadata"]["disassembly"][0]["mnemonic"], "ret")
        self.assertIsNotNone(store.history(self.source)["items"][0]["invalidated_at"])
        with self.assertRaises(SourceChangedError):
            store.save_analysis(self.source, self.result(), expected_hash=old_hash)
        self.assertEqual(store.history(self.source)["total"], 1)
        new_id = store.save_analysis(self.source, self.result())
        self.assertNotEqual(new_id, old_id)
        self.assertIsNotNone(store.load_analysis(self.source))
        store.invalidate(self.source)
        self.assertIsNone(store.load_analysis(self.source))

    def test_transaction_rollback_and_concurrent_saves(self) -> None:
        store = ProjectStore(self.database)
        original = fingerprint(self.source)
        with patch("fangida.project.fingerprint",
                   side_effect=[original, ("0" * 64, original[1])]):
            with self.assertRaises(SourceChangedError):
                store.save_analysis(self.source, self.result())
        self.assertEqual(store.history(self.source)["total"], 0)
        self.assertIsNone(store.load_analysis(self.source))

        def save_one(_: int) -> int:
            return ProjectStore(self.database).save_analysis(self.source, self.result())

        with ThreadPoolExecutor(max_workers=6) as executor:
            identifiers = list(executor.map(save_one, range(12)))
        self.assertEqual(len(set(identifiers)), 12)
        self.assertEqual(store.history(self.source)["total"], 12)
        self.assertEqual(store.history(self.source, offset=10, limit=1)["next_offset"], 11)

    def test_upgrade_v1_and_reject_newer_schema(self) -> None:
        self.database.parent.mkdir(parents=True)
        with closing(sqlite3.connect(self.database)) as connection, connection:
            ProjectStore._create_v1(connection)
            connection.execute("PRAGMA user_version=1")
        migrated = ProjectStore(self.database)
        migrated.rename_symbol(self.source, 123, "foo")
        self.assertEqual(migrated.annotations(self.source)["renames"][123], "foo")
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("PRAGMA user_version=999")
        with self.assertRaises(ProjectSchemaError):
            ProjectStore(self.database)

    def test_bad_inputs_never_write(self) -> None:
        store = ProjectStore(self.database)
        with self.assertRaises(ValueError):
            store.rename_symbol(self.source, -1, "bad")
        with self.assertRaises(ValueError):
            store.rename_symbol(self.source, 1, "bad\nname")
        with self.assertRaises(ValueError):
            store.page(1, "functions", limit=0)
        with self.assertRaises(KeyError):
            store.get_snapshot(1)
        self.assertEqual(store.history()["total"], 0)

    def test_read_only_store_does_not_migrate_or_mutate(self) -> None:
        with self.assertRaises(FileNotFoundError):
            ProjectStore(self.database, read_only=True)
        writer = ProjectStore(self.database)
        snapshot_id = writer.save_analysis(self.source, self.result())
        writer.rename_symbol(self.source, 0x1000, "mine")
        reader = ProjectStore(self.database, read_only=True)
        self.assertEqual(reader.get_snapshot(snapshot_id)["status"], "partial")
        self.assertEqual(reader.load_analysis(self.source)["status"], "partial")
        self.assertEqual(reader.page(snapshot_id, "functions")["total"], 2)
        self.assertEqual(reader.annotations(self.source)["renames"][0x1000], "mine")
        for mutate in (lambda: reader.save_analysis(self.source, self.result()),
                       lambda: reader.rename_symbol(self.source, 0x1000, "new"),
                       lambda: reader.set_comment(self.source, 0x1000, "text"),
                       lambda: reader.invalidate(self.source)):
            with self.assertRaises(ProjectError):
                mutate()
        self.source.write_bytes(b"binary-B")
        self.assertIsNone(reader.load_analysis(self.source))
        self.assertIsNone(writer.history(self.source)["items"][0]["invalidated_at"])
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("PRAGMA user_version=1")
        with self.assertRaises(ProjectSchemaError):
            ProjectStore(self.database, read_only=True)


if __name__ == "__main__":
    unittest.main()
