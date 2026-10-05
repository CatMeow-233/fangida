"""完整分析后处理（CLI 导出、测速摘要、项目保存、数据库读写、JSON 导出）的逐字节等价性。"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import fields
from hashlib import sha256
import io
import json
import random
import sqlite3
import tempfile
from types import MappingProxyType
import unittest
from pathlib import Path
from typing import Any, Mapping
from unittest.mock import patch

from fangida import _json_stream, benchmark, project, ui
from fangida.api import AnalysisView, open_database
from fangida.models import AnalysisResult, Instruction
from fangida.plugins import sqlite_storage
from fangida.plugins.sqlite_storage import SQLiteAnalysisDatabase
from fangida.project import ProjectStore
from fangida.scripts import ScriptCapabilities, ScriptContext


def _historical_evidence_digest(result: AnalysisResult) -> str:
    """改动前 benchmark._evidence_digest 的冻结副本。"""
    def sorted_records(items):
        return sorted(items, key=lambda item: json.dumps(item, sort_keys=True))
    evidence = {"kind": result.kind, "status": result.status,
                "functions": sorted_records(result.functions),
                "strings": sorted_records(result.strings),
                "imports": sorted_records(result.imports),
                "exports": sorted_records(result.exports),
                "xrefs": sorted_records(result.xrefs),
                "metadata": result.metadata, "warnings": sorted(result.warnings)}
    digest = sha256()
    for chunk in json.JSONEncoder(sort_keys=True, separators=(",", ":")).iterencode(evidence):
        digest.update(chunk.encode())
    return digest.hexdigest()


def _record(rng: random.Random) -> dict:
    text = lambda: "".join(rng.choice(['a', ',', ':', ' ', '"', '[', '}', '\\', 'é', '0'])
                           for _ in range(rng.randrange(4)))
    record = {"name": text(), "start": rng.randrange(-3, 3)}
    if rng.random() < 0.6:
        record["blocks"] = [{"start": rng.randrange(3), "ops": [text() for _ in range(rng.randrange(3))]}
                            for _ in range(rng.randrange(3))]
    if rng.random() < 0.5:
        record[text()] = rng.choice([None, True, 1.5, [], {}, [1, [2]], {"x": ","}])
    return record


def _result(rng: random.Random, path: str = "sample.elf") -> AnalysisResult:
    instructions = [{"addr": 0x1000 + index, "size": 2, "mnemonic": "mov",
                     "operands": ("eax", "ebx"), "branch_info": {}, "arch_meta": {"engine": "capstone"}}
                    for index in range(700)]
    return AnalysisResult(
        path, "elf", "kkagent", "partial",
        metadata={"full_disassembly": instructions, "full_analysis": {"enabled": True},
                  "sections": [{"name": ".text"}], "note": "中文 "},
        functions=[{**_record(rng), "blocks": [{"start": 0x1000, "instructions": instructions[:40]}]}
                   for _ in range(30)] + [_record(rng) for _ in range(30)],
        strings=[_record(rng) for _ in range(40)], imports=[_record(rng) for _ in range(5)],
        exports=[], xrefs=[{"src": rng.randrange(50), "dst": rng.randrange(50), "kind": "call",
                            "confidence": rng.choice([1.0, 0.5])} for _ in range(300)],
        stats={"full_analysis": True, "phase_seconds": {"disassembly": 1.0}},
        warnings=["b", "a"])


class _LegacyEncoder(sqlite_storage._Encoder):
    """改动前 _Encoder.pack/pack_mapping 的冻结副本（逐个 isinstance(Mapping) 判断）。"""

    def pack(self, value: Any) -> Any:
        if isinstance(value, Mapping):
            if (type(value.get("addr")) is int and type(value.get("size")) is int
                    and isinstance(value.get("mnemonic"), str)):
                address = value["addr"]
                candidates = self.by_address.setdefault(address, [])
                for index, previous in candidates:
                    if previous is value or previous == value:
                        return self.reference(index)
                index = len(self.instructions)
                self.instructions.append(value)
                candidates.append((index, value))
                return self.reference(index)
            return self.pack_mapping(value)
        if isinstance(value, (list, tuple)):
            return [self.pack(item) for item in value]
        return value

    def pack_mapping(self, value: Mapping[str, Any]) -> dict[str, Any]:
        if self.annotations:
            address = value.get("address", value.get("start", value.get("addr")))
            restored = None
            if type(address) is int:
                name = self.annotations["renames"].get(address)
                if (name is not None and value.get("name") == name
                        and "original_name" in value):
                    restored = dict(value)
                    restored["name"] = restored.pop("original_name")
                comment = self.annotations["comments"].get(address)
                if comment is not None and value.get("comment") == comment:
                    if restored is None:
                        restored = dict(value)
                    if "original_comment" in restored:
                        restored["comment"] = restored.pop("original_comment")
                    else:
                        restored.pop("comment", None)
            if restored is not None:
                value = restored
        packed = {key: self.pack(item) for key, item in value.items()}
        if len(packed) == 1 and (sqlite_storage._REF in packed or sqlite_storage._LITERAL in packed):
            return {sqlite_storage._LITERAL: packed}
        return packed


class _LegacyReader(sqlite_storage._Reader):
    """改动前 _Reader.expand 的冻结副本（每次引用都走 items() 与边界检查）。"""

    def expand(self, value: Any) -> Any:
        REF, LITERAL, POOL = sqlite_storage._REF, sqlite_storage._LITERAL, sqlite_storage._POOL
        StorageSchemaError = sqlite_storage.StorageSchemaError
        if isinstance(value, dict):
            if len(value) == 1 and REF in value:
                index = value[REF]
                if (type(index) is not int or index < 0
                        or index >= self.descriptor(POOL)["item_count"]):
                    raise StorageSchemaError("Invalid instruction reference")
                if index in self.resolving:
                    raise StorageSchemaError("Cyclic instruction references")
                if index not in self.instructions:
                    self.resolving.add(index)
                    try:
                        record = self.items(POOL, index, 1, expand=False)[0]
                        instruction = self.expand(record)
                        if not isinstance(instruction, dict):
                            raise StorageSchemaError("Invalid instruction pool record")
                        self.instructions[index] = instruction
                    finally:
                        self.resolving.remove(index)
                return self.instructions[index]
            if len(value) == 1 and LITERAL in value:
                literal = value[LITERAL]
                if not isinstance(literal, dict):
                    raise StorageSchemaError("Invalid escaped literal")
                return {key: self.expand(item) for key, item in literal.items()}
            return {key: self.expand(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.expand(item) for item in value]
        return value


class _Items(list):
    pass


def _storage_result(rng: random.Random, path: str, digest: str) -> AnalysisResult:
    """覆盖 Mapping/元组/列表子类、伪造引用字面量、嵌套指令和注释恢复等打包分支。"""
    result = _result(rng, path)
    pool = result.metadata["full_disassembly"]
    pool[3]["target"] = pool[4]                       # 指令内嵌指令：依赖校验与池追加
    pool[5]["original_name"], pool[5]["name"] = "orig", "renamed"
    result.functions[0]["address"] = 0x1000
    result.functions[0].update(name="renamed", original_name="main", comment="note")
    result.metadata.update(
        proxy=MappingProxyType({"k": [1, (2, 3)], "inner": MappingProxyType({"addr": 1})}),
        items=_Items([{"x": 1}, ("a", {"b": None})]),
        tupled=(pool[8], MappingProxyType({"z": (pool[9],)})),
        literal={sqlite_storage._REF: 3}, escaped={sqlite_storage._LITERAL: {"y": 2}},
        copy_of_instruction=dict(pool[7]), floats=[0.1, -0.0, 1e300],
        user_annotations={"sha256": digest, "renames": {str(0x1000): "renamed"},
                          "comments": {str(0x1000): "note"}})
    return result


class PostprocessEquivalenceTests(unittest.TestCase):
    def test_full_json_matches_standard_library_stream(self):
        result = _result(random.Random(1))
        payload = {item.name: getattr(result, item.name) for item in fields(result)}
        for ensure_ascii in (False, True):
            for value in (result, payload):
                stream = io.StringIO()
                ui._full_json(value, stream, ensure_ascii=ensure_ascii)
                expected = "".join(json.JSONEncoder(indent=2, ensure_ascii=ensure_ascii)
                                   .iterencode(payload)) + "\n"
                self.assertEqual(stream.getvalue(), expected)

    def test_full_json_writes_large_chunks(self):
        writes = []
        class Sink:
            def write(self, text):
                writes.append(len(text))
                return len(text)
        ui._full_json(_result(random.Random(2)), Sink(), ensure_ascii=False)
        tokens = sum(1 for _ in json.JSONEncoder(indent=2).iterencode(
            {item.name: getattr(_result(random.Random(2)), item.name)
             for item in fields(AnalysisResult)}))
        self.assertLess(len(writes), 10)
        self.assertGreater(tokens, 1000)

    def test_evidence_digest_matches_historical_ordering(self):
        for seed in range(25):
            result = _result(random.Random(seed))
            self.assertEqual(benchmark._evidence_digest(result), _historical_evidence_digest(result))
        empty = AnalysisResult("x", "elf", "kkagent", "error")
        self.assertEqual(benchmark._evidence_digest(empty), _historical_evidence_digest(empty))

    def test_export_json_matches_json_dumps_with_and_without_c_indent(self):
        result = _result(random.Random(4))
        result.metadata["unicode"] = "中文   \x00"
        result.metadata["specials"] = [float("inf"), float("nan"), -0.0, 10 ** 30, True, None]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for c_indent in (True, False):
                for view in (AnalysisView(result), AnalysisView._from_owned_result(result)):
                    with self.subTest(c_indent=c_indent), \
                         patch.object(_json_stream, "c_indent_supported", return_value=c_indent):
                        expected = json.dumps(view._snapshot, indent=2, ensure_ascii=False) + "\n"
                        path = view.export_json(root / "view.json")
                        self.assertEqual(path.read_text(encoding="utf-8"), expected)
                        context = ScriptContext(result, export_root=root,
                                                capabilities=ScriptCapabilities({"export"}))
                        target = context.export_json("nested/context.json")
                        self.assertEqual(target.read_text(encoding="utf-8"),
                                         json.dumps(context._snapshot, indent=2, ensure_ascii=False) + "\n")
                    with patch.object(_json_stream, "c_indent_supported", return_value=c_indent):
                        # 仍是先完整序列化再写入：编码失败时不创建文件。
                        broken = AnalysisView._from_owned_snapshot({**view.snapshot(),
                                                                   "stats": {"bad": object()}})
                        with self.assertRaises(TypeError):
                            broken.export_json(root / "broken.json")
                        self.assertFalse((root / "broken.json").exists())

    def test_project_save_matches_asdict_encoding(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.bin"
            source.write_bytes(b"\x7fELF bytes")
            result = _result(random.Random(7), str(source))
            # 嵌套 dataclass 实例过去由 asdict 展开，现在由 default 钩子展开。
            result.metadata["instruction_object"] = Instruction(1, 2, "nop", ("a",))
            result.functions.append(Instruction(3, 1, "ret", ()))
            expected_result = json.dumps(result.to_dict(), ensure_ascii=False, allow_nan=False)
            store = ProjectStore(Path(directory) / "project.sqlite")
            with patch.object(result, "to_dict", side_effect=AssertionError("deep copied graph")):
                snapshot_id = store.save_analysis(source, result)
            connection = sqlite3.connect(Path(directory) / "project.sqlite")
            try:
                saved = connection.execute("SELECT result_json FROM snapshots WHERE id=?",
                                           (snapshot_id,)).fetchone()[0]
                rows = connection.execute("SELECT collection, ordinal, value_json FROM snapshot_entries "
                                          "WHERE snapshot_id=?", (snapshot_id,)).fetchall()
            finally:
                connection.close()
            self.assertEqual(saved, expected_result)
            payload = result.to_dict()
            for collection, ordinal, value_json in rows:
                values = (payload["metadata"]["full_disassembly"] if collection == "disassembly"
                          else payload[collection])
                self.assertEqual(value_json, json.dumps(values[ordinal], ensure_ascii=False,
                                                        allow_nan=False))
            self.assertEqual(len(rows), sum(len(payload[name]) for name in
                                            ("functions", "strings", "imports", "exports",
                                             "xrefs", "warnings")) + 700)

    def test_project_save_keeps_strict_encoding_outside_the_asdict_path(self):
        class Custom(AnalysisResult):
            def to_dict(self):
                data = super().to_dict()
                data["metadata"]["custom"] = True
                return data

        class Leaky(AnalysisResult):
            def to_dict(self):
                data = super().to_dict()
                data["metadata"]["raw"] = Instruction(1, 1, "nop", ())
                return data

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.bin"
            source.write_bytes(b"bytes")
            store = ProjectStore(Path(directory) / "project.sqlite")
            mapping = AnalysisResult(str(source), "elf", "kkagent", "partial").to_dict()
            mapping["metadata"]["raw"] = Instruction(1, 1, "nop", ())
            mapping_entry = AnalysisResult(str(source), "elf", "kkagent", "partial").to_dict()
            mapping_entry["functions"] = [Instruction(1, 1, "nop", ())]
            for value in (mapping, mapping_entry, MappingProxyType(mapping),
                          Leaky(str(source), "elf", "kkagent", "partial")):
                with self.subTest(type(value).__name__), \
                     self.assertRaisesRegex(TypeError, "Object of type Instruction is not JSON serializable"):
                    store.save_analysis(source, value)
            custom = Custom(str(source), "elf", "kkagent", "partial")
            snapshot_id = store.save_analysis(source, custom)
            self.assertTrue(store.get_snapshot(snapshot_id)["metadata"]["custom"])
            odd = AnalysisResult(str(source), "elf", "kkagent", "partial")
            odd.metadata = MappingProxyType({"x": 1})  # 非 dict 元数据仍交给 asdict（无法深拷贝即报错）
            with self.assertRaises(TypeError):
                store.save_analysis(source, odd)
            self.assertEqual(len(store.history(source)["items"]), 1)

    def test_project_entries_are_encoded_before_the_transaction(self):
        events: list[str] = []
        original_hook, original_transaction = project._dataclass_json, ProjectStore._transaction

        def hook(value):
            events.append("encode")
            return original_hook(value)

        @contextmanager
        def transaction(self):
            events.append("transaction")
            with original_transaction(self) as connection:
                yield connection

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.bin"
            source.write_bytes(b"bytes")
            store = ProjectStore(Path(directory) / "project.sqlite")
            result = AnalysisResult(str(source), "elf", "kkagent", "partial",
                                    functions=[Instruction(index, 1, "nop", ()) for index in range(3)],
                                    warnings=["w"])
            with patch.object(project, "_dataclass_json", hook), \
                 patch.object(ProjectStore, "_transaction", transaction):
                store.save_analysis(source, result)
            # 3 次条目编码 + 3 次 result_json 编码，全部早于事务开始。
            self.assertEqual(events, ["encode"] * 6 + ["transaction"])
            failing = AnalysisResult(str(source), "elf", "kkagent", "partial",
                                     warnings=["ok"], xrefs=[{"confidence": float("nan")}])
            with self.assertRaises(ValueError):
                store.save_analysis(source, failing)
            self.assertEqual(len(store.history(source)["items"]), 1)

    def test_sqlite_storage_bytes_and_snapshots_match_legacy_codec(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.bin"
            source.write_bytes(b"\x7fELF bytes")
            digest = project.fingerprint(source)[0]
            for seed in range(3):
                result = _storage_result(random.Random(seed), str(source), digest)
                paths = {}
                for name, encoder in (("legacy", _LegacyEncoder), ("current", sqlite_storage._Encoder)):
                    paths[name] = Path(directory) / f"{name}-{seed}.fdb"
                    with patch.object(sqlite_storage, "_Encoder", encoder):
                        database = SQLiteAnalysisDatabase(paths[name], create=True)
                        try:
                            database.save_analysis(source, result)
                        finally:
                            database.close()
                dumps = []
                for name in ("legacy", "current"):
                    connection = sqlite3.connect(paths[name])
                    try:
                        dumps.append((
                            connection.execute("SELECT collection,chunk_index,ordinal_start,item_count,"
                                               "raw_size,data FROM fdb_chunks ORDER BY rowid").fetchall(),
                            connection.execute("SELECT collection,item_count,chunk_count,alias "
                                               "FROM fdb_collections ORDER BY rowid").fetchall(),
                            connection.execute("SELECT result_json FROM snapshots").fetchall()))
                    finally:
                        connection.close()
                self.assertEqual(dumps[0], dumps[1])
                snapshots = []
                for reader in (_LegacyReader, sqlite_storage._Reader):
                    with patch.object(sqlite_storage, "_Reader", reader):
                        database = SQLiteAnalysisDatabase(paths["current"], read_only=True)
                        try:
                            snapshots.append(database.get_snapshot())
                        finally:
                            database.close()
                legacy, current = snapshots
                self.assertEqual(json.dumps(current), json.dumps(legacy))
                # 共享的指令对象在两种实现中保持相同的别名结构。
                for snapshot in (legacy, current):
                    self.assertIs(snapshot["functions"][0]["blocks"][0]["instructions"][0],
                                  snapshot["metadata"]["full_disassembly"][0])

    def test_open_database_owns_fresh_sqlite_snapshot_but_stays_isolated(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.bin"
            source.write_bytes(b"\x7fELF bytes")
            path = Path(directory) / "saved.fdb"
            database = SQLiteAnalysisDatabase(path, create=True)
            try:
                database.save_analysis(source, _result(random.Random(3), str(source)))
            finally:
                database.close()
            reader = SQLiteAnalysisDatabase(path, read_only=True)
            try:
                expected = reader.get_snapshot()
            finally:
                reader.close()
            first, second = open_database(path), open_database(path)
            self.assertEqual(first.snapshot(), expected)
            self.assertIsNot(first._snapshot, second._snapshot)
            first.functions()[0]["name"] = "changed"
            self.assertEqual(first.snapshot(), second.snapshot())

            class CachingDatabase(SQLiteAnalysisDatabase):
                """子类可能复用快照：不得继承“可直接接管”的声明。"""
            self.assertFalse(CachingDatabase(path, read_only=True).fresh_snapshots)
            self.assertTrue(SQLiteAnalysisDatabase(path, read_only=True).fresh_snapshots)
            self.assertIsInstance(AnalysisView.from_snapshot(expected), AnalysisView)


if __name__ == "__main__":
    unittest.main()
