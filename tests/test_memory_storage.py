"""分析数据库读写的内存优化：值、类型、键顺序与写入的数据库都与改动前逐字一致，只改变对象共享。

覆盖：_disassembly_records 快速路径与分组回退、_Encoder.by_address 紧凑索引、读回时字符串与
指令子字典的规范化、列表按实际长度分配且不跨记录共享、函数 xrefs_in/xrefs_out 与顶层 xrefs
重新共享，以及标注叠加（存储层 _overlay 与界面 _apply_annotation）不会连带修改共享对象。
"""
from __future__ import annotations

import gc
import json
import random
import sqlite3
import sys
import tempfile
import unittest
import weakref
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping
from unittest.mock import patch

from fangida import gui
from fangida.models import AnalysisResult
from fangida.plugins import sqlite_storage
from fangida.plugins.sqlite_storage import SQLiteAnalysisDatabase


def _legacy_disassembly_records(payload: Mapping[str, Any], metadata: Mapping[str, Any]) -> list[Any]:
    """改动前 _disassembly_records 的冻结副本（(source, 地址) 元组键 + 排序键）。"""
    indexed: dict[tuple[str, int], Mapping[str, Any]] = {}

    def collect(values: Any, source: str = "") -> None:
        if not isinstance(values, list):
            return
        for value in values:
            if type(value) is not dict and not isinstance(value, Mapping):
                continue
            address = value.get("addr", value.get("address", value.get("offset")))
            if type(address) is not int or address < 0:
                continue
            if source and "source" not in value:
                value = {**value, "source": source}
            indexed[(str(value.get("source", "")), address)] = value

    for values in (payload.get("instructions"), metadata.get("disassembly"),
                   metadata.get("full_disassembly"), metadata.get("instructions")):
        collect(values)
    bytecode = payload.get("kind") in {"apk", "dex", "jar", "class"}
    for function in payload.get("functions", []):
        if type(function) is not dict and not isinstance(function, Mapping):
            continue
        source = str(function.get("source", "")) if bytecode else ""
        collect(function.get("instructions"), source)
        collect(function.get("disassembly"), source)
        blocks = function.get("blocks", [])
        if isinstance(blocks, list):
            for block in blocks:
                if type(block) is dict or isinstance(block, Mapping):
                    collect(block.get("instructions"), source)
    return [indexed[key] for key in sorted(indexed, key=lambda key: (key[1], key[0]))]


class _LegacyEncoder(sqlite_storage._Encoder):
    """改动前 _Encoder.pack 的冻结副本：by_address 为每个地址保存 [(index, record)]。"""

    def pack(self, value: Any) -> Any:
        kind = type(value)
        if kind in sqlite_storage._SCALARS:
            return value
        if kind is dict or (kind is not list and kind is not tuple and isinstance(value, Mapping)):
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
        if kind is list or kind is tuple or isinstance(value, (list, tuple)):
            return [self.pack(item) for item in value]
        return value


class _LegacyReader(sqlite_storage._Reader):
    """改动前 _Reader.expand 的冻结副本：不规范化字符串，不共享子字典，列表按追加增长。"""

    def expand(self, value: Any) -> Any:
        if isinstance(value, dict):
            if len(value) == 1 and sqlite_storage._REF in value:
                index = value[sqlite_storage._REF]
                if type(index) is int:
                    cached = self.instructions.get(index)
                    if cached is not None:
                        return cached
                if (type(index) is not int or index < 0
                        or index >= self.descriptor(sqlite_storage._POOL)["item_count"]):
                    raise sqlite_storage.StorageSchemaError("Invalid instruction reference")
                if index in self.resolving:
                    raise sqlite_storage.StorageSchemaError("Cyclic instruction references")
                if index not in self.instructions:
                    self.resolving.add(index)
                    try:
                        instruction = self.expand(self._pool_record(index))
                        if not isinstance(instruction, dict):
                            raise sqlite_storage.StorageSchemaError("Invalid instruction pool record")
                        self.instructions[index] = instruction
                    finally:
                        self.resolving.remove(index)
                return self.instructions[index]
            if len(value) == 1 and sqlite_storage._LITERAL in value:
                literal = value[sqlite_storage._LITERAL]
                if not isinstance(literal, dict):
                    raise sqlite_storage.StorageSchemaError("Invalid escaped literal")
                return {key: self.expand(item) for key, item in literal.items()}
            return {key: (item if type(item) in sqlite_storage._SCALARS else self.expand(item))
                    for key, item in value.items()}
        if isinstance(value, list):
            return [item if type(item) in sqlite_storage._SCALARS else self.expand(item) for item in value]
        return value


def _instructions(count: int, start: int = 0x1000) -> list[dict[str, Any]]:
    """与完整分析相同的形状：arch_meta/branch_info 与操作数元组在记录之间共享。"""
    meta = {"engine": "capstone", "architecture": "arm64"}
    plain, call = {}, {"kind": "call", "target": 0x1000, "conditional": False}
    operands = ("x0", "x1")
    records = []
    for index in range(count):
        records.append({"addr": start + index * 4, "size": 4,
                        "mnemonic": "bl" if index % 5 == 0 else "mov",
                        "operands": operands, "reads": ("x1",), "writes": ("x0",) if index % 2 else (),
                        "branch_info": call if index % 5 == 0 else plain,
                        "arch_meta": meta if index % 7 else {"engine": "capstone", "architecture": "arm64",
                                                             "memory_references": (start + index,)}})
    return records


def _full_result(path: str, count: int = 1200) -> AnalysisResult:
    full = _instructions(count)
    functions, xrefs = [], []
    for number, first in enumerate(range(0, count, 40)):
        rows = full[first:first + 40]
        half = max(1, len(rows) // 2)
        functions.append({"name": f"sub_{rows[0]['addr']:x}", "start": rows[0]["addr"],
                          "address": rows[0]["addr"], "comment": "auto" if number % 3 == 0 else None,
                          "blocks": [{"start": rows[0]["addr"], "instructions": rows[:half]},
                                     {"start": rows[half]["addr"], "instructions": rows[half:]}]
                                    if len(rows) > 1 else [{"start": rows[0]["addr"], "instructions": rows}],
                          "xrefs_in": [], "xrefs_out": []})
    by_start = {function["start"]: function for function in functions}
    for row in full:
        if row["mnemonic"] == "bl":
            target = functions[(row["addr"] // 4) % len(functions)]["start"]
            reference = {"src": row["addr"], "dst": target, "kind": "call", "confidence": 1.0}
            if row["addr"] % 3 == 0:
                reference["evidence"] = "mapped_immediate"
            xrefs.append(reference)
            by_start[target]["xrefs_in"].append(reference)
            owner = functions[(row["addr"] - 0x1000) // 4 // 40]
            owner["xrefs_out"].append(reference)
    return AnalysisResult(path, "elf", "kkagent", "complete",
                          metadata={"full_disassembly": full, "disassembly": full[:50],
                                    "full_analysis": {"enabled": True}},
                          functions=functions, xrefs=xrefs,
                          strings=[{"address": 0x9000 + index, "value": "text"} for index in range(30)],
                          stats={"full_analysis": True}, warnings=["w"])


class _Workspace(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = self.root / "sample.elf"
        self.source.write_bytes(b"\x7fELF sample bytes")

    def save(self, result: Any, name: str = "saved.fdb", *, legacy: bool = False) -> Path:
        """legacy=True 时用改动前的编码器与 _disassembly_records 写入，作为逐字节对照。"""
        path = self.root / name
        with patch.object(sqlite_storage, "_Encoder", _LegacyEncoder if legacy else sqlite_storage._Encoder), \
             patch.object(sqlite_storage, "_disassembly_records",
                          _legacy_disassembly_records if legacy else sqlite_storage._disassembly_records):
            database = SQLiteAnalysisDatabase(path, create=True)
            try:
                database.save_analysis(self.source, result)
            finally:
                database.close()
        return path

    @staticmethod
    def read(path: Path, *, reader: Any = None, reshare: bool = True) -> dict[str, Any]:
        with patch.object(sqlite_storage, "_Reader", reader or sqlite_storage._Reader), \
             patch.object(sqlite_storage, "_reshare_references",
                          sqlite_storage._reshare_references if reshare else (lambda payload: None)):
            database = SQLiteAnalysisDatabase(path, read_only=True)
            try:
                return database.get_snapshot()
            finally:
                database.close()

    @staticmethod
    def dump(path: Path) -> list[Any]:
        connection = sqlite3.connect(path)
        try:
            return [connection.execute("SELECT collection,chunk_index,ordinal_start,item_count,raw_size,data "
                                       "FROM fdb_chunks ORDER BY rowid").fetchall(),
                    connection.execute("SELECT collection,item_count,chunk_count,alias "
                                       "FROM fdb_collections ORDER BY rowid").fetchall(),
                    connection.execute("SELECT status,result_schema,result_json FROM snapshots").fetchall()]
        finally:
            connection.close()

    def assertIdenticalValues(self, left: Any, right: Any) -> None:
        # repr 区分 list/tuple、1/1.0/True、-0.0；JSON 再核对键顺序。
        self.assertEqual(repr(left), repr(right))
        self.assertEqual(json.dumps(left), json.dumps(right))


class DisassemblyRecordsTests(unittest.TestCase):
    def assertSameRecords(self, payload: dict[str, Any], metadata: dict[str, Any]) -> list[Any]:
        expected = _legacy_disassembly_records(payload, metadata)
        actual = sqlite_storage._disassembly_records(payload, metadata)
        self.assertIs(type(actual), list)
        self.assertEqual(len(actual), len(expected))
        # 输入里的记录必须原样（同一对象）返回；字节码补 source 时新建的副本按值比较。
        self.assertTrue(all(left is right or (type(left) is type(right) and left == right
                                              and "source" in left and "source" in right)
                            for left, right in zip(actual, expected)))
        return actual

    def test_full_analysis_shape_takes_fast_path_and_returns_same_objects(self):
        result = _full_result("sample.elf")
        payload = {"kind": "elf", "functions": result.functions}
        self.assertIsNotNone(sqlite_storage._full_listing_records(payload, result.metadata))
        records = self.assertSameRecords(payload, result.metadata)
        self.assertIsNot(records, result.metadata["full_disassembly"])

    def test_fallback_variants_match_original_merge(self):
        full = _instructions(60)
        copy = dict(full[10])
        variants = {
            "function_copy": ({"functions": [{"instructions": [copy]}]}, {"full_disassembly": full}),
            "function_source": ({"functions": [{"blocks": [{"instructions": [{**full[3], "source": "m"}]}]}]},
                                {"full_disassembly": full}),
            "extra_listing": ({"functions": []}, {"full_disassembly": full,
                                                  "disassembly": [{"addr": 7, "size": 1, "mnemonic": "x"}]}),
            "payload_instructions": ({"instructions": [full[0]], "functions": []}, {"full_disassembly": full}),
            "metadata_instructions": ({"functions": []}, {"full_disassembly": full, "instructions": [copy]}),
            "unsorted": ({"functions": []}, {"full_disassembly": [full[1], full[0], *full[2:]]}),
            "duplicate": ({"functions": []}, {"full_disassembly": [full[0], dict(full[0]), *full[1:]]}),
            "bytecode": ({"kind": "dex", "functions": [{"source": "classes.dex", "instructions": full[:5]}]},
                         {"full_disassembly": full}),
            "mapping_record": ({"functions": [{"instructions": [MappingProxyType(full[4])]}]},
                               {"full_disassembly": full}),
            "mapping_function": ({"functions": [MappingProxyType({"instructions": full[:3]})]},
                                 {"full_disassembly": full}),
            "negative_and_text": ({"functions": [{"instructions": [{"addr": -1}, "x", {"offset": 3}]}]},
                                  {"full_disassembly": full}),
            "address_key": ({"functions": []}, {"full_disassembly": full,
                                                "disassembly": [{"address": full[2]["addr"]}]}),
            "not_lists": ({"functions": [{"instructions": "x", "blocks": "y"}]},
                          {"full_disassembly": full, "disassembly": "z"}),
            "no_full": ({"functions": [{"instructions": full[:3]}]}, {}),
            "full_with_source": ({"functions": []}, {"full_disassembly": [{**full[0], "source": ""}]}),
            "empty_full": ({"functions": [{"instructions": full[:2]}]}, {"full_disassembly": []}),
        }
        for name, (payload, metadata) in variants.items():
            with self.subTest(name=name):
                self.assertSameRecords(payload, metadata)

    def test_random_listings_match_original_merge(self):
        rng = random.Random(7)
        for _ in range(300):
            full = _instructions(rng.randrange(0, 40), start=rng.choice([0, 0x1000]))
            pool = full + [dict(record) for record in full[:5]] + [
                {"addr": rng.randrange(-2, 200), "size": 1, "mnemonic": "n"} for _ in range(3)]

            def listing():
                return [rng.choice(pool) for _ in range(rng.randrange(0, 6))] if pool else []
            functions = [{"instructions": listing() if rng.random() < 0.3 else full[:rng.randrange(0, 5)],
                          "blocks": [{"instructions": full[index:index + rng.randrange(1, 6)]
                                      if rng.random() < 0.9 else listing()}
                                     for index in range(0, len(full), 7)]}
                         for _ in range(rng.randrange(0, 4))]
            metadata = {"full_disassembly": full}
            if rng.random() < 0.5:
                metadata["disassembly"] = full[:rng.randrange(0, 10)] if rng.random() < 0.8 else listing()
            self.assertSameRecords({"kind": rng.choice(["elf", "dex"]), "functions": functions}, metadata)


class EncoderTests(_Workspace):
    def test_compact_address_index_writes_identical_database(self):
        result = _full_result(str(self.source), 900)
        full = result.metadata["full_disassembly"]
        # 同地址的不同记录：第二条升级为下标列表，第三条追加；同值副本仍复用第一条。
        result.metadata["variants"] = [{**full[5], "mnemonic": "alt"}, {**full[5], "mnemonic": "alt2"},
                                       dict(full[5]), {**full[5], "mnemonic": "alt"}]
        result.functions[1]["blocks"][0]["instructions"] = [dict(row) for row in
                                                            result.functions[1]["blocks"][0]["instructions"]]
        legacy = self.save(result, "legacy.fdb", legacy=True)
        current = self.save(result, "current.fdb")
        self.assertEqual(self.dump(legacy), self.dump(current))

        encoder = sqlite_storage._Encoder()
        encoder.pack(result.metadata["variants"])
        self.assertEqual(encoder.by_address, {full[5]["addr"]: [0, 1, 2]})
        encoder.pack(full[:3])
        self.assertIs(type(encoder.by_address[full[0]["addr"]]), int)
        self.assertEqual(len(encoder.instructions), 6)


class ReaderSharingTests(_Workspace):
    def test_reopened_snapshot_equals_legacy_reader_and_shares_only_immutable_parts(self):
        path = self.save(_full_result(str(self.source)))
        legacy = self.read(path, reader=_LegacyReader, reshare=False)
        current = self.read(path)
        self.assertIdenticalValues(current, legacy)

        full = current["metadata"]["full_disassembly"]
        movs = [row for row in full if row["mnemonic"] == "mov"]
        self.assertIs(movs[0]["mnemonic"], movs[1]["mnemonic"])
        self.assertIs(movs[0]["operands"][0], movs[1]["operands"][0])
        # 平坦且可哈希的子字典共享；含列表（memory_references）的保持独立。
        self.assertIs(full[1]["arch_meta"], full[2]["arch_meta"])
        self.assertIs(full[0]["branch_info"], full[5]["branch_info"])
        self.assertIsNot(full[0]["arch_meta"], full[7]["arch_meta"])
        # 列表仍是每条记录各自一份，且按实际长度分配。
        self.assertIsNot(full[1]["operands"], full[2]["operands"])
        self.assertEqual(full[1]["operands"], full[2]["operands"])
        for row in full[:20]:
            for key in ("operands", "reads", "writes"):
                self.assertIs(type(row[key]), list)
                self.assertEqual(sys.getsizeof(row[key]), sys.getsizeof(row[key][:]))
        legacy_full = legacy["metadata"]["full_disassembly"]
        self.assertIsNot(legacy_full[1]["arch_meta"], legacy_full[2]["arch_meta"])

    def test_subdict_sharing_keeps_types_and_skips_annotation_targets(self):
        rows = _instructions(6)
        rows[0]["branch_info"] = {"kind": "jump", "conditional": False}
        rows[1]["branch_info"] = {"kind": "jump", "conditional": 0}
        rows[2]["branch_info"] = {"conditional": False, "kind": "jump"}
        rows[3]["arch_meta"] = {"engine": "x", "address": 0x1004}
        rows[4]["arch_meta"] = {"engine": "x", "address": 0x1004}
        rows[5]["arch_meta"] = {"engine": "x", "scale": -0.0}
        rows[0]["arch_meta"] = {"engine": "x", "scale": 0.0}
        result = AnalysisResult(str(self.source), "elf", "kkagent", "complete",
                                metadata={"full_disassembly": rows})
        path = self.save(result)
        current = self.read(path)
        self.assertIdenticalValues(current, self.read(path, reader=_LegacyReader, reshare=False))
        full = current["metadata"]["full_disassembly"]
        self.assertIsNot(full[0]["branch_info"], full[1]["branch_info"])  # False 与 0
        self.assertIsNot(full[0]["branch_info"], full[2]["branch_info"])  # 键顺序不同
        self.assertIsNot(full[3]["arch_meta"], full[4]["arch_meta"])      # 带整数 address：标注目标
        self.assertIsNot(full[0]["arch_meta"], full[5]["arch_meta"])      # 浮点数不共享

    def test_reader_tables_are_released_after_reading(self):
        path = self.save(_full_result(str(self.source), 300))
        readers: list[weakref.ref] = []

        class Tracked(sqlite_storage._Reader):
            def __init__(self, *args: Any) -> None:
                super().__init__(*args)
                readers.append(weakref.ref(self))
        snapshot = self.read(path, reader=Tracked)
        gc.collect()
        self.assertTrue(readers)
        self.assertTrue(all(reference() is None for reference in readers))
        self.assertEqual(len(snapshot["metadata"]["full_disassembly"]), 300)


class ReferenceResharingTests(_Workspace):
    def test_function_xrefs_reshare_top_level_dicts_like_a_fresh_analysis(self):
        result = _full_result(str(self.source))
        path = self.save(result)
        baseline = self.read(path, reader=_LegacyReader, reshare=False)
        current = self.read(path)
        self.assertIdenticalValues(current, baseline)
        top = {id(reference) for reference in current["xrefs"]}
        inner = [reference for function in current["functions"]
                 for key in ("xrefs_in", "xrefs_out") for reference in function[key]]
        self.assertTrue(inner)
        self.assertTrue(all(id(reference) in top for reference in inner))
        self.assertFalse(any(id(reference) in {id(item) for item in baseline["xrefs"]}
                             for function in baseline["functions"] for reference in function["xrefs_in"]))
        # 与新分析相同：每个内层元素都是与之同值的那个顶层 xref。
        fresh = [result.xrefs.index(item) for function in result.functions
                 for key in ("xrefs_in", "xrefs_out") for item in function[key]]
        self.assertEqual([next(i for i, ref in enumerate(current["xrefs"]) if ref is item) for item in inner], fresh)

    def test_resharing_is_type_and_order_strict_and_handles_unsorted_xrefs(self):
        top = [{"src": 9, "dst": 1, "kind": "call", "confidence": 1.0},
               {"src": 3, "dst": 1, "kind": "data", "confidence": 0.0},
               {"src": 3, "dst": 2, "kind": "data", "confidence": 0.5, "evidence": {"a": [1, 2.0]}},
               "not a dict", {"src": "x"}]
        inner = [dict(top[0]), {"src": 9, "dst": 1, "kind": "call", "confidence": 1},
                 {"dst": 1, "src": 9, "kind": "call", "confidence": 1.0},
                 {"src": 3, "dst": 1, "kind": "data", "confidence": -0.0}, dict(top[1]),
                 {"src": 3, "dst": 2, "kind": "data", "confidence": 0.5, "evidence": {"a": [1, 2]}},
                 json.loads(json.dumps(top[2])), {"src": 4, "dst": 1}, "text", {"src": None}]
        result = AnalysisResult(str(self.source), "elf", "kkagent", "complete",
                                functions=[{"start": 1, "xrefs_in": inner, "xrefs_out": [dict(top[0])]}],
                                xrefs=top)
        path = self.save(result)
        baseline = self.read(path, reader=_LegacyReader, reshare=False)
        current = self.read(path)
        self.assertIdenticalValues(current, baseline)
        xrefs, entries = current["xrefs"], current["functions"][0]["xrefs_in"]
        self.assertIs(entries[0], xrefs[0])
        self.assertIsNot(entries[1], xrefs[0])   # confidence 1 与 1.0
        self.assertIsNot(entries[2], xrefs[0])   # 键顺序不同
        self.assertIsNot(entries[3], xrefs[1])   # -0.0 与 0.0
        self.assertIs(entries[4], xrefs[1])
        self.assertIsNot(entries[5], xrefs[2])   # 嵌套 2 与 2.0
        self.assertIs(entries[6], xrefs[2])
        self.assertIs(current["functions"][0]["xrefs_out"][0], xrefs[0])

    def test_annotations_do_not_leak_through_shared_objects(self):
        result = _full_result(str(self.source))
        path = self.save(result)
        database = SQLiteAnalysisDatabase(path)
        try:
            snapshot = database.get_snapshot()
            snapshot_id = snapshot["metadata"]["analysis_database"]["snapshot_id"]
            target = snapshot["metadata"]["full_disassembly"][2]
            function = snapshot["functions"][1]
            shared_meta = target["arch_meta"]
            # 界面在内存中叠加标注（与写库后重新读出等价）。
            index = gui._annotation_index(snapshot)
            gui._apply_annotation(snapshot, index, "set_comment", target["addr"], "note")
            gui._apply_annotation(snapshot, index, "rename_symbol", function["start"], "renamed")
            gui._apply_annotation(snapshot, index, "set_comment", function["start"], "fn note")
            database.set_comment(snapshot_id, target["addr"], "note")
            database.rename_symbol(snapshot_id, function["start"], "renamed")
            database.set_comment(snapshot_id, function["start"], "fn note")
            reread = database.get_snapshot(snapshot_id)
        finally:
            database.close()
        legacy = self.read(path, reader=_LegacyReader, reshare=False)
        legacy["metadata"]["analysis_database"]["read_only"] = False
        self.assertIdenticalValues(reread, legacy)
        self.assertEqual(snapshot, reread)
        for current in (snapshot, reread):
            full = current["metadata"]["full_disassembly"]
            # 只有被注释地址上的记录（目标指令，以及函数起点处的指令）带注释。
            self.assertEqual([row["addr"] for row in full if "comment" in row],
                             [target["addr"], function["start"]])
            self.assertNotIn("comment", current["metadata"]["full_disassembly"][3]["arch_meta"])
            self.assertEqual(sum(f.get("name") == "renamed" for f in current["functions"]), 1)
            self.assertTrue(all("comment" not in reference and "name" not in reference
                                for reference in current["xrefs"]))
        self.assertEqual(shared_meta, {"engine": "capstone", "architecture": "arm64"})

        # 再保存带标注的快照：编码器恢复原名/原注释，写出的数据库与旧编码器一致。
        resaved = [self.save(reread, "resave-legacy.fdb", legacy=True), self.save(reread, "resave.fdb")]
        self.assertEqual(self.dump(resaved[0]), self.dump(resaved[1]))


if __name__ == "__main__":
    unittest.main()
