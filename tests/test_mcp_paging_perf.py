"""MCP get_disasm 指令索引缓存：分页结果与无缓存实现逐字节一致，且会话改动后正确失效。"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import random
import tempfile
from typing import Any
import unittest
from unittest.mock import patch

from fangida import mcp_server
from fangida.mcp_server import (McpServer, _address, _instructions, _page, _record_address,
                                _result, _tool_error)
from fangida.models import AnalysisResult
from fangida.settings import Settings


def reference_instructions(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """改动前 _instructions 的逐行副本：每次调用都重建、排序全部记录。"""
    records: list[dict[str, Any]] = []
    metadata = snapshot.get("metadata", {})
    for source in (snapshot.get("instructions"), metadata.get("disassembly"),
                   metadata.get("full_disassembly"), metadata.get("instructions")):
        if isinstance(source, list):
            records.extend(item for item in source if isinstance(item, dict))
    for function in snapshot.get("functions", []):
        if not isinstance(function, dict):
            continue
        for field in ("instructions", "disassembly"):
            if isinstance(function.get(field), list):
                records.extend(({"source": function.get("source", ""), **item}
                                if "source" not in item else item)
                               for item in function[field] if isinstance(item, dict))
        for block in function.get("blocks", []):
            if isinstance(block, dict) and isinstance(block.get("instructions"), list):
                records.extend(item for item in block["instructions"] if isinstance(item, dict))
    by_address = {(str(item.get("source", "")), address): item for item in records
                  if (address := _record_address(item, "address", "addr", "offset")) is not None}
    return [item for _, item in sorted(by_address.items())]


def reference_get_disasm(snapshot: dict[str, Any], arguments: dict[str, Any]) -> dict[str, Any]:
    """改动前 get_disasm 分支的副本（含参数校验顺序与错误文本）。"""
    try:
        offset, limit = McpServer._pagination(arguments)
        start = _address(arguments["address"]) if "address" in arguments else None
        instructions = reference_instructions(snapshot)
        if not instructions:
            return _tool_error("Disassembly is unavailable for this analysis result")
        source = arguments.get("source")
        if source is not None:
            if not isinstance(source, str):
                raise ValueError("source must be a string")
            instructions = [item for item in instructions if item.get("source") == source]
        if start is not None:
            instructions = [item for item in instructions
                            if _record_address(item, "address", "addr", "offset") >= start]
        return _result({"available": True, **_page(instructions, offset, limit)})
    except (ValueError, KeyError, TypeError) as exc:
        return _tool_error(str(exc))


def wire(response: dict[str, Any]) -> bytes:
    # 与 serve() 写出的 JSON-RPC 行相同的编码，比较 content 文本与 structuredContent 两部分。
    return json.dumps({"jsonrpc": "2.0", "id": 1, "result": response},
                      separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def synthetic_snapshot(seed: int = 7, count: int = 600) -> dict[str, Any]:
    """覆盖多来源、地址键混用、重复地址、函数级延迟副本、块内记录与无效条目。"""
    rng = random.Random(seed)
    sources = [None, "", "classes.dex", "classes2.dex", "lib/a.so"]

    def record(address: int) -> dict[str, Any]:
        key = rng.choice(("addr", "addr", "address", "offset"))
        value: Any = address if rng.random() < 0.8 else hex(address)
        item: dict[str, Any] = {key: value, "size": rng.randint(1, 8),
                                "mnemonic": rng.choice(("nop", "mov", "call", "ret", "调用"))}
        source = rng.choice(sources)
        if source is not None:
            item["source"] = source
        return item

    full = [record(0x1000 + rng.randrange(count * 2)) for _ in range(count)]
    full += [{"addr": "zz"}, {"addr": -1}, {"addr": True}, {"mnemonic": "no address"}, "not a dict"]
    functions: list[Any] = ["not a function"]
    for index in range(12):
        function: dict[str, Any] = {"name": f"f{index}", "start": 0x1000 + index * 0x40}
        if index % 3 == 0:
            function["source"] = rng.choice(("classes.dex", "classes2.dex"))
            function["disassembly"] = [{"addr": 0x1000 + rng.randrange(count), "mnemonic": "invoke"}
                                       for _ in range(15)]
        if index % 4 == 1:
            function["instructions"] = [record(0x1000 + rng.randrange(count)) for _ in range(10)]
        if index % 2 == 0:
            function["blocks"] = [{"instructions": [record(0x1000 + rng.randrange(count * 2))
                                                    for _ in range(rng.randint(0, 6))]}
                                  for _ in range(rng.randint(1, 5))] + ["not a block", {"start": 1}]
        functions.append(function)
    return {"path": "synthetic", "kind": "dex", "status": "partial", "warnings": [],
            "instructions": [record(0x1000 + rng.randrange(count)) for _ in range(20)],
            "metadata": {"disassembly": [record(0x1000 + rng.randrange(count)) for _ in range(40)],
                         "full_disassembly": full,
                         "instructions": [record(0x1000 + rng.randrange(count)) for _ in range(20)]},
            "functions": functions, "xrefs": [], "strings": [], "imports": [], "exports": []}


def full_result(path: str, base: int, count: int) -> AnalysisResult:
    records = [{"addr": base + index, "size": 1, "mnemonic": "nop"} for index in range(count)]
    return AnalysisResult(path, "elf", "kkagent", "partial",
                          metadata={"disassembly": records[:2], "full_disassembly": records},
                          functions=[{"start": base, "name": f"entry_{base:x}",
                                      "blocks": [{"start": base, "instructions": records[:3]}]}],
                          stats={"full_analysis": True})


QUERIES: list[dict[str, Any]] = [
    {}, {"offset": 1}, {"offset": 7, "limit": 3}, {"limit": 200}, {"offset": 10 ** 6},
    {"address": 0}, {"address": "0x1100"}, {"address": 0x1200, "offset": 5, "limit": 9},
    {"address": "4608"}, {"address": 10 ** 9}, {"source": ""}, {"source": "classes.dex"},
    {"source": "classes2.dex", "address": 0x1080, "limit": 4}, {"source": "missing"},
    {"source": "lib/a.so", "offset": 2, "limit": 1}, {"source": 3}, {"limit": 0},
    {"offset": -1}, {"address": "zz"}, {"address": True},
]


class McpPagingCacheTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = McpServer(allow_writes=True, settings=Settings())
        self.addCleanup(self.server.close)

    def assert_same(self, handle: str, arguments: dict[str, Any]) -> dict[str, Any]:
        response = self.server.call_tool("get_disasm", {"handle": handle, **arguments})
        expected = reference_get_disasm(self.server._snapshots[handle], arguments)
        self.assertEqual(wire(response), wire(expected), arguments)
        return response

    def walk_pages(self, handle: str, arguments: dict[str, Any], limit: int) -> list[Any]:
        """沿 next_offset 翻完全部页，每页都与无缓存实现逐字节比较。"""
        items: list[Any] = []
        offset: int | None = 0
        while offset is not None:
            page = self.assert_same(handle, {**arguments, "offset": offset, "limit": limit})
            items.extend(page["structuredContent"]["items"])
            offset = page["structuredContent"]["next_offset"]
        return items

    def test_module_instructions_helper_keeps_old_output(self) -> None:
        snapshot = synthetic_snapshot()
        self.assertEqual(json.dumps(_instructions(snapshot), ensure_ascii=False),
                         json.dumps(reference_instructions(snapshot), ensure_ascii=False))

    def test_every_query_matches_uncached_implementation_on_repeat(self) -> None:
        for seed in (1, 7, 42):
            handle = f"s{seed}"
            self.server._snapshots[handle] = synthetic_snapshot(seed)
            # 第二轮全部命中缓存，仍须与每次重建的旧实现完全一致。
            for _ in range(2):
                for arguments in QUERIES:
                    self.assert_same(handle, arguments)

    def test_multi_page_walks_match_and_build_index_once(self) -> None:
        self.server._snapshots["s"] = synthetic_snapshot(count=1500)
        with patch.object(mcp_server, "_instruction_entries",
                          wraps=mcp_server._instruction_entries) as build:
            for arguments in ({}, {"address": 0x1400}, {"source": "classes.dex"},
                              {"source": "", "address": "0x1300"}):
                items = self.walk_pages("s", arguments, limit=7)
                expected = reference_get_disasm(self.server._snapshots["s"],
                                                {**arguments, "limit": 200, "offset": 0})
                self.assertEqual(len(items), expected["structuredContent"]["total"])
        self.assertEqual(build.call_count, 1)

    def test_full_open_file_pages_match_and_reuse_index(self) -> None:
        raw = full_result("first.bin", 0x4000, 2500)
        with patch.object(self.server.service, "analyze", return_value=raw):
            handle = self.server.call_tool("open_file", {"path": "first.bin", "full_analysis": True}
                                           )["structuredContent"]["handle"]
        offset = 0
        for _ in range(20):
            offset = self.assert_same(handle, {"offset": offset, "limit": 100}
                                      )["structuredContent"]["next_offset"]
        index = self.server._instruction_indexes[handle]
        self.assert_same(handle, {"address": 0x4800, "offset": 33, "limit": 50})
        self.assertIs(self.server._instruction_indexes[handle], index)

    def test_opening_another_file_keeps_each_handle_separate(self) -> None:
        handles = []
        for path, base in (("first.bin", 0x4000), ("second.bin", 0x9000)):
            with patch.object(self.server.service, "analyze", return_value=full_result(path, base, 300)):
                handles.append(self.server.call_tool("open_file", {"path": path, "full_analysis": True}
                                                     )["structuredContent"]["handle"])
            self.assert_same(handles[-1], {"offset": 10, "limit": 5})
        first, second = (self.server.call_tool("get_disasm", {"handle": handle, "limit": 1})
                         ["structuredContent"]["items"][0]["addr"] for handle in handles)
        self.assertEqual((first, second), (0x4000, 0x9000))
        self.server.call_tool("close_file", {"handle": handles[0]})
        self.assertNotIn(handles[0], self.server._instruction_indexes)
        self.assertTrue(self.server.call_tool("get_disasm", {"handle": handles[0]})["isError"])
        self.assert_same(handles[1], {"address": 0x9100})

    def test_structural_changes_rebuild_index(self) -> None:
        snapshot = synthetic_snapshot()
        self.server._snapshots["s"] = snapshot
        query = {"offset": 3, "limit": 50}
        before = self.assert_same("s", query)
        mutations = [
            lambda: snapshot["metadata"].__setitem__(
                "full_disassembly", [{"addr": 0x10, "mnemonic": "replaced"}]),
            lambda: snapshot["metadata"]["full_disassembly"].append({"addr": 0x8, "mnemonic": "appended"}),
            lambda: snapshot["metadata"]["disassembly"].pop(),
            lambda: snapshot["functions"][1].__setitem__("source", "renamed.dex"),
            lambda: snapshot["functions"][1]["disassembly"].append({"addr": 0x4, "mnemonic": "late"}),
            lambda: snapshot["functions"][3]["blocks"][0].__setitem__(
                "instructions", [{"addr": 0x2, "mnemonic": "block"}]),
            lambda: snapshot["functions"][3]["blocks"].append({"instructions": [{"addr": 0x1}]}),
            lambda: snapshot["functions"].append({"instructions": [{"addr": 0x0, "mnemonic": "new"}]}),
            lambda: snapshot.__setitem__("instructions", None),
            lambda: snapshot.pop("functions"),
        ]
        for mutate in mutations:
            mutate()
            for arguments in (query, {"source": "renamed.dex"}, {"address": 0x1100, "limit": 9}):
                self.assert_same("s", arguments)
        self.assertNotEqual(wire(before), wire(self.assert_same("s", query)))
        # 句柄重新绑定到另一份结果时按身份识别并重建。
        self.server._snapshots["s"] = synthetic_snapshot(seed=99)
        self.assert_same("s", query)

    def test_in_place_record_content_is_reflected_without_rebuild(self) -> None:
        snapshot = synthetic_snapshot()
        self.server._snapshots["s"] = snapshot
        self.assert_same("s", {"limit": 200})
        index = self.server._instruction_indexes["s"]
        for item in snapshot["metadata"]["full_disassembly"]:
            if isinstance(item, dict):
                item["mnemonic"] = "changed"
        for function in snapshot["functions"][1:]:
            for item in function.get("disassembly", []):
                item["comment"] = "函数级副本也要反映"
        for arguments in ({"limit": 200}, {"source": "classes.dex", "limit": 200}):
            self.assert_same("s", arguments)
        self.assertIs(self.server._instruction_indexes["s"], index)

    def test_rename_symbol_invalidates_and_results_stay_consistent(self) -> None:
        snapshot = synthetic_snapshot()
        self.server._snapshots["s"] = snapshot
        self.assert_same("s", {"address": 0x1000})
        renamed = self.server.call_tool("rename_symbol", {"handle": "s", "address": 0x1040, "name": "renamed"})
        self.assertFalse(renamed.get("isError"), renamed)
        self.assertNotIn("s", self.server._instruction_indexes)
        self.assert_same("s", {"address": 0x1000})
        self.assertEqual(snapshot["functions"][2]["name"], "renamed")

    def test_database_comment_appears_in_reopened_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "sample.elf"
            source.write_bytes(b"\x7fELF" + b"\0" * 60)
            raw = full_result(str(source), 0x1000, 40)
            with patch.object(self.server.service, "analyze", return_value=raw):
                handle = self.server.call_tool("open_file", {"path": str(source), "full_analysis": True}
                                               )["structuredContent"]["handle"]
            before = self.assert_same(handle, {"address": 0x1001, "limit": 2})
            database = self.server.call_tool("create_database", {"path": str(Path(directory) / "a.fdb")}
                                             )["structuredContent"]["database"]
            saved = self.server.call_tool("save_to_database", {"database": database, "handle": handle})
            snapshot_id = saved["structuredContent"]["snapshot_id"]
            self.assertEqual(wire(before), wire(self.assert_same(handle, {"address": 0x1001, "limit": 2})))
            comments = []
            for text in ("第一次注释", "第二次注释"):
                written = self.server.call_tool("database_set_comment", {
                    "database": database, "snapshot_id": snapshot_id, "address": 0x1001, "text": text})
                self.assertFalse(written.get("isError"), written)
                reopened = self.server.call_tool("open_database_snapshot", {
                    "database": database, "snapshot_id": snapshot_id})["structuredContent"]["handle"]
                page = self.assert_same(reopened, {"address": 0x1001, "limit": 2})
                comments.append(page["structuredContent"]["items"][0].get("comment"))
                self.server.call_tool("close_file", {"handle": reopened})
            self.assertEqual(comments, ["第一次注释", "第二次注释"])
            # 会话内已打开的结果是独立快照，数据库注释不回写，旧句柄输出保持不变。
            self.assertEqual(wire(before), wire(self.assert_same(handle, {"address": 0x1001, "limit": 2})))
            self.server.call_tool("close_database", {"database": database})

    def test_unusual_shapes_are_not_cached_and_keep_old_errors(self) -> None:
        cases: list[tuple[dict[str, Any], bool]] = [
            ({"status": "partial", "functions": None}, False),
            ({"status": "partial", "functions": ({"instructions": [{"addr": 1}]},)}, False),
            ({"status": "partial", "functions": [{"blocks": None}]}, False),
            ({"status": "partial", "functions": [{"blocks": ({"instructions": [{"addr": 2}]},)}]}, False),
            ({"status": "partial", "metadata": {"full_disassembly": [{"addr": 3, "source": 5}]}}, True),
            ({"status": "partial", "metadata": {}}, True),
        ]
        for snapshot, cacheable in cases:
            self.server._snapshots["odd"] = snapshot
            for arguments in ({}, {"source": "5"}, {"address": 2}):
                self.assert_same("odd", arguments)
            self.assertEqual("odd" in self.server._instruction_indexes, cacheable, snapshot)
        self.server._snapshots["broken"] = {"status": "partial", "metadata": None}
        with self.assertRaises(AttributeError):
            reference_get_disasm(self.server._snapshots["broken"], {})
        with self.assertRaises(AttributeError):
            self.server.call_tool("get_disasm", {"handle": "broken"})

    def test_close_releases_indexes(self) -> None:
        self.server._snapshots["s"] = deepcopy(synthetic_snapshot())
        self.assert_same("s", {})
        self.server.close()
        self.assertEqual(self.server._instruction_indexes, {})


if __name__ == "__main__":
    unittest.main()
