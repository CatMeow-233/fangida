"""原生 agent 的有界只读 MCP 投影；不解码，不改变既有详细结果。"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from fangida.core.kkagent.test_semantic import DECODER_AVAILABLE, _sample
from fangida.mcp_server import MAX_PAGE_SIZE, McpServer
from fangida.plugins.sqlite_storage import SQLiteAnalysisDatabase
from fangida.settings import Settings


def function(address: int = 0x1000, **fields: object) -> dict:
    return {"name": "entry", "start": address, "size": 3, "source": "eh_frame",
            "blocks": [{"start": address + index, "successors": [address + index + 1],
                        "instructions": [{"addr": address + index, "size": 1, "mnemonic": "nop"}],
                        "annotation": {"labels": ["原标签"]}}
                       for index in range(3)],
            "cfg": {"scope": "bounded_function", "entry": address, "complete": False,
                    "boundary_known": True, "assumptions": ["示例假设"],
                    "edges": [{"src": address, "dst": address + 1, "kind": "fallthrough"},
                              {"src": address + 1, "dst": address + 2, "kind": "fallthrough"}],
                    "frontier": [{"from": address + 2, "to": address + 3, "reason": "undecoded"}]},
            "xrefs_in": [{"src": address - 1, "dst": address}],
            "xrefs_out": [], **fields}


def snapshot(functions: list, kind: str = "elf") -> dict:
    return {"path": "fixture.bin", "kind": kind, "analyzer": "kkagent", "status": "partial",
            "schema_version": "1.0", "functions": functions, "strings": [], "imports": [],
            "exports": [], "xrefs": [], "metadata": {}, "stats": {}, "warnings": []}


class UnreadableInstructions(list):
    def __iter__(self):
        raise AssertionError("紧凑读取不能遍历指令")

    def __deepcopy__(self, memo):
        raise AssertionError("紧凑读取不能复制完整 IR")


class NativeAgentMcpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = McpServer(settings=Settings())
        self.addCleanup(self.server.close)
        self.server._snapshots["s"] = snapshot([function()])

    def query(self, name: str = "get_cfg", **arguments: object) -> dict:
        response = self.server.call_tool(name, {"handle": "s", **arguments})
        self.assertNotIn("isError", response, response)
        self.assertEqual(json.loads(response["content"][0]["text"]), response["structuredContent"])
        return response["structuredContent"]

    def error(self, name: str = "get_cfg", **arguments: object) -> str:
        response = self.server.call_tool(name, {"handle": "s", **arguments})
        self.assertTrue(response.get("isError"), response)
        return response["content"][0]["text"]

    def test_tools_are_available_read_only_with_optional_compact_functions(self) -> None:
        self.server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                            "params": {"protocolVersion": "2025-11-25"}})
        self.server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
        tools = self.server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]
        by_name = {tool["name"]: tool for tool in tools}
        for name in ("get_cfg", "analysis_summary"):
            self.assertTrue(by_name[name]["annotations"]["readOnlyHint"])
        schema = by_name["get_cfg"]["inputSchema"]
        self.assertEqual(schema["required"], ["handle", "address"])
        # 原有三个取值保持原顺序；noreturn_calls 是追加的可选取值。
        self.assertEqual(schema["properties"]["collection"]["enum"], ["blocks", "edges", "frontier", "noreturn_calls"])
        self.assertEqual(schema["properties"]["limit"]["maximum"], MAX_PAGE_SIZE)
        self.assertEqual(by_name["list_functions"]["inputSchema"]["properties"]["include_details"], {
            "type": "boolean", "default": True,
            "description": "False returns compact function summaries without IR"})
        database_schema = by_name["database_page"]["inputSchema"]
        self.assertEqual(database_schema["properties"]["include_details"]["type"], "boolean")
        self.assertTrue(database_schema["properties"]["include_details"]["default"])
        self.assertNotIn("include_details", database_schema["required"])

    def test_cfg_pages_preserve_counts_completeness_and_block_summaries(self) -> None:
        first = self.query(address="0x1000", limit=2)
        self.assertEqual(first["function"], {"address": 0x1000, "name": "entry", "size": 3,
                                            "source": "", "address_space": "native"})
        self.assertEqual(first["counts"], {"blocks": 3, "edges": 2, "frontier": 1, "instructions": 3})
        self.assertFalse(first["cfg"]["complete"])
        self.assertEqual(first["cfg"]["scope"], "bounded_function")
        self.assertEqual((first["total"], first["next_offset"]), (3, 2))
        self.assertNotIn("blocks", first["cfg"])
        for block in first["items"]:
            self.assertNotIn("instructions", block)
            self.assertEqual(block["instruction_count"], 1)
        final = self.query(address=0x1000, offset=first["next_offset"], limit=2)
        self.assertEqual((len(final["items"]), final["next_offset"]), (1, None))
        edges = self.query(address=0x1000, collection="edges", offset=1, limit=1)
        self.assertEqual(edges["items"], self.server._snapshots["s"]["functions"][0]["cfg"]["edges"][1:])
        frontier = self.query(address=0x1000, collection="frontier")
        self.assertEqual(frontier["items"][0]["reason"], "undecoded")
        empty = self.query(address=0x1000, offset=100)
        self.assertEqual((empty["items"], empty["total"], empty["next_offset"]), ([], 3, None))

    def test_noreturn_calls_are_paged_and_summarized_only_when_recorded(self) -> None:
        record = {"from": 0x1001, "fallthrough": 0x1002, "target": 0x2000, "name": "abort", "evidence": "import_stub"}
        recorded = function(noreturn=True, noreturn_evidence={"name": "entry", "evidence": "local_fixed_point"})
        recorded["cfg"] = {**recorded["cfg"], "noreturn_calls": [record]}
        self.server._snapshots["s"] = snapshot([recorded, function(0x3000, name="old")])
        page = self.query(address=0x1000, collection="noreturn_calls")
        self.assertEqual((page["items"], page["total"]), ([record], 1))
        page["items"][0]["name"] = "改动"
        self.assertEqual(self.server._snapshots["s"]["functions"][0]["cfg"]["noreturn_calls"][0]["name"], "abort")
        # 旧结果（没有该字段）：空页，其它集合照常。
        self.assertEqual(self.query(address=0x3000, collection="noreturn_calls")["items"], [])
        listed = {item["name"]: item for item in self.query("list_functions", include_details=False)["items"]}
        self.assertEqual((listed["entry"]["noreturn"], listed["entry"]["noreturn_evidence"]["evidence"],
                          listed["entry"]["noreturn_call_count"]), (True, "local_fixed_point", 1))
        for field in ("noreturn", "noreturn_evidence", "noreturn_call_count"):
            self.assertNotIn(field, listed["old"])

    def test_malformed_noreturn_calls_only_affect_their_own_collection(self) -> None:
        broken = function()
        broken["cfg"] = {**broken["cfg"], "noreturn_calls": "bad"}
        self.server._snapshots["s"] = snapshot([broken])
        self.assertEqual(self.query(address=0x1000)["total"], 3)
        self.assertIn("noreturn_calls must be a list", self.error(address=0x1000, collection="noreturn_calls"))
        self.assertIn("collection must be", self.error(address=0x1000, collection="calls"))

    def test_every_cfg_response_is_a_defensive_copy(self) -> None:
        original = deepcopy(self.server._snapshots["s"])
        page = self.query(address=0x1000)
        page["items"][0]["successors"].append(123)
        page["items"][0]["annotation"]["labels"][0] = "改动"
        page["cfg"]["assumptions"].append("改动")
        page["function"]["name"] = "改动"
        for collection in ("edges", "frontier"):
            self.query(address=0x1000, collection=collection)["items"][0]["reason"] = "改动"
        self.assertEqual(self.server._snapshots["s"], original)

    def test_apk_members_require_disambiguation_before_cfg_availability(self) -> None:
        first = function(0x80, name="first", code_offset=0x80, source="classes.dex", kind="dex")
        second = function(0x80, name="second", code_offset=0x80, source="classes2.dex", kind="dex", cfg={})
        self.server._snapshots["s"] = snapshot([first, second], "apk")
        self.assertIn("Ambiguous", self.error(address=0x80))
        selected = self.query(address=0x80, source="classes.dex", address_space="file_offset")
        self.assertEqual(selected["function"]["name"], "first")
        self.assertEqual(selected["function"]["source"], "classes.dex")
        self.assertIn("unavailable", self.error(address=0x80, source="classes2.dex"))
        self.assertIn("No identified", self.error(address=0x80, source="missing.dex"))

    def test_address_spaces_and_container_metadata_are_distinct(self) -> None:
        native = function(0x80, address_space="ram", source="entry_window")
        foreign = function(0x80, name="foreign", address_space="file_offset", source="wrong",
                           arch_meta={"container_member": "classes.dex"})
        self.server._snapshots["s"] = snapshot([native, foreign])
        self.assertIn("Ambiguous", self.error(address=0x80))
        self.assertEqual(self.query(address=0x80, address_space="native")["function"]["source"], "")
        self.assertEqual(self.query(address=0x80, address_space="virtual")["function"]["name"], "entry")
        selected = self.query(address=0x80, source="classes.dex", address_space="offset")
        self.assertEqual(selected["function"]["address_space"], "file_offset")
        self.assertEqual(selected["function"]["name"], "foreign")
        # APK 中声明了原生空间的成员不能因外层容器种类误归入文件偏移空间。
        self.server._snapshots["s"]["kind"] = "apk"
        self.assertEqual(self.query(address=0x80, source="", address_space="native")["function"]["name"], "entry")

    def test_missing_cfg_is_unavailable_without_creating_one(self) -> None:
        self.server._snapshots["s"] = snapshot([{"name": "symbol", "start": 0x1000}])
        with patch.object(self.server.service, "analyze", side_effect=AssertionError("不能重新分析")):
            self.assertIn("unavailable", self.error(address=0x1000))
            self.assertIn("No identified", self.error(address=0x1001))
        self.assertNotIn("cfg", self.server._snapshots["s"]["functions"][0])

    def test_cfg_collections_inside_graph_are_also_supported(self) -> None:
        record = self.server._snapshots["s"]["functions"][0]
        record["cfg"]["blocks"] = record.pop("blocks")
        self.assertEqual(self.query(address=0x1000)["counts"]["instructions"], 3)

    def test_validation_uses_existing_tool_error_rules(self) -> None:
        for arguments in ({}, {"address": True}, {"address": -1}, {"address": "bad"},
                          {"address": 0x1000, "source": 1}, {"address": 0x1000, "address_space": ""},
                          {"address": 0x1000, "address_space": 1}, {"address": 0x1000, "collection": "IR"},
                          {"address": 0x1000, "offset": -1}, {"address": 0x1000, "offset": True},
                          {"address": 0x1000, "limit": 0}, {"address": 0x1000, "limit": True},
                          {"address": 0x1000, "limit": MAX_PAGE_SIZE + 1}):
            with self.subTest(arguments=arguments):
                self.error(**arguments)
        for value in (0, 1, "false", None, []):
            self.assertIn("boolean", self.error("list_functions", include_details=value))
        self.server.call_tool("close_file", {"handle": "s"})
        self.assertIn("unknown file handle", self.error(address=0x1000))
        self.assertIn("unknown file handle", self.error("analysis_summary"))

    def test_function_details_default_is_unchanged_and_compact_pages_are_copied(self) -> None:
        original = deepcopy(self.server._snapshots["s"])
        old = self.query("list_functions", limit=1)
        explicit = self.query("list_functions", include_details=True, limit=1)
        self.assertEqual(old, explicit)
        self.assertEqual(old["items"], original["functions"])
        compact = self.query("list_functions", include_details=False, limit=1)
        item = compact["items"][0]
        self.assertNotIn("blocks", item)
        self.assertNotIn("instructions", item)
        self.assertNotIn("edges", item["cfg"])
        self.assertEqual((item["address"], item["source"], item["symbol_source"]), (0x1000, "", "eh_frame"))
        self.assertEqual((item["block_count"], item["instruction_count"], item["xref_in_count"]), (3, 3, 1))
        item["cfg"]["complete"] = True
        self.assertEqual(self.server._snapshots["s"], original)
        self.assertEqual(self.query("list_functions", include_details=False, offset=100)["items"], [])

    def test_compact_queries_do_not_visit_or_copy_ir(self) -> None:
        record = self.server._snapshots["s"]["functions"][0]
        for block in record["blocks"]:
            block["instructions"] = UnreadableInstructions([{}, {}])
        self.server._snapshots["s"]["metadata"] = {
            "full_disassembly": UnreadableInstructions([{}] * 100_000),
            "entry_cfg": {"blocks": UnreadableInstructions([{}])},
            "ghidra": {"pcode": UnreadableInstructions([{}])},
            "bytes": b"original bytes",
        }
        self.assertEqual(self.query(address=0x1000, limit=1)["counts"]["instructions"], 6)
        self.assertEqual(self.query("list_functions", include_details=False)["items"][0]["instruction_count"], 6)
        summary = self.query("analysis_summary")
        self.assertNotIn("metadata", summary)
        self.assertNotIn("functions", summary)
        self.assertNotIn("cfg", summary)
        self.assertEqual(summary["counts"]["instructions"], 100_000)
        self.assertEqual(summary["instruction_count_source"], "metadata.full_disassembly")
        self.assertLess(len(json.dumps(summary)), 2048)

    def test_summary_has_counts_coverage_bounded_warnings_and_defensive_stats(self) -> None:
        current = self.server._snapshots["s"]
        current["stats"] = {"full_instructions": 25, "phase_seconds": {"cfg": 0.2},
                            "instructions": UnreadableInstructions([{}])}
        current["metadata"] = {
            "source_sha256": "a" * 64, "size_bytes": 256, "architecture": "x86_64",
            "full_analysis": {"enabled": True, "scope": "all_file_backed_executable_regions", "decode_complete": True,
                              "function_recovery_complete": False, "instruction_count": 25,
                              "regions": UnreadableInstructions([{}, {}]), "full_disassembly": ["不应出现"]}}
        current["warnings"] = ["x" * 3000] + [f"warning{i}" for i in range(110)]
        summary = self.query("analysis_summary")
        self.assertEqual(summary["counts"]["functions"], 1)
        self.assertEqual(summary["counts"]["instructions"], 25)
        self.assertEqual(summary["instruction_count_source"], "metadata.full_analysis.instruction_count")
        self.assertEqual(summary["source"]["sha256"], "a" * 64)
        self.assertEqual(summary["source"]["size_bytes"], 256)
        self.assertEqual(summary["full_analysis"]["region_count"], 2)
        self.assertTrue(summary["full_analysis"]["decode_complete"])
        self.assertFalse(summary["full_analysis"]["function_recovery_complete"])
        self.assertNotIn("regions", summary["full_analysis"])
        self.assertNotIn("instructions", summary["stats"])
        self.assertTrue(summary["stats_truncated"])
        self.assertEqual((len(summary["warnings"]), summary["warning_count"]), (100, 111))
        self.assertTrue(summary["warnings_truncated"])
        self.assertEqual(len(summary["warnings"][0]), 2048)
        summary["stats"]["phase_seconds"]["cfg"] = 99
        summary["source"]["sha256"] = "改动"
        summary["full_analysis"]["decode_complete"] = False
        self.assertEqual(current["stats"]["phase_seconds"]["cfg"], 0.2)
        self.assertEqual(current["metadata"]["source_sha256"], "a" * 64)
        self.assertTrue(current["metadata"]["full_analysis"]["decode_complete"])

    def test_summary_instruction_count_prefers_full_listing_and_labels_legacy_fallback(self) -> None:
        current = self.server._snapshots["s"]
        summary = self.query("analysis_summary")
        self.assertEqual(summary["counts"]["instructions"], 0)
        self.assertEqual(summary["instruction_count_source"], "unavailable")
        current["instructions"] = UnreadableInstructions([{}, {}])
        summary = self.query("analysis_summary")
        self.assertEqual(summary["counts"]["instructions"], 2)
        self.assertEqual(summary["instruction_count_source"], "instructions")
        current["metadata"] = {"full_analysis": {"enabled": True, "instruction_count": 999},
                               "full_disassembly": UnreadableInstructions([{}, {}, {}])}
        summary = self.query("analysis_summary")
        self.assertEqual(summary["counts"]["instructions"], 3)
        self.assertEqual(summary["instruction_count_source"], "metadata.full_disassembly")
        current["metadata"]["full_disassembly"] = UnreadableInstructions([])
        self.assertEqual(self.query("analysis_summary")["counts"]["instructions"], 0)

    def test_summary_coverage_count_requires_enabled_full_mode_and_nonnegative_integer(self) -> None:
        current = self.server._snapshots["s"]
        current["instructions"] = UnreadableInstructions([{}, {}])
        for value in (True, False, -1, 1.5, "3", None):
            with self.subTest(value=value):
                current["metadata"] = {"full_analysis": {"enabled": True, "instruction_count": value}}
                summary = self.query("analysis_summary")
                self.assertEqual(summary["counts"]["instructions"], 2)
                self.assertEqual(summary["instruction_count_source"], "instructions")
        for enabled in (False, None, 1, "true"):
            with self.subTest(enabled=enabled):
                current["metadata"] = {"full_analysis": {"enabled": enabled, "instruction_count": 3}}
                self.assertEqual(self.query("analysis_summary")["counts"]["instructions"], 2)
        # 部分分析中已完成的指令数仍可用；计数不改变完整性证据。
        current["metadata"] = {"full_analysis": {"enabled": True, "instruction_count": 7,
                                                 "decode_complete": False}}
        summary = self.query("analysis_summary")
        self.assertEqual(summary["counts"]["instructions"], 7)
        self.assertFalse(summary["full_analysis"]["decode_complete"])

    def database_store(self, page: dict) -> Mock:
        store = Mock()
        store.page.return_value = page
        for name in ("get_snapshot", "info", "history"):
            getattr(store, name).side_effect = AssertionError("函数页不得为摘要再读快照或元数据")
        self.server._databases["d"] = store
        return store

    def database_page(self, **arguments: object) -> dict:
        return self.server.call_tool("database_page", {
            "database": "d", "snapshot_id": 1, "collection": "functions", **arguments})

    def test_database_functions_default_and_explicit_details_keep_original_page(self) -> None:
        page = {"items": [function()], "total": 8, "next_offset": 1}
        store = self.database_store(page)
        for arguments in ({}, {"include_details": True}):
            response = self.database_page(**arguments)
            self.assertNotIn("isError", response, response)
            self.assertEqual(response["structuredContent"], page)
            self.assertIn("instructions", response["structuredContent"]["items"][0]["blocks"][0])
        self.assertEqual(store.page.call_count, 2)
        store.get_snapshot.assert_not_called()

    def test_database_compact_page_uses_only_requested_page_and_copies_summaries(self) -> None:
        native = function()
        dex = function(0x80, code_offset=0x80, source="classes.dex", kind="dex")
        for record in (native, dex):
            for block in record["blocks"]:
                block["instructions"] = UnreadableInstructions([{}, {}])
        page = {"items": [native, dex], "total": 12, "next_offset": 7}
        store = self.database_store(page)
        with patch.object(self.server.service, "analyze", side_effect=AssertionError("不得重新分析")):
            response = self.database_page(include_details=False, offset=5, limit=2)
        self.assertNotIn("isError", response, response)
        projected = response["structuredContent"]
        self.assertEqual((projected["total"], projected["next_offset"]), (12, 7))
        self.assertEqual((projected["items"][0]["source"], projected["items"][0]["address_space"]), ("", "native"))
        self.assertEqual((projected["items"][1]["source"], projected["items"][1]["address_space"]),
                         ("classes.dex", "file_offset"))
        self.assertEqual(projected["items"][0]["instruction_count"], 6)
        self.assertNotIn("blocks", projected["items"][0])
        projected["items"][0]["cfg"]["complete"] = True
        self.assertFalse(native["cfg"]["complete"])
        self.assertIs(page["items"][0], native)
        self.assertIn("blocks", page["items"][0])
        store.page.assert_called_once_with(1, "functions", offset=5, limit=2)
        for name in ("get_snapshot", "info", "history"):
            getattr(store, name).assert_not_called()

    def test_database_compact_other_collections_passthrough_and_validate_boolean(self) -> None:
        page = {"items": [{"addr": 0x1000, "mnemonic": "ret"}], "total": 1, "next_offset": None}
        store = self.database_store(page)
        response = self.database_page(collection="disassembly", include_details=False)
        self.assertEqual(response["structuredContent"], page)
        store.page.assert_called_once_with(1, "disassembly", offset=0, limit=100)
        for value in (0, 1, None, "false", []):
            with self.subTest(value=value):
                response = self.database_page(include_details=value)
                self.assertTrue(response.get("isError"), response)
                self.assertIn("boolean", response["content"][0]["text"])
        self.assertEqual(store.page.call_count, 1)

    def test_database_compact_page_respects_optional_provider_kind(self) -> None:
        member = function(0x80, source="classes.dex")
        self.database_store({"kind": "apk", "items": [member], "total": 1, "next_offset": None})
        response = self.database_page(include_details=False)
        self.assertEqual(response["structuredContent"]["items"][0]["source"], "classes.dex")
        self.assertEqual(response["structuredContent"]["items"][0]["address_space"], "file_offset")

    @unittest.skipUnless(DECODER_AVAILABLE, "需要原生解码器")
    def test_real_full_native_cfg_can_be_read_offline_from_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "sample.elf"
            source.write_bytes(_sample())
            result = self.server.service.analyze(source, full_analysis=True)
            self.assertNotEqual(result.status, "error", result.warnings)
            database_path = Path(directory) / "sample.fdb"
            database = SQLiteAnalysisDatabase(database_path, create=True)
            try:
                database.save_analysis(source, result)
            finally:
                database.close()
            source.unlink()
            with patch.object(self.server.service, "analyze", side_effect=AssertionError("只能读取快照")):
                opened = self.server.call_tool("open_database", {"path": str(database_path)})["structuredContent"]
                loaded = self.server.call_tool("open_database_snapshot", {"database": opened["database"]})
                self.assertNotIn("isError", loaded, loaded)
                handle = loaded["structuredContent"]["handle"]
                summary = self.server.call_tool("analysis_summary", {"handle": handle})["structuredContent"]
                self.assertEqual(summary["counts"]["instructions"], result.stats["full_instructions"])
                self.assertEqual(summary["counts"]["instructions"], 6)
                self.assertEqual(summary["instruction_count_source"], "metadata.full_disassembly")
                response = self.server.call_tool("get_cfg", {"handle": handle, "address": "0x401000"})
                self.assertNotIn("isError", response, response)
                graph = response["structuredContent"]
                self.assertEqual(graph["cfg"]["scope"], "full_region_recovered_function")
                self.assertTrue(graph["cfg"]["complete"])
                self.assertEqual(graph["counts"]["instructions"], 2)
                self.assertTrue(graph["items"])
                self.assertTrue(all("instructions" not in item for item in graph["items"]))
                store = self.server._databases[opened["database"]]
                with patch.object(store, "get_snapshot", side_effect=AssertionError("分页不能整库恢复")):
                    compact = self.server.call_tool("database_page", {
                        "database": opened["database"], "snapshot_id": loaded["structuredContent"]["snapshot_id"],
                        "collection": "functions", "include_details": False, "limit": 1})
                self.assertNotIn("isError", compact, compact)
                self.assertEqual(compact["structuredContent"]["items"][0]["instruction_count"], 2)
                self.assertNotIn("blocks", compact["structuredContent"]["items"][0])


if __name__ == "__main__":
    unittest.main()
