"""完成结果接管必须显式开启；默认外部结果隔离和图内别名保持不变。"""
from copy import deepcopy
import io
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from fangida import mcp_server
from fangida.mcp_server import McpServer, serve
from fangida.models import AnalysisResult
from fangida.settings import Settings


def completed(kind: str = "elf", result_type=AnalysisResult, *, full: bool = True) -> AnalysisResult:
    instructions = [{"addr": 0x1000, "size": 1, "mnemonic": "ret", "branch_info": {"kind": "return"}}]
    return result_type("sample.bin", kind, "kkagent", "partial",
                      metadata={"full_disassembly": instructions, "disassembly": instructions},
                      functions=[{"start": 0x1000, "name": "entry", "size": 1, "source": "entry",
                                  "blocks": [{"start": 0x1000, "instructions": instructions, "successors": []}],
                                  "cfg": {"entry": 0x1000, "complete": True, "scope": "bounded_function",
                                          "edges": [], "frontier": []}}],
                      xrefs=[{"src": 0x1000, "dst": 0x2000, "kind": "data"}],
                      stats={"full_analysis": full})


class McpCompletedOwnershipTests(unittest.TestCase):
    def server(self, **options) -> McpServer:
        server = McpServer(allow_writes=True, settings=Settings(), **options)
        self.addCleanup(server.close)
        return server

    def open(self, server: McpServer, result: AnalysisResult) -> tuple[str, dict]:
        with patch.object(server.service, "analyze", return_value=result):
            response = server.call_tool("open_file", {"path": result.path, "full_analysis": True})
        self.assertNotIn("isError", response, response)
        handle = response["structuredContent"]["handle"]
        return handle, server._snapshots[handle]

    def test_default_and_explicit_false_keep_external_graph_isolated(self) -> None:
        for options in ({}, {"own_completed_results": False}):
            with self.subTest(options=options):
                server = self.server(**options)
                result = completed()
                handle, snapshot = self.open(server, result)
                self.assertFalse(server.own_completed_results)
                self.assertIsNot(snapshot["metadata"], result.metadata)
                self.assertIsNot(snapshot["functions"], result.functions)
                original = result.metadata["full_disassembly"][0]
                copied = snapshot["metadata"]["full_disassembly"][0]
                self.assertIsNot(copied, original)
                # 图内共享记录仍是同一个副本，不能把旧身份断言弱化为值相等。
                self.assertIs(copied, snapshot["functions"][0]["blocks"][0]["instructions"][0])
                original["mnemonic"] = "changed externally"
                self.assertEqual(copied["mnemonic"], "ret")
                renamed = server.call_tool("rename_symbol", {"handle": handle, "address": 0x1000, "name": "session_name"})
                self.assertNotIn("isError", renamed, renamed)
                self.assertEqual(result.functions[0]["name"], "entry")

    def test_opt_in_consumes_completed_private_native_graph_without_deep_copy(self) -> None:
        server = self.server(own_completed_results=True)
        result = completed()
        with patch.object(mcp_server, "deepcopy", side_effect=AssertionError("不能复制完整 IR")):
            _, snapshot = self.open(server, result)
        self.assertIsNot(snapshot, vars(result))
        self.assertIs(snapshot["metadata"], result.metadata)
        self.assertIs(snapshot["functions"], result.functions)
        self.assertIs(snapshot["stats"], result.stats)
        self.assertIs(snapshot["xrefs"], result.xrefs)
        self.assertIs(snapshot["metadata"]["full_disassembly"][0],
                      snapshot["functions"][0]["blocks"][0]["instructions"][0])
        snapshot["functions"][0]["name"] = "owned session"
        self.assertEqual(result.functions[0]["name"], "owned session")
        # 顶层容器已经转移，后续顶层键调整不会改写 dataclass 的属性字典。
        snapshot["extra"] = "session only"
        self.assertNotIn("extra", vars(result))

    def test_owned_and_default_snapshots_report_identical_evidence(self) -> None:
        evidence = completed()
        expected = deepcopy(vars(evidence))
        answers = []
        for own in (False, True):
            server = self.server(own_completed_results=own)
            handle, snapshot = self.open(server, deepcopy(evidence))
            self.assertEqual(snapshot, expected)
            queries = [("get_disasm", {"address": 0x1000}),
                       ("get_cfg", {"address": 0x1000}),
                       ("xref_query", {"address": 0x1000}),
                       ("list_functions", {"include_details": False}),
                       ("analysis_summary", {})]
            answers.append([server.call_tool(name, {"handle": handle, **arguments})
                            for name, arguments in queries])
        self.assertEqual(*answers)

    def test_opt_in_does_not_borrow_non_full_bytecode_or_subclass_results(self) -> None:
        class SpecializedResult(AnalysisResult):
            pass
        cases = [completed(full=False), completed(kind="apk"), completed(result_type=SpecializedResult)]
        for result in cases:
            with self.subTest(kind=result.kind, result_type=type(result)):
                server = self.server(own_completed_results=True)
                _, snapshot = self.open(server, result)
                self.assertIsNot(snapshot["metadata"], result.metadata)
                self.assertIsNot(snapshot["functions"], result.functions)
                self.assertIsNot(snapshot["metadata"]["full_disassembly"][0],
                                 result.metadata["full_disassembly"][0])
                first = snapshot["metadata"]["full_disassembly"][0]
                block_first = snapshot["functions"][0]["blocks"][0]["instructions"][0]
                if type(result) is AnalysisResult and result.stats.get("full_analysis"):
                    self.assertIs(first, block_first)
                else:
                    # 非 full 与 dataclass 子类仍走旧 asdict 路径，它会逐字段复制共享记录。
                    self.assertIsNot(first, block_first)

    def test_setting_requires_boolean_before_constructing_service(self) -> None:
        for value in (0, 1, None, "false", []):
            with self.subTest(value=value), patch.object(mcp_server, "AnalysisService") as service:
                with self.assertRaisesRegex(ValueError, "own_completed_results must be boolean"):
                    McpServer(own_completed_results=value)
                service.assert_not_called()

    def test_stdio_explicit_option_and_cli_forward_only_optional_setting(self) -> None:
        for own in (False, True):
            fake = Mock()
            with patch.object(mcp_server, "McpServer", return_value=fake) as factory:
                serve(io.BytesIO(), io.BytesIO(), own_completed_results=own)
            factory.assert_called_once_with(allow_writes=False, own_completed_results=own)
            fake.close.assert_called_once_with()
        incoming, outgoing = io.BytesIO(), io.BytesIO()
        with patch.object(mcp_server.sys, "stdin", SimpleNamespace(buffer=incoming)), \
                patch.object(mcp_server.sys, "stdout", SimpleNamespace(buffer=outgoing)), \
                patch.object(mcp_server, "serve") as run:
            self.assertEqual(mcp_server.main(["--own-completed-results"]), 0)
        run.assert_called_once_with(incoming, outgoing, allow_writes=False, own_completed_results=True)


if __name__ == "__main__":
    unittest.main()
