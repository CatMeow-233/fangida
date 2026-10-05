"""v0.4 公共契约基线：允许增量扩展，阻止破坏旧调用及旧数据格式。

这些常量来自拆分 loader/processor 前的接口；不能用当前实现自动生成，
也不能为了让重构通过而删掉基线。新增 API 的实现测试由各模块负责。
"""
from __future__ import annotations

from importlib import import_module
import inspect
import json
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest.mock import patch

from fangida.api import open_file
from fangida.dispatcher import AnalysisService, identify
from fangida.mcp_server import McpServer
from fangida.models import AnalysisResult, AnalysisTask, Instruction, Xref
from fangida.plugins.manager import PluginManager
from fangida.settings import Settings


# (旧位置参数顺序, 旧必填参数, 旧仅关键字参数)。旧可选项不能改为必填；
# 新位置参数只能追加，新增关键字项必须有默认值。
CALLS = {
    "fangida.api:open_file": ("path service", "path", ""),
    "fangida.api:AnalysisView": ("result", "result", ""),
    "fangida.api:AnalysisView.snapshot": ("self", "self", ""),
    "fangida.api:AnalysisView.functions": ("self", "self", ""),
    "fangida.api:AnalysisView.strings": ("self", "self", ""),
    "fangida.api:AnalysisView.xrefs": ("self address", "self", ""),
    "fangida.api:AnalysisView.disassembly": ("self start limit", "self start", ""),
    "fangida.api:AnalysisView.export_json": ("self destination", "self destination", ""),
    "fangida.dispatcher:identify": ("path", "path", ""),
    "fangida.dispatcher:analyze": ("path manager max_bytes on_progress cancel", "path", ""),
    "fangida.dispatcher:AnalysisService": ("settings manager project_path", "", ""),
    "fangida.dispatcher:AnalysisService.analyze": (
        "self path max_bytes use_ghidra deep_analysis on_progress cancel", "self path", ""),
    "fangida.dispatcher:AnalysisService.close": ("self", "self", ""),
    "fangida.plugins.manager:Plugin.capabilities": ("self", "self", ""),
    "fangida.plugins.manager:Plugin.analyze": ("self task", "self task", ""),
    "fangida.plugins.manager:Plugin.teardown": ("self", "self", ""),
    "fangida.plugins.manager:PluginManager": ("", "", ""),
    "fangida.plugins.manager:PluginManager.load": ("self name", "self name", ""),
    "fangida.plugins.manager:PluginManager.analyze": (
        "self name task on_progress cancel", "self name task", ""),
    "fangida.plugins.manager:PluginManager.teardown": ("self", "self", ""),
    "fangida.core.kkagent.binary:parse_binary": ("data kind", "data kind", ""),
    "fangida.core.kkagent.binary:BinaryImage.metadata": ("self", "self", ""),
    "fangida.core.kkagent.translator:disassemble_entry": ("data image", "data image", ""),
    "fangida.core.kkagent.translator:objdump_available": ("", "", ""),
    "fangida.core.kkagent.semantic:analyze_semantics": (
        "data image", "data image", "max_functions max_instructions max_workers is_cancelled on_progress"),
    "fangida.native_bridge:NativeBridge": ("library", "library", ""),
    "fangida.native_bridge:NativeBridge.analyze": ("self data", "self data", ""),
    "fangida.core.apk_analyzer.dex_bytecode:decode_code": (
        "reader code_offset caller source max_instructions max_output max_calls", "reader code_offset caller source", ""),
    "fangida.core.apk_analyzer.jvm_bytecode:decode_code": (
        "code resolve_method caller source code_file_offset max_instructions max_output max_calls",
        "code resolve_method caller source code_file_offset", ""),
    "fangida.core.apk_analyzer.dex_analyzer:parse_dex": ("data source", "data", ""),
    "fangida.core.apk_analyzer.jvm_analyzer:parse_class": (
        "data source max_output_methods max_scan_instructions", "data source", ""),
    "fangida.core.apk_analyzer.worker:analyze": ("task cancel progress", "task", ""),
    "fangida.settings:Settings.validated": ("self", "self", ""),
    "fangida.settings:load_settings": ("project_dir global_path session", "", ""),
    "fangida.scripts:ScriptCapabilities": ("grants", "", ""),
    "fangida.scripts:ScriptCapabilities.from_names": ("names", "names", ""),
    "fangida.scripts:ScriptCapabilities.require": ("self name", "self name", ""),
    "fangida.scripts:ScriptContext": (
        "result", "result", "source_path store capabilities export_root"),
    "fangida.scripts:ScriptContext.from_project": (
        "store source_path", "store source_path", "capabilities export_root"),
    "fangida.scripts:ScriptContext.snapshot": ("self", "self", ""),
    "fangida.scripts:ScriptContext.functions": ("self", "self", ""),
    "fangida.scripts:ScriptContext.strings": ("self", "self", ""),
    "fangida.scripts:ScriptContext.imports": ("self", "self", ""),
    "fangida.scripts:ScriptContext.exports": ("self", "self", ""),
    "fangida.scripts:ScriptContext.xrefs": ("self address", "self", ""),
    "fangida.scripts:ScriptContext.disassembly": ("self start limit", "self", ""),
    "fangida.scripts:ScriptContext.annotations": ("self", "self", ""),
    "fangida.scripts:ScriptContext.rename_symbol": ("self address name", "self address name", ""),
    "fangida.scripts:ScriptContext.set_comment": ("self address text", "self address text", ""),
    "fangida.scripts:ScriptContext.export_json": ("self destination", "self destination", ""),
    "fangida.scripts.runner:run_script": (
        "script_path context", "script_path context", "timeout_seconds max_output_bytes"),
    "fangida.project:ProjectStore": ("database", "database", "read_only"),
    "fangida.project:ProjectStore.save_analysis": ("self source_path result", "self source_path result", "expected_hash"),
    "fangida.project:ProjectStore.load_analysis": ("self source_path", "self source_path", ""),
    "fangida.project:ProjectStore.get_snapshot": ("self snapshot_id", "self snapshot_id", ""),
    "fangida.project:ProjectStore.page": ("self snapshot_id collection", "self snapshot_id collection", "offset limit"),
    "fangida.project:ProjectStore.history": ("self source_path", "self", "offset limit"),
    "fangida.project:ProjectStore.invalidate": ("self source_path", "self source_path", ""),
    "fangida.project:ProjectStore.rename_symbol": ("self source_path address name", "self source_path address name", ""),
    "fangida.project:ProjectStore.set_comment": ("self source_path address text", "self source_path address text", ""),
    "fangida.project:ProjectStore.annotations": ("self source_path", "self source_path", "read_only"),
    "fangida.mcp_server:McpServer": ("allow_writes settings", "", ""),
    "fangida.mcp_server:McpServer.call_tool": ("self name arguments", "self name arguments", ""),
    "fangida.mcp_server:McpServer.handle": ("self message", "self message", ""),
    "fangida.mcp_server:serve": ("input_stream output_stream", "input_stream output_stream", "allow_writes"),
}

MODEL_FIELDS = {
    "fangida.models:AnalysisTask": (
        "path kind max_bytes worker_timeout_seconds max_archive_entries "
        "max_archive_uncompressed_bytes use_ghidra ghidra_timeout_seconds "
        "ghidra_max_cpu ghidra_decompiled_functions ghidra_decompile_seconds "
        "deep_analysis semantic_max_functions semantic_max_instructions semantic_threads parse_threads"),
    "fangida.models:AnalysisResult": (
        "path kind analyzer status metadata functions strings imports exports xrefs stats warnings schema_version"),
    "fangida.models:Instruction": "addr size mnemonic operands reads writes branch_info arch_meta",
    "fangida.models:Xref": "src dst kind confidence",
    "fangida.core.kkagent.binary:BinaryImage": (
        "format architecture bits endian entry_address entry_offset image_base fat_slice_offset sections functions warnings"),
    "fangida.scripts.runner:ScriptRun": "stdout stderr returncode",
    "fangida.settings:Settings": (
        "max_bytes worker_timeout_seconds max_archive_entries max_archive_uncompressed_bytes "
        "io_threads parse_threads analyze_threads native_threads semantic_threads mcp_allow_writes "
        "ghidra_enabled ghidra_timeout_seconds ghidra_max_cpu ghidra_decompiled_functions "
        "ghidra_decompile_seconds deep_analysis semantic_max_functions semantic_max_instructions"),
}

# 公共 tools/list 响应中的旧工具及其参数。通过协议取表，避免绑定私有工厂。
READ_TOOLS = {
    "open_file": ("path max_bytes use_ghidra deep_analysis", "path"),
    "close_file": ("handle", "handle"),
    "list_functions": ("handle offset limit", "handle"),
    "get_disasm": ("handle address source offset limit", "handle"),
    "get_pseudoc": ("handle address", "handle"),
    "xref_query": ("handle address direction offset limit", "handle address"),
    "list_api_calls": ("handle offset limit", "handle"),
    "export_result": ("handle offset limit", "handle"),
    "open_project": ("path", "path"),
    "close_project": ("project", "project"),
    "project_history": ("project path offset limit", "project"),
    "project_page": ("project snapshot_id collection offset limit", "project snapshot_id collection"),
    "open_project_snapshot": ("project snapshot_id", "project snapshot_id"),
    "project_annotations": ("project path offset limit", "project path"),
}
WRITE_TOOLS = {
    "rename_symbol": ("handle address name", "handle address name"),
    "create_project": ("path", "path"),
    "analyze_to_project": ("project path max_bytes use_ghidra deep_analysis", "project path"),
    "project_rename_symbol": ("project path address name", "project path address name"),
    "project_set_comment": ("project path address text", "project path address text"),
}
PARAMETER_TYPES = {
    **dict.fromkeys("path handle project source direction collection name text".split(), {"string"}),
    **dict.fromkeys("max_bytes offset limit snapshot_id".split(), {"integer"}),
    **dict.fromkeys("use_ghidra deep_analysis".split(), {"boolean"}),
    "address": {"integer", "string"},
}
CONSOLE_SCRIPTS = {
    "fangida": "fangida.ui:main", "fangida-mcp": "fangida.mcp_server:main",
    "fangida-bench": "fangida.benchmark:main", "fangida-gui": "fangida.gui:main",
    "fangida-project": "fangida.project_cli:main", "fangida-mcp-http": "fangida.mcp_http:main",
}


def resolve(path: str):
    module, attributes = path.split(":")
    value = import_module(module)
    for attribute in attributes.split("."):
        value = getattr(value, attribute)
    return value


class ApiCompatibilityTests(unittest.TestCase):
    def test_old_imports_and_call_shapes_stay_available(self) -> None:
        for path, (positional, required, keyword_only) in CALLS.items():
            with self.subTest(api=path):
                signature = inspect.signature(resolve(path))
                old_positional = positional.split()
                old_keywords = keyword_only.split()
                current_positional = [name for name, item in signature.parameters.items()
                                      if item.kind in (item.POSITIONAL_ONLY, item.POSITIONAL_OR_KEYWORD)]
                self.assertEqual(current_positional[:len(old_positional)], old_positional)
                for name in old_positional + old_keywords:
                    self.assertIn(name, signature.parameters)
                    self.assertNotEqual(signature.parameters[name].kind, inspect.Parameter.POSITIONAL_ONLY)
                # 最少的旧调用必须继续成功绑定，不能增加必填参数。
                signature.bind(**dict.fromkeys(required.split(), object()))
                signature.bind(*[object() for _ in old_positional],
                               **dict.fromkeys(old_keywords, object()))
                signature.bind(**dict.fromkeys(old_positional + old_keywords, object()))

    def test_models_keep_old_fields_order_and_defaults(self) -> None:
        for path, fields in MODEL_FIELDS.items():
            with self.subTest(model=path):
                model = resolve(path)
                names = fields.split()
                self.assertTrue(set(names) <= model.__dataclass_fields__.keys())
                positional = [name for name, value in inspect.signature(model).parameters.items()
                              if value.kind == value.POSITIONAL_OR_KEYWORD]
                self.assertEqual(positional[:len(names)], names)
        # 旧构造调用与旧 JSON 字段必须继续工作；新字段可以有默认值。
        task = AnalysisTask("sample", "elf")
        self.assertEqual((task.max_bytes, task.semantic_threads), (16 * 1024 * 1024, 1))
        result = AnalysisResult("sample", "elf", "kkagent", "partial")
        self.assertTrue(set(MODEL_FIELDS["fangida.models:AnalysisResult"].split()) <= result.to_dict().keys())
        self.assertEqual(result.schema_version, "1.0")
        self.assertEqual(Instruction(0x1000, 1, "ret").to_dict()["operands"], ())
        self.assertEqual(Xref(0x1000, 0x2000, "call").to_dict()["confidence"], 1.0)
        Settings().validated()

    def test_legacy_plugin_does_not_need_new_control_methods(self) -> None:
        class LegacyPlugin:
            name = "legacy"
            version = "0.4"

            def capabilities(self):
                return ("elf",)

            def analyze(self, task):
                return AnalysisResult(task.path, task.kind, self.name, "partial")

            def teardown(self):
                pass

        manager = PluginManager()
        with patch.object(manager, "load", return_value=LegacyPlugin()):
            result = manager.analyze("legacy", AnalysisTask("sample", "elf"), lambda _: None, None)
        self.assertEqual(result.analyzer, "legacy")

    def test_old_binary_and_translator_paths_keep_their_return_contract(self) -> None:
        image_type = resolve("fangida.core.kkagent.binary:BinaryImage")
        image = image_type("elf", "x86_64", 64, "little")
        self.assertTrue({"format", "architecture", "bits", "endian", "entry_address",
                         "entry_offset", "image_base", "fat_slice_offset", "sections"}
                        <= image.metadata().keys())
        instructions, warnings = resolve("fangida.core.kkagent.translator:disassemble_entry")(b"", image)
        self.assertEqual(instructions, [])
        self.assertIsInstance(warnings, list)
        with self.assertRaises(resolve("fangida.core.kkagent.binary:BinaryFormatError")):
            resolve("fangida.core.kkagent.binary:parse_binary")(b"", "unknown")
        modules = resolve("fangida.plugins.manager:MODULES")
        self.assertEqual(modules["kkagent"], "fangida.core.kkagent")
        self.assertEqual(modules["apk_analyzer"], "fangida.core.apk_analyzer")

    def test_legacy_service_and_snapshot_api_still_accept_old_calls(self) -> None:
        class LegacyManager:
            closed = False

            def analyze(self, name, task, on_progress=None, cancel=None):
                return AnalysisResult(task.path, task.kind, name, "partial")

            def teardown(self):
                self.closed = True

        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory) / "sample.elf"
            sample.write_bytes(b"\x7fELF" + bytes(60))
            self.assertEqual(identify(sample), ("elf", "magic"))
            manager = LegacyManager()
            with AnalysisService(Settings(), manager, None) as service:
                result = service.analyze(sample, 64, False, False, None, None)
                self.assertEqual(result.kind, "elf")
                self.assertEqual(open_file(sample, service).snapshot()["path"], str(sample.resolve()))
            self.assertTrue(manager.closed)

    def test_mcp_keeps_old_tool_names_parameters_and_supported_versions(self) -> None:
        for writes in (False, True):
            for version in ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"):
                server = McpServer(writes, Settings())
                try:
                    response = server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                              "params": {"protocolVersion": version}})
                    self.assertEqual(response["result"]["protocolVersion"], version)
                    server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
                    response = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
                    tools = {tool["name"]: tool["inputSchema"] for tool in response["result"]["tools"]}
                    baseline = {**READ_TOOLS, **(WRITE_TOOLS if writes else {})}
                    for name, (parameters, required) in baseline.items():
                        with self.subTest(writes=writes, version=version, tool=name):
                            self.assertIn(name, tools)
                            schema = tools[name]
                            self.assertTrue(set(parameters.split()) <= schema["properties"].keys())
                            self.assertTrue(set(schema.get("required", [])) <= set(required.split()))
                            for parameter in parameters.split():
                                types = schema["properties"][parameter]["type"]
                                self.assertTrue(PARAMETER_TYPES[parameter] <= set(types if isinstance(types, list) else [types]))
                finally:
                    server.close()

    def test_json_schema_still_accepts_old_result_and_instruction_fields(self) -> None:
        schema = json.loads((Path(__file__).resolve().parents[1] / "schemas/analysis-result.schema.json").read_text())
        old_result = set(MODEL_FIELDS["fangida.models:AnalysisResult"].split())
        self.assertTrue(old_result <= schema["properties"].keys())
        self.assertTrue(set(schema["required"]) <= old_result)
        self.assertEqual(schema["properties"]["schema_version"]["const"], "1.0")
        for field, values in {
            "kind": {"elf", "pe", "macho", "apk", "dex", "jar", "class", "unknown"},
            "analyzer": {"kkagent", "apk_analyzer"},
            "status": {"partial", "complete", "error"},
        }.items():
            if "enum" in schema["properties"][field]:
                self.assertTrue(values <= set(schema["properties"][field]["enum"]))
            else:
                self.assertEqual(schema["properties"][field]["type"], "string")
                self.assertLessEqual(schema["properties"][field].get("minLength", 0), min(map(len, values)))
        instruction = schema["$defs"]["instruction"]
        old_instruction = set(MODEL_FIELDS["fangida.models:Instruction"].split())
        self.assertTrue(old_instruction <= instruction["properties"].keys())
        self.assertTrue(set(instruction["required"]) <= old_instruction)

    def test_console_entry_points_and_exception_paths_stay_compatible(self) -> None:
        metadata = tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text())
        scripts = metadata["project"]["scripts"]
        for name, target in CONSOLE_SCRIPTS.items():
            self.assertEqual(scripts[name], target)
            self.assertTrue(callable(resolve(target)))
        self.assertTrue(issubclass(resolve("fangida.scripts.runner:ScriptTimeout"),
                                  resolve("fangida.scripts.runner:ScriptExecutionError")))
        self.assertTrue(issubclass(resolve("fangida.scripts.runner:ScriptOutputLimitExceeded"),
                                  resolve("fangida.scripts.runner:ScriptExecutionError")))
        self.assertTrue(issubclass(resolve("fangida.project:SourceChangedError"),
                                  resolve("fangida.project:ProjectError")))
        scripts_api = import_module("fangida.scripts")
        for name in ("ScriptRun", "ScriptExecutionError", "ScriptTimeout", "ScriptOutputLimitExceeded", "run_script"):
            self.assertIs(getattr(scripts_api, name), resolve(f"fangida.scripts.runner:{name}"))


if __name__ == "__main__":
    unittest.main()
