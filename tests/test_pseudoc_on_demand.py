"""按需伪 C：分析完成后可为任意函数（不只前 128 个）生成，结果与流水线一致。

覆盖点：
- 一致性：对流水线生成过的函数，按需生成的伪 C（可读/机器文本、截断标记、重建报告）逐字相同；
  编译运行的样本（先运行确认语义）、JSON 往返后的 MCP 快照与真实样本都验证；
- 第 129 个及之后的函数可以生成；参数传播的调用闭包包含被请求函数（调用处给出实参）；
  生成不修改结果对象（函数记录、metadata、warnings）；
- 单函数指令上限可配置：settings.pseudoc_max_instructions（默认 512，最大 8192），
  按需生成可传更大的值；源码恢复上限只在作用域内放宽；
- 上下文与结果缓存：有界、线程安全、名字变化后重建；
- MCP get_pseudoc：generate 默认 false 时行为不变；true 时按需生成并在会话内缓存，不写快照；
  工具 schema 只增不删；
- GUI：“生成伪代码”命令登记在命令体系中（Ctrl+F5 / Shift+F5、视图菜单、伪代码视图按钮），
  在后台线程生成、期间界面可操作、同一函数结果缓存；无显示环境时跳过 Tk 部分；
- libtersafe.so 上测量第 1000 个之后函数的按需生成耗时（首次含上下文构建、之后命中缓存）。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fangida.models import AnalysisResult
from fangida.plugins.pseudoc import on_demand, pipeline
from fangida.plugins.pseudoc.on_demand import (PseudocContext, generate_function_pseudoc,
                                               pseudoc_context)
from fangida.settings import Settings
from tests import test_gui_workbench as gui_fixture
from tests.test_pseudoc import function, instruction

LIBTERSAFE = Path("/Users/meow233/Downloads/libtersafe.so")
CHALLENGE = Path("/Users/meow233/Downloads/project/dist/challenge")
CHAIN = 160  # 编译样本中的函数链长度：保证有第 129 个之后的函数
_COMPARED = ("pseudoc", "machine_pseudoc", "pseudoc_truncated", "pseudoc_reconstruction", "pseudoc_style")


def _chain_source() -> str:
    """f0..f159 依次调用前一个函数（每个都使用自己的参数），main 打印结果。"""
    lines = ["#include <stdio.h>", "#include <stdlib.h>",
             "__attribute__((noinline)) int f0(int x) { return x * 3 + 1; }"]
    for index in range(1, CHAIN):
        lines.append(f"__attribute__((noinline)) int f{index}(int x) {{ "
                     f"if (x & 1) return f{index - 1}(x - {index}) ^ {index}; "
                     f"return f{index - 1}(x + {index}) + {index}; }}")
    lines.append(f"int main(int argc, char **argv) {{ int v = f{CHAIN - 1}(argc > 1 ? atoi(argv[1]) : 7); "
                 'printf("%d\\n", v); return 0; }')
    return "\n".join(lines) + "\n"


def _expected(value: int) -> int:
    """与样本相同的 32 位有符号整数语义。"""
    def wrap(number: int) -> int:
        number &= 0xffffffff
        return number - (1 << 32) if number & 0x80000000 else number

    def call(index: int, x: int) -> int:
        if index == 0:
            return wrap(x * 3 + 1)
        if x & 1:
            return wrap(call(index - 1, wrap(x - index)) ^ index)
        return wrap(call(index - 1, wrap(x + index)) + index)
    return call(CHAIN - 1, value)


def _pipeline_outputs(result) -> list[tuple[int, dict]]:
    """流水线为其生成过伪 C、且单函数字符预算未被总预算压低的函数（下标, 记录）。"""
    chosen, characters = [], 0
    for index, record in enumerate(result.functions):
        if record.get("pseudoc_producer") != "fangida_native_pseudoc" or not record.get("pseudoc"):
            continue
        budget = min(32768, pipeline.MAX_TOTAL_CHARS - characters)
        characters += len(record["pseudoc"])
        if budget == 32768:
            chosen.append((index, record))
    return chosen


def _analyze(path: Path) -> AnalysisResult:
    from fangida.dispatcher import AnalysisService
    with AnalysisService(Settings(analyze_threads=2)) as service:
        return service.analyze(path, full_analysis=True)


def _size(record: dict) -> int:
    return sum(len(block.get("instructions", ())) for block in record.get("blocks", ()))


class _CompiledChain:
    """编译、运行并分析一次链式样本，供本模块的多个测试类复用。"""
    _state: dict | None = None

    @classmethod
    def get(cls) -> dict:
        if cls._state is None:
            compiler = shutil.which("cc")
            if not compiler or os.name == "nt":
                raise unittest.SkipTest("需要 C 编译器")
            directory = tempfile.TemporaryDirectory()
            source, binary = Path(directory.name) / "chain.c", Path(directory.name) / "chain"
            source.write_text(_chain_source())
            built = subprocess.run([compiler, "-O1", "-fno-optimize-sibling-calls", "-fno-inline",
                                    "-o", str(binary), str(source)], capture_output=True, text=True)
            if built.returncode:
                directory.cleanup()
                raise unittest.SkipTest("无法编译样本：" + built.stderr[-200:])
            # 先运行确认样本语义与预期一致，再分析同一个二进制。
            ran = subprocess.run([str(binary), "11"], capture_output=True, text=True, timeout=30)
            result = _analyze(binary)
            cls._state = {"directory": directory, "binary": binary, "result": result,
                          "output": ran.stdout.strip(), "returncode": ran.returncode}
        return cls._state


def tearDownModule() -> None:  # noqa: N802 - unittest 约定
    state = _CompiledChain._state
    if state is not None:
        state["directory"].cleanup()
        _CompiledChain._state = None
    on_demand.clear_pseudoc_contexts()


def _named(result, name: str) -> tuple[int, dict]:
    for index, record in enumerate(result.functions):
        if pipeline.display_name(record) == name:
            return index, record
    raise AssertionError(f"样本中没有函数 {name}")


class CompiledConsistencyTests(unittest.TestCase):
    def setUp(self):
        self.state = _CompiledChain.get()
        self.result = self.state["result"]

    def test_sample_runs_with_expected_semantics(self):
        self.assertEqual(self.state["returncode"], 0)
        self.assertEqual(int(self.state["output"]), _expected(11))
        self.assertGreater(len(self.result.functions), pipeline.MAX_FUNCTIONS)

    def test_on_demand_text_equals_pipeline_text(self):
        compared = _pipeline_outputs(self.result)
        self.assertGreaterEqual(len(compared), 16)
        context = PseudocContext(self.result)
        for index, record in compared:
            with self.subTest(index=index, name=record.get("name")):
                generated = context.generate(record)
                for key in _COMPARED:
                    self.assertEqual(generated.get(key), record.get(key), key)
                self.assertTrue(generated["on_demand"])
        self.assertEqual(context.builds, 1)

    def test_functions_beyond_first_128_generate_with_arguments_from_their_closure(self):
        before_warnings = list(self.result.warnings)
        before_metadata = set(self.result.metadata)
        index, record = _named(self.result, f"f{CHAIN - 10}")
        self.assertGreaterEqual(index, pipeline.MAX_FUNCTIONS)
        self.assertNotIn("pseudoc", record)  # 流水线没有为它生成
        context = PseudocContext(self.result)
        generated = context.generate(record["start"], address_space=record.get("address_space"))
        text = generated["pseudoc"]
        self.assertIn(f"f{CHAIN - 11}(", text)
        # 调用闭包包含被请求函数：被调函数的参数用法已知，调用处给出实参。
        self.assertNotIn("unknown_arguments", text)
        callee = _named(self.result, f"f{CHAIN - 11}")[1]
        self.assertIn(record["start"], context._state.closure)
        self.assertIn(callee["start"], context._state.closure)
        self.assertTrue(context._state.summaries["ram"][callee["start"]]["parameters"])
        # 函数自身按流水线规则得到签名：参数列表不是 void。
        self.assertNotIn("(void)", text.splitlines()[1])
        # 不修改结果对象。
        self.assertNotIn("pseudoc", record)
        self.assertEqual(self.result.warnings, before_warnings)
        self.assertEqual(set(self.result.metadata), before_metadata)
        # main 也能生成：调用链首函数时给出实参，格式串还原为字面量。
        main = _named(self.result, "main")[1]
        text = context.generate(main)["pseudoc"]
        self.assertRegex(text, rf"f{CHAIN - 1}\(\w+\)")
        self.assertIn('"%d\\n"', text)

    def test_extending_the_closure_keeps_earlier_results_identical(self):
        compared = _pipeline_outputs(self.result)[:8]
        context = PseudocContext(self.result)
        for name in (f"f{CHAIN - 1}", f"f{CHAIN - 30}", "main"):
            context.generate(_named(self.result, name)[1])
        for index, record in compared:
            with self.subTest(index=index):
                self.assertEqual(context.generate(record)["pseudoc"], record["pseudoc"])

    def test_snapshot_mapping_and_module_cache(self):
        snapshot = vars(self.result)
        index, record = _named(self.result, f"f{CHAIN - 2}")
        first = generate_function_pseudoc(snapshot, record["start"], address_space=record.get("address_space"))
        second = generate_function_pseudoc(snapshot, record["start"], address_space=record.get("address_space"))
        self.assertFalse(first["cached"])
        self.assertTrue(second["cached"])
        self.assertEqual(first["pseudoc"], second["pseudoc"])
        self.assertIs(pseudoc_context(snapshot), pseudoc_context(snapshot))
        # 返回值是副本：修改它不会污染缓存。
        second["pseudoc_reconstruction"]["mutated"] = True
        third = generate_function_pseudoc(snapshot, record["start"], address_space=record.get("address_space"))
        self.assertNotIn("mutated", third["pseudoc_reconstruction"])
        on_demand.discard_pseudoc_context(snapshot)
        with self.assertRaises(ValueError):
            generate_function_pseudoc(snapshot, record["start"], context=PseudocContext({"functions": []}))


def _long_function(count: int) -> dict:
    rows = [instruction(0x1000 + index * 3, "add", "eax", "1", size=3) for index in range(count)]
    rows.append(instruction(0x1000 + count * 3, "ret", kind="return"))
    return function(*rows, name="long_body")


class LimitTests(unittest.TestCase):
    def _result(self, count: int = 700) -> AnalysisResult:
        functions = [function(instruction(0x100 + index * 16, "ret", kind="return"), name=f"stub_{index}")
                     for index in range(3)]
        functions.append(_long_function(count))
        return AnalysisResult("long", "elf", "kkagent", "partial", metadata={"architecture": "x86_64"},
                              functions=functions)

    def test_settings_field_defaults_to_pipeline_limit_and_is_validated(self):
        self.assertEqual(Settings().pseudoc_max_instructions, 512)
        self.assertEqual(Settings(pseudoc_max_instructions=8192).validated().pseudoc_max_instructions, 8192)
        for value in (0, 8193, True, 1.5):
            with self.subTest(value=value), self.assertRaises(ValueError):
                Settings(pseudoc_max_instructions=value).validated()

    def test_default_limit_truncates_and_larger_limit_covers_the_whole_function(self):
        result = self._result()
        context = PseudocContext(result)
        default = context.generate(0x1000)
        larger = context.generate(0x1000, max_instructions=1024)
        self.assertEqual(default["max_instructions"], 512)
        self.assertTrue(default["pseudoc_truncated"])
        self.assertFalse(larger["pseudoc_truncated"])
        self.assertEqual(larger["max_instructions"], 1024)
        self.assertGreaterEqual(larger["max_chars"], 131072)
        # 可读视图覆盖完整函数（700 次加 1），默认上限只覆盖前一部分。
        self.assertEqual(larger["pseudoc"].count("+ 1"), 700)
        self.assertLess(default["pseudoc"].count("+ 1"), 700)
        self.assertTrue(larger["machine_pseudoc"])
        self.assertGreater(len(larger["pseudoc"]), len(default["pseudoc"]))
        for value in (0, 8193, "512", True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                context.generate(0x1000, max_instructions=value)

    def test_source_limit_is_scoped_and_pipeline_default_is_unchanged(self):
        from fangida.plugins.pseudoc import reconstruct
        self.assertEqual(reconstruct._source_limit(), reconstruct.MAX_SOURCE_INSTRUCTIONS)
        with reconstruct.source_instruction_limit(2048):
            self.assertEqual(reconstruct._source_limit(), 2048)
            seen = []
            worker = threading.Thread(target=lambda: seen.append(reconstruct._source_limit()))
            worker.start()
            worker.join()
            self.assertEqual(seen, [reconstruct.MAX_SOURCE_INSTRUCTIONS])  # 其它线程不受影响
        self.assertEqual(reconstruct._source_limit(), reconstruct.MAX_SOURCE_INSTRUCTIONS)
        with self.assertRaises(ValueError), reconstruct.source_instruction_limit(9000):
            pass
        # 流水线仍按 512 截断，按需生成的默认结果与它相同。
        result = self._result()
        pipeline.populate_native_pseudoc(result)
        self.assertTrue(result.functions[-1]["pseudoc_truncated"])
        generated = PseudocContext(result).generate(result.functions[-1])
        self.assertEqual(generated["pseudoc"], result.functions[-1]["pseudoc"])

    def test_unsupported_inputs_are_rejected_without_analysis(self):
        bytecode = AnalysisResult("a", "dex", "kkagent", "partial", metadata={"architecture": "dex"},
                                  functions=[function(instruction(0, "nop"), name="m")])
        with self.assertRaisesRegex(ValueError, "unavailable"):
            PseudocContext(bytecode).generate(0)
        context = PseudocContext(self._result())
        with self.assertRaisesRegex(ValueError, "No function starts"):
            context.generate(0xdead)
        with self.assertRaisesRegex(ValueError, "does not belong"):
            context.generate(dict(self._result().functions[0]))
        with self.assertRaises(TypeError):
            PseudocContext(object())


class CacheTests(unittest.TestCase):
    def _result(self) -> AnalysisResult:
        functions = [function(instruction(0x100 + index * 16, "mov", "eax", str(index), size=5),
                              instruction(0x105 + index * 16, "ret", kind="return"), name=f"routine_{index}")
                     for index in range(4)]
        return AnalysisResult("cache", "elf", "kkagent", "partial", metadata={"architecture": "x86_64"},
                              functions=functions)

    def test_concurrent_requests_build_the_context_once_and_share_results(self):
        result = self._result()
        context = PseudocContext(result)
        outputs, errors = [], []

        def work():
            try:
                outputs.append(context.generate(0x110)["pseudoc"])
            except Exception as exc:  # pragma: no cover - 失败时由断言报告
                errors.append(exc)

        threads = [threading.Thread(target=work) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(set(outputs)), 1)
        self.assertEqual(context.builds, 1)
        self.assertTrue(context.generate(0x110)["cached"])

    def test_rename_rebuilds_context_and_output_cache_is_bounded(self):
        result = self._result()
        context = PseudocContext(result)
        self.assertIn("routine_1", context.generate(0x110)["pseudoc"])
        result.functions[1]["name"] = "renamed_routine"
        self.assertFalse(context.current())
        self.assertIn("renamed_routine", context.generate(0x110)["pseudoc"])
        self.assertEqual(context.builds, 2)
        with patch.object(on_demand, "MAX_CACHED_OUTPUTS", 2):
            for start in (0x100, 0x110, 0x120, 0x130):
                context.generate(start)
            self.assertLessEqual(len(context._outputs), 2)

    def test_module_cache_is_bounded(self):
        results = [self._result() for _ in range(on_demand.MAX_CONTEXTS + 2)]
        contexts = [pseudoc_context(result) for result in results]
        self.assertLessEqual(len(on_demand._CONTEXTS), on_demand.MAX_CONTEXTS)
        self.assertIs(pseudoc_context(results[-1]), contexts[-1])
        on_demand.clear_pseudoc_contexts()
        self.assertEqual(len(on_demand._CONTEXTS), 0)


class McpGenerateTests(unittest.TestCase):
    def setUp(self):
        from fangida.mcp_server import McpServer
        self.state = _CompiledChain.get()
        # 与数据库/MCP 相同：JSON 往返后的快照。
        self.snapshot = json.loads(json.dumps(self.state["result"].to_dict()))
        self.server = McpServer(settings=Settings())
        self.server._snapshots["chain"] = self.snapshot
        self.addCleanup(self.server.close)

    def _call(self, **arguments):
        return self.server.call_tool("get_pseudoc", {"handle": "chain", **arguments})

    def test_schema_only_adds_optional_parameters(self):
        self.server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                            "params": {"protocolVersion": "2025-06-18"}})
        self.server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
        response = self.server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tools = {tool["name"]: tool["inputSchema"] for tool in response["result"]["tools"]}
        schema = tools["get_pseudoc"]
        self.assertEqual(schema["required"], ["handle"])
        self.assertEqual(schema["properties"]["generate"]["type"], "boolean")
        self.assertIs(schema["properties"]["generate"]["default"], False)
        self.assertEqual(schema["properties"]["max_instructions"]["type"], "integer")
        self.assertEqual(schema["properties"]["max_instructions"]["maximum"], 8192)
        self.assertTrue({"handle", "address", "source", "style", "address_space"} <= schema["properties"].keys())

    def test_default_behaviour_is_unchanged_and_generate_caches_in_session(self):
        index, record = _named(self.state["result"], f"f{CHAIN - 5}")
        address = record["start"]
        missing = self._call(address=address)
        self.assertTrue(missing["isError"])
        self.assertIn("Pseudo-C is unavailable", json.dumps(missing))
        first = self._call(address=address, generate=True)["structuredContent"]
        self.assertTrue(first["available"])
        self.assertTrue(first["generated"])
        self.assertFalse(first["cached"])
        self.assertEqual(first["max_instructions"], 512)
        self.assertEqual(first["address"], address)
        second = self._call(address=address, generate=True)["structuredContent"]
        self.assertTrue(second["cached"])
        self.assertEqual(second["pseudoc"], first["pseudoc"])
        # 内部地址同样命中该函数；不写回快照。
        interior = self._call(address=address + 4, generate=True)["structuredContent"]
        self.assertEqual(interior["address"], address)
        saved = next(item for item in self.snapshot["functions"] if item.get("start") == address)
        self.assertNotIn("pseudoc", saved)
        machine = self._call(address=address, generate=True, style="machine")["structuredContent"]
        self.assertEqual(machine["style"], "machine")
        self.assertIn("IR-derived pseudo-C", machine["pseudoc"])
        # 关闭句柄释放会话缓存。
        self.assertIn("chain", self.server._pseudoc_contexts)
        self.server.call_tool("close_file", {"handle": "chain"})
        self.assertNotIn("chain", self.server._pseudoc_contexts)

    def test_saved_pseudoc_wins_and_explicit_limit_regenerates_identically(self):
        index, record = _pipeline_outputs(self.state["result"])[3]
        address = record["start"]
        saved = self._call(address=address, generate=True)["structuredContent"]
        self.assertNotIn("generated", saved)  # 已保存的伪 C：返回结构与原来相同
        self.assertEqual(saved["pseudoc"], record["pseudoc"])
        regenerated = self._call(address=address, generate=True, max_instructions=512)["structuredContent"]
        self.assertTrue(regenerated["generated"])
        # JSON 往返后的快照上按需生成的文本与流水线文本相同。
        self.assertEqual(regenerated["pseudoc"], record["pseudoc"])
        self.assertEqual(regenerated["reconstruction"], json.loads(json.dumps(record["pseudoc_reconstruction"])))

    def test_invalid_arguments_are_tool_errors(self):
        for arguments in ({"generate": "yes"}, {"generate": True, "max_instructions": 0},
                          {"generate": True, "max_instructions": 9000}, {"generate": True, "max_instructions": True}):
            with self.subTest(arguments=arguments):
                self.assertTrue(self._call(address=0, **arguments)["isError"])


class GuiCommandLogicTests(unittest.TestCase):
    """不需要显示环境的部分：命令登记、键位与生成结果行。"""

    def test_command_is_registered_outside_the_ida_key_table(self):
        from fangida.gui_modules.commands import IDA_COMMANDS, PSEUDOCODE_COMMANDS, CommandRegistry
        from fangida.gui_modules.shortcuts import ShortcutBinder, shortcut_label
        from tests.test_gui_shortcuts import _Window
        from types import SimpleNamespace
        command = next(item for item in PSEUDOCODE_COMMANDS if item.id == "generate_pseudocode")
        self.assertNotIn("generate_pseudocode", {item.id for item in IDA_COMMANDS})
        self.assertEqual(shortcut_label(command, "linux"), "Ctrl+F5 / Shift+F5")
        registry, calls = CommandRegistry(), []
        for item in IDA_COMMANDS + PSEUDOCODE_COMMANDS:
            registry.register(item, lambda _event=None, command_id=item.id: calls.append(command_id))
        window = _Window()
        ShortcutBinder(window, registry, platform="linux").bind_all()  # 与已有键位不冲突
        self.assertEqual(window.handlers["<Control-F5>"](SimpleNamespace(state=4)), "break")
        self.assertEqual(window.handlers["<F5>"](SimpleNamespace(state=0)), "break")
        self.assertEqual(calls, ["generate_pseudocode", "show_pseudocode"])

    def test_generated_row_matches_pseudocode_table_fields(self):
        from fangida.gui_modules.records import generated_pseudocode_row
        record = {"name": "f", "start": 0x40, "size": 8, "xrefs_out": [1], "blocks": []}
        generated = {"pseudoc": "int f(void) {\n    return 0;\n}", "pseudoc_producer": "fangida_native_pseudoc",
                     "pseudoc_truncated": False, "machine_pseudoc": "x", "pseudoc_style": "readable",
                     "pseudoc_reconstruction": {"complete": True}, "max_instructions": 512}
        row = generated_pseudocode_row(record, generated)
        self.assertEqual(row["name"], "f")
        self.assertEqual(row["start"], 0x40)
        self.assertEqual(row["pseudoc"], generated["pseudoc"])
        self.assertTrue(row["pseudoc_on_demand"])
        self.assertIn("pseudoc_status", row)
        self.assertNotIn("blocks", row)
        self.assertNotIn("pseudoc", record)

    def test_gui_facade_reexports_the_generator(self):
        import fangida.gui as gui
        self.assertIs(gui.PseudocContext, PseudocContext)


class GuiGenerateTests(unittest.TestCase):
    """真实 Tk 工作区：后台生成、期间可操作、结果缓存与显示（无法创建 Tk 窗口时跳过）。"""
    fixture = gui_fixture
    setUp = gui_fixture.GuiWorkbenchIntegrationTests.setUp
    _close = gui_fixture.GuiWorkbenchIntegrationTests._close
    _load = gui_fixture.GuiWorkbenchIntegrationTests._load

    def _pump(self, predicate=None, timeout=30.0):
        import _tkinter
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.root.tk.dooneevent(_tkinter.DONT_WAIT)
            if self.callback_errors:
                self.fail(f"Tk 回调出现错误：{self.callback_errors!r}")
            if predicate is not None and predicate():
                return
            if predicate is None:
                return
            time.sleep(0.002)
        self.fail("等待 Tk 状态超时")

    def _navigate(self, address):
        from fangida.gui_modules.navigation import Location
        self.assertTrue(self.browser.workbench.navigate(Location(address)))

    def test_generate_runs_in_background_and_result_is_cached(self):
        browser, workbench, target = self.browser, self.browser.workbench, self.fixture.TARGET
        self._navigate(target + 4)
        self.assertTrue(workbench.registry.is_enabled("generate_pseudocode"))
        release, entered = threading.Event(), threading.Event()
        real = PseudocContext

        class SlowContext(real):
            def generate(self, *args, **kwargs):
                entered.set()
                release.wait(20)
                return super().generate(*args, **kwargs)

        with patch("fangida.gui.PseudocContext", SlowContext):
            self.assertTrue(workbench.registry.execute("generate_pseudocode"))
            self.assertTrue(entered.wait(10))
            # 生成期间界面可操作：没有进入忙碌状态，可以导航，重复请求不会再开线程。
            self.assertFalse(browser._busy)
            self._navigate(self.fixture.BASE + 4)
            self._navigate(target + 4)
            with patch("threading.Thread", side_effect=AssertionError("同一函数不应再开线程")):
                self.assertTrue(browser.request_pseudocode(target, "target"))
            self.assertEqual(browser._pseudocode_jobs().pending, {target})
            self.assertIn("正在后台生成", browser.status.get())
            release.set()
            self._pump(lambda: browser.generated_pseudocode(target) is not None)
            self._pump(lambda: browser.pseudocode_view.row is browser.generated_pseudocode(target))
        row = browser.generated_pseudocode(target)
        self.assertTrue(row["pseudoc_on_demand"])
        self.assertIn("target", row["pseudoc"])
        self.assertIn("按需生成", browser.pseudocode_view.info.get())
        self.assertEqual(browser.pseudocode_view.code.get("1.0", "end-1c"), row["pseudoc"])
        # 同一函数再次执行命令：直接显示缓存结果，不再生成。
        self._navigate(self.fixture.BASE)
        self._navigate(target)
        with patch.object(PseudocContext, "generate", side_effect=AssertionError("不应重新生成")):
            workbench.registry.execute("generate_pseudocode")
            workbench.show_pseudocode()
        self.assertIs(browser.pseudocode_view.row, row)
        # 快照没有被写回。
        functions = browser._view._snapshot["functions"]
        self.assertFalse(any("pseudoc" in item for item in functions))
        # 打开新结果后旧的生成结果失效。
        browser._generation += 1
        self._load(self.fixture._view("/nonexistent/other-fixture.elf"))
        self.assertIsNone(browser.generated_pseudocode(target))

    def test_view_button_and_menu_use_the_same_command(self):
        browser = self.browser
        self.assertIsNotNone(browser.pseudocode_view.generate_button)
        found = False
        pending = list(self.root.winfo_children())
        while pending:
            child = pending.pop()
            pending.extend(child.winfo_children())
            for _index, command_id in getattr(child, "_fangida_commands", ()):
                found = found or command_id == "generate_pseudocode"
        self.assertTrue(found)
        with patch.object(browser, "request_pseudocode") as request:
            self._navigate(self.fixture.TARGET + 8)
            browser.pseudocode_view.generate_button.invoke()
        request.assert_called_once_with(self.fixture.TARGET, "target")
        # 没有结果时按钮只提示，不启动工作线程。
        browser._view = None
        with patch.object(browser, "request_pseudocode", side_effect=AssertionError("不应生成")):
            browser.pseudocode_view.generate_button.invoke()
        self.assertIn("先打开", browser.status.get())


class RealSampleTests(unittest.TestCase):
    def test_challenge_on_demand_equals_pipeline(self):
        if not CHALLENGE.is_file():
            raise unittest.SkipTest("缺少真实样本 challenge")
        result = _analyze(CHALLENGE)
        compared = _pipeline_outputs(result)
        self.assertGreater(len(compared), 64)
        context = PseudocContext(result)
        for index, record in compared[:64]:
            with self.subTest(index=index):
                generated = context.generate(record)
                for key in _COMPARED:
                    self.assertEqual(generated.get(key), record.get(key), key)
        beyond = next(index for index, record in enumerate(result.functions)
                      if index >= pipeline.MAX_FUNCTIONS and _size(record) >= 8 and "pseudoc" not in record)
        self.assertTrue(context.generate(result.functions[beyond])["pseudoc"])

    def test_libtersafe_function_after_1000_timing(self):
        if not LIBTERSAFE.is_file():
            raise unittest.SkipTest("缺少真实样本 libtersafe.so")
        result = _analyze(LIBTERSAFE)
        index = next(index for index, record in enumerate(result.functions)
                     if index > 1000 and 60 <= _size(record) <= 400 and "pseudoc" not in record)
        record = result.functions[index]
        context = PseudocContext(result)
        began = time.perf_counter()
        first = context.generate(record)
        first_seconds = time.perf_counter() - began
        began = time.perf_counter()
        cached = context.generate(record)
        cached_seconds = time.perf_counter() - began
        other = next(item for position, item in enumerate(result.functions)
                     if position > index and 60 <= _size(item) <= 400 and "pseudoc" not in item)
        began = time.perf_counter()
        context.generate(other)
        warm_seconds = time.perf_counter() - began
        self.assertTrue(first["pseudoc"])
        self.assertTrue(cached["cached"])
        self.assertEqual(cached["pseudoc"], first["pseudoc"])
        self.assertLess(cached_seconds, first_seconds)
        print(f"\nlibtersafe.so 第 {index + 1} 个函数（{_size(record)} 条指令）按需伪 C："
              f"首次（含上下文构建）{first_seconds:.3f}s，命中缓存 {cached_seconds * 1000:.2f}ms，"
              f"上下文已建好时另一函数 {warm_seconds:.3f}s")


if __name__ == "__main__":
    unittest.main()
