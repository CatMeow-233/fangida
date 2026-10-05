"""按需伪 C 审查修复的回归测试（与 tests/test_pseudoc_on_demand.py 互补）。

覆盖点：
- 放宽指令上限后重新提升可读视图的分支（_widen_readable 真正替换输出）：截断标记保留机器视图
  自身的截断（与 generate_pseudoc 的语义相同），MCP 的 style=machine 据此返回 truncated=true；
- MCP 未传 max_instructions 时从 settings.pseudoc_max_instructions 取默认上限；
- 流水线渲染范围之外的 sub_ 函数：按需生成的函数头与（同样按需生成的）调用处使用同一个
  function_N；流水线渲染过的函数文本保持不变；机器视图仍统一使用原始名字；
- MCP generate=true 且给出 max_instructions：不能按需生成（dex 等）时回退到已保存的伪 C；
- 快照函数列表含非字典条目时，按需生成仍可用，MCP 返回正常结果而不是 JSON-RPC 内部错误；
  上下文构建遇到异常快照时给出 ValueError；
- 范围之外的 PLT 桩：按需生成时补充核对它本身是否为链接桩，函数头与调用处同用导入名；
- GUI 按需生成：每个结果至多一个工作线程，连续请求多个函数时排队（后请求的先生成），
  打开新结果后旧队列不再生成；
- libtersafe.so 上审查给出的样例（放宽上限的截断标记、function_N 与导入桩的名字一致）。
"""
from __future__ import annotations

import json
import queue
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fangida.gui_modules.browser_jobs import _JobsMixin
from fangida.models import AnalysisResult
from fangida.plugins.pseudoc import on_demand, pipeline
from fangida.plugins.pseudoc.on_demand import PseudocContext
from fangida.settings import Settings
from tests.test_pseudoc import function, instruction

LIBTERSAFE = Path("/Users/meow233/Downloads/libtersafe.so")


def _long_result(count: int) -> AnalysisResult:
    """3 个桩函数 + 一个由 count 条 add eax, 1 组成的长函数（起点 0x1000，每条 3 字节）。"""
    functions = [function(instruction(0x100 + index * 16, "ret", kind="return"), name=f"stub_{index}")
                 for index in range(3)]
    rows = [instruction(0x1000 + index * 3, "add", "eax", "1", size=3) for index in range(count)]
    rows.append(instruction(0x1000 + count * 3, "ret", kind="return"))
    functions.append(function(*rows, name="long_body"))
    return AnalysisResult("long", "elf", "kkagent", "partial", metadata={"architecture": "x86_64"},
                          functions=functions)


class _WidenSpy:
    """记录 _widen_readable 的调用次数与真正替换输出的次数（不改变行为）。"""

    def __init__(self) -> None:
        self.calls = self.widened = 0
        self.machine_truncated: list[bool] = []
        self._real = on_demand._widen_readable

    def __call__(self, snapshot, architecture, output, max_instructions, max_chars):
        self.calls += 1
        self.machine_truncated.append(output.truncated)
        replaced = self._real(snapshot, architecture, output, max_instructions, max_chars)
        self.widened += replaced is not output
        return replaced


class WidenedReadableTests(unittest.TestCase):
    def test_widened_readable_view_keeps_the_machine_truncation_flag(self):
        # 700 条指令、上限 1024、字符上限 40000：机器视图（约 100 字符/条）超出字符上限被减半，
        # 可读视图经 _widen_readable 重新提升后覆盖整个函数。
        spy = _WidenSpy()
        with patch.object(on_demand, "_widen_readable", spy):
            generated = PseudocContext(_long_result(700)).generate(0x1000, max_instructions=1024,
                                                                   max_chars=40000)
        self.assertEqual((spy.calls, spy.widened), (1, 1))  # 确实走了替换分支
        self.assertEqual(spy.machine_truncated, [True])
        self.assertEqual(generated["pseudoc"].count("+ 1"), 700)  # 可读视图完整
        machine = generated["machine_pseudoc"]
        self.assertLessEqual(len(machine), 40000)
        self.assertNotIn(f"{0x1000 + 699 * 3:#x}", machine)  # 机器视图只覆盖前一部分
        # 与 generate_pseudoc 的语义一致：任一视图被截断即为真（此处机器视图被截断）。
        self.assertTrue(generated["pseudoc_truncated"])

    def test_default_path_and_widened_path_report_the_same_flag_semantics(self):
        # 同一函数、同一上限：默认路径（不放宽）机器视图被截断时标记为真；放宽路径也为真。
        result = _long_result(700)
        default = pipeline.generate_pseudoc(
            {**result.functions[-1], "pseudoc_context": {"kind": "elf"}}, "x86_64",
            max_instructions=1024, max_chars=40000, style="readable")
        self.assertTrue(default.truncated)
        widened = PseudocContext(result).generate(0x1000, max_instructions=1024, max_chars=40000)
        self.assertEqual(widened["pseudoc_truncated"], default.truncated)
        # 没有触发放宽（机器视图未超出字符上限）时标记仍为假。
        complete = PseudocContext(_long_result(700)).generate(0x1000, max_instructions=1024)
        self.assertFalse(complete["pseudoc_truncated"])


class _McpCase(unittest.TestCase):
    handle = "fixture"

    def _server(self, snapshot, settings=None):
        from fangida.mcp_server import McpServer
        server = McpServer(settings=settings or Settings())
        server._snapshots[self.handle] = snapshot
        self.addCleanup(server.close)
        return server

    def _call(self, server, **arguments):
        return server.call_tool("get_pseudoc", {"handle": self.handle, **arguments})


class McpWidenAndSettingsTests(_McpCase):
    def setUp(self):
        # 与数据库/MCP 相同：JSON 往返后的快照。2000 条指令、上限 2048 时字符上限为 131072，
        # 机器视图（约 20 万字符）被减半，可读视图放宽后覆盖整个函数。
        self.snapshot = json.loads(json.dumps(_long_result(2000).to_dict()))

    def test_machine_style_reports_truncation_when_readable_view_was_widened(self):
        server = self._server(self.snapshot)
        spy = _WidenSpy()
        with patch.object(on_demand, "_widen_readable", spy):
            machine = self._call(server, address=0x1000, generate=True, max_instructions=2048,
                                 style="machine")["structuredContent"]
        self.assertEqual((spy.calls, spy.widened), (1, 1))
        self.assertEqual(machine["style"], "machine")
        self.assertEqual(machine["max_instructions"], 2048)
        self.assertNotIn(f"{0x1000 + 2000 * 3:#x}", machine["pseudoc"])  # 机器文本没有到达函数末尾
        self.assertTrue(machine["truncated"])
        readable = self._call(server, address=0x1000, generate=True, max_instructions=2048)["structuredContent"]
        self.assertTrue(readable["cached"])  # 同一生成结果的另一个视图
        self.assertEqual(readable["pseudoc"].count("+ 1"), 2000)
        self.assertTrue(readable["truncated"])

    def test_default_limit_comes_from_settings(self):
        configured = self._call(self._server(self.snapshot, Settings(pseudoc_max_instructions=2048)),
                                address=0x1000, generate=True)["structuredContent"]
        self.assertTrue(configured["generated"])
        self.assertEqual(configured["max_instructions"], 2048)
        self.assertEqual(configured["pseudoc"].count("+ 1"), 2000)
        default = self._call(self._server(self.snapshot), address=0x1000, generate=True)["structuredContent"]
        self.assertEqual(default["max_instructions"], 512)
        self.assertLess(default["pseudoc"].count("+ 1"), 2000)
        self.assertTrue(default["truncated"])
        # 显式参数优先于 settings。
        explicit = self._call(self._server(self.snapshot, Settings(pseudoc_max_instructions=2048)),
                              address=0x1000, generate=True, max_instructions=512)["structuredContent"]
        self.assertEqual(explicit["max_instructions"], 512)
        self.assertEqual(explicit["pseudoc"], default["pseudoc"])


class McpSavedFallbackTests(_McpCase):
    def test_bytecode_result_falls_back_to_saved_pseudoc_with_explicit_limit(self):
        saved = "void m() {\n    return;\n}"
        record = function(instruction(0, "return-void", kind="return"), name="m", pseudoc=saved,
                          pseudoc_producer="fangida_bytecode_pseudoc", pseudoc_style="bytecode")
        snapshot = {"path": "a.dex", "kind": "dex", "metadata": {"architecture": "dex"}, "functions": [record]}
        server = self._server(snapshot)
        plain = self._call(server, address=0)["structuredContent"]
        self.assertTrue(plain["available"])
        for arguments in ({"generate": True}, {"generate": True, "max_instructions": 100}):
            with self.subTest(arguments=arguments):
                response = self._call(server, address=0, **arguments)
                self.assertFalse(response.get("isError"), response)
                self.assertEqual(response["structuredContent"], plain)  # 与已保存伪 C 的返回相同
        self.assertFalse(getattr(server, "_pseudoc_contexts", {}))  # 没有尝试按需生成

    def test_native_function_without_instructions_falls_back_to_saved_pseudoc(self):
        saved = {"name": "imported", "start": 0x500, "pseudoc": "int imported(void);",
                 "pseudoc_producer": "analyzer"}
        body = _long_result(4).to_dict()
        snapshot = json.loads(json.dumps({**body, "functions": [saved, *body["functions"]]}))
        server = self._server(snapshot)
        response = self._call(server, address=0x500, generate=True, max_instructions=1024)
        self.assertFalse(response.get("isError"), response)
        self.assertEqual(response["structuredContent"]["pseudoc"], "int imported(void);")
        self.assertNotIn("generated", response["structuredContent"])
        # 带指令的原生函数仍按请求的上限重新生成。
        regenerated = self._call(server, address=0x1000, generate=True, max_instructions=1024)
        self.assertTrue(regenerated["structuredContent"]["generated"])
        self.assertEqual(regenerated["structuredContent"]["max_instructions"], 1024)


class MalformedSnapshotTests(_McpCase):
    def setUp(self):
        self.snapshot = json.loads(json.dumps(_long_result(8).to_dict()))
        self.snapshot["functions"].append(None)  # 快照里混入的非字典条目

    def test_context_tolerates_non_dict_entries(self):
        clean = json.loads(json.dumps(_long_result(8).to_dict()))
        expected = PseudocContext(clean).generate(0x1000)
        generated = PseudocContext(self.snapshot).generate(0x1000)
        for key in ("pseudoc", "machine_pseudoc", "pseudoc_truncated", "pseudoc_reconstruction"):
            self.assertEqual(generated[key], expected[key], key)
        self.assertIsNone(self.snapshot["functions"][-1])  # 不修改快照

    def test_mcp_generate_returns_a_tool_result_not_an_internal_error(self):
        server = self._server(self.snapshot)
        server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"protocolVersion": "2025-06-18"}})
        server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
        for arguments in ({"generate": True}, {}):
            with self.subTest(arguments=arguments):
                response = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                    "name": "get_pseudoc", "arguments": {"handle": self.handle, **arguments}}})
                self.assertIn("result", response)
                self.assertNotIn("error", response)
        generated = server.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "get_pseudoc", "arguments": {"handle": self.handle, "address": 0x1000, "generate": True}}})
        self.assertTrue(generated["result"]["structuredContent"]["generated"])

    def test_unexpected_build_failure_is_a_value_error(self):
        broken = {"kind": "elf", "metadata": {"architecture": "x86_64"},
                  "functions": [{"name": "odd", "start": 0x10, "cfg": "not-a-mapping"}]}
        with self.assertRaisesRegex(ValueError, "Pseudo-C context unavailable"):
            PseudocContext(broken).generate(0x10)


def _naming_result() -> AnalysisResult:
    """entry（第 1 个，流水线渲染）调用 sub_3000；filler 填满前 MAX_FUNCTIONS 个之后，
    sub_2000（调用 sub_3000）与 sub_3000 都在流水线渲染范围之外。"""
    functions = [function(instruction(0x100, "call", "0x3000", size=5, kind="call", target=0x3000),
                          instruction(0x105, "ret", kind="return"), name="entry")]
    functions += [function(instruction(0x200 + index * 16, "ret", kind="return"), name=f"filler_{index}")
                  for index in range(1, pipeline.MAX_FUNCTIONS + 2)]
    functions.append(function(instruction(0x2000, "mov", "edi", "5", size=5),
                              instruction(0x2005, "call", "0x3000", size=5, kind="call", target=0x3000),
                              instruction(0x200a, "add", "eax", "1", size=3),
                              instruction(0x200d, "ret", kind="return"), name="sub_2000"))
    functions.append(function(instruction(0x3000, "lea", "eax", "[rdi+7]", size=3),
                              instruction(0x3003, "ret", kind="return"), name="sub_3000"))
    return AnalysisResult("naming", "elf", "kkagent", "partial", metadata={"architecture": "x86_64"},
                          functions=functions)


class OffPipelineNamingTests(unittest.TestCase):
    def test_header_and_on_demand_call_sites_share_one_name(self):
        result = _naming_result()
        callee_index, caller_index = len(result.functions) - 1, len(result.functions) - 2
        self.assertGreaterEqual(caller_index, pipeline.MAX_FUNCTIONS)
        name = f"function_{callee_index + 1}"
        context = PseudocContext(result)
        callee = context.generate(0x3000)
        caller = context.generate(0x2000)
        self.assertIn(f" {name}(", callee["pseudoc"].splitlines()[1])  # 函数头
        self.assertIn(f"{name}(", caller["pseudoc"])  # 调用处使用同一个名字
        self.assertNotIn("sub_3000", caller["pseudoc"])
        self.assertIn(f" function_{caller_index + 1}(", caller["pseudoc"].splitlines()[1])
        # 先生成调用者、再生成被调函数，结果相同（与请求顺序无关）。
        fresh = PseudocContext(_naming_result())
        self.assertEqual(fresh.generate(0x2000)["pseudoc"], caller["pseudoc"])
        self.assertEqual(fresh.generate(0x3000)["pseudoc"], callee["pseudoc"])
        # 机器视图不使用签名摘要：函数头与调用处仍统一使用原始名字。
        self.assertIn("sub_3000(", callee["machine_pseudoc"])
        self.assertIn("sub_3000(", caller["machine_pseudoc"])
        # 不修改结果对象，也不改动共享上下文里的摘要。
        self.assertNotIn("pseudoc", result.functions[caller_index])
        self.assertNotIn("name", context._state.summaries.get("ram", {}).get(0x3000, {}))

    def test_failed_signature_recovery_keeps_the_shared_name(self):
        result = _naming_result()
        name = f"function_{len(result.functions)}"
        context = PseudocContext(result).prepare()
        with patch.object(pipeline, "_signature_summary", return_value=None):  # 签名恢复失败
            header = context.generate(0x3000)["pseudoc"].splitlines()[1]
        self.assertIn(f" {name}(", header)
        self.assertNotIn("recovered_function", header)

    def test_pipeline_rendered_text_is_unchanged(self):
        result = _naming_result()
        pipeline.populate_native_pseudoc(result)
        entry = result.functions[0]
        self.assertIn("sub_3000(", entry["pseudoc"])  # 流水线文本：范围之外的被调函数用原始名字
        context = PseudocContext(result)
        context.generate(0x2000)  # 先为范围之外的函数生成，不影响流水线渲染过的函数
        self.assertEqual(context.generate(entry)["pseudoc"], entry["pseudoc"])


class _Status:
    def __init__(self) -> None:
        self.value = ""

    def set(self, text: str) -> None:
        self.value = text

    def get(self) -> str:
        return self.value


class _FakeBrowser(_JobsMixin):
    """只含按需生成所需属性的浏览器替身（不需要 Tk）。"""

    def __init__(self, snapshot) -> None:
        self._closed = self._busy = False
        self._view = SimpleNamespace(_snapshot=snapshot)
        self._generation = 1
        self._messages = queue.Queue()
        self.status = _Status()
        self.pseudoc_max_instructions = 512


class GuiQueueTests(unittest.TestCase):
    def setUp(self):
        functions = [function(instruction(0x100 + index * 16, "mov", "eax", str(index), size=5),
                              instruction(0x105 + index * 16, "ret", kind="return"), name=f"routine_{index}")
                     for index in range(5)]
        self.snapshot = {"path": "q.elf", "kind": "elf", "metadata": {"architecture": "x86_64"},
                         "functions": functions}
        self.browser = _FakeBrowser(self.snapshot)
        self.release, self.entered = threading.Event(), threading.Event()
        self.order: list[int] = []
        test = self

        class SlowContext(PseudocContext):
            def generate(self, function, **kwargs):
                test.order.append(function["start"])
                test.entered.set()
                test.release.wait(20)
                return super().generate(function, **kwargs)

        patcher = patch("fangida.gui.PseudocContext", SlowContext)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.release.set)

    def _workers(self):
        return [thread for thread in threading.enumerate() if thread.name == "fangida-gui-pseudocode"]

    def _drain(self, count, timeout=20.0):
        messages = []
        for _ in range(count):
            generation, message = self.browser._messages.get(timeout=timeout)
            messages.append((generation, message))
        return messages

    def test_requests_are_queued_on_a_single_worker(self):
        browser, starts = self.browser, [0x100, 0x110, 0x120, 0x130]
        real_thread, created = threading.Thread, []

        def counting_thread(*args, **kwargs):
            created.append(kwargs.get("name"))
            return real_thread(*args, **kwargs)

        with patch("threading.Thread", side_effect=counting_thread):
            self.assertTrue(browser.request_pseudocode(starts[0], "first"))
            self.assertTrue(self.entered.wait(10))
            for start in starts[1:]:
                self.assertTrue(browser.request_pseudocode(start))
        self.assertEqual(created, ["fangida-gui-pseudocode"])  # 只开了一个工作线程
        self.assertEqual(len(self._workers()), 1)
        self.assertIn("已排队", browser.status.value)
        self.assertEqual(browser._pseudocode_jobs().pending, set(starts))
        self.release.set()
        messages = self._drain(len(starts))
        self.assertTrue(all(generation == 1 and message.error is None for generation, message in messages))
        # 后请求的先生成：第一个请求之后按 0x130、0x120、0x110 的顺序。
        self.assertEqual(self.order, [0x100, 0x130, 0x120, 0x110])
        self.assertEqual([message.start for _, message in messages], self.order)
        for thread in self._workers():
            thread.join(10)
        self.assertEqual(self._workers(), [])  # 队列空了线程即退出
        # Tk 线程登记结果后，新请求再开一个工作线程（同一时间仍只有一个）。
        jobs = browser._pseudocode_jobs()
        for _, message in messages:
            jobs.pending.discard(message.start)
        self.assertFalse(jobs.running)
        self.assertTrue(browser.request_pseudocode(0x140))
        self.assertEqual(self._drain(1)[0][1].start, 0x140)

    def test_new_result_cancels_queued_requests(self):
        browser = self.browser
        self.assertTrue(browser.request_pseudocode(0x100))
        self.assertTrue(self.entered.wait(10))
        self.assertTrue(browser.request_pseudocode(0x110))
        self.assertTrue(browser.request_pseudocode(0x120))
        old = browser._pseudocode_jobs()
        browser._generation += 1  # 打开了新结果
        fresh = browser._pseudocode_jobs()
        self.assertIsNot(fresh, old)
        self.assertTrue(old.cancelled)
        self.assertEqual(old.waiting, [])
        self.release.set()
        generation, message = self._drain(1)[0]
        self.assertEqual((generation, message.start), (1, 0x100))  # 正在生成的那一个照常完成
        for thread in self._workers():
            thread.join(10)
        self.assertEqual(self.order, [0x100])  # 排队的请求没有再生成
        self.assertTrue(self.browser._messages.empty())
        self.assertFalse(old.running)



class RealSampleTests(unittest.TestCase):
    """libtersafe.so（arm64 ELF）上审查给出的样例。"""
    result = None

    @classmethod
    def setUpClass(cls):
        if not LIBTERSAFE.is_file():
            raise unittest.SkipTest("缺少真实样本 libtersafe.so")
        from fangida.dispatcher import AnalysisService
        with AnalysisService(Settings(analyze_threads=2)) as service:
            cls.result = service.analyze(LIBTERSAFE, full_analysis=True)
        cls.index = {record.get("name"): position for position, record in enumerate(cls.result.functions)}

    def _position(self, name):
        self.assertIn(name, self.index)
        position = self.index[name]
        self.assertGreaterEqual(position, pipeline.MAX_FUNCTIONS)  # 都在流水线渲染范围之外
        return position

    def test_large_function_with_raised_limit_reports_machine_truncation(self):
        record = self.result.functions[self._position("fde_499d68")]
        last = max(row["addr"] for block in record["blocks"] for row in block["instructions"])
        generated = PseudocContext(self.result).generate(record, max_instructions=4096)
        self.assertNotIn(f"{last:#x}", generated["machine_pseudoc"])  # 机器文本只覆盖前一部分
        self.assertTrue(generated["pseudoc_truncated"])

    def test_off_pipeline_names_agree_between_header_and_call_sites(self):
        functions, context = self.result.functions, PseudocContext(self.result)
        callee, caller = self._position("sub_3428a0"), self._position("fde_342694")
        self.assertIn(f" function_{callee + 1}(", context.generate(functions[callee])["pseudoc"].splitlines()[1])
        text = context.generate(functions[caller])["pseudoc"]
        self.assertIn(f"function_{callee + 1}(", text)
        self.assertNotIn("sub_3428a0", text)
        # 范围之外的 PLT 桩：调用处经链接证据写出导入名，桩自身的函数头也用同一导入名。
        stub, user = self._position("sub_50e9b0"), self._position("fde_379268")
        self.assertIn(" __stack_chk_fail(", context.generate(functions[stub])["pseudoc"].splitlines()[1])
        self.assertIn("__stack_chk_fail(", context.generate(functions[user])["pseudoc"])
        self.assertEqual(context.builds, 1)


if __name__ == "__main__":
    unittest.main()
