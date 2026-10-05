"""伪代码视图：纯函数（高亮、函数头、跳转目标、查找、终端排版）与真实 Tk 代码视图。

纯函数测试不需要显示环境；真实 Tk 测试沿用 test_gui_workbench 的 withdraw
窗口夹具，没有显示时跳过。
"""
from __future__ import annotations

import gc
import io
import re
import unittest
from unittest.mock import patch

from fangida.api import AnalysisView
from fangida.gui import PSEUDOCODE_LIST_COLUMNS, TABLE_COLUMNS, _display
from fangida.gui_modules import pseudocode as P
from fangida.gui_modules.records import display_text, extra_tables
from fangida.models import AnalysisResult
from fangida.tui import browse, print_pseudocode


MAIN = 0x100000600
PUTS = 0x100000870
HELLO = 0x100000900
GOT = 0x100004000

READABLE = """/* 部分源码重建：示例 */
int32_t function_1(int64_t arg_1, char * arg_2) {
    uint64_t value_3;

    // 行注释 0x100000870
    if ((uint32_t)(arg_1) == 0x1234) {
        function_4("hello");
        goto block_7;
    }
    value_3 = 'a' + 4096 + 4294969456 + 65535;
    struct item * p = NULL;
    switch (arg_1) {
    default:
        break;
    }
block_7:
    return puts(0x100000900);
}"""

MACHINE = """// IR-derived pseudo-C
uint64_t main(/* ABI arguments symbolic */) {
  uint64_t x0 = symbolic_input("x0");
L_100000600: /* 0x100000600 */
  x0 = sub_100000870(/* symbolic args */);
  goto L_100000600;
}"""


def _function(**extra):
    record = {
        "name": "main", "start": MAIN, "pseudoc": READABLE, "machine_pseudoc": MACHINE,
        "pseudoc_producer": "fangida_native_pseudoc", "pseudoc_truncated": False,
        "pseudoc_reconstruction": {
            "parameters": [{"name": "arg_1", "type": "int64_t"}, {"name": "arg_2", "type": "char *"}],
            "return_type": "int32_t", "signature_complete": False,
            "calls": [{"address": MAIN + 8, "target": PUTS, "name": "function_4"},
                      {"address": MAIN + 16, "target": PUTS, "name": "function_4"},
                      {"address": MAIN + 24, "target": None, "name": "indirect_call", "kind": "tail_transfer"}],
            "unresolved": [{"kind": "call_signature"}, {"kind": "call_signature"},
                           {"kind": "control_flow_target", "transfer_kind": "indirect_jump"}],
            "residual_gotos": 1, "complete": False},
        "xrefs_out": [{"src": MAIN + 4, "dst": HELLO, "kind": "data"}],
    }
    record.update(extra)
    return record


def _context(functions=None):
    functions = functions if functions is not None else [_function(), {"name": "_puts", "start": PUTS}]
    return P.build_symbol_context(
        functions=functions, imports=[{"name": "printf", "address": 0x100000880}],
        strings=[{"value": "hello", "address": HELLO, "addresses": [HELLO]},
                 {"value": "dup", "addresses": [0x100000910, 0x100000920]}],
        sections=[{"name": "__text", "address": 0x100000000, "size": 0x1000},
                  {"name": "__got", "address": GOT, "size": 0x30}],
        pseudocode=[item for item in functions if item.get("pseudoc")])


def _tagged(code, tag):
    return [code[span.start:span.end] for span in P.highlight_spans(code) if span.tag == tag]


class HighlightTests(unittest.TestCase):
    def test_every_token_class_is_classified(self):
        code = READABLE
        self.assertIn("/* 部分源码重建：示例 */", _tagged(code, "comment"))
        self.assertIn("// 行注释 0x100000870", _tagged(code, "comment"))
        self.assertEqual(_tagged(code, "string"), ['"hello"', "'a'"])
        for keyword in ("if", "goto", "return", "switch", "default", "break", "struct"):
            self.assertIn(keyword, _tagged(code, "keyword"))
        for name in ("int32_t", "int64_t", "char", "uint64_t", "uint32_t", "item"):
            self.assertIn(name, _tagged(code, "type"))
        for number in ("0x1234", "4096", "4294969456", "65535", "NULL", "0x100000900"):
            self.assertIn(number, _tagged(code, "number"))
        self.assertEqual(_tagged(code, "function"), ["function_1", "function_4", "puts"])
        # 定义处和 goto 目标都是标签；"default:" 是关键字而不是标签。
        self.assertEqual(_tagged(code, "label"), ["block_7", "block_7"])
        self.assertNotIn("value_3", sum((_tagged(code, tag) for tag in P.HIGHLIGHT_TAGS), []))

    def test_spans_are_sorted_non_overlapping_and_cached(self):
        spans = P.highlight_spans(READABLE)
        self.assertEqual(list(spans), sorted(spans, key=lambda span: span.start))
        for previous, current in zip(spans, spans[1:]):
            self.assertLessEqual(previous.end, current.start)
        self.assertIs(P.analyze_code(READABLE), P.analyze_code(READABLE))
        grouped = P.group_spans(spans)
        self.assertEqual(sum(map(len, grouped.values())), len(spans))
        self.assertTrue(set(grouped) <= set(P.HIGHLIGHT_TAGS))

    def test_unterminated_literals_and_comments_do_not_swallow_following_lines(self):
        code = 'x = "open\ny = 1; /* tail'
        self.assertEqual(_tagged(code, "string"), ['"open'])
        self.assertEqual(_tagged(code, "number"), ["1"])
        self.assertEqual(_tagged(code, "comment"), ["/* tail"])
        self.assertEqual(P.highlight_spans(""), ())

    def test_tk_index_conversion_round_trips(self):
        model = P.analyze_code("ab\ncde\n\nf")
        self.assertEqual(model.line_starts, (0, 3, 7, 8))
        for offset, index in ((0, "1.0"), (2, "1.2"), (3, "2.0"), (5, "2.2"), (7, "3.0"), (8, "4.0"), (9, "4.1")):
            self.assertEqual(P.text_index(model.line_starts, offset), index)
            line, column = map(int, index.split("."))
            self.assertEqual(P.index_offset(model.line_starts, line, column), offset)


class JumpTargetTests(unittest.TestCase):
    def test_targets_with_context(self):
        function = _function()
        targets = P.jump_targets(READABLE, function, _context())
        by_text = {}
        for item in targets:
            by_text.setdefault(item.text, []).append(item)
        # 调用证据把 function_4 映射到桩函数；Mach-O 下划线前缀的符号也可用。
        self.assertEqual({item.address for item in by_text["function_4"]}, {PUTS})
        self.assertEqual(by_text["function_4"][0].name, "_puts")
        self.assertEqual(by_text["puts"][0].address, PUTS)
        self.assertEqual(by_text["function_1"][0].address, MAIN)
        self.assertEqual(by_text['"hello"'][0].kind, "string")
        self.assertEqual(by_text['"hello"'][0].address, HELLO)
        self.assertEqual(by_text["0x100000900"][0].address, HELLO)
        self.assertEqual(by_text["0x100000870"][0].address, PUTS)  # 注释中的地址
        self.assertEqual(by_text["4294969456"][0].address, PUTS)   # 恰为函数入口的十进制常量
        self.assertNotIn("4096", by_text)   # 小十进制数不是地址
        self.assertNotIn("65535", by_text)
        self.assertNotIn("0x1234", by_text)  # 不在任何区段内
        label = by_text["block_7"]
        self.assertEqual([item.kind for item in label], ["label"])  # 只有 goto 处可跳转
        self.assertEqual(READABLE[label[0].label_offset:label[0].label_offset + 7], "block_7")
        self.assertTrue(READABLE[:label[0].label_offset].endswith("\n"))
        for item in targets:
            self.assertEqual(READABLE[item.start:item.end], item.text)

    def test_machine_view_labels_and_address_comments(self):
        targets = P.jump_targets(MACHINE, _function(), _context())
        kinds = [(item.kind, item.text) for item in targets]
        self.assertIn(("address", "0x100000600"), kinds)
        # 名称带地址后缀且地址落在已知函数上：按地址跳转。
        self.assertIn(("address", "sub_100000870"), kinds)
        goto = [item for item in targets if item.kind == "label"]
        self.assertEqual(len(goto), 1)
        self.assertEqual(MACHINE[goto[0].label_offset:].split(":")[0], "L_100000600")
        self.assertNotIn("x0", [item.text for item in targets])

    def test_without_context_only_large_hex_and_local_evidence(self):
        code = "f(0x10); g(0x401000); h(123456789); goto done;\ndone:\n  return;"
        targets = P.jump_targets(code)
        self.assertEqual([(item.kind, item.text) for item in targets],
                         [("address", "0x401000"), ("label", "done")])

    def test_target_lookup_by_offset(self):
        targets = P.jump_targets(READABLE, _function(), _context())
        first = targets[0]
        self.assertIs(P.target_at(targets, first.start), first)
        self.assertIs(P.target_at(targets, first.end - 1), first)
        self.assertIs(P.target_at(targets, first.end), first)  # 光标在词尾
        self.assertIsNone(P.target_at(targets, 0))
        self.assertIsNone(P.target_at((), 5))

    def test_identifier_occurrences_and_find(self):
        offset = READABLE.index("value_3 =")
        self.assertEqual(P.identifier_at(READABLE, offset + 2)[2], "value_3")
        self.assertEqual(len(P.occurrence_spans(READABLE, "value_3")), 2)
        self.assertEqual(P.occurrence_spans(READABLE, "value"), ())  # 整词匹配
        self.assertEqual(P.occurrence_spans(READABLE, "a+b"), ())
        start = P.find_in_code(READABLE, "BLOCK_7")
        self.assertEqual(READABLE[start[0]:start[1]], "block_7")
        second = P.find_in_code(READABLE, "block_7", start[1])
        self.assertGreater(second[0], start[0])
        self.assertIsNone(P.find_in_code(READABLE, "block_7", len(READABLE)))
        self.assertEqual(P.find_in_code(READABLE, "block_7", len(READABLE), wrap=True), start)
        self.assertIsNone(P.find_in_code(READABLE, ""))

    def test_c_unescape(self):
        self.assertEqual(P.c_unescape(r'"total=%d %s\n"'), "total=%d %s\n")
        self.assertEqual(P.c_unescape(r'"a\x41\101\0\"q\\"'), 'aAA\0"q\\')
        self.assertEqual(P.c_unescape('"unterminated'), "unterminated")


class HeaderTests(unittest.TestCase):
    def test_header_summarises_signature_calls_strings_and_status(self):
        header = P.build_header(_function(), context=_context())
        self.assertEqual((header.name, header.address, header.code_name), ("main", MAIN, "function_1"))
        self.assertEqual(header.signature, "int32_t function_1(int64_t arg_1, char * arg_2)")
        self.assertEqual([(call.name, call.target, call.resolved, call.count, call.kind) for call in header.calls],
                         [("function_4", PUTS, "_puts", 2, "call"),
                          ("indirect_call", None, "", 1, "tail_transfer")])
        # 字符常量 'a' 不是字符串引用；"hello" 同时来自字面量和数据 xref，只列一次。
        self.assertEqual([item.value for item in header.strings], ["hello"])
        self.assertEqual(header.strings[0].address, HELLO)
        self.assertEqual(header.status, "不完整")
        self.assertIn("2 处调用的参数未能确定", header.reasons)
        self.assertIn("1 个未解析的控制流目标（indirect_jump）", header.reasons)
        self.assertIn("1 个标签未能结构化，保留 goto", header.reasons)
        self.assertTrue(header.machine_available)
        self.assertEqual(header.line_count, READABLE.count("\n") + 1)

        formatted = P.format_header(header)
        lines = formatted.text.splitlines()
        self.assertTrue(lines[0].startswith("main  @ 0x100000600  ·  可读视图  ·  fangida_native_pseudoc"))
        self.assertIn("伪 C 中名为 function_1", lines[0])
        self.assertEqual(lines[1], "签名：int32_t function_1(int64_t arg_1, char * arg_2)  （按 ABI 推断）")
        self.assertEqual(lines[2], "调用：function_4→_puts @ 0x100000870 ×2，indirect_call（间接尾跳转）")
        self.assertEqual(lines[3], '字符串："hello"')
        self.assertTrue(lines[4].startswith("状态：不完整 —— "))
        self.assertTrue(lines[5].startswith("说明：签名按 ABI 默认推断"))
        for link in formatted.links:
            self.assertEqual(formatted.text[link.start:link.end], link.text)
        self.assertEqual([(link.kind, link.text, link.address) for link in formatted.links],
                         [("address", "0x100000600", MAIN), ("function", "function_4", PUTS),
                          ("string", '"hello"', HELLO)])
        tags = {span.tag for span in formatted.spans}
        self.assertTrue({"header_name", "header_label", "header_warning", "header_note"} <= tags)

    def test_machine_header_and_fallbacks(self):
        header = P.build_header(_function(), style="machine", context=_context())
        self.assertEqual(header.style, "machine")
        # 机器视图中的 symbolic_input("x0") 不是被引用的字符串。
        self.assertNotIn("x0", [item.value for item in header.strings])
        plain = {"name": "sub_401000", "start": 0x401000,
                 "pseudoc": "void sub_401000(int a) {\n    return;\n}",
                 "xrefs_out": [{"src": 0x401004, "dst": PUTS, "kind": "call"}]}
        header = P.build_header(plain, style="machine", context=_context())
        self.assertEqual(header.style, "readable")  # 没有 machine_pseudoc 时回退
        self.assertFalse(header.machine_available)
        self.assertEqual(header.signature, "void sub_401000(int a)")
        self.assertEqual([(call.name, call.target) for call in header.calls], [("_puts", PUTS)])
        self.assertEqual(header.status, "完整")
        self.assertEqual(header.reasons, ())
        text = P.header_text(header)
        self.assertIn("状态：完整", text)
        self.assertIn("字符串：无", text)
        # 生成器辅助调用的字符串实参（指令名/寄存器名）不是程序字符串。
        helpers = {"name": "g", "start": 0x401100, "pseudoc": (
            'void g(void) {\n    unresolved_operation("push");\n    symbolic_input( "x0" );\n'
            '    puts("hello");\n}')}
        self.assertEqual([(item.value, item.address) for item in
                          P.build_header(helpers, context=_context()).strings], [("hello", HELLO)])

    def test_truncation_and_status_flags(self):
        self.assertEqual(P.status_flags({"pseudoc": "void f(void) {}"}), "完整")
        self.assertEqual(P.status_flags({"pseudoc": "x", "pseudoc_truncated": True}), "截断")
        budget = {"pseudoc": "/* Reconstruction text budget exhausted. */", "pseudoc_truncated": True,
                  "pseudoc_reconstruction": {"unresolved": [{"kind": "control_flow_target"}]}}
        self.assertEqual(P.status_flags(budget), "截断")
        self.assertIn("文本或指令预算用尽，输出被截断", P.build_header(budget).reasons)
        frontier = {"pseudoc": "x", "pseudoc_truncated": True, "pseudoc_reconstruction": {
            "unresolved": [{"kind": "control_flow_target", "transfer_kind": "direct_jump"}] * 2}}
        self.assertEqual(P.status_flags(frontier), "不完整")
        self.assertIn("2 个未解析的控制流目标（direct_jump×2）", P.build_header(frontier).reasons)
        gotos = {"pseudoc": "x", "pseudoc_reconstruction": {"residual_gotos": 2, "complete": False}}
        self.assertEqual(P.status_flags(gotos), "含 goto")
        regions = {"pseudoc": "x", "pseudoc_reconstruction": {"machine_regions": [{"name": "r"}]}}
        self.assertEqual(P.status_flags(regions), "不完整")
        operations = {"pseudoc": "x", "pseudoc_reconstruction": {"unresolved": [
            {"kind": "operation", "mnemonic": "svc"}, {"kind": "future_kind"}]}}
        reasons = P.build_header(operations).reasons
        self.assertIn("1 条指令未能翻译成 C（svc）", reasons)
        self.assertIn("其它未解析证据：future_kind×1", reasons)
        broken = {"pseudoc": "x", "pseudoc_reconstruction": {"unresolved": 5, "calls": "bad",
                                                             "parameters": None}, "xrefs_out": 3}
        self.assertEqual(P.build_header(broken, context=_context()).calls, ())

    def test_empty_messages(self):
        message = P.no_pseudocode_message({"pseudoc_budget_exhausted": True}, "elf")
        self.assertIn("当前结果没有伪代码", message)
        self.assertIn("预算已用尽", message)
        self.assertIn("--full", message)
        self.assertIn("不会隐式重新分析", message)
        self.assertIn("APK/JAR", P.no_pseudocode_message({}, "apk"))
        self.assertIn("共 3 个函数有伪代码", P.placeholder_message(3))
        self.assertIn("Tab/F5", P.placeholder_message(3))

    def test_palettes_cover_every_tag(self):
        for name in P.CODE_PALETTES:
            palette = P.code_palette(name)
            for tag in P.HIGHLIGHT_TAGS + ("background", "foreground", "find", "occurrence"):
                self.assertRegex(palette[tag], r"^#[0-9a-f]{6}$")
        self.assertEqual(P.code_palette("missing"), P.code_palette("dark"))
        P.code_palette()["keyword"] = "#000000"
        self.assertNotEqual(P.code_palette()["keyword"], "#000000")


class ListingTests(unittest.TestCase):
    def test_terminal_listing_keeps_code_verbatim(self):
        listing = P.render_listing(_function(), context=_context())
        head, body = listing.split("-" * 78 + "\n", 1)
        self.assertTrue(head.startswith("=" * 78 + "\n// main  @ 0x100000600"))
        self.assertTrue(all(line.startswith("// ") for line in head.splitlines()[1:]))
        self.assertEqual(body, READABLE + "\n")
        self.assertNotIn("\x1b[", listing)
        colored = P.render_listing(_function(), context=_context(), color=True)
        self.assertIn("\x1b[34mif\x1b[0m", colored)
        self.assertEqual(re.sub(r"\x1b\[[0-9;]*m", "", colored), listing)
        machine = P.render_listing(_function(), style="machine")
        self.assertIn("机器视图", machine)
        self.assertTrue(machine.endswith(MACHINE + "\n"))

    def test_function_selection(self):
        other = {"name": "helper", "start": 0x100000700, "pseudoc": "void helper(void) {}",
                 "blocks": [{"start": 0x100000700, "instructions": [{"addr": 0x100000700, "size": 4},
                                                                     {"addr": 0x100000704, "size": 4}]}]}
        functions = [_function(), other, {"name": "no_code", "start": 0x1}]
        self.assertEqual([item["name"] for item in P.select_functions(functions)], ["main", "helper"])
        self.assertEqual(P.select_functions(functions, "helper"), [other])
        self.assertEqual(P.select_functions(functions, "function_1")[0]["name"], "main")
        self.assertEqual(P.select_functions(functions, "0x100000700"), [other])
        self.assertEqual(P.select_functions(functions, "0x100000706"), [other])
        self.assertEqual(P.select_functions(functions, "HELP"), [other])
        self.assertEqual(P.select_functions(functions, "0x5"), [])


class RecordAndTableTests(unittest.TestCase):
    def test_pseudocode_rows_keep_old_fields_and_add_view_fields(self):
        function = _function(blocks=[{"start": MAIN}], microcode_complete=False)
        rows = extra_tables({"functions": [function, {"name": "plain"}], "metadata": {}})["Pseudocode"]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertIs(row["pseudoc"], function["pseudoc"])
        self.assertIs(row["machine_pseudoc"], function["machine_pseudoc"])
        self.assertIs(row["pseudoc_reconstruction"], function["pseudoc_reconstruction"])
        self.assertIs(row["xrefs_out"], function["xrefs_out"])
        self.assertEqual(row["pseudoc_status"], "不完整")
        self.assertNotIn("blocks", row)
        self.assertIs(display_text("Pseudocode", row), function["pseudoc"])

    def test_list_columns_are_additive(self):
        keys = [column[0] for column in TABLE_COLUMNS["Pseudocode"]]
        self.assertEqual(keys[:4], ["name", "start", "pseudoc_producer", "pseudoc"])
        self.assertTrue(set(PSEUDOCODE_LIST_COLUMNS) <= set(keys))
        self.assertEqual(_display(MAIN, "start"), "0x100000600")


def _tui_view(functions):
    return AnalysisView(AnalysisResult(
        "sample", "macho", "kkagent", "partial", functions=functions,
        strings=[{"value": "hello", "address": HELLO}],
        metadata={"sections": [{"name": "__text", "address": 0x100000000, "size": 0x1000}]}))


class TuiTests(unittest.TestCase):
    def _run(self, view, commands):
        output = io.StringIO()
        with patch("builtins.input", side_effect=commands + ["quit"]), \
             patch.object(AnalysisView, "snapshot", side_effect=AssertionError("不应复制快照")):
            browse(view, output)
        return output.getvalue()

    def test_pseudocode_command_prints_headers_and_full_code(self):
        view = _tui_view([_function(), {"name": "helper", "start": 0x100000700,
                                        "pseudoc": "void helper(void) {\n}"}])
        baseline = AnalysisView.snapshot(view)
        text = self._run(view, ["pseudocode"])
        self.assertIn("共 2 个函数有伪代码", text)
        self.assertIn("// main  @ 0x100000600", text)
        self.assertIn("// 签名：int32_t function_1(int64_t arg_1, char * arg_2)", text)
        self.assertIn("// 状态：不完整", text)
        self.assertIn(READABLE, text)
        self.assertIn("// helper  @ 0x100000700", text)
        self.assertEqual(text.count("=" * 78), 2)
        self.assertEqual(AnalysisView.snapshot(view), baseline)

    def test_selection_machine_view_and_legacy_json(self):
        view = _tui_view([_function()])
        text = self._run(view, ["code main machine"])
        self.assertIn("机器视图", text)
        self.assertIn(MACHINE, text)
        legacy = self._run(view, ["pseudoc"])
        self.assertIn('"pseudoc": ' + __import__("json").dumps(READABLE), legacy)
        missing = self._run(view, ["pseudocode nothing"])
        self.assertIn("没有名称或地址匹配“nothing”的伪代码函数", missing)
        self.assertIn("0x100000600  main  [不完整]", missing)

    def test_no_pseudocode_message(self):
        text = self._run(_tui_view([{"name": "main", "start": MAIN}]), ["decompile"])
        self.assertIn("当前结果没有伪代码", text)
        output = io.StringIO()
        snapshot = {"functions": [_function()], "metadata": {}, "stats": {}}
        self.assertEqual(print_pseudocode(snapshot, ["main"], output, color=True), 1)
        self.assertIn("\x1b[", output.getvalue())


# ---------------------------------------------------------------------------
# 真实 Tk 代码视图
# ---------------------------------------------------------------------------

from tests import test_gui_workbench as fixture  # noqa: E402

ENTRY_CODE = ("int32_t entry(void) {\n    target(1);\n    goto block_2;\n"
              "    value = 0;\nblock_2:\n    return 0;\n}\n")
TARGET_CODE = "void target(int64_t arg_1) {\n    return;\n}\n"


class PseudocodeViewTkTests(unittest.TestCase):
    _close = fixture.GuiWorkbenchIntegrationTests._close
    _pump = fixture.GuiWorkbenchIntegrationTests._pump
    _load = fixture.GuiWorkbenchIntegrationTests._load
    _navigate = fixture.GuiWorkbenchIntegrationTests._navigate

    def setUp(self):
        # 先登记的清理最后执行：窗口关闭后在主线程回收 Tk 变量，避免之后
        # 由其它测试的工作线程触发垃圾回收时在错误线程析构 Tcl 对象。
        self.addCleanup(self._collect_tk_objects)
        fixture.GuiWorkbenchIntegrationTests.setUp(self)

    def _collect_tk_objects(self):
        for name in ("browser", "root"):
            self.__dict__.pop(name, None)
        gc.collect()

    def _load_code(self, *, with_code=True):
        snapshot = fixture._view().snapshot()
        if with_code:
            entry, target = snapshot["functions"]
            entry.update(pseudoc=ENTRY_CODE, machine_pseudoc="// machine\nL_1000:\n  goto L_1000;\n",
                         pseudoc_reconstruction={"calls": [{"name": "target", "target": fixture.TARGET}],
                                                 "return_type": "int32_t", "parameters": []})
            target.update(pseudoc=TARGET_CODE, pseudoc_truncated=True)
        self._load(AnalysisView.from_snapshot(snapshot))
        return self.browser.pseudocode_view

    def _open_entry(self):
        view = self._load_code()
        self.browser.workbench.show_pseudocode()
        tree = self.browser._tables["Pseudocode"]
        self._pump(lambda: tree.selection() == ("0",) and view.row is not None)
        return view, tree

    def test_code_view_layout_header_and_highlight(self):
        view, tree = self._open_entry()
        browser = self.browser
        self.assertIs(browser._details["Pseudocode"], view.code)
        self.assertEqual(view.code.get("1.0", "end-1c"), ENTRY_CODE)
        self.assertEqual(tuple(tree["displaycolumns"]), PSEUDOCODE_LIST_COLUMNS)
        self.assertEqual(tree.item("0", "values")[1], f"{fixture.BASE:#x}")
        self.assertEqual(tree.item("1", "values")[4], "截断")
        header = view.header.get("1.0", "end-1c")
        self.assertTrue(header.startswith(f"entry  @ {fixture.BASE:#x}"))
        self.assertIn("签名：int32_t entry(void)", header)
        self.assertIn("调用：target", header)
        ranges = view.code.tag_ranges("keyword")
        self.assertIn("goto", [view.code.get(ranges[i], ranges[i + 1]) for i in range(0, len(ranges), 2)])
        self.assertEqual(str(view.code.cget("state")), "disabled")
        self.assertEqual(str(view.machine_button.cget("state")), "normal")

    def test_double_click_target_opens_callee_and_escape_returns(self):
        view, tree = self._open_entry()
        workbench = self.browser.workbench
        target = next(item for item in view._targets if item.text == "target")
        self.assertEqual(target.address, fixture.TARGET)
        self.assertTrue(view.activate(target))
        self._pump(lambda: tree.selection() == ("1",))
        self.assertEqual(view.code.get("1.0", "end-1c"), TARGET_CODE)
        self.assertEqual(workbench.current.address, fixture.TARGET)
        self.assertIn("截断", view.info.get())
        workbench.back()
        self._pump(lambda: tree.selection() == ("0",))
        self.assertEqual(self.browser.notebook.select(), str(self.browser._tabs["Pseudocode"]))
        self.assertEqual(view.code.get("1.0", "end-1c"), ENTRY_CODE)
        # Shift+双击（disassembly=True）回到反汇编行。
        view.activate(target, disassembly=True)
        expected = str(fixture.TARGET_INDEX)
        self._pump(lambda: self.browser._tables["Disassembly"].selection() == (expected,))

    def test_label_jump_follow_and_xref_operand(self):
        view, tree = self._open_entry()
        label = next(item for item in view._targets if item.kind == "label")
        view.activate(label)
        self.assertEqual(view.code.get("insert linestart", "insert lineend"), "block_2:")
        view.code.mark_set("insert", "2.6")  # "    target(1);" 中的 target
        with patch.object(type(view), "has_focus", return_value=True):
            self.assertEqual(view.target_at_insert().text, "target")
            with patch.object(self.browser.workbench, "_choose_references") as choose:
                self.browser.workbench.show_xrefs("incoming", operand=True)
            self.assertEqual(choose.call_args[0][1].address, fixture.TARGET)
            self.browser.workbench.follow()
        self._pump(lambda: tree.selection() == ("1",))

    def test_find_in_code_and_across_functions(self):
        view, tree = self._open_entry()
        workbench = self.browser.workbench
        with patch("tkinter.simpledialog.askstring", return_value="RETURN"):
            workbench.find_dialog()
        self.assertEqual(workbench._find_table, "Pseudocode")
        self.assertEqual(view.code.get("sel.first", "sel.last"), "return")
        self.assertEqual(view.code.index("insert"), "6.4")
        workbench.find_next()  # 当前函数没有更多匹配 → 下一个函数
        self._pump(lambda: tree.selection() == ("1",) and view.code.tag_ranges("find"))
        self.assertEqual(view.code.get("find.first", "find.last"), "return")
        self.assertIn("找到", self.browser.status.get())

    def test_mode_switch_occurrences_and_no_pseudocode_message(self):
        view, _tree = self._open_entry()
        view.mode.set("machine")
        view._mode_changed()
        self.assertTrue(view.code.get("1.0", "end-1c").startswith("// machine"))
        self.assertIn("机器视图", view.header.get("1.0", "end-1c"))
        view.mode.set("readable")
        view._mode_changed()
        view.code.mark_set("insert", "1.10")  # entry
        self.assertEqual(view.highlight_occurrences(), 1)
        self._load_code(with_code=False)
        self.assertIn("当前结果没有伪代码", view.header.get("1.0", "end-1c"))
        self.assertEqual(view.code.get("1.0", "end-1c"), "")


if __name__ == "__main__":
    unittest.main()
