"""伪 C 流水线去重渲染回归：复用必须与逐次重新渲染/提升的结果逐字节一致。

覆盖点：
- 每个函数在流水线内只做一次“全部行”渲染（签名恢复、generate 首次渲染、截断后的
  微码重提升共用这一次），文本超预算时的减半渲染照旧进行；
- 启用与禁用渲染备忘录两种路径的全部输出（函数字段、告警、统计、元数据、进度事件）
  逐字节相同，包括调用符号名、截断/frontier、减半、已有伪 C、非整数入口、预算耗尽；
- 备忘录只在一次 populate_native_pseudoc 调用内有效，异常退出也会恢复；
- 注册了第三方语义处理器时不复用；
- _memo_lift 与 lift_function 返回值逐字段一致，非法参数不改变原有错误。
"""
from __future__ import annotations

import contextlib
import copy
import json
import unittest
from unittest.mock import patch

from fangida.models import AnalysisResult
from fangida.plugins.pseudoc import generate_pseudoc, native, pipeline
from fangida.plugins.pseudoc.microcode import lift_function
from fangida.plugins.pseudoc.microcode.registry import DEFAULT_LIFTERS
from fangida.plugins.pseudoc.reconstruct import recover_signature
from tests.test_pseudoc import function, instruction


def _x86_body(base: int, callee: int | None) -> list[dict]:
    """一个带比较、条件跳转、回边循环与（可选）直接调用的 x86_64 函数体。"""
    rows = [
        instruction(base, "push", "rbp"),
        instruction(base + 1, "mov", "rbp", "rsp", size=3),
        instruction(base + 4, "mov", "eax", "edi", size=2),
        instruction(base + 6, "cmp", "eax", "10", size=3),
        instruction(base + 9, "jge", hex(base + 0x20), size=2, kind="jump", target=base + 0x20, conditional=True),
        instruction(base + 11, "add", "eax", "1", size=3),
        instruction(base + 14, "cmp", "eax", "esi", size=2),
        instruction(base + 16, "jl", hex(base + 6), size=2, kind="jump", target=base + 6, conditional=True),
    ]
    if callee is not None:
        rows.append(instruction(base + 18, "call", hex(callee), size=5, kind="call", target=callee))
    rows += [
        instruction(base + 0x20, "pop", "rbp"),
        instruction(base + 0x21, "ret", kind="return"),
    ]
    return rows


def _x86_result(count: int = 6) -> AnalysisResult:
    functions = []
    for index in range(count):
        base = 0x1000 + index * 0x100
        callee = 0x1000 + ((index + 1) % count) * 0x100 if index % 2 == 0 else None
        functions.append(function(*_x86_body(base, callee), name=f"routine_{index}"))
    # 不完整 CFG：generate 结果被标为截断，流水线必须给出独立、完整预算的微码。
    functions[1]["cfg"] = {"complete": False, "frontier": [{"reason": "indirect */ target", "address": 0x1111}]}
    # 函数自带的符号表覆盖同名全局名称。
    functions[2]["pseudoc_symbols"] = {0x1300: "declared_callee"}
    # 已有外部伪 C 但缺少微码：只补微码，不重新生成文本。
    functions[3].update(pseudoc="int external() {}", pseudoc_producer="ghidra")
    # 非整数入口：不参与签名恢复与预渲染，但仍会被第二轮处理。
    functions[4]["start"] = None
    return AnalysisResult("sample", "elf", "kkagent", "partial", metadata={"architecture": "x86_64"},
                          functions=functions)


def _arm64_result() -> AnalysisResult:
    rows = [
        instruction(0x100, "cmp", "w0", "#3", size=4),
        instruction(0x104, "b.ne", "#0x110", size=4, kind="jump", target=0x110, conditional=True),
        instruction(0x108, "bl", "#0x200", size=4, kind="call", target=0x200),
        instruction(0x10c, "cbz", "x0", "#0x100", size=4, kind="jump", target=0x100, conditional=True),
        instruction(0x110, "ret", size=4, kind="return"),
    ]
    callee = [instruction(0x200, "mov", "w0", "#42", size=4), instruction(0x204, "ret", size=4, kind="return")]
    return AnalysisResult("arm", "macho", "kkagent", "partial", metadata={"architecture": "arm64"},
                          functions=[function(*rows, name="caller"), function(*callee, name="answer")])


def _observable(result: AnalysisResult, events: list[dict]) -> str:
    return json.dumps({"functions": result.functions, "warnings": result.warnings, "stats": result.stats,
                       "metadata": result.metadata, "events": events}, sort_keys=True, default=repr)


class _RenderCounter:
    """统计 _Renderer.render 调用次数与每次渲染的行数（不改变行为）。"""

    def __init__(self) -> None:
        self.rows: list[int] = []
        self._original = native._Renderer.render

    def __enter__(self) -> _RenderCounter:
        counter = self

        def render(renderer, truncated):
            counter.rows.append(len(renderer.rows))
            return counter._original(renderer, truncated)

        self._patch = patch.object(native._Renderer, "render", render)
        self._patch.__enter__()
        return self

    def __exit__(self, *exc) -> None:
        self._patch.__exit__(*exc)


def _run(result: AnalysisResult, *, memo: bool, **patches) -> tuple[str, list[int]]:
    result = copy.deepcopy(result)
    events: list[dict] = []
    with contextlib.ExitStack() as stack:
        if not memo:
            # 禁用备忘录即回到逐次渲染/重新提升的原始路径，作为逐字节对照基线。
            stack.enter_context(patch.object(native, "_render_scope", contextlib.nullcontext))
        for name, value in patches.items():
            stack.enter_context(patch.object(pipeline, name, value))
        counter = stack.enter_context(_RenderCounter())
        pipeline.populate_native_pseudoc(result, on_progress=events.append)
    return _observable(result, events), counter.rows


class RenderReuseEquivalenceTests(unittest.TestCase):
    def assert_equivalent(self, result: AnalysisResult, **patches) -> tuple[list[int], list[int]]:
        reused, reused_rows = _run(result, memo=True, **patches)
        baseline, baseline_rows = _run(result, memo=False, **patches)
        self.assertEqual(reused, baseline)
        self.assertLessEqual(len(reused_rows), len(baseline_rows))
        return reused_rows, baseline_rows

    def test_x86_outputs_identical_and_each_function_rendered_once(self):
        result = _x86_result()
        reused_rows, baseline_rows = self.assert_equivalent(result)
        # 6 个函数：基线为签名恢复 5 次（入口非整数者跳过）+ generate 5 次 + 截断重提升；
        # 复用后每个函数只有一次完整渲染（已有伪 C 的函数也只做一次，用于微码）。
        self.assertEqual(len(reused_rows), 6)
        self.assertGreater(len(baseline_rows), len(reused_rows))
        rendered = json.loads(_run(result, memo=True)[0])["functions"]
        # 机器伪 C 的调用名来自快照符号：第一个函数调用 routine_1，第三个函数自带符号覆盖全局名。
        self.assertIn("routine_1(", rendered[0]["machine_pseudoc"])
        self.assertIn("declared_callee(", rendered[2]["machine_pseudoc"])
        self.assertTrue(rendered[1]["pseudoc_truncated"])
        self.assertTrue(rendered[1]["microcode"])
        self.assertEqual(rendered[3]["pseudoc"], "int external() {}")
        self.assertTrue(rendered[3]["microcode"])

    def test_arm64_outputs_identical(self):
        self.assert_equivalent(_arm64_result())

    def test_halving_and_budget_exhaustion_identical(self):
        # 很小的总字符预算迫使文本减半渲染并最终耗尽预算；减半渲染不得被跳过或复用错。
        reused_rows, _ = self.assert_equivalent(_x86_result(), MAX_TOTAL_CHARS=1200)
        self.assertTrue(any(rows < 11 for rows in reused_rows))

    def test_functions_beyond_signature_window_identical(self):
        # 签名恢复只看前 MAX_FUNCTIONS 个；第二轮可能处理之后未预渲染的函数（未命中路径）。
        result = _x86_result(8)
        result.functions[0]["blocks"] = []
        result.functions[0]["cfg"] = {"complete": True, "frontier": []}
        self.assert_equivalent(result, MAX_FUNCTIONS=3)

    def test_truncated_generate_output_reuses_full_render_microcode(self):
        result = _x86_result()
        with patch("fangida.plugins.pseudoc.microcode.lift_function",
                   side_effect=AssertionError("同一快照不应再次提升")):
            reused, _ = _run(result, memo=True)
        baseline, _ = _run(result, memo=False)
        self.assertEqual(reused, baseline)

    def test_empty_and_unsupported_results_identical(self):
        empty = AnalysisResult("empty", "macho", "kkagent", "partial", metadata={"architecture": "x86_64"})
        self.assertEqual(_run(empty, memo=True), _run(empty, memo=False))
        self.assertEqual(json.loads(_run(empty, memo=True)[0])["stats"]["pseudoc_functions"], 0)
        other = AnalysisResult("dex", "apk", "kkagent", "partial", metadata={"architecture": "dex"},
                               functions=[function(instruction(0, "ret", kind="return"))])
        self.assertEqual(_run(other, memo=True), _run(other, memo=False))

    def test_third_party_lifter_disables_reuse(self):
        names = DEFAULT_LIFTERS.names() + ("third_party_fixture",)
        with patch.object(DEFAULT_LIFTERS, "names", return_value=names):
            reused, reused_rows = _run(_x86_result(), memo=True)
        baseline, baseline_rows = _run(_x86_result(), memo=False)
        self.assertEqual(reused, baseline)
        self.assertEqual(len(reused_rows), len(baseline_rows) + 5)  # 预渲染仍执行但从不命中


class RenderMemoScopeTests(unittest.TestCase):
    def test_memo_is_scoped_to_one_call_even_on_error(self):
        self.assertIsNone(native._ACTIVE_MEMO.get())
        result = _x86_result()
        pipeline.populate_native_pseudoc(result)
        self.assertIsNone(native._ACTIVE_MEMO.get())

        def fail(event):
            raise RuntimeError("progress sink failure")

        with self.assertRaises(RuntimeError):
            pipeline.populate_native_pseudoc(_x86_result(), on_progress=fail)
        self.assertIsNone(native._ACTIVE_MEMO.get())
        # 作用域外调用公共 API 时总是重新渲染。
        with _RenderCounter() as counter:
            generate_pseudoc(result.functions[0], "x86_64")
            generate_pseudoc(result.functions[0], "x86_64")
            recover_signature(result.functions[0], "x86_64")
        self.assertEqual(len(counter.rows), 3)

    def test_nested_scopes_restore_outer_memo(self):
        with native._render_scope() as outer:
            with native._render_scope() as inner:
                self.assertIs(native._ACTIVE_MEMO.get(), inner)
            self.assertIs(native._ACTIVE_MEMO.get(), outer)
        self.assertIsNone(native._ACTIVE_MEMO.get())


class MemoLiftContractTests(unittest.TestCase):
    def dumps(self, value) -> str:
        return json.dumps(value, sort_keys=True, default=repr)

    def test_memo_lift_matches_lift_function_for_truncation_flags(self):
        rows = _x86_body(0x2000, 0x3000)
        cases = [
            function(*rows),
            function(*rows, cfg={"complete": False, "frontier": []}),
            function(*rows, cfg={"complete": True, "frontier": [{"reason": "x"}]}),
            function(*rows, start=0x2006),
            function(*rows, start=0x9999),  # 入口不在快照内：incomplete
        ]
        for snapshot in cases:
            for limit in (512, 4):  # 4 行触发 limited
                with self.subTest(start=snapshot["start"], cfg=snapshot["cfg"], limit=limit):
                    expected = lift_function(snapshot, "x86_64", max_instructions=limit)
                    with native._render_scope():
                        self.assertIsNone(native._memo_lift(snapshot, "x86_64", limit))
                        self.assertTrue(native._prime_render(snapshot, "x86_64", max_instructions=limit))
                        first = native._memo_lift(snapshot, "x86_64", limit)
                        first["instructions"].append("caller mutation")
                        second = native._memo_lift(snapshot, "x86_64", limit)
                    self.assertEqual(self.dumps(second), self.dumps(expected))
                    self.assertEqual(len(first["instructions"]), len(expected["instructions"]) + 1)

    def test_instruction_limit_alone_marks_reused_lift_truncated(self):
        # 只有 limited 为真（无 frontier、CFG 完整、末行是 return 不产生外部转移）。
        snapshot = function(instruction(0, "mov", "eax", "1"), instruction(1, "ret", kind="return"),
                            instruction(2, "ret", kind="return"))
        expected = lift_function(snapshot, "x86_64", max_instructions=2)
        self.assertTrue(expected["truncated"])
        with native._render_scope():
            native._prime_render(snapshot, "x86_64", max_instructions=2)
            self.assertEqual(self.dumps(native._memo_lift(snapshot, "x86_64", 2)), self.dumps(expected))
            self.assertIsNone(native._memo_lift(snapshot, "x86_64", 512))  # 行集合不同：未命中
        # 同一行集合但不同上限：重复行使 limit=2 因扫描上限而 limited，limit=512 则不是。
        rows = [instruction(0, "mov", "eax", "1"), instruction(1, "ret", kind="return")]
        repeated = function(*rows)
        repeated["blocks"] = [{"start": 0, "instructions": rows} for _ in range(20)]
        short, full = lift_function(repeated, "x86_64", max_instructions=2), lift_function(repeated, "x86_64")
        self.assertNotEqual(short["truncated"], full["truncated"])
        with native._render_scope():
            native._prime_render(repeated, "x86_64", max_instructions=2)
            self.assertEqual(self.dumps(native._memo_lift(repeated, "x86_64", 2)), self.dumps(short))
            self.assertEqual(self.dumps(native._memo_lift(repeated, "x86_64", 512)), self.dumps(full))

    def test_reuse_rejects_different_entry_for_same_rows(self):
        rows = _x86_body(0x2000, 0x3000)
        primed = function(*rows)
        for start in (0x2009, 0x9999):  # 入口标签改变比较来源；入口在快照外则不完整
            variant = {**primed, "start": start}
            with self.subTest(start=start), native._render_scope():
                native._prime_render(primed, "x86_64")
                self.assertIsNone(native._memo_lift(variant, "x86_64"))
                self.assertEqual(self.dumps(recover_signature(variant, "x86_64")),
                                 self.dumps(recover_signature(copy.deepcopy(variant), "x86_64")))
                self.assertEqual(generate_pseudoc(variant, "x86_64"), generate_pseudoc(copy.deepcopy(variant), "x86_64"))
        self.assertNotEqual(self.dumps(lift_function({**primed, "start": 0x2009}, "x86_64")),
                            self.dumps(lift_function(primed, "x86_64")))

    def test_text_reuse_requires_same_truncated_argument(self):
        snapshot = function(instruction(0, "mov", "eax", "1"), instruction(1, "ret", kind="return"))
        rows, _, truncated = native._first_render_inputs(snapshot, 512)
        with native._render_scope():
            native._prime_render(snapshot, "x86_64")
            _, flipped = native._complete_render(snapshot, "x86_64", rows, not truncated)
            _, same = native._complete_render(snapshot, "x86_64", rows, truncated)
        self.assertEqual(flipped, native._Renderer(snapshot, "x86_64", rows).render(not truncated))
        self.assertEqual(same, native._Renderer(snapshot, "x86_64", rows).render(truncated))
        self.assertNotEqual(flipped, same)

    def test_invalid_arguments_keep_original_errors(self):
        snapshot = function(*_x86_body(0x2000, None))
        with native._render_scope():
            native._prime_render(snapshot, "x86_64")
            for limit in (0, 9000, 1.5, True):
                self.assertIsNone(native._memo_lift(snapshot, "x86_64", limit))
            self.assertIsNone(native._memo_lift(snapshot, "dex"))
            with self.assertRaises(ValueError):
                recover_signature(snapshot, "x86_64", max_instructions=0)
            with self.assertRaises(ValueError):
                recover_signature(snapshot, "mips")

    def test_text_reuse_requires_identical_render_inputs(self):
        snapshot = function(*_x86_body(0x2000, 0x3000), name="caller")
        view = {**snapshot, "pseudoc_symbols": {0x3000: "named_callee"}}
        expected = generate_pseudoc(view, "x86_64")
        variants = [
            ({**snapshot, "pseudoc_symbols": dict(view["pseudoc_symbols"])}, True),  # 内容相同但不是同一字典
            ({**view, "name": "renamed"}, True),
            ({**view, "cfg": {"complete": True, "frontier": []}}, True),  # 不同 frontier 对象
            ({**view}, False),  # 浅拷贝：所有渲染输入都是同一对象，可复用
        ]
        for candidate, renders in variants:
            with self.subTest(candidate=sorted(candidate)), native._render_scope():
                native._prime_render(view, "x86_64")
                with _RenderCounter() as counter:
                    output = generate_pseudoc(candidate, "x86_64")
                self.assertEqual(len(counter.rows), 1 if renders else 0)
                self.assertEqual(output, generate_pseudoc(candidate, "x86_64"))
        with native._render_scope():
            native._prime_render(view, "x86_64")
            self.assertEqual(generate_pseudoc({**view}, "x86_64"), expected)
            with _RenderCounter() as counter:  # 文本只供首次渲染消费一次
                self.assertEqual(generate_pseudoc({**view}, "x86_64"), expected)
            self.assertEqual(len(counter.rows), 1)


if __name__ == "__main__":
    unittest.main()
