"""_json_stream 必须与标准库纯 Python 流式编码逐字节一致（含 3.11/3.12 的回退路径）。

参照输出统一用 ``json.JSONEncoder(**options).iterencode``：非 one-shot 模式在所有版本上
都是纯 Python 实现。本文件不使用 3.10+ 语法，可用系统旧版解释器运行，作为“C 编码器
不支持 indent”的真实代理。
"""
from __future__ import annotations

from collections import OrderedDict, namedtuple
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
import importlib.util
import inspect
import io
import json
import math
from pathlib import Path
import platform
import sys
import tempfile
import tracemalloc
import unittest
from unittest.mock import patch

from fangida import _json_stream
from fangida.database_cli import main as database_main
from fangida.models import AnalysisResult
from fangida.plugins.sqlite_storage import SQLiteAnalysisDatabase
from fangida.project import ProjectStore
from fangida.project_cli import main as project_main


Point = namedtuple("Point", "x y")


class Text(str):
    pass


class Number(int):
    pass


class Real(float):
    pass


class Items(list):
    pass


class Opaque:
    def __init__(self, payload):
        self.payload = payload


def _default(value):
    if isinstance(value, Opaque):
        return {"opaque": value.payload}
    raise TypeError(f"Object of type {value.__class__.__name__} is not JSON serializable")


def _reference(value, **options) -> str:
    return "".join(json.JSONEncoder(**options).iterencode(value))


def _stream(value, chunk_size=1 << 20, **options) -> list:
    return list(_json_stream.iterencode(value, chunk_size=chunk_size, **options))


_REAL_C_ENCODER = json.encoder.c_make_encoder


def _c_ignoring_indent(markers, default, encoder, indent, *rest):
    """模拟 3.11/3.12：C 编码器接受 indent 参数但完全忽略它。"""
    return _REAL_C_ENCODER(markers, default, encoder, None, *rest)


@contextmanager
def _backend(name: str):
    """切换单元编码器。

    native=当前解释器；py312=C 编码器忽略缩进（自检必须拒绝它）；python=把 C 编码器探测
    结果强制为不支持，所有单元走纯 Python；none=没有 C 编码器（例如未编译 _json）。
    """
    with ExitStack() as stack:
        if name == "py312" and _REAL_C_ENCODER is not None:
            stack.enter_context(patch.object(json.encoder, "c_make_encoder", _c_ignoring_indent))
            stack.enter_context(patch.object(_json_stream, "_C_INDENT_OK", None))
            stack.enter_context(patch.object(_json_stream, "_C_COMPACT_OK", None))
        elif name == "python":
            stack.enter_context(patch.object(_json_stream, "_C_INDENT_OK", False))
            stack.enter_context(patch.object(_json_stream, "_C_COMPACT_OK", False))
        elif name == "none":
            stack.enter_context(patch.object(json.encoder, "c_make_encoder", None))
        yield


BACKENDS = ("native", "py312", "python", "none")


@contextmanager
def _aggressive():
    """强制几乎所有容器都下钻、字典也切片，覆盖所有拼接路径。"""
    with patch.object(_json_stream, "_SMALL_BUDGET", 1), \
         patch.object(_json_stream, "_DICT_SLICE_MIN", 2):
        yield


def _instruction(address: int) -> dict:
    return {"addr": address, "size": 4, "mnemonic": "mov", "operands": ("rax", "rbx"),
            "text": "mov rax, rbx ; 注释 é", "branch_info": {},
            "arch_meta": {"engine": "capstone", "memory_references": [address + 8]}}


def _analysis_like(count: int = 600) -> dict:
    instructions = [_instruction(0x1000 + index) for index in range(count)]
    return {"path": "/tmp/样本", "kind": "elf",
            "metadata": {"full_disassembly": instructions, "sections": [], "entry_cfg": {}},
            "functions": [{"name": f"f{index}", "start": index, "size": None,
                           "blocks": [{"start": index, "instructions": instructions[index:index + 20],
                                       "successors": []}],
                           "cfg": {"edges": [], "complete": True}} for index in range(20)],
            "xrefs": [{"src": index, "dst": index + 1, "kind": "call", "confidence": 0.5}
                      for index in range(300)],
            "stats": {"seconds": 1.25}, "warnings": []}


# 覆盖嵌套空容器、Unicode/转义、非 str 键、浮点特殊值、tuple、子类与 default 钩子。
EDGE_VALUES = [
    [], {}, (), "", 0, -0.0, None, True, False, math.nan, math.inf, -math.inf, 1e300, 0.1,
    [[]], [{}], {"a": []}, {"a": {}}, [[], {}, (), [[[]]], {"b": [{}]}],
    {"": "", " ": "\n", "\x00\x1f": "\"\\/", "é": "中文", "😀": "\U0001f600\ud83d"},
    {3: "int", 2.5: "float", True: "bool", None: "none", False: 0, -7: [], 10 ** 30: {}},
    {math.nan: 1, math.inf: 2, -math.inf: 3},
    {"x": (1, 2, (3, (4,))), "t": (), "nested": ((), [()], ({},))},
    OrderedDict([("b", 1), ("a", 2)]),
    [Text("子类"), Number(3), Real(0.5), Items([1, "a"]), Point(1, [2])],
    {Text("k"): Number(-1), "items": Items([{}, []])},
    [Opaque([1, {"x": Opaque("内层")}]), {"o": Opaque(None)}],
    ["a", "b", "c"], ["a", 1, "b"], ["a", ["b"]], [Text("a"), "b"],
    {f"k{index}": [index, str(index), {"v": index}] for index in range(12)},
    [{"addr": index, "ops": ["rax", "rbx"]} for index in range(40)],
]

OPTIONS = (
    {"indent": 2, "ensure_ascii": False},
    {"indent": 2, "ensure_ascii": True},
    {"indent": 0},
    {"indent": "\t", "sort_keys": True, "ensure_ascii": False},
    {"indent": 4, "separators": (" ,", " : ")},
    {"sort_keys": True, "separators": (",", ":")},
    {"ensure_ascii": False},
    {"indent": 2, "skipkeys": True},
)


class JsonStreamEquivalenceTests(unittest.TestCase):
    def assert_same(self, value, chunk_sizes=(1, 7, 1 << 20), **options):
        try:
            expected = _reference(value, **options)
        except (TypeError, ValueError) as error:
            with self.assertRaises(type(error)):
                _stream(value, 1, **options)
            return
        for chunk_size in chunk_sizes:
            chunks = _stream(value, chunk_size, **options)
            self.assertEqual("".join(chunks), expected, (options, chunk_size))
            self.assertTrue(all(chunks), "不应产出空块")

    def test_edge_values_on_every_backend(self):
        for backend in BACKENDS:
            for aggressive in (False, True):
                with self.subTest(backend=backend, aggressive=aggressive), ExitStack() as stack:
                    stack.enter_context(_backend(backend))
                    if aggressive:
                        stack.enter_context(_aggressive())
                    for value in EDGE_VALUES:
                        for options in OPTIONS:
                            self.assert_same(value, default=_default, **options)
                    if backend == "py312" and _REAL_C_ENCODER is not None:
                        # 自检必须识别出“忽略缩进”的 C 编码器并回退到纯 Python 单元。
                        self.assertIs(_json_stream._C_INDENT_OK, False)
                        self.assertIs(_json_stream._C_COMPACT_OK, True)

    def test_analysis_shaped_payload_and_chunk_bounds(self):
        payload = _analysis_like()
        expected = {ensure_ascii: _reference(payload, indent=2, ensure_ascii=ensure_ascii)
                    for ensure_ascii in (False, True)}
        compact = _reference(payload, sort_keys=True, separators=(",", ":"))
        for backend in BACKENDS:
            with self.subTest(backend=backend), _backend(backend):
                for ensure_ascii in (False, True):
                    for chunk_size in (4096, 1 << 20):
                        chunks = _stream(payload, chunk_size, indent=2, ensure_ascii=ensure_ascii)
                        self.assertEqual("".join(chunks), expected[ensure_ascii])
                self.assertEqual("".join(_stream(payload, 4096, sort_keys=True,
                                                 separators=(",", ":"))), compact)
        chunks = _stream(payload, 16384, indent=2)
        self.assertGreater(len(chunks), 10)
        # 单元按自适应切片编码：任何一块都不应接近整体大小。
        self.assertLess(max(map(len, chunks)), sum(map(len, chunks)) // 4)

    def test_deep_nesting_of_900_levels_succeeds(self):
        value: object = 0
        for depth in range(900):
            value = [value] if depth % 2 else {"k": value, "n": depth}
        for backend in ("native", "python"):
            with self.subTest(backend=backend), _backend(backend):
                for options in ({"indent": 2}, {"separators": (",", ":")}):
                    self.assertEqual("".join(_stream(value, 4096, **options)),
                                     _reference(value, **options))

    def test_c_recursion_error_falls_back_without_stale_markers(self):
        """C 递归上限低于 Python 时：清理 C 留下的 markers，再用纯 Python 单元重试。"""
        value = {"a": [[{"b": [1, 2]}], {"c": "d"}], "e": list(range(100))}
        streamer = _json_stream._Streamer(json.JSONEncoder(indent=2), 1 << 20)

        def failing(unit_value, level):
            streamer.markers[id(unit_value)] = unit_value  # 模拟 C 编码器出错时遗留的条目
            raise RecursionError("simulated C recursion limit")
        streamer.c_unit = failing
        self.assertEqual("".join(streamer.run(value)), _reference(value, indent=2))
        self.assertEqual(streamer.markers, {})

    def test_errors_match_reference(self):
        circular: list = [1]
        circular.append({"loop": circular})
        nested = {"a": [1, {"b": [2]}]}
        nested["a"][1]["b"].append(nested)
        through_default = Opaque(None)
        through_default.payload = [through_default]
        cases = (
            (circular, {"indent": 2}, ValueError),
            (nested, {"separators": (",", ":")}, ValueError),
            ([through_default], {"indent": 2, "default": lambda o: o.payload}, ValueError),
            ({(1, 2): 3}, {"indent": 2}, TypeError),
            ({"x": object()}, {"indent": 2}, TypeError),
            ([1, math.nan], {"indent": 2, "allow_nan": False}, ValueError),
            ({"x": [math.inf]}, {"allow_nan": False}, ValueError),
            ({-math.inf: 1}, {"indent": 2, "allow_nan": False}, ValueError),
        )
        for backend in BACKENDS:
            for aggressive in (False, True):
                with self.subTest(backend=backend, aggressive=aggressive), ExitStack() as stack:
                    stack.enter_context(_backend(backend))
                    if aggressive:
                        stack.enter_context(_aggressive())
                    for value, options, error in cases:
                        with self.assertRaises(error):
                            _reference(value, **options)
                        with self.assertRaises(error):
                            _stream(value, 1, **options)
                    # skipkeys 跳过全部键时标准库仍输出换行缩进的特殊格式。
                    self.assert_same({(1,): 1, (2,): 2}, indent=2, skipkeys=True)
                    self.assert_same([{(1,): 1}, {}], indent=2, skipkeys=True)

    def test_unchecked_cycle_raises_recursion_error_without_buffering_everything(self):
        """check_circular=False：沿用标准库逐 token 产出，在递归上限处报错前已按块交出。"""
        payload = "x" * 10000
        loop: list = [payload]
        loop.append(loop)
        reference = []
        with self.assertRaises(RecursionError):
            for piece in json.JSONEncoder(check_circular=False).iterencode(loop):
                reference.append(piece)
        reference_text = "".join(reference)
        chunk_size = 1 << 16
        received = []
        tracemalloc.start()
        try:
            with self.assertRaises(RecursionError):
                for chunk in _json_stream.iterencode(loop, chunk_size=chunk_size,
                                                     check_circular=False):
                    received.append(len(chunk))
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        produced = sum(received)
        # 报错前已交出大部分输出，且每块都受 chunk_size 约束（最多再多一个片段）。
        self.assertGreater(produced, 50 * len(payload))
        self.assertTrue(all(size < chunk_size + len(payload) + 16 for size in received))
        # 若把整段输出累积在内存中，峰值会接近 produced（数 MB）；流式时只有一两个块。
        self.assertLess(peak, max(produced // 4, 8 * chunk_size))
        self.assertGreaterEqual(len(reference_text), produced)
        # 同样的选项下（无环数据）输出与标准库一致。
        self.assert_same({"a": [1, (2, {})]}, indent=2, check_circular=False)

    def test_iterencode_with_honors_encoder_subclass_default(self):
        class Encoder(json.JSONEncoder):
            def default(self, o):
                if isinstance(o, Opaque):
                    return ["opaque", o.payload]
                return super().default(o)

        value = {"items": [Opaque(index) for index in range(50)], "x": Opaque({"y": Opaque(1)})}
        for backend in BACKENDS:
            with self.subTest(backend=backend), _backend(backend), _aggressive():
                for options in ({"indent": 2}, {"sort_keys": True, "separators": (",", ":")}):
                    encoder = Encoder(**options)
                    self.assertEqual("".join(_json_stream.iterencode_with(encoder, value, chunk_size=64)),
                                     "".join(Encoder(**options).iterencode(value)))

    def test_dump_writes_large_chunks(self):
        payload = _analysis_like()
        stream = io.StringIO()
        with patch.object(stream, "write", wraps=stream.write) as write:
            _json_stream.dump(payload, stream, indent=2, ensure_ascii=False)
        self.assertEqual(stream.getvalue(), _reference(payload, indent=2, ensure_ascii=False))
        self.assertLess(write.call_count, 8)

    def test_chunk_size_is_validated_eagerly(self):
        for chunk_size in (0, -1, True, 1.5, None):
            for check_circular in (True, False):
                with self.assertRaises(ValueError):
                    _json_stream.iterencode([1], chunk_size=chunk_size, check_circular=check_circular)


class JsonStreamInterfaceTests(unittest.TestCase):
    def test_package_internal_interface_is_kept(self):
        """ui/api/benchmark/CLI 依赖的包内接口名与签名。"""
        self.assertIsNone(importlib.util.find_spec("fangida.json_stream"))
        self.assertIsInstance(_json_stream.DEFAULT_CHUNK_SIZE, int)
        signatures = {
            "dump": "(obj, stream, *, chunk_size=1048576, **options)",
            "iterencode": "(obj, *, chunk_size=1048576, **options)",
            "iterencode_with": "(encoder, obj, *, chunk_size=1048576)",
            "c_indent_supported": "()",
            "c_compact_supported": "()",
        }
        for name, expected in signatures.items():
            signature = inspect.signature(getattr(_json_stream, name))
            text = str(signature.replace(return_annotation=inspect.Signature.empty,
                                         parameters=[parameter.replace(annotation=inspect.Parameter.empty)
                                                     for parameter in signature.parameters.values()]))
            self.assertEqual(text, expected, name)

    def test_c_encoder_probes(self):
        indent_ok, compact_ok = _json_stream.c_indent_supported(), _json_stream.c_compact_supported()
        self.assertIsInstance(indent_ok, bool)
        self.assertIsInstance(compact_ok, bool)
        if platform.python_implementation() == "CPython" and _REAL_C_ENCODER is not None:
            # 3.13+ 的 C 编码器支持缩进；更早的版本接受 indent 参数却忽略它，必须被自检拒绝。
            self.assertEqual(indent_ok, sys.version_info >= (3, 13))
            self.assertTrue(compact_ok)
        with patch.object(json.encoder, "c_make_encoder", None), \
             patch.object(_json_stream, "_C_INDENT_OK", None), \
             patch.object(_json_stream, "_C_COMPACT_OK", None):
            self.assertFalse(_json_stream.c_indent_supported())
            self.assertFalse(_json_stream.c_compact_supported())

    def test_rejecting_c_encoder_constructor_falls_back(self):
        """私有 c_make_encoder 签名变化（构造抛 TypeError）时退回纯 Python 单元。"""
        def broken(*args):
            raise TypeError("make_encoder() signature changed")

        value = _analysis_like(50)
        with patch.object(json.encoder, "c_make_encoder", broken), \
             patch.object(_json_stream, "_C_INDENT_OK", None), \
             patch.object(_json_stream, "_C_COMPACT_OK", None):
            for options in ({"indent": 2}, {"separators": (",", ":")}):
                self.assertEqual("".join(_stream(value, 512, **options)), _reference(value, **options))
            self.assertIs(_json_stream._C_INDENT_OK, False)
            self.assertIs(_json_stream._C_COMPACT_OK, False)
        with patch.object(_json_stream, "_C_INDENT_OK", True), \
             patch.object(_json_stream, "_C_COMPACT_OK", True), \
             patch.object(json.encoder, "c_make_encoder", broken):
            # 即使缓存的自检结果为真，构造失败也不能让编码失败。
            self.assertIsNone(_json_stream._Streamer(json.JSONEncoder(indent=2), 64).c_unit)
            self.assertEqual("".join(_stream(value, 512, indent=2)), _reference(value, indent=2))



class DumpsTests(unittest.TestCase):
    """_json_stream.dumps 与 json.dumps 返回相同的完整字符串（含强制纯 Python 回退）。"""

    def test_dumps_matches_json_dumps(self):
        value = {"中文": [1, 2.5, None, True, (), {}], 3: {"nested": [[], [{"k": "v\u2028"}]]},
                 "big": list(range(3000)), "float": float("inf")}
        for indent_ok in (None, False):
            with patch.object(_json_stream, "_C_INDENT_OK", indent_ok):
                for options in ({"indent": 2, "ensure_ascii": False}, {"indent": 2},
                                {}, {"separators": (",", ":")}):
                    self.assertEqual(_json_stream.dumps(value, **options), json.dumps(value, **options))
                with self.assertRaises(ValueError):
                    _json_stream.dumps(value, indent=2, allow_nan=False)


class SnapshotShowStreamingTests(unittest.TestCase):
    """fangida-db / fangida-project 的 show 输出与 print(json.dumps(...)) 逐字节一致，失败时不留半截输出。"""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / "样本.bin"
        self.source.write_bytes(b"\x7fELF bytes")

    def result(self) -> AnalysisResult:
        instructions = [{"addr": 0x1000 + index, "size": 1, "mnemonic": "nop", "operands": [],
                         "text": f"nop ; 第{index}条 \"q\"\t"} for index in range(200)]
        return AnalysisResult(
            str(self.source), "elf", "kkagent", "partial",
            metadata={"full_disassembly": instructions, "note": "中文 \u2028 é 😀",
                      "sections": [{"name": ".text", "flags": ["x"]}], "empty": {}, "nested": [[], [{}]]},
            functions=[{"address": 0x1000 + index, "name": f"函数_{index}",
                        "blocks": [{"start": 0x1000 + index, "instructions": instructions[index:index + 5]}]}
                       for index in range(30)],
            strings=[{"address": 0x5000, "value": "hello \"世界\"\n"}],
            xrefs=[{"src": 0x1000, "dst": 0x1001, "kind": "call", "confidence": 0.5}],
            warnings=["limited scan"])

    @staticmethod
    def printed(value) -> str:
        output = io.StringIO()
        with redirect_stdout(output):
            print(json.dumps(value, indent=2, ensure_ascii=False))
        return output.getvalue()

    def run_cli(self, main, arguments: list, streamed: bool) -> str:
        outputs = []
        # 3.13+ 走 json.dumps；强制关闭 C indent 时（模拟 3.11/3.12）走分块编码器，输出必须相同。
        for indent_ok in (None, False):
            output, error = io.StringIO(), io.StringIO()
            with redirect_stdout(output), redirect_stderr(error), \
                 patch.object(_json_stream, "_C_INDENT_OK", indent_ok):
                status = main(arguments)
            self.assertEqual((status, error.getvalue()), (0, ""))
            outputs.append(output.getvalue())
        self.assertEqual(outputs[0], outputs[1])
        return outputs[0]

    def test_show_encoding_failure_leaves_stdout_empty(self):
        # 原实现先完整生成 JSON 再一次 print：输出编码失败时 stdout 一个字节都不写。
        path = Path(self.temp.name) / "saved.fdb"
        database = SQLiteAnalysisDatabase(path, create=True)
        try:
            snapshot_id = database.save_analysis(self.source, self.result())
        finally:
            database.close()
        for main, target in ((database_main, [str(path), "show", str(snapshot_id)]),):
            raw = io.BytesIO()
            stdout = io.TextIOWrapper(raw, encoding="ascii", errors="strict", write_through=True)
            error = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(error):
                status = main(target)
            self.assertEqual(status, 2)
            self.assertEqual(raw.getvalue(), b"")
            self.assertIn("ascii", error.getvalue())

    def test_database_show_matches_print_of_json_dumps(self):
        path = Path(self.temp.name) / "saved.fdb"
        database = SQLiteAnalysisDatabase(path, create=True)
        try:
            snapshot_id = database.save_analysis(self.source, self.result())
            database.rename_symbol(snapshot_id, 0x1001, "改名")
            database.set_comment(snapshot_id, 0x1000, "注释\n第二行")
        finally:
            database.close()
        reader = SQLiteAnalysisDatabase(path, read_only=True)
        try:
            snapshot = reader.get_snapshot(snapshot_id)
            history = reader.history()
        finally:
            reader.close()
        self.assertIn("改名", json.dumps(snapshot, ensure_ascii=False))
        expected = self.printed(snapshot)
        for arguments in (["show"], ["show", str(snapshot_id)]):
            self.assertEqual(self.run_cli(database_main, [str(path), *arguments], True), expected)
        self.assertEqual(self.run_cli(database_main, [str(path), "history"], False), self.printed(history))
        # 与 print 相同：没有标准输出（如 pythonw）时静默成功。
        with redirect_stdout(None):
            self.assertEqual(database_main([str(path), "show"]), 0)

    def test_project_show_matches_print_of_json_dumps(self):
        path = Path(self.temp.name) / "project.fangida"
        snapshot_id = ProjectStore(path).save_analysis(self.source, self.result())
        reader = ProjectStore(path, read_only=True)
        expected = self.printed(reader.get_snapshot(snapshot_id))
        self.assertEqual(self.run_cli(project_main, [str(path), "show", str(snapshot_id)], True), expected)
        self.assertEqual(self.run_cli(project_main, [str(path), "history"], False),
                         self.printed(reader.history()))


if __name__ == "__main__":
    unittest.main()
