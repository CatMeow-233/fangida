"""GUI 结果路径的内存优化：值与行为不变的检查（不启动图形界面或分析器）。

- 导出 JSON 流式写出，文件逐字节相同，失败语义不变；
- 换文件时释放旧结果的标注缓存与按需伪代码状态；
- 紧凑标注索引与原索引分组、组内顺序逐对象相同；
- 导航索引的反汇编行视图、xref 排序数组、CFG 块数组与原逐行索引的查询结果相同。
"""
from __future__ import annotations

import gc
import json
import os
import random
import tempfile
import threading
import unittest
import weakref
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from pathlib import Path
from unittest.mock import Mock, patch

from fangida import _json_stream
from fangida import gui as G
from fangida.api import AnalysisView
from fangida.gui_modules import navigation as N
from fangida.gui_modules.browser_jobs import _PseudocodeJobs
from fangida.gui_modules.navigation import AddressIndex, Location
from fangida.models import AnalysisResult
from fangida.scripts import ScriptCapabilities, ScriptContext


class _Rows(list):
    """list 子类：导航索引对它不走快速路径，用作原逐行实现的参照。"""


class _Sentinel:
    pass


def _snapshot_view(**extra):
    result = AnalysisResult("sample.bin", "elf", "kkagent", "partial",
                            metadata={"unicode": "中文；注释 \x00", "specials": [float("inf"), -0.0, 10 ** 30],
                                      "full_disassembly": [{"addr": 16 * i, "size": 4, "mnemonic": "nop"}
                                                           for i in range(500)], **extra},
                            functions=[{"name": f"f{i}", "start": 64 * i, "comment": "说明"} for i in range(40)],
                            strings=[{"address": 0x9000 + i, "value": "字" * i} for i in range(30)],
                            xrefs=[{"src": 16 * i, "dst": 64 * (i % 40), "kind": "call"} for i in range(300)],
                            stats={"full_analysis": True})
    return AnalysisView._from_owned_result(result)


_REAL_C_ENCODER = json.encoder.c_make_encoder


def _c_ignoring_indent(markers, default, encoder, indent, *rest):
    """模拟 3.11/3.12：C 编码器接受 indent 参数但完全忽略它（同 tests/test_json_stream.py）。"""
    return _REAL_C_ENCODER(markers, default, encoder, None, *rest)


@contextmanager
def _json_backend(name):
    """切换流式编码器的单元编码器：native=当前解释器；py312=C 编码器忽略缩进（自检必须拒绝）；
    python=强制全部走纯 Python 单元。期望文本都在切换之前用标准库算好。"""
    with ExitStack() as stack:
        if name == "py312" and _REAL_C_ENCODER is not None:
            stack.enter_context(patch.object(json.encoder, "c_make_encoder", _c_ignoring_indent))
            stack.enter_context(patch.object(_json_stream, "_C_INDENT_OK", None))
            stack.enter_context(patch.object(_json_stream, "_C_COMPACT_OK", None))
        elif name == "python":
            stack.enter_context(patch.object(_json_stream, "_C_INDENT_OK", False))
            stack.enter_context(patch.object(_json_stream, "_C_COMPACT_OK", False))
        yield


class StreamingExportTests(unittest.TestCase):
    def test_export_matches_original_and_never_builds_the_whole_text(self):
        view = _snapshot_view()
        expected = json.dumps(view._snapshot, indent=2, ensure_ascii=False) + "\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # 参照文件按原实现（Path.write_text 整串、文本模式）写出：换行转换与平台一致，
            # 因此 Windows 上同样逐字节可比。
            reference = root / "reference.json"
            reference.write_text(expected, encoding="utf-8")
            context = ScriptContext(view._snapshot, export_root=root, capabilities=ScriptCapabilities({"export"}))
            context_expected = json.dumps(context._snapshot, indent=2, ensure_ascii=False) + "\n"
            context_reference = root / "context_reference.json"
            context_reference.write_text(context_expected, encoding="utf-8")
            for backend in ("native", "py312", "python"):
                with self.subTest(backend=backend), _json_backend(backend), \
                        patch.object(_json_stream, "dumps", side_effect=AssertionError("不得生成整串")):
                    path = view.export_json(root / "view.json")
                    self.assertEqual(path, (root / "view.json").resolve())
                    self.assertEqual(path.read_text(encoding="utf-8"), expected)
                    self.assertEqual(path.read_bytes(), reference.read_bytes())
                    target = context.export_json("nested/context.json")
                    self.assertEqual(target.read_text(encoding="utf-8"), context_expected)
                    self.assertEqual(target.read_bytes(), context_reference.read_bytes())

    def test_public_probe_patch_only_steers_dumps(self):
        # 替换公开探测 c_indent_supported 只影响 dumps 是否直接调用 json.dumps；流式写出仍按
        # 真实自检选择单元编码器，3.11/3.12 上忽略缩进的 C 编码器不会被误用（输出不会变成紧凑格式）。
        view = _snapshot_view()
        expected = json.dumps(view._snapshot, indent=2, ensure_ascii=False) + "\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for backend in ("native", "py312"):
                for c_indent in (True, False):
                    with self.subTest(backend=backend, c_indent=c_indent), _json_backend(backend), \
                            patch.object(_json_stream, "c_indent_supported", return_value=c_indent):
                        if backend == "py312":
                            self.assertFalse(_json_stream._c_indent_ok())
                        path = view.export_json(root / "view.json")
                        self.assertEqual(path.read_text(encoding="utf-8"), expected)
                        self.assertEqual("".join(_json_stream.iterencode(
                            view._snapshot, chunk_size=64, indent=2, ensure_ascii=False)), expected[:-1])

    def test_invalid_chunk_size_is_rejected_before_touching_target(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "out.json"
            target.write_bytes(b"previous")
            for chunk_size in (0, -1, True, 1.5, None):
                with self.subTest(chunk_size=chunk_size), self.assertRaises(ValueError):
                    _json_stream.write_text(target, {"a": 1}, chunk_size=chunk_size, indent=2)
                self.assertEqual(target.read_bytes(), b"previous")

    def test_small_chunks_and_encodings_match_write_text(self):
        value = {"a": ["中文", "x" * 50, {"b": [1.5, None, True]}], "c": "é" * 30}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for encoding in ("utf-8", "utf-16", "latin-1"):
                with self.subTest(encoding=encoding):
                    reference, streamed = root / f"r.{encoding}", root / f"s.{encoding}"
                    try:
                        reference.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n",
                                             encoding=encoding)
                        expected_error = None
                    except UnicodeEncodeError as exc:
                        expected_error = exc
                    if expected_error is None:
                        _json_stream.write_text(streamed, value, end="\n", encoding=encoding, chunk_size=7,
                                                indent=2, ensure_ascii=False)
                        self.assertEqual(streamed.read_bytes(), reference.read_bytes())
                    else:
                        with self.assertRaises(UnicodeEncodeError) as raised:
                            _json_stream.write_text(streamed, value, end="\n", encoding=encoding,
                                                    chunk_size=7, indent=2, ensure_ascii=False)
                        self.assertEqual(str(raised.exception), str(expected_error))
                        self.assertEqual(streamed.read_bytes(), reference.read_bytes())

    def test_serialization_failure_does_not_touch_existing_target(self):
        broken = AnalysisView._from_owned_snapshot({**_snapshot_view().snapshot(), "stats": {"bad": object()}})
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "out.json"
            with self.assertRaises(TypeError):
                broken.export_json(target)
            self.assertFalse(target.exists())
            target.write_bytes(b"previous")
            with self.assertRaises(TypeError) as raised:
                broken.export_json(target)
            self.assertEqual(target.read_bytes(), b"previous")
            with self.assertRaises(TypeError) as original:
                json.dumps(broken._snapshot, indent=2, ensure_ascii=False)
            self.assertEqual(str(raised.exception), str(original.exception))

    def test_unencodable_text_matches_original_write_text_failure(self):
        # 孤立代理项：JSON 编码成功、UTF-8 编码失败。原实现先截断目标再抛 UnicodeEncodeError。
        view = _snapshot_view(bad="\ud800")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reference, target = root / "reference.json", root / "target.json"
            reference.write_bytes(b"previous")
            target.write_bytes(b"previous")
            with self.assertRaises(UnicodeEncodeError) as expected:
                reference.write_text(json.dumps(view._snapshot, indent=2, ensure_ascii=False) + "\n",
                                     encoding="utf-8")
            with self.assertRaises(UnicodeEncodeError) as raised:
                view.export_json(target)
            self.assertEqual(str(raised.exception), str(expected.exception))
            self.assertEqual(target.read_bytes(), reference.read_bytes())

    def test_export_writes_in_place_keeping_hard_links(self):
        view = _snapshot_view()
        with tempfile.TemporaryDirectory() as directory:
            target, alias = Path(directory) / "out.json", Path(directory) / "alias.json"
            target.write_text("old", encoding="utf-8")
            os.link(target, alias)
            inode = target.stat().st_ino
            view.export_json(target)
            self.assertEqual(target.stat().st_ino, inode)
            self.assertEqual(alias.read_bytes(), target.read_bytes())
            self.assertEqual(json.loads(alias.read_text(encoding="utf-8")), json.loads(
                json.dumps(view._snapshot, ensure_ascii=False)))


def _bare_browser():
    browser = object.__new__(G._Browser)
    for name in ("hex_go", "hex_prev", "hex_next", "hex_range", "hex_text", "cfg_choice", "cfg_selection",
                 "cfg_jump", "cfg_status", "cfg_tree", "cfg_detail", "open_button", "open_database_button",
                 "export_button", "save_database_button", "rename_button", "comment_button", "file_label",
                 "status", "summary"):
        setattr(browser, name, Mock())
    browser.cfg_tree.get_children.return_value = ()
    browser._generation = 1
    browser._busy = False
    browser._tables, browser._rows, browser._details, browser._tabs = {}, {}, {}, {}
    return browser


class StaleResultReleaseTests(unittest.TestCase):
    def test_begin_open_drops_annotation_index_and_pseudocode_state(self):
        browser = _bare_browser()
        sentinel = _Sentinel()
        snapshot = {"metadata": {"sentinel": sentinel}, "functions": [{"start": 1, "name": "a"}]}
        cache = browser._annotation_cache = {"snapshot": snapshot, "index": G._annotation_targets(snapshot)}
        jobs = browser._pseudocode_job_state = _PseudocodeJobs(1, context=Mock(source=snapshot))
        jobs.waiting.append((0x100, snapshot, None))
        alive = weakref.ref(sentinel)
        del sentinel, snapshot
        generation = browser._begin_open("next.bin", "打开")
        self.assertEqual(generation, 2)
        self.assertIs(browser._annotation_cache, cache)  # 同一字典，只是清空（存储线程拿到的仍是它）
        self.assertEqual(cache, {})
        self.assertIsNone(browser._pseudocode_job_state)
        self.assertTrue(jobs.cancelled)
        self.assertEqual(jobs.waiting, [])
        del jobs
        gc.collect()
        self.assertIsNone(alive())  # 旧快照已无引用
        fresh = browser._pseudocode_jobs()  # 惰性重建，与 generation 变化后的原行为相同
        self.assertEqual(fresh.generation, 2)

    def test_begin_open_without_caches_is_unchanged(self):
        browser = _bare_browser()
        self.assertEqual(browser._begin_open("next.bin", "打开"), 2)
        self.assertFalse(hasattr(browser, "_annotation_cache"))
        self.assertIsNone(getattr(browser, "_pseudocode_job_state", None))


def _annotation_snapshot(seed):
    rng = random.Random(seed)
    shared = [{"addr": 0x1000 + 4 * i, "size": 4, "mnemonic": "nop", "comment": "c" if i % 5 == 0 else None,
               "arch_meta": {"memory_references": [{"address": 0x9000 + i}]} if i % 3 == 0 else {"engine": "x"}}
              for i in range(200)]
    blocks = [{"start": shared[i]["addr"], "instructions": shared[i:i + 5]} for i in range(0, 200, 5)]
    functions = [{"start": shared[i]["addr"], "name": f"f{i}", "blocks": blocks[i // 5:i // 5 + 2],
                  "cfg": {"edges": [{"src": 1, "dst": 2}]}} for i in range(0, 200, 10)]

    class Record(dict):
        pass
    many = [{"address": 7, "name": f"dup{i}"} for i in range(20)]  # 同一地址很多条记录（走 id 集合去重）
    snapshot = {"metadata": {"full_disassembly": shared, "sections": [{"address": 0x1000, "name": ".text"}],
                             "many": many, "again": many[3:9], "subclass": [Record(start=0x1004, name="r")]},
                "functions": functions, "xrefs": [{"src": 0x1000, "dst": 0x1010}],
                "strings": [{"address": 0x9000 + i, "value": "s"} for i in range(0, 60, 7)]}
    cycle = {"loop": None}
    cycle["loop"] = [cycle, {"start": 0x1008, "name": "inner"}]
    snapshot["metadata"]["cycle"] = cycle
    rng.shuffle(snapshot["metadata"]["again"])
    return snapshot


class AnnotationTargetsTests(unittest.TestCase):
    def test_groups_and_order_match_original_index(self):
        for seed in range(5):
            snapshot = _annotation_snapshot(seed)
            original = G._annotation_index(snapshot)
            compact = G._annotation_targets(snapshot)
            self.assertEqual(list(compact), list(original))
            for address, records in original.items():
                slot = compact[address]
                if len(records) == 1:
                    self.assertIs(slot, records[0])
                else:
                    self.assertIs(type(slot), list)
                    self.assertEqual([id(item) for item in slot], [id(item) for item in records])

    def test_applying_with_either_index_gives_identical_snapshots(self):
        operations = [("rename_symbol", 0x1000, "main"), ("set_comment", 0x1000, "入口"),
                      ("set_comment", 0x1014, "x"), ("set_comment", 0x1014, ""), ("rename_symbol", 7, "seven"),
                      ("set_comment", 0x1004, "子类"), ("set_comment", 0xDEAD, "nothing"),
                      ("rename_symbol", 0x1008, "inner2"), ("set_comment", 0x1000, "")]
        first, second = _annotation_snapshot(1), _annotation_snapshot(1)
        old_index, new_index = G._annotation_index(first), G._annotation_targets(second)
        for operation, address, value in operations:
            G._apply_annotation(first, old_index, operation, address, value)
            G._apply_annotation(second, new_index, operation, address, value)
        # 环单独比较（其中的记录也被标注），其余部分整体比较。
        first_cycle, second_cycle = first["metadata"].pop("cycle"), second["metadata"].pop("cycle")
        self.assertEqual(first_cycle["loop"][1], second_cycle["loop"][1])
        self.assertEqual(second_cycle["loop"][1]["name"], "inner2")
        self.assertEqual(first, second)
        self.assertEqual(json.dumps(first, sort_keys=True, default=repr),
                         json.dumps(second, sort_keys=True, default=repr))

    def test_cache_miss_releases_previous_index_before_rebuilding(self):
        old_snapshot = {"metadata": {}}
        cache = {"snapshot": old_snapshot, "index": {"old": True}}
        view = AnalysisView._from_owned_snapshot({
            "path": "x", "kind": "elf", "analyzer": "kkagent", "status": "partial", "schema_version": "1",
            "metadata": {"analysis_database": {"path": "db.fdb", "snapshot_id": 1}},
            "functions": [{"start": 4, "name": "a"}]})
        seen_during_build = []
        original = G._annotation_targets

        def build(snapshot):
            seen_during_build.append(dict(cache))
            return original(snapshot)
        database = Mock()
        storage = Mock()
        storage.open_database.return_value = database
        manager = Mock()
        manager.load_storage.return_value = storage
        with patch.object(G, "PluginManager", return_value=manager), \
                patch.object(G, "_annotation_targets", side_effect=build):
            result = G._annotate_owned_view(view, "rename_symbol", 4, "b", cache=cache)
        self.assertEqual(seen_during_build, [{}])
        self.assertIs(cache["snapshot"], view._snapshot)
        self.assertEqual(result._snapshot["functions"][0]["name"], "b")
        database.rename_symbol.assert_called_once_with(1, 4, "b")


def _tables(seed, *, strings=True):
    rng = random.Random(seed)
    disassembly, address = [], 0x1000
    for _ in range(800):
        size = rng.choice((1, 2, 4, 4, 8))
        disassembly.append({"addr": address, "size": size, "mnemonic": "op",
                            "arch_meta": {"engine": "x"} if rng.random() < 0.3 else {}})
        address += size + rng.choice((0, 0, 0, 2))
    disassembly.insert(100, dict(disassembly[100]))  # 同一地址两条记录
    end = address
    string_rows = [{"address": 0x9000 + 32 * i, "offset": 0x2000 + 32 * i, "length": 9, "value": "s"}
                   for i in range(25)] if strings else []
    xrefs = []
    for i in range(1200):
        src = rng.randrange(0x1000, end)
        if rng.random() < 0.3 and string_rows:
            dst = rng.choice(string_rows)["address"] + rng.randrange(0, 12)
        else:
            dst = rng.choice(disassembly)["addr"]
        row = {"src": src, "dst": dst, "kind": rng.choice(("call", "jump", "data")), "confidence": 1.0}
        if rng.random() < 0.02:
            row["dst"] = rng.choice((-4, [], None, 1 << 64))
        if rng.random() < 0.02:
            row["src"] = -1
        if rng.random() < 0.05:
            del row["kind"]
        xrefs.append(row)
    xrefs.sort(key=lambda item: item["src"] if type(item["src"]) is int else -1)
    xrefs.insert(7, None)
    xrefs.append(dict(xrefs[3]))  # 重复行，且打乱 src 顺序
    functions = [{"name": f"f{i}", "start": disassembly[i * 40]["addr"], "size": 64} for i in range(20)]
    api_calls = [{"addr": functions[3]["start"], "target": "f5"}, {"addr": 0x9000 + 2, "target": "f6"},
                 {"addr": disassembly[5]["addr"], "target": "missing"}]
    cfgs = []
    for i, function in enumerate(functions[:15]):
        start = disassembly.index(next(item for item in disassembly if item["addr"] == function["start"]))
        blocks = [{"start": disassembly[start + k]["addr"], "instructions": disassembly[start + k:start + k + 6]}
                  for k in range(0, 30, 6)]
        cfgs.append({"name": function["name"], "start": function["start"], "graph": {"blocks": blocks}})
    tables = {"Sections": [{"name": ".text", "address": 0x1000, "offset": 0x1000, "size": end - 0x1000}],
              "Functions": functions, "Disassembly": disassembly, "Strings": string_rows,
              "Xrefs": xrefs, "API Calls": api_calls}
    return tables, cfgs


def _ref(reference):
    return (reference.table, reference.row_index, reference.src, reference.dst, reference.kind, reference.target)


class CompactNavigationIndexTests(unittest.TestCase):
    def _pair(self, tables, cfgs, *, kind="elf"):
        fast = AddressIndex(tables, cfgs, kind=kind)
        slow = AddressIndex({name: _Rows(rows) for name, rows in tables.items()}, cfgs, kind=kind)
        return fast, slow

    def _assert_same(self, fast, slow, tables, probes):
        for address in probes:
            for space in ("native", "file_offset"):
                location = Location(address, "", space)
                self.assertEqual(fast.find_targets(location), slow.find_targets(location), hex(address))
                for table in ("Disassembly", "Xrefs", "CFG", "Strings", "Functions", "API Calls"):
                    self.assertEqual(fast.find_targets(location, table=table),
                                     slow.find_targets(location, table=table))
                self.assertEqual(fast.find_functions(location), slow.find_functions(location))
                self.assertEqual([_ref(item) for item in fast.incoming(location)],
                                 [_ref(item) for item in slow.incoming(location)], hex(address))
                self.assertEqual([_ref(item) for item in fast.outgoing(location)],
                                 [_ref(item) for item in slow.outgoing(location)])
            self.assertEqual(fast.locations(address), slow.locations(address))
        for name in ("f1", "f5", "missing", ".text"):
            try:
                expected = slow.resolve(name)
            except ValueError as exc:
                with self.assertRaises(type(exc)):
                    fast.resolve(name)
            else:
                self.assertEqual(fast.resolve(name), expected)

    def _probes(self, tables, seed):
        rng = random.Random(seed)
        probes = {rng.randrange(0, 0xA000) for _ in range(1500)}
        for row in tables["Xrefs"]:
            if isinstance(row, dict):
                probes.update(value for value in (row.get("src"), row.get("dst"))
                              if type(value) is int and 0 <= value < 1 << 64)
        probes.update(row["addr"] for row in tables["Disassembly"][::7])
        return sorted(probes)

    def test_fast_paths_are_used_and_answer_like_the_row_by_row_index(self):
        for seed in range(3):
            tables, cfgs = _tables(seed)
            fast, slow = self._pair(tables, cfgs)
            context = ("", "native")
            self.assertIs(type(fast._points[context]["Disassembly"][0]), N._RowAddresses)
            self.assertIsNotNone(fast._xref_points)
            self.assertIsNone(slow._xref_points)
            self.assertIs(type(fast._cfg_ranges[context]), N._PackedIntervals)
            self.assertEqual(list(fast._points[context]), list(slow._points[context]))  # 表的顺序不变
            self.assertEqual(dict(fast._string_references).keys(), dict(slow._string_references).keys())
            for identifier, references in slow._string_references.items():
                self.assertEqual([_ref(item) for item in fast._string_references[identifier]],
                                 [_ref(item) for item in references])
            self._assert_same(fast, slow, tables, self._probes(tables, seed))

    def test_reference_objects_keep_shared_identity(self):
        tables, cfgs = _tables(4)
        fast, _ = self._pair(tables, cfgs)
        for row in tables["Xrefs"][:200]:
            if not isinstance(row, dict) or N._address(row.get("src")) is None or N._address(row.get("dst")) is None:
                continue
            outgoing = fast.outgoing(Location(row["src"]))
            incoming = fast.incoming(Location(row["dst"]))
            shared = [item for item in outgoing if item.table == "Xrefs" and any(item is other for other in incoming)]
            self.assertTrue(shared)
            self.assertTrue(all(any(item is again for again in fast.outgoing(Location(row["src"])))
                                for item in shared))

    def test_any_non_native_xref_row_keeps_the_original_index(self):
        tables, cfgs = _tables(5)
        tables["Xrefs"].append({"src": 0x1000, "dst": 0x1010, "src_space": "ram", "kind": "ghidra"})
        fast, slow = self._pair(tables, cfgs)
        self.assertIsNone(fast._xref_points)
        self._assert_same(fast, slow, tables, self._probes(tables, 5)[:400])
        bytecode = AddressIndex({"Xrefs": [{"src": 16, "dst": 20, "kind": "call"}]}, kind="apk")
        self.assertIsNone(bytecode._xref_points)

    def test_unsorted_or_non_plain_disassembly_keeps_the_original_points(self):
        tables, cfgs = _tables(6)
        tables["Disassembly"][3], tables["Disassembly"][4] = tables["Disassembly"][4], tables["Disassembly"][3]
        fast, slow = self._pair(tables, cfgs)
        self.assertIs(type(fast._points[("", "native")]["Disassembly"]), tuple)
        self.assertIs(type(fast._points[("", "native")]["Disassembly"][0]), tuple)
        self._assert_same(fast, slow, tables, self._probes(tables, 6)[:400])
        tables, cfgs = _tables(7)
        tables["Disassembly"][10] = {**tables["Disassembly"][10], "kind": "dex"}
        fast, slow = self._pair(tables, cfgs)
        self.assertIs(type(fast._points[("", "native")]["Disassembly"][0]), tuple)
        self._assert_same(fast, slow, tables, self._probes(tables, 7)[:400])

    def test_index_borrows_rows_without_mutation(self):
        tables, cfgs = _tables(8)
        before = deepcopy(tables)
        index = AddressIndex(tables, cfgs, kind="elf")
        index.find_targets(Location(0x1004))
        index.incoming(Location(0x9002))
        self.assertEqual(tables, before)
        self.assertIs(index._rows["Disassembly"], tables["Disassembly"])

    def test_packed_intervals_match_tuple_intervals(self):
        rng = random.Random(9)
        values = [(start, start + rng.randrange(1, 50), identifier)
                  for identifier, start in enumerate(rng.randrange(0, 2000) for _ in range(500))]
        packed, plain = N._packed_intervals(values), N._Intervals(values)
        self.assertIs(type(packed), N._PackedIntervals)
        for address in range(0, 2100):
            self.assertEqual(packed.at(address), plain.at(address))
        overflow = N._packed_intervals([((1 << 64) - 1, 1 << 64, 0)])
        self.assertIs(type(overflow), N._Intervals)
        self.assertEqual(overflow.at((1 << 64) - 1), (0,))

    def test_cfg_block_table_returns_the_original_triples(self):
        tables, cfgs = _tables(10)
        index = AddressIndex(tables, cfgs, kind="elf")
        identifier = 0
        for cfg_index, cfg in enumerate(cfgs):
            for block_index, block in enumerate(cfg["graph"]["blocks"]):
                self.assertEqual(index._cfg_blocks[identifier],
                                 (cfg_index, block_index, Location(block["start"])))
                identifier += 1
        self.assertEqual(len(index._cfg_blocks), identifier)

    def test_prepared_full_result_matches_row_by_row_index(self):
        tables, cfgs = _tables(11)
        result = AnalysisResult("sample.bin", "elf", "kkagent", "partial",
                                metadata={"full_disassembly": tables["Disassembly"], "sections": tables["Sections"]},
                                functions=[{**function, "blocks": cfgs[i]["graph"]["blocks"]} if i < len(cfgs)
                                           else function for i, function in enumerate(tables["Functions"])],
                                strings=tables["Strings"],
                                xrefs=[row for row in tables["Xrefs"] if row is not None],
                                stats={"full_analysis": True})
        loaded = G._prepare(AnalysisView._from_owned_result(result), share_completed=True)
        slow = AddressIndex({name: _Rows(rows) for name, rows in loaded.tables.items()}, loaded.cfgs,
                            kind=loaded.kind)
        self.assertIsNotNone(loaded.navigation_index._xref_points)
        self._assert_same(loaded.navigation_index, slow, loaded.tables, self._probes(loaded.tables, 11)[:600])


if __name__ == "__main__":
    unittest.main()
