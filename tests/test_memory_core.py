"""完整分析 core 子系统的内存修复：值逐项不变，只减少重复对象与提前释放死局部变量。

  - _ReferenceStream.result() 核对后释放全部快照与逐区域引用列表，结果列表不再另建一份；
  - analyze_full 在 index_references 之前放开 cache/addresses/reached/种子表/原始指针候选/
    流对象/预览种子，统计值（unassigned、instruction_count、function_sources）不变；
  - _analyze_function(compact=True) 与缺省结果相等，地址复用记录自带的 int、块指令列表精确尺寸；
  - local_noreturn 的紧凑反向索引与按集合登记的原实现逐值相同；
  - index_references 的单函数直存索引与原两层结构逐对象、逐顺序相同；
  - 预览函数就地标注，键序与值同 {**item, "analysis_scope": ...}；
  - 别名保留只为起点命中 Loader 符号的函数建 (start, name)，追加结果不变。
"""
from __future__ import annotations

from contextlib import ExitStack
import copy
import importlib.util
import os
import random
import sys
import threading
import unittest
from typing import Any
from unittest.mock import patch

from fangida.core import kkagent
from fangida.core.kkagent import full_analysis, noreturn, semantic
from fangida.core.kkagent.full_analysis import _CachedDecoder
from fangida.models import AnalysisResult
from fangida.processors import full_decode
from fangida.xrefs import DataRangeIndex, XrefStage, index_references
from tests.test_full_xref_stream import _page_add, _serial
from tests.test_full_thread_matrix import BASE, _image

CAPSTONE_AVAILABLE = importlib.util.find_spec("capstone") is not None


def _record(address: int, size: int = 1, kind: str | None = None, target: int | None = None,
            conditional: bool = False) -> dict[str, Any]:
    return {"addr": address, "size": size, "mnemonic": "nop", "operands": (),
            "branch_info": ({"kind": kind, "target": target, "conditional": conditional}
                            if kind else {}),
            "arch_meta": {"engine": "test"}}


class ReferenceStreamReleaseTests(unittest.TestCase):
    def test_result_releases_snapshots_and_reuses_region_list(self) -> None:
        records = _page_add(0x1000, 0x5000, 0x10)
        with XrefStage(separate_thread=True) as stage:
            stream = full_analysis._ReferenceStream(stage, DataRangeIndex())
            stream([{"address": 0x1000}], 0, records)
            region_refs = stream._regions[0][2]
            result = stream.result(records)
        self.assertEqual(result, _serial(records, frozenset({0x1000})))
        # 单区域时直接沿用该区域的引用列表，不另建一份全量列表。
        self.assertIs(result, region_refs)
        self.assertIs(type(result), list)
        self.assertEqual(stream._regions, {})
        self.assertEqual(len(stream._futures), 0)

    def test_multiple_regions_merge_in_address_order(self) -> None:
        low = _page_add(0x1000, 0x5000, 0x10)
        high = _page_add(0x2000, 0x6000, 0x20)
        regions = [{"address": 0x2000}, {"address": 0x1000}]
        with XrefStage(separate_thread=True) as stage:
            stream = full_analysis._ReferenceStream(stage, DataRangeIndex())
            stream(regions, 0, high)
            stream(regions, 1, low)
            result = stream.result(low + high)
        self.assertEqual(result, _serial(low + high, frozenset({0x1000, 0x2000})))
        self.assertEqual([ref["dst"] for ref in result], [0x5010, 0x6020])
        self.assertEqual(stream._regions, {})

    def test_fallback_also_releases(self) -> None:
        records = _page_add(0x1000, 0x5000, 0x10)
        with XrefStage(separate_thread=True) as stage:
            stream = full_analysis._ReferenceStream(stage, DataRangeIndex())
            stream([{"address": 0x1000}], 0, records)
            self.assertIsNone(stream.result([dict(item) for item in records]))
        self.assertEqual(stream._regions, {})
        self.assertEqual(len(stream._futures), 0)


# 在 index_references 时刻必须已放开（None）的 analyze_full 局部变量。
_RELEASED = ("cache", "addresses", "reached", "known", "seeds", "pending", "seeds_by_start",
             "raw_candidates", "stream", "stream_options", "preview_functions", "preview_coverage")


@unittest.skipUnless(CAPSTONE_AVAILABLE, "Capstone is required for the synthetic x86-64 image")
class AnalyzeFullReleaseTests(unittest.TestCase):
    def _run(self, workers: int, image_functions: list[dict[str, Any]] | None = None):
        data, image = _image()
        if image_functions is not None:
            image.functions = image_functions
        main = threading.main_thread().ident
        seen: dict[str, Any] = {}
        original = full_analysis.index_references

        def probe(functions, references):
            # index_references 在 xref 线程执行；从主线程栈上找到 analyze_full 的帧检查局部变量。
            frame = sys._current_frames()[main]
            while frame is not None and frame.f_code is not full_analysis.analyze_full.__code__:
                frame = frame.f_back
            seen["thread"] = threading.current_thread().name
            seen["locals"] = {name: frame.f_locals.get(name, "unbound") for name in _RELEASED}
            return original(functions, references)

        previews: list[Any] = []
        with ExitStack() as stack:
            if workers > 1:
                # 与 test_full_xref_stream 相同：小样本也走进程解码路径，使引用分析流式完成。
                stack.enter_context(patch.object(full_decode, "_PROCESS_MIN_BYTES", 0x1000))
                stack.enter_context(patch.object(full_decode, "_PROCESS_MIN_PIECE_BYTES", 0x400))
                stack.enter_context(patch.object(full_decode, "_PROCESS_PIECE_BYTES", 0x800))
                stack.enter_context(patch.object(full_decode, "_process_mismatch", False))
                stack.enter_context(patch.dict(os.environ, {"FANGIDA_DECODE_PROCESSES": ""}))
            stack.enter_context(patch.object(full_analysis, "index_references", probe))
            stage = stack.enter_context(XrefStage(separate_thread=workers > 1))
            result = full_analysis.analyze_full(
                data, image, workers=workers, xref_stage=stage,
                on_decoded=lambda *args: previews.append(len(args[2])))
        return result, seen, previews

    def test_dead_locals_are_released_before_xref_index(self) -> None:
        for workers in (1, 3):
            with self.subTest(workers=workers):
                (functions, refs, stats, metadata, _), seen, previews = self._run(workers)
                self.assertTrue(previews)
                self.assertEqual({name: value for name, value in seen["locals"].items()
                                  if value is not None}, {})
                if workers > 1:
                    # 引用索引仍在独立的 xref 线程执行。
                    self.assertTrue(seen["thread"].startswith("fangida-xref"))
                    self.assertTrue(stats["full_xref_streamed"])
                records = metadata["full_disassembly"]
                union = {ins["addr"] for fn in functions for block in fn.get("blocks") or ()
                         for ins in block["instructions"]}
                addresses = {record["addr"] for record in records}
                self.assertEqual(stats["full_instructions"], len(records))
                self.assertEqual(metadata["full_analysis"]["instruction_count"], len(records))
                self.assertEqual(stats["semantic_instructions"], len(union))
                self.assertEqual(stats["full_unassigned_instructions"], len(addresses - union))
                self.assertEqual(metadata["full_analysis"]["unassigned_instructions"],
                                 len(addresses - union))
                self.assertTrue(stats["full_xref_pass_complete"])
                self.assertIs(type(stats["full_function_sources"]), dict)
                self.assertIn("executable_region", stats["full_function_sources"])
                # 块起点、跨块落空边与后继复用指令记录自带的 int（完整模式 compact=True）。
                by_value = {record["addr"]: record for record in records}
                for fn in functions:
                    for block in fn.get("blocks") or ():
                        self.assertIs(block["start"], block["instructions"][0]["addr"])
                        for ins in block["instructions"]:
                            self.assertIs(ins, by_value[ins["addr"]])
                    for edge in (fn.get("cfg") or {}).get("edges", ()):
                        if edge["kind"] == "fallthrough":
                            self.assertIs(edge["dst"], by_value[edge["dst"]]["addr"])
                # xrefs_in/out 仍是 refs 中的同一批对象。
                ids = {id(ref) for ref in refs}
                self.assertTrue(all(id(ref) in ids for fn in functions
                                    for key in ("xrefs_in", "xrefs_out") for ref in fn.get(key, ())))

    def test_symbol_aliases_are_retained_exactly_once(self) -> None:
        symbols = [{"name": "main", "start": BASE, "size": None},
                   {"name": "main_alias", "start": BASE, "size": None},
                   {"name": "far", "start": 0x900000, "size": None}]
        (functions, _, _, _, _), _, _ = self._run(1, symbols)
        named = [(fn["name"], fn["start"], fn["analysis_scope"]) for fn in functions
                 if fn["start"] in {BASE, 0x900000}]
        self.assertEqual(sorted(named), sorted([
            ("main", BASE, "full_region_recovered_function"),
            ("main_alias", BASE, "not_decoded"),
            ("far", 0x900000, "not_decoded")]))


class CompactCfgTests(unittest.TestCase):
    def _cache(self) -> dict[int, dict[str, Any]]:
        # 0x1000 nop；0x1001 条件跳 0x1006（落空 0x1003 成为新块）；0x1003 nop；
        # 0x1004 nop（0x1009 跳回这里，成为块首，于是 0x1003→0x1004 是跨块落空边）；
        # 0x1005 nop；0x1006 nop ×3；0x1009 条件跳 0x1004；0x100b ret。
        rows = [_record(0x1000), _record(0x1001, 2, "jump", 0x1006, True), _record(0x1003),
                _record(0x1004), _record(0x1005), _record(0x1006), _record(0x1007), _record(0x1008),
                _record(0x1009, 2, "jump", 0x1004, True), _record(0x100B, 1, "return")]
        return {row["addr"]: row for row in rows}

    def _analyze(self, cache, compact: bool):
        addresses = sorted(cache)
        regions = [semantic._Region(0x1000, 0, 0x100)]
        decoder = _CachedDecoder(cache, addresses, regions, 0x1000, None, "test")
        seed = {"name": "f", "start": 0x1000, "size": None, "source": "test"}
        return semantic._analyze_function(seed, decoder, {0x1000}, set(), 64, 64,
                                          validate_overlaps=False, collect_xrefs=False,
                                          compute_liveness=False, compact=compact)

    def test_compact_result_equals_default_and_reuses_record_ints(self) -> None:
        cache = self._cache()
        plain = self._analyze(cache, False)
        compact = self._analyze(cache, True)
        self.assertEqual(compact, plain)
        function, _, _, seen = compact
        self.assertEqual(type(function["blocks"]), list)
        self.assertGreater(len(function["blocks"]), 3)
        fallthrough = [edge for edge in function["cfg"]["edges"] if edge["kind"] == "fallthrough"]
        self.assertTrue(fallthrough)
        for block in function["blocks"]:
            members = block["instructions"]
            self.assertIs(type(members), list)
            self.assertIs(block["start"], members[0]["addr"])
            self.assertTrue(all(ins is cache[ins["addr"]] for ins in members))
            # 精确尺寸：与切片拷贝（容量等于长度）占用相同。
            self.assertEqual(sys.getsizeof(members), sys.getsizeof(members[:]))
            for successor in block["successors"]:
                self.assertIs(type(successor), int)
        for edge in fallthrough:
            self.assertIs(edge["dst"], cache[edge["dst"]]["addr"])
            self.assertIs(edge["src"], cache[edge["src"]]["addr"])
        self.assertTrue(all(address is cache[address]["addr"] for address in seen))
        # 缺省路径不变：落空地址仍是新算出的 int（不要求复用）。
        _, _, _, default_seen = plain
        self.assertEqual(default_seen, seen)


def _reference_local_noreturn(functions, targets, sites=None, *,
                              max_rounds=noreturn.MAX_FIXED_POINT_ROUNDS):
    """原实现（反向索引每项一个集合），用作逐值对照。"""
    sites = sites or {}
    summaries, sources, first_round = {}, {}, {}
    callers: dict[int, set[int]] = {}
    call_sites: dict[int, set[int]] = {}
    for function in functions:
        if not isinstance(function, dict):
            continue
        cfg = function.get("cfg")
        scanned = (noreturn._scan(function, targets, sites)
                   if isinstance(cfg, dict) and cfg.get("scope") in noreturn._TRUSTED_SCOPES else None)
        if scanned is None:
            summary = noreturn._summary(function)
            if summary is None or summary[0] in sources:
                continue
            start, blocks, dependencies, called = summary
            summaries[start] = (start, blocks)
        else:
            start, dependencies, called, verdict = scanned
            if start in sources:
                continue
            if verdict is not None:
                first_round[start] = verdict
        sources[start] = function
        for dependency in dependencies:
            if dependency not in targets:
                callers.setdefault(dependency, set()).add(start)
        for target in called:
            if target not in targets:
                call_sites.setdefault(target, set()).add(start)

    def may_return(start):
        verdict = first_round.pop(start, None)
        if verdict is not None:
            return verdict
        summary = summaries.get(start)
        if summary is None:
            return noreturn._may_return_blocks(sources[start], current, sites)
        return noreturn._may_return(*summary, current, sites)

    current = dict(targets)
    found: dict[int, dict[str, Any]] = {}
    pending = sorted(start for start in sources if start not in current)
    rounds = 0
    while pending and rounds < max_rounds:
        rounds += 1
        new = [start for start in pending if not may_return(start)]
        first_round.clear()
        if not new:
            break
        for start in new:
            name = sources[start].get("name")
            evidence = {"name": name if isinstance(name, str) else f"sub_{start:x}",
                        "evidence": "local_fixed_point", "round": rounds}
            current[start] = found[start] = evidence
        pending = sorted({caller for start in new for caller in callers.get(start, ())}
                         - current.keys())
    rebuild = sorted({caller for start in found for caller in call_sites.get(start, ())})
    return found, rebuild, rounds


def _call_graph(rng: random.Random, count: int, scope: str) -> list[dict[str, Any]]:
    """随机调用图：每个函数一串“调用；…”块，末尾以返回或调用 abort 结束。"""
    functions = []
    for index in range(count):
        start = 0x10000 + 0x100 * index
        blocks = []
        callees = rng.sample(range(count), rng.randrange(0, 4))
        address = start
        for callee in callees:
            blocks.append({"start": address,
                           "instructions": [_record(address, 1, "call", 0x10000 + 0x100 * callee)],
                           "successors": [address + 1]})
            address += 1
        tail = rng.random()
        if tail < 0.4:
            row = _record(address, 1, "return")
        elif tail < 0.7:
            row = _record(address, 1, "call", 0x900000)   # abort
        else:
            row = _record(address, 1, "call", 0x10000 + 0x100 * rng.randrange(count))
        blocks.append({"start": address, "instructions": [row],
                       "successors": [address + 1] if row["branch_info"].get("kind") == "call" else []})
        if row["branch_info"].get("kind") == "call":
            address += 1
            blocks.append({"start": address, "instructions": [_record(address, 1, "return")],
                           "successors": []})
        functions.append({"start": start, "name": f"f{index}", "blocks": blocks,
                          "cfg": {"scope": scope, "frontier": []}})
    return functions


class LocalNoreturnIndexTests(unittest.TestCase):
    def test_index_matches_set_registration(self) -> None:
        rng = random.Random(11)
        index: dict[int, Any] = {}
        reference: dict[int, set[int]] = {}
        for start in range(1000, 1400):
            for key in rng.sample(range(3000), rng.randrange(0, 6)):
                noreturn._index_add(index, key, start)
                reference.setdefault(key, set()).add(start)
        for key in range(3100):
            members = noreturn._index_get(index, key)
            self.assertEqual(len(members), len(set(members)))
            self.assertEqual(set(members), reference.get(key, set()))
        # 只有一个登记者时直接存值，不建容器。
        singles = [key for key, value in reference.items() if len(value) == 1]
        self.assertTrue(singles)
        self.assertTrue(all(type(index[key]) is int for key in singles))

    def test_multiple_callers_reach_the_same_fixed_point(self) -> None:
        def function(start, callee):
            return {"start": start, "name": f"f{start:x}",
                    "cfg": {"scope": "full_region_recovered_function", "frontier": []},
                    "blocks": [{"start": start, "instructions": [_record(start, 1, "call", callee)],
                                "successors": [start + 1]},
                               {"start": start + 1, "instructions": [_record(start + 1, 1, "return")],
                                "successors": []}]}

        # A 调 abort；B、C 都调 A（A 有两个调用者）；D 调 B。
        graph = [function(0x100, 0x900), function(0x200, 0x100), function(0x300, 0x100),
                 function(0x400, 0x200)]
        found, rebuild, rounds = noreturn.local_noreturn(graph, {0x900: {"name": "abort"}})
        self.assertEqual(sorted(found), [0x100, 0x200, 0x300, 0x400])
        self.assertEqual(rebuild, [0x200, 0x300, 0x400])
        self.assertEqual(rounds, 3)

    def test_random_graphs_match_set_based_reference(self) -> None:
        for seed in range(40):
            rng = random.Random(seed)
            scope = "full_region_recovered_function" if seed % 2 else "external_graph"
            graph = _call_graph(rng, rng.randrange(5, 60), scope)
            targets = {0x900000: {"name": "abort"}}
            if seed % 3 == 0 and graph:
                targets[graph[0]["start"]] = {"name": "known"}
            with self.subTest(seed=seed):
                self.assertEqual(noreturn.local_noreturn(graph, targets),
                                 _reference_local_noreturn(graph, targets))
                self.assertEqual(noreturn.local_noreturn(graph, targets, max_rounds=2),
                                 _reference_local_noreturn(graph, targets, max_rounds=2))


def _reference_index_references(functions, references) -> None:
    """原实现：源地址集合 + 每个源一个函数列表 + 每个起点一个函数列表。"""
    references = list(references)
    sources = {reference["src"] for reference in references}
    by_start: dict[int, list[dict[str, Any]]] = {}
    by_instruction: dict[int, list[dict[str, Any]]] = {}
    for function in functions:
        by_start.setdefault(function["start"], []).append(function)
        for block in function.get("blocks", []):
            for instruction in block["instructions"]:
                address = instruction["addr"]
                if address in sources:
                    by_instruction.setdefault(address, []).append(function)
    for reference in references:
        for target in by_start.get(reference["dst"], []):
            target.setdefault("xrefs_in", []).append(reference)
        for source in by_instruction.get(reference["src"], []):
            source.setdefault("xrefs_out", []).append(reference)


class IndexReferencesTests(unittest.TestCase):
    def _functions(self, rng: random.Random) -> list[dict[str, Any]]:
        functions = []
        for index in range(30):
            start = 0x1000 + 0x10 * rng.randrange(25)          # 允许多个函数同起点
            blocks = []
            for _ in range(rng.randrange(0, 4)):
                first = 0x1000 + rng.randrange(0x200)
                blocks.append({"start": first,
                               "instructions": [_record(first + offset) for offset in range(rng.randrange(1, 5))]})
            if blocks and rng.random() < 0.2:
                blocks.append(blocks[0])                         # 同一函数内重复的块
            function = {"start": start, "name": f"f{index}", "blocks": blocks}
            if rng.random() < 0.5:
                function["xrefs_in"], function["xrefs_out"] = [], []
            functions.append(function)
        functions.append(functions[0])                           # 同一函数对象出现两次
        return functions

    def test_matches_original_two_level_index(self) -> None:
        for seed in range(60):
            rng = random.Random(seed)
            functions = self._functions(rng)
            references = [{"src": 0x1000 + rng.randrange(0x210), "dst": 0x1000 + 0x10 * rng.randrange(30),
                           "kind": rng.choice(("call", "jmp", "data"))} for _ in range(rng.randrange(0, 120))]
            ours, theirs = copy.deepcopy(functions), copy.deepcopy(functions)
            index_references(ours, references if seed % 2 else tuple(references))
            _reference_index_references(theirs, references)
            with self.subTest(seed=seed):
                self.assertEqual(ours, theirs)
                ids = [id(reference) for reference in references]
                for mine, other in zip(ours, theirs):
                    for key in ("xrefs_in", "xrefs_out"):
                        self.assertEqual([ids.index(id(ref)) for ref in mine.get(key, ())],
                                         [ids.index(id(ref)) for ref in other.get(key, ())])

    def test_iterator_input_is_accepted(self) -> None:
        functions = [{"start": 0x10, "blocks": [{"instructions": [_record(0x10), _record(0x11)]}]}]
        references = [{"src": 0x11, "dst": 0x10, "kind": "jmp"}]
        index_references(functions, iter(references))
        self.assertEqual(functions[0]["xrefs_in"], references)
        self.assertEqual(functions[0]["xrefs_out"], references)
        self.assertIs(functions[0]["xrefs_out"][0], references[0])


class PreviewFunctionsTests(unittest.TestCase):
    def test_in_place_scope_keeps_order_and_values(self) -> None:
        fresh = [{"name": "a", "start": 1, "size": None},
                 {"name": "b", "analysis_scope": "x", "start": 2}]
        expected = [{**item, "analysis_scope": "preview_declared_root"} for item in fresh]
        originals = list(fresh)
        result = AnalysisResult("p", "elf", "kkagent", "partial")
        preview = kkagent._preview_result(result, [], [], fresh)
        self.assertEqual(preview.functions, expected)
        self.assertEqual([list(item) for item in preview.functions], [list(item) for item in expected])
        self.assertTrue(all(item is original for item, original in zip(preview.functions, originals)))
        self.assertIsNot(preview.functions, fresh)
        self.assertTrue(all(type(item) is dict for item in preview.functions))

    def test_non_dict_items_are_copied(self) -> None:
        from collections import OrderedDict
        item = OrderedDict(name="a", start=1)
        scoped = kkagent._preview_functions([item])
        self.assertEqual(scoped, [{"name": "a", "start": 1, "analysis_scope": "preview_declared_root"}])
        self.assertIs(type(scoped[0]), dict)
        self.assertNotIn("analysis_scope", item)

    def test_default_path_still_copies_result_functions(self) -> None:
        result = AnalysisResult("p", "elf", "kkagent", "partial", functions=[{"name": "a", "start": 1}])
        preview = kkagent._preview_result(result, [], [])
        self.assertEqual(preview.functions, result.functions)
        self.assertIsNot(preview.functions[0], result.functions[0])


if __name__ == "__main__":
    unittest.main()
