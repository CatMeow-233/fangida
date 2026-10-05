"""默认（deep）模式语义分析热点的等价性与规模守护。

重叠检查改用有序地址索引后，返回值、原因字符串、窗口计数、告警与缓存内容
（含插入顺序）都必须与改动前的整表线性扫描逐值一致。规模测试只统计指令
长度的读取次数，不依赖墙钟，避免 CI 抖动误报。
"""
from __future__ import annotations

import random
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fangida.core.kkagent import semantic
from fangida.core.kkagent.binary import parse_binary
from fangida.core.kkagent.test_semantic import DECODER_AVAILABLE, _sample


class _SyntheticProcessor:
    """按字节值给出 1..5 字节的变长指令；不同窗口起点会得到互相交错的指令流。"""

    engine = "synthetic"
    warning = None

    def decode_bytes(self, chunk: bytes, address: int, max_instructions: int = 128):
        if chunk[:1] == b"\xfd":
            raise ValueError("synthetic failure")
        instructions, offset = [], 0
        while offset < len(chunk) and len(instructions) < max_instructions:
            value = chunk[offset]
            mnemonic = "(bad)" if value == 0xFF else ".byte" if value == 0xFE else "op"
            # 末条指令可能越过窗口末尾，用来覆盖 decode 的越界过滤。
            instructions.append({"addr": address + offset, "size": value % 5 + 1,
                                 "mnemonic": mnemonic, "branch_info": {}})
            offset += value % 5 + 1
        return instructions, ([] if instructions else ["empty window"])


class _LinearDecoder(semantic._Decoder):
    """改动前 _Decoder.decode 的副本（每次整表线性扫描），作为等价参照。"""

    def decode(self, address, limit=None):
        if any(start < address < start + ins["size"] for start, ins in self.cache.items()):
            return None, "overlapping_decode"
        if address in self.cache:
            instruction = self.cache[address]
            if limit is not None and address + instruction["size"] > limit:
                return None, "symbol_end"
            return instruction, None
        if self.engine == "none":
            return None, "decoder_unavailable"
        region = self.region(address)
        if region is None:
            return None, "outside_executable"
        if limit is not None and address >= limit:
            return None, "symbol_end"
        if self.windows >= self.max_windows:
            return None, "window_limit"
        end = min(region.address + region.size, address + semantic.WINDOW_BYTES)
        if limit is not None:
            end = min(end, limit)
        offset = region.offset + address - region.address
        chunk = self.data[offset:offset + end - address]
        if not chunk:
            return None, "outside_scan"
        self.windows += 1
        try:
            instructions, warnings = self._processor.decode_bytes(chunk, address, max_instructions=128)
            if warnings and self.warning is None:
                self.warning = warnings[0]
        except Exception as exc:
            instructions = []
            if self.warning is None:
                self.warning = f"Capstone decode failed: {type(exc).__name__}: {exc}"
        for ins in instructions:
            if (ins["size"] > 0 and ins["addr"] + ins["size"] <= end and
                    not ins["mnemonic"].startswith(".") and
                    ins["mnemonic"] not in {"(bad)", "bad", "<unknown>"}):
                self.cache.setdefault(ins["addr"], ins)
        instruction = self.cache.get(address)
        return (instruction, None) if instruction is not None else (None, "undecoded")


class _CountingInstruction(dict):
    """统计 "size" 读取次数：规模守护用比较工作量代替墙钟。"""

    reads = 0

    def __getitem__(self, key):
        if key == "size":
            _CountingInstruction.reads += 1
        return dict.__getitem__(self, key)


def _ins(address: int, size: int) -> dict:
    return {"addr": address, "size": size, "mnemonic": "op", "branch_info": {}}


def _decoders(data: bytes, regions: list, cls=semantic._Decoder, **options):
    image = SimpleNamespace(architecture="synthetic", endian="little")
    with patch.object(semantic, "get_processor", lambda *_: _SyntheticProcessor()):
        return cls(data, image, regions, **options)


def _linear_inside(cache: dict, address: int) -> bool:
    return any(start < address < start + ins["size"] for start, ins in cache.items())


class DecoderOverlapIndexTests(unittest.TestCase):
    def assert_same(self, new, old) -> None:
        self.assertEqual(list(new.cache.items()), list(old.cache.items()))
        self.assertEqual((new.windows, new.warning), (old.windows, old.warning))

    def test_boundaries_match_linear_scan(self) -> None:
        cache = {start: _ins(start, size) for start, size in (
            (0x100, 4), (0x104, 2),                       # 相邻：0x104 不在 0x100 内
            (0x110, 15), (0x112, 1), (0x114, 3), (0x11E, 2),  # 长指令跨过多个短指令
            (0x130, 1), (0x131, 1))}
        new = _decoders(b"", [], cache=dict(cache))
        old = _decoders(b"", [], cls=_LinearDecoder, cache=dict(cache))
        for address in range(0xF0, 0x140):
            with self.subTest(address=hex(address)):
                self.assertEqual(new._inside_cached(address), _linear_inside(cache, address))
                for limit in (None, address, address + 1, address + 4):
                    self.assertEqual(new.decode(address, limit), old.decode(address, limit))
        # 0x113 的有序前驱 0x112 已结束，只有更早的 0x110 跨过它：不能只看前驱。
        self.assertTrue(new._inside_cached(0x113))
        self.assertFalse(new._inside_cached(0x104))
        self.assertEqual(new.decode(0x100), (cache[0x100], None))
        self.assertEqual(new.decode(0x112), (None, "overlapping_decode"))

    def test_cross_window_streams_match_linear_scan(self) -> None:
        data = bytes([3]) * 0x600  # 全是 4 字节指令；窗口起点错开 1 字节即得到交错指令流。
        regions = [semantic._Region(0x1000, 0, len(data))]
        new = _decoders(data, regions)
        old = _decoders(data, regions, cls=_LinearDecoder)
        for address in (0x1000, 0x1202, 0x1201, 0x1202, 0x1200, 0x1203, 0x1205, 0x1204, 0x11FC):
            with self.subTest(address=hex(address)):
                self.assertEqual(new.decode(address), old.decode(address))
                self.assert_same(new, old)
        # 0x1205 是缓存中的精确起点，但被另一条流的 0x1204 跨过，仍是歧义。
        self.assertIn(0x1205, new.cache)
        self.assertEqual(new.decode(0x1205), (None, "overlapping_decode"))

    def test_random_decode_sequences_match_linear_scan(self) -> None:
        for seed in range(30):
            rng = random.Random(seed)
            data = bytes(rng.randrange(256) for _ in range(1500))
            regions = [semantic._Region(0x1000, 0, 700), semantic._Region(0x1400, 700, 800)]
            windows = rng.choice([3, 8, 64])
            new = _decoders(data, regions, max_windows=windows)
            old = _decoders(data, regions, cls=_LinearDecoder, max_windows=windows)
            for step in range(150):
                starts = list(new.cache)
                choice = rng.randrange(5)
                if starts and choice:
                    start = rng.choice(starts)
                    address = start + (0, 1, new.cache[start]["size"], -1)[choice - 1]
                else:
                    address = rng.randrange(0xFF0, 0x1400 + 820)
                limit = rng.choice([None, None, address + rng.randrange(0, 24), address - 1])
                with self.subTest(seed=seed, step=step, address=hex(address)):
                    self.assertEqual(new.decode(address, limit), old.decode(address, limit))
                    self.assert_same(new, old)
            self.assertEqual(new._starts, sorted(new.cache))

    def test_external_cache_writes_and_replacement_are_seen(self) -> None:
        decoder = _decoders(b"", [], cache={0x10: _ins(0x10, 4)})
        self.assertTrue(decoder._inside_cached(0x12))
        decoder.cache[0x20] = _ins(0x20, 8)  # 旧代码可直接写 cache：按条目数发现并重建。
        self.assertTrue(decoder._inside_cached(0x26))
        decoder.cache = {0x30: _ins(0x30, 2)}  # 整体替换：按对象身份发现。
        self.assertFalse(decoder._inside_cached(0x12))
        self.assertTrue(decoder._inside_cached(0x31))
        decoder.cache = {}
        self.assertFalse(decoder._inside_cached(0x31))

    def test_decode_and_region_stay_patchable_on_the_class(self) -> None:
        decoded: list[int] = []
        located: list[int] = []
        original_decode, original_region = semantic._Decoder.decode, semantic._Decoder.region

        def decode(self, address, limit=None):
            decoded.append(address)
            return original_decode(self, address, limit)

        def region(self, address):
            located.append(address)
            return original_region(self, address)

        decoder = _decoders(bytes([3]) * 64, [semantic._Region(0x10, 0, 64)])
        with patch.object(semantic._Decoder, "decode", decode), \
                patch.object(semantic._Decoder, "region", region):
            seed = {"start": 0x10, "size": 8, "name": "f"}
            semantic._analyze_function(seed, decoder, {0x10}, set(), 64, 64, collect_xrefs=False)
        self.assertEqual(decoded, [0x10, 0x14])
        # 0x10 来自 decode 内部开窗，0x14 来自落空后继检查。
        self.assertEqual(located, [0x10, 0x14])

    def test_decode_work_is_bounded_by_instruction_length_not_cache_size(self) -> None:
        count = 20_000
        cache = {0x10000 + 4 * index: _CountingInstruction(_ins(0x10000 + 4 * index, 4))
                 for index in range(count)}
        # 另一条错开 2 字节的流，模拟不同窗口的交错缓存。
        cache.update({0x10002 + 8 * index: _CountingInstruction(_ins(0x10002 + 8 * index, 4))
                      for index in range(0, count // 2, 50)})
        decoder = _decoders(b"", [], cache=cache)
        rng = random.Random(7)
        probes = [0x10000 + rng.randrange(4 * count) for _ in range(2_000)]
        _CountingInstruction.reads = 0
        for address in probes:
            decoder.decode(address)
        # 首次查询建索引时读一遍长度；之后每次只看 (address - 4, address) 内的起点。
        rebuild = len(cache)
        self.assertLessEqual(_CountingInstruction.reads, rebuild + len(probes) * 8)
        # 参照：原线性扫描每次要读所有更小起点的长度，规模相差数个数量级。
        linear = _decoders(b"", [], cls=_LinearDecoder, cache=cache)
        _CountingInstruction.reads = 0
        for address in probes[:10]:
            linear.decode(address)
        self.assertGreater(_CountingInstruction.reads, 10 * 1000)

    def test_crosses_accepted_matches_linear_scan(self) -> None:
        for seed in range(200):
            rng = random.Random(seed)
            instructions: dict[int, dict] = {}
            ordered: list[int] = []
            for _ in range(60):
                address, size = rng.randrange(0x100, 0x180), rng.randrange(1, 9)
                if address in instructions:
                    continue
                expected = any(old < address < old + previous["size"] or
                               address < old < address + size
                               for old, previous in instructions.items())
                crossed, position = semantic._crosses_accepted(ordered, instructions, address, size)
                self.assertEqual(crossed, expected, (seed, address, size))
                if not crossed:
                    ordered.insert(position, address)
                    instructions[address] = _ins(address, size)
            self.assertEqual(ordered, sorted(instructions))

    def test_crosses_accepted_reads_at_most_neighbours(self) -> None:
        # 512 条（单函数上限）已接受指令，间隔 8、长度 4：探测点既有跨越也有落在空隙的。
        instructions = {8 * index: _CountingInstruction(_ins(8 * index, 4)) for index in range(512)}
        ordered = sorted(instructions)
        probes = [address for address in range(8 * 512) if address not in instructions]
        _CountingInstruction.reads = 0
        crossed = sum(semantic._crosses_accepted(ordered, instructions, address, 2)[0]
                      for address in probes)
        self.assertTrue(0 < crossed < len(probes))
        # 每次至多读一次有序前驱的长度；原扫描每次要比较全部已接受指令。
        self.assertLessEqual(_CountingInstruction.reads, len(probes))

    def test_analyze_function_reports_the_same_overlap_frontier(self) -> None:
        table = {
            0x10: (4, {"kind": "jump", "target": 0x12, "conditional": True}),
            0x12: (2, {}),                      # 落在 0x10 内部：前驱跨越
            0x14: (3, {"kind": "jump", "target": 0x20, "conditional": True}),
            0x17: (1, {"kind": "jump", "target": 0x1E}),
            0x20: (2, {"kind": "return"}),
            0x1E: (4, {"kind": "return"}),       # 跨过已接受的 0x20：后继跨越
        }

        class Stub:
            windows, cache, engine = 0, {}, "none"
            regions = [semantic._Region(0x10, 0, 0x40)]

            def region(self, address):
                return self.regions[0] if self.regions[0].contains(address) else None

            def decode(self, address, limit=None):
                size, branch = table[address]
                return {**_ins(address, size), "branch_info": branch}, None

        seed = {"start": 0x10, "size": None, "name": "f"}
        function, *_ = semantic._analyze_function(seed, Stub(), {0x10}, set(), 64, 64,
                                                  collect_xrefs=False, compute_liveness=False)
        self.assertEqual(function["cfg"]["frontier"], [
            {"from": 0x10, "to": 0x12, "reason": "overlapping_decode"},
            {"from": 0x17, "to": 0x1E, "reason": "overlapping_decode"}])
        self.assertEqual(sorted(ins["addr"] for block in function["blocks"]
                                for ins in block["instructions"]), [0x10, 0x14, 0x17, 0x20])


class ParallelBookkeepingTests(unittest.TestCase):
    def test_private_cache_matches_the_old_copy_and_is_private(self) -> None:
        rng = random.Random(3)
        cache = {}
        # 区间两端恰好有起点：半开区间 [address, address + size) 只含左端。
        for address in [0x10FF, 0x1100, 0x117F, 0x1180, 0x1200] + [
                rng.randrange(0x1000, 0x1400) for _ in range(400)]:
            cache.setdefault(address, _ins(address, rng.randrange(1, 9)))
        decoder = _decoders(b"", [], cache=cache)
        for address, size in ((0x1100, 0x80), (0x1000, 1), (0x13F0, 0x100), (0x1200, 0), (0x1200, None)):
            with self.subTest(address=hex(address), size=size):
                expected = {old: ins for old, ins in cache.items()
                            if size is None or address <= old < address + size}
                cached, (starts, max_size) = semantic._private_cache(decoder, address, size)
                self.assertEqual(cached, expected)
                self.assertTrue(all(cached[key] is expected[key] for key in expected))
                if size is None:
                    self.assertEqual(list(cached), list(expected))
                self.assertEqual(starts, sorted(cached))
                self.assertGreaterEqual(max_size, max((ins["size"] for ins in cached.values()), default=0))
                self.assertIsNot(cached, decoder.cache)
                self.assertIsNot(starts, decoder._starts)
                worker = _decoders(b"", [], cache=cached)
                worker._adopt_index(starts, max_size)
                for probe in range(address - 8, address + 16):
                    self.assertEqual(worker._inside_cached(probe), _linear_inside(cached, probe))
        snapshot = list(decoder._starts)
        cached, (starts, _) = semantic._private_cache(decoder, 0x1000, None)
        cached[0x9999] = _ins(0x9999, 1)
        starts.append(0x9999)
        self.assertNotIn(0x9999, decoder.cache)
        self.assertEqual(decoder._starts, snapshot)

    def test_merge_replacing_an_entry_with_a_longer_one_is_seen(self) -> None:
        main = _decoders(b"", [], cache={0x100: _ins(0x100, 2), 0x110: _ins(0x110, 2)})
        other = _decoders(b"", [], cache={0x110: _ins(0x110, 12)})
        main._ordered_starts()
        other._ordered_starts()
        main._merge_from(other)  # 条目数不变，只是同一地址换成更长的指令。
        self.assertEqual(main.cache[0x110]["size"], 12)
        self.assertTrue(main._inside_cached(0x115))
        self.assertEqual(main.decode(0x11B), (None, "overlapping_decode"))

    def test_merge_from_equals_update_and_keeps_index_exact(self) -> None:
        for seed in range(50):
            rng = random.Random(seed)
            base = {}
            for _ in range(rng.randrange(0, 60)):
                address = rng.randrange(0x100, 0x200)
                base.setdefault(address, _ins(address, rng.randrange(1, 6)))
            main = _decoders(b"", [], cache=dict(base))
            reference = dict(base)
            other_cache = {old: ins for old, ins in base.items() if rng.random() < 0.5}
            for _ in range(rng.randrange(0, 40)):
                address = rng.randrange(0x80, 0x280)
                other_cache.setdefault(address, _ins(address, rng.randrange(1, 12)))
            other = _decoders(b"", [], cache=other_cache)
            if rng.random() < 0.7:
                main._ordered_starts()
            if rng.random() < 0.7:
                other._ordered_starts()
            main._merge_from(other)
            reference.update(other_cache)
            self.assertEqual(list(main.cache.items()), list(reference.items()))
            for probe in range(0x78, 0x290):
                self.assertEqual(main._inside_cached(probe), _linear_inside(reference, probe))
            self.assertEqual(main._starts, sorted(reference))

    def test_each_independence_rule_on_minimal_batches(self) -> None:
        def result(reached=(), fresh=(), frontier=(), targets=()):
            cache = {address: _ins(address, size) for address, size in fresh}
            blocks = [{"start": address, "instructions": [_ins(address, size)]}
                      for address, size in reached]
            return ({"blocks": blocks, "cfg": {"frontier": [{"to": to} for to in frontier]}},
                    [], set(targets), {address for address, _ in reached},
                    SimpleNamespace(cache=cache), 0)

        cases = [  # (说明, 先提交结果, 后提交结果, 后者符号长度, 期望)
            ("相邻已到达区间", result([(0x100, 4)]), result([(0x104, 4)]), None, True),
            ("已到达区间重叠", result([(0x100, 4)]), result([(0x103, 2)]), None, False),
            ("先者起点在后者前沿", result([(0x100, 2)]), result([(0x140, 2)], frontier=[0x100]),
             None, False),
            ("新解码区间重叠", result(fresh=[(0x120, 4)]), result(fresh=[(0x123, 1)]), None, False),
            ("新解码区间相邻", result(fresh=[(0x120, 4)]), result(fresh=[(0x124, 1)]), None, True),
            ("先者新解码覆盖后者已到达", result(fresh=[(0x120, 4)]), result([(0x122, 1)]),
             None, False),
            # 原实现不检查“先者已到达 x 后者新解码”，快速路径必须保留这一不对称。
            ("先者已到达对后者新解码不检查", result([(0x120, 4)]), result(fresh=[(0x122, 1)]),
             None, True),
            ("后者前沿落入先者新解码", result(fresh=[(0x120, 4)]), result(frontier=[0x123]),
             None, False),
            ("后者前沿紧邻先者新解码", result(fresh=[(0x120, 4)]), result(frontier=[0x124, None]),
             None, True),
            ("调用目标落入后者已到达", result(targets=[0x141]), result([(0x140, 2)]), None, False),
            ("调用目标已是已知函数", result(targets=[0x150]), result([(0x150, 2)]), None, True),
            ("调用目标在后者前沿", result(targets=[0x160]), result(frontier=[0x160]), None, False),
            ("调用目标在后者符号范围", result(targets=[0x146]), result([(0x140, 2)]), 8, False),
            ("调用目标恰在后者符号末尾", result(targets=[0x148]), result([(0x140, 2)]), 8, True),
        ]
        for label, earlier, later, later_size, expected in cases:
            with self.subTest(label):
                seeds = {0x100: {"start": 0x100, "size": None},
                         0x140: {"start": 0x140, "size": later_size}}
                arguments = ([0x100, 0x140], [earlier, later], seeds, {0x100, 0x140, 0x150}, {})
                self.assertEqual(semantic._batch_is_independent_scan(*arguments), expected)
                self.assertEqual(semantic._batch_is_independent(*arguments), expected)
        # 有界符号的已到达指令越出自身范围：首项检查。
        seeds = {0x100: {"start": 0x100, "size": 2}, 0x140: {"start": 0x140, "size": None}}
        arguments = ([0x100, 0x140], [result([(0x100, 2), (0x102, 1)]), result()],
                     seeds, {0x100, 0x140}, {})
        self.assertFalse(semantic._batch_is_independent_scan(*arguments))
        self.assertFalse(semantic._batch_is_independent(*arguments))

    def test_batch_independence_matches_pairwise_scan(self) -> None:
        outcomes = {True: 0, False: 0}
        for seed in range(1500):
            rng = random.Random(seed)
            count = rng.randrange(2, 5)
            candidates = rng.sample(range(0x100, 0x180, 4), count)
            seeds = {address: {"start": address,
                               "size": rng.choice([None, rng.randrange(1, 24)])}
                     for address in candidates}
            initial = {address: _ins(address, 2) for address in rng.sample(range(0x100, 0x180), 8)}
            known = set(candidates) | set(rng.sample(range(0x100, 0x180), 4))
            proposed = []
            for _ in candidates:
                reached = []
                cursor = rng.randrange(0x100, 0x180)
                for _ in range(rng.randrange(0, 5)):
                    size = rng.randrange(1, 6)
                    reached.append((cursor, size))
                    cursor += size + rng.randrange(0, 6)
                cache = dict(initial)
                for _ in range(rng.randrange(0, 6)):
                    address = rng.randrange(0x100, 0x190)
                    cache.setdefault(address, _ins(address, rng.randrange(1, 6)))
                frontier = [{"to": rng.choice([None, True, rng.randrange(0x100, 0x190)])}
                            for _ in range(rng.randrange(0, 3))]
                if rng.random() < 0.03:
                    # 非常规长度或地址类型：快速路径必须回退原扫描。
                    reached.append((rng.choice([0x150, float(0x150)]), rng.choice([0, 600, 2])))
                blocks = [{"start": address, "instructions": [_ins(address, size)]}
                          for address, size in reached]
                targets = {rng.choice([rng.randrange(0x100, 0x190), True])
                           for _ in range(rng.randrange(0, 3))}
                proposed.append(({"blocks": blocks, "cfg": {"frontier": frontier}}, [], targets,
                                 {address for address, _ in reached},
                                 SimpleNamespace(cache=cache), 0))
            expected = semantic._batch_is_independent_scan(candidates, proposed, seeds, known, initial)
            with self.subTest(seed=seed):
                self.assertEqual(semantic._batch_is_independent(candidates, proposed, seeds,
                                                                known, initial), expected)
            outcomes[expected] += 1
        self.assertGreater(min(outcomes.values()), 100, outcomes)


@unittest.skipUnless(DECODER_AVAILABLE, "A native instruction decoder is required")
class ParallelIsolationTests(unittest.TestCase):
    def test_workers_receive_private_caches_and_indexes(self) -> None:
        data = _sample()
        image = parse_binary(data, "elf")
        serial = semantic.analyze_semantics(data, image)
        original = semantic._parallel_function
        received: list[tuple] = []
        lock = threading.Lock()

        def observe(*args):
            with lock:
                received.append((args[6], args[8]))
            return original(*args)

        with patch.object(semantic, "_parallel_function", side_effect=observe):
            parallel = semantic.analyze_semantics(data, image, max_workers=2)
        self.assertEqual(parallel[:2], serial[:2])
        self.assertEqual(parallel[3], serial[3])
        self.assertGreaterEqual(len(received), 2)
        caches = [cached for cached, _ in received]
        indexes = [index[0] for _, index in received]
        self.assertEqual(len({id(item) for item in caches}), len(caches))
        self.assertEqual(len({id(item) for item in indexes}), len(indexes))


if __name__ == "__main__":
    unittest.main()
