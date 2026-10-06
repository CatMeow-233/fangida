"""解码记录的内存优化：紧凑记录、帧内/区域内按值共享与行协议。

  - decode_bytes_fast 的记录仍是普通 dict，键、键顺序、值与字面量构造逐字相同，
    每条记录仍拥有自己的 branch_info / arch_meta（快路径自身契约不变）；
  - 子进程 share_records 把记录换成行（ROWS），元组内字符串、含嵌套字典的 arch_meta
    也按值共享；父进程重建的记录与原记录逐值相同；
  - 串行/线程路径按区域共享只读子对象，结果与不共享时逐字相同，区域之间不共享；
  - 进程路径流式交付的记录与最终结果是同一批对象。
"""
from __future__ import annotations

from contextlib import ExitStack
import copy
import importlib.util
import json
import marshal
import os
import pickle
import struct
import sys
import unittest
from unittest.mock import patch

from fangida.core.kkagent.binary import BinaryImage
from fangida.processors import _decode_worker, decoder as decoder_module, full_decode
from fangida.processors.decoder import NativeDecoder, RECORD_KEYS, record_from_row, records_from_rows
from fangida.processors.full_decode import stream_decode_regions

CAPSTONE_AVAILABLE = importlib.util.find_spec("capstone") is not None
BASE = 0x400000
REGION = 0x2000
PAGE = 0x900000


def _adrp(address: int, target: int, register: int = 8) -> int:
    pages = ((target & ~0xFFF) - (address & ~0xFFF)) >> 12
    return 0x90000000 | ((pages & 3) << 29) | (((pages >> 2) & 0x7FFFF) << 5) | register


def _arm64_code(base: int, size: int) -> bytes:
    """重复的 adrp/add/ldr/mov/cbz/nop/bl/ret：覆盖嵌套 address_operation、内存操作与分支。"""
    words = []
    for address in range(base, base + size, 32):
        words += [_adrp(address, PAGE),          # adrp x8, PAGE（同一目标页：值相同）
                  0x91004108,                    # add x8, x8, #0x10
                  0xF9400500,                    # ldr x0, [x8, #8]
                  0xAA0103E0,                    # mov x0, x1
                  0xB4000040,                    # cbz x0, +8
                  0xD503201F,                    # nop
                  0x94000000,                    # bl .（目标为自身地址）
                  0xD65F03C0]                    # ret
    return struct.pack(f"<{len(words)}I", *words)


def _image(regions: int = 2) -> tuple[bytes, BinaryImage]:
    data = b"".join(_arm64_code(BASE + index * REGION, REGION) for index in range(regions))
    sections = [{"name": f".text{index}", "address": BASE + index * REGION, "offset": index * REGION,
                 "size": REGION, "executable": True} for index in range(regions)]
    return data, BinaryImage("elf", "arm64", 64, "little", entry_address=BASE, sections=sections)


def _literal(record: dict) -> dict:
    """同内容的字面量构造（原实现的记录形式）。"""
    return {key: record[key] for key in RECORD_KEYS}


class CompactRecordTests(unittest.TestCase):
    def test_record_from_row_is_a_plain_dict_with_identical_value_and_order(self):
        row = (0x1000, 4, "mov", ("x0", "x1"), ("x1",), ("x0",), {}, {"engine": "capstone", "architecture": "arm64"})
        for build in (record_from_row, lambda item: records_from_rows([item])[0]):
            record = build(row)
            literal = dict(zip(RECORD_KEYS, row))
            self.assertIs(type(record), dict)
            self.assertEqual(tuple(record), RECORD_KEYS)
            self.assertEqual(record, literal)
            self.assertEqual(repr(record), repr(literal))
            self.assertEqual(json.dumps(record), json.dumps(literal))
            self.assertEqual(marshal.dumps(record), marshal.dumps(literal))
            self.assertEqual(pickle.dumps(record), pickle.dumps(literal))
            self.assertEqual(copy.deepcopy(record), literal)
            if decoder_module.COMPACT_RECORDS:
                self.assertLess(sys.getsizeof(record), sys.getsizeof(literal))

    def test_new_keys_keep_insertion_order_and_do_not_leak_between_records(self):
        first, second = record_from_row(range(8)), record_from_row(range(8, 16))
        first["comment"] = "x"
        first["other"] = 1
        self.assertEqual(list(first), [*RECORD_KEYS, "comment", "other"])
        self.assertEqual(list(second), list(RECORD_KEYS))
        third = record_from_row(range(16, 24))
        self.assertEqual(list(third), list(RECORD_KEYS))
        del first["size"]
        self.assertEqual(list(first), [key for key in RECORD_KEYS if key != "size"] + ["comment", "other"])

    def test_self_check_falls_back_when_instance_dicts_are_not_smaller(self):
        self.assertIsInstance(decoder_module._compact_supported(), bool)
        with patch.object(sys, "getsizeof", return_value=64):
            self.assertFalse(decoder_module._compact_supported())
        with patch.object(decoder_module, "COMPACT_RECORDS", False):
            record = record_from_row(range(8))
            self.assertEqual(record, dict(zip(RECORD_KEYS, range(8))))
            self.assertEqual(records_from_rows([range(8)]), [record])

    @unittest.skipUnless(CAPSTONE_AVAILABLE, "Capstone unavailable")
    def test_fast_decoder_records_equal_literal_form_and_own_their_dicts(self):
        decoder = NativeDecoder("arm64")
        code = _arm64_code(BASE, 0x400)
        for include_data in (False, True):
            with self.subTest(include_data=include_data):
                compact, warnings = decoder.decode_bytes_fast(code, BASE, max_instructions=1024,
                                                              include_data=include_data)
                self.assertFalse(warnings)
                with patch.object(decoder_module, "COMPACT_RECORDS", False):
                    literal, _ = decoder.decode_bytes_fast(code, BASE, max_instructions=1024,
                                                           include_data=include_data)
                self.assertEqual(compact, literal)
                self.assertEqual(repr(compact), repr(literal))
                self.assertTrue(all(type(record) is dict and tuple(record) == RECORD_KEYS
                                    for record in compact))
                # 快路径自身契约：每条记录拥有自己的 branch_info / arch_meta。
                for key in ("branch_info", "arch_meta"):
                    self.assertEqual(len({id(record[key]) for record in compact}), len(compact))
                if decoder_module.COMPACT_RECORDS:
                    self.assertTrue(all(sys.getsizeof(record) < sys.getsizeof(_literal(record))
                                        for record in compact))


@unittest.skipUnless(CAPSTONE_AVAILABLE, "Capstone unavailable")
class FrameSharingTests(unittest.TestCase):
    def _sweep(self, include_data: bool = True):
        data, image = _image(1)
        decoder = NativeDecoder("arm64")
        return _decode_worker.sweep(decoder.decode_bytes_fast, data, 0, BASE, REGION, 0, REGION, 0x400, 4,
                                    full_decode._LOOKAHEAD, full_decode._INVALID_MNEMONICS, include_data)

    def test_rows_rebuild_identical_records_with_shared_sub_objects(self):
        result = self._sweep()
        expected = copy.deepcopy(result[1])
        results = [result, None]
        _decode_worker.share_records(results)
        self.assertIsNone(results[1])
        addrs, rows, gaps, end, marker = results[0]
        self.assertEqual(marker, _decode_worker.ROWS)
        self.assertEqual((addrs, gaps, end), (result[0], result[2], result[3]))
        self.assertTrue(all(type(row) is tuple and len(row) == len(RECORD_KEYS) for row in rows))
        # 经过 marshal 往返（与真实应答相同）后重建：逐值、逐类型、键顺序都相同。
        _, loaded = marshal.loads(marshal.dumps((1, results)))
        rebuilt = records_from_rows(loaded[0][1])
        self.assertEqual(rebuilt, expected)
        self.assertEqual(repr(rebuilt), repr(expected))
        self.assertTrue(all(tuple(record) == RECORD_KEYS for record in rebuilt))
        # 含嵌套 address_operation 的 arch_meta 按值共享，嵌套字典也共享。
        pages = [record["arch_meta"] for record in rebuilt if record["mnemonic"] == "adrp"]
        adds = [record["arch_meta"] for record in rebuilt if record["mnemonic"] == "add"]
        self.assertGreater(len(pages), 1)
        self.assertTrue(all(meta is pages[0] for meta in pages))
        self.assertTrue(all(meta is adds[0] for meta in adds))
        self.assertEqual(adds[0]["address_operation"],
                         {"kind": "add", "destination": "x8", "source": "x8", "value": 16})
        # 元组按值共享，不同元组中的相同字符串也是同一对象（marshal 只写一次）。
        movs = [record for record in rebuilt if record["mnemonic"] == "mov"]
        self.assertTrue(all(record["operands"] is movs[0]["operands"] for record in movs))
        self.assertIs(movs[0]["operands"][0], movs[0]["writes"][0])
        self.assertTrue(all(record["mnemonic"] is movs[0]["mnemonic"] for record in movs))

    def test_frozen_keys_distinguish_types_and_reject_unhashable_values(self):
        self.assertNotEqual(_decode_worker._frozen({"value": 1}), _decode_worker._frozen({"value": True}))
        self.assertNotEqual(_decode_worker._frozen({"value": 1}), _decode_worker._frozen({"value": 1.0}))
        self.assertNotEqual(_decode_worker._frozen({"a": 1, "b": 2}), _decode_worker._frozen({"b": 2, "a": 1}))
        self.assertNotEqual(_decode_worker._frozen((1,)), _decode_worker._frozen({1: None}))
        with self.assertRaises(TypeError):
            _decode_worker._frozen({"value": [1]})
        canonical: dict = {}
        first = {"engine": "capstone", "address_operation": {"kind": "set", "value": 1}}
        second = {"engine": "capstone", "address_operation": {"kind": "set", "value": True}}
        third = {"engine": "capstone", "address_operation": {"kind": "set", "value": 1}}
        listed = {"engine": "capstone", "address_operation": {"kind": "set", "value": [1]}}
        self.assertIs(_decode_worker._share_dict(canonical, "arch_meta", first), first)
        self.assertIs(_decode_worker._share_dict(canonical, "arch_meta", second), second)
        self.assertIs(_decode_worker._share_dict(canonical, "arch_meta", third), first)
        self.assertIs(_decode_worker._share_dict(canonical, "arch_meta", listed), listed)
        self.assertIs(type(second["address_operation"]["value"]), bool)

    def test_non_standard_records_stay_dicts_with_equal_values(self):
        records = [{"addr": 1, "size": 1, "mnemonic": "nop", "operands": ("a", "b")},
                   {"addr": 2, "size": 1, "mnemonic": "nop", "operands": ("a", "b"),
                    "branch_info": {}, "arch_meta": {"engine": "x", "address_operation": {"value": 1}}}]
        expected = copy.deepcopy(records)
        results = [([1, 2], records, [], 2)]
        _decode_worker.share_records(results)
        self.assertEqual(len(results[0]), 4)
        self.assertEqual(results[0][1], expected)
        self.assertIs(records[0]["operands"], records[1]["operands"])
        self.assertIs(records[0]["mnemonic"], records[1]["mnemonic"])

    def test_commit_builds_records_once_for_results_and_stream(self):
        data, image = _image(1)
        regions, _ = full_decode._regions(data, image)
        result = self._sweep()
        expected = copy.deepcopy(result[1])
        results = [result]
        _decode_worker.share_records(results)
        piece = marshal.loads(marshal.dumps(results))[0]
        self.assertTrue(full_decode._on_path(piece, 0, 0, BASE, 4))
        state = full_decode._ProcessRegion(0, regions[0], 1, 4)
        state.fresh = []
        state.commit(piece)
        self.assertEqual(list(state.records.values()), expected)
        self.assertEqual(list(state.records), result[0])
        self.assertEqual(len(state.fresh), len(expected))
        self.assertTrue(all(left is right for left, right in zip(state.fresh, state.records.values())))

    def test_handshake_covers_row_format(self):
        self.assertEqual(_decode_worker.PROTOCOL, 4)
        self.assertEqual(_decode_worker.hello()[1], 4)
        fingerprint = _decode_worker.code_fingerprint()
        self.assertEqual(_decode_worker._compute_fingerprint(), fingerprint)
        with patch.object(_decode_worker, "share_records", lambda results: None):
            self.assertNotEqual(_decode_worker._compute_fingerprint(), fingerprint)
        with patch.object(_decode_worker, "ROWS", "columns"):
            self.assertNotEqual(_decode_worker._compute_fingerprint(), fingerprint)
        self.assertEqual(_decode_worker.code_fingerprint(), fingerprint)


@unittest.skipUnless(CAPSTONE_AVAILABLE, "Capstone unavailable")
class RegionSharingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data, cls.image = _image()
        # 关闭区域内共享（令门控不成立）得到的结果：原实现的值。
        with patch.object(full_decode, "_BUILTIN_FAST", None):
            cls.unshared = stream_decode_regions(cls.data, cls.image, include_data=True)

    def _assert_same(self, result):
        # worker_id 是调度诊断（线程标识），不属于结果值。
        def canonical(item):
            return (item[0], [{key: value for key, value in region.items() if key != "worker_id"}
                              for region in item[1]], item[2])
        self.assertEqual(canonical(result), canonical(self.unshared))
        self.assertEqual(repr(canonical(result)), repr(canonical(self.unshared)))
        self.assertTrue(all(type(record) is dict and tuple(record) == RECORD_KEYS
                            for record in result[0].values()))

    def test_serial_and_thread_paths_share_within_each_region_only(self):
        for workers in (1, 2):
            with self.subTest(workers=workers):
                result = stream_decode_regions(self.data, self.image, workers=workers, include_data=True,
                                               processes=False)
                self._assert_same(result)
                by_region = [[record for address, record in result[0].items()
                              if region["address"] <= address < region["address"] + region["size"]]
                             for region in result[1]]
                firsts = []
                for records in by_region:
                    empty = [record["branch_info"] for record in records if not record["branch_info"]]
                    plain = [record["arch_meta"] for record in records if len(record["arch_meta"]) == 2]
                    pages = [record["arch_meta"] for record in records if record["mnemonic"] == "adrp"]
                    mnemonics = [record["mnemonic"] for record in records if record["mnemonic"] == "nop"]
                    for values in (empty, plain, pages, mnemonics):
                        self.assertGreater(len(values), 1)
                        self.assertTrue(all(value is values[0] for value in values))
                    # 非空 branch_info 不共享（每条记录自己的字典）。
                    branches = [record["branch_info"] for record in records if record["branch_info"]]
                    self.assertEqual(len({id(branch) for branch in branches}), len(branches))
                    firsts.append((empty[0], plain[0], pages[0]))
                # 共享表属于各自的区域：区域之间没有共享的可变对象。
                for left, right in zip(firsts[0], firsts[1]):
                    self.assertIsNot(left, right)

    def test_replaced_fast_decoder_is_not_shared(self):
        real = NativeDecoder.decode_bytes_fast
        with patch.object(NativeDecoder, "decode_bytes_fast",
                          lambda self, *args, **kwargs: real(self, *args, **kwargs)):
            result = stream_decode_regions(self.data, self.image, include_data=True)
        self._assert_same(result)
        records = list(result[0].values())
        self.assertEqual(len({id(record["branch_info"]) for record in records}), len(records))
        self.assertEqual(len({id(record["arch_meta"]) for record in records}), len(records))

    def test_process_path_streams_the_returned_record_objects(self):
        delivered: list[dict] = []
        diagnostics: dict = {}
        with ExitStack() as stack:
            stack.enter_context(patch.object(full_decode, "_PROCESS_MIN_BYTES", 0x1000))
            stack.enter_context(patch.object(full_decode, "_PROCESS_MIN_PIECE_BYTES", 0x400))
            stack.enter_context(patch.object(full_decode, "_PROCESS_PIECE_BYTES", 0x800))
            stack.enter_context(patch.object(full_decode, "_process_mismatch", False))
            stack.enter_context(patch.dict(os.environ, {"FANGIDA_DECODE_PROCESSES": ""}))
            result = stream_decode_regions(
                self.data, self.image, workers=2, include_data=True, processes=True,
                diagnostics=diagnostics,
                on_records=lambda regions, index, records: delivered.extend(records))
        self.assertGreaterEqual(diagnostics["processes_used"], 1)
        self._assert_same(result)
        self.assertEqual(len(delivered), len(result[0]))
        self.assertTrue(all(record is result[0][record["addr"]] for record in delivered))
        if decoder_module.COMPACT_RECORDS:
            self.assertTrue(all(sys.getsizeof(record) < sys.getsizeof(_literal(record))
                                for record in delivered))
        pages = [record["arch_meta"] for record in delivered if record["mnemonic"] == "adrp"]
        self.assertGreater(len({id(meta) for meta in pages}), 0)
        self.assertLess(len({id(meta) for meta in pages}), len(pages))


if __name__ == "__main__":
    unittest.main()
