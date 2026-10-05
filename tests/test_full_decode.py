"""Full executable-region decoding, gaps and private parallel processors."""
from __future__ import annotations

import importlib.util
import struct
import threading
import time
import unittest
from unittest.mock import patch

from fangida import processors
from fangida.loaders import BinaryImage, load_binary
from fangida.models import Instruction
from fangida.processors.decoder import NativeDecoder
from fangida.processors.full_decode import MAX_OBJDUMP_WINDOW, stream_decode_regions


def _image(code: bytes, architecture: str = "x86_64") -> BinaryImage:
    return BinaryImage("elf", architecture, 64, "little", sections=[{
        "name": ".text", "address": 0x1000, "offset": 0,
        "size": len(code), "executable": True,
    }])


def _record(address: int, mnemonic: str = "fixture") -> dict:
    return {"addr": address, "size": 1, "mnemonic": mnemonic, "operands": (),
            "reads": (), "writes": (), "branch_info": {},
            "arch_meta": {"engine": "fixture", "architecture": "fixture"}}


class FullDecodeControlTests(unittest.TestCase):
    def test_arguments_are_validated_without_coercing_thread_limits(self):
        for name, value in (("workers", 0), ("workers", True), ("chunk_bytes", 0),
                            ("chunk_bytes", 2.5)):
            with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                stream_decode_regions(b"", _image(b""), **{name: value})

    def test_parallel_registered_processors_are_private_and_callbacks_stay_on_caller(self):
        caller = threading.get_ident()
        gate = threading.Barrier(2)
        decoding_threads, callback_threads, constructed = set(), set(), []

        class RegisteredDecoder(NativeDecoder):
            engine, warning = "fixture", None

            def __init__(self, architecture, endian):
                self.first = True
                constructed.append(self)

            # This registered subclass intentionally implements only the public
            # protocol and must not be bypassed by the built-in fast path.
            def decode_bytes(self, code, address, *, max_instructions=128):
                decoding_threads.add(threading.get_ident())
                if self.first:
                    self.first = False
                    gate.wait(timeout=5)
                return [_record(address + n) for n in range(min(len(code), max_instructions))], []

        data = b"x" * 64
        image = _image(data, "fixture")
        image.sections = [{"name": str(n), "address": 0x1000 + n * 0x100,
                           "offset": n * 32, "size": 32, "executable": True}
                          for n in range(2)]
        registry = processors.ProcessorRegistry()
        registry.register("fixture", RegisteredDecoder)
        events = []

        def cancelled():
            callback_threads.add(threading.get_ident())
            return False

        def progress(event):
            callback_threads.add(threading.get_ident())
            events.append(event)

        with patch.object(processors, "_registry", registry):
            records, coverage, warnings = stream_decode_regions(
                data, image, workers=2, chunk_bytes=4, is_cancelled=cancelled, on_progress=progress)
        self.assertEqual(len(records), 64)
        self.assertEqual(len(constructed), 2)
        self.assertEqual(len(decoding_threads), 2)
        self.assertEqual(callback_threads, {caller})
        self.assertNotIn(caller, decoding_threads)
        self.assertEqual({region["worker_id"] for region in coverage}, decoding_threads)
        self.assertTrue(all(region["complete"] for region in coverage))
        self.assertFalse(warnings)
        self.assertEqual(events[-1]["regions_completed"], 2)
        self.assertEqual(events[-1]["workers_used"], 2)
        self.assertEqual(events[-1]["processed_bytes"], len(data))

    def test_cancellation_keeps_parallel_results_and_records_remaining_coverage(self):
        gate = threading.Barrier(2)
        decoded_on, callback_on = set(), set()
        stop = False

        class SlowDecoder:
            engine, warning = "fixture", None

            def __init__(self, architecture, endian):
                self.first = True

            def decode_bytes(self, code, address, *, max_instructions=128):
                decoded_on.add(threading.get_ident())
                if self.first:
                    self.first = False
                    gate.wait(timeout=5)
                time.sleep(0.01)
                return [_record(address + n) for n in range(len(code))], []

        data = b"x" * 2048
        image = _image(data, "fixture")
        image.sections = [{"name": str(n), "address": 0x1000 + n * 0x1000,
                           "offset": n * 1024, "size": 1024, "executable": True}
                          for n in range(2)]
        registry = processors.ProcessorRegistry()
        registry.register("fixture", SlowDecoder)

        def cancelled():
            callback_on.add(threading.get_ident())
            return stop

        def progress(event):
            nonlocal stop
            callback_on.add(threading.get_ident())
            if event["processed_bytes"]:
                stop = True

        with patch.object(processors, "_registry", registry):
            records, coverage, warnings = stream_decode_regions(
                data, image, workers=2, chunk_bytes=1, is_cancelled=cancelled, on_progress=progress)
        self.assertEqual(len(decoded_on), 2)
        self.assertEqual(callback_on, {threading.get_ident()})
        self.assertGreater(len(records), 0)
        self.assertLess(len(records), len(data))
        self.assertTrue(all(region["cancelled"] for region in coverage))
        for region in coverage:
            self.assertEqual(region["decoded_bytes"] + sum(g["size"] for g in region["gaps"]),
                             region["size"])
            self.assertEqual(region["gaps"][-1]["reason"], "cancelled")
        self.assertTrue(any("cancelled" in warning for warning in warnings))

    def test_unavailable_architecture_does_not_fabricate_instructions(self):
        records, coverage, warnings = stream_decode_regions(b"\xc3" * 4, _image(b"x" * 4, "unknown"))
        self.assertEqual(records, {})
        self.assertEqual(coverage[0]["gaps"], [{"address": 0x1000, "offset": 0,
                                             "size": 4, "reason": "decoder_unavailable"}])
        self.assertFalse(coverage[0]["complete"])
        self.assertIsNone(coverage[0]["worker_id"])
        self.assertTrue(any("unavailable" in warning for warning in warnings))

    def test_data_pseudo_records_are_rejected_even_from_registered_providers(self):
        class DataDecoder:
            engine, warning = "fixture", None

            def decode_bytes(self, code, address, *, max_instructions=128):
                return [_record(address + n, ".byte") for n in range(len(code))], []

        registry = processors.ProcessorRegistry()
        registry.register("fixture", lambda *_: DataDecoder())
        with patch.object(processors, "_registry", registry):
            records, coverage, warnings = stream_decode_regions(b"x" * 8, _image(b"x" * 8, "fixture"))
        self.assertFalse(records)
        self.assertEqual(coverage[0]["gaps"][0]["size"], 8)
        self.assertTrue(any("data-only" in warning for warning in warnings))

    def test_cancellation_callback_failure_stops_without_decoding_remaining_bytes(self):
        def broken_cancel():
            raise RuntimeError("fixture cancellation failure")

        for workers in (1, 2):
            with self.subTest(workers=workers):
                records, coverage, warnings = stream_decode_regions(
                    b"x" * 8, _image(b"x" * 8), workers=workers, is_cancelled=broken_cancel)
                self.assertFalse(records)
                self.assertTrue(coverage[0]["cancelled"])
                self.assertIsNone(coverage[0]["worker_id"])
                self.assertEqual(coverage[0]["gaps"][0]["reason"], "cancelled")
                self.assertTrue(any("Cancellation callback failed" in warning for warning in warnings))


@unittest.skipUnless(importlib.util.find_spec("capstone"), "Capstone unavailable")
class FullDecodeCapstoneTests(unittest.TestCase):
    def test_cross_window_instructions_match_unbounded_decode(self):
        code = bytes.fromhex("90 48 b8 0102030405060708 e8 01000000 c3 c3") * 19
        expected, warnings = NativeDecoder("x86_64").decode_bytes(code, 0x1000, max_instructions=len(code))
        self.assertFalse(warnings)
        for chunk_bytes in (1, 7, 15, 32, 65536):
            with self.subTest(chunk_bytes=chunk_bytes):
                records, coverage, warnings = stream_decode_regions(code, _image(code), chunk_bytes=chunk_bytes)
                self.assertEqual(list(records.values()), expected)
                self.assertEqual(coverage[0]["decoded_bytes"], len(code))
                self.assertTrue(coverage[0]["complete"])
                self.assertFalse(warnings)

    def test_fast_api_preserves_register_branch_and_tuple_contract_without_asdict(self):
        for architecture, endian, code in (
            ("x86_64", "little", "48 89 e5 e8 01000000 c3 c3"),
            ("x86", "little", "89 e5 e8 01000000 c3 c3"),
            ("arm", "big", "eb000000 e12fff1e"),
            ("arm64", "little", "00000094 c0035fd6"),
        ):
            with self.subTest(architecture=architecture):
                decoder = NativeDecoder(architecture, endian)
                data = bytes.fromhex(code)
                expected = decoder.decode_bytes(data, 0x1000)
                with patch.object(Instruction, "to_dict", side_effect=AssertionError("deep-copy path used")):
                    actual = decoder.decode_bytes_fast(data, 0x1000)
                self.assertEqual(actual, expected)
                self.assertTrue(all(isinstance(record["operands"], tuple) for record in actual[0]))

    def test_fast_api_snapshots_pc_relative_targets_without_changing_old_api(self):
        for architecture, code, expected in (
            ("x86_64", "48 8b 05 10000000", 0x1017),
            ("x86", "a1 10200000", None),  # Absolute memory is outside this narrow addition.
            ("arm", "04009fe5", 0x100C),
            ("arm64", "40000058", 0x1008),
        ):
            with self.subTest(architecture=architecture):
                decoder = NativeDecoder(architecture)
                data = bytes.fromhex(code)
                old, old_warnings = decoder.decode_bytes(data, 0x1000)
                fast, warnings = decoder.decode_bytes_fast(data, 0x1000)
                self.assertFalse(old_warnings + warnings)
                self.assertNotIn("memory_references", old[0]["arch_meta"])
                self.assertEqual(fast[0]["arch_meta"].get("memory_references"),
                                 None if expected is None else (expected,))

        decoder = NativeDecoder("x86_64")
        eip, warnings = decoder.decode_bytes_fast(bytes.fromhex("67 8b 05 10000000"), 0x100000000)
        self.assertFalse(warnings)
        self.assertEqual(eip[0]["arch_meta"]["memory_references"], (0x17,))
        tls, warnings = decoder.decode_bytes_fast(bytes.fromhex("64 48 8b 05 10000000"), 0x1000)
        self.assertFalse(warnings)
        self.assertNotIn("memory_references", tls[0]["arch_meta"])

    def test_invalid_and_truncated_bytes_are_explicit_gaps_without_data_instructions(self):
        for architecture, data, addresses, gaps in (
            ("x86_64", bytes.fromhex("06 c3 0f"), [0x1001], [(0x1000, 1), (0x1002, 1)]),
            ("arm64", bytes.fromhex("ffffffff c0035fd6 ffff"), [0x1004], [(0x1000, 4), (0x1008, 2)]),
        ):
            with self.subTest(architecture=architecture):
                records, coverage, warnings = stream_decode_regions(data, _image(data, architecture), chunk_bytes=1)
                self.assertEqual(list(records), addresses)
                self.assertEqual([(g["address"], g["size"]) for g in coverage[0]["gaps"]], gaps)
                self.assertFalse(coverage[0]["complete"])
                self.assertTrue(warnings)
                self.assertTrue(all(not record["mnemonic"].startswith(".") for record in records.values()))

    def test_virtual_only_and_nonexec_regions_are_not_read_and_file_truncation_is_partial(self):
        data = b"\xc3\xc3"
        image = _image(data)
        image.sections = [
            {"name": "normal", "address": 0x1000, "offset": 0, "size": 1, "executable": True},
            {"name": "nobits", "address": 0x2000, "offset": 0, "size": 2, "type": 8, "executable": True},
            {"name": "virtual", "address": 0x3000, "offset": 0, "size": 2, "file_backed": False, "executable": True},
            {"name": "data", "address": 0x4000, "offset": 0, "size": 2, "executable": False},
            {"name": "truncated", "address": 0x5000, "offset": 1, "size": 5, "executable": True},
            {"name": "file_size", "address": 0x6000, "offset": 0, "size": 100, "file_size": 2, "executable": True},
        ]
        records, coverage, warnings = stream_decode_regions(data, image, workers=2)
        self.assertEqual(set(records), {0x1000, 0x5000, 0x6000, 0x6001})
        self.assertEqual([row["name"] for row in coverage], ["normal", "truncated", "file_size"])
        self.assertEqual(coverage[1]["gaps"], [{"address": 0x5001, "offset": 2,
                                             "size": 4, "reason": "outside_file"}])
        self.assertFalse(coverage[1]["complete"])
        self.assertEqual(coverage[2]["size"], 2)
        self.assertTrue(warnings)

    def test_single_and_multi_worker_evidence_match_when_worker_ids_are_removed(self):
        data = bytes.fromhex("90 c3") * 32
        image = _image(data)
        image.sections = [{"name": str(n), "address": 0x1000 + n * 0x100,
                           "offset": n * 32, "size": 32, "executable": True}
                          for n in range(2)]
        single = stream_decode_regions(data, image, workers=1, chunk_bytes=7)
        parallel = stream_decode_regions(data, image, workers=2, chunk_bytes=7)
        for result in (single, parallel):
            for coverage in result[1]:
                coverage.pop("worker_id")
        self.assertEqual(single, parallel)

    def test_region_priority_rejects_different_start_interval_overlaps(self):
        data = bytes.fromhex("48 89 e5 c3")
        original = {"name": "first", "address": 0x1000, "offset": 0, "size": 4, "executable": True}
        alias = {"name": "alias", "address": 0x1001, "offset": 1, "size": 3, "executable": True}
        for workers in (1, 2):
            for sections in ([original, alias], [alias, original]):
                with self.subTest(workers=workers, priority=sections[0]["name"]):
                    image = _image(data)
                    image.sections = sections
                    records, coverage, warnings = stream_decode_regions(data, image, workers=workers)
                    expected = [0x1000, 0x1003] if sections[0] is original else [0x1001, 0x1003]
                    self.assertEqual(list(records), expected)
                    self.assertFalse(coverage[1]["complete"])
                    self.assertEqual(coverage[1]["decoded_bytes"], 0)
                    self.assertEqual(coverage[1]["instruction_count"], 0)
                    self.assertTrue(all(g["reason"] == "overlapping_region" for g in coverage[1]["gaps"]))
                    self.assertEqual(sum(g["size"] for g in coverage[1]["gaps"]), sections[1]["size"])
                    self.assertTrue(any("overlaps instructions" in warning for warning in warnings))


class FullDecodeObjdumpTests(unittest.TestCase):
    def test_fallback_uses_bounded_windows_and_marks_coverage_partial(self):
        windows = []

        def render(code, address, architecture):
            windows.append(len(code))
            lines = [f"{address+n:x}: c3  ret" for n in range(len(code))]
            return "\n".join(lines), "gnu"

        data = b"\xc3" * (MAX_OBJDUMP_WINDOW + 100)
        with patch.dict("sys.modules", {"capstone": None}), \
             patch("fangida.processors.decoder.disassemble_bytes", side_effect=render):
            records, coverage, warnings = stream_decode_regions(data, _image(data))
        self.assertEqual(len(records), len(data))
        self.assertEqual(len(windows), 2)
        self.assertLessEqual(max(windows), MAX_OBJDUMP_WINDOW + 15)
        self.assertEqual(coverage[0]["engine"], "objdump")
        self.assertTrue(coverage[0]["complete"])
        self.assertFalse(coverage[0]["details_complete"])
        self.assertEqual(coverage[0]["gaps"], [])
        self.assertTrue(any("Register read/write" in warning for warning in warnings))


class LoaderFileBackedTests(unittest.TestCase):
    def test_macho_zero_fill_flags_and_segment_extent_are_explicit(self):
        from fangida.core.kkagent.test_native import macho64

        for flag in (1, 0xC, 0x12):
            with self.subTest(flag=flag):
                data = bytearray(macho64())
                struct.pack_into("<I", data, 104 + 64, flag)
                image = load_binary(bytes(data), "macho")
                self.assertFalse(image.sections[0]["file_backed"])
                self.assertEqual(image.sections[0]["file_size"], 0)
                records, coverage, warnings = stream_decode_regions(bytes(data), image)
                self.assertEqual((records, coverage), ({}, []))
                self.assertTrue(warnings)
        data = bytearray(macho64())
        struct.pack_into("<Q", data, 104 + 40, 10)  # Existing virtual size stays intact.
        image = load_binary(bytes(data), "macho")
        self.assertEqual(image.sections[0]["size"], 10)
        self.assertEqual(image.sections[0]["file_size"], 3)
        self.assertTrue(image.sections[0]["file_backed"])

    def test_pe_raw_extent_remains_distinct_from_virtual_only_content(self):
        from fangida.core.kkagent.test_native import pe64

        data = bytearray(pe64())
        image = load_binary(bytes(data), "pe")
        self.assertTrue(image.sections[0]["file_backed"])
        self.assertEqual(image.sections[0]["file_size"], 0x10)
        struct.pack_into("<I", data, 0x188 + 16, 0)
        image = load_binary(bytes(data), "pe")
        self.assertFalse(image.sections[0]["file_backed"])
        self.assertEqual(image.sections[0]["file_size"], 0)


if __name__ == "__main__":
    unittest.main()
