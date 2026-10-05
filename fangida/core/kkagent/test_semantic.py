"""Native function discovery tests with exact, hand-written machine code."""
from __future__ import annotations

import importlib.util
import json
import struct
import threading
import unittest
from unittest.mock import patch

from .binary import parse_binary
from . import semantic
from .semantic import _liveness, analyze_semantics
from .test_native import elf64_with_symbols
from .translator import objdump_available


DECODER_AVAILABLE = bool(importlib.util.find_spec("capstone") or objdump_available())


def _sample(*, helper_symbol: bool = True) -> bytes:
    """ELF with main: call helper; ret; padding; helper: push rbp; ret."""
    data = bytearray(elf64_with_symbols())
    data[0x100:0x10a] = bytes.fromhex("e8 03 00 00 00 c3 90 90 55 c3")
    struct.pack_into("<Q", data, 0x40 + 32, 10)  # executable segment's p_filesz
    struct.pack_into("<Q", data, 0x40 + 40, 10)  # executable segment's p_memsz
    struct.pack_into("<Q", data, 0x240 + 32, 10)  # .text size
    names = b"\0main\0helper\0"
    data[0x160:0x160 + len(names)] = names
    struct.pack_into("<Q", data, 0x300 + 32, len(names))
    struct.pack_into("<IBBHQQ", data, 0x180 + 24, 1, 0x12, 0, 1, 0x401000, 6)
    if helper_symbol:
        struct.pack_into("<IBBHQQ", data, 0x180 + 48, 6, 0x12, 0, 1, 0x401008, 2)
        struct.pack_into("<Q", data, 0x2c0 + 32, 72)
    return bytes(data)


@unittest.skipUnless(DECODER_AVAILABLE, "Capstone or a supported objdump required")
class SemanticIntegrationTests(unittest.TestCase):
    def test_parallel_bounded_symbols_match_serial_and_use_two_threads(self) -> None:
        data = _sample()
        image = parse_binary(data, "elf")
        serial = analyze_semantics(data, image)
        original = semantic._parallel_function
        barrier = threading.Barrier(2)
        workers: set[int] = set()
        lock = threading.Lock()

        def observe(*args: object) -> object:
            with lock:
                workers.add(threading.get_ident())
            barrier.wait(timeout=5)
            return original(*args)

        with patch.object(semantic, "_parallel_function", side_effect=observe):
            parallel = analyze_semantics(data, image, max_workers=2)
        self.assertEqual(len(workers), 2)
        self.assertEqual(parallel[:2], serial[:2])
        self.assertEqual(parallel[3], serial[3])
        self.assertEqual({key: value for key, value in parallel[2].items()
                          if not key.startswith("semantic_worker") and
                          key != "semantic_parallel_functions"},
                         {key: value for key, value in serial[2].items()
                          if not key.startswith("semantic_worker") and
                          key != "semantic_parallel_functions"})
        self.assertEqual(parallel[2]["semantic_workers_requested"], 2)
        self.assertEqual(parallel[2]["semantic_workers_used"], 2)
        self.assertEqual(parallel[2]["semantic_parallel_functions"], 2)

    def test_parallel_preserves_discovery_outside_other_symbol_ranges(self) -> None:
        data = bytearray(_sample())
        data[0x101] = 1  # main calls unseeded 0x401006, then helper stays a known symbol.
        raw = bytes(data)
        image = parse_binary(raw, "elf")
        serial = analyze_semantics(raw, image)
        parallel = analyze_semantics(raw, image, max_workers=2)
        self.assertEqual(parallel[:2], serial[:2])
        self.assertEqual(parallel[3], serial[3])
        self.assertEqual(parallel[2]["semantic_parallel_functions"], 2)
        self.assertEqual(parallel[2]["semantic_discovered_calls"], 1)

    def test_parallel_falls_back_when_call_discovers_inside_later_symbol(self) -> None:
        data = bytearray(_sample())
        data[0x101] = 4  # main calls an address inside helper's symbol range.
        raw = bytes(data)
        image = parse_binary(raw, "elf")
        serial = analyze_semantics(raw, image)
        parallel = analyze_semantics(raw, image, max_workers=2)
        self.assertEqual(parallel[:2], serial[:2])
        self.assertEqual(parallel[3], serial[3])
        self.assertEqual(parallel[2]["semantic_parallel_functions"], 0)

    def test_parallel_falls_back_when_new_seed_changes_later_frontier(self) -> None:
        data = bytearray(_sample())
        data[0x101] = 4  # main calls just beyond helper's one-byte symbol.
        data[0x108] = 0x90  # helper falls through to the new call seed.
        struct.pack_into("<Q", data, 0x180 + 48 + 16, 1)
        raw = bytes(data)
        image = parse_binary(raw, "elf")
        serial = analyze_semantics(raw, image)
        parallel = analyze_semantics(raw, image, max_workers=2)
        self.assertEqual(parallel[:2], serial[:2])
        self.assertEqual(parallel[3], serial[3])
        self.assertEqual(parallel[2]["semantic_parallel_functions"], 0)

    def test_parallel_falls_back_on_overlapping_symbol_ranges(self) -> None:
        data = bytearray(_sample())
        struct.pack_into("<Q", data, 0x180 + 48 + 8, 0x401004)
        raw = bytes(data)
        image = parse_binary(raw, "elf")
        parallel = analyze_semantics(raw, image, max_workers=2)
        serial = analyze_semantics(raw, image)
        self.assertEqual(parallel[:2], serial[:2])
        self.assertEqual(parallel[2]["semantic_parallel_functions"], 0)

    def test_progress_and_cancel_callbacks_preserve_serial_event_order(self) -> None:
        data = _sample()
        image = parse_binary(data, "elf")
        events: list[dict] = []
        parallel_requested = analyze_semantics(
            data, image, max_workers=2,
            is_cancelled=lambda: False, on_progress=events.append)
        serial_events: list[dict] = []
        serial = analyze_semantics(data, image, on_progress=serial_events.append,
                                   is_cancelled=lambda: False)
        self.assertEqual(parallel_requested[:2], serial[:2])
        self.assertEqual(events, serial_events)
        self.assertEqual(parallel_requested[2]["semantic_parallel_functions"], 0)
        self.assertEqual(parallel_requested[2]["semantic_workers_used"], 1)

    def test_symbol_functions_and_direct_call_xref(self) -> None:
        data = _sample()
        functions, xrefs, stats, warnings = analyze_semantics(data, parse_binary(data, "elf"))
        by_name = {fn["name"]: fn for fn in functions}
        self.assertEqual(set(by_name), {"main", "helper"})
        self.assertEqual(xrefs, [{"src": 0x401000, "dst": 0x401008,
                                  "kind": "call", "confidence": 1.0}])
        self.assertEqual(by_name["main"]["xrefs_out"], xrefs)
        self.assertEqual(by_name["helper"]["xrefs_in"], xrefs)
        self.assertTrue(by_name["main"]["boundary_known"])
        self.assertTrue(by_name["main"]["cfg"]["complete"])
        self.assertEqual({ins["addr"] for block in by_name["main"]["blocks"]
                          for ins in block["instructions"]}, {0x401000, 0x401005})
        self.assertNotIn(0x401006, {ins["addr"] for block in by_name["main"]["blocks"]
                                    for ins in block["instructions"]})
        self.assertEqual(stats["semantic_instructions"], 4)
        self.assertFalse(warnings)

    def test_call_seed_has_unknown_boundary(self) -> None:
        data = _sample(helper_symbol=False)
        functions, xrefs, stats, _ = analyze_semantics(data, parse_binary(data, "elf"))
        by_start = {fn["start"]: fn for fn in functions}
        helper = by_start[0x401008]
        self.assertEqual(helper["source"], "direct_call")
        self.assertIsNone(helper["size"])
        self.assertFalse(helper["boundary_known"])
        self.assertEqual(stats["semantic_discovered_calls"], 1)
        self.assertEqual(helper["xrefs_in"], xrefs)

    def test_budget_frontier_does_not_claim_a_complete_graph(self) -> None:
        data = _sample()
        functions, _, stats, warnings = analyze_semantics(
            data, parse_binary(data, "elf"), max_instructions=1)
        self.assertEqual(stats["semantic_functions"], 1)
        self.assertEqual(stats["semantic_pending_symbols"], 1)
        self.assertEqual(functions[1]["analysis_scope"], "not_decoded")
        self.assertFalse(functions[0]["cfg"]["complete"])
        self.assertEqual(functions[0]["cfg"]["frontier"][0]["reason"], "instruction_limit")
        self.assertTrue(stats["semantic_budget_exhausted"])
        self.assertTrue(any("budget" in warning for warning in warnings))

    def test_conditional_branch_keeps_both_paths_and_skips_dead_padding(self) -> None:
        data = bytearray(_sample(helper_symbol=False))
        data[0x100:0x106] = bytes.fromhex("74 03 90 c3 90 c3")
        struct.pack_into("<Q", data, 0x180 + 24 + 16, 6)  # main symbol size
        functions, _, _, _ = analyze_semantics(bytes(data), parse_binary(bytes(data), "elf"))
        main = next(fn for fn in functions if fn["name"] == "main")
        self.assertEqual({ins["addr"] for block in main["blocks"]
                          for ins in block["instructions"]},
                         {0x401000, 0x401002, 0x401003, 0x401005})
        self.assertEqual({(e["src"], e["dst"], e["kind"]) for e in main["cfg"]["edges"]},
                         {(0x401000, 0x401002, "fallthrough"),
                          (0x401000, 0x401005, "branch")})
        self.assertTrue(main["cfg"]["complete"])

    def test_self_loop_is_preserved_as_cfg_edge(self) -> None:
        data = bytearray(_sample(helper_symbol=False))
        data[0x100:0x102] = bytes.fromhex("eb fe")
        struct.pack_into("<Q", data, 0x180 + 24 + 16, 2)
        functions, _, _, _ = analyze_semantics(bytes(data), parse_binary(bytes(data), "elf"))
        main = next(fn for fn in functions if fn["name"] == "main")
        self.assertEqual(main["cfg"]["edges"],
                         [{"src": 0x401000, "dst": 0x401000, "kind": "branch"}])
        self.assertTrue(main["cfg"]["complete"])

    def test_truncated_opcode_remains_an_undecoded_frontier(self) -> None:
        data = bytearray(_sample())
        data[0x100] = 0x0f  # x86 two-byte opcode prefix alone is incomplete.
        struct.pack_into("<Q", data, 0x180 + 24 + 16, 1)
        functions, _, _, _ = analyze_semantics(bytes(data), parse_binary(bytes(data), "elf"))
        main = next(fn for fn in functions if fn["name"] == "main")
        self.assertFalse(main["cfg"]["complete"])
        self.assertEqual(main["blocks"], [])
        self.assertEqual(main["cfg"]["frontier"][0]["reason"], "undecoded")

    def test_cancel_inside_function_retains_a_partial_graph_and_known_symbols(self) -> None:
        data = _sample()
        checks = 0

        def stop() -> bool:
            nonlocal checks
            checks += 1
            return checks >= 3  # Initial check + first instruction + cancel.

        events: list[dict] = []
        functions, xrefs, stats, warnings = analyze_semantics(
            data, parse_binary(data, "elf"), is_cancelled=stop, on_progress=events.append)
        self.assertEqual([event["event"] for event in events],
                         ["started", "function", "done"])
        json.dumps(events)  # IPC can forward these events without adaptation.
        self.assertTrue(stats["semantic_cancelled"])
        self.assertFalse(stats["semantic_budget_exhausted"])
        self.assertEqual(functions[0]["cfg"]["frontier"][0]["reason"], "cancelled")
        self.assertEqual(functions[1]["analysis_scope"], "not_decoded")
        self.assertEqual(len(xrefs), 1)  # A decoded call remains useful evidence.
        self.assertTrue(any("cancelled" in warning for warning in warnings))
        self.assertEqual(events[-1]["decoded_instructions"], 1)

    def test_progress_callback_failure_does_not_abort_analysis(self) -> None:
        data = _sample()

        def fail(_event: dict) -> None:
            raise ValueError("consumer unavailable")

        functions, _, stats, warnings = analyze_semantics(
            data, parse_binary(data, "elf"), max_workers=2, on_progress=fail)
        self.assertEqual(stats["semantic_functions"], 2)
        self.assertFalse(stats["semantic_cancelled"])
        self.assertEqual(stats["semantic_parallel_functions"], 0)
        self.assertTrue(all(fn["cfg"]["complete"] for fn in functions))
        self.assertEqual(sum("Progress callback failed" in warning for warning in warnings), 1)

    def test_large_function_emits_instruction_progress(self) -> None:
        data = bytearray(_sample(helper_symbol=False))
        data[0x100:0x121] = b"\x90" * 32 + b"\xc3"
        section_names = b"\0.text\0.shstrtab\0"
        data[0x130:0x130 + len(section_names)] = section_names
        struct.pack_into("<Q", data, 0x280 + 24, 0x130)  # Move section names.
        struct.pack_into("<Q", data, 0x40 + 32, 33)
        struct.pack_into("<Q", data, 0x40 + 40, 33)
        struct.pack_into("<Q", data, 0x240 + 32, 33)
        struct.pack_into("<Q", data, 0x180 + 24 + 16, 33)
        events: list[dict] = []
        functions, _, stats, _ = analyze_semantics(
            bytes(data), parse_binary(bytes(data), "elf"), on_progress=events.append)
        self.assertTrue(functions[0]["cfg"]["complete"])
        self.assertEqual(stats["semantic_instructions"], 33)
        self.assertEqual([event["decoded_instructions"] for event in events
                          if event["event"] == "instructions"], [32])

    def test_call_into_middle_of_instruction_has_xref_but_no_new_function(self) -> None:
        data = bytearray(_sample(helper_symbol=False))
        data[0x100:0x105] = bytes.fromhex("e8 fc ff ff ff")  # call 0x401001
        functions, xrefs, stats, warnings = analyze_semantics(
            bytes(data), parse_binary(bytes(data), "elf"))
        self.assertEqual([fn["name"] for fn in functions], ["main"])
        self.assertEqual(xrefs[0]["dst"], 0x401001)
        self.assertEqual(stats["semantic_ambiguous_call_targets"], 1)
        self.assertTrue(any("overlap" in warning for warning in warnings))


class LivenessTests(unittest.TestCase):
    def test_backward_dataflow_across_blocks(self) -> None:
        blocks = [
            {"start": 0x10, "instructions": [{"addr": 0x10, "reads": ["rdi"],
                                                "writes": ["rax"]}]},
            {"start": 0x20, "instructions": [{"addr": 0x20, "reads": ["rax"],
                                                "writes": ["rbx"]}]},
            {"start": 0x30, "instructions": [{"addr": 0x30, "reads": ["rbx"],
                                                "writes": []}]},
        ]
        edges = [{"src": 0x10, "dst": 0x20}, {"src": 0x20, "dst": 0x30}]
        flow = _liveness(blocks, edges, True, "capstone")
        self.assertTrue(flow["available"])
        by_start = {block["start"]: block for block in flow["blocks"]}
        self.assertEqual(by_start[0x10]["live_in"], ["rdi"])
        self.assertEqual(by_start[0x10]["live_out"], ["rax"])
        self.assertEqual(by_start[0x20]["live_out"], ["rbx"])
        self.assertEqual(by_start[0x30]["live_in"], ["rbx"])

    def test_fallback_marks_register_evidence_unavailable(self) -> None:
        self.assertFalse(_liveness([], [], False, "objdump")["available"])


if __name__ == "__main__":
    unittest.main()
