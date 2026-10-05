"""Coverage, compatibility and actual thread identities for opt-in full mode."""
from contextlib import ExitStack
from pathlib import Path
from threading import Event, get_ident
import tempfile
import unittest
from unittest.mock import patch

from fangida.api import AnalysisView
from fangida.benchmark import _evidence_digest
from fangida.core.kkagent import full_analysis
from fangida.core.kkagent.test_semantic import _sample, DECODER_AVAILABLE
from fangida.dispatcher import AnalysisService
from fangida.loaders.models import BinaryImage
from fangida.processors.decoder import NativeDecoder
from fangida.settings import Settings
from fangida.xrefs import XrefStage


@unittest.skipUnless(DECODER_AVAILABLE, "A native decoder is required")
class FullAnalysisTests(unittest.TestCase):
    def test_full_sweeps_padding_and_exceeds_legacy_per_function_cap(self):
        data = b"\x90" * 600 + b"\xc3"
        image = BinaryImage("elf", "x86_64", 64, "little", entry_address=0x1000,
                            sections=[{"name": ".text", "address": 0x1000,
                                       "offset": 0, "size": len(data), "executable": True}])
        with XrefStage() as stage:
            functions, _, stats, metadata, _ = full_analysis.analyze_full(
                data, image, workers=1, xref_stage=stage)
        self.assertEqual(stats["full_instructions"], 601)
        self.assertTrue(stats["full_decode_complete"])
        self.assertEqual(stats["full_unassigned_instructions"], 0)
        self.assertEqual(sum(len(block["instructions"]) for block in functions[0]["blocks"]), 601)
        self.assertTrue(functions[0]["cfg"]["complete"])
        self.assertFalse(metadata["full_analysis"]["function_recovery_complete"])

    def test_single_and_multi_worker_evidence_matches_and_progress_keeps_separation(self):
        data = _sample()
        digests = []
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.elf"
            path.write_bytes(data)
            for budget in (1, 3):
                decoded, indexed = set(), set()
                def observe(function, target):
                    def wrapped(*args, **kwargs):
                        target.add(get_ident())
                        return function(*args, **kwargs)
                    return wrapped
                events = []
                with ExitStack() as stack:
                    stack.enter_context(patch.object(NativeDecoder, "decode_bytes_fast",
                        observe(NativeDecoder.decode_bytes_fast, decoded)))
                    stack.enter_context(patch.object(full_analysis._CachedDecoder, "decode",
                        observe(full_analysis._CachedDecoder.decode, decoded)))
                    for name in ("_references", "index_references"):
                        stack.enter_context(patch.object(full_analysis, name,
                            observe(getattr(full_analysis, name), indexed)))
                    with AnalysisService(Settings(analyze_threads=budget, semantic_threads=2)) as service:
                        result = service.analyze(path, full_analysis=True, on_progress=events.append)
                self.assertNotEqual(result.status, "error", result.warnings)
                self.assertFalse(any("Progress callback failed" in item for item in result.warnings))
                self.assertTrue(events)
                self.assertTrue(decoded)
                self.assertTrue(indexed)
                self.assertEqual(decoded, indexed) if budget == 1 else self.assertTrue(decoded.isdisjoint(indexed))
                self.assertTrue(result.stats["full_decode_complete"])
                self.assertEqual(result.stats["full_instructions"], 6)
                self.assertTrue(any(ref["kind"] == "call" for ref in result.xrefs))
                self.assertEqual(len(AnalysisView(result).disassembly(0x401006)), 4)
                digests.append(_evidence_digest(result))
            self.assertEqual(*digests)

    def test_unwind_roots_are_consumed_without_mutating_loader_records(self):
        data = b"\xc3\x90\xc3"
        image = BinaryImage("elf", "x86_64", 64, "little", entry_address=0x1000,
                            sections=[{"address": 0x1000, "offset": 0, "size": 3, "executable": True}])
        root = {"start": 0x1002, "name": "declared", "size": 1,
                "source": "eh_frame", "boundary_scope": "unwind_range"}
        with patch("fangida.loaders.elf.recover_function_ranges", return_value=([root], [])):
            with XrefStage() as stage:
                functions, _, _, _, _ = full_analysis.analyze_full(data, image, workers=1, xref_stage=stage)
        self.assertEqual(image.functions, [])
        recovered = next(fn for fn in functions if fn["start"] == 0x1002)
        self.assertEqual(recovered["source"], "eh_frame")
        self.assertTrue(recovered["cfg"]["complete"])

    def test_cancel_and_explicit_scan_limit_do_not_claim_complete_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.elf"
            path.write_bytes(_sample())
            with AnalysisService(Settings()) as service:
                limited = service.analyze(path, full_analysis=True, max_bytes=0x105)
                self.assertFalse(limited.stats["full_decode_complete"])
                self.assertTrue(limited.metadata["full_analysis"]["input_truncated"])
                stop = Event()
                def progress(event):
                    if event.get("stage") == "native_full":
                        stop.set()
                interrupted = service.analyze(path, full_analysis=True, cancel=stop, on_progress=progress)
                self.assertTrue(interrupted.stats.get("cancelled"))
                self.assertNotEqual(interrupted.status, "error", interrupted.warnings)

    def test_full_option_validation_and_unsupported_container(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.unknown"
            path.write_bytes(b"unsupported format")
            with AnalysisService(Settings()) as service:
                with self.assertRaisesRegex(ValueError, "supports ELF"):
                    service.analyze(path, full_analysis=True)
                with self.assertRaisesRegex(ValueError, "boolean"):
                    service.analyze(path, full_analysis=1)


class FullAnalysisAuditTests(unittest.TestCase):
    """Keep stage/root validation independent of optional native decoders."""

    @staticmethod
    def instruction(address, kind=None, target=None):
        return {"addr": address, "size": 1,
                "mnemonic": "ret" if kind == "return" else "nop",
                "operands": (), "reads": (), "writes": (),
                "branch_info": {"kind": kind, "target": target} if kind else {},
                "arch_meta": {"engine": "test"}}

    @staticmethod
    def coverage(size):
        return [{"address": 0x1000, "offset": 0, "size": size,
                 "decoded_bytes": size, "instruction_count": size,
                 "complete": True, "engine": "test", "worker_id": None}]

    def test_unmapped_declaration_cannot_suppress_executable_roots(self):
        cache = {address: self.instruction(address) for address in range(0x1000, 0x1010)}
        image = BinaryImage("pe", "x86_64", 64, "little",
                            sections=[{"address": 0x1000, "offset": 0, "size": 16,
                                       "executable": True}],
                            functions=[{"start": 0x900, "size": 0x1000,
                                        "name": "bad_symbol", "source": "symtab"}])
        seeds, warnings = full_analysis._roots(
            bytes(16), image, cache,
            [{"src": 0x1000, "dst": 0x1008, "kind": "call"}], self.coverage(16))
        starts = {seed["start"] for seed in seeds}
        self.assertIn(0x1000, starts)
        self.assertIn(0x1008, starts)
        self.assertTrue(any("0x900" in warning for warning in warnings), warnings)

    def test_mapped_declaration_with_invalid_size_cannot_hide_call_targets(self):
        cache = {address: self.instruction(address) for address in range(0x1000, 0x1010)}
        symbol = {"start": 0x1000, "size": 0x1000, "name": "bad_range",
                  "source": "symtab"}
        image = BinaryImage("pe", "x86_64", 64, "little",
                            sections=[{"address": 0x1000, "offset": 0, "size": 16,
                                       "executable": True}], functions=[symbol])
        seeds, warnings = full_analysis._roots(
            bytes(16), image, cache,
            [{"src": 0x1000, "dst": 0x1008, "kind": "call"}], self.coverage(16))
        self.assertIn(0x1008, {seed["start"] for seed in seeds})
        declaration = next(seed for seed in seeds if seed["start"] == 0x1000)
        self.assertIsNone(declaration["size"])
        self.assertFalse(declaration["boundary_known"])
        self.assertEqual(declaration["declared_size"], 0x1000)
        self.assertTrue(any("0x1000" in warning for warning in warnings), warnings)
        self.assertEqual(symbol["size"], 0x1000)

    def test_xref_cancellation_is_latched_before_cfg_or_final_statistics(self):
        cache = {0x1000: self.instruction(0x1000, "call", 0x1002),
                 0x1001: self.instruction(0x1001, "return"),
                 0x1002: self.instruction(0x1002, "return")}
        image = BinaryImage("pe", "x86_64", 64, "little", entry_address=0x1000,
                            sections=[{"address": 0x1000, "offset": 0, "size": 3,
                                       "executable": True}])
        checks = 0

        def cancelled_once():
            nonlocal checks
            checks += 1
            return checks == 1

        with patch.object(full_analysis, "stream_decode_regions",
                          return_value=(cache, self.coverage(3), [])):
            with XrefStage() as stage:
                _, references, stats, metadata, warnings = full_analysis.analyze_full(
                    bytes(3), image, workers=1, xref_stage=stage,
                    is_cancelled=cancelled_once)
        self.assertEqual(references, [])
        self.assertTrue(stats["semantic_cancelled"])
        self.assertEqual(stats["full_cfg_functions"], 0)
        # Decode had already completed; later cancellation must preserve its
        # evidence while marking the omitted xref/CFG work as cancelled.
        self.assertTrue(metadata["full_analysis"]["decode_complete"])
        self.assertTrue(any("cancel" in warning.lower() for warning in warnings), warnings)

    def test_cancelled_cfg_attempt_is_not_counted_as_a_completed_pass(self):
        cache = {0x1000: self.instruction(0x1000),
                 0x1001: self.instruction(0x1001, "return")}
        image = BinaryImage("pe", "x86_64", 64, "little", entry_address=0x1000,
                            sections=[{"address": 0x1000, "offset": 0, "size": 2,
                                       "executable": True}])
        stop = Event()
        original_decode = full_analysis._CachedDecoder.decode

        def decode_then_cancel(*args, **kwargs):
            result = original_decode(*args, **kwargs)
            stop.set()
            return result

        with patch.object(full_analysis, "stream_decode_regions",
                          return_value=(cache, self.coverage(2), [])), \
                patch.object(full_analysis._CachedDecoder, "decode", decode_then_cancel):
            with XrefStage() as stage:
                functions, _, stats, metadata, _ = full_analysis.analyze_full(
                    bytes(2), image, workers=1, xref_stage=stage, is_cancelled=stop.is_set)
        self.assertTrue(stats["semantic_cancelled"])
        self.assertTrue(stats["full_xref_pass_complete"])
        self.assertTrue(any(item["reason"] == "cancelled"
                            for function in functions for item in function["cfg"]["frontier"]))
        self.assertFalse(stats["full_cfg_pass_complete"])
        self.assertFalse(metadata["full_analysis"]["cfg_pass_complete"])


if __name__ == "__main__":
    unittest.main()
