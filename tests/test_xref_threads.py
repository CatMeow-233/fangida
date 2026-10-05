"""Thread identity and evidence checks for the independent xref stage."""
from __future__ import annotations

from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from fangida.core import kkagent
from fangida.core.kkagent import semantic
from fangida.core.kkagent.binary import parse_binary
from fangida.core.kkagent.test_semantic import DECODER_AVAILABLE, _sample
from fangida.dispatcher import AnalysisService
from fangida.settings import Settings
from fangida.xrefs import XrefStage


@unittest.skipUnless(DECODER_AVAILABLE, "A native instruction decoder is required")
class XrefThreadTests(unittest.TestCase):
    def observe(self, decode_ids: set[int], xref_ids: set[int], *, entry: bool = False):
        patches = []
        lock = threading.Lock()

        def wrap(function, target):
            def observed(*args, **kwargs):
                with lock:
                    target.add(threading.get_ident())
                return function(*args, **kwargs)
            return observed

        patches.append(patch.object(semantic._Decoder, "decode",
                                    wrap(semantic._Decoder.decode, decode_ids)))
        for name in ("function_references", "merge_references", "index_references", "sorted_references"):
            patches.append(patch.object(semantic, name, wrap(getattr(semantic, name), xref_ids)))
        if entry:
            patches.append(patch.object(kkagent, "disassemble_entry",
                                        wrap(kkagent.disassemble_entry, decode_ids)))
            for name in ("direct_references", "index_entry_references"):
                patches.append(patch.object(kkagent, name, wrap(getattr(kkagent, name), xref_ids)))
        from contextlib import ExitStack
        stack = ExitStack()
        for item in patches:
            stack.enter_context(item)
        return stack

    def test_multi_worker_decoding_and_xrefs_have_disjoint_threads(self) -> None:
        data = _sample()
        image = parse_binary(data, "elf")
        expected = semantic.analyze_semantics(data, image)
        decoded: set[int] = set()
        indexed: set[int] = set()
        with self.observe(decoded, indexed):
            actual = semantic.analyze_semantics(data, image, max_workers=2)
        self.assertTrue(decoded)
        self.assertEqual(len(indexed), 1)
        self.assertTrue(decoded.isdisjoint(indexed))
        self.assertEqual(actual[:2], expected[:2])

    def test_callbacks_and_conflict_replay_keep_thread_separation(self) -> None:
        # main discovers an address inside helper, forcing speculative replay.
        data = bytearray(_sample())
        data[0x101] = 4
        for callbacks in (False, True):
            with self.subTest(callbacks=callbacks):
                decoded: set[int] = set()
                indexed: set[int] = set()
                events: list[dict] = []
                controls = {"on_progress": events.append, "is_cancelled": lambda: False} if callbacks else {}
                with self.observe(decoded, indexed):
                    result = semantic.analyze_semantics(
                        bytes(data), parse_binary(bytes(data), "elf"), max_workers=2, **controls)
                self.assertEqual(result[2]["semantic_parallel_functions"], 0)
                self.assertTrue(decoded.isdisjoint(indexed))
                self.assertTrue(indexed)

    def test_single_worker_stays_on_one_thread(self) -> None:
        data = _sample()
        decoded: set[int] = set()
        indexed: set[int] = set()
        with self.observe(decoded, indexed):
            semantic.analyze_semantics(data, parse_binary(data, "elf"))
        self.assertEqual(decoded, {threading.get_ident()})
        self.assertEqual(decoded, indexed)

    def test_service_fast_and_deep_respect_the_total_thread_budget(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.elf"
            path.write_bytes(_sample())
            for budget in (1, 2):
                for deep in (False, True):
                    with self.subTest(budget=budget, deep=deep):
                        decoded: set[int] = set()
                        indexed: set[int] = set()
                        with self.observe(decoded, indexed, entry=True):
                            with AnalysisService(Settings(analyze_threads=budget, semantic_threads=4)) as service:
                                result = service.analyze(path, deep_analysis=deep)
                        self.assertNotEqual(result.status, "error", result.warnings)
                        self.assertTrue(decoded)
                        self.assertTrue(indexed)
                        if budget == 1:
                            self.assertEqual(decoded, indexed)
                        else:
                            self.assertTrue(decoded.isdisjoint(indexed))

    def test_cancelled_partial_xrefs_still_use_the_reference_worker(self) -> None:
        data = _sample()
        checks = 0

        def stop():
            nonlocal checks
            checks += 1
            return checks >= 3

        decoded: set[int] = set()
        indexed: set[int] = set()
        with self.observe(decoded, indexed):
            result = semantic.analyze_semantics(data, parse_binary(data, "elf"),
                                                max_workers=2, is_cancelled=stop)
        self.assertTrue(result[2]["semantic_cancelled"])
        self.assertEqual(len(result[1]), 1)
        self.assertTrue(decoded.isdisjoint(indexed))

    def test_an_inline_stage_cannot_override_multi_worker_separation(self) -> None:
        data = _sample()
        with XrefStage() as stage:
            with self.assertRaisesRegex(ValueError, "separate xref thread"):
                semantic.analyze_semantics(data, parse_binary(data, "elf"),
                                           max_workers=2, xref_stage=stage)

    def test_stage_exception_and_nested_calls_do_not_leak_workers(self) -> None:
        with XrefStage(separate_thread=True) as stage:
            with self.assertRaisesRegex(ValueError, "broken index"):
                stage.run(lambda: (_ for _ in ()).throw(ValueError("broken index")))
            self.assertEqual(stage.run(lambda: stage.run(lambda: 7)), 7)
        with self.assertRaisesRegex(RuntimeError, "closed"):
            stage.run(lambda: 8)


if __name__ == "__main__":
    unittest.main()
