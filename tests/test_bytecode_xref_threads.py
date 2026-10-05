"""实测 DEX/JVM 解码与引用线程，验证单线程及旧返回格式。"""
from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
import struct
from tempfile import TemporaryDirectory
from threading import get_ident
import unittest
from unittest.mock import patch
import zipfile

from fangida.core.apk_analyzer import dex_analyzer, dex_bytecode, jvm_analyzer, jvm_bytecode, worker
from fangida.core.apk_analyzer.test_analyzer import sample_calling_class, sample_calling_dex
from fangida.models import AnalysisTask
from fangida.xrefs import XrefStage


def observe(function, threads: set[int]):
    def invoke(*args, **kwargs):
        threads.add(get_ident())
        return function(*args, **kwargs)
    return invoke


class BytecodeXrefThreadTests(unittest.TestCase):
    def test_parsers_use_separate_xref_thread_and_keep_old_complete_results(self) -> None:
        for analyzer, bytecode, frame_name, fixture, source in (
            (dex_analyzer, dex_bytecode, "_width", sample_calling_dex, "classes.dex"),
            (jvm_analyzer, jvm_bytecode, "_instruction_length", sample_calling_class, "Foo.class"),
        ):
            parser = analyzer.parse_dex if analyzer is dex_analyzer else analyzer.parse_class
            baseline = asdict(parser(fixture(), source))
            for separate in (False, True):
                decode_threads: set[int] = set()
                xref_threads: set[int] = set()
                api_threads: set[int] = set()
                with self.subTest(backend=source, separate=separate), \
                     patch.object(bytecode, frame_name, observe(getattr(bytecode, frame_name), decode_threads)), \
                     patch.object(bytecode, "_resolve_invocations", observe(bytecode._resolve_invocations, xref_threads)), \
                     patch.object(analyzer, "_api_calls", observe(analyzer._api_calls, api_threads)), \
                     XrefStage(separate_thread=separate) as stage:
                    summary = parser(fixture(), source, xref_stage=stage)
                    self.assertEqual(asdict(summary), baseline)
                    self.assertEqual(decode_threads, {get_ident()})
                    self.assertEqual(xref_threads, api_threads)
                    self.assertEqual(len(xref_threads), 1)
                    self.assertEqual(decode_threads.isdisjoint(xref_threads), separate)
                    self.assertIn(stage.run(get_ident), xref_threads)

    def test_bounded_invocation_batches_preserve_validation_after_output_limit(self) -> None:
        # 输出限额不能导致忽略后续方法引用，也不能积累无界快照。
        for bytecode in (dex_bytecode, jvm_bytecode):
            resolutions: list[int] = []
            batches: list[int] = []
            xref_threads: set[int] = set()

            def method(index):
                resolutions.append(index)
                xref_threads.add(get_ident())
                return "Example->call", "()V"

            original = bytecode._resolve_invocations

            def resolve(sites, *args):
                batches.append(len(sites))
                return original(sites, *args)

            with self.subTest(backend=bytecode.__name__), \
                 XrefStage(separate_thread=True) as stage, \
                 patch.object(bytecode, "_resolve_invocations", side_effect=resolve):
                if bytecode is jvm_bytecode:
                    listing, calls, scanned, truncated = bytecode.decode_code(
                        b"\xb8\x00\x01" * 600 + b"\xb1", method, "Caller", "Foo.class", 10,
                        max_output=1, max_calls=0, xref_stage=stage)
                else:
                    class Reader:
                        data = struct.pack("<HHHHII", 1, 0, 0, 0, 0, 1801) + \
                               struct.pack("<HHH", 0x1071, 1, 0) * 600 + b"\x0e\x00"

                        def u16(self, offset):
                            return struct.unpack_from("<H", self.data, offset)[0]

                        def u32(self, offset):
                            return struct.unpack_from("<I", self.data, offset)[0]

                        def method(self, index):
                            return method(index)

                    listing, calls, scanned, truncated = bytecode.decode_code(
                        Reader(), 0, "Caller", "classes.dex", max_output=1, max_calls=0,
                        xref_stage=stage)
                self.assertEqual((len(listing), len(calls), scanned, truncated), (1, 0, 601, False))
                self.assertEqual(listing[0]["operands"], ["Example->call()V"])
                self.assertEqual(resolutions, [1] * 600)
                self.assertTrue(batches and max(batches) <= 256)
                self.assertEqual(len(xref_threads), 1)
                self.assertNotIn(get_ident(), xref_threads)

    def test_archive_reuses_one_xref_stage_for_dex_jvm_and_aggregate_index(self) -> None:
        with TemporaryDirectory() as directory:
            archive_path = Path(directory) / "mixed.apk"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("classes.dex", sample_calling_dex())
                archive.writestr("classes2.dex", sample_calling_dex())
                archive.writestr("Foo.class", sample_calling_class())
                archive.writestr("Other.class", sample_calling_class())
            for configured in (0, 1):
                stages: list[XrefStage] = []
                decode_threads: set[int] = set()
                xref_threads: set[int] = set()
                index_threads: set[int] = set()

                def make_stage(*args, **kwargs):
                    stage = XrefStage(*args, **kwargs)
                    stages.append(stage)
                    return stage

                with self.subTest(xref_threads=configured), \
                     patch.object(worker, "XrefStage", side_effect=make_stage), \
                     patch.object(worker, "_record_invocations", observe(worker._record_invocations, index_threads)), \
                     patch.object(dex_bytecode, "_width", observe(dex_bytecode._width, decode_threads)), \
                     patch.object(jvm_bytecode, "_instruction_length", observe(jvm_bytecode._instruction_length, decode_threads)), \
                     patch.object(dex_bytecode, "_resolve_invocations", observe(dex_bytecode._resolve_invocations, xref_threads)), \
                     patch.object(jvm_bytecode, "_resolve_invocations", observe(jvm_bytecode._resolve_invocations, xref_threads)):
                    result = worker.analyze(AnalysisTask(str(archive_path), "apk", xref_threads=configured))
                    self.assertEqual(result.status, "partial")
                    self.assertEqual(len(result.metadata["direct_invocations"]), 4)
                    self.assertEqual(len(result.metadata["api_calls"]), 4)
                    self.assertEqual(len(stages), 1)
                    self.assertEqual(xref_threads, index_threads)
                    self.assertEqual(len(xref_threads), 1)
                    self.assertEqual(decode_threads.isdisjoint(xref_threads), bool(configured))
                    self.assertEqual(result.stats["xref_worker_threads"], configured)
                with self.assertRaises(RuntimeError):
                    stages[0].run(lambda: None)

    def test_invalid_reference_is_not_hidden_by_zero_call_limit(self) -> None:
        def invalid(_):
            raise ValueError("invalid method")

        with XrefStage(separate_thread=True) as stage:
            with self.assertRaisesRegex(ValueError, "invalid method"):
                jvm_bytecode.decode_code(b"\xb8\x00\x01", invalid, "Caller", "Foo.class", 0,
                                         max_calls=0, xref_stage=stage)

    def test_multiple_workers_cannot_disable_reference_thread_with_zero_hint(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "Foo.class"
            path.write_bytes(sample_calling_class())
            threads: set[int] = set()
            with patch.object(jvm_bytecode, "_resolve_invocations", observe(jvm_bytecode._resolve_invocations, threads)):
                result = worker.analyze(AnalysisTask(str(path), "class", semantic_threads=2, xref_threads=0))
            self.assertEqual(result.stats["xref_worker_threads"], 1)
            self.assertEqual(len(threads), 1)
            self.assertNotIn(get_ident(), threads)


if __name__ == "__main__":
    unittest.main()
