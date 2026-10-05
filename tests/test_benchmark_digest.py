"""benchmark._evidence_digest 必须与改动前的冻结实现逐字节一致。"""
from __future__ import annotations

from contextlib import ExitStack
from hashlib import sha256
import json
import math
from pathlib import Path
import random
import tempfile
import unittest
from unittest.mock import patch

from fangida import _json_stream, benchmark
from fangida.core.kkagent.test_semantic import DECODER_AVAILABLE, _sample
from fangida.dispatcher import AnalysisService
from fangida.models import AnalysisResult
from fangida.settings import Settings


def _frozen_evidence_digest(result: AnalysisResult) -> str:
    """改动前 benchmark._evidence_digest 的冻结副本（排序键为默认分隔符的 json.dumps）。"""
    def sorted_records(items):
        return sorted(items, key=lambda item: json.dumps(item, sort_keys=True))

    evidence = {
        "kind": result.kind, "status": result.status,
        "functions": sorted_records(result.functions),
        "strings": sorted_records(result.strings),
        "imports": sorted_records(result.imports),
        "exports": sorted_records(result.exports),
        "xrefs": sorted_records(result.xrefs),
        "metadata": result.metadata,
        "warnings": sorted(result.warnings),
    }
    digest = sha256()
    encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"))
    for chunk in encoder.iterencode(evidence):
        digest.update(chunk.encode())
    return digest.hexdigest()


# 结构性逗号/冒号与字符串内的 ", "、": "、引号、括号混杂，专门考验“紧凑文本排序 == 历史排序”。
_ALPHABET = ["a", "b", ",", ":", " ", ", ", ": ", "\"", "\\", "[", "]", "{", "}", "0", "1",
             "-", ".", "é", "中", "\n", "\x00", "😀", "\ud800"]


def _text(rng: random.Random) -> str:
    return "".join(rng.choice(_ALPHABET) for _ in range(rng.randrange(4)))


def _scalar(rng: random.Random):
    return rng.choice([None, True, False, 0, 1, -1, 10, 1.5, -0.0, 1e-7, 1e300, math.inf,
                       -math.inf, math.nan, _text(rng), _text(rng)])


def _value(rng: random.Random, depth: int):
    roll = rng.random()
    if depth <= 0 or roll < 0.4:
        return _scalar(rng)
    if roll < 0.7:
        return [_value(rng, depth - 1) for _ in range(rng.randrange(4))]
    return {_text(rng): _value(rng, depth - 1) for _ in range(rng.randrange(4))}


def _record(rng: random.Random) -> dict:
    record = {"name": _text(rng), "start": rng.randrange(-2, 3)}
    for _ in range(rng.randrange(3)):
        record[_text(rng)] = _value(rng, 3)
    return record


# 历史排序键与紧凑文本最容易出现分歧的手工样本：字符串内的逗号/空格紧邻结构性逗号。
_TRICKY = [
    {"a": "x, y"}, {"a": "x,", "b": 1}, {"a": "x", "b": 1}, {"a": "x ", "b": 1},
    {"a": [1, 2]}, {"a": [1], "b": 2}, {"a": "1, 2"}, {"a": [1, 2], "b": None},
    {"a": 1}, {"a": 10}, {"a": -1}, {"a": 1.5}, {"a": None}, {"a ": 1}, {"a": " 1"},
    {"a": {"b": 1}, "c": 2}, {"a": {"b": 1, "c": 2}}, {"a": {"b": "1,\"c\":2"}},
    {"a:": 1}, {"a": ":1"}, {"": ""}, {}, {"a": []}, {"a": [[]]}, {"a": [{}]},
]


def _instructions(count: int) -> list:
    return [{"addr": 0x1000 + index, "size": 2, "mnemonic": "mov", "operands": ("eax", "ebx"),
             "branch_info": {}, "arch_meta": {"engine": "capstone", "z": index, "a": [index]}}
            for index in range(count)]


def _result(rng: random.Random) -> AnalysisResult:
    instructions = _instructions(300)
    functions = [{**_record(rng), "blocks": [{"start": 0x1000, "instructions": instructions[:20]}]}
                 for _ in range(10)] + [_record(rng) for _ in range(20)]
    # 重复记录：排序并列项在两种实现中都必须产出相同文本。
    functions += functions[:3] + [dict(item) for item in _TRICKY]
    return AnalysisResult(
        "sample.elf", "elf", "kkagent", rng.choice(["partial", "ok"]),
        metadata={"full_disassembly": instructions, "full_analysis": {"enabled": True, "z": [], "a": {}},
                  "sections": [{"name": ".text", "flags": ("x", "r")}], "note": "中文 ",
                  "zz": _value(rng, 3), "aa": [_value(rng, 2) for _ in range(5)]},
        functions=functions,
        strings=[_record(rng) for _ in range(20)] + list(_TRICKY),
        imports=[_record(rng) for _ in range(5)], exports=[],
        xrefs=[{"src": rng.randrange(50), "dst": rng.randrange(50), "kind": rng.choice(["call", "jump"]),
                "confidence": rng.choice([1.0, 0.5])} for _ in range(400)],
        stats={"full_analysis": True, "phase_seconds": {"disassembly": 1.0}},
        warnings=["b", "a", "中", "a"])


class EvidenceDigestEquivalenceTests(unittest.TestCase):
    def test_synthetic_results_match_frozen_implementation(self):
        for seed in range(8):
            result = _result(random.Random(seed))
            with self.subTest(seed=seed):
                self.assertEqual(benchmark._evidence_digest(result), _frozen_evidence_digest(result))
        empty = AnalysisResult("x", "elf", "kkagent", "error")
        self.assertEqual(benchmark._evidence_digest(empty), _frozen_evidence_digest(empty))

    def test_record_batches_and_unit_backends_do_not_change_digest(self):
        """记录分批哈希的边界、C 编码器缺失或被拒绝时摘要都不变。"""
        result = _result(random.Random(99))
        expected = _frozen_evidence_digest(result)
        cases = (
            ("tiny-batches", ((_json_stream, "DEFAULT_CHUNK_SIZE", 1),)),
            ("small-batches", ((_json_stream, "DEFAULT_CHUNK_SIZE", 100),)),
            ("python-units", ((_json_stream, "_C_INDENT_OK", False),
                              (_json_stream, "_C_COMPACT_OK", False))),
            ("no-c-encoder", ((json.encoder, "c_make_encoder", None),)),
        )
        for name, patches in cases:
            with self.subTest(name), ExitStack() as stack:
                for target, attribute, value in patches:
                    stack.enter_context(patch.object(target, attribute, value))
                self.assertEqual(benchmark._evidence_digest(result), expected)

    def test_unencodable_records_fail_like_frozen_implementation(self):
        for field_name, value in (("functions", [{"x": object()}]), ("xrefs", [{1: 1, "a": 2}])):
            result = AnalysisResult("x", "elf", "kkagent", "ok", **{field_name: value})
            with self.assertRaises(TypeError):
                _frozen_evidence_digest(result)
            with self.assertRaises(TypeError):
                benchmark._evidence_digest(result)

    @unittest.skipUnless(DECODER_AVAILABLE, "Capstone or a supported objdump required")
    def test_small_elf_results_match_frozen_implementation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.elf"
            path.write_bytes(_sample())
            with AnalysisService(Settings(analyze_threads=2, semantic_threads=1, deep_analysis=True,
                                          ghidra_enabled=False)) as service:
                for full_analysis in (False, True):
                    result = service.analyze(path, full_analysis=full_analysis)
                    with self.subTest(full_analysis=full_analysis):
                        self.assertNotEqual(result.status, "error", result.warnings)
                        self.assertTrue(result.functions)
                        self.assertEqual(benchmark._evidence_digest(result),
                                         _frozen_evidence_digest(result))


if __name__ == "__main__":
    unittest.main()
