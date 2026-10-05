"""字符串地址取址、有限状态和各分析模式的独立引用阶段回归。"""
from __future__ import annotations

from contextlib import ExitStack
import importlib.util
from pathlib import Path
import struct
import tempfile
from threading import get_ident
import unittest
from unittest.mock import patch

from fangida.core.kkagent import full_analysis
from fangida.core.kkagent import semantic
from fangida.dispatcher import AnalysisService
from fangida.loaders.models import BinaryImage
from fangida.processors.decoder import NativeDecoder, decode_objdump
from fangida.processors.full_decode import stream_decode_regions
from fangida.settings import Settings
from fangida.xrefs import (DataRangeIndex, ReferenceState, XrefStage, direct_references,
                           function_references, mapped_data_ranges)


def _adrp(address: int, target: int, register: int = 0) -> bytes:
    pages = ((target & ~0xfff) - (address & ~0xfff)) >> 12
    encoded = 0x90000000 | ((pages & 3) << 29) | (((pages >> 2) & 0x7ffff) << 5) | register
    return encoded.to_bytes(4, "little")


def _add(immediate: int = 0x340, destination: int = 0, source: int = 0, *,
         shifted: bool = False, wide: bool = True) -> bytes:
    encoded = (0x91000000 if wide else 0x11000000) | (int(shifted) << 22)
    return (encoded | (immediate << 10) | (source << 5) | destination).to_bytes(4, "little")


def _elf(code: bytes, architecture: str = "x86_64") -> bytes:
    """真实 ELF 容器：独立代码段/数据段，字符串仅经虚拟地址被引用。"""
    names = b"\0.text\0.rodata\0.shstrtab\0"
    text_offset, strings_offset = 0x100, 0x180
    strings = b"referenced string\0unused string\0"
    table_offset, names_offset = 0x200, 0x1c0
    machine = 62 if architecture == "x86_64" else 183
    ident = b"\x7fELF" + bytes((2, 1, 1)) + bytes(9)
    header = ident + struct.pack("<HHIQQQIHHHHHH", 2, machine, 1, 0x401000, 0,
                                table_offset, 0, 64, 0, 0, 64, 4, 3)
    data = bytearray(table_offset + 4 * 64)
    data[:64] = header
    data[text_offset:text_offset + len(code)] = code
    data[strings_offset:strings_offset + len(strings)] = strings
    data[names_offset:names_offset + len(names)] = names
    for index, values in enumerate((
        (1, 1, 6, 0x401000, text_offset, len(code), 0, 0, 1, 0),
        (7, 1, 2, 0x402000, strings_offset, len(strings), 0, 0, 1, 0),
        (15, 3, 0, 0, names_offset, len(names), 0, 0, 1, 0),
    ), 1):
        struct.pack_into("<IIQQQQIIQQ", data, table_offset + index * 64, *values)
    return bytes(data)


class CompletedSnapshotTests(unittest.TestCase):
    def test_rich_stream_still_uses_registered_public_processor_protocol(self):
        class PublicProcessor(NativeDecoder):
            engine, warning = "fixture", None
            def __init__(self):
                pass
            def decode_bytes(self, code, address, *, max_instructions=128):
                return [{"addr": address + index, "size": 1, "mnemonic": "nop",
                         "branch_info": {}, "arch_meta": {"engine": "fixture"}}
                        for index in range(len(code))], []
        data = b"x" * 8
        image = BinaryImage("elf", "fixture", 64, "little", sections=[
            {"address": 0x1000, "offset": 0, "size": 8, "executable": True}])
        with patch("fangida.processors.full_decode.get_processor", return_value=PublicProcessor()):
            records, coverage, warnings = stream_decode_regions(data, image, include_data=True)
        self.assertEqual(len(records), 8)
        self.assertTrue(coverage[0]["complete"])
        self.assertFalse(warnings)

    def test_legacy_control_reference_default_and_readonly_snapshot(self):
        instruction = {"addr": 0x1000, "size": 4, "branch_info": {},
                       "arch_meta": {"architecture": "x86_64", "memory_references": (0x2000,)}}
        self.assertEqual(direct_references((instruction,)), [])
        before = dict(instruction["arch_meta"])
        with patch.object(NativeDecoder, "decode_bytes", side_effect=AssertionError("引用阶段不能解码")), \
                patch.object(NativeDecoder, "decode_bytes_fast", side_effect=AssertionError("引用阶段不能解码")):
            refs = direct_references((instruction,), include_data=True)
        self.assertEqual(refs, [{"src": 0x1000, "dst": 0x2000, "kind": "data", "confidence": 1.0}])
        self.assertEqual(instruction["arch_meta"], before)

    def test_mapping_filters_unmapped_nobits_virtual_tail_and_outside_file(self):
        sections = [
            {"address": 0x2000, "offset": 100, "size": 40, "virtual_size": 8},
            {"address": 0, "offset": 10, "size": 20},
            {"address": 0x3000, "offset": 10, "size": 20, "allocated": False},
            {"address": 0x4000, "offset": 10, "size": 20, "mapped": False},
            {"address": 0x5000, "offset": 10, "size": 20, "type": 8},
            {"address": 0x6000, "offset": 10, "size": 20, "file_backed": False},
            {"address": 0x7000, "offset": 10, "size": 20, "executable": True},
            {"address": 0x8000, "offset": 150, "size": 20},
            {"address": 0x9000, "offset": 117, "size": 20},
        ]
        self.assertEqual(mapped_data_ranges(sections, kind="elf", file_size=120),
                         ((0x2000, 0x2008), (0x9000, 0x9003)))

    def test_pointer_candidates_require_mapped_data_and_never_change_call_seeds(self):
        records = [{"addr": 0x1000, "size": 4, "branch_info": {},
                    "arch_meta": {"address_candidates": (0x2000, 7, 0x3000)}},
                   {"addr": 0x1004, "size": 4, "branch_info": {"kind": "call", "target": 0x1010}}]
        refs, seeds = function_references(records, ((0x1000, 0x1020),), include_data=True,
                                         data_ranges=((0x2000, 0x2008),))
        self.assertEqual(seeds, {0x1010})
        self.assertEqual([ref["dst"] for ref in refs if ref["kind"] == "data"], [0x2000])
        candidate = next(ref for ref in refs if ref["kind"] == "data")
        self.assertEqual(candidate["evidence"], "mapped_immediate")
        self.assertLess(candidate["confidence"], 1.0)
        self.assertEqual(DataRangeIndex(((0x2000, 0x2008), (0x2004, 0x2010))).ends, (0x2010,))

    def test_objdump_completed_intel_operands_have_data_evidence_without_capstone(self):
        rendered = (
            "  1000: 48 8d 3d f9 0f 00 00\tlea rdi,[rip+0xff9] # 0x2000\n"
            "  1007: 48 8b 04 25 00 30 00 00\tmov rax,QWORD PTR ds:0x3000\n"
            "  100f: bf 00 40 00 00\tmov edi,0x4000\n"
            "  1014: 64 a1 00 20 00 00\tmov eax,DWORD PTR fs:0x2000\n"
        )
        legacy, _ = decode_objdump(b"x", 0x1000, "x86_64", render=lambda *_: (rendered, "llvm"))
        records, _ = decode_objdump(b"x", 0x1000, "x86_64", include_data=True,
                                    render=lambda *_: (rendered, "llvm"))
        self.assertTrue(all("memory_references" not in ins["arch_meta"] for ins in legacy))
        refs = direct_references(records, include_data=True, data_ranges=((0x4000, 0x4010),))
        self.assertEqual([(ref["src"], ref["dst"]) for ref in refs],
                         [(0x1000, 0x2000), (0x1007, 0x3000), (0x100f, 0x4000)])


@unittest.skipUnless(importlib.util.find_spec("capstone"), "Capstone unavailable")
class NativeAddressEvidenceTests(unittest.TestCase):
    def test_rich_fast_and_stream_are_explicit_and_retain_legacy_default_snapshots(self):
        code = bytes.fromhex("48 8b 04 25 00 20 00 00 bf 00 20 00 00 c3")
        decoder = NativeDecoder("x86_64")
        original, _ = decoder.decode_bytes(code, 0x1000)
        fast, _ = decoder.decode_bytes_fast(code, 0x1000)
        enriched, _ = decoder.decode_bytes_fast(code, 0x1000, include_data=True)
        self.assertEqual(fast, original)
        self.assertEqual(enriched[0]["arch_meta"]["memory_references"], (0x2000,))
        self.assertEqual(enriched[1]["arch_meta"]["address_candidates"], (0x2000,))
        image = BinaryImage("elf", "x86_64", 64, "little", sections=[
            {"address": 0x1000, "offset": 0, "size": len(code), "executable": True}])
        for chunk_bytes in (1, 7, 32, 65536):
            with self.subTest(chunk_bytes=chunk_bytes):
                records, _, _ = stream_decode_regions(code, image, chunk_bytes=chunk_bytes)
                rich, _, _ = stream_decode_regions(code, image, chunk_bytes=chunk_bytes, include_data=True)
                self.assertEqual(list(records.values()), original)
                self.assertEqual(list(rich.values()), enriched)
        for flag in (1, "true", None):
            with self.subTest(flag=flag):
                with self.assertRaisesRegex(ValueError, "boolean"):
                    decoder.decode_bytes_fast(code, 0x1000, include_data=flag)
                with self.assertRaisesRegex(ValueError, "boolean"):
                    stream_decode_regions(code, image, include_data=flag)

    def test_public_ir_defaults_remain_unchanged_and_new_flag_is_optional(self):
        decoder = NativeDecoder("x86_64")
        code = bytes.fromhex("48 8d 3d f9 0f 00 00")
        original, warnings = decoder.decode_bytes(code, 0x1000)
        enriched, extra = decoder.decode_bytes(code, 0x1000, include_data=True)
        self.assertFalse(warnings + extra)
        self.assertEqual(original[0]["arch_meta"], {"engine": "capstone", "architecture": "x86_64"})
        self.assertEqual(enriched[0]["arch_meta"]["memory_references"], (0x2000,))
        for flag in (1, "true", None):
            with self.assertRaisesRegex(ValueError, "boolean"):
                decoder.decode_bytes(code, 0x1000, include_data=flag)

    def test_absolute_memory_immediates_rip_address_and_tls_exclusion(self):
        for architecture, code, ranges, expected in (
            ("x86", "a1 00 20 00 00", (), [0x2000]),
            ("x86_64", "48 8b 04 25 00 20 00 00", (), [0x2000]),
            ("x86_64", "48 8d 3d f9 0f 00 00", (), [0x2000]),
            ("x86_64", "bf 00 20 00 00", (), []),
            ("x86_64", "bf 00 20 00 00", ((0x2000, 0x2020),), [0x2000]),
            ("x86_64", "83 c0 07", ((0, 0x3000),), []),
            ("x86_64", "64 48 8b 04 25 00 20 00 00", (), []),
            ("x86_64", "65 48 8d 3d f9 0f 00 00", (), []),
        ):
            with self.subTest(architecture=architecture, code=code, ranges=ranges):
                records, warnings = NativeDecoder(architecture).decode_bytes_fast(bytes.fromhex(code), 0x1000, include_data=True)
                self.assertFalse(warnings)
                refs = direct_references(records, include_data=True, data_ranges=ranges)
                self.assertEqual([ref["dst"] for ref in refs], expected)

    def test_arm64_adr_page_add_shift_and_memory_operand(self):
        adr = (0x10000000 | ((0x1000 >> 2) << 5)).to_bytes(4, "little")
        cases = [
            (adr, [(0x1000, 0x2000)]),
            (_adrp(0x1000, 0x2000) + _add(), [(0x1004, 0x2340)]),
            (_adrp(0x1000, 0x2000) + _add(1, shifted=True), [(0x1004, 0x3000)]),
            (_adrp(0x1000, 0x2000) + _add(destination=1) + bytes.fromhex("200440f9"),
             [(0x1004, 0x2340), (0x1008, 0x2348)]),
            (_adrp(0x1000, 0x2000, 29) + _add(source=29), [(0x1004, 0x2340)]),
        ]
        for code, expected in cases:
            with self.subTest(code=code.hex()):
                records, warnings = NativeDecoder("arm64").decode_bytes_fast(code, 0x1000, include_data=True)
                self.assertFalse(warnings)
                refs = direct_references(records, include_data=True)
                self.assertEqual([(ref["src"], ref["dst"]) for ref in refs], expected)

    def test_arm64_state_does_not_survive_gaps_control_flow_or_alias_writes(self):
        decoder = NativeDecoder("arm64")
        for middle in (bytes.fromhex("e003012a"),  # mov w0,w1 覆盖 x0
                       bytes.fromhex("01000094"),  # bl 清理调用前状态
                       bytes.fromhex("02000014"),  # b
                       bytes.fromhex("c0035fd6"),  # ret
                       _add(wide=False)):
            with self.subTest(middle=middle.hex()):
                records, warnings = decoder.decode_bytes_fast(_adrp(0x1000, 0x2000) + middle + _add(), 0x1000, include_data=True)
                self.assertFalse(warnings)
                self.assertEqual([ref for ref in direct_references(records, include_data=True)
                                  if ref["kind"] == "data"], [])
        state = ReferenceState()
        page, _ = decoder.decode_bytes_fast(_adrp(0x1000, 0x2000), 0x1000, include_data=True)
        add, _ = decoder.decode_bytes_fast(_add(), 0x1008, include_data=True)
        self.assertEqual(direct_references(page, include_data=True, state=state), [])
        self.assertEqual(direct_references(add, include_data=True, state=state), [])
        self.assertLessEqual(len(state.registers), 31)

    def test_arm64_contiguous_regions_cannot_share_address_state(self):
        code = _adrp(0x1000, 0x2000) + _add()
        records, warnings = NativeDecoder("arm64").decode_bytes_fast(code, 0x1000, include_data=True)
        self.assertFalse(warnings)
        refs, _ = function_references(records, ((0x1000, 0x1004), (0x1004, 0x1008)), include_data=True)
        self.assertEqual(refs, [])
        image = BinaryImage("macho", "arm64", 64, "little", sections=[
            {"address": 0x1000, "offset": 0, "size": 4, "executable": True},
            {"address": 0x1004, "offset": 4, "size": 4, "executable": True},
        ])
        with XrefStage() as stage:
            _, refs, _, _, _ = full_analysis.analyze_full(code, image, workers=1, xref_stage=stage)
        self.assertEqual(refs, [])

    def test_arm64_failed_register_access_discards_prior_address_state(self):
        import capstone
        decoder = NativeDecoder("arm64")
        original = capstone.CsInsn.regs_access
        def access(instruction):
            if instruction.address == 0x1004:
                raise ValueError("access unavailable")
            return original(instruction)
        with patch.object(capstone.CsInsn, "regs_access", access):
            records, warnings = decoder.decode_bytes_fast(
                _adrp(0x1000, 0x2000) + bytes.fromhex("e003012a") + _add(), 0x1000, include_data=True)
        self.assertFalse(warnings)
        self.assertEqual(direct_references(records, include_data=True), [])

    def test_page_pair_survives_full_bounded_batch_boundary_on_reference_thread(self):
        code = bytes.fromhex("1f2003d5") * 4095 + _adrp(0x4ffc, 0x8000) + _add() + bytes.fromhex("c0035fd6")
        data = code + b"target string\0"
        image = BinaryImage("macho", "arm64", 64, "little", entry_address=0x1000,
                            sections=[{"address": 0x1000, "offset": 0, "size": len(code), "executable": True},
                                      {"address": 0x8340, "offset": len(code), "size": 14, "executable": False}])
        decoded, indexed, batches = set(), set(), []
        original_decode, original_references = NativeDecoder.decode_bytes_fast, full_analysis._references
        def decode(*args, **kwargs):
            decoded.add(get_ident())
            return original_decode(*args, **kwargs)
        def references(snapshot, **kwargs):
            indexed.add(get_ident())
            batches.append(len(snapshot))
            return original_references(snapshot, **kwargs)
        with patch.object(NativeDecoder, "decode_bytes_fast", decode), \
                patch.object(full_analysis, "_references", references):
            with XrefStage(separate_thread=True) as stage:
                # 先启用长期存在的引用线程，避免已结束的解码线程 OS id 被复用。
                reference_id = stage.run(get_ident)
                _, refs, stats, _, _ = full_analysis.analyze_full(data, image, workers=2, xref_stage=stage)
        self.assertEqual([ref for ref in refs if ref["kind"] == "data"],
                         [{"src": 0x5000, "dst": 0x8340, "kind": "data", "confidence": 1.0}])
        self.assertEqual(batches, [4096, 2])
        self.assertTrue(decoded and indexed)
        self.assertEqual(indexed, {reference_id})
        self.assertTrue(decoded.isdisjoint(indexed))
        self.assertTrue(stats["full_xref_pass_complete"])

    def test_service_entry_deep_full_have_string_evidence_and_thread_separation(self):
        cases = (
            ("x86_64", bytes.fromhex("48 8d 3d f9 0f 00 00 c3"), 0x401000),
            ("x86_64", bytes.fromhex("bf 00 20 40 00 c3"), 0x401000),
            ("arm64", _adrp(0x401000, 0x402000) + _add(0) + bytes.fromhex("c0035fd6"), 0x401004),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "data references.elf"
            for architecture, code, source in cases:
                path.write_bytes(_elf(code, architecture))
                for budget in (1, 2, 4):
                    for mode in ("entry", "deep", "full"):
                        with self.subTest(architecture=architecture, code=code.hex(), budget=budget, mode=mode):
                            decoded, indexed = set(), set()
                            def observe(function, target):
                                def wrapped(*args, **kwargs):
                                    target.add(get_ident())
                                    return function(*args, **kwargs)
                                return wrapped
                            with ExitStack() as stack:
                                stack.enter_context(patch.object(NativeDecoder, "decode_bytes_fast",
                                    observe(NativeDecoder.decode_bytes_fast, decoded)))
                                for owner, name in ((full_analysis, "_references"), (semantic, "function_references")):
                                    stack.enter_context(patch.object(owner, name, observe(getattr(owner, name), indexed)))
                                import fangida.core.kkagent as plugin
                                stack.enter_context(patch.object(plugin, "direct_references",
                                    observe(plugin.direct_references, indexed)))
                                with AnalysisService(Settings(analyze_threads=budget, semantic_threads=3)) as service:
                                    result = service.analyze(path, deep_analysis=mode == "deep", full_analysis=mode == "full")
                            self.assertNotEqual(result.status, "error", result.warnings)
                            self.assertTrue(any(ref["src"] == source and ref["dst"] == 0x402000
                                                and ref["kind"] == "data" for ref in result.xrefs), result.xrefs)
                            self.assertTrue(decoded and indexed)
                            if budget == 1:
                                self.assertEqual(decoded, indexed)
                            else:
                                self.assertTrue(decoded.isdisjoint(indexed))


if __name__ == "__main__":
    unittest.main()
