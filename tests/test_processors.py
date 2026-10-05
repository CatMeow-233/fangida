"""Standalone processor interfaces and instruction-contract regressions."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch

from fangida import processors
from fangida.processors import objdump_backend
from fangida.core.kkagent import translator
from fangida.core.kkagent.binary import BinaryImage


def _entry(code: bytes, architecture: str = "x86_64") -> BinaryImage:
    return BinaryImage("elf", architecture, 64, "little", entry_address=0x1000, entry_offset=0,
                       sections=[{"address": 0x1000, "offset": 0, "size": len(code), "executable": True}])


class ProcessorRegistryTests(unittest.TestCase):
    def test_standalone_import_does_not_load_analysis_cores_or_capstone(self):
        code = (
            "import json, sys; import fangida.processors as p; "
            "print(json.dumps({'cores': [n for n in sys.modules if n.startswith('fangida.core')], "
            "'capstone': 'capstone' in sys.modules, 'architectures': p.list_processors()}))"
        )
        result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                                encoding="utf-8", check=True, timeout=5)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["cores"], [])
        self.assertFalse(payload["capstone"])
        self.assertEqual(payload["architectures"], ["arm", "arm64", "x86", "x86_64"])

    def test_registered_factory_is_lazy_reusable_and_reaches_legacy_entry_api(self):
        calls = []
        decoded = []

        class FixtureDecoder:
            engine, warning = "fixture", None

            def decode_bytes(self, code, address, *, max_instructions=128):
                decoded.append((len(code), address, max_instructions))
                return [{"addr": address, "size": 1, "mnemonic": "fixture", "operands": (),
                         "reads": (), "writes": (), "branch_info": {},
                         "arch_meta": {"engine": self.engine, "architecture": "fixture"}}], []

        def factory(architecture, endian):
            calls.append((architecture, endian))
            return FixtureDecoder()

        registry = processors.ProcessorRegistry()
        with patch.object(processors, "_registry", registry):
            processors.register_processor("fixture", factory)
            self.assertEqual(calls, [])
            self.assertEqual(processors.list_processors(), ("fixture",))
            with self.assertRaisesRegex(ValueError, "already registered"):
                processors.register_processor("fixture", factory)
            records, warnings = processors.decode_bytes(b"x", 0x1000, "fixture", "big", 1)
            self.assertEqual(calls, [("fixture", "big")])
            self.assertEqual(records[0]["mnemonic"], "fixture")
            self.assertFalse(warnings)
            code = b"x" * 1000
            records, warnings = translator.disassemble_entry(code, _entry(code, "fixture"))
            self.assertEqual(decoded[-1], (512, 0x1000, 128))
            self.assertEqual(records[0]["mnemonic"], "fixture")
            processors.register_processor("fixture", factory, replace=True)

    def test_unregistered_architecture_reports_a_missing_capability(self):
        decoder = processors.get_processor("mips")
        self.assertEqual(decoder.engine, "none")
        self.assertEqual(decoder.decode_bytes(b"\0" * 4, 0x1000),
                         ([], ["Disassembly unavailable for mips"]))

    def test_legacy_objdump_module_is_the_same_provider_module(self):
        from fangida.core.kkagent import objdump_backend as legacy
        self.assertIs(legacy, objdump_backend)
        self.assertIs(legacy._provider, objdump_backend._provider)

    def test_objdump_fallback_preserves_call_ir_and_tuple_register_fields(self):
        rendered = "  1000: e8 01 00 00 00\tcall 0x1006\n  1005: c3\tret\n  1006: c3\tret\n"
        with patch.dict("sys.modules", {"capstone": None}), \
             patch("fangida.processors.decoder.disassemble_bytes", return_value=(rendered, "llvm")):
            records, warnings = processors.decode_bytes(b"\xe8\x01\0\0\0\xc3\xc3", 0x1000,
                                                       "x86_64", max_instructions=2)
        self.assertEqual([(item["addr"], item["size"]) for item in records], [(0x1000, 5), (0x1005, 1)])
        self.assertEqual(records[0]["branch_info"], {"kind": "call", "target": 0x1006, "conditional": False})
        self.assertEqual(records[0]["operands"], ("0x1006",))
        self.assertEqual(records[0]["reads"], ())
        self.assertEqual(records[0]["writes"], ())
        self.assertEqual(records[0]["arch_meta"]["provider"], "llvm")
        self.assertIn("Register read/write", warnings[0])

    def test_entry_fallback_keeps_the_original_objdump_patch_point(self):
        code = b"\xc3"
        sentinel = ([{"addr": 0x1000, "mnemonic": "fixture"}], ["fixture"])
        with patch.dict("sys.modules", {"capstone": None}), \
             patch.object(translator, "_objdump", return_value=sentinel) as fallback:
            self.assertEqual(translator.disassemble_entry(code, _entry(code)), sentinel)
        fallback.assert_called_once_with(code, 0x1000, "x86_64")

    def test_registered_native_subclass_uses_public_protocol_in_both_analysis_paths(self):
        from fangida.processors.decoder import NativeDecoder
        from fangida.core.kkagent import semantic
        from fangida.core.kkagent.binary import parse_binary
        from fangida.core.kkagent.test_semantic import _sample

        data = _sample()
        image = parse_binary(data, "elf")
        for engine in ("custom", "objdump"):
            with self.subTest(engine=engine):
                decoding_threads, reference_threads = set(), set()
                gate = threading.Barrier(2)
                parallel_phase = False

                class RegisteredDecoder(NativeDecoder):
                    def __init__(self, architecture, endian):
                        self.architecture, self.endian = architecture, endian
                        self.engine, self.warning = engine, None
                        self.capstone = self.disassembler = None

                    # Deliberately implement only the public decoder protocol:
                    # no implementation-specific classify keyword is accepted.
                    def decode_bytes(self, code, address, *, max_instructions=128):
                        if parallel_phase:
                            decoding_threads.add(threading.get_ident())
                            gate.wait(timeout=5)
                        if address == 0x401000:
                            records = [(address, 5, "fixture_call", "call", 0x401008),
                                       (address + 5, 1, "fixture_return", "return", None)]
                        else:
                            records = [(address, 1, "fixture_return", "return", None)]
                        return [{"addr": start, "size": size, "mnemonic": name,
                                 "operands": (), "reads": (), "writes": (),
                                 "branch_info": {"kind": kind, "target": target, "conditional": False},
                                 "arch_meta": {"engine": self.engine, "architecture": self.architecture}}
                                for start, size, name, kind, target in records[:max_instructions]], []

                registry = processors.ProcessorRegistry()
                registry.register("x86_64", RegisteredDecoder)
                original_references = semantic.function_references

                def observe_references(*args, **kwargs):
                    reference_threads.add(threading.get_ident())
                    return original_references(*args, **kwargs)

                with patch.object(processors, "_registry", registry), \
                     patch.object(translator, "_objdump", side_effect=AssertionError("registered decoder was bypassed")), \
                     patch.object(semantic, "_objdump", side_effect=AssertionError("registered decoder was bypassed")), \
                     patch.object(semantic, "function_references", side_effect=observe_references):
                    entry, warnings = translator.disassemble_entry(data, image)
                    self.assertFalse(warnings)
                    self.assertEqual([instruction["mnemonic"] for instruction in entry],
                                     ["fixture_call", "fixture_return"])
                    parallel_phase = True
                    functions, xrefs, stats, warnings = semantic.analyze_semantics(data, image, max_workers=2)
                self.assertFalse(warnings)
                self.assertEqual(stats["semantic_decoder"], engine)
                self.assertEqual(xrefs, [{"src": 0x401000, "dst": 0x401008,
                                         "kind": "call", "confidence": 1.0}])
                self.assertEqual(functions[0]["xrefs_out"], xrefs)
                self.assertEqual(functions[1]["xrefs_in"], xrefs)
                self.assertEqual(len(decoding_threads), 2)
                self.assertEqual(len(reference_threads), 1)
                self.assertFalse(decoding_threads & reference_threads)


@unittest.skipUnless(importlib.util.find_spec("capstone"), "Capstone unavailable")
class CapstoneProcessorTests(unittest.TestCase):
    def test_x86_register_access_direct_call_and_instruction_limit(self):
        for architecture, move, registers in (
            ("x86_64", "48 89 e5", (("rsp",), ("rbp",))),
            ("x86", "89 e5", (("esp",), ("ebp",))),
        ):
            with self.subTest(architecture=architecture):
                code = bytes.fromhex(move + " e8 01 00 00 00 c3 c3")
                records, warnings = processors.decode_bytes(code, 0x401000, architecture, max_instructions=2)
                self.assertEqual(len(records), 2)
                self.assertFalse(warnings)
                self.assertEqual((records[0]["reads"], records[0]["writes"]), registers)
                self.assertIsInstance(records[0]["operands"], tuple)
                target = 0x401000 + len(bytes.fromhex(move)) + 6
                self.assertEqual(records[1]["branch_info"],
                                 {"kind": "call", "target": target, "conditional": False})

    def test_arm_instruction_mode_and_endian_preserve_direct_branch_targets(self):
        for architecture, endian, code, target in (
            ("arm", "little", "00 00 00 eb", 0x1008),
            ("arm", "big", "eb 00 00 00", 0x1008),
            ("arm64", "little", "00 00 00 94", 0x1000),
        ):
            with self.subTest(architecture=architecture, endian=endian):
                records, warnings = processors.decode_bytes(bytes.fromhex(code), 0x1000,
                                                            architecture, endian, 1)
                self.assertFalse(warnings)
                self.assertEqual(records[0]["size"], 4)
                self.assertEqual(records[0]["branch_info"],
                                 {"kind": "call", "target": target, "conditional": False})

    def test_concurrent_decoders_own_their_state_and_keep_addresses(self):
        first = processors.get_processor("x86_64")
        second = processors.get_processor("x86_64")
        self.assertIsNot(first, second)
        self.assertIsNot(first.disassembler, second.disassembler)
        addresses = [0x1000 + index * 0x100 for index in range(16)]
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda address: processors.decode_bytes(b"\xc3", address, "x86_64"),
                                    addresses))
        self.assertEqual([records[0]["addr"] for records, _ in results], addresses)
        self.assertTrue(all(records[0]["branch_info"]["kind"] == "return" for records, _ in results))

    def test_entry_capstone_keeps_the_original_branch_patch_point(self):
        with patch.object(translator, "_branch", wraps=translator._branch) as classify:
            records, _ = translator.disassemble_entry(b"\xc3", _entry(b"\xc3"))
        classify.assert_called_once_with("ret", None)
        self.assertEqual(records[0]["branch_info"], {"kind": "return", "target": None, "conditional": False})


if __name__ == "__main__":
    unittest.main()
