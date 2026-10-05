"""GNU/LLVM fallback behavior and portability regressions."""
from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from fangida.core.kkagent import objdump_backend as backend
from fangida.core.kkagent.binary import parse_binary
from fangida.core.kkagent.semantic import analyze_semantics
from fangida.core.kkagent.test_semantic import _sample
from fangida.core.kkagent.translator import _objdump, objdump_available


class ObjdumpDiscoveryTests(unittest.TestCase):
    def tearDown(self) -> None:
        backend._provider.cache_clear()

    def test_recognizes_gnu_and_apple_llvm_under_arbitrary_paths(self) -> None:
        backend._provider.cache_clear()
        tools = {"gobjdump": "/tools with spaces/gnu", "objdump": "/apple/objdump"}
        def version(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            banner = "GNU objdump (GNU Binutils) 2.40" if command[0] == tools["gobjdump"] else "Apple LLVM version 21.0.0"
            return subprocess.CompletedProcess(command, 0, banner, "")
        with patch.object(backend.shutil, "which", side_effect=tools.get), \
                patch.object(backend.subprocess, "run", side_effect=version) as probe:
            self.assertEqual([item.provider for item in backend.available_backends()], ["gnu", "llvm"])
            backend.available_backends()
            self.assertEqual(probe.call_count, 2)

    def test_path_is_resolved_again_after_an_unavailable_tool(self) -> None:
        backend._provider.cache_clear()
        with patch.object(backend.shutil, "which", return_value=None):
            self.assertFalse(objdump_available())
        with patch.object(backend.shutil, "which", side_effect=lambda name: "/new/llvm" if name == "llvm-objdump" else None), \
                patch.object(backend.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "LLVM version 18.1.0", "")):
            self.assertTrue(objdump_available())

    def test_unknown_tool_is_not_treated_as_a_supported_backend(self) -> None:
        backend._provider.cache_clear()
        with patch.object(backend.shutil, "which", return_value="/other/objdump"), \
                patch.object(backend.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "Other tool", "")):
            instructions, warnings = _objdump(b"\xc3", 0x1000, "x86_64")
        self.assertEqual(instructions, [])
        self.assertIn("No compatible GNU or LLVM", warnings[0])

    def test_failed_gnu_backend_retries_llvm_without_gnu_options(self) -> None:
        tools = (backend.ObjdumpBackend("gnu", "gnu"), backend.ObjdumpBackend("llvm", "llvm"))
        commands: list[list[str]] = []
        def decode(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            commands.append(command)
            if command[0] == "gnu":
                return subprocess.CompletedProcess(command, 1, "", "unsupported architecture")
            self.assertNotIn("--insn-width=16", command)
            self.assertNotIn("-b", command)
            return subprocess.CompletedProcess(command, 0, "  1000: c3\tret\n", "")
        with patch.object(backend, "available_backends", return_value=tools), \
                patch.object(backend.subprocess, "run", side_effect=decode):
            instructions, _ = _objdump(b"\xc3", 0x1000, "x86_64")
        self.assertEqual([command[0] for command in commands], ["gnu", "llvm"])
        self.assertEqual(instructions[0]["arch_meta"]["provider"], "llvm")

    def test_invalid_decoder_placeholders_do_not_become_instructions(self) -> None:
        rendered = "  1000: 0f\t<unknown>\n  1001: ff\t(bad)\n  1002: c3\tret\n"
        with patch("fangida.core.kkagent.translator.disassemble_bytes", return_value=(rendered, "llvm")):
            instructions, _ = _objdump(b"\x0f\xff\xc3", 0x1000, "x86_64")
        self.assertEqual([(item["addr"], item["mnemonic"]) for item in instructions], [(0x1002, "ret")])


@unittest.skipUnless(objdump_available(), "GNU/LLVM objdump unavailable")
class ObjdumpIntegrationTests(unittest.TestCase):
    def test_x86_32_and_high_x86_64_call_targets(self) -> None:
        for arch, address in (("x86", 0x401000), ("x86_64", 0x140001000)):
            with self.subTest(arch=arch):
                instructions, _ = _objdump(bytes.fromhex("e8 01 00 00 00 c3 c3"), address, arch)
                self.assertEqual([(item["addr"], item["size"]) for item in instructions],
                                 [(address, 5), (address + 5, 1), (address + 6, 1)])
                self.assertEqual(instructions[0]["branch_info"]["target"], address + 6)

    def test_semantic_analysis_uses_fallback_when_capstone_is_missing(self) -> None:
        sample = _sample()
        with patch.dict("sys.modules", {"capstone": None}):
            functions, xrefs, stats, warnings = analyze_semantics(sample, parse_binary(sample, "elf"))
        self.assertEqual([function["start"] for function in functions], [0x401000, 0x401008])
        self.assertTrue(any(xref["kind"] == "call" and xref["dst"] == 0x401008 for xref in xrefs))
        self.assertTrue(all(not function["liveness"]["available"] for function in functions))


if __name__ == "__main__":
    unittest.main()
