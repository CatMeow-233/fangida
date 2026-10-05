"""已完成快照的伪 C：独立插件加载、机器语义、预算和外部入口回归。"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock, patch

from fangida.core.kkagent.test_semantic import DECODER_AVAILABLE, _sample
from fangida.dispatcher import AnalysisService
from fangida.mcp_server import McpServer
from fangida.models import AnalysisResult
from fangida.plugins.interfaces import Plugin, PseudocodePlugin
from fangida.plugins.manager import PluginManager
from fangida.plugins.pseudoc import generate_pseudoc, pipeline
from fangida.plugins.pseudoc.models import PseudocodeResult
from fangida.settings import Settings


def instruction(addr, mnemonic, *operands, size=1, kind=None, target=None, conditional=False):
    return {"addr": addr, "size": size, "mnemonic": mnemonic, "operands": operands,
            "branch_info": {"kind": kind, "target": target, "conditional": conditional} if kind else {}}


def function(*rows, name="example", start=None, **fields):
    return {"name": name, "start": rows[0]["addr"] if start is None and rows else start,
            "blocks": [{"start": row["addr"], "instructions": [row]} for row in rows],
            "cfg": {"complete": True, "frontier": []}, **fields}


class Provider:
    name, version = "custom_pseudoc", "1"

    def capabilities(self):
        return ("snapshot_only",)

    def generate(self, function, architecture, *, max_instructions=512, max_chars=32768):
        return PseudocodeResult("void custom() {}", self.name)

    def teardown(self):
        pass


class PseudocodePluginTests(unittest.TestCase):
    def test_protocol_registration_is_lazy_and_independent(self):
        manager = PluginManager()
        factory = Mock(side_effect=Provider)
        with patch("fangida.plugins.manager.import_module") as importer:
            manager.register_pseudocode("custom_pseudoc", factory)
            self.assertEqual(manager.route("elf"), ("kkagent", "analyze"))
            factory.assert_not_called()
            importer.assert_not_called()
            provider = manager.load_pseudocode("custom_pseudoc")
            self.assertIs(provider, manager.load_pseudocode("custom_pseudoc"))
            self.assertIsInstance(provider, PseudocodePlugin)
            self.assertNotIsInstance(provider, Plugin)
            output = generate_pseudoc({}, "custom-cpu", manager=manager, provider="custom_pseudoc")
            self.assertEqual(output.producer, "custom_pseudoc")
            factory.assert_called_once_with()
            importer.assert_not_called()
        with self.assertRaisesRegex(ValueError, "Unknown pseudocode"):
            PluginManager().load_pseudocode("custom_pseudoc")
        manager.teardown()

    def test_builtin_renderers_are_not_imported_with_analyzers(self):
        code = "import sys; import fangida.core.kkagent; import fangida.core.apk_analyzer.jvm_analyzer; "
        code += "assert 'fangida.plugins.pseudoc.native' not in sys.modules; "
        code += "assert 'fangida.plugins.pseudoc.bytecode' not in sys.modules"
        subprocess.run([sys.executable, "-c", code], check=True, capture_output=True)

    def test_concurrent_load_constructs_once_and_teardown_cleans_all(self):
        manager, calls = PluginManager(), []
        def factory():
            calls.append("created")
            instance = Provider()
            instance.teardown = lambda: calls.append("closed")
            return instance
        manager.register_pseudocode("custom_pseudoc", factory)
        with ThreadPoolExecutor(max_workers=4) as executor:
            providers = list(executor.map(manager.load_pseudocode, ["custom_pseudoc"] * 12))
        self.assertTrue(all(provider is providers[0] for provider in providers))
        manager.teardown()
        self.assertEqual(calls, ["created", "closed"])
        self.assertIsNot(manager.load_pseudocode("custom_pseudoc"), providers[0])
        manager.teardown()

    def test_names_and_contract_are_checked_across_plugin_families(self):
        manager = PluginManager()
        for name in ("kkagent", "sqlite_storage", "native_pseudoc", "bytecode_pseudoc"):
            with self.assertRaises(ValueError):
                manager.register_pseudocode(name, Provider)
        manager.register_pseudocode("custom", Provider)
        with self.assertRaises(ValueError):
            manager.register("custom", Provider)
        with self.assertRaises(ValueError):
            manager.register_storage("custom", Provider)
        manager.register_pseudocode("invalid", object)
        with self.assertRaises(TypeError):
            manager.load_pseudocode("invalid")
        for value in ("native_pseudoc", "bytecode_pseudoc"):
            with self.assertRaises(ValueError):
                manager.register(value, Provider)
            with self.assertRaises(ValueError):
                manager.register_storage(value, Provider)

    def test_oversized_plugin_result_does_not_discard_completed_evidence(self):
        provider = Provider()
        provider.generate = lambda *args, **kwargs: PseudocodeResult("x" * 40000, "custom")
        manager = PluginManager()
        manager._pseudoc_loaded["native_pseudoc"] = provider
        result = AnalysisResult("sample", "elf", "kkagent", "partial",
            metadata={"architecture": "x86_64"}, functions=[function(instruction(0, "ret", kind="return"))])
        before = copy.deepcopy(result.functions)
        pipeline.populate_native_pseudoc(result, manager=manager)
        self.assertEqual(result.functions, before)
        self.assertEqual(result.status, "partial")
        self.assertIn("oversized", result.warnings[0])


class NativePseudocodeTests(unittest.TestCase):
    def test_alias_writes_and_returns_preserve_machine_widths(self):
        snapshot = function(instruction(0, "mov", "eax", "0x1234"),
                            instruction(1, "mov", "al", "0x56"),
                            instruction(2, "mov", "ah", "0x78"),
                            instruction(3, "ret", kind="return"))
        output = generate_pseudoc(snapshot, "x86_64")
        self.assertIn("rax = (uint32_t)(0x1234)", output.pseudoc)
        self.assertIn("~0xffULL", output.pseudoc)
        self.assertIn("~0xff00ULL", output.pseudoc)
        self.assertIn("return rax;", output.pseudoc)
        self.assertFalse(output.truncated)

    @unittest.skipUnless(shutil.which("cc"), "需要 C 编译器验证生成代码的寄存器别名语义")
    def test_generated_c_executes_known_alias_result(self):
        snapshot = function(instruction(0, "mov", "eax", "0x1234"),
                            instruction(1, "mov", "al", "0x56"),
                            instruction(2, "mov", "ah", "0x78"),
                            instruction(3, "ret", kind="return"), name="lifted")
        source = "#include <stdint.h>\nuint64_t symbolic_input(const char *name) { return ~0ULL; }\n"
        source += generate_pseudoc(snapshot, "x86_64").pseudoc
        source += "\nint main(void) { return lifted() == 0x7856 ? 0 : 1; }\n"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "lifted.c"
            path.write_text(source)
            binary = Path(tmp) / "lifted"
            subprocess.run([shutil.which("cc"), str(path), "-o", str(binary)], check=True, capture_output=True)
            subprocess.run([str(binary)], check=True, capture_output=True)

    def test_register_arithmetic_and_condition_keep_both_paths(self):
        snapshot = function(instruction(0, "add", "eax", "3"),
            instruction(1, "cmp", "eax", "4"),
            instruction(2, "jne", "0x5", kind="jump", target=5, conditional=True),
            instruction(3, "ret", kind="return"), instruction(5, "ret", kind="return"))
        output = generate_pseudoc(snapshot, "x86_64")
        self.assertIn("x86_add_flags32", output.pseudoc)
        self.assertIn("x86_sub_flags32", output.pseudoc)
        self.assertIn("if ((uint32_t)cmp_left_1 != (uint32_t)cmp_right_1) { goto L_5; }", output.pseudoc)
        predicate = output.microcode[2]["operations"][0]["attributes"]["condition"]
        self.assertEqual((predicate["domain"], predicate["width"], predicate["origin"]), ("bitvector", 32, 1))
        self.assertIn("goto L_3", output.pseudoc)
        self.assertFalse(output.truncated)

    def test_stack_memory_and_rip_relative_address_are_not_guessed_locals(self):
        snapshot = function(instruction(0x1000, "lea", "rax", "[rip + 0x20]", size=7),
            instruction(0x1007, "mov", "dword ptr [rbp - 8]", "eax", size=3),
            instruction(0x100a, "movsx", "ecx", "byte ptr [rbp - 8]", size=3),
            instruction(0x100d, "ret", kind="return"))
        output = generate_pseudoc(snapshot, "x86_64")
        self.assertIn("rax = 0x1007 + 0x20", output.pseudoc)
        self.assertIn("store32(rbp - 8", output.pseudoc)
        self.assertIn("(int8_t)(load8(rbp - 8))", output.pseudoc)
        self.assertFalse(output.truncated)

    def test_arm64_subregisters_memory_and_zero_test(self):
        snapshot = function(instruction(0, "mov", "w0", "#42", size=4),
            instruction(4, "str", "w0", "[sp", "#8]", size=4),
            instruction(8, "cbz", "x0", "0x10", size=4, kind="jump", target=16, conditional=True),
            instruction(12, "ret", size=4, kind="return"), instruction(16, "ret", size=4, kind="return"))
        output = generate_pseudoc(snapshot, "arm64")
        self.assertIn("x0 = (uint32_t)(42)", output.pseudoc)
        self.assertIn("memory_address_4 = sp + 8", output.pseudoc)
        self.assertIn("store32(memory_address_4", output.pseudoc)
        self.assertIn("if (x0 == 0) { goto L_10; }", output.pseudoc)
        self.assertIn("return x0", output.pseudoc)
        self.assertFalse(output.truncated)

    def test_32_bit_architectures_remain_supported(self):
        for architecture, register in (("x86", "eax"), ("arm", "r0")):
            with self.subTest(architecture=architecture):
                output = generate_pseudoc(function(instruction(0, "mov", register, "42"),
                    instruction(1, "ret", kind="return")), architecture)
                self.assertIn("uint32_t example", output.pseudoc)
                self.assertIn(f"return {register}", output.pseudoc)
                self.assertFalse(output.truncated)

    def test_outside_targets_and_indirect_branches_do_not_create_labels(self):
        for target in (None, 0x500):
            output = generate_pseudoc(function(instruction(0, "jmp", "rax", kind="jump", target=target)), "x86_64")
            self.assertIn("return unresolved_jump", output.pseudoc)
            self.assertNotIn("goto L_500", output.pseudoc)
            self.assertTrue(output.truncated)

    def test_self_loop_and_entry_above_another_block_keep_control_flow(self):
        snapshot = function(instruction(0, "ret", kind="return"),
            instruction(8, "jmp", "0x8", kind="jump", target=8), start=8)
        output = generate_pseudoc(snapshot, "x86_64")
        self.assertLess(output.pseudoc.index("goto L_8"), output.pseudoc.index("L_0:"))
        self.assertEqual(output.pseudoc.count("goto L_8"), 2)
        self.assertFalse(output.truncated)

    def test_opaque_instruction_and_cfg_frontier_are_preserved(self):
        snapshot = function(instruction(0, "unrecognized", "rax"), instruction(1, "ret", kind="return"))
        snapshot["cfg"] = {"complete": False, "frontier": [{"reason": "instruction_limit"}]}
        output = generate_pseudoc(snapshot, "x86_64")
        self.assertIn('asm_opaque("unrecognized rax")', output.pseudoc)
        self.assertIn("instruction_limit", output.pseudoc)
        self.assertTrue(output.truncated)
        self.assertTrue(output.warnings)

    def test_limits_close_output_and_never_leave_dangling_labels(self):
        snapshot = function(instruction(0, "jne", "0x2", kind="jump", target=2, conditional=True),
            instruction(1, "ret", kind="return"), instruction(2, "ret", kind="return"))
        for options in ({"max_instructions": 1}, {"max_chars": 256}):
            output = generate_pseudoc(snapshot, "x86_64", **options)
            self.assertTrue(output.truncated)
            self.assertTrue(output.pseudoc.endswith("}"))
            self.assertLessEqual(len(output.pseudoc), options.get("max_chars", 32768))
            labels = set(re.findall(r"L_([0-9a-f]+):", output.pseudoc))
            self.assertTrue(set(re.findall(r"goto L_([0-9a-f]+)", output.pseudoc)) <= labels)
        for options in ({"max_instructions": 0}, {"max_instructions": True}, {"max_chars": 255}):
            with self.assertRaises(ValueError):
                generate_pseudoc(snapshot, "x86_64", **options)

    def test_snapshot_is_read_only_and_no_other_stages_are_called(self):
        snapshot = function(instruction(0, "ret", kind="return"))
        before = copy.deepcopy(snapshot)
        with patch("fangida.processors.get_processor", side_effect=AssertionError("不能重新解码")), \
             patch("fangida.loaders.load_binary", side_effect=AssertionError("不能重新加载")), \
             patch("fangida.xrefs.direct_references", side_effect=AssertionError("不能重新分析引用")):
            threads = set(threading.enumerate())
            self.assertTrue(generate_pseudoc(snapshot, "x86_64").pseudoc)
            self.assertEqual(threads, set(threading.enumerate()))
        self.assertEqual(snapshot, before)
        self.assertFalse(generate_pseudoc(snapshot, "unsupported").pseudoc)
        self.assertFalse(generate_pseudoc({}, "x86_64").pseudoc)

    def test_pipeline_is_bounded_cancelable_and_preserves_ghidra(self):
        result = AnalysisResult("sample", "elf", "kkagent", "partial", metadata={"architecture": "x86_64"},
            functions=[function(instruction(0, "ret", kind="return")), function(instruction(8, "ret", kind="return")),
                function(instruction(16, "ret", kind="return"), pseudoc="int ghidra() {}", pseudoc_producer="ghidra")])
        events = []
        with patch.object(pipeline, "MAX_FUNCTIONS", 1):
            pipeline.populate_native_pseudoc(result, on_progress=events.append)
        self.assertIn("pseudoc", result.functions[0])
        self.assertNotIn("pseudoc", result.functions[1])
        self.assertEqual(result.functions[2]["pseudoc_producer"], "ghidra")
        self.assertTrue(result.stats["pseudoc_budget_exhausted"])
        self.assertEqual(len(events), 1)
        with patch.object(pipeline, "generate_pseudoc", side_effect=AssertionError("取消后不能继续")):
            pipeline.populate_native_pseudoc(result, is_cancelled=lambda: True)


class BytecodePseudocodeTests(unittest.TestCase):
    def test_empty_legacy_outline_keeps_declaration_and_return_contract(self):
        from fangida.core.apk_analyzer.pseudocode import outline
        text, truncated = outline("Example->run", "()V", "jvm", [], 0)
        self.assertIn("void run()", text)
        self.assertFalse(truncated)
        text, truncated = outline("Example->run", "()V", "jvm", [], 3)
        self.assertIn("Remaining bytecode omitted", text)
        self.assertTrue(truncated)

    def test_character_limit_regenerates_targets_without_dangling_labels(self):
        rows = [{"addr": 0, "size": 3, "mnemonic": "goto", "branch_info": {"target_offset": 63},
                 "arch_meta": {"bytecode_offset": 0}}]
        rows += [{"addr": offset, "size": 1, "mnemonic": "return", "arch_meta": {"bytecode_offset": offset}}
                 for offset in range(3, 64)]
        output = generate_pseudoc({"name": "Example->run", "descriptor": "()V",
            "disassembly": rows, "bytecode_length": 64}, "jvm", max_chars=256)
        self.assertLessEqual(len(output.pseudoc), 256)
        self.assertTrue(output.truncated)
        labels = set(re.findall(r"L([0-9a-f]+):", output.pseudoc))
        self.assertTrue(set(re.findall(r"goto L([0-9a-f]+)", output.pseudoc)) <= labels)

    def test_renderer_consumes_normalized_snapshot_without_source_bytes(self):
        rows = [{"addr": 20, "size": 2, "mnemonic": "goto", "branch_info": {"target_offset": 1},
                 "arch_meta": {"code_unit_offset": 0}},
                {"addr": 22, "size": 2, "mnemonic": "return-void", "arch_meta": {"code_unit_offset": 1}}]
        before = copy.deepcopy(rows)
        output = generate_pseudoc({"name": "Example->run", "descriptor": "()V",
            "disassembly": rows, "bytecode_length": 4}, "dex")
        self.assertIn("goto L0001", output.pseudoc)
        self.assertEqual(output.producer, "fangida_bytecode_outline")
        self.assertFalse(output.truncated)
        self.assertEqual(rows, before)

    def test_missing_branch_target_is_an_explicit_frontier(self):
        row = {"addr": 0, "size": 3, "mnemonic": "goto", "branch_info": {"target_offset": 10},
               "arch_meta": {"bytecode_offset": 0}}
        output = generate_pseudoc({"name": "Example->run", "descriptor": "()V",
            "disassembly": [row], "bytecode_length": 3}, "jvm")
        self.assertIn("outside instruction snapshot", output.pseudoc)
        self.assertNotIn("goto L000a", output.pseudoc)
        self.assertTrue(output.truncated)


@unittest.skipUnless(DECODER_AVAILABLE, "需要 Capstone 或 objdump")
class PseudocodeIntegrationTests(unittest.TestCase):
    def test_fast_deep_full_reach_existing_mcp_and_snapshot_interfaces(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.elf"
            path.write_bytes(_sample())
            for deep, full in ((False, False), (True, False), (True, True)):
                with self.subTest(deep=deep, full=full), AnalysisService(Settings(analyze_threads=2)) as service:
                    result = service.analyze(path, deep_analysis=deep, full_analysis=full)
                    self.assertNotEqual(result.status, "error")
                    entry = next(fn for fn in result.functions if fn["start"] == 0x401000)
                    self.assertEqual(entry["pseudoc_producer"], "fangida_native_pseudoc")
                    if deep:
                        self.assertIn("helper(", entry["pseudoc"])
                    snapshot = json.loads(json.dumps(result.to_dict()))
                    server = McpServer(settings=Settings())
                    try:
                        server._snapshots["fixture"] = snapshot
                        response = server.call_tool("get_pseudoc", {"handle": "fixture", "address": "0x401005"})
                        self.assertEqual(response["structuredContent"]["address"], 0x401000)
                        self.assertEqual(response["structuredContent"]["pseudoc"], entry["pseudoc"])
                    finally:
                        server.close()

    def test_mcp_member_filter_and_exact_start_priority(self):
        server = McpServer(settings=Settings())
        try:
            server._snapshots["fixture"] = {"kind": "apk", "metadata": {}, "functions": [
                {"name": "first", "source": "classes.dex", "start": 0x20,
                 "pseudoc": "first() {}", "disassembly": [{"addr": 0x40, "size": 2}]},
                {"name": "second", "source": "classes2.dex", "start": 0x40,
                 "pseudoc": "second() {}"}]}
            self.assertEqual(server.call_tool("get_pseudoc", {"handle": "fixture", "address": 0x40})
                ["structuredContent"]["pseudoc"], "second() {}")
            selected = server.call_tool("get_pseudoc", {"handle": "fixture", "address": 0x41,
                "source": "classes.dex", "address_space": "file_offset"})
            self.assertEqual(selected["structuredContent"]["pseudoc"], "first() {}")
        finally:
            server.close()


if __name__ == "__main__":
    unittest.main()
