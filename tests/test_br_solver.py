"""独立 BR 插件：真实 ARM64 快照、原文件映射与 Unicorn 端到端验证。"""
from __future__ import annotations

import copy
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from threading import Event
import unittest
from unittest.mock import patch

from fangida.loaders import load_binary
from fangida.plugins.manager import PluginManager
from fangida.processors import NativeDecoder


HAVE_NATIVE = (importlib.util.find_spec("capstone") is not None and
               importlib.util.find_spec("unicorn") is not None)
CODE_ADDRESS, DATA_ADDRESS = 0x1000, 0x3000


def _words(*values: int) -> bytes:
    return b"".join(struct.pack("<I", value) for value in values)


def _movz(register: int, immediate: int, shift: int = 0) -> int:
    return 0xD2800000 | ((shift // 16) << 21) | (immediate << 5) | register


def _movk(register: int, immediate: int, shift: int = 0) -> int:
    return 0xF2800000 | ((shift // 16) << 21) | (immediate << 5) | register


def _br(register: int, *, link: bool = False) -> int:
    return (0xD63F0000 if link else 0xD61F0000) | (register << 5)


def _adrp(register: int, target: int, origin: int = CODE_ADDRESS) -> int:
    delta = ((target & ~0xFFF) - (origin & ~0xFFF)) >> 12
    delta &= (1 << 21) - 1
    return 0x90000000 | ((delta & 3) << 29) | ((delta >> 2) << 5) | register


def _add(destination: int, source: int, immediate: int) -> int:
    return 0x91000000 | (immediate << 10) | (source << 5) | destination


def arm64_elf(code: bytes, *, pointer: int = 0x6000, writable: bool = False) -> bytes:
    """两个有权限声明的 PT_LOAD 和对应真实节表；不依赖分析器伪造映射。"""
    data = bytearray(0x800)
    data[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 2, 183, 1, CODE_ADDRESS,
                     64, 0x600, 0, 64, 56, 2, 64, 4, 3)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0x200, CODE_ADDRESS,
                     CODE_ADDRESS, len(code), len(code), 0x1000)
    struct.pack_into("<IIQQQQQQ", data, 120, 1, 6 if writable else 4, 0x400,
                     DATA_ADDRESS, DATA_ADDRESS, 8, 8, 0x1000)
    data[0x200:0x200 + len(code)] = code
    struct.pack_into("<Q", data, 0x400, pointer)
    names = b"\0.text\0.rodata\0.shstrtab\0"
    data[0x500:0x500 + len(names)] = names
    struct.pack_into("<IIQQQQIIQQ", data, 0x640, 1, 1, 6, CODE_ADDRESS,
                     0x200, len(code), 0, 0, 4, 0)
    struct.pack_into("<IIQQQQIIQQ", data, 0x680, 7, 1, 3 if writable else 2,
                     DATA_ADDRESS, 0x400, 8, 0, 0, 8, 0)
    struct.pack_into("<IIQQQQIIQQ", data, 0x6C0, 15, 3, 0, 0,
                     0x500, len(names), 0, 0, 1, 0)
    return bytes(data)


def branch_snapshot(code: bytes, data: bytes, *, known_function: bool = True) -> dict:
    decoder = NativeDecoder("arm64")
    rows, warnings = decoder.decode_bytes(code, CODE_ADDRESS, max_instructions=4096, include_data=True)
    if warnings or len(rows) != len(code) // 4 or decoder.engine != "capstone":
        raise AssertionError((decoder.engine, warnings, rows))
    metadata = load_binary(data).metadata()
    metadata.update(full_disassembly=rows, source_sha256=hashlib.sha256(data).hexdigest())
    functions = ([{"name": "fixture", "start": CODE_ADDRESS, "size": len(code),
                   "instructions": rows, "blocks": []}] if known_function else [])
    return {"kind": "elf", "metadata": metadata, "functions": functions, "xrefs": []}


@unittest.skipUnless(HAVE_NATIVE, "端到端求解需要 Capstone 和 Unicorn")
class BranchSolverTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.manager = PluginManager()
        self.addCleanup(self.manager.teardown)
        self.solver = self.manager.load_branch_solver()

    def prepare(self, code, *, pointer=0x6000, writable=False, known_function=True):
        data = arm64_elf(code, pointer=pointer, writable=writable)
        path = Path(self.directory.name) / "branch.elf"
        path.write_bytes(data)
        snapshot = branch_snapshot(code, data, known_function=known_function)
        return snapshot, path, CODE_ADDRESS + len(code) - 4

    def solve(self, code, **options):
        snapshot, path, branch = self.prepare(code)
        return self.solver.solve(snapshot, branch, source_path=path, timeout_ms=1000, **options)

    def assert_verified(self, result, target):
        self.assertEqual(result["status"], "resolved", result)
        self.assertEqual(result["targets"], [target], result)
        self.assertTrue(result["verified_by_unicorn"], result)
        self.assertTrue(result["source_verified"], result)
        self.assertEqual(result["engine"], "backward_slice+unicorn")
        self.assertTrue(all(path["verification"]["branch_bytes_verified"] for path in result["paths"]))

    def test_movz_br_and_blr_use_real_unicorn_and_have_static_provenance(self):
        for link in (False, True):
            with self.subTest(link=link):
                result = self.solve(_words(_movz(2, 0x6000), _br(2, link=link)))
                self.assert_verified(result, 0x6000)
                self.assertFalse(result["runtime_generated"])
                self.assertFalse(result["requires_runtime_context"])
                self.assertEqual(result["branch_mnemonic"], "blr" if link else "br")

    def test_movk_and_adrp_add_keep_full_64_bit_target(self):
        cases = [(_words(_movz(2, 0x1234), _movk(2, 0x5678, 16), _br(2)), 0x56781234),
                 (_words(_adrp(2, 0x6000), _add(2, 2, 0x120), _br(2)), 0x6120)]
        for code, target in cases:
            with self.subTest(target=target):
                self.assert_verified(self.solve(code), target)

    def pointer_code(self):
        return _words(_adrp(1, DATA_ADDRESS), 0xF9400022, _br(2))  # ldr x2,[x1]

    def test_readonly_pointer_table_is_resolved_from_unique_loader_mapping(self):
        snapshot, path, branch = self.prepare(self.pointer_code())
        section = next(record for record in snapshot["metadata"]["sections"] if record["address"] == DATA_ADDRESS)
        self.assertFalse(section["writable"])
        self.assertTrue(section["readable"])
        result = self.solver.solve(snapshot, branch, source_path=path, timeout_ms=1000)
        self.assert_verified(result, 0x6000)
        self.assertFalse(result["runtime_generated"])

    def test_writable_pointer_initial_value_cannot_be_treated_as_runtime_constant(self):
        snapshot, path, branch = self.prepare(self.pointer_code(), writable=True)
        result = self.solver.solve(snapshot, branch, source_path=path, timeout_ms=1000)
        self.assertEqual(result["status"], "runtime_required", result)
        self.assertEqual(result["targets"], [])
        self.assertNotIn(0x6000, result["possible_targets"])
        self.assertTrue(result["runtime_generated"])
        self.assertTrue(any(item["kind"] == "writable_memory" for item in result["dependencies"]))

    def test_runtime_memory_context_resolves_actual_value_without_claiming_static_origin(self):
        snapshot, path, branch = self.prepare(self.pointer_code(), writable=True)
        result = self.solver.solve(snapshot, branch, source_path=path,
            memory=[{"address": DATA_ADDRESS, "data": struct.pack("<Q", 0x8000)}], timeout_ms=1000)
        self.assert_verified(result, 0x8000)
        self.assertTrue(result["context_dependent"])
        self.assertIsNot(result["runtime_generated"], False, result)

    def test_dynamic_relocation_does_not_accept_file_pointer_initial_value(self):
        snapshot, path, branch = self.prepare(self.pointer_code())
        snapshot["metadata"]["dynamic_relocations"] = [{"address": DATA_ADDRESS,
            "address_kind": "virtual_address", "kind": "import", "type": "R_AARCH64_GLOB_DAT"}]
        result = self.solver.solve(snapshot, branch, source_path=path, timeout_ms=1000)
        self.assertEqual(result["targets"], [])
        self.assertEqual(result["status"], "runtime_required", result)
        self.assertTrue(result["runtime_generated"])
        self.assertTrue(any(item["kind"] == "runtime_relocation" for item in result["dependencies"]))

    def test_unmapped_and_unknown_permission_reads_keep_origin_unknown(self):
        snapshot, path, branch = self.prepare(self.pointer_code())
        section = next(record for record in snapshot["metadata"]["sections"] if record["address"] == DATA_ADDRESS)
        section["readable"] = None
        unknown = self.solver.solve(snapshot, branch, source_path=path, timeout_ms=1000)
        self.assertEqual(unknown["targets"], [])
        self.assertIsNone(unknown["runtime_generated"], unknown)
        unmapped = self.solve(_words(_movz(1, 0x9000), 0xF9400022, _br(2)))
        self.assertEqual(unmapped["targets"], [])
        self.assertEqual(unmapped["possible_targets"], [])
        self.assertIsNone(unmapped["runtime_generated"], unmapped)

    def test_entry_parameter_is_runtime_and_unknown_register_is_never_zero(self):
        code = _words(0xAA0003E2, _br(2))  # mov x2,x0; br x2
        snapshot, path, branch = self.prepare(code)
        missing = self.solver.solve(snapshot, branch, source_path=path, timeout_ms=1000)
        self.assertEqual(missing["targets"], [])
        self.assertEqual(missing["possible_targets"], [])
        self.assertEqual(missing["status"], "runtime_required")
        self.assertTrue(missing["runtime_generated"])
        supplied = self.solver.solve(snapshot, branch, source_path=path,
                                     registers={"x0": 0x9000}, timeout_ms=1000)
        self.assert_verified(supplied, 0x9000)
        self.assertTrue(supplied["context_dependent"])
        self.assertTrue(supplied["runtime_generated"])

    def test_missing_definition_context_cannot_prove_static_generation(self):
        snapshot, path, branch = self.prepare(_words(_br(2)), known_function=False)
        result = self.solver.solve(snapshot, branch, source_path=path,
                                   registers={"x2": 0x7000}, timeout_ms=1000)
        self.assert_verified(result, 0x7000)
        self.assertTrue(result["context_dependent"])
        self.assertIsNot(result["runtime_generated"], False, result)

    def test_wsp_context_zero_extends_like_a_32_bit_register_write(self):
        code = _words(0x910003E2, _br(2))  # mov x2,sp (add x2,sp,#0)
        result = self.solve(code, registers={"wsp": 0x100006000})
        self.assert_verified(result, 0x6000)
        self.assertTrue(result["runtime_generated"])
        self.assertTrue(result["context_dependent"])
        self.assertFalse(result["requires_runtime_context"])

    def test_external_call_cannot_reuse_entry_x0_as_callee_return_value(self):
        code = _words(0x94000040, _br(0))  # bl 0x1100; br x0
        snapshot, path, branch = self.prepare(code)
        result = self.solver.solve(snapshot, branch, source_path=path,
                                   registers={"x0": 0x6000}, timeout_ms=1000)
        self.assertEqual(result["targets"], [])
        self.assertNotIn(0x6000, result["possible_targets"])
        self.assertTrue(result["runtime_generated"])
        self.assertTrue(any(item["kind"] == "external_call" for item in result["dependencies"]))

    def test_missing_source_retains_ir_static_candidate_without_unicorn_claim(self):
        snapshot, _path, branch = self.prepare(_words(_movz(2, 0x6000), _br(2)))
        result = self.solver.solve(snapshot, branch)
        self.assertEqual(result["targets"], [0x6000])
        self.assertEqual(result["status"], "resolved")
        self.assertFalse(result["verified_by_unicorn"])
        self.assertFalse(result["source_verified"])
        self.assertEqual(result["engine"], "backward_slice")

    def test_source_hash_mismatch_is_rejected_before_using_modified_bytes(self):
        snapshot, path, branch = self.prepare(_words(_movz(2, 0x6000), _br(2)))
        original = bytearray(path.read_bytes())
        original[0x200:0x204] = _words(_movz(2, 0x8000))
        path.write_bytes(original)
        with self.assertRaisesRegex(ValueError, "指纹.*不一致"):
            self.solver.solve(snapshot, branch, source_path=path)

    def test_branch_byte_conflict_revokes_static_proof_before_unknown_prologue(self):
        code = _words(0xA9BF7BFD, _movz(2, 0x6000), _br(2))
        snapshot, path, branch = self.prepare(code)
        snapshot["metadata"].pop("source_sha256")
        original = bytearray(path.read_bytes())
        branch_offset = 0x200 + branch - CODE_ADDRESS
        original[branch_offset:branch_offset + 4] = _words(_br(3))
        path.write_bytes(original)
        result = self.solver.solve(snapshot, branch, source_path=path, timeout_ms=1000)
        self.assertEqual(result["targets"], [], result)
        self.assertIsNone(result["runtime_generated"], result)
        self.assertFalse(result["verified_by_unicorn"])
        self.assertTrue(any(record.get("source") == "byte_mismatch" for record in result["dependencies"]), result)

    def test_upstream_cfg_frontier_blocks_confirmation_but_requested_br_frontier_does_not(self):
        snapshot, path, branch = self.prepare(_words(_movz(2, 0x6000), _br(2)))
        own_frontier = {"from": branch, "to": None, "reason": "indirect_jump"}
        snapshot["functions"][0]["cfg"] = {"complete": False, "frontier": [own_frontier]}
        result = self.solver.solve(snapshot, branch, source_path=path, timeout_ms=1000)
        self.assert_verified(result, 0x6000)
        for reason in ("instruction_limit", "undecoded"):
            with self.subTest(reason=reason):
                snapshot["functions"][0]["cfg"] = {"complete": False, "frontier": [own_frontier,
                    {"from": CODE_ADDRESS, "to": CODE_ADDRESS + 0x40, "reason": reason}]}
                blocked = self.solver.solve(snapshot, branch, source_path=path, timeout_ms=1000)
                self.assertEqual(blocked["targets"], [], blocked)
                self.assertFalse(blocked["verified_by_unicorn"])

    def test_solve_does_not_mutate_snapshot_and_reports_progress(self):
        snapshot, path, branch = self.prepare(_words(_movz(2, 0x6000), _br(2)))
        original = copy.deepcopy(snapshot)
        progress = []
        result = self.solver.solve(snapshot, branch, source_path=path,
            timeout_ms=1000, include_details=True, on_progress=progress.append)
        self.assert_verified(result, 0x6000)
        self.assertEqual(snapshot, original)
        self.assertTrue(progress)
        self.assertEqual(progress[-1]["stage"], "br_solver")

    def test_instruction_path_and_loop_bounds_do_not_confirm_possible_targets(self):
        code = _words(_movz(2, 0x6000), _add(2, 2, 1), _br(2))
        limited = self.solve(code, max_instructions=1)
        self.assertEqual(limited["targets"], [])
        self.assertTrue(limited["slice_truncated"])
        paths = _words(0xB4000080, _movz(2, 0x4000), 0x14000003,
                       0xD503201F, _movz(2, 0x5000), _br(2))
        limited_paths = self.solve(paths, max_paths=1)
        self.assertEqual(limited_paths["targets"], [])
        self.assertTrue(limited_paths["slice_truncated"])
        self.assertTrue(any(item["kind"] == "path_budget" for item in limited_paths["dependencies"]))
        loop = _words(_movz(2, 0x6000), 0xB5FFFFE0, _br(2))
        limited_loop = self.solve(loop)
        self.assertEqual(limited_loop["targets"], [])
        self.assertTrue(limited_loop["slice_truncated"])

    def test_unsupported_instruction_and_system_input_never_become_zero_target(self):
        unsupported = self.solve(_words(0x9AC14C02, _br(2)))  # crc32x w2,w0,x1
        self.assertEqual(unsupported["targets"], [])
        self.assertNotIn(0, unsupported["possible_targets"])
        self.assertIsNone(unsupported["runtime_generated"], unsupported)
        system = self.solve(_words(0xD53BD042, _br(2)))  # mrs x2,tpidr_el0
        self.assertEqual(system["targets"], [])
        self.assertTrue(system["runtime_generated"])

    def test_unknown_stack_prologue_does_not_change_static_target_origin(self):
        code = _words(0xA9BF7BFD, _movz(2, 0x6000), _br(2))  # stp x29,x30,[sp,#-16]!
        result = self.solve(code)
        self.assertEqual(result["status"], "resolved", result)
        self.assertEqual(result["targets"], [0x6000])
        self.assertFalse(result["runtime_generated"], result)
        self.assertIn(0x6000, result["possible_targets"])
        self.assertFalse(result["verified_by_unicorn"])
        self.assertTrue(any(path["verification"]["status"] == "runtime_dependent"
                            for path in result["paths"]))

    def test_runtime_control_selecting_different_constant_targets_keeps_origin_with_context(self):
        code = _words(0xB4000060, _movz(2, 0x4000), 0x14000002, _movz(2, 0x5000), _br(2))
        snapshot, path, branch = self.prepare(code)
        unknown = self.solver.solve(snapshot, branch, source_path=path, timeout_ms=1000)
        self.assertTrue(unknown["runtime_generated"], unknown)
        self.assertEqual(unknown["possible_targets"], [0x4000, 0x5000])
        self.assertEqual(unknown["targets"], [])
        for entry_value, target in ((0, 0x5000), (1, 0x4000)):
            with self.subTest(x0=entry_value):
                result = self.solver.solve(snapshot, branch, source_path=path,
                    registers={"x0": entry_value}, timeout_ms=1000)
                self.assert_verified(result, target)
                self.assertEqual(result["possible_targets"], [target])
                self.assertTrue(result["context_dependent"])
                self.assertTrue(result["runtime_generated"], result)

    def test_runtime_control_selecting_same_constant_preserves_static_target_origin(self):
        code = _words(0xB4000060, _movz(2, 0x4000), 0x14000002, _movz(2, 0x4000), _br(2))
        snapshot, path, branch = self.prepare(code)
        for registers in (None, {"x0": 0}, {"x0": 1}):
            with self.subTest(registers=registers):
                result = self.solver.solve(snapshot, branch, source_path=path,
                    registers=registers, timeout_ms=1000)
                self.assertFalse(result["runtime_generated"], result)
                self.assertEqual(result["possible_targets"], [0x4000])

    def test_partial_function_rows_cannot_hide_entry_path_that_skips_definition(self):
        code = _words(0x14000002, _movz(2, 0x6000), _br(2))  # b BR; unreachable movz
        snapshot, path, branch = self.prepare(code)
        snapshot["functions"][0]["instructions"] = snapshot["functions"][0]["instructions"][1:]
        result = self.solver.solve(snapshot, branch, source_path=path, timeout_ms=1000)
        self.assertEqual(result["targets"], [], result)
        self.assertFalse(result["verified_by_unicorn"])

    def test_partial_function_with_entry_cannot_hide_internal_branch(self):
        code = _words(0xD503201F, 0x14000002, _movz(2, 0x6000), _br(2))
        snapshot, path, branch = self.prepare(code)
        rows = snapshot["functions"][0]["instructions"]
        snapshot["functions"][0]["instructions"] = [rows[index] for index in (0, 2, 3)]
        result = self.solver.solve(snapshot, branch, source_path=path, timeout_ms=1000)
        self.assertEqual(result["targets"], [], result)
        self.assertFalse(result["verified_by_unicorn"])

    def test_unicorn_infeasible_path_does_not_leave_candidate_or_origin_evidence(self):
        code = _words(0xB4000060, _movz(2, 0x4000), 0x14000002, _movz(2, 0x5000), _br(2))
        snapshot, path, branch = self.prepare(code)
        # 故意不完整的旧 CFG 声明：物理 CBZ 仍有条件，快照却遗漏 conditional。
        # 实际 x0=1 会落空；Unicorn 必须排除反向图枚举出的唯一 taken 路径。
        snapshot["metadata"]["full_disassembly"][0]["branch_info"]["conditional"] = False
        rows = snapshot["metadata"]["full_disassembly"]
        snapshot["functions"][0]["instructions"] = [rows[index] for index in (0, 3, 4)]
        result = self.solver.solve(snapshot, branch, source_path=path,
            registers={"x0": 1}, timeout_ms=1000)
        self.assertNotIn(0x5000, result["targets"], result)
        self.assertNotIn(0x5000, result["possible_targets"], result)
        if not result["targets"]:
            self.assertIsNone(result["runtime_generated"])
            self.assertFalse(result["verified_by_unicorn"])

    def test_pre_cancelled_request_does_not_read_source(self):
        snapshot, path, branch = self.prepare(_words(_movz(2, 0x6000), _br(2)))
        path.unlink()
        cancel = Event()
        cancel.set()
        result = self.solver.solve(snapshot, branch, source_path=path, cancel=cancel)
        self.assertEqual(result["status"], "cancelled")
        self.assertEqual(result["targets"], [])

    def test_cancellation_during_source_read_stops_before_completing_fingerprint(self):
        snapshot, path, branch = self.prepare(_words(_movz(2, 0x6000), _br(2)))
        content = path.read_bytes() + bytes(2 * 1024 * 1024)
        path.write_bytes(content)
        snapshot["metadata"]["source_sha256"] = hashlib.sha256(content).hexdigest()
        cancel = Event()

        class InterruptedSource(io.BytesIO):
            reads = 0

            def read(self, size=-1):
                self.reads += 1
                result = super().read(size)
                cancel.set()
                return result

        stream = InterruptedSource(content)
        with patch.object(Path, "open", return_value=stream):
            result = self.solver.solve(snapshot, branch, source_path=path,
                cancel=cancel, timeout_ms=1000)
        self.assertEqual(result["status"], "cancelled")
        self.assertEqual(result["targets"], [])
        self.assertEqual(stream.reads, 1)
        self.assertFalse(result["verified_by_unicorn"])

    def test_path_progress_cancellation_stops_remaining_paths(self):
        code = _words(0xB4000060, _movz(2, 0x4000), 0x14000002, _movz(2, 0x5000), _br(2))
        snapshot, path, branch = self.prepare(code)
        cancel, progress = Event(), []

        def after_path(record):
            progress.append(record)
            cancel.set()

        result = self.solver.solve(snapshot, branch, source_path=path,
            cancel=cancel, timeout_ms=1000, on_progress=after_path)
        self.assertEqual(result["status"], "cancelled")
        self.assertEqual(result["targets"], [])
        self.assertEqual(len(progress), 1)

    def test_cli_json_and_database_use_explicit_plugin_without_modifying_inputs(self):
        from fangida.plugins.sqlite_storage import SQLiteAnalysisDatabase
        snapshot, path, branch = self.prepare(_words(_movz(2, 0x6000), _br(2)))
        snapshot.update(status="partial", schema_version="1.0", path=str(path))
        json_path = Path(self.directory.name) / "analysis.json"
        json_path.write_text(json.dumps(snapshot), encoding="utf-8")
        database_path = Path(self.directory.name) / "analysis.fdb"
        with SQLiteAnalysisDatabase(database_path, create=True) as database:
            database.save_analysis(path, snapshot)
        original = {candidate: candidate.read_bytes() for candidate in (path, json_path, database_path)}
        for candidate, extra in ((json_path, []), (database_path, ["--database"])):
            with self.subTest(snapshot=str(candidate)):
                process = subprocess.run([sys.executable, "-m", "fangida.plugins.br_solver", str(candidate),
                    *extra, "--address", hex(branch), "--source", str(path), "--timeout-ms", "1000"],
                    capture_output=True, text=True, timeout=15)
                self.assertEqual(process.returncode, 0, process.stderr)
                result = json.loads(process.stdout)
                self.assert_verified(result, 0x6000)
        self.assertTrue(all(candidate.read_bytes() == data for candidate, data in original.items()))
        listing = subprocess.run([sys.executable, "-m", "fangida.plugins.br_solver", str(json_path), "--list"],
                                 capture_output=True, text=True, timeout=15)
        self.assertEqual(listing.returncode, 0, listing.stderr)
        self.assertEqual([row["address"] for row in json.loads(listing.stdout)["branches"]], [branch])

    def test_cli_output_cannot_overwrite_snapshot_or_original_binary(self):
        snapshot, path, branch = self.prepare(_words(_movz(2, 0x6000), _br(2)))
        json_path = Path(self.directory.name) / "analysis.json"
        json_path.write_text(json.dumps(snapshot), encoding="utf-8")
        for protected in (json_path, path):
            with self.subTest(path=str(protected)):
                before = protected.read_bytes()
                process = subprocess.run([sys.executable, "-m", "fangida.plugins.br_solver", str(json_path),
                    "--address", hex(branch), "--source", str(path), "--output", str(protected), "--timeout-ms", "1000"],
                    capture_output=True, text=True, timeout=15)
                self.assertEqual(process.returncode, 2, process.stdout)
                self.assertIn("不能覆盖", process.stderr)
                self.assertEqual(protected.read_bytes(), before)

    def test_cli_output_cannot_overwrite_hardlink_to_an_input(self):
        snapshot, path, branch = self.prepare(_words(_movz(2, 0x6000), _br(2)))
        json_path = Path(self.directory.name) / "analysis.json"
        json_path.write_text(json.dumps(snapshot), encoding="utf-8")
        for index, protected in enumerate((json_path, path)):
            with self.subTest(path=str(protected)):
                before = protected.read_bytes()
                alias = Path(self.directory.name) / f"hardlink-{index}.json"
                os.link(protected, alias)
                process = subprocess.run([sys.executable, "-m", "fangida.plugins.br_solver", str(json_path),
                    "--address", hex(branch), "--source", str(path), "--output", str(alias), "--timeout-ms", "1000"],
                    capture_output=True, text=True, timeout=15)
                self.assertEqual(process.returncode, 2, process.stdout)
                self.assertIn("硬链接", process.stderr)
                self.assertEqual(protected.read_bytes(), before)


class BranchPluginIsolationTests(unittest.TestCase):
    def test_manager_and_default_routes_do_not_import_solver_or_unicorn(self):
        code = """
import sys
from fangida.plugins.manager import PluginManager
from fangida.plugins.interfaces import BranchSolverPlugin
manager = PluginManager()
assert manager.route('elf') == ('kkagent', 'analyze')
assert not any(name.startswith(('fangida.plugins.br_solver', 'unicorn')) for name in sys.modules)
plugin = manager.load_branch_solver()
assert isinstance(plugin, BranchSolverPlugin)
assert plugin is manager.load_branch_solver()
assert 'fangida.plugins.br_solver' in sys.modules
assert not any(name.startswith(('unicorn', 'fangida.processors', 'fangida.core.')) for name in sys.modules)
snapshot = {'kind': 'elf', 'metadata': {'architecture': 'arm64', 'full_disassembly': [
    {'addr': 4096, 'size': 4, 'mnemonic': 'mov', 'operands': ('x2', '#0x6000')},
    {'addr': 4100, 'size': 4, 'mnemonic': 'br', 'operands': ('x2',)}]},
    'functions': [{'start': 4096, 'size': 8}]}
assert plugin.solve(snapshot, 4100)['targets'] == [24576]
assert not any(name.startswith('unicorn') for name in sys.modules)
manager.teardown()
"""
        result = subprocess.run([sys.executable, "-c", code], capture_output=True,
                                text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_branch_provider_registration_is_lazy_and_does_not_change_native_route(self):
        events = []

        class Provider:
            name, version = "test_br_solver", "1"

            def capabilities(self):
                return ("arm64_br",)

            def solve(self, snapshot, branch_address, **kwargs):
                return {"status": "unknown", "targets": []}

            def teardown(self):
                events.append("closed")

        manager = PluginManager()
        manager.register_branch_solver("test_br_solver", lambda: (events.append("loaded") or Provider()))
        self.assertEqual(events, [])
        self.assertEqual(manager.route("elf"), ("kkagent", "analyze"))
        self.assertIs(manager.load_branch_solver("test_br_solver"), manager.load_branch_solver("test_br_solver"))
        self.assertEqual(events, ["loaded"])
        manager.teardown()
        self.assertEqual(events, ["loaded", "closed"])


if __name__ == "__main__":
    unittest.main()
