"""Unicorn backend safety over completed ARM64 snapshots."""
from __future__ import annotations

import builtins
import importlib.util
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from unittest.mock import patch

from fangida.plugins.br_solver.emulator import (
    MAX_MAPPING_BYTES, MAX_STEPS, emulate_slice,
)
from fangida.processors.decoder import NativeDecoder

_HAS_UNICORN = importlib.util.find_spec("unicorn") is not None


def _word(value):
    return value.to_bytes(4, "little")


def _mov(register, value, *, wide=True):
    return _word((0xD2800000 if wide else 0x52800000) | (value << 5) | register)


def _branch(register=16, *, link=False):
    return _word((0xD63F0000 if link else 0xD61F0000) | (register << 5))


def _snapshot(code, address=0x1000):
    rows, warnings = NativeDecoder("arm64").decode_bytes_fast(code, address, include_data=True)
    if warnings or len(rows) * 4 != len(code):
        raise AssertionError(f"测试样本必须先完整解码：{warnings}")
    return rows


def _code_segment(code, *, address=0x1000):
    return {"address": address, "data": code, "writable": False, "executable": True, "origin": "file"}


def _memory(value=0x4000, *, address=0x2000, writable=False, origin="file", data=None):
    return {"address": address, "data": value.to_bytes(8, "little") if data is None else data,
            "writable": writable, "executable": False, "origin": origin}


@unittest.skipUnless(_HAS_UNICORN, "Unicorn 是可选依赖")
class BrEmulatorTests(unittest.TestCase):
    def run_code(self, code, *, rows=None, segments=(), **options):
        rows = _snapshot(code) if rows is None else rows
        return emulate_slice(rows, rows[-1]["addr"], "x16",
                             segments=(_code_segment(code), *segments), **options)

    def test_constant_br_blr_stop_before_branch_without_decoding_or_threads(self):
        for link in (False, True):
            code = _mov(16, 0x1234) + _branch(link=link)
            rows = _snapshot(code)
            original = deepcopy(rows)
            with patch.object(NativeDecoder, "decode_bytes", side_effect=AssertionError("后端不得解码")), \
                    patch.object(NativeDecoder, "decode_bytes_fast", side_effect=AssertionError("后端不得解码")), \
                    patch.object(threading.Thread, "start", side_effect=AssertionError("后端不得创建 Python 线程")):
                result = self.run_code(code, rows=rows)
            self.assertEqual(result["status"], "resolved", result)
            self.assertEqual(result["target"], 0x1234)
            self.assertEqual(result["steps"], 1)
            self.assertTrue(result["path_verified"])
            self.assertFalse(result["context_dependent"])
            self.assertEqual(rows, original)

    def test_writes_w_register_clear_high_x_bits_and_aliases_are_checked(self):
        code = _mov(16, 0x12, wide=False) + _branch()
        result = self.run_code(code, registers={"x16": 0xFFFFFFFF00000000})
        self.assertEqual(result["target"], 0x12, result)
        self.assertFalse(result["context_dependent"])
        conflict = self.run_code(code, registers={"x16": 0x100000000, "w16": 0x20})
        self.assertEqual(conflict["status"], "error", conflict)

    def test_runtime_register_never_uses_default_zero(self):
        code = _word(0x91000410) + _branch()  # add x16,x0,#1
        result = self.run_code(code)
        self.assertEqual(result["status"], "runtime_dependent", result)
        self.assertIsNone(result["target"])
        self.assertEqual(result["steps"], 0)
        self.assertEqual(result["dependencies"][0]["register"], "x0")
        provided = self.run_code(code, registers={"w0": 0x4000})
        self.assertEqual(provided["target"], 0x4001, provided)
        self.assertTrue(provided["context_dependent"])

    def test_movk_requires_previous_destination_definition(self):
        code = _word(0xF2A00030) + _branch()  # movk x16,#1,lsl #16
        result = self.run_code(code)
        self.assertEqual(result["status"], "runtime_dependent", result)
        self.assertIsNone(result["target"])
        provided = self.run_code(code, registers={"x16": 0x1234})
        self.assertEqual(provided["target"], 0x11234, provided)
        self.assertTrue(provided["context_dependent"])

    def test_zero_register_and_semantic_constant_kill(self):
        for word in (0xAA1F03F0, 0xCA000010):  # mov x16,xzr; eor x16,x0,x0
            result = self.run_code(_word(word) + _branch())
            self.assertEqual(result["status"], "resolved", result)
            self.assertEqual(result["target"], 0)
            self.assertFalse(result["context_dependent"])
            self.assertEqual(result["proofs"][0]["kind"], "constant_assignment")

    def test_branch_byte_guard_rejects_a_different_operand_even_if_values_match(self):
        code = _mov(16, 0x4000) + _branch()
        rows = _snapshot(code)
        for changed_branch in (_branch(0), _word(0xD503201F), _branch(link=True)):
            changed_code = code[:4] + changed_branch
            result = self.run_code(changed_code, rows=rows, registers={"x0": 0x4000})
            self.assertEqual(result["status"], "unknown", result)
            self.assertIsNone(result["target"])
            self.assertFalse(result["branch_bytes_verified"])
            self.assertFalse(result["path_verified"])
            self.assertTrue(any(dep.get("source") == "byte_mismatch" for dep in result["dependencies"]))
        changed_code = _mov(0, 0x4000) + _branch()  # IR 声称写 x16，字节实际写 x0
        result = self.run_code(changed_code, rows=rows)
        self.assertEqual(result["status"], "unknown", result)
        self.assertIsNone(result["target"])
        self.assertTrue(any(dep.get("source") == "byte_mismatch" for dep in result["dependencies"]))

    def test_fp_lr_aliases_and_sp_need_explicit_context(self):
        code = _word(0xAA1E03F0) + _branch()  # mov x16,x30
        result = self.run_code(code, registers={"lr": 0x4000})
        self.assertEqual(result["target"], 0x4000, result)
        self.assertTrue(result["context_dependent"])
        code = _word(0xF94003F0) + _branch()  # ldr x16,[sp]
        missing = self.run_code(code, segments=(_memory(),))
        self.assertEqual(missing["status"], "runtime_dependent", missing)
        provided = self.run_code(code, segments=(_memory(origin="provided"),), registers={"sp": 0x2000})
        self.assertEqual(provided["target"], 0x4000, provided)
        self.assertTrue(provided["context_dependent"])

    def test_branch_preflight_is_not_hidden_by_unknown_stack_prologue(self):
        # stp x29,x30,[sp,#-16]!; mov x16,#0x4000; br x16
        code = _word(0xA9BF7BFD) + _mov(16, 0x4000) + _branch()
        rows = _snapshot(code)
        unknown_stack = self.run_code(code, rows=rows)
        self.assertEqual(unknown_stack["status"], "runtime_dependent", unknown_stack)
        self.assertTrue(unknown_stack["branch_bytes_verified"])
        changed = code[:-4] + _branch(0)
        result = self.run_code(changed, rows=rows)
        self.assertEqual(result["status"], "unknown", result)
        self.assertEqual(result["steps"], 0)
        self.assertFalse(result["branch_bytes_verified"])
        self.assertTrue(any(dep.get("source") == "byte_mismatch" for dep in result["dependencies"]))
        non_executable = {**_code_segment(code), "executable": False}
        result = emulate_slice(rows, rows[-1]["addr"], "x16", segments=(non_executable,))
        self.assertEqual(result["status"], "unknown", result)
        self.assertEqual(result["steps"], 0)
        self.assertTrue(any(dep.get("source") == "non_executable" for dep in result["dependencies"]))

    def test_readonly_file_memory_is_static_but_writable_and_runtime_are_unknown(self):
        code = _mov(0, 0x2000) + _word(0xF9400010) + _branch()  # ldr x16,[x0]
        result = self.run_code(code, segments=(_memory(),))
        self.assertEqual(result["status"], "resolved", result)
        self.assertEqual(result["target"], 0x4000)
        self.assertFalse(result["context_dependent"])
        for source in (_memory(writable=True), _memory(origin="runtime")):
            unknown = self.run_code(code, segments=(source,))
            self.assertEqual(unknown["status"], "runtime_dependent", unknown)
            self.assertIsNone(unknown["target"])
        unknown_permission = self.run_code(code, segments=(_memory(writable=None),))
        self.assertEqual(unknown_permission["status"], "unknown", unknown_permission)

    def test_runtime_snapshot_overrides_file_bytes_and_is_context_dependent(self):
        code = _mov(0, 0x2000) + _word(0xF9400010) + _branch()
        result = self.run_code(code, segments=(_memory(0x4000, writable=True),
                                               _memory(0x9000, writable=True, origin="provided")))
        self.assertEqual(result["status"], "resolved", result)
        self.assertEqual(result["target"], 0x9000)
        self.assertTrue(result["context_dependent"])
        self.assertTrue(any(item.get("source") == "provided" for item in result["dependencies"]))

    def test_page_padding_and_partial_runtime_snapshot_are_not_known_zero(self):
        code = _mov(0, 0x2000) + _word(0xF9400010) + _branch()
        result = self.run_code(code, segments=(_memory(data=b"\x00" * 4),))
        self.assertEqual(result["status"], "unknown", result)
        self.assertIsNone(result["target"])
        result = self.run_code(code, segments=(_memory(writable=True),
                                               _memory(origin="provided", data=b"\x00" * 4)))
        self.assertEqual(result["status"], "runtime_dependent", result)
        self.assertIsNone(result["target"])

    def test_known_stores_make_only_the_written_bytes_known(self):
        prefix = _mov(0, 0x2000) + _mov(1, 0x4000)
        for store, expected in ((0xF9000001, "resolved"), (0xB9000001, "runtime_dependent")):
            code = prefix + _word(store) + _word(0xF9400010) + _branch()
            result = self.run_code(code, segments=(_memory(writable=True),))
            self.assertEqual(result["status"], expected, result)
            self.assertEqual(result["target"], 0x4000 if expected == "resolved" else None)
        code = prefix + _word(0xF9000001) + _word(0xF9400010) + _branch()
        readonly = self.run_code(code, segments=(_memory(writable=False),))
        self.assertEqual(readonly["status"], "unknown", readonly)

    def test_declared_read_permissions_and_self_modifying_code_remain_unknown(self):
        load = _mov(0, 0x2000) + _word(0xF9400010) + _branch()
        for readable in (False, None):
            memory = {**_memory(), "readable": readable}
            result = self.run_code(load, segments=(memory,))
            self.assertEqual(result["status"], "unknown", result)
            self.assertIsNone(result["target"])
        code = _mov(0, 0x2000) + _mov(1, 0x4000) + _word(0xF9000001) + _branch()
        mutable_code = {**_memory(writable=True, origin="provided"), "executable": True}
        result = self.run_code(code, segments=(mutable_code,))
        self.assertEqual(result["status"], "unknown", result)
        self.assertTrue(any(dep.get("source") == "self_modifying_code" for dep in result["dependencies"]))

    def test_unmapped_address_and_code_bytes_are_not_generated(self):
        code = _mov(0, 0x2000) + _word(0xF9400010) + _branch()
        result = self.run_code(code)
        self.assertEqual(result["status"], "unknown", result)
        self.assertIsNone(result["target"])
        rows = _snapshot(_mov(16, 0x1234) + _branch())
        result = emulate_slice(rows, 0x1004, "x16", segments=(_code_segment(code[:4]),))
        self.assertEqual(result["status"], "unknown", result)
        self.assertIsNone(result["target"])

    def test_conditional_path_must_match_actual_unicorn_pc(self):
        code = _mov(16, 0x4000) + _word(0xB4000040) + _word(0xD503201F) + _branch()
        rows = _snapshot(code)
        taken = [rows[0], rows[1], rows[3]]
        result = self.run_code(code, rows=taken, registers={"x0": 0})
        self.assertEqual(result["status"], "resolved", result)
        self.assertEqual(result["target"], 0x4000)
        mismatch = self.run_code(code, rows=taken, registers={"x0": 1})
        self.assertEqual(mismatch["status"], "infeasible", mismatch)
        self.assertIsNone(mismatch["target"])
        missing = self.run_code(code, rows=taken)
        self.assertEqual(missing["status"], "runtime_dependent", missing)

    def test_direct_branch_and_pc_relative_readonly_target(self):
        code = _mov(16, 0x4000) + _word(0x14000002) + _word(0xD503201F) + _branch()
        rows = _snapshot(code)
        result = self.run_code(code, rows=[rows[0], rows[1], rows[3]])
        self.assertEqual(result["status"], "resolved", result)
        self.assertEqual(result["target"], 0x4000)
        # adrp x16,#0x2000; ldr x16,[x16]; br x16
        code = _word(0xB0000010) + _word(0xF9400210) + _branch()
        result = self.run_code(code, segments=(_memory(),))
        self.assertEqual(result["status"], "resolved", result)
        self.assertEqual(result["target"], 0x4000)

    def test_flags_are_not_default_zero_and_old_snapshots_get_semantic_effects(self):
        code = _mov(16, 0x4000) + _word(0x54000040) + _word(0xD503201F) + _branch()
        rows = _snapshot(code)
        taken = [rows[0], rows[1], rows[3]]
        for row in taken:
            row.pop("reads", None)
            row.pop("writes", None)
        missing = self.run_code(code, rows=taken)
        self.assertEqual(missing["status"], "runtime_dependent", missing)
        self.assertTrue(any(dep.get("register") == "nzcv" for dep in missing["dependencies"]))
        provided = self.run_code(code, rows=taken, registers={"nzcv": 1 << 30})
        self.assertEqual(provided["status"], "resolved", provided)
        self.assertTrue(provided["context_dependent"])

    def test_skipped_pure_output_is_invalidated_and_calls_cannot_be_skipped(self):
        code = _mov(16, 0x4000) + _branch()
        skipped = self.run_code(code, slice_addresses=(0x1004,), registers={"x16": 0x9000})
        self.assertEqual(skipped["status"], "runtime_dependent", skipped)
        self.assertIsNone(skipped["target"])
        for operation in (0x94000001, 0xD4000001):  # bl; svc
            code = _word(operation) + _mov(16, 0x4000) + _branch()
            result = self.run_code(code, slice_addresses=(0x1004, 0x1008))
            self.assertEqual(result["status"], "runtime_dependent", result)
            self.assertEqual(result["steps"], 0)

    def test_step_time_cancel_and_mapping_budgets(self):
        code = _mov(16, 0x4000) + _word(0x91000610) + _branch()
        bounded = self.run_code(code, max_steps=1)
        self.assertEqual(bounded["status"], "budget_exceeded", bounded)
        self.assertEqual(bounded["steps"], 1)
        self.assertIsNone(bounded["target"])
        self.assertEqual(self.run_code(code, cancel=lambda: True)["status"], "cancelled")
        event = threading.Event()
        event.set()
        self.assertEqual(self.run_code(code, cancel=event)["status"], "cancelled")
        self.assertEqual(self.run_code(code, max_steps=MAX_STEPS + 1)["status"], "budget_exceeded")
        self.assertEqual(self.run_code(code, segments=(_memory(data=b"x" * (MAX_MAPPING_BYTES + 1)),))["status"], "budget_exceeded")
        empty = _memory(data=b"")
        self.assertEqual(self.run_code(code, segments=(empty,) * 256)["status"], "budget_exceeded")
        # Page count cannot exceed its limit even with a small unaligned tail.
        with patch("fangida.plugins.br_solver.emulator.MAX_MAPPING_PAGES", 1):
            result = self.run_code(code, segments=(_memory(address=0x2FFF, data=b"xx"),))
            self.assertEqual(result["status"], "budget_exceeded", result)
        with patch("fangida.plugins.br_solver.emulator.monotonic", side_effect=[0, 1]):
            result = self.run_code(code, timeout_ms=1)
            self.assertEqual(result["status"], "budget_exceeded", result)

    def test_each_request_has_an_independent_engine_and_memory(self):
        code = _word(0x91000410) + _branch()
        rows = _snapshot(code)
        with ThreadPoolExecutor(max_workers=4) as pool:
            outputs = list(pool.map(lambda value: self.run_code(code, rows=rows, registers={"x0": value}), range(8)))
        self.assertEqual([output["target"] for output in outputs], list(range(1, 9)))
        self.assertTrue(all(output["status"] == "resolved" for output in outputs))


class BrEmulatorOptionalDependencyTests(unittest.TestCase):
    def test_unicorn_import_is_lazy_and_missing_dependency_returns_unavailable(self):
        original_import = builtins.__import__

        def unavailable(name, *args, **kwargs):
            if name == "unicorn" or name.startswith("unicorn."):
                raise ImportError("模拟可选依赖未安装")
            return original_import(name, *args, **kwargs)

        row = {"addr": 0x1000, "size": 4, "mnemonic": "br", "operands": ["x16"]}
        with patch("builtins.__import__", side_effect=unavailable):
            result = emulate_slice([row], 0x1000, "x16")
        self.assertEqual(result["status"], "unavailable", result)
        self.assertIsNone(result["target"])


if __name__ == "__main__":
    unittest.main()
