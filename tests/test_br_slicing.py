"""ARM64 BR/BLR 切片：多路径、运行时来源和缺失证据边界。"""
from __future__ import annotations

import copy
import threading
import time
import unittest
from unittest.mock import patch

from fangida.plugins.br_solver.slicing import slice_branch, simplify_slice_expression
from fangida.plugins.pseudoc.microcode import Expression, constant


def row(address, mnemonic, operands="", **fields):
    return {"addr": address, "size": 4, "mnemonic": mnemonic, "operands": operands, **fields}


def solve(*rows, entry=None, **options):
    functions = () if entry is None else ({"start": entry, "instructions": list(rows)},)
    return slice_branch(rows, rows[-1]["addr"], "arm64", functions=functions, **options)


class BrSlicingTests(unittest.TestCase):
    def test_constant_movk_partial_write_and_blr(self):
        result = solve(row(0x1000, "movz", "x9, #0x1234"),
                       row(0x1004, "movk", "x9, #0x5678, lsl #16"),
                       row(0x1008, "blr", "x9"), entry=0x1000)
        self.assertEqual(result["status"], "static")
        self.assertEqual(result["paths"][0]["constant_target"], 0x56781234)
        self.assertEqual(result["paths"][0]["slice_addresses"], [0x1000, 0x1004, 0x1008])

    def test_w_write_zeros_upper_bits_and_overwritten_runtime_is_killed(self):
        result = solve(row(0, "mrs", "x9, tpidr_el0"), row(4, "mov", "w9, #0x40"),
                       row(8, "br", "x9"), entry=0)
        self.assertEqual(result["status"], "static")
        self.assertEqual(result["paths"][0]["constant_target"], 64)
        self.assertNotIn(0, result["paths"][0]["slice_addresses"])

    def test_live_in_is_runtime_only_at_proven_function_entry(self):
        rows = [row(0, "add", "x9, x0, #8"), row(4, "br", "x9")]
        runtime = solve(*rows, entry=0)
        self.assertEqual(runtime["status"], "runtime")
        self.assertEqual(runtime["paths"][0]["dependencies"][0]["kind"], "entry_register")
        unknown = solve(*rows)
        self.assertEqual(unknown["status"], "unknown")
        self.assertEqual(unknown["paths"][0]["dependencies"][0]["kind"], "missing_definition")

    def test_system_register_and_external_call_classification(self):
        system = solve(row(0, "mrs", "x9, tpidr_el0"), row(4, "add", "x9, x9, #8"),
                       row(8, "br", "x9"), entry=0)
        self.assertEqual(system["status"], "runtime")
        self.assertEqual(system["paths"][0]["dependencies"][0]["system_register"], "tpidr_el0")
        external = solve(row(0, "bl", "0x2000"), row(4, "mov", "x9, x0"),
                         row(8, "br", "x9"), entry=0)
        self.assertEqual(external["status"], "runtime")
        self.assertEqual(external["paths"][0]["dependencies"][0]["kind"], "external_call")

    def test_unsupported_never_claims_runtime_or_static(self):
        result = solve(row(0, "future_unknown", "x9, x0"), row(4, "br", "x9"), entry=0)
        self.assertEqual(result["status"], "unknown")
        self.assertIsNone(result["paths"][0]["constant_target"])
        self.assertIn("unsupported", {item["kind"] for item in result["paths"][0]["dependencies"]})

    def test_distinct_predecessor_constants_are_preserved(self):
        rows = [row(0, "cbz", "x0, #0xc"), row(4, "mov", "x9, #0x1000"),
                row(8, "b", "#0x10"), row(12, "mov", "x9, #0x2000"), row(16, "br", "x9")]
        result = solve(*rows, entry=0)
        self.assertEqual(result["status"], "runtime")
        self.assertEqual(len(result["paths"]), 2)
        self.assertEqual({path["constant_target"] for path in result["paths"]}, {0x1000, 0x2000})
        self.assertEqual({path["conditions"][0]["taken"] for path in result["paths"]}, {True, False})

    def test_known_control_input_excludes_infeasible_predecessor(self):
        rows = [row(0, "mov", "x0, #0"), row(4, "cbz", "x0, #0x10"),
                row(8, "mov", "x9, #0x1000"), row(12, "b", "#0x14"),
                row(16, "mov", "x9, #0x2000"), row(20, "br", "x9")]
        result = solve(*rows, entry=0)
        self.assertEqual(result["status"], "static")
        feasible = [path for path in result["paths"] if path["feasible"]]
        self.assertEqual(len(feasible), 1)
        self.assertEqual(feasible[0]["constant_target"], 0x2000)
        self.assertIn(0, feasible[0]["slice_addresses"])

    def test_select_dependencies_and_constant_predicate_kill_unused_arm(self):
        known = solve(row(0, "mov", "x1, #0x4000"), row(4, "cmp", "x1, #0x4000"),
                      row(8, "csel", "x9, x1, x2, eq"), row(12, "br", "x9"), entry=0)
        self.assertEqual(known["status"], "static")
        self.assertEqual(known["paths"][0]["constant_target"], 0x4000)
        self.assertEqual(known["paths"][0]["dependencies"], [])
        runtime = solve(row(0, "cmp", "x0, #0"), row(4, "csel", "x9, x1, x2, eq"),
                        row(8, "br", "x9"), entry=0)
        self.assertEqual(runtime["status"], "runtime")
        self.assertEqual({dep["register"] for dep in runtime["paths"][0]["dependencies"]}, {"x0", "x1", "x2"})

    def test_spilled_target_and_overlapping_byte_store(self):
        result = solve(row(0, "mov", "x9, #0x1000"), row(4, "str", "x9, [sp]"),
                       row(8, "mov", "w0, #0x44"), row(12, "strb", "w0, [sp, #1]"),
                       row(16, "ldr", "x8, [sp]"), row(20, "br", "x8"), entry=0)
        self.assertEqual(result["status"], "static")
        self.assertEqual(result["paths"][0]["constant_target"], 0x4400)
        self.assertIn(4, result["paths"][0]["slice_addresses"])
        self.assertIn(12, result["paths"][0]["slice_addresses"])

    def test_preindex_pair_store_and_postindex_pair_load(self):
        result = solve(row(0, "mov", "x9, #0x1110"), row(4, "mov", "x10, #0x2220"),
                       row(8, "stp", "x9, x10, [sp, #-16]!"),
                       row(12, "ldp", "x11, x12, [sp], #16"), row(16, "br", "x12"), entry=0)
        self.assertEqual(result["status"], "static")
        self.assertEqual(result["paths"][0]["constant_target"], 0x2220)

    def test_unknown_memory_remains_symbolic_and_reports_byte_addresses(self):
        result = solve(row(0x1000, "adrp", "x1, #0x2000"), row(0x1004, "ldr", "x9, [x1, #8]"),
                       row(0x1008, "br", "x9"), entry=0x1000)
        self.assertEqual(result["status"], "unknown")
        dependencies = result["paths"][0]["dependencies"]
        self.assertEqual({dep["kind"] for dep in dependencies}, {"memory_read"})
        self.assertEqual({dep["address"] for dep in dependencies}, set(range(0x2008, 0x2010)))
        self.assertIsNone(result["paths"][0]["constant_target"])

    def test_unknown_store_alias_does_not_reuse_older_concrete_store(self):
        result = solve(row(0, "mov", "x9, #0x1000"), row(4, "str", "x9, [sp]"),
                       row(8, "str", "x0, [x1]"), row(12, "ldr", "x8, [sp]"),
                       row(16, "br", "x8"), entry=0)
        self.assertEqual(result["status"], "unknown")
        self.assertIn("memory_alias", {dep["kind"] for dep in result["paths"][0]["dependencies"]})

    def test_path_and_instruction_limits_never_claim_completeness(self):
        rows = [row(0, "cbz", "x0, #0xc"), row(4, "mov", "x9, #0x1000"),
                row(8, "b", "#0x10"), row(12, "mov", "x9, #0x2000"), row(16, "br", "x9")]
        paths = solve(*rows, entry=0, max_paths=1)
        self.assertEqual(paths["status"], "unknown")
        self.assertTrue(paths["truncated"])
        self.assertIn("path_budget", {dep["kind"] for dep in paths["paths"][0]["dependencies"]})
        limited = solve(*rows, entry=0, max_instructions=1)
        self.assertTrue(limited["truncated"])
        self.assertEqual(limited["paths"][0]["boundary"], "instruction_budget")

    def test_loop_does_not_invent_missing_iteration_values(self):
        rows = [row(0, "add", "x9, x9, #4"), row(4, "cbnz", "x0, #0"), row(8, "br", "x9")]
        result = solve(*rows)
        self.assertEqual(result["status"], "unknown")
        self.assertTrue(result["truncated"])
        self.assertIn("loop", {dep["kind"] for dep in result["paths"][0]["dependencies"]})
        explicit_entry = solve(*rows, entry=0)
        self.assertEqual(explicit_entry["status"], "unknown")
        self.assertTrue(explicit_entry["truncated"])

    def test_dependencies_preserve_control_vs_target_roles(self):
        result = solve(row(0, "cbz", "x0, #8"), row(4, "mov", "x9, x1"),
                       row(8, "br", "x9"), entry=0)
        dependencies = [dep for path in result["paths"] for dep in path["dependencies"]]
        self.assertIn(("x0", "control"), {(dep.get("register"), dep.get("role")) for dep in dependencies})
        self.assertIn(("x1", "target"), {(dep.get("register"), dep.get("role")) for dep in dependencies})

    def test_equivalent_select_arms_kill_flags_input(self):
        result = solve(row(0, "mov", "x1, #32"), row(4, "csel", "x9, x1, x1, eq"),
                       row(8, "br", "x9"), entry=0)
        self.assertEqual(result["status"], "static")
        self.assertEqual(result["paths"][0]["dependencies"], [])

    def test_expression_budget_is_distinct_from_path_budget(self):
        rows = [row(index * 4, "add", "x9, x9, #1") for index in range(100)]
        result = solve(*rows, row(400, "br", "x9"), entry=0)
        self.assertEqual(result["status"], "unknown")
        self.assertTrue(result["truncated"])
        kinds = {dep["kind"] for dep in result["paths"][0]["dependencies"]}
        self.assertIn("expression_budget", kinds)
        self.assertNotIn("path_budget", kinds)

    def test_public_expression_folding_after_proven_substitution(self):
        flags = Expression("arm_flag", 1, (constant(0, 64), constant(0, 64)), name="arm:sub:64:Z")
        predicate = Expression("condition", 1, (flags,), value=2, name="eq")
        select = Expression("select", 64, (predicate, constant(0x4000, 64),
                                          Expression("register", 64, name="x2")))
        self.assertEqual(simplify_slice_expression(select).value, 0x4000)
        self.assertEqual(simplify_slice_expression(select.to_dict()).value, 0x4000)
        with self.assertRaises(TypeError):
            simplify_slice_expression(None)

    def test_deadline_and_pre_cancel_are_explicit_without_fake_target(self):
        rows = [row(0, "mov", "x9, #16"), row(4, "br", "x9")]
        event = threading.Event()
        event.set()
        for options, reason in (({"deadline": time.monotonic() - 1}, "deadline"),
                                ({"cancel": event}, "cancelled"), ({"cancel": lambda: True}, "cancelled")):
            result = solve(*rows, entry=0, **options)
            self.assertEqual(result["status"], "unknown")
            self.assertTrue(result["truncated"])
            self.assertEqual(result["stop_reason"], reason)
            self.assertEqual(result["paths"][0]["dependencies"][0]["kind"], reason)
            self.assertFalse(result["paths"][0]["complete"])
            self.assertIsNone(result["paths"][0]["constant_target"])

    def test_cancel_during_snapshot_collection_does_not_require_entire_input(self):
        event = threading.Event()

        def instructions():
            yield row(0, "mov", "x9, #16")
            event.set()
            yield row(4, "br", "x9")
            self.fail("cancelled snapshot was consumed beyond the next row")

        result = slice_branch(instructions(), 4, "arm64", cancel=event)
        self.assertEqual(result["stop_reason"], "cancelled")

    def test_cancel_during_function_scope_and_cfg_construction(self):
        from fangida.plugins.br_solver import slicing
        rows = [row(0, "mov", "x9, #16"), row(4, "br", "x9")]
        event = threading.Event()

        def function_rows():
            yield rows[0]
            event.set()
            yield rows[1]
            self.fail("cancelled function scope was consumed beyond the next row")

        result = slice_branch(rows, 4, "arm64", functions=[{"start": 0, "blocks": [{"instructions": function_rows()}]}], cancel=event)
        self.assertEqual(result["stop_reason"], "cancelled")
        event.clear()
        original = slicing._branch

        def branch_metadata(instruction):
            event.set()
            return original(instruction)

        with patch.object(slicing, "_branch", side_effect=branch_metadata):
            result = solve(*rows, entry=0, cancel=event)
        self.assertEqual(result["stop_reason"], "cancelled")

    def test_deadline_during_lifting_and_cancel_during_reverse_propagation(self):
        from fangida.plugins.br_solver import slicing
        rows = [row(0, "mov", "x9, #16"), row(4, "br", "x9")]
        original = slicing.lift_instruction

        def slow_lift(instruction, architecture):
            time.sleep(0.01)
            return original(instruction, architecture)

        with patch.object(slicing, "lift_instruction", side_effect=slow_lift):
            result = solve(*rows, entry=0, deadline=time.monotonic() + 0.005)
        self.assertEqual(result["stop_reason"], "deadline")
        self.assertIsNone(result["paths"][0]["constant_target"])
        event = threading.Event()
        original_write = slicing._write_value

        def cancelling_write(operation, address):
            event.set()
            return original_write(operation, address)

        with patch.object(slicing, "_write_value", side_effect=cancelling_write):
            result = solve(*rows, entry=0, cancel=event)
        self.assertEqual(result["stop_reason"], "cancelled")
        self.assertIsNone(result["paths"][0]["constant_target"])

    def test_cancel_during_predecessor_path_enumeration(self):
        from fangida.plugins.br_solver import slicing
        rows = [row(0, "cbz", "x0, #0xc"), row(4, "mov", "x9, #16"),
                row(8, "b", "#0x10"), row(12, "mov", "x9, #32"), row(16, "br", "x9")]
        event, calls = threading.Event(), []
        original = slicing._branch

        def metadata(instruction):
            calls.append(instruction["addr"])
            # Each row is visited once while CFG edges are built.  The next
            # metadata request comes from conditional predecessor enumeration.
            if len(calls) > len(rows):
                event.set()
            return original(instruction)

        with patch.object(slicing, "_branch", side_effect=metadata):
            result = solve(*rows, entry=0, cancel=event)
        self.assertGreater(len(calls), len(rows))
        self.assertEqual(result["stop_reason"], "cancelled")
        self.assertIsNone(result["paths"][0]["constant_target"])

    def test_exponential_register_expression_has_bounded_nodes(self):
        rows = [row(index * 4, "mul", "x9, x9, x9") for index in range(40)]
        started = time.monotonic()
        result = solve(*rows, row(160, "br", "x9"), entry=0)
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(result["status"], "unknown")
        self.assertTrue(result["truncated"])
        self.assertIn("expression_budget", {item["kind"] for item in result["paths"][0]["dependencies"]})
        self.assertIsNone(result["paths"][0]["constant_target"])

    def test_shared_expression_is_checked_without_serializing_exponential_tree(self):
        expr = Expression("register", 64, name="x0")
        for _ in range(40):
            expr = Expression("mul", 64, (expr, expr))
        started = time.monotonic()
        with self.assertRaisesRegex(ValueError, "node budget"):
            simplify_slice_expression(expr)
        self.assertLess(time.monotonic() - started, 0.5)
        serialized = {"opcode": "register", "width": 64, "name": "x0"}
        for _ in range(40):
            serialized = {"opcode": "mul", "width": 64, "args": [serialized, serialized]}
        with patch.object(Expression, "from_dict", side_effect=AssertionError("unbounded dictionary expansion")):
            with self.assertRaisesRegex(ValueError, "node budget"):
                simplify_slice_expression(serialized)

    def test_new_limit_arguments_validate_types(self):
        rows = [row(0, "mov", "x9, #16"), row(4, "br", "x9")]
        for deadline in (False, "soon", float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                solve(*rows, deadline=deadline)
        with self.assertRaises(TypeError):
            solve(*rows, cancel=True)

    def test_declared_function_entry_missing_does_not_confirm_local_constant(self):
        rows = [row(4, "movz", "x9, #0x4000"), row(8, "br", "x9")]
        result = solve(*rows, entry=0)
        self.assertEqual(result["status"], "unknown")
        self.assertTrue(result["truncated"])
        path = result["paths"][0]
        self.assertFalse(path["complete"])
        self.assertEqual(path["constant_target"], 0x4000)
        self.assertIn(("cfg_incomplete", "control"), {(dep["kind"], dep.get("role")) for dep in path["dependencies"]})

    def test_gap_or_disconnected_predecessor_cannot_prove_function_path(self):
        for head in (row(0, "nop"), row(0, "ret")):
            rows = [head, row(8, "movz", "x9, #0x4000"), row(12, "br", "x9")]
            result = solve(*rows, entry=0)
            self.assertEqual(result["status"], "unknown")
            self.assertFalse(result["paths"][0]["complete"])
            self.assertIn("cfg_incomplete", {dep["kind"] for dep in result["paths"][0]["dependencies"]})

    def test_unscoped_constant_proof_keeps_compatibility_and_complete_function_is_static(self):
        tail = [row(4, "movz", "x9, #0x4000"), row(8, "br", "x9")]
        unscoped = solve(*tail)
        self.assertEqual(unscoped["status"], "static")
        self.assertTrue(unscoped["paths"][0]["complete"])
        full = solve(row(0, "nop"), *tail, entry=0)
        self.assertEqual(full["status"], "static")
        self.assertTrue(full["paths"][0]["complete"])

    def test_entry_reachability_excludes_isolated_fallthrough_block(self):
        rows = [row(0x1000, "cbz", "x0, #0x1010"), row(0x1004, "movz", "x2, #0x4000"),
                row(0x1008, "b", "#0x1014"), row(0x100c, "nop"),
                row(0x1010, "movz", "x2, #0x5000"), row(0x1014, "br", "x2")]
        result = solve(*rows, entry=0x1000)
        self.assertEqual(len(result["paths"]), 2)
        for path in result["paths"]:
            self.assertTrue(path["complete"])
            self.assertEqual(path["boundary"], "entry")
            self.assertEqual(len(path["conditions"]), 1)
            self.assertNotIn(0x100c, {item["addr"] for item in path["instructions"]})
        false_path = next(path for path in result["paths"] if not path["conditions"][0]["taken"])
        true_path = next(path for path in result["paths"] if path["conditions"][0]["taken"])
        self.assertEqual(false_path["constant_target"], 0x4000)
        self.assertEqual(true_path["constant_target"], 0x5000)

    def test_reachable_gap_is_preserved_when_other_path_reaches_branch(self):
        rows = [row(0, "cbz", "x0, #8"), row(4, "b", "#0x10"),
                row(8, "movz", "x9, #0x4000"), row(12, "br", "x9")]
        result = solve(*rows, entry=0)
        self.assertEqual(result["status"], "unknown")
        self.assertTrue(result["truncated"])
        self.assertFalse(result["paths"][0]["complete"])
        cfg = next(item for item in result["paths"][0]["dependencies"] if item["kind"] == "cfg_incomplete")
        self.assertEqual(cfg["role"], "control")
        self.assertEqual(cfg["frontiers"], [{"at": 4, "target": 16, "kind": "missing_instruction", "taken": None}])

    def test_reachable_unknown_indirect_transfer_preserves_cfg_barrier(self):
        rows = [row(0, "cbz", "x0, #8"), row(4, "br", "x1"),
                row(8, "movz", "x9, #0x4000"), row(12, "br", "x9")]
        result = solve(*rows, entry=0)
        self.assertEqual(result["status"], "unknown")
        self.assertFalse(result["paths"][0]["complete"])
        cfg = next(item for item in result["paths"][0]["dependencies"] if item["kind"] == "cfg_incomplete")
        self.assertEqual(cfg["frontiers"][0]["kind"], "indirect_control")
        self.assertEqual(cfg["frontiers"][0]["at"], 4)

    def test_snapshot_only_preserves_original_rows_and_api_validation(self):
        rows = [row(0, "mov", "x9, #16", bytes="090280d2", custom={"keep": True}), row(4, "br", "x9", bytes="20011fd6")]
        original = copy.deepcopy(rows)
        with patch("fangida.processors.decoder.NativeDecoder.__init__", side_effect=AssertionError("decoder called")):
            result = solve(*rows, entry=0)
        self.assertEqual(rows, original)
        self.assertEqual(result["paths"][0]["instructions"], original)
        with self.assertRaises(ValueError):
            slice_branch(rows, 4, "x86_64")
        for key, value in (("max_paths", False), ("max_instructions", 0)):
            with self.assertRaises(ValueError):
                solve(*rows, **{key: value})


if __name__ == "__main__":
    unittest.main()
