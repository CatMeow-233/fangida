"""Retain terminal machine-state regions that have no justified C contract.

This is an explicit partial-source boundary, not another instruction lifter.
All instructions and effects remain in the original microcode and in the
region's evidence; the source display never invents a return from a jump.
"""
from __future__ import annotations

from copy import deepcopy

from .cfg import reachable
from .model import Statement, Value


def retain_machine_regions(blocks, entry, frame, architecture, original_records=None):
    regions = []
    original_rows = {row["addr"]: row for row in original_records or ()}
    for block in list(blocks.values()):
        if not block.records:
            continue
        terminal = next((operation for operation in block.records[-1]["operations"]
                         if operation["opcode"] in {"jump", "return", "trap"}), None)
        if terminal is None:
            continue
        attributes = terminal.get("attributes", {})
        target = attributes.get("external_target", attributes.get("target"))
        # A region with a source successor needs an explicit state-to-source
        # contract. Do not silently replace it and then resume ordinary C.
        if terminal["opcode"] == "jump" and isinstance(target, int) and any(
                row["addr"] == target for candidate in blocks.values() for row in candidate.records):
            continue
        reasons = []
        for row in block.records:
            for operation in row["operations"]:
                attrs = operation.get("attributes", {})
                if operation["opcode"] == "system_transition" and attrs.get("handler", "unknown") == "unknown":
                    reasons.append("unknown_exception_handler_contract")
            offset = frame.before.get(row["addr"], {}).get(frame.abi.stack_pointer)
            if offset is not None and offset > 0:
                reasons.append("stack_pointer_outside_function_frame")
        if not reasons:
            continue
        name = f"machine_region_{len(regions) + 1}"
        addresses = [row.get("original_address", row["addr"]) for row in block.records]
        operations = [deepcopy(original_rows.get(row.get("original_address", row["addr"]), row)) for row in block.records]
        for row in operations:
            row["addr"] = row.pop("original_address", row["addr"])
        inputs = sorted({root for row in operations for root in row.get("reads", ())})
        region = {"name": name, "architecture": architecture, "entry": addresses[0],
                  "end": addresses[-1] + block.records[-1]["size"],
                  "reasons": sorted(set(reasons)), "instruction_count": len(operations),
                  "instructions": operations, "state_inputs": inputs,
                  "state_contract": "original_machine_state_required",
                  "source_semantics_complete": False, "terminal": terminal["opcode"],
                  "target": target}
        regions.append(region)
        # This marker has no C-call semantics. The renderer labels it as a
        # retained machine region, whose execution cannot be modeled by the
        # inferred C parameters alone (including hidden register/stack state).
        block.statements = [Statement("machine_region", Value("string", name=name), address=block.address)]
        block.successors, block.predicate, block.terminal = (), None, "machine_region"
    if regions:
        remaining = reachable(blocks, entry)
        blocks.clear()
        blocks.update(remaining)
    return regions


def region_text(statement, indent=""):
    return indent + f'__machine_state_region__({statement.value.name}); /* 未恢复；保留原始机器状态语义，非 C 调用 */'
