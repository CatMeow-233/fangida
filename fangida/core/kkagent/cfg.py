"""Conservative control-flow graph over an already bounded entry window.

The graph contains only instructions reachable from the entry. A missing
instruction, indirect branch, or direct target outside the decoded window is
recorded as a frontier. It never infers a whole-function boundary.
"""
from __future__ import annotations

from typing import Any, Mapping


def build_entry_cfg(instructions: list[dict[str, Any]], entry: int | None,
                    noreturn_targets: Mapping[int, Any] | None = None
                    ) -> tuple[dict[str, Any] | None, set[int]]:
    """Return a bounded CFG plus the addresses reached by its traversal.

    noreturn_targets（可选，调用目标 → 证据）：为空时行为不变；否则对这些目标的无条件
    调用不再顺序落空，并在图的 noreturn_calls 中记录。
    """
    if entry is None or not instructions:
        return None, set()
    by_addr = {ins["addr"]: ins for ins in instructions if ins.get("size", 0) > 0}
    if entry not in by_addr:
        return None, set()
    window_end = max(ins["addr"] + ins["size"] for ins in by_addr.values())
    leaders = {entry}
    for ins in by_addr.values():
        branch = ins.get("branch_info") or {}
        kind = branch.get("kind")
        if kind not in {"jump", "return", "trap"}:
            continue
        if kind == "jump" and branch.get("target") in by_addr:
            leaders.add(branch["target"])
        if branch.get("conditional") and ins["addr"] + ins["size"] in by_addr:
            leaders.add(ins["addr"] + ins["size"])

    blocks: dict[int, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    frontier: list[dict[str, Any]] = []
    noreturn_calls: list[dict[str, Any]] | None = [] if noreturn_targets else None
    reached: set[int] = set()
    queue = [entry]
    queued = {entry}

    def add_edge(source: int, target: int | None, kind: str) -> None:
        if target is None:
            frontier.append({"from": source, "to": None, "reason": "indirect_jump"})
        elif target not in by_addr:
            reason = "outside_window" if target < entry or target >= window_end else "not_instruction_boundary"
            frontier.append({"from": source, "to": target, "reason": reason})
        else:
            edges.append({"src": source, "dst": target, "kind": kind})
            if target not in queued:
                queued.add(target)
                queue.append(target)

    while queue:
        start = queue.pop(0)
        if start in blocks:
            continue
        block: dict[str, Any] = {"start": start, "instructions": [], "successors": []}
        blocks[start] = block
        cursor = start
        while True:
            ins = by_addr.get(cursor)
            if ins is None:
                frontier.append({"from": block["instructions"][-1]["addr"] if block["instructions"] else start,
                                 "to": cursor, "reason": "undecoded"})
                break
            if cursor != start and cursor in leaders:
                add_edge(block["instructions"][-1]["addr"], cursor, "fallthrough")
                break
            if cursor in reached:
                # A decoded instruction cannot belong to two basic blocks.
                frontier.append({"from": block["instructions"][-1]["addr"] if block["instructions"] else start,
                                 "to": cursor, "reason": "overlapping_blocks"})
                break
            reached.add(cursor)
            block["instructions"].append(ins)
            branch = ins.get("branch_info") or {}
            kind = branch.get("kind")
            next_addr = cursor + ins["size"]
            if kind in {"return", "trap"}:
                # 条件返回（处理器给出 conditional=True 时）在条件不成立时顺序执行。
                if branch.get("conditional"):
                    add_edge(cursor, next_addr, "fallthrough")
                break
            if kind == "jump":
                add_edge(cursor, branch.get("target"), "branch")
                if branch.get("conditional"):
                    add_edge(cursor, next_addr, "fallthrough")
                break
            # Calls are interprocedural xrefs. The intraprocedural path
            # continues on the conventional assumption that the call returns.
            if (kind == "call" and noreturn_calls is not None and not branch.get("conditional")
                    and type(branch.get("target")) is int and branch["target"] in noreturn_targets):
                evidence = noreturn_targets[branch["target"]]
                record = {
                    "from": cursor, "fallthrough": next_addr, "target": branch["target"],
                    "name": evidence.get("name") if isinstance(evidence, dict) else evidence,
                    "evidence": (evidence.get("evidence", "noreturn") if isinstance(evidence, dict)
                                 else "noreturn")}
                noreturn_calls.append(record)
                following = by_addr.get(next_addr)
                if following is None or (following.get("branch_info") or {}).get("kind") != "trap":
                    break
                # 落空目标本身是陷阱（不返回调用之后的 ud2/brk #1/int3）：照常保留，陷阱即终点，
                # 不会多吸入代码。新增字段 fallthrough_trap 缺省表示 False。
                record["fallthrough_trap"] = True
            if next_addr not in by_addr:
                frontier.append({"from": cursor, "to": next_addr, "reason": "outside_window"
                                 if next_addr >= window_end else "undecoded"})
                break
            cursor = next_addr

    for block in blocks.values():
        last = block["instructions"][-1]["addr"] if block["instructions"] else None
        block["successors"] = sorted({edge["dst"] for edge in edges if edge["src"] == last})
    graph = {"scope": "bounded_entry_window", "entry": entry,
             "window_end": window_end, "complete": not frontier,
             "boundary_known": False, "blocks": [blocks[key] for key in sorted(blocks)],
             "edges": edges, "frontier": frontier,
             "assumptions": ["Calls may return to the next instruction"]}
    if noreturn_calls is not None:
        graph["assumptions"].append(
            "Unconditional calls to known non-returning targets do not fall through")
        graph["noreturn_calls"] = noreturn_calls
    return graph, reached
