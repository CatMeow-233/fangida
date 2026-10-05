"""Conservative simplification of a completely discovered CFG.

Preconditions for treating the returned view as a sound CFG:

* Every block has a unique integer ``start`` and a complete list of explicit
  integer ``successors``. ``entry`` names a known block.
* There are no incoming references to removable blocks outside these edges
  (such as address-taken labels, exception handlers, or indirect jumps).
* An instruction represented as an unconditional direct jump has no effects
  other than changing control flow. The decoder must supply accurate effects.

The function checks the structural facts it can prove and bypasses only a
one-instruction block whose branch target agrees with its sole successor.
It does not infer an obfuscated dispatcher's state or rewrite binary bytes.
The original block map remains in the result so clients can inspect evidence.
"""
from __future__ import annotations

from copy import deepcopy
import json
from typing import Any, Mapping, Sequence


MAX_BLOCKS = 10000


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _transparent_target(block: Mapping[str, Any]) -> int | None:
    instructions = block.get("instructions")
    successors = block.get("successors")
    if not isinstance(instructions, list) or len(instructions) != 1:
        return None
    if not isinstance(successors, list) or len(successors) != 1:
        return None
    instruction = instructions[0]
    if not isinstance(instruction, dict):
        return None
    branch = instruction.get("branch_info")
    target = successors[0]
    if not isinstance(branch, dict) or not _is_int(target):
        return None
    if branch.get("kind") != "jump" or branch.get("conditional") is not False:
        return None
    if not _is_int(branch.get("target")) or branch["target"] != target:
        return None
    # Require an address-aligned, single-instruction block and no declared
    # register effects. A jump through a register has no known direct target.
    if instruction.get("address", instruction.get("addr")) != block["start"]:
        return None
    if instruction.get("reads") not in ([], ()) or instruction.get("writes") not in ([], ()):
        return None
    return target


def simplify_transparent_dispatchers(
    entry: int, blocks: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    """Return a simplified *view* of direct jump-only CFG blocks.

    ``blocks`` use ``{start, instructions, successors}``, with each instruction
    in Fangida's JSON IR shape. The returned ``blocks`` retain instructions and
    carry rewritten successors; ``original_blocks`` preserve the input graph.
    A self-loop or jump-only cycle remains intact. Ambiguous and malformed
    graphs raise ``ValueError`` instead of producing a misleading result.
    """
    if not _is_int(entry):
        raise ValueError("entry must be a nonnegative integer address")
    if isinstance(blocks, (str, bytes)) or not isinstance(blocks, Sequence):
        raise ValueError("blocks must be a sequence")
    if len(blocks) > MAX_BLOCKS:
        raise ValueError(f"CFG exceeds {MAX_BLOCKS} blocks")
    original: list[dict[str, Any]] = []
    by_start: dict[int, dict[str, Any]] = {}
    for block in blocks:
        if not isinstance(block, Mapping):
            raise ValueError("each block must be a mapping")
        start, successors, instructions = (block.get("start"), block.get("successors"),
                                            block.get("instructions"))
        if not _is_int(start) or start in by_start:
            raise ValueError("blocks need unique nonnegative integer starts")
        if not isinstance(successors, list) or any(not _is_int(item) for item in successors):
            raise ValueError("successors must be integer address lists")
        if not isinstance(instructions, list) or any(not isinstance(item, dict) for item in instructions):
            raise ValueError("instructions must be lists of IR objects")
        copied = deepcopy(dict(block))
        original.append(copied)
        by_start[start] = copied
    try:
        json.dumps(original, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("blocks must contain JSON-compatible values") from exc
    if entry not in by_start:
        raise ValueError("entry is not a known block")
    if any(target not in by_start for block in original for target in block["successors"]):
        raise ValueError("all successor targets must name known blocks")

    candidates = {start: target for start, block in by_start.items()
                  if (target := _transparent_target(block)) is not None}

    # Memoize each chain. None marks cycles and every chain leading into them;
    # these addresses must not be bypassed.
    destinations: dict[int, int | None] = {}
    for start in candidates:
        if start in destinations:
            continue
        path: list[int] = []
        positions: set[int] = set()
        current = start
        while current in candidates and current not in destinations and current not in positions:
            path.append(current)
            positions.add(current)
            current = candidates[current]
        destination = (None if current in positions else
                       destinations[current] if current in destinations else current)
        for address in path:
            destinations[address] = destination
    redirected = {start: (destination if (destination := destinations.get(start)) is not None else start)
                  for start in by_start}
    removed = {start for start in candidates if redirected[start] != start}
    simplified = []
    for block in original:
        if block["start"] in removed:
            continue
        updated = deepcopy(block)
        updated["successors"] = list(dict.fromkeys(redirected[target] for target in block["successors"]))
        simplified.append(updated)
    return {
        "entry": redirected[entry],
        "blocks": simplified,
        "original_blocks": original,
        "bypassed": [{"start": start, "target": redirected[start]} for start in sorted(removed)],
        "limitations": ["Requires complete CFG edges and no external references to bypassed addresses",
                        "Does not resolve state-based dispatchers or indirect branches"],
    }
