"""Page saved microcode only; query paths never dispatch analysis work."""
from __future__ import annotations

from copy import deepcopy
from collections.abc import Mapping


def microcode_page(snapshot: Mapping, address: int, *, offset: int = 0, limit: int = 100,
                   source: str | None = None, address_space: str | None = None,
                   category: str | None = None) -> dict:
    if type(address) is not int or address < 0:
        raise ValueError("address must be a non-negative integer")
    if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("offset must be non-negative and limit in [1, 1000]")
    for name, value in (("source", source), ("address_space", address_space), ("category", category)):
        if value is not None and (not isinstance(value, str) or (name != "source" and not value)):
            raise ValueError(f"Invalid {name} filter")
    function, context = _select_function(snapshot, address, source, address_space)
    rows = function.get("microcode", [])
    if not rows:
        raise ValueError("Microcode is unavailable for this saved function")
    if category is not None:
        rows = [row for row in rows if row.get("category") == category]
    return {"available": True, "address": function.get("start", function.get("code_offset")),
            "name": function.get("name", ""), "source": context[0], "address_space": context[1],
            "microcode_version": function.get("microcode_version", "1.0"),
            "complete": function.get("microcode_complete", False), "items": deepcopy(rows[offset:offset + limit]),
            "offset": offset, "limit": limit, "total": len(rows),
            "next_offset": offset + limit if offset + limit < len(rows) else None}


def _select_function(snapshot, address, source, address_space):
    from ...snapshot_context import function_context, SPACE_ALIASES
    space = SPACE_ALIASES.get(address_space, address_space)
    matching, interior = [], []
    for function in snapshot.get("functions", []):
        if not isinstance(function, dict):
            continue
        context = function_context(function, snapshot.get("kind", ""))
        if ((source is not None and source != context[0]) or (space is not None and space != context[1])):
            continue
        rows = function.get("microcode", [])
        if function.get("start", function.get("code_offset")) == address:
            matching.append((function, context))
        elif any(row.get("addr", -1) <= address < row.get("addr", -1) + row.get("size", 0) for row in rows):
            interior.append((function, context))
    matching = matching or interior
    if not matching:
        raise ValueError("No saved microcode function at this address")
    if len(matching) != 1:
        raise ValueError("Ambiguous microcode address; specify source and address_space")
    return matching[0]


def microcode_facts_page(snapshot: Mapping, address: int, *, offset: int = 0, limit: int = 100,
                         source: str | None = None, address_space: str | None = None,
                         kind: str | None = None) -> dict:
    if type(address) is not int or address < 0:
        raise ValueError("address must be a non-negative integer")
    if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("offset must be non-negative and limit in [1, 1000]")
    for name, value in (("source", source), ("address_space", address_space), ("kind", kind)):
        if value is not None and (not isinstance(value, str) or (name != "source" and not value)):
            raise ValueError(f"Invalid {name} filter")
    function, context = _select_function(snapshot, address, source, address_space)
    analysis = function.get("microcode_analysis")
    if not isinstance(analysis, dict):
        raise ValueError("Microcode facts are unavailable for this saved function")
    facts = analysis.get("facts", [])
    if kind is not None:
        facts = [fact for fact in facts if fact.get("kind") == kind]
    return {"available": True, "address": function.get("start", function.get("code_offset")),
            "source": context[0], "address_space": context[1], "scope": analysis.get("scope"),
            "categories": deepcopy(analysis.get("categories", {})),
            "unsupported_addresses": deepcopy(analysis.get("unsupported_addresses", [])[:100]),
            "microcode_version": analysis.get("microcode_version", "1.0"),
            "items": deepcopy(facts[offset:offset + limit]), "total": len(facts), "offset": offset,
            "limit": limit, "next_offset": offset + limit if offset + limit < len(facts) else None}
