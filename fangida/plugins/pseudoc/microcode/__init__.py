"""Public typed microcode API; consumes completed instruction snapshots only."""
from __future__ import annotations

from .analysis import analyze_microcode
from .conditions import Condition, ComparisonOrigin, condition, evaluate_condition
from .evaluate import UnknownValue, evaluate_expression, floating_flags, integer_flags, signed
from .ir import CATEGORIES, MICROCODE_VERSION, Expression, MicroOperation, LiftedInstruction, constant
from .optimize import simplify_expression


def lift_instruction(instruction, architecture):
    from ..native import _Renderer
    if architecture not in {"x86", "x86_64", "arm", "arm64"}:
        raise ValueError(f"No native semantic lifter for {architecture}")
    renderer = _Renderer({"start": instruction["addr"]}, architecture, [instruction])
    renderer.statement(instruction)
    return renderer.microcode[0]


def lift_function(function, architecture, *, max_instructions=512):
    from ..models import validate_limits
    from ..native import _Renderer, _snapshot
    validate_limits(max_instructions, 32768)
    if architecture not in {"x86", "x86_64", "arm", "arm64"}:
        raise ValueError(f"No native semantic lifter for {architecture}")
    rows, limited = _snapshot(function, max_instructions)
    if not rows:
        return {"instructions": [], "truncated": bool(function.get("cfg", {}).get("frontier")), "microcode_version": MICROCODE_VERSION}
    renderer = _Renderer(function, architecture, rows)
    renderer.render(limited)
    return {"instructions": renderer.microcode,
            "truncated": limited or renderer.incomplete or bool(function.get("cfg", {}).get("frontier")) or
                         function.get("cfg", {}).get("complete") is False,
            "microcode_version": MICROCODE_VERSION}


def register_lifter(name, handler, *, first=False):
    from .registry import DEFAULT_LIFTERS
    DEFAULT_LIFTERS.register(name, handler, first=first)


def list_lifters():
    from .registry import DEFAULT_LIFTERS
    return DEFAULT_LIFTERS.names()


__all__ = ["MICROCODE_VERSION", "CATEGORIES", "Expression", "MicroOperation", "LiftedInstruction",
           "Condition", "ComparisonOrigin", "constant", "signed", "UnknownValue", "lift_instruction",
           "lift_function", "register_lifter", "list_lifters", "evaluate_expression", "integer_flags",
           "floating_flags", "evaluate_condition", "condition", "simplify_expression", "analyze_microcode"]
