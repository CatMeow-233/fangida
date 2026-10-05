"""Condition codes with signedness, comparison provenance and IEEE unordered cases."""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from collections.abc import Mapping
from functools import lru_cache
from typing import Any

from .evaluate import floating_flags, integer_flags

X86_CONDITIONS = {
    "e": "flags.ZF", "z": "flags.ZF", "ne": "!flags.ZF", "nz": "!flags.ZF",
    "a": "!flags.CF && !flags.ZF", "nbe": "!flags.CF && !flags.ZF",
    "ae": "!flags.CF", "nb": "!flags.CF", "nc": "!flags.CF",
    "b": "flags.CF", "c": "flags.CF", "nae": "flags.CF",
    "be": "flags.CF || flags.ZF", "na": "flags.CF || flags.ZF",
    "g": "!flags.ZF && flags.SF == flags.OF", "nle": "!flags.ZF && flags.SF == flags.OF",
    "ge": "flags.SF == flags.OF", "nl": "flags.SF == flags.OF",
    "l": "flags.SF != flags.OF", "nge": "flags.SF != flags.OF",
    "le": "flags.ZF || flags.SF != flags.OF", "ng": "flags.ZF || flags.SF != flags.OF",
    "s": "flags.SF", "ns": "!flags.SF", "o": "flags.OF", "no": "!flags.OF",
    "p": "flags.PF", "pe": "flags.PF", "np": "!flags.PF", "po": "!flags.PF",
}
ARM_CONDITIONS = {"eq": "flags.Z", "ne": "!flags.Z", "cs": "flags.C", "hs": "flags.C",
    "cc": "!flags.C", "lo": "!flags.C", "mi": "flags.N", "pl": "!flags.N",
    "vs": "flags.V", "vc": "!flags.V", "hi": "flags.C && !flags.Z",
    "ls": "!flags.C || flags.Z", "ge": "flags.N == flags.V", "lt": "flags.N != flags.V",
    "gt": "!flags.Z && flags.N == flags.V", "le": "flags.Z || flags.N != flags.V"}

INTEGER_RELATIONS = {
    "x86": {**{code: ("bitvector", "eq") for code in ("e", "z")},
        **{code: ("bitvector", "ne") for code in ("ne", "nz")},
        **{code: ("unsigned", "gt") for code in ("a", "nbe")},
        **{code: ("unsigned", "ge") for code in ("ae", "nb", "nc")},
        **{code: ("unsigned", "lt") for code in ("b", "c", "nae")},
        **{code: ("unsigned", "le") for code in ("be", "na")},
        **{code: ("signed", "gt") for code in ("g", "nle")},
        **{code: ("signed", "ge") for code in ("ge", "nl")},
        **{code: ("signed", "lt") for code in ("l", "nge")},
        **{code: ("signed", "le") for code in ("le", "ng")}},
    "arm": {"eq": ("bitvector", "eq"), "ne": ("bitvector", "ne"),
        "hi": ("unsigned", "gt"), "hs": ("unsigned", "ge"), "cs": ("unsigned", "ge"),
        "lo": ("unsigned", "lt"), "cc": ("unsigned", "lt"), "ls": ("unsigned", "le"),
        "gt": ("signed", "gt"), "ge": ("signed", "ge"), "lt": ("signed", "lt"), "le": ("signed", "le")},
}
FP_RELATIONS = {
    "x86": {"a": ("gt", False), "nbe": ("gt", False), "ae": ("ge", False), "nb": ("ge", False),
        "nc": ("ge", False), "b": ("lt", True), "c": ("lt", True), "nae": ("lt", True),
        "be": ("le", True), "na": ("le", True), "e": ("eq", True), "z": ("eq", True),
        "ne": ("ne", False), "nz": ("ne", False), "p": ("unordered", True), "pe": ("unordered", True),
        "np": ("ordered", False), "po": ("ordered", False)},
    "arm": {"eq": ("eq", False), "ne": ("ne", True), "hi": ("gt", True), "ls": ("le", False),
        "hs": ("ge", True), "cs": ("ge", True), "lo": ("lt", False), "cc": ("lt", False),
        "mi": ("lt", False), "pl": ("ge", True), "gt": ("gt", False), "ge": ("ge", False),
        "lt": ("lt", True), "le": ("le", True), "vs": ("unordered", True), "vc": ("ordered", False)},
}


@dataclass(frozen=True)
class ComparisonOrigin:
    addr: int
    family: str
    width: int
    domain: str
    left: str
    right: str


@dataclass(frozen=True)
class Condition:
    family: str
    code: str
    domain: str = "flags"
    width: int = 0
    relation: str = "flags"
    origin: int | None = None
    unordered: bool = False
    captured_left: str = ""
    captured_right: str = ""

    def to_dict(self) -> dict[str, Any]:
        return dict(vars(self))

    def render(self) -> str:
        formula = (X86_CONDITIONS if self.family == "x86" else ARM_CONDITIONS).get(self.code)
        if formula is None:
            raise ValueError(f"Unsupported condition code: {self.code}")
        if self.origin is None or self.relation == "flags":
            return formula
        left, right = self.captured_left, self.captured_right
        if self.domain == "floating":
            unordered = f"isunordered({left}, {right})"
            if self.relation == "unordered":
                return unordered
            if self.relation == "ordered":
                return f"!{unordered}"
            operator = {"eq": "==", "ne": "!=", "gt": ">", "ge": ">=", "lt": "<", "le": "<="}[self.relation]
            clause = f"{left} {operator} {right}"
            # != is true for NaN in C; explicitly constrain ordered comparisons.
            return f"({unordered} || {clause})" if self.unordered else f"(!{unordered} && {clause})"
        cast = ("int" if self.domain == "signed" else "uint") + str(self.width) + "_t"
        operator = {"eq": "==", "ne": "!=", "gt": ">", "ge": ">=", "lt": "<", "le": "<="}[self.relation]
        return f"({cast}){left} {operator} ({cast}){right}"


def condition(family: str, code: str, origin: ComparisonOrigin | None = None) -> Condition:
    table = X86_CONDITIONS if family == "x86" else ARM_CONDITIONS if family == "arm" else {}
    if code not in table:
        raise ValueError(f"Unsupported {family} condition code: {code}")
    if origin is None or origin.family != family:
        return Condition(family, code)
    relation = FP_RELATIONS[family].get(code) if origin.domain == "floating" else INTEGER_RELATIONS[family].get(code)
    if relation is None:
        return Condition(family, code, origin.domain, origin.width, origin=origin.addr)
    domain, comparison, unordered = (("floating", relation[0], relation[1]) if origin.domain == "floating"
                                      else (relation[0], relation[1], False))
    return Condition(family, code, domain, origin.width, comparison, origin.addr,
                     unordered, origin.left, origin.right)


def evaluate_condition(predicate: Condition | Mapping[str, Any], *,
                       flags: Mapping[str, bool | None] | None = None,
                       left: int | float | None = None, right: int | float | None = None,
                       width: int | None = None, domain: str | None = None) -> bool | None:
    pred = predicate if isinstance(predicate, Condition) else Condition(**dict(predicate))
    if flags is None:
        if left is None or right is None:
            return None
        value_domain = domain or pred.domain
        if value_domain == "floating":
            flags = floating_flags(pred.family, float(left), float(right))
        else:
            value_width = width or pred.width
            if not value_width:
                raise ValueError("A comparison width is required")
            flags = integer_flags(pred.family, "sub", int(left), int(right), value_width)
    formula = (X86_CONDITIONS if pred.family == "x86" else ARM_CONDITIONS).get(pred.code)
    if formula is None:
        raise ValueError("Unknown condition code")
    # 公式文本 -> 语法树只解析一次；树只读遍历，按公式文本缓存是纯函数。
    tree = _parse_formula(formula) if type(formula) is str else _parse_formula_uncached(formula)
    return _evaluate_flag_node(tree.body, flags)


_NEGATION = re.compile(r"!(?!=)")


def _parse_formula_uncached(formula):
    code = _NEGATION.sub("not ", formula).replace("&&", " and ").replace("||", " or ")
    return ast.parse(code.strip(), mode="eval")


_parse_formula = lru_cache(maxsize=256)(_parse_formula_uncached)


def _evaluate_flag_node(node, flags):
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "flags":
        value = flags.get(node.attr)
        return None if value is None else bool(value)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        value = _evaluate_flag_node(node.operand, flags)
        return None if value is None else not value
    if isinstance(node, ast.BoolOp):
        values = [_evaluate_flag_node(value, flags) for value in node.values]
        if isinstance(node.op, ast.And):
            return False if False in values else None if None in values else True
        return True if True in values else None if None in values else False
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        left_value, right_value = _evaluate_flag_node(node.left, flags), _evaluate_flag_node(node.comparators[0], flags)
        if left_value is None or right_value is None:
            return None
        return left_value == right_value if isinstance(node.ops[0], ast.Eq) else left_value != right_value
    raise ValueError("Invalid flag expression")
