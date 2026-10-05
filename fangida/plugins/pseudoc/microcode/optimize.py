"""Conservative MBA/opaque-expression simplification in fixed-width IR."""
from __future__ import annotations

from .evaluate import UnknownValue, evaluate_expression
from .ir import IMPURE_OPCODES, Expression, constant


def simplify_expression(expression: Expression | dict, *, _depth: int = 0) -> Expression:
    return _simplify(expression, _depth)[0]


def _simplify(expression: Expression | dict, _depth: int) -> tuple[Expression, bool]:
    """Return the simplified expression together with its ``pure`` property.

    纯度自底向上一次算出（与 Expression.pure 的递归定义相同），避免每层重复遍历子树；
    子表达式未变化时复用原对象（冻结数据类，值相等），否则与原实现一样重建。
    """
    expr = Expression.from_dict(expression) if isinstance(expression, dict) else expression
    if _depth > 64:
        raise ValueError("Micro-expression nesting exceeds limit")
    old_args = expr.args
    if old_args:
        depth = _depth + 1
        results = [_simplify(arg, depth) for arg in old_args]
        args = tuple([result[0] for result in results])
        children_pure = all([result[1] for result in results])
    else:
        args = ()
        children_pure = True
    if not (type(expr) is Expression and type(old_args) is tuple and
            all([new is old for new, old in zip(args, old_args)])):
        expr = Expression(expr.opcode, expr.width, args, expr.value, expr.name, expr.domain)
    pure = expr.opcode not in IMPURE_OPCODES and children_pure
    if expr.domain != "bitvector" or any(arg.domain != "bitvector" for arg in args) or not pure:
        return expr, pure
    # 以下所有返回值都由纯子表达式构成，纯度恒为 True。
    if args and all(arg.opcode == "constant" for arg in args):
        try:
            return constant(int(evaluate_expression(expr)), expr.width), True
        except UnknownValue:
            return expr, True
    if len(args) != 2 or any(arg.width != expr.width for arg in args):
        return expr, True
    left, right = args
    if left == right:
        if expr.opcode in {"xor", "sub"}:
            return constant(0, expr.width), True
        if expr.opcode in {"and", "or"}:
            return left, True
    if right.opcode == "constant":
        if right.value == 0:
            if expr.opcode in {"add", "sub", "or", "xor", "shl", "lshr", "ashr", "rol", "ror"}:
                return left, True
            if expr.opcode in {"and", "mul"}:
                return right, True
        if expr.opcode == "mul" and right.value == 1:
            return left, True
        if right.value == (1 << expr.width) - 1:
            if expr.opcode == "and":
                return left, True
            if expr.opcode == "or":
                return right, True
        if left.opcode == expr.opcode == "xor" and left.args[1] == right:
            return left.args[0], True
        if expr.opcode == "sub" and left.opcode == "add" and left.args[1] == right:
            return left.args[0], True
    # (x & y) + (x | y) == x + y modulo 2^width.
    if expr.opcode == "add" and {left.opcode, right.opcode} == {"and", "or"} and left.args == right.args:
        return Expression("add", expr.width, left.args), True
    # The complementary representation x^y + 2*(x&y).
    if expr.opcode == "add":
        for xor, product in ((left, right), (right, left)):
            if xor.opcode == "xor" and product.opcode == "mul":
                conjunction, factor = product.args
                if conjunction.opcode == "and" and conjunction.args == xor.args and factor == constant(2, expr.width):
                    return Expression("add", expr.width, xor.args), True
    return expr, True
