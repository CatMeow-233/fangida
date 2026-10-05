"""源码可读性整理：常量折叠、字符串/函数地址还原、可变参数定数、去冗余转换。

全部在常量传播与死代码删除（dataflow.optimize）之后、结构化之前进行，只做与 C
语义等价的改写：
- 常量折叠按表达式宽度做模运算；只读字符串地址换成字面量（地址相同）。
- 可变参数个数只在格式串可完整解析时确定，否则保留 unknown_arguments()。
- 只删除“值不变”的类型转换：赋值/返回时的隐式转换与显式转换在 C 中相同；
  同宽度符号重解释、先扩展再截回等组合按位等价。
- 被丢弃的调用结果只去掉外层转换与“高位未知”包装，调用本身（副作用）保留。
"""
from __future__ import annotations

import re

from .model import Value
from .prototypes import format_arguments, printf_int_arguments
from .types import integer_type

_INTEGER = re.compile(r"(u?)int(8|16|32|64)_t")
_FOLDABLE = frozenset({"add", "sub", "mul", "and", "or", "xor", "shl", "lshr"})


_INTEGER_INFO = {}


def integer_info(ctype, bits=64):
    """(是否有符号, 宽度)；不是已知整数类型时返回 None。结果按 (类型, 位宽) 缓存。"""
    key = (ctype, bits)
    try:
        return _INTEGER_INFO[key]
    except KeyError:
        pass
    except TypeError:
        return _integer_info(ctype, bits)
    result = _INTEGER_INFO[key] = _integer_info(ctype, bits)
    if len(_INTEGER_INFO) > 4096:
        _INTEGER_INFO.clear()
        _INTEGER_INFO[key] = result
    return result


def _integer_info(ctype, bits):
    if ctype == "bool":
        return False, 1
    match = _INTEGER.fullmatch(ctype or "")
    if match:
        return not match.group(1), int(match.group(2))
    if ctype in {"size_t", "uintptr_t"}:
        return False, bits
    return None


def preserving(source, target, bits=64):
    """source 类型的每个值都能被 target 类型精确表示（整数之间）。"""
    left, right = integer_info(source, bits), integer_info(target, bits)
    if left is None or right is None:
        return False
    (signed_source, width_source), (signed_target, width_target) = left, right
    if not signed_source:
        return width_target > width_source or width_target == width_source and not signed_target
    return signed_target and width_target >= width_source


_UNTYPED_INTEGER_OPS = frozenset({"select", "add", "sub", "mul", "and", "or", "xor", "shl", "lshr", "neg", "not", "constant"})


def value_type(value):
    """值的 C 类型；少数构造时未记类型的整数运算按其宽度视为无符号整数。"""
    if value.ctype:
        return value.ctype
    if value.op in _UNTYPED_INTEGER_OPS and value.width in {8, 16, 32, 64}:
        return integer_type(value.width)
    return ""


def _mask(width):
    return (1 << width) - 1 if width else 0


def _constant(number, width, ctype):
    ctype = ctype if integer_info(ctype) else integer_type(width)
    number &= _mask(width)
    if ctype.startswith("int") and width and number & (1 << (width - 1)):
        number -= 1 << width
    return Value("constant", width, number=number, ctype=ctype)


def _int_constant(value):
    return value.op == "constant" and type(value.number) is int


class Rewriter:
    """按实例缓存的自底向上改写（Value 不可变，相同子树只处理一次）。

    leaves：这些操作的无参数节点原样返回（不进入 visit，也不占缓存）。
    context 只区分真/假两种（如“是否处在访存地址里”）。
    """
    __slots__ = ("visit", "cache", "context_cache", "leaves")

    def __init__(self, visit, leaves=frozenset()):
        self.visit, self.cache, self.context_cache, self.leaves = visit, {}, {}, leaves

    def __call__(self, value, context=None):
        if value is None:
            return None
        if not value.args and value.op in self.leaves:
            return value
        cache = self.context_cache if context else self.cache
        cached = cache.get(id(value))
        if cached is not None and cached[0] is value:
            return cached[1]
        result = self.visit(self, value, context)
        cache[id(value)] = (value, result)
        return result


# 改写时永远不变的叶子（常量单独处理：折叠/字面量还原需要看到它们）。
# PE 的 UTF-16LE 宽字符串字面量的类型（伪 C 中写成 L"..."）。
WIDE_STRING_TYPE = "const wchar_t *"
_STABLE_LEAVES = frozenset({"variable", "unknown", "string", "string_literal", "function", "global", "slot_access"})
_ALL_LEAVES = _STABLE_LEAVES | {"constant", "float_constant"}


def _rebuild(value, args):
    for new, old in zip(args, value.args):  # 显式循环比 all(生成器) 快：每个函数的每次改写都经过这里
        if new is not old:
            break
    else:
        return value
    return Value(value.op, value.width, tuple(args), value.name, value.number, value.ctype, value.effect)


# ---------------------------------------------------------------------------
# 常量折叠与数据地址还原
# ---------------------------------------------------------------------------

def fold(value):
    """只折叠参数全是整数常量的节点；结果按节点宽度取模。"""
    op, args = value.op, value.args
    if op in _FOLDABLE and len(args) == 2 and all(map(_int_constant, args)) and value.width:
        left, right = args[0].number & _mask(value.width), args[1].number & _mask(value.width)
        if op in {"shl", "lshr"} and right >= value.width:
            return value
        number = {"add": lambda: left + right, "sub": lambda: left - right, "mul": lambda: left * right,
                  "and": lambda: left & right, "or": lambda: left | right, "xor": lambda: left ^ right,
                  "shl": lambda: left << right, "lshr": lambda: left >> right}[op]()
        return _constant(number, value.width, value.ctype)
    if op in {"add", "sub"} and len(args) == 2 and _int_constant(args[1]) and args[0].op in {"add", "sub"} and \
            len(args[0].args) == 2 and _int_constant(args[0].args[1]) and args[0].width == value.width and value.width:
        # (x ± c1) ± c2 → x ± (c1 ± c2)：同宽度模运算下结合律成立。
        inner = args[0]
        total = (inner.args[1].number if inner.op == "add" else -inner.args[1].number) + (
            args[1].number if op == "add" else -args[1].number)
        total &= _mask(value.width)
        if total == 0 and value_type(inner.args[0]) == value_type(value):
            return inner.args[0]
        return Value("add", value.width, (inner.args[0], _constant(total, value.width, args[1].ctype)),
                     value.name, value.number, value.ctype, value.effect)
    if op in {"and", "or", "xor"} and len(args) == 2 and _int_constant(args[1]) and args[0].op == op and \
            len(args[0].args) == 2 and _int_constant(args[0].args[1]) and args[0].width == value.width and value.width:
        # (x & c1) & c2 → x & (c1 & c2)；| 与 ^ 同理（同宽度按位运算满足结合律）。
        inner = args[0]
        first, second = inner.args[1].number, args[1].number
        combined = (first & second if op == "and" else first | second if op == "or" else first ^ second) & _mask(value.width)
        return fold(Value(op, value.width, (inner.args[0], _constant(combined, value.width, args[1].ctype)),
                          value.name, value.number, value.ctype, value.effect))
    if op in _FOLDABLE and len(args) == 2 and value.width:
        left, right = args
        identity = _identity(op, left, right, value)
        if identity is not None:
            return identity
    if op in {"neg", "not"} and len(args) == 1 and _int_constant(args[0]) and value.width:
        number = -args[0].number if op == "neg" else ~args[0].number
        return _constant(number, value.width, value.ctype)
    if op == "cast" and args and _int_constant(args[0]) and "*" not in value.ctype and integer_info(value.ctype):
        return _constant(args[0].number, value.width, value.ctype)
    if op == "select" and len(args) == 3 and args[1] == args[2] and args[0].pure and args[1].pure:
        return args[1]
    return value


def _as_type(value, ctype, width):
    if not ctype or value_type(value) == ctype:
        return value
    return Value("cast", width, (value,), ctype=ctype)


def _identity(op, left, right, value):
    """x|0、x^0、x+0、x-0、x*1、x<<0、x&全1 → x；x&0、x*0 → 0（被丢弃的一侧必须没有副作用）。"""
    mask = _mask(value.width)
    ctype = value.ctype or value_type(value)
    for operand, other, side in ((right, left, "right"), (left, right, "left")):
        if not _int_constant(operand):
            continue
        number = operand.number & mask
        if number == 0 and (op in {"or", "xor", "add"} or op in {"sub", "shl", "lshr"} and side == "right"):
            return _as_type(other, ctype, value.width)
        if number == 1 and op == "mul":
            return _as_type(other, ctype, value.width)
        if number == mask and op == "and":
            return _as_type(other, ctype, value.width)
        if number == 0 and op in {"and", "mul"} and other.pure:
            return _constant(0, value.width, ctype)
    return None


def _integer_parameters(name):
    from .prototypes import lookup
    from .types import valid_type
    prototype = lookup(name)
    if prototype is None:
        return frozenset()
    return frozenset(index for index, (_, ctype) in enumerate(prototype.parameters)
                     if integer_info(valid_type(ctype, ""), 64) or ctype == "long")


def fold_and_resolve(blocks, references, bits):
    """折叠常量；非访存地址位置上的指针宽度常量若指向只读字符串/已命名函数则换成字面量/名字。"""
    lookups = {}

    def describe(number):
        if number not in lookups:
            try:
                lookups[number] = references.get(number) if references is not None else None
            except Exception:
                lookups[number] = None
        return lookups[number]

    def visit(rewrite, value, address):
        if not value.has_constants:
            return value  # 没有常量：既不能折叠，也没有可还原的地址
        op = value.op
        if op == "load":
            args = (rewrite(value.args[0], True),)
        elif op == "index":
            args = (rewrite(value.args[0], True), rewrite(value.args[1], False))
        elif op == "store":
            args = (rewrite(value.args[0], False), rewrite(value.args[1], False))
        elif op == "call" and value.args:
            # 已知原型里声明为整数的形参（大小、标志…）不是地址：不在这些位置还原字面量。
            integers = _integer_parameters(value.name)
            args = tuple(rewrite(arg, index in integers) for index, arg in enumerate(value.args))
        else:
            args = tuple([rewrite(arg, False) for arg in value.args])
        value = fold(_rebuild(value, args))
        if (value.op == "constant" and not address and type(value.number) is int and value.number >= 0x1000
                and value.width >= 32 and references is not None):
            found = describe(value.number)
            if isinstance(found, dict):
                replacement = None
                if found.get("kind") == "string" and isinstance(found.get("value"), str):
                    wide = found.get("encoding") == "utf-16le"
                    replacement = Value("string_literal", bits, name=found["value"], number=value.number,
                                        ctype=WIDE_STRING_TYPE if wide else "const char *")
                elif found.get("kind") == "function" and isinstance(found.get("name"), str) and value.number >= 0x10000:
                    # 低地址的代码位置容易与普通整数常量（4096、0x2000…）重合，只对较大的地址还原函数名。
                    from ..native_operands import identifier
                    replacement = Value("function", bits, name=identifier(found["name"]), number=value.number, ctype="void *")
                if replacement is not None:
                    # 保留原常量的整数类型：(uint64_t)"..." 与原常量逐位相同；指针类型的变量/形参处再去掉。
                    if integer_info(value.ctype, bits):
                        return Value("cast", value.width, (replacement,), ctype=value.ctype)
                    return replacement
        if value.op == "cast" and "*" in value.ctype and value.ctype.replace(" ", "").endswith("char*"):
            # (const char *)"..." 与 (const char *)(uint64_t)"..."（指针宽度整数中转）都不改变地址，只保留字面量。
            inner = value.args[0]
            while inner.op == "cast" and inner.width == bits and (integer_info(inner.ctype, bits) or ("*" in inner.ctype)):
                inner = inner.args[0]
            if _literal_like(inner, bits) and not _wide_literal(inner, bits):
                return literal_value(inner, bits)
        return value

    rewrite = Rewriter(visit, _STABLE_LEAVES)
    changed = False
    for block in blocks.values():
        for statement in block.statements:
            if statement.value is not None:
                new = rewrite(statement.value, False)
                if new is not statement.value:
                    statement.value, changed = new, True
        if block.predicate is not None:
            new = rewrite(block.predicate, False)
            if new is not block.predicate:
                block.predicate, changed = new, True
    return changed


# ---------------------------------------------------------------------------
# 可变参数
# ---------------------------------------------------------------------------

def _strip_integer_casts(value, bits):
    """去掉一串转为整数（至少 32 位）或指针的转换；返回 (内层值, 这些转换里的最小宽度)。"""
    width = bits
    while value.op == "cast":
        if _is_pointer(value.ctype):
            value = value.args[0]
            continue
        info = integer_info(value.ctype, bits)
        if info is None or info[1] < 32:
            break
        width = min(width, info[1])
        value = value.args[0]
    return value, width


def _literal_like(value, bits=64, width=None):
    """字符串字面量（外层整数转换不截断其地址），或两臂都是这样的字面量的条件表达式。"""
    inner, narrowest = _strip_integer_casts(value, bits)
    narrowest = min(narrowest, width or bits)
    if inner.op in {"string_literal", "function"} and inner.number is not None:
        # 转成窄于指针的整数只在地址本身放得下时才不改变值（如 x86-64 非 PIE 的 32 位地址立即数）。
        return narrowest >= bits or type(inner.number) is int and 0 <= inner.number < 1 << narrowest
    return (inner.op == "select" and len(inner.args) == 3 and _literal_like(inner.args[1], bits, narrowest)
            and _literal_like(inner.args[2], bits, narrowest))


def literal_value(value, bits=64):
    """_literal_like 为真时，去掉其中整数转换后的字面量表达式（地址逐位不变）。"""
    value, _ = _strip_integer_casts(value, bits)
    if value.op == "select":
        return Value("select", value.width, (value.args[0], literal_value(value.args[1], bits), literal_value(value.args[2], bits)),
                     value.name, value.number, "const char *", value.effect)
    return value


def _wide_literal(value, bits=64):
    """表达式里含宽字符串字面量（L"..."）。"""
    inner, _ = _strip_integer_casts(value, bits)
    if inner.op == "select" and len(inner.args) == 3:
        return _wide_literal(inner.args[1], bits) or _wide_literal(inner.args[2], bits)
    return inner.op == "string_literal" and inner.ctype == WIDE_STRING_TYPE


def _literal(value):
    while value.op == "cast":
        value = value.args[0]
    # 格式串只按窄字符串解析；宽字符串不参与 printf 系列的实参计数。
    return value.name if value.op == "string_literal" and value.ctype != WIDE_STRING_TYPE else None


def _has_variadic(value):
    pending = [value]
    while pending:
        item = pending.pop()
        if item.op == "variadic":
            return True
        if item.op == "call" or item.op == "cast" or item.op == "store":
            pending.extend(item.args)
    return False


def resolve_variadic(blocks, calls, unresolved, abi, variadic_on_stack=False):
    """把 restore_call 留下的可变参数占位换成具体实参；无法确定个数时换成 unknown_arguments()。"""
    evidence = {item.get("address"): item for item in calls if isinstance(item, dict)}
    resolved_addresses = set()
    word = abi.word * 8

    def visit(rewrite, value, _):
        args = tuple(rewrite(arg) for arg in value.args)
        value = _rebuild(value, args)
        if value.op != "call" or not any(arg.op == "variadic" for arg in value.args):
            return value
        index = next(position for position, arg in enumerate(value.args) if arg.op == "variadic")
        marker, fixed = value.args[index], list(value.args[:index])
        at = marker.args[0].number if marker.args and _int_constant(marker.args[0]) else None
        candidates = list(marker.args[1:])
        count = None
        format_index = marker.number if type(marker.number) is int else -1
        # tail_transfer(target, ...) 的首个实参是目标本身。
        offset = 1 if value.name == "tail_transfer" else 0
        if 0 <= format_index and format_index + offset < len(fixed):
            text = _literal(fixed[format_index + offset])
            counts = format_arguments(text, marker.name or "printf") if text is not None else None
            if counts is not None and (counts[1] == 0 or variadic_on_stack):
                count = counts[0] + counts[1]
        tail = Value("call", word, name="unknown_arguments")
        if count is not None and count <= len(candidates) and not any(item.op == "unknown" for item in candidates[:count]):
            arguments = fixed + candidates[:count]
            item = evidence.get(at)
            if item is not None:
                item.update(argument_count_known=True, recovered_argument_count=len(arguments) - offset,
                            variadic_argument_count=count)
                resolved_addresses.add(at)
        else:
            arguments = fixed + [tail]
        return Value(value.op, value.width, tuple(arguments), value.name, value.number, value.ctype, value.effect)

    rewrite = Rewriter(lambda rewrite, value, context: visit(rewrite, value, context), _ALL_LEAVES)
    changed = False
    for block in blocks.values():
        for statement in block.statements:
            # 占位只出现在调用里；先用一次廉价的扫描跳过没有占位的语句。
            if statement.value is not None and _has_variadic(statement.value):
                new = rewrite(statement.value)
                if new is not statement.value:
                    statement.value, changed = new, True
        if block.predicate is not None and _has_variadic(block.predicate):
            block.predicate = rewrite(block.predicate)
    if resolved_addresses:
        unresolved[:] = [item for item in unresolved if not (
            item.get("kind") == "call_signature" and item.get("address") in resolved_addresses)]
    return changed


# ---------------------------------------------------------------------------
# 去冗余转换
# ---------------------------------------------------------------------------

def _strip_int_argument(value, bits):
    """去掉按 int 读取的可变实参外层到 ≥32 位整数的转换（内层仍是整数时）。"""
    current = value
    while current.op == "cast" and current.args:
        info = integer_info(current.ctype, bits)
        inner = current.args[0]
        if info is None or info[1] < 32 or integer_info(value_type(inner), bits) is None:
            break
        current = inner
    return current


def _upper_wrapper(value):
    match = re.fullmatch(r"unknown_return_upper(8|16|32)", value.name) if value.op == "call" else None
    return int(match.group(1)) if match and len(value.args) == 1 else None


def simplify_value(value, bits=64, rewriter=None):
    """表达式内部的等价化简（不依赖所在语句）。rewriter 可在同一函数的多条语句间共享缓存。"""
    return (rewriter or simplifier(bits))(value)


def simplifier(bits=64):
    def visit(rewrite, value, _):
        value = _rebuild(value, [rewrite(arg) for arg in value.args])
        if value.op == "cast":
            return _simplify_cast(value, bits)
        if value.op == "compare" and value.name in {"==", "!="}:
            return _simplify_equality(value, bits)
        if value.op == "logical_not" and len(value.args) == 1 and value.args[0].op == "compare":
            # !(a != b) → a == b。大小关系只对整数取反（浮点数的 NaN 使 !(a < b) 不等于 a >= b）。
            inner = value.args[0]
            if inner.name in {"==", "!="} or all(integer_info(arg.ctype, bits) for arg in inner.args):
                from .structure import negate
                return negate(inner)
            return value
        if value.op == "load":
            return _index(value, bits)
        if value.op == "index":
            return _index_base(value, bits)
        if value.op == "call":
            return _call_arguments(value, bits)
        return fold(value)

    return Rewriter(visit, _ALL_LEAVES)


def _strip_pointer_integer(value, bits):
    """去掉“指针 → 指针宽度整数”以及指针之间的转换（地址不变），返回最内层指针；不是这种形式时返回 None。"""
    while value.op == "cast" and value.width == bits and (
            (integer_info(value.ctype, bits) or (False, 0))[1] == bits or _is_pointer(value.ctype) and _is_pointer(value.args[0].ctype)):
        value = value.args[0]
    return value if _is_pointer(value.ctype) else None


def _is_pointer(ctype):
    return isinstance(ctype, str) and ctype.endswith("*")


def _pointee(ctype):
    return ctype[:-1].strip()


def _element_size(ctype, bits):
    base = _pointee(ctype)
    if base.startswith("const "):
        base = base[6:]
    if base in {"char", "signed char", "unsigned char", "bool"}:
        return 1
    if _is_pointer(base):
        return bits // 8
    info = integer_info(base, bits)
    if info is not None and info[1] >= 8:
        return info[1] // 8
    return None


def _index(value, bits):
    """*(uintN_t *)((uintptr)p + k*sizeof(*p)) 写成 p[k]（元素宽度与访问宽度相同时）。"""
    if value.width not in {8, 16, 32, 64} or not value.args:
        return value
    address = value.args[0]
    base, displacement, negative = address, None, False
    if address.op in {"add", "sub"} and len(address.args) == 2:
        base, displacement = address.args
        negative = address.op == "sub"
    pointer = _strip_pointer_integer(base, bits)
    if pointer is not None and pointer.op == "cast" and pointer.args and pointer.args[0].op == "constant":
        return value  # 固定地址的读取保持 *(T *)0x... 形式
    if pointer is None or pointer is base and displacement is not None:
        # 已是指针类型的加法按元素计数（不是字节），这里只处理字节地址形式。
        return value
    size = _element_size(pointer.ctype, bits)
    if size is None or size * 8 != value.width:
        return value
    if displacement is None:
        index = Value("constant", bits, number=0, ctype=integer_type(bits))
    elif _int_constant(displacement) and displacement.number % size == 0:
        number = displacement.number
        if number >= 1 << (displacement.width - 1):
            number -= 1 << displacement.width
        index = Value("constant", bits, number=(-number if negative else number) // size, ctype=integer_type(bits, True))
    elif size == 1 and not negative and integer_info(value_type(displacement), bits):
        index = displacement
    else:
        return value
    element_type = _pointee(pointer.ctype)
    target = integer_type(value.width)
    element = Value("index", value.width, (pointer, index), ctype=element_type, effect=value.effect)
    if element_type == target:
        return element
    return Value("cast", value.width, (element,), ctype=target)


def _index_base(value, bits):
    """((P *)q)[k]：q 的元素与 P 等宽时写成 (P)q[k]（同一地址、同样宽度的读取）。"""
    if len(value.args) != 2:
        return value
    base = value.args[0]
    if base.op != "cast" or not _is_pointer(base.ctype):
        return value
    inner = _strip_pointer_integer(base.args[0], bits) if not _is_pointer(base.args[0].ctype) else base.args[0]
    if inner is None or not _is_pointer(inner.ctype) or inner.op == "cast" and inner.args and inner.args[0].op == "constant":
        return value
    size, wanted = _element_size(inner.ctype, bits), _element_size(base.ctype, bits)
    if size is None or size != wanted:
        return value
    element_type = _pointer_type_element(inner.ctype)
    element = Value("index", value.width, (inner, value.args[1]), ctype=element_type, effect=value.effect)
    return element if element_type == value.ctype or not value.ctype else Value("cast", value.width, (element,), ctype=value.ctype)


def _pointer_type_element(ctype):
    return _pointee(ctype)


def _call_arguments(value, bits):
    """已知原型的实参：去掉与形参类型之间的隐式转换；可变参数位置去掉指针⇄指针宽度整数的转换。

    其它调用：字符串字面量实参外的转换（来自对被调函数形参类型的推测）一律去掉，地址不变。
    """
    from .prototypes import lookup
    prototype = lookup(value.name)
    if prototype is None:
        if any(arg.op == "cast" and _literal_like(arg, bits) for arg in value.args):
            return _rebuild(value, [literal_value(arg, bits) if arg.op == "cast" and _literal_like(arg, bits) else arg
                                    for arg in value.args])
        return value
    offset = 1 if value.name == "tail_transfer" else 0
    from .types import valid_type
    args = list(value.args)
    for position in range(offset, len(args)):
        index = position - offset
        argument = args[position]
        if index < len(prototype.parameters):
            args[position] = strip_implicit(argument, valid_type(prototype.parameters[index][1]), bits)
        elif prototype.variadic and argument.op == "cast" and _literal_like(argument, bits):
            args[position] = literal_value(argument, bits)
        elif prototype.variadic and argument.op == "cast" and argument.width == bits and _is_pointer(argument.args[0].ctype):
            args[position] = argument.args[0]
    if (prototype.variadic and prototype.format_kind == "printf" and prototype.format_index is not None
            and offset + prototype.format_index < len(args)):
        # 按 int 读取的可变实参（%d/%x/%c、* 宽度…）：printf 只读低 32 位，外层到 ≥32 位整数的
        # 转换不改变输出（更窄的值按默认实参提升），去掉这些转换。实参个数必须与格式串一致。
        text = _literal(args[offset + prototype.format_index])
        kinds = printf_int_arguments(text) if text is not None else None
        first = offset + len(prototype.parameters)
        if kinds is not None and len(args) - first == len(kinds) and not any(
                arg.op == "call" and arg.name == "unknown_arguments" for arg in args[first:]):
            for position, is_int in zip(range(first, len(args)), kinds):
                if is_int:
                    args[position] = _strip_int_argument(args[position], bits)
    return _rebuild(value, args)


def _simplify_cast(value, bits):
    inner = value.args[0]
    target = value.ctype
    if inner.ctype == target:
        return inner
    folded = fold(value)
    if folded is not value:
        return folded
    if _is_pointer(target):
        # (Q *)(P *)x：中间的指针类型不改变地址。
        if inner.op == "cast" and _is_pointer(inner.ctype) and (
                _is_pointer(value_type(inner.args[0])) or (integer_info(value_type(inner.args[0]), bits) or (False, 0))[1] == bits):
            source = inner.args[0]
            return source if value_type(source) == target else _simplify_cast(Value("cast", value.width, (source,), ctype=target), bits)
        # (char *)((uintptr_t)p + k)，p 是字节指针：就是 p + k（指针按字节前进）。
        if inner.op in {"add", "sub"} and len(inner.args) == 2 and integer_info(value_type(inner), bits) and (
                integer_info(value_type(inner), bits)[1] == bits):
            base = _strip_pointer_integer(inner.args[0], bits)
            if base is not None and base is not inner.args[0] and _element_size(base.ctype, bits) == 1 and \
                    integer_info(value_type(inner.args[1]), bits):
                moved = Value(inner.op, bits, (base, inner.args[1]), ctype=base.ctype)
                return moved if base.ctype == target else Value("cast", value.width, (moved,), ctype=target)
        # (T *)(uint64_t)p：指针经指针宽度整数再转回指针，地址不变。
        pointer = _strip_pointer_integer(inner, bits)
        if pointer is not None and pointer is not inner:
            return pointer if pointer.ctype == target else Value("cast", value.width, (pointer,), ctype=target)
        if _literal_like(inner, bits) and (inner.op == "cast" or inner.op == "select"):
            literal = literal_value(inner, bits)
            return literal if target.replace(" ", "").endswith("char*") else Value("cast", value.width, (literal,), ctype=target)
        return value
    target_info = integer_info(target, bits)
    if target_info is None:
        return value
    low = _low_bits(inner, target_info[1])
    if low is not inner:
        # 截取的低位与被掩掉的部分无关：(uint8_t)((x & ~0xff) | y) == (uint8_t)y。
        return _simplify_cast(Value("cast", value.width, (low,), ctype=target), bits) if low.ctype != target else low
    wrapper = _upper_wrapper(inner)
    if wrapper is not None and target_info[1] <= wrapper:
        # 截到不超过已知宽度：未知的高位被丢弃。
        return _simplify_cast(Value("cast", value.width, inner.args, ctype=target), bits)
    if inner.op == "cast" and _is_pointer(inner.ctype) and integer_info(value_type(inner.args[0]), bits):
        # (T)(P *)x：整数经指针中转（指针宽度、无符号）再转回整数。
        inner = Value("cast", inner.width, inner.args, ctype=integer_type(bits))
    if inner.op == "cast":
        source = inner.args[0]
        source_type = value_type(source)
        source_info, middle_info = integer_info(source_type, bits), integer_info(inner.ctype, bits)
        # (T)(M)x == (T)x：x→M 保值；或 T 不宽于 x 与 M（只取低位）。同宽度但符号不同的 M
        # 再扩展时结果取决于 M 的符号，不能省略。
        if source_info is not None and middle_info is not None and (
                preserving(source_type, inner.ctype, bits) or
                target_info[1] <= min(source_info[1], middle_info[1])):
            if source_type == target:
                return source
            return _simplify_cast(Value("cast", value.width, (source,), ctype=target), bits)
    return value


def _low_bits(value, width):
    """只关心低 width 位时可以去掉的部分：(x & M) 的 M 低位全 0 时整个与项为 0；低位全 0 的常量
    （部分寄存器写入合并时 (C & ~0xff) 折叠出的常量）对低位也没有贡献（或、异或、加法都不向低位进位）。"""
    if value.op in {"or", "xor", "add"} and len(value.args) == 2:
        low_mask = (1 << width) - 1
        kept = []
        for arg in value.args:
            if arg.op == "and" and len(arg.args) == 2 and arg.pure and any(
                    _int_constant(item) and item.number & low_mask == 0 for item in arg.args):
                continue
            if _int_constant(arg) and arg.number & low_mask == 0:
                continue
            kept.append(arg)
        if len(kept) == 1:
            return kept[0]
    return value


def _boolean_select(value):
    """(c ? 1 : 0)（可带整数转换）→ c；不是这种形式时返回 None。"""
    while value.op == "cast" and integer_info(value.ctype):
        value = value.args[0]
    if (value.op == "select" and len(value.args) == 3 and _int_constant(value.args[1]) and _int_constant(value.args[2])
            and value.args[1].number == 1 and value.args[2].number == 0 and value.args[0].ctype == "bool"):
        return value.args[0]
    return None


def _simplify_equality(value, bits):
    left, right = value.args
    condition = _boolean_select(left)
    if condition is not None and _int_constant(right) and right.number in (0, 1):
        # (c ? 1 : 0) == 0 → !c；!= 0 / == 1 → c。
        from .structure import negate
        keep = (value.name == "!=") == (right.number == 0)
        return condition if keep else negate(condition)
    # (x & 0x80..0) == 0 是符号位测试：写成 (intN_t)x >= 0（!= 0 写成 < 0）。
    if (left.op == "and" and len(left.args) == 2 and _int_constant(left.args[1]) and _int_constant(right)
            and right.number == 0 and left.width in {8, 16, 32, 64} and left.args[1].number == 1 << (left.width - 1)):
        signed = integer_type(left.width, True)
        operand = left.args[0]
        operand = operand if operand.ctype == signed else Value("cast", left.width, (operand,), ctype=signed)
        operand = _simplify_cast(operand, bits) if operand.op == "cast" else operand
        return Value("compare", value.width, (operand, Value("constant", left.width, number=0, ctype=signed)),
                     ">=" if value.name == "==" else "<", value.number, value.ctype, value.effect)

    def strip(side, other):
        if side.op != "cast":
            return None
        inner = side.args[0]
        outer_info, inner_info = integer_info(side.ctype, bits), integer_info(inner.ctype, bits)
        if outer_info is None or inner_info is None or outer_info[1] != inner_info[1] or outer_info[1] < 8:
            return None
        if _int_constant(other) and 0 <= other.number < 1 << (inner_info[1] - 1):
            return inner
        return None

    new_left = strip(left, right)
    if new_left is not None:
        return Value("compare", value.width, (new_left, right), value.name, value.number, value.ctype, value.effect)
    if left.op == "cast" and right.op == "cast" and left.ctype == right.ctype:
        a, b = left.args[0], right.args[0]
        outer = integer_info(left.ctype, bits)
        if outer and a.ctype == b.ctype and integer_info(a.ctype, bits) and integer_info(a.ctype, bits)[1] == outer[1]:
            return Value("compare", value.width, (a, b), value.name, value.number, value.ctype, value.effect)
    return value


def refine_return_type(returns, return_type, bits=64):
    """返回值全是同一种指针（含只读字符串字面量）时，把指针宽度的整数返回类型改成该指针类型。

    returns：最终要打印的 return 语句（每个对象一次）。数值逐位不变，只改类型与写法：
    字面量、指针变量去掉外层到整数的转换；其它指针宽度的读内存（例如字符串指针表
    ``((uint64_t *)表)[i]``）显式写成 ``(T)`` 读；常量 0 保持为 0。至少要有一个返回值本身是
    字符串字面量或指针变量；任何其它返回值都放弃改动。返回（可能改变的）返回类型；
    改动时同时就地改写各 return 语句。
    """
    info = integer_info(return_type, bits)
    if info is None or info[1] != bits:
        return return_type
    returns = [statement for statement in returns if statement.kind == "return" and statement.value is not None]
    if not returns:
        return return_type
    plans, types = [], set()
    for statement in returns:
        inner, width = _strip_integer_casts(statement.value, bits)
        if width < bits:
            return return_type
        if _literal_like(inner, bits) and not _has_function_literal(inner):
            literal = literal_value(inner, bits)
            types.add(literal.ctype or "const char *")
            plans.append((statement, "same", literal))
        elif _is_pointer(inner.ctype) and inner.op != "cast" and inner.width == bits:
            types.add(inner.ctype)
            plans.append((statement, "same", inner))
        elif inner.op in {"load", "index"} and inner.width == bits and integer_info(inner.ctype, bits) is not None:
            plans.append((statement, "cast", inner))
        elif inner.op == "constant" and inner.number == 0:
            plans.append((statement, "same", inner))
        else:
            return return_type
    if types <= _CHAR_POINTER_TYPES and types:
        target = "const char *" if "const char *" in types else "char *"
    elif len(types) == 1:
        target = next(iter(types))
    else:
        return return_type
    for statement, how, value in plans:
        statement.value = Value("cast", bits, (value,), ctype=target) if how == "cast" else value
    return target


_CHAR_POINTER_TYPES = frozenset({"char *", "const char *"})


def _has_function_literal(value):
    if value.op == "function":
        return True
    return any(_has_function_literal(arg) for arg in value.args)


def strip_implicit(value, target, bits=64):
    """赋值/返回/存储时到 target 的转换：值不变或同宽度重解释时去掉显式转换（C 隐式转换相同）。"""
    if value is None or value.op != "cast" or value.ctype != target:
        return value
    inner = value.args[0]
    if _is_pointer(target) and (_is_pointer(inner.ctype) or _literal_like(inner, bits)):
        # 增加 const、与 void * 互转是 C 的隐式指针转换。
        literal = _literal_like(inner, bits)
        source = (literal_value(inner, bits).ctype or "const char *") if literal else inner.ctype
        if target == source or target == "const " + source or target in {"void *", "const void *"} or source == "void *":
            return literal_value(inner, bits) if literal else inner
        return value
    source_type = value_type(inner)
    source_info, target_info = integer_info(source_type, bits), integer_info(target, bits)
    if source_info is None or target_info is None:
        return value
    if preserving(source_type, target, bits) or source_info[1] == target_info[1] and source_info[1] >= 8:
        return inner
    return value


def discard_result(value):
    """结果被丢弃的表达式：只保留真正需要求值的部分（调用、读内存或自身有副作用的运算）。

    外层的转换、“高位未知”包装与纯运算都不影响副作用；只有一个带副作用的操作数时
    逐层剥到它为止（求值顺序与次数不变）。
    """
    current = value
    while True:
        if current.op in {"call", "load", "index", "slot_access"} and _upper_wrapper(current) is None:
            break
        if current.effect and _upper_wrapper(current) is None:
            break
        effectful = [arg for arg in current.args if not arg.pure]
        if len(effectful) != 1:
            break
        current = effectful[0]
    return current


def _constant_load_address(value):
    """结果被丢弃的 *(T *)常量 或 ((T *)常量)[k] 读：返回被读的常量地址，否则 None。"""
    def constant(item):
        while item.op == "cast" and item.args:
            item = item.args[0]
        return item.number if item.op == "constant" and type(item.number) is int else None
    if value.op == "load" and len(value.args) == 1:
        return constant(value.args[0])
    if value.op == "index" and len(value.args) == 2 and value.width % 8 == 0:
        base, index = constant(value.args[0]), constant(value.args[1])
        if base is not None and index is not None:
            return base + index * (value.width // 8)
    return None


def simplify_statements(blocks, variable_types, return_type, bits=64, readable_addresses=None):
    """readable_addresses：已核实、必然可读且读取无副作用的地址（如导入指针槽位）；
    结果被丢弃的对这些地址的读整句删除。可选参数，默认行为不变。"""
    rewriter = simplifier(bits)
    for block in blocks.values():
        kept = []
        for statement in block.statements:
            value = statement.value
            if value is None:
                kept.append(statement)
                continue
            value = rewriter(value)
            if statement.kind == "expression":
                value = discard_result(value)
                if readable_addresses and _constant_load_address(value) in readable_addresses:
                    continue  # 例如导入桩读取 GOT 槽位、目标已按导入名给出：读本身没有可见效果
            elif statement.kind == "assign":
                value = strip_implicit(value, variable_types.get(statement.destination), bits)
            elif statement.kind == "return":
                value = strip_implicit(value, return_type, bits)
            elif statement.kind == "store" and value.op == "store" and len(value.args) == 2:
                destination, stored = value.args
                stored = strip_implicit(stored, integer_type(value.width), bits)
                if stored is not value.args[1]:
                    value = Value("store", value.width, (destination, stored), value.name, value.number, value.ctype, value.effect)
            statement.value = value
            if statement.kind == "assign" and value.op == "variable" and value.name == statement.destination and value.pure:
                continue  # x = x：去掉同宽度转换后的空赋值
            kept.append(statement)
        block.statements = kept
        if block.predicate is not None:
            block.predicate = rewriter(block.predicate)
