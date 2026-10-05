"""可读伪 C 的指针/整数一致性：在 C 要求的位置把两者之间的转换写成显式转换。

源码恢复的各阶段（按定义-使用网重定类型、复制传播、去冗余转换、返回类型细化）各自保证“值逐位不变”，
但不保证每个使用点的 C 类型合法：例如复制传播把 `rax = (uint64_t *)x` 代入 `rax & 0xff`，得到对指针
做按位与；整数变量被代入下标位置时变成 `p[(uint8_t *)i]`；指针赋给整数变量、作整数实参或返回值。
这些写法在 C 中是约束违例（Clang 15+ 默认报错 int-conversion，GCC 14 同样），而它们表示的机器值是确定的。

这里在结构化完成、所有类型（变量声明、形参、最终返回类型）都已确定之后，按渲染出的 C 类型逐个
检查表达式，只在 C 不接受隐式转换的位置插入显式转换，不改变任何变量的声明类型（类型仍只来自证据）：

* 赋值、存储、返回、已知原型的实参：指针 ⇄ 整数（空指针常量 0 除外）、互不兼容的指针类型、丢掉被指类型
  限定符的指针（const char * → void *，C11 6.5.16.1）、函数名 → 对象指针（void * 除外）→ 转为目标类型；
* 按位运算、移位、乘除、取反、比较大小、下标、switch：指针操作数 → 指针宽度的无符号整数
  （运算宽度更窄时再截到该宽度，与微码只取低 W 位一致）；
* 加减：整数结果的加减（微码的加减，按字节计算）里出现指针 → 先转为整数（否则 C 会按元素大小缩放）；
  指针结果的加减按 C 的指针运算解释，单位是节点自身类型（Value.ctype）的元素：字节地址运算（局部数组地址
  + 偏移）的节点记为 uint8_t *，按元素计的指针加法（ordering.py、readability 构造的 p + k）记为基址的指针类型。
  基址渲染出的元素大小与节点的不同时：字节单位改写为 `(T *)((uintptr_t)p + k)`，其它单位先把基址转为节点类型；
* 下标的基址不是指针 → 转为元素类型的指针；存储目的上的右值转换 `(uint8_t)p[0] = v`（C 不允许）→
  直接对同宽度的左值 `p[0]` 赋值；
* 自递归调用：实参按本函数最终的形参类型、结果按最终返回类型（与定义一致）。

指针与同宽度整数之间的转换在 GCC/Clang 支持的目标上逐位不变；插入的转换因此不改变任何值。已经类型
正确的表达式原样返回（同一对象），不产生文本差异。
"""
from __future__ import annotations

import re

from .model import Value
from .prototypes import lookup
from .readability import _element_size as _pointer_element_size, integer_info
from .types import integer_type, valid_type

# 渲染为函数名（函数指示符）的节点类型：赋给整数时必须显式转换。
FUNCTION = "function"
# 参数个数与类型任意（前导中声明为未指定形参）的占位与辅助调用。
_ANY_ARGUMENT_CALLS = frozenset({"unresolved_condition", "tail_transfer", "indirect_call", "arm64_supervisor_call"})
# 前导中形参为指针（字符串、对象地址）的名字：位置 → 形参类型。
_POINTER_PARAMETERS = {"unresolved_operation": {0: "const char *"}, "handler_dependent_value": {1: "const char *"},
                       "__arm_rsr64": {0: "const char *"}, "__arm_wsr64": {0: "const char *"},
                       "fangida_machine_state_region": {0: "const char *"},
                       "initialize_unknown_bytes": {0: "void *"}}
# 渲染为调用（call 节点）、形参全为整数的前导辅助函数（见 prelude.py；不依赖前导文本本身的生成）。
_INTEGER_HELPER_CALLS = re.compile(r"x86_rep_(?:stos|movs)\d+|x86_[ui]div_(?:quo|rem)_\d+|[us]mul_overflow_\d+|"
                                   r"unknown_return_upper\d+|unresolved_fallthrough")
# 即使操作数都不是指针也要检查的节点：下标的基址必须是指针、调用的实参按形参类型、存储目的必须是左值。
_ALWAYS_CHECKED = frozenset({"index", "call", "store"})
# 自身的操作数从不需要转换的节点（转换、访存、取地址、逻辑运算、可变参数占位）：只检查其子表达式。
_OPERANDS_UNCHECKED = frozenset({"cast", "load", "address_of", "logical_and", "logical_or", "logical_not", "variadic"})
# 以 C 运算符渲染、操作数必须是整数的运算（加减另行处理）。
_INTEGER_OPERATORS = frozenset({"mul", "shl", "lshr", "and", "or", "xor", "neg", "not"})
_LEAVES = frozenset({"variable", "global", "slot_access", "constant", "float_constant", "string_literal", "string",
                     "unknown", "function"})
# 渲染出的类型可能是指针（或函数名）的叶子：其余叶子（常量、未知值、栈槽访问…）总是整数。
_POINTER_LEAVES = frozenset({"global", "string_literal", "string", "function"})
# 8 位的元素类型（指针符号不同只是 -Wpointer-sign 告警，不是约束违例）。
_BYTE_TYPES = frozenset({"char", "signed char", "unsigned char", "int8_t", "uint8_t"})


_POINTER_ENDINGS = ("*", "]")


def is_pointer(ctype):
    """C 类型是否为指针（数组按退化后的指针看待）。"""
    return isinstance(ctype, str) and ctype.endswith(_POINTER_ENDINGS)


def decayed(ctype):
    """数组类型退化为元素指针：uint8_t[16] → uint8_t *。"""
    if isinstance(ctype, str) and ctype.endswith("]") and "[" in ctype:
        return ctype.split("[", 1)[0].strip() + " *"
    return ctype


def pointee(ctype):
    """指针所指的类型（去掉一层 *）。"""
    return decayed(ctype)[:-1].strip()


def _bare(ctype):
    """去掉 const/volatile 限定与多余空白，便于比较。"""
    words = [word for word in ctype.replace("*", " * ").split() if word not in {"const", "volatile"}]
    return " ".join(words).replace(" *", "*")


_scalar_info = integer_info  # (是否有符号, 宽度)；不是已知整数类型时为 None


_QUALIFIERS = frozenset({"const", "volatile"})


def _own_qualifiers(ctype):
    """类型本身（最外一层）的限定符：const char → {const}；char * 的限定符在 * 之后（这里的类型没有）。"""
    words = ctype.replace("*", " * ").split()
    if "*" in words:
        words = words[len(words) - words[::-1].index("*"):]
    return frozenset(word for word in words if word in _QUALIFIERS)


def discards_qualifiers(target, source):
    """source 指针隐式转换为 target 指针时丢掉被指类型的限定符（C11 6.5.16.1：target 的被指类型必须带有
    source 被指类型的全部限定符，如 const char * 不能隐式赋给 void * 或 char *）；多级指针的内层限定符必须
    完全相同（char ** 不能隐式转换为 const char **）。比较与条件运算允许限定符不同，不用这个检查。"""
    left, right = pointee(target), pointee(source)
    if not _own_qualifiers(right) <= _own_qualifiers(left):
        return True
    while is_pointer(left) and is_pointer(right):
        left, right = pointee(left), pointee(right)
        if _own_qualifiers(left) != _own_qualifiers(right):
            return True
    return False


def compatible_pointers(target, source, bits=64):
    """source 指针可以隐式赋给 target 指针（C11 6.5.16.1，另接受只差符号的整数元素：-Wpointer-sign 只是告警）。"""
    left, right = _bare(pointee(target)), _bare(pointee(source))
    if left == right or left == "void" or right == "void":
        return True
    if left in _BYTE_TYPES and right in _BYTE_TYPES:
        return True
    left_info, right_info = _scalar_info(left, bits), _scalar_info(right, bits)
    return left_info is not None and right_info is not None and left_info[1] == right_info[1] and left_info[1] >= 8 \
        and left not in {"bool", "size_t", "uintptr_t"} and right not in {"bool", "size_t", "uintptr_t"}


class TypeCoercion:
    """按渲染出的 C 类型检查语句与条件，在 C 不接受隐式转换的位置插入显式转换（见模块说明）。

    variable_types：变量名 → 声明的 C 类型；return_type：函数最终的返回类型（结构化细化后可更新）；
    function_name/parameter_types：被重建函数自己的名字与最终形参类型（自递归调用据此检查）。
    """

    def __init__(self, variable_types, return_type, bits=64, function_name=None, parameter_types=None,
                 check_all=False):
        self.variable_types = dict(variable_types or {})
        # 声明为指针或数组的变量名：不含这些变量、也没有指针类型节点（Value.pointer_typed）的表达式是纯整数的，
        # 不需要检查。check_all 为真时（函数里有按本函数签名恢复的自递归调用，其实参要按最终形参类型检查）逐条检查。
        self._pointer_names = frozenset(name for name, ctype in self.variable_types.items() if is_pointer(ctype))
        self.check_all = check_all
        self.return_type = return_type
        self.bits = bits
        self.function_name = function_name
        self.parameter_types = list(parameter_types or ())
        self.word = integer_type(bits)
        self._cache = {}
        self._types = {}
        self._pointer_types = {}  # 类型文本 → 是否为指针或函数名（指针/整数检查只在这些操作数处需要）
        self._declared = {}  # 变量名 → 渲染出的类型（声明类型，数组退化为指针）

    # -- 类型 ------------------------------------------------------------
    def type_of(self, value):
        """value 渲染成 C 之后的类型（见 expressions._format）；未知时返回空串。"""
        key = id(value)
        cached = self._types.get(key)
        if cached is not None and cached[0] is value:
            return cached[1]
        result = self._type_of(value)
        self._types[key] = (value, result)
        return result

    def _type_of(self, value):
        op = value.op
        if op == "variable":
            declared = self._declared.get(value.name)
            if declared is None:
                declared = decayed(self.variable_types.get(value.name, value.ctype) or self.word)
                if value.name in self.variable_types:
                    self._declared[value.name] = declared
            return declared
        if op == "global":
            return decayed(value.ctype or "uint8_t *")
        if op == "function":
            return FUNCTION
        if op in {"constant", "unknown"}:
            return value.ctype if value.ctype and not is_pointer(value.ctype) else self.word
        if op == "string_literal":
            return value.ctype or "const char *"
        if op == "string":
            return "const char *"
        if op == "cast":
            return value.ctype
        if op in {"load", "slot_access"}:
            return integer_type(value.width)
        if op == "index":
            base = value.args[0] if value.args else None
            if base is not None and base.op == "unknown":
                return value.ctype if value.ctype and not is_pointer(value.ctype) else integer_type(value.width)
            if (base is not None and base.op == "cast" and base.args and base.args[0].op == "constant"
                    and is_pointer(base.ctype)):
                return pointee(base.ctype)
            base_type = self.type_of(base) if base is not None else ""
            return pointee(base_type) if is_pointer(base_type) else value.ctype or integer_type(value.width)
        if op == "address_of":
            inner = self.type_of(value.args[0]) if value.args else ""
            return (inner + " *") if inner and not inner.endswith("*") else (inner + "*" if inner else value.ctype)
        if op in {"add", "sub"} and len(value.args) == 2 and value.width >= 32:
            left, right = (self.type_of(arg) for arg in value.args)
            if is_pointer(left) and is_pointer(right):
                return "long" if op == "sub" else left
            if is_pointer(left):
                return left
            if is_pointer(right) and op == "add":
                return right
        if op == "select" and len(value.args) == 3:
            left, right = self.type_of(value.args[1]), self.type_of(value.args[2])
            if is_pointer(left) and (is_pointer(right) or _null(value.args[2])):
                return left
            if is_pointer(right) and _null(value.args[1]):
                return right
        if op in {"compare", "logical_and", "logical_or", "logical_not"}:
            return "int"
        if op == "call":
            if self.function_name and value.name == self.function_name:
                return self.return_type or value.ctype or self.word
            return value.ctype or self.word
        if value.ctype and not is_pointer(value.ctype):
            return value.ctype
        return integer_type(value.width) if value.width in {8, 16, 32, 64, 128} else self.word

    # -- 转换 ------------------------------------------------------------
    def _cast(self, value, ctype):
        """把 value 显式转换为 ctype（按渲染出的类型判断，不信任节点上可能过时的 ctype 记录）。

        指针与指针宽度整数之间的中转转换不改变地址，转换前先去掉：(uint64_t)(T *)x → x（x 为整数），
        (P *)(uint64_t)p → (P *)p（p 为指针）。"""
        if self.type_of(value) == ctype:
            return value
        inner = value
        while inner.op == "cast" and inner.args and inner.width == self.bits:
            candidate = inner.args[0]
            candidate_type = self.type_of(candidate)
            candidate_info = _scalar_info(candidate_type, self.bits)
            if is_pointer(inner.ctype) and (is_pointer(candidate_type) or candidate_info is not None and candidate_info[1] <= self.bits):
                inner = candidate  # 整数/指针 → 指针 → 目标：中间的指针不改变值
            elif (_scalar_info(inner.ctype, self.bits) == (False, self.bits) and is_pointer(candidate_type)
                  and (is_pointer(ctype) or _scalar_info(ctype, self.bits) == (False, self.bits))):
                inner = candidate  # 指针 → 指针宽度无符号整数 → 指针/同宽整数：地址不变
            else:
                break
        if self.type_of(inner) == ctype:
            return inner
        width = (_scalar_info(ctype, self.bits) or (False, self.bits))[1]
        return Value("cast", width, (inner,), ctype=ctype)

    def integer(self, value, width=None):
        """value 作整数操作数：指针、函数名或字面量 → 指针宽度的无符号整数（width 更窄时再截到 width 位）。"""
        source = self.type_of(value)
        if not (is_pointer(source) or source == FUNCTION):
            return value
        result = self._cast(value, self.word)
        if width in {8, 16, 32} and width < self.bits:
            result = self._cast(result, integer_type(width))
        return result

    def convert(self, value, target):
        """赋值/存储/返回/按原型传参到 target 类型：只在 C 不接受隐式转换时显式转换。"""
        if value is None or not target or target == "void" or target.endswith("]"):
            return value
        source = self.type_of(value)
        if source == target:
            return value
        if is_pointer(target):
            if is_pointer(source):
                if compatible_pointers(target, source, self.bits) and not discards_qualifiers(target, source):
                    return value
                return self._cast(value, target)
            if source == FUNCTION:
                # 函数名 → 对象指针：C 不允许隐式转换（Clang 告警、GCC 14 默认报错 incompatible-pointer-types）；
                # 赋给 void * 是 GCC/Clang 的扩展，不告警，保持原样。
                return value if _bare(pointee(target)) == "void" else self._cast(value, target)
            if _null(value):
                return value
            if _scalar_info(source, self.bits) is not None or source in {"int", "long"}:
                return self._cast(value, target)
            return value
        if _scalar_info(target, self.bits) is not None and (is_pointer(source) or source == FUNCTION):
            width = _scalar_info(target, self.bits)[1]
            if width < self.bits and target != "bool":
                return self._cast(self._cast(value, self.word), target)
            return self._cast(value, target)
        return value

    # -- 表达式 ----------------------------------------------------------
    def expression(self, value):
        """自底向上检查一个表达式；类型已经正确时返回同一对象。"""
        if value is None or not value.args and value.op in _LEAVES:
            return value
        if value.op in _OPERANDS_UNCHECKED:
            for arg in value.args:
                if arg.args or arg.op not in _LEAVES:
                    break
            else:
                return value  # 自身操作数不需要转换、操作数又都是叶子（如 (uint64_t)p、*(T *)p）：原样返回
        if value.op == "cast" and len(value.args) == 1 and not self._candidate(value.args[0]):
            return value  # 纯整数子表达式外的一层转换（赋值写回、下标基址…）：转换本身总是合法的
        if value.op == "index" and len(value.args) == 2:
            base, index = value.args
            if (base.op == "variable" and is_pointer(self.type_of(base)) and not self._candidate(index)):
                return value  # 最常见的下标：声明为指针的变量以纯整数下标访问，本身就合法
        key = id(value)
        cached = self._cache.get(key)
        if cached is not None and cached[0] is value:
            return cached[1]
        result = self._expression(value)
        self._cache[key] = (value, result)
        return result

    def _expression(self, value):
        op = value.op
        # 只递归进可能有指针参与的子表达式（见 _candidate）；纯整数的子表达式原样保留，其类型也不是指针。
        pointer_types, names, check_all, pointer = self._pointer_types, self._pointer_names, self.check_all, False
        typed = op not in _OPERANDS_UNCHECKED  # 是否需要知道操作数里有没有指针
        args = []
        for arg in value.args:
            if arg.args or arg.op not in _LEAVES:
                if check_all or not arg.variable_names.isdisjoint(names) or arg.pointer_typed:
                    arg = self.expression(arg)
                else:
                    args.append(arg)
                    continue
            elif not (arg.op == "variable" and arg.name in names or arg.op in _POINTER_LEAVES or check_all
                      or (arg.ctype or "").endswith("*")):
                args.append(arg)
                continue
            if not pointer and typed:
                ctype = self.type_of(arg)
                pointer = pointer_types.get(ctype)
                if pointer is None:
                    pointer = pointer_types[ctype] = is_pointer(ctype) or ctype == FUNCTION
            args.append(arg)
        args = tuple(args)
        if not pointer and op not in _ALWAYS_CHECKED:
            # 快速路径：没有指针（或函数名）操作数的节点、自身操作数不需要转换的节点，各规则都不会改动它。
            return _rebuild(value, args)
        if _promoted_operands(value, args):
            pass  # 窄于 32 位的加/减/乘/移位渲染为 (uint32_t)a op (uint32_t)b：操作数已显式转换（见 expressions._format）
        elif op in _INTEGER_OPERATORS:
            narrow = value.width if value.width < self.bits else None
            args = tuple(self.integer(arg, narrow) for arg in args)
        elif op in {"add", "sub"} and len(args) == 2:
            args = self._additive(value, args)
            if isinstance(args, Value):
                return args
        elif op == "compare" and len(args) == 2:
            args = self._comparison(value, args)
        elif op == "select" and len(args) == 3:
            args = self._selection(value, args)
        elif op == "index" and len(args) == 2:
            args = (self._index_base(value, args[0]), self.integer(args[1]))
        elif op == "call":
            args = self._arguments(value, args)
        elif op == "store" and len(args) == 2:
            destination = self._writable(_lvalue(args[0]))
            args = (destination, self.convert(args[1], self._lvalue_type(destination)))
        elif op not in _OPERANDS_UNCHECKED:
            # 前导辅助函数（{运算}_{W}(…)、vec_*、pac*、浮点占位…）与 ashr/rol/除法：形参都是整数。
            args = tuple(self.integer(arg) for arg in args)
        result = _rebuild(value, args)
        if op == "call" and self.function_name and value.name == self.function_name and self.return_type:
            # 自递归调用：渲染出的结果类型是本函数最终的返回类型；使用处期望的类型不同则显式转换回去。
            if value.ctype and self.return_type != "void" and value.ctype != self.return_type:
                return self.convert(Value("call", value.width, result.args, result.name, result.number, self.return_type,
                                          result.effect), value.ctype)
        return result

    def _additive(self, value, args):
        """加减。返回新的操作数，或整个改写后的值。

        整数结果（微码的加减，按字节）：指针操作数按地址整数参与运算。指针结果（基址是指针）：按 C 的指针运算，
        单位是节点类型 value.ctype 的元素（字节地址运算的节点为 uint8_t *；ordering/readability 构造的按元素
        计的 p + k 为基址的指针类型），与 readability._index、ordering._pointer 的约定一致。"""
        left, right = args
        left_type, right_type = self.type_of(left), self.type_of(right)
        if not (is_pointer(left_type) or is_pointer(right_type) or FUNCTION in {left_type, right_type}):
            return args
        if not is_pointer(value.ctype) or not is_pointer(left_type) or is_pointer(right_type):
            # 整数结果：指针操作数按地址整数参与运算。
            narrow = value.width if value.width < self.bits else None
            return self.integer(left, narrow), self.integer(right, narrow)
        unit, size = _unit(value.ctype, self.bits), _unit(left_type, self.bits)
        if unit is None or size == unit:
            return left, right  # 基址的元素大小与节点的单位相同：C 的 p + k 就是所表示的地址
        if unit == 1:
            # 字节地址运算但基址不是字节指针：C 的 p + k 会按元素大小缩放，改为按字节地址计算。
            moved = Value(value.op, value.width, (self.integer(left), right), ctype=self.word)
            return Value("cast", value.width, (moved,), ctype=value.ctype)
        # 按元素计的指针加法但基址渲染成另一种元素大小（如变量按定义-使用网重定为字节指针）：先转为节点类型。
        return self._cast(left, value.ctype), right

    def _comparison(self, value, args):
        left, right = args
        left_type, right_type = self.type_of(left), self.type_of(right)
        left_pointer = is_pointer(left_type) or left_type == FUNCTION
        right_pointer = is_pointer(right_type) or right_type == FUNCTION
        if not (left_pointer or right_pointer):
            return args
        equality = value.name in {"==", "!="}
        if left_pointer and right_pointer and equality and left_type != FUNCTION and right_type != FUNCTION and (
                compatible_pointers(left_type, right_type, self.bits)):
            return args
        if equality and (left_pointer and _null(right) or right_pointer and _null(left)):
            return args
        width = left.width if left.width < self.bits else None
        return self.integer(left, width), self.integer(right, width)

    def _selection(self, value, args):
        condition, true, false = args
        true_type, false_type = self.type_of(true), self.type_of(false)
        true_pointer, false_pointer = is_pointer(true_type), is_pointer(false_type)
        if not (true_pointer or false_pointer or FUNCTION in {true_type, false_type}):
            return args
        if is_pointer(value.ctype):
            return condition, self.convert(true, value.ctype), self.convert(false, value.ctype)
        if true_pointer and false_pointer and compatible_pointers(true_type, false_type, self.bits):
            return args
        if true_pointer and _null(false) or false_pointer and _null(true):
            return args
        narrow = value.width if value.width < self.bits else None
        return condition, self.integer(true, narrow), self.integer(false, narrow)

    def _index_base(self, value, base):
        if base.op == "unknown" or base.op == "cast" and base.args and base.args[0].op == "constant":
            return base
        if is_pointer(self.type_of(base)):
            return base
        element = value.ctype if value.ctype and not is_pointer(value.ctype) else integer_type(value.width)
        return Value("cast", self.bits, (base,), ctype=element + " *")

    def _arguments(self, value, args):
        name = value.name
        if name in _ANY_ARGUMENT_CALLS:
            return args
        if self.function_name and name == self.function_name:
            if len(args) != len(self.parameter_types):
                return args
            return tuple(self.convert(arg, ctype) for arg, ctype in zip(args, self.parameter_types))
        if name in _POINTER_PARAMETERS or _INTEGER_HELPER_CALLS.fullmatch(name or ""):
            # 前导中以整数为形参的辅助函数（指针形参的位置见 _POINTER_PARAMETERS）。
            pointers = _POINTER_PARAMETERS.get(name, {})
            return tuple(arg if index in pointers else self.integer(arg) for index, arg in enumerate(args))
        prototype = lookup(name)
        if prototype is None:
            return args  # 形参未知的外部函数：前导按未指定形参声明，任何标量实参都合法
        result = list(args)
        for index, (_, ctype) in enumerate(prototype.parameters[:len(result)]):
            result[index] = self.convert(result[index], valid_type(ctype, ""))
        return tuple(result)

    def _writable(self, destination):
        """经 const 限定的指针下标写入（指针类型只是推测，如按 const char * 形参传过）：基址显式转为非 const 指针。"""
        if destination.op != "index" or len(destination.args) != 2:
            return destination
        base = destination.args[0]
        base_type = self.type_of(base)
        if not is_pointer(base_type) or "const" not in pointee(base_type).split():
            return destination
        writable = " ".join(word for word in pointee(base_type).split() if word != "const") + " *"
        return _rebuild(destination, (self._cast(base, writable), destination.args[1]))

    def _lvalue_type(self, destination):
        if destination.op == "variable":
            return self.variable_types.get(destination.name, destination.ctype)
        if destination.op in {"load", "slot_access"}:
            return integer_type(destination.width)
        if destination.op == "index":
            return self.type_of(destination)
        return ""

    # -- 语句 ------------------------------------------------------------
    def _candidate(self, value):
        """表达式里可能有指针（或函数名）参与：有记为指针类型的节点，或引用了声明为指针/数组的变量。"""
        # 先查名字集合（各遍共用的缓存，通常已算好），再查 pointer_typed（首次访问时才遍历子树）。
        return self.check_all or not value.variable_names.isdisjoint(self._pointer_names) or value.pointer_typed

    def statement(self, statement):
        """就地检查一条语句（赋值、存储、返回、只求值的表达式、控制转移）。"""
        value = statement.value
        if value is None or statement.kind == "machine_region":
            return statement
        if (statement.kind == "assign" and value.op == "cast" and len(value.args) == 1
                and value.ctype == self.variable_types.get(statement.destination) and not self._candidate(value.args[0])):
            return statement  # 最常见的形式：纯整数表达式按目的变量的声明类型写回，本身就合法
        if not self._candidate(value) and not (
                statement.kind == "assign" and statement.destination in self._pointer_names
                or statement.kind == "return" and is_pointer(self.return_type)):
            return statement  # 纯整数的表达式赋给整数目的：没有指针与整数之间的转换
        value = self.expression(value)
        if statement.kind == "assign":
            value = self.convert(value, self.variable_types.get(statement.destination, ""))
        elif statement.kind == "return":
            value = self.convert(value, self.return_type)
        statement.value = value
        return statement

    def condition(self, value):
        """if/while 条件：标量即可（指针在条件中合法），只检查内部表达式。"""
        return self.expression(value) if self._candidate(value) else value

    def scalar(self, value):
        """switch 的控制表达式：必须是整数。"""
        return self.integer(self.expression(value)) if self._candidate(value) else value


def _promoted_operands(value, args):
    """窄于 32 位、以 C 运算符渲染的加/减/乘/移位：_format 把两个操作数都写成 (uint32_t) 转换。"""
    if value.width >= 32 or value.op not in {"add", "sub", "mul", "shl", "lshr"} or len(args) != 2:
        return False
    if value.op in {"shl", "lshr"}:
        from .expressions import _HELPER_WIDTHS, _shift_in_range
        return not (value.width in _HELPER_WIDTHS and not _shift_in_range(args[1], value.width))
    return True


def _null(value):
    """空指针常量：整数常量 0（可以直接与指针比较、赋给指针）。"""
    return value.op == "constant" and value.number == 0


def _element_size(ctype, bits):
    return _pointer_element_size(decayed(ctype), bits)


def _unit(ctype, bits):
    """指针加减的单位（字节）：元素大小；void *（GNU C 按字节计算）为 1；未知（结构体等）为 None。"""
    return 1 if _bare(pointee(ctype)) == "void" else _element_size(ctype, bits)


def _lvalue(destination):
    """存储目的上的右值转换（简化下标读取时加在元素外的同宽度整数转换）去掉，直接写同宽度的左值。"""
    while (destination.op == "cast" and destination.args and destination.args[0].op in {"index", "load", "slot_access", "variable"}
           and destination.args[0].width == destination.width):
        destination = destination.args[0]
    return destination


def _rebuild(value, args):
    old = value.args
    if len(args) == len(old):
        for new, previous in zip(args, old):
            if new is not previous:
                break
        else:
            return value
    return Value(value.op, value.width, tuple(args), value.name, value.number, value.ctype, value.effect)
