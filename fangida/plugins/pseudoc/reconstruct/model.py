"""Source reconstruction models, separate from machine microcode."""
from __future__ import annotations

from dataclasses import dataclass, field

# 只有这三类节点携带源码层名字；variables()/variable_names 只收集它们。
_NAMED_OPS = frozenset({"variable", "slot_access", "global"})
# 常量以及由常量还原出的地址节点。
_CONSTANT_OPS = frozenset({"constant", "string_literal", "function"})
_NO_NAMES = frozenset()


class _memoized:
    """无锁的按实例缓存描述符（非数据描述符）。

    Value 是冻结数据类，其派生属性（是否纯、引用的名字集合）完全由字段决定，
    因此首次计算后写入实例 __dict__，此后普通属性查找即可命中。
    不使用 functools.cached_property：Python 3.11 的实现带全局锁，
    对大量小对象的首次访问开销明显。重复计算（并发竞态）结果相同，无害。
    缓存值不参与 __eq__/__hash__/__repr__/replace()，不改变数据类语义。
    """

    def __init__(self, function):
        self.function = function
        self.name = function.__name__
        self.__doc__ = function.__doc__

    def __set_name__(self, owner, name):
        self.name = name

    def __get__(self, instance, owner=None):
        if instance is None:
            return self
        value = self.function(instance)
        # 冻结数据类只拦截 __setattr__；直接写 __dict__ 与 cached_property 做法相同。
        instance.__dict__[self.name] = value
        return value


@dataclass(frozen=True)
class Value:
    op: str
    width: int = 64
    args: tuple[Value, ...] = ()
    name: str = ""
    number: int | float | None = None
    ctype: str = ""
    effect: bool = False

    @_memoized
    def pure(self):
        # 与原 property 语义相同：无副作用且所有子表达式都纯；结果按实例缓存（显式循环比 all(生成器) 快）。
        if self.effect:
            return False
        for arg in self.args:
            if not arg.pure:
                return False
        return True

    @_memoized
    def variable_names(self):
        """不可变的名字集合（frozenset），供内部热路径直接使用，避免反复递归。"""
        args = self.args
        if self.op in _NAMED_OPS:
            own = frozenset((self.name,))
            return own.union(*[arg.variable_names for arg in args]) if args else own
        if not args:
            return _NO_NAMES
        first = args[0].variable_names
        if len(args) == 1:
            return first  # 集合不可变：与唯一的子节点共用，不再复制
        return first.union(*[arg.variable_names for arg in args[1:]])

    @_memoized
    def has_constants(self):
        """子树里是否有常量或由常量还原出的地址（字面量、函数名）；常量折叠/地址还原只需访问这些子树。按实例缓存。"""
        if self.op in _CONSTANT_OPS:
            return True
        for arg in self.args:
            if arg.has_constants:
                return True
        return False

    @_memoized
    def pointer_typed(self):
        """子树里是否有记为指针类型（ctype 以 * 结尾）的节点：指针变量与全局、到指针的转换、字符串字面量、
        函数名、取地址、返回指针的调用等。typecheck 据此（加上声明为指针的变量名）跳过纯整数的表达式。按实例缓存。"""
        if (self.ctype or "").endswith("*"):
            return True
        for arg in self.args:
            if arg.pointer_typed:
                return True
        return False

    def variables(self):
        # 兼容旧接口：每次返回新的可变 set，调用方可以安全地就地修改。
        return set(self.variable_names)


@dataclass
class Statement:
    kind: str
    value: Value | None = None
    destination: str = ""
    address: int = 0

    def uses(self):
        # 兼容旧接口：返回新的可变 set。
        return set(self.value.variable_names) if self.value is not None else set()


@dataclass
class Block:
    address: int
    records: list[dict] = field(default_factory=list)
    successors: tuple[int | None, ...] = ()
    statements: list[Statement] = field(default_factory=list)
    predicate: Value | None = None
    terminal: str = ""
    # One descriptor per successor; missing edges retain their machine target.
    frontiers: tuple[dict | None, ...] = ()


@dataclass
class Variable:
    name: str
    ctype: str
    width: int
    storage: str
    parameter: bool = False
    evidence: list[str] = field(default_factory=list)

    def to_dict(self):
        return {"name": self.name, "type": self.ctype, "width": self.width,
                "storage": self.storage, "parameter": self.parameter, "evidence": self.evidence}
