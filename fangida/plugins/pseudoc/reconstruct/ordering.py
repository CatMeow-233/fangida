"""AArch64 获取/释放访存（ldar/ldapr/stlr 系列）在可读 C 中的写法。

微码把这些指令的值语义提升为普通的 load/store，内存序作为操作属性保留（memory_order 与能精确表达它的
C11 内存序 c11_memory_order）。可读 C 若写成普通的非原子读写，编译器可以把读取提出循环（自旋等待变成
死循环）、并发访问还属于数据竞争；因此这里改写为前导中按 C11 内存序定义的原子访问辅助函数：

* ldar/ldarb/ldarh → arm_load_acquire_W(p)（seq_cst）；ldapr/ldaprb/ldaprh → arm_load_acquire_pc_W(p)（acquire）；
* stlr/stlrb/stlrh → arm_store_release_W(p, v)（seq_cst）。

指针取自普通内存访问（*(T *)addr、p[i]）的地址表达式。私有栈槽（地址未外泄）只有本线程能访问，普通读写
就是精确的；地址已外泄的栈槽保持普通读写，并记一条 memory_order 未解析项，使重建不自称完整。
"""
from __future__ import annotations

from .expressions import cast
from .model import Value
from .types import integer_type

# 微码属性 c11_memory_order → 前导辅助函数名（不含宽度后缀）。
_LOAD_HELPERS = {"seq_cst": "arm_load_acquire", "acquire": "arm_load_acquire_pc"}
_STORE_HELPERS = {"seq_cst": "arm_store_release"}
_WIDTHS = frozenset({8, 16, 32, 64})


def _pointer(memory, bits):
    """普通内存访问值（load / index）的地址表达式；栈槽（variable / slot_access）或基址未知时返回 None。"""
    if memory.op == "load" and memory.args:
        return Value("cast", bits, (memory.args[0],), ctype=integer_type(memory.width) + " *")
    if memory.op == "index" and len(memory.args) == 2:
        base, index = memory.args
        if base.op == "unknown" or "*" not in (base.ctype or ""):
            return None
        if index.op == "constant" and index.number == 0:
            return base
        return Value("add", bits, (base, index), ctype=base.ctype)  # 指针加法按元素计
    return None


def _frame_slot(memory, at, unresolved, mnemonic):
    """栈槽访问：地址外泄（有副作用）时记 memory_order 未解析项。"""
    if memory.effect:
        unresolved.append({"address": at, "kind": "memory_order", "mnemonic": mnemonic})


def ordered_load(expressions, expression, attributes, at, unresolved, mnemonic=""):
    """带内存序的加载（assign 的表达式为 load 或 zext(load)）。返回可读 C 的值；不适用时返回 None
    （此时调用方按普通表达式提升，尚未调用过 expressions.memory，不会重复记录未解析项）。"""
    helper = _LOAD_HELPERS.get(attributes.get("c11_memory_order"))
    if helper is None or not isinstance(expression, dict):
        return None
    widened, inner = None, expression
    if inner.get("opcode") == "zext" and len(inner.get("args", ())) == 1:
        widened, inner = inner.get("width"), inner["args"][0]
    width = inner.get("width")
    if inner.get("opcode") != "load" or width not in _WIDTHS or not inner.get("args"):
        return None
    memory = expressions.memory(inner["args"][0], width, at)
    pointer = _pointer(memory, expressions.bits)
    if pointer is None:
        _frame_slot(memory, at, unresolved, mnemonic)
        value = memory
    else:
        value = Value("call", width, (pointer,), name=f"{helper}_{width}", ctype=integer_type(width), effect=True)
    if widened is not None and widened != width:
        value = cast(cast(value, integer_type(width), width), integer_type(widened), widened)
    return value


def ordered_store(expressions, operation, at, unresolved, mnemonic=""):
    """带内存序的存储。返回 (目的, 值, 调用)：调用不为 None 时整句写成 arm_store_release_W(p, v)；
    否则（栈槽）按普通存储写出目的与值。不适用时返回 None。"""
    attributes = operation.get("attributes", {})
    helper = _STORE_HELPERS.get(attributes.get("c11_memory_order"))
    width = operation.get("width")
    inputs = operation.get("inputs", ())
    if helper is None or width not in _WIDTHS or len(inputs) != 2:
        return None
    destination = expressions.memory(inputs[0], width, at)
    value = expressions.lift(inputs[1], at)
    pointer = _pointer(destination, expressions.bits)
    if pointer is None:
        _frame_slot(destination, at, unresolved, mnemonic)
        return destination, value, None
    stored = cast(value, integer_type(width), width)
    return destination, value, Value("call", width, (pointer, stored), name=f"{helper}_{width}", ctype="void", effect=True)
