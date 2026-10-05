"""Typed, serializable semantic IR; independent of containers and CPU decoders."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

MICROCODE_VERSION = "1.0"
CATEGORIES = ("data_transfer", "conversion", "integer_arithmetic", "bitwise",
              "memory", "stack", "comparison", "conditional", "floating_point",
              "control_flow", "system", "opaque")


# AArch64 指针认证（PAC）表达式：结果取决于密钥、PAuth 实现（PAuth/PAuth2、FPAC）与
# SCTLR/TCR 配置，不能离线求值；aut* 在实现 FEAT_FPAC 时认证失败会陷入。
POINTER_AUTH_OPCODES = frozenset({"pacia", "pacib", "pacda", "pacdb", "pacga",
                                  "autia", "autib", "autda", "autdb", "xpaci", "xpacd"})

# Opcodes that can trap or depend on FP state (see Expression.pure).
# system_register：系统寄存器读取依赖机器状态（计数器、FPSR 随时间/浮点运算变化，可能陷入），
# 两次读取不能视为同一值；autia/autib/autda/autdb 可能陷入。
IMPURE_OPCODES = frozenset({"load", "unknown", "call", "sdiv", "udiv", "srem", "urem",
    "signed_to_float", "unsigned_to_float", "float_to_signed", "float_to_unsigned", "float_resize",
    "system_register", "autia", "autib", "autda", "autdb"})


@dataclass(frozen=True)
class Expression:
    opcode: str
    width: int
    args: tuple[Expression, ...] = ()
    value: int | float | None = None
    name: str = ""
    domain: str = "bitvector"

    @property
    def pure(self) -> bool:
        # Expressions that can trap or depend on FP state cannot be erased by
        # an integer identity, even when their textual operands are equal.
        return self.opcode not in IMPURE_OPCODES and all(arg.pure for arg in self.args)

    def to_dict(self) -> dict[str, Any]:
        # 每次都返回全新的 dict/list（调用方可能就地修改），只减少属性查找次数。
        result: dict[str, Any] = {"opcode": self.opcode, "width": self.width, "domain": self.domain}
        args = self.args
        if args:
            result["args"] = [arg.to_dict() for arg in args]
        value = self.value
        if value is not None:
            result["value"] = value
        name = self.name
        if name:
            result["name"] = name
        return result

    @classmethod
    def from_dict(cls, record: dict[str, Any], *, _depth: int = 0) -> Expression:
        if _depth > 64:
            raise ValueError("Micro-expression nesting exceeds limit")
        width = record.get("width")
        if type(width) is not int or not 1 <= width <= 512:
            raise ValueError("Micro-expression width must be in [1, 512]")
        args = record.get("args", [])
        if not isinstance(args, (list, tuple)) or len(args) > 4:
            raise ValueError("Invalid micro-expression operands")
        # 求值顺序与原实现一致：先取 opcode，再转换子表达式，最后取 value/name/domain。
        opcode = str(record["opcode"])
        if args:
            depth = _depth + 1
            children = tuple([cls.from_dict(arg, _depth=depth) for arg in args])
        else:
            children = ()
        return cls(opcode, width, children,
                   record.get("value"), str(record.get("name", "")), str(record.get("domain", "bitvector")))


def constant(value: int, width: int) -> Expression:
    return Expression("constant", width, value=value & ((1 << width) - 1))


@dataclass(frozen=True)
class MicroOperation:
    opcode: str
    width: int = 0
    inputs: tuple[Expression, ...] = ()
    output: str | None = None
    expression: Expression | None = None
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"opcode": self.opcode, "width": self.width,
                                  "inputs": [value.to_dict() for value in self.inputs]}
        if self.output is not None:
            result["output"] = self.output
        if self.expression is not None:
            result["expression"] = self.expression.to_dict()
        if self.attributes:
            result["attributes"] = dict(self.attributes)
        return result


@dataclass(frozen=True)
class LiftedInstruction:
    addr: int
    size: int
    mnemonic: str
    architecture: str
    category: str
    operations: tuple[MicroOperation, ...]
    statements: tuple[str, ...] = ()
    reads: tuple[str, ...] = ()
    writes: tuple[str, ...] = ()
    flag_effect: str = "preserve"
    memory_effect: str = "none"
    supported: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {"addr": self.addr, "size": self.size, "mnemonic": self.mnemonic,
                "architecture": self.architecture, "category": self.category,
                "operations": [operation.to_dict() for operation in self.operations],
                "reads": list(self.reads), "writes": list(self.writes),
                "flag_effect": self.flag_effect, "memory_effect": self.memory_effect,
                "supported": self.supported, "microcode_version": MICROCODE_VERSION}
