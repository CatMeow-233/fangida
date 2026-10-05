"""Descriptor and metadata helpers; importing them does not load a renderer."""
from __future__ import annotations

PRIMITIVES = {"V": "void", "Z": "boolean", "B": "byte", "S": "short",
              "C": "char", "I": "int", "J": "long", "F": "float", "D": "double"}
MAX_OUTLINE_CHARS = 8_192


def _type_at(descriptor: str, position: int) -> tuple[str, int]:
    arrays = 0
    while position < len(descriptor) and descriptor[position] == "[":
        arrays += 1
        position += 1
    if position >= len(descriptor):
        raise ValueError("Truncated bytecode type descriptor")
    token = descriptor[position]
    if token == "L":
        end = descriptor.find(";", position + 1)
        if end == -1:
            raise ValueError("Truncated object type descriptor")
        name = descriptor[position + 1:end].replace("/", ".")
        position = end + 1
    elif token in PRIMITIVES:
        name = PRIMITIVES[token]
        position += 1
    else:
        raise ValueError("Invalid bytecode type descriptor")
    return name + "[]" * arrays, position


def method_signature(name: str, descriptor: str, access_flags: int = 0) -> str:
    """Format a descriptor as a readable method declaration, with a safe fallback."""
    try:
        if not descriptor.startswith("("):
            raise ValueError("Invalid method descriptor")
        position = 1
        params: list[str] = []
        while position < len(descriptor) and descriptor[position] != ")":
            field, position = _type_at(descriptor, position)
            if field == "void" or len(params) >= 256:
                raise ValueError("Invalid method parameter")
            params.append(f"{field} arg{len(params)}")
        if position >= len(descriptor):
            raise ValueError("Invalid method descriptor")
        return_type, position = _type_at(descriptor, position + 1)
        if position != len(descriptor):
            raise ValueError("Extra method descriptor bytes")
        method = name.rsplit("->", 1)[-1]
        owner = name.split("->", 1)[0]
        if owner.startswith("L") and owner.endswith(";"):
            owner = owner[1:-1]
        if method == "<init>":
            declaration = owner.rsplit("/", 1)[-1].rsplit("$", 1)[-1]
        elif method == "<clinit>":
            declaration = "static_initializer"
        else:
            declaration = f"{return_type} {method}"
        static = "static " if access_flags & 0x8 and method != "<clinit>" else ""
        return f"{static}{declaration}({', '.join(params)})"
    except ValueError:
        return f"method {name} /* descriptor {descriptor[:256]} */"



def kotlin_hints(name: str, descriptor: str, metadata: dict[str, object] | None) -> list[str]:
    """Use cautiously named heuristics; no coroutine/source reconstruction claim."""
    hints: list[str] = []
    if metadata:
        hints.append("kotlin_metadata_annotation")
        if metadata.get("kind") in {"file_facade", "multi_file_part", "synthetic_class"}:
            hints.append(str(metadata["kind"]))
    if ("Lkotlin/coroutines/Continuation;" in descriptor or
            "kotlin/coroutines/Continuation;" in descriptor):
        hints.append("continuation_parameter")
        if descriptor.endswith("Ljava/lang/Object;"):
            hints.append("suspend_signature_candidate")
    if name.endswith("->invokeSuspend"):
        hints.append("coroutine_state_method_candidate")
    return hints


def _call_name(operand: str) -> str:
    """Render an observed member reference without inventing argument values."""
    owner_and_method = operand.split("(", 1)[0]
    if "->" not in owner_and_method:
        return operand[:256]
    owner, method = owner_and_method.split("->", 1)
    if owner.startswith("L") and owner.endswith(";"):
        owner = owner[1:-1]
    owner = owner.replace("/", ".")
    descriptor = operand[len(owner_and_method):][:128]
    return f"{owner}.{method}(/* symbolic args, descriptor {descriptor} */)"


