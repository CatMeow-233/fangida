"""Stack pointer changes remain separate from memory and ABI inference."""
from __future__ import annotations

from .common import assignment, lifted, value
from .ir import Expression, MicroOperation


def lift(context, row, args, op):
    mnemonic = str(row["mnemonic"]).lower()
    if not context.architecture.startswith("x86"):
        return None
    sp, bp, step = ("rsp", "rbp", 8) if op.bits == 64 else ("esp", "ebp", 4)
    pointer = Expression("register", op.bits, name=sp)
    if mnemonic in {"push", "pop"} and len(args) == 1 and op.width(args[0]) == op.bits:
        context.registers.add(sp)
        if mnemonic == "push":
            statements = [f"store{op.bits}({sp} - {step}, {op.read(args[0])});", f"{sp} -= {step};"]
            operation = MicroOperation("stack_push", op.bits, (value(op, args[0]), pointer), output=sp,
                attributes={"delta": -step, "value_before_pointer_change": True, "memory_write": True})
        else:
            temporary = f"pop_{row['addr']:x}"
            statements = [f"uint{op.bits}_t {temporary} = load{op.bits}({sp});", f"{sp} += {step};", op.write(args[0], temporary)]
            operation = MicroOperation("stack_pop", op.bits, (pointer,), output=sp,
                attributes={"delta": step, "destination": args[0], "pointer_before_destination": True, "memory_read": True,
                            "outputs": [op.register(args[0]).root] if op.register(args[0]) else []})
        memory_effect = ("read_write" if "[" in args[0] else "write" if mnemonic == "push" else "read")
        return lifted(context, row, "stack", statements, [operation], memory_effect=memory_effect)
    if mnemonic == "leave" and not args:
        context.registers.update((sp, bp))
        return lifted(context, row, "stack", [f"{sp} = {bp};", f"{bp} = load{op.bits}({sp});", f"{sp} += {step};"],
            [MicroOperation("stack_leave", op.bits, (Expression("register", op.bits, name=bp),),
                attributes={"outputs": [sp, bp], "pop_bytes": step})], memory_effect="read")
    return None
