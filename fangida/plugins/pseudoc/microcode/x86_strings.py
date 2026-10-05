"""x86 串存储/串复制（stos/movs 及其 rep 形式）的显式寄存器结果与内存效果。

* 单次 stos{b,w,d,q}：store(rdi, 累加器)，rdi += 元素字节数；单次 movs：store(rdi, load(rsi))，
  rsi、rdi 各加元素字节数。全部用已有的 store/load/assign 操作表达。
* rep stos：memory_fill 操作（目的、填充值、计数），随后 rdi += rcx * 元素字节数、rcx = 0；
  rep movs：memory_copy 操作（目的、源、计数），随后 rsi、rdi 同样前进、rcx = 0。计数为 0 时
  不访问内存，结果公式同样成立。复制按元素从低地址到高地址逐个进行（区域重叠时与 memmove
  不同），记录在属性 order 中。
* 方向标志 DF：只按前进方向（DF=0）建模，这是记录在属性里的 ABI 假设——System V 与
  Windows x64 ABI 都要求函数入口、调用前后 DF 为 0。只要函数快照里出现可能置位 DF 的指令
  （std、popf…），就无法再依赖这个假设，指令保持 opaque。
* 只接受默认地址宽度的形式：64 位模式用 rdi/rsi/rcx；32 位模式用 es:[edi]/[esi]/ecx，
  并按平坦内存模型假设 ES 段基址为 0（同样记入属性）。地址宽度前缀（67h）、段超越、
  repe/repne 的 cmps/scas（提前终止且写标志）等形式保持 opaque。
"""
from __future__ import annotations

from .common import assignment, lifted, value
from .ir import Expression, MicroOperation, constant

_ELEMENT_BITS = {"b": 8, "w": 16, "d": 32, "q": 64}
_PTR_WORDS = {8: "byte", 16: "word", 32: "dword", 64: "qword"}
_ACCUMULATORS = {8: "al", 16: "ax", 32: "eax", 64: "rax"}
# 可能把 DF 置 1 的指令（cld 只会清零，不影响前进方向的假设）。
_DF_WRITERS = frozenset({"std", "popf", "popfd", "popfq", "popfw", "iret", "iretd", "iretq"})


def _direction_flag_may_be_set(context):
    """函数快照中是否有可能置位 DF 的指令（结果缓存在渲染上下文上）。"""
    cached = getattr(context, "_x86_df_writer_seen", None)
    if cached is None:
        cached = any(str(row.get("mnemonic", "")).lower() in _DF_WRITERS for row in getattr(context, "rows", ()))
        try:
            context._x86_df_writer_seen = cached
        except AttributeError:
            pass
    return cached


def lift(context, row, args, op):
    mnemonic = str(row["mnemonic"]).lower()
    words = mnemonic.split()
    repeat = len(words) == 2 and words[0] == "rep"
    if not (len(words) == 1 or repeat):
        return None
    base = words[-1]
    if len(base) != 5 or base[:4] not in {"stos", "movs"} or base[4] not in _ELEMENT_BITS or len(args) != 2:
        return None
    width = _ELEMENT_BITS[base[4]]
    bits = op.bits
    if width > bits:
        return None
    if bits == 64:
        destination_root, source_root, count_root, segment = "rdi", "rsi", "rcx", None
        destination_text = f"{_PTR_WORDS[width]} ptr [rdi]"
    else:
        destination_root, source_root, count_root, segment = "edi", "esi", "ecx", "es"
        destination_text = f"{_PTR_WORDS[width]} ptr es:[edi]"
    store = base.startswith("stos")
    expected_source = _ACCUMULATORS[width] if store else f"{_PTR_WORDS[width]} ptr [{source_root}]"
    if args[0].lower().strip() != destination_text or args[1].lower().strip() != expected_source:
        return None
    if _direction_flag_may_be_set(context):
        return None  # DF 可能为 1：前进方向的 ABI 假设不再成立，保持 opaque
    element_bytes = width // 8
    destination = value(op, destination_root)
    destination_address = Expression("address", bits, name=op.read(destination_root))
    attributes = {"element_bytes": element_bytes, "direction": "forward", "direction_flag": "assumed_clear",
                  "direction_evidence": "abi_df_clear_and_no_df_writer_in_function_snapshot"}
    if segment:
        attributes["segment"] = "es_base_zero_flat_model_assumed"
    statements, operations = [], []
    if store:
        accumulator_text = op.read(_ACCUMULATORS[width])
        accumulator = value(op, _ACCUMULATORS[width])
    else:
        source = value(op, source_root)
        source_text = op.read(source_root)
    if repeat:
        count = value(op, count_root)
        count_text = op.read(count_root)
        shift = element_bytes.bit_length() - 1
        advance = Expression("shl", bits, (count, constant(shift, bits))) if shift else count
        advance_text = f"({count_text} << {shift})" if shift else count_text
        attributes.update(repeat_prefix="rep", count_register=count_root, zero_count="no_memory_access",
                          order="element_by_element_ascending")
        if store:
            statements.append(f"x86_rep_stos{width}({op.read(destination_root)}, {accumulator_text}, {count_text}); "
                              "/* DF=0 assumed (ABI) */")
            operations.append(MicroOperation("memory_fill", width, (destination, accumulator, count),
                                             attributes={**attributes, "effect": "write",
                                                         "destination": destination_root}))
        else:
            statements.append(f"x86_rep_movs{width}({op.read(destination_root)}, {source_text}, {count_text}); "
                              "/* DF=0 assumed (ABI); ascending element copy */")
            operations.append(MicroOperation("memory_copy", width, (destination, source, count),
                                             attributes={**attributes, "effect": "read_write",
                                                         "destination": destination_root, "source": source_root,
                                                         "overlap": "element_by_element_ascending_not_memmove"}))
            statements.append(op.write(source_root, f"{source_text} + {advance_text}"))
            operations.append(assignment(op, source_root, Expression("add", bits, (source, advance))))
        statements.append(op.write(destination_root, f"{op.read(destination_root)} + {advance_text}"))
        operations.append(assignment(op, destination_root, Expression("add", bits, (destination, advance))))
        statements.append(op.write(count_root, "0"))
        operations.append(assignment(op, count_root, constant(0, bits)))
        return lifted(context, row, "memory", statements, operations,
                      memory_effect="write" if store else "read_write")
    step = constant(element_bytes, bits)
    if store:
        stored, stored_text = accumulator, accumulator_text
    else:
        source_address = Expression("address", bits, name=source_text)
        stored, stored_text = Expression("load", width, (source_address,)), f"load{width}({source_text})"
    statements.append(f"store{width}({op.read(destination_root)}, {stored_text}); /* DF=0 assumed (ABI) */")
    operations.append(MicroOperation("store", width, (destination_address, stored),
                                     attributes={"effect": "write", "endianness": "architecture", **attributes}))
    if not store:
        statements.append(op.write(source_root, f"{source_text} + {element_bytes}"))
        operations.append(assignment(op, source_root, Expression("add", bits, (source, step))))
    statements.append(op.write(destination_root, f"{op.read(destination_root)} + {element_bytes}"))
    operations.append(assignment(op, destination_root, Expression("add", bits, (destination, step))))
    return lifted(context, row, "memory", statements, operations,
                  memory_effect="write" if store else "read_write")
