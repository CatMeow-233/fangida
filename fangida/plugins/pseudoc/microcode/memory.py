"""Explicit loads/stores, pair accesses and address writeback."""
from __future__ import annotations

import re

from . import x86_strings
from .common import assignment, lifted, resize, value
from .ir import Expression, MicroOperation, constant

# 模块级预编译正则（与原字符串模式及标志位一致）。
_LITERAL_TARGET = re.compile(r"#?(?:0x[0-9a-f]+|[0-9]+)", re.I)
_VECTOR_SCALAR = re.compile(r"([sdq])([0-9]|[12][0-9]|3[01])")
_BRACKETED = re.compile(r"\[\s*([^\]]+)\s*\]")
_INDEX_EXTENSION = re.compile(r"(lsl|uxtw|sxtw|sxtx)(?:\s+#?(0x[0-9a-f]+|[0-9]+))?", re.I)
_BASE_REGISTER = re.compile(r"\[\s*([a-z0-9]+)")


def _literal_address(row, operand):
    """Validate an A64 decoded literal target; retain an actual memory read.

    The processor snapshot has already resolved the signed imm19 * 4 offset
    to an absolute address.  Reconstructing it here must not read binary bytes
    or assume that an address in a code section is immutable data.
    """
    if not _LITERAL_TARGET.fullmatch(operand):
        raise ValueError("Unsupported literal memory target")
    token = operand.removeprefix("#")
    target = int(token, 16 if token.lower().startswith("0x") else 10)
    pc = row["addr"]
    if type(pc) is not int or not 0 <= pc < 1 << 64 or not 0 <= target < 1 << 64:
        raise ValueError("Invalid literal memory address")
    # A64 PC arithmetic wraps at 64 bits; only aligned imm19 encodings exist.
    delta = ((target - pc + (1 << 63)) % (1 << 64)) - (1 << 63)
    if pc % 4 or target % 4 or not -(1 << 20) <= delta <= (1 << 20) - 4:
        raise ValueError("Unencodable literal memory target")
    return hex(target)


def _vector_operand(operand):
    match = _VECTOR_SCALAR.fullmatch(operand.lower())
    return ({"s": 32, "d": 64, "q": 128}[match[1]], "v" + match[2]) if match else None


def _indexed_address(op, operand, width):
    """A64 register offsets, with explicit subregister and extension types."""
    match = _BRACKETED.fullmatch(operand)
    if match is None:
        return None
    parts = [part.strip() for part in match[1].split(",")]
    if len(parts) < 2 or op.register(parts[1]) is None:
        return None
    if len(parts) not in {2, 3}:
        raise ValueError("Invalid register-offset address")
    base, index = op.register(parts[0]), op.register(parts[1])
    if base is None or base.bits != 64 or base.root == "zero" or index.root == "sp":
        raise ValueError("Invalid register-offset address register")
    extension, shift = "lsl", 0
    if len(parts) == 3:
        extended = _INDEX_EXTENSION.fullmatch(parts[2])
        if extended is None or extended[1].lower() == "lsl" and extended[2] is None:
            raise ValueError("Invalid register-offset extension")
        extension = extended[1].lower()
        shift = int(extended[2], 16 if extended[2].lower().startswith("0x") else 10) if extended[2] else 0
    if index.bits != (32 if extension in {"uxtw", "sxtw"} else 64):
        raise ValueError("Index width disagrees with its extension")
    if width not in {8, 16, 32, 64, 128} or shift not in {0, (width // 8).bit_length() - 1}:
        raise ValueError("Unencodable register-offset shift")
    index_value = value(op, parts[1])
    index_value = resize(index_value, 64, signed=extension in {"sxtw", "sxtx"})
    offset = Expression("shl", 64, (index_value, constant(shift, 64)))
    expression = Expression("add", 64, (value(op, parts[0]), offset))
    index_text = op.read(parts[1])
    if extension == "sxtw":
        index_text = f"(uint64_t)(int64_t)(int32_t)({index_text})"
    else:
        index_text = f"(uint64_t)({index_text})"
    return f"({op.read(parts[0])} + ({index_text} << {shift}))", expression


# AArch64 单寄存器的带内存序加载/存储：获取（ldar/ldapr 系列）与释放（stlr 系列）。
# 访问的值语义与普通 ldr/str 相同，内存序作为属性保留（memory_order），地址必须是裸基址 [Xn]。
_ACQUIRE_LOADS = {"ldar": None, "ldarb": 8, "ldarh": 16,
                  "ldapr": None, "ldaprb": 8, "ldaprh": 16}
_RELEASE_STORES = {"stlr": None, "stlrb": 8, "stlrh": 16}
_ORDERED_MNEMONICS = frozenset(_ACQUIRE_LOADS) | frozenset(_RELEASE_STORES)
_BASE_ONLY = re.compile(r"\[\s*([a-z][a-z0-9]*)\s*\]")


def _acquire_release(context, row, args, op, mnemonic):
    load = mnemonic in _ACQUIRE_LOADS
    store = mnemonic in _RELEASE_STORES
    if not (load or store) or len(args) != 2:
        return None
    match = _BASE_ONLY.fullmatch(args[1].strip())
    if match is None:
        return None  # 偏移、前后变址等形式不在此表达（保持不透明）
    base = op.register(match[1])
    if base is None or base.bits != 64 or base.root == "zero":
        return None
    lane = (_ACQUIRE_LOADS if load else _RELEASE_STORES)[mnemonic]
    width = lane or op.width(args[0])
    if width not in {8, 16, 32, 64}:
        return None
    register = op.register(args[0])
    if register is None or register.root == "sp":
        return None
    address_text = op.address(args[1])
    address = Expression("address", op.bits, name=address_text)
    order = "acquire" if load else "release"
    # 能精确表达该内存序的 C11 内存序：ldar/stlr 系列是 RCsc（stlr 之后的 ldar 不能提前），只有 seq_cst 能表达；
    # ldapr 系列（RCpc）是 acquire。可读 C 据此写成前导的 arm_load_acquire*/arm_store_release* 原子访问。
    c11_order = "acquire" if mnemonic.startswith("ldapr") else "seq_cst"
    if load:
        expression = Expression("load", width, (address,))
        loaded = f"load{width}({address_text})"
        if lane and register.bits > width:
            expression = resize(expression, register.bits)  # ldarb/ldarh 零扩展到目的寄存器
        statements = [op.write(args[0], loaded)]
        operations = [MicroOperation("assign", op.width(args[0]), (expression,), register.root, expression,
            {**assignment(op, args[0], expression).attributes, "memory_order": order, "memory_width": width,
             "c11_memory_order": c11_order})]
        return lifted(context, row, "memory", statements, operations, memory_effect="read")
    source = value(op, args[0])
    source_text = op.read(args[0], width)
    if width < op.width(args[0]):
        source = resize(source, width)
        source_text = f"(uint{width}_t)({source_text})"
    statements = [f"store{width}({address_text}, {source_text});"]
    operations = [MicroOperation("store", width, (address, source),
        attributes={"effect": "write", "endianness": "architecture", "memory_order": order,
                    "c11_memory_order": c11_order})]
    return lifted(context, row, "memory", statements, operations, memory_effect="write")


def _order_pair_loads(operations, first, base):
    """成对加载（ldp/ldpsw，无回写）的第一个目的与基址是同一寄存器时（ldp x0, x1, [x0]，架构上合法），
    两个元素都必须从原基址读取：微码按顺序执行，若先写第一个目的，第二个元素的地址就会用到刚加载的值。
    此时先发出第二个元素的加载（第二个目的与基址不同：两个目的相同属约束不可预测、已拒绝），结果与硬件一致。
    带回写的形式中目的与基址相同属约束不可预测，已在前面拒绝。"""
    if (len(operations) == 2 and first is not None and base is not None and first.root == base.root
            and all(operation.opcode == "assign" for operation in operations)):
        operations.reverse()


def _load_pair_signed_word(context, row, args, op, mnemonic):
    """ldpsw Xt1, Xt2, [Xn{, #imm}]（含前后变址）：加载一对 32 位值并各自符号扩展到 64 位。"""
    if mnemonic != "ldpsw" or len(args) not in {3, 4}:
        return None
    first, second = op.register(args[0]), op.register(args[1])
    if first is None or second is None or first.bits != 64 or second.bits != 64:
        return None
    if first.root in {"sp", "zero"} or first.root == second.root:
        return None  # 约束不可预测：目的相同
    address_operand = args[2]
    pre_index = address_operand.endswith("!")
    post_index = len(args) == 4
    if pre_index and post_index:
        raise ValueError("Conflicting address writebacks")
    base_match = _BASE_REGISTER.match(address_operand)
    if base_match is None:
        return None
    base = base_match[1]
    base_register = op.register(base)
    if base_register is None or base_register.bits != 64:
        return None
    if (pre_index or post_index) and any(op.register(arg) is not None and op.register(base) is not None
            and op.register(arg).root == op.register(base).root for arg in args[:2]):
        raise ValueError("Unproven access/writeback alias")
    address_text = op.address(address_operand.rstrip("!"))
    address_name = f"memory_address_{row['addr']:x}"
    statements = [f"uint{op.bits}_t {address_name} = {address_text};"]
    operations = []
    for index, destination in enumerate(args[:2]):
        element_address = address_name if index == 0 else f"({address_name} + 4)"
        address_expr = Expression("address", op.bits, name=address_text if index == 0 else f"({address_text} + 4)")
        expression = resize(Expression("load", 32, (address_expr,)), 64, signed=True)
        statements.append(op.write(destination, f"(int32_t)load32({element_address})"))
        operations.append(assignment(op, destination, expression))
    _order_pair_loads(operations, first, base_register)
    if pre_index or post_index:
        new_base = address_name if pre_index else f"({address_name} + {op.read(args[-1])})"
        statements.append(op.write(base, new_base))
        operations.append(MicroOperation("address_writeback", op.bits, output=op.register(base).root,
            attributes={"mode": "pre_index" if pre_index else "post_index", "address": address_text,
                        "offset": args[-1] if post_index else "included_in_address", "after_access": True}))
    return lifted(context, row, "memory", statements, operations, memory_effect="read")


def lift(context, row, args, op):
    mnemonic = str(row["mnemonic"]).lower()
    if context.architecture.startswith("x86"):
        # stos/movs 及 rep 形式（见 x86_strings.py）；其余 x86 内存访问由各自的处理器表达。
        if mnemonic[-5:-1] in {"stos", "movs"}:
            return x86_strings.lift(context, row, args, op)
        return None
    if context.architecture == "arm64":
        # 先做极轻量的助记符判断，常见的 ldr/str/ldp/stp 不额外进入这两个分支（保持单条提升吞吐）。
        if mnemonic in _ORDERED_MNEMONICS:
            ordered = _acquire_release(context, row, args, op, mnemonic)
            if ordered is not None:
                return ordered
        elif mnemonic == "ldpsw":
            pair_signed = _load_pair_signed_word(context, row, args, op, mnemonic)
            if pair_signed is not None:
                return pair_signed
    unscaled = mnemonic in {"ldur", "ldurb", "ldurh", "ldursw", "ldursb", "ldursh", "stur", "sturb", "sturh"}
    if unscaled and context.architecture != "arm64":
        return None
    mnemonic = {"ldur": "ldr", "ldurb": "ldrb", "ldurh": "ldrh", "ldursw": "ldrsw", "ldursb": "ldrsb", "ldursh": "ldrsh",
                "stur": "str", "sturb": "strb", "sturh": "strh"}.get(mnemonic, mnemonic)
    pair = mnemonic in {"ldp", "stp"}
    scalar = mnemonic in {"ldr", "ldrb", "ldrh", "ldrsw", "ldrsb", "ldrsh", "str", "strb", "strh"}
    if not pair and not scalar:
        return None
    address_index = 2 if pair else 1
    if len(args) not in {address_index + 1, address_index + 2}:
        return None
    address_operand = args[address_index]
    pre_index = address_operand.endswith("!")
    post_index = len(args) == address_index + 2
    if unscaled and (pre_index or post_index):
        raise ValueError("Unscaled access cannot write back")
    if pre_index and post_index:
        raise ValueError("Conflicting address writebacks")
    vector_operands = [_vector_operand(arg) for arg in args[:address_index]]
    vector = context.architecture == "arm64" and all(vector_operands)
    if vector and (mnemonic not in {"ldr", "str", "ldp", "stp"} or len({operand[0] for operand in vector_operands}) != 1):
        raise ValueError("Invalid SIMD memory access form")
    width = vector_operands[0][0] if vector else {"ldrb": 8, "strb": 8, "ldrh": 16, "strh": 16, "ldrsw": 32,
             "ldrsb": 8, "ldrsh": 16}.get(mnemonic, op.width(args[0]))
    typed_address = None
    base_match = _BASE_REGISTER.match(address_operand)
    if base_match is None:
        # Literal loads form a separate addressing class.  SP destinations,
        # stores, unscaled loads and byte/halfword literals have no A64 form.
        if context.architecture != "arm64" or unscaled or mnemonic not in {"ldr", "ldrsw"} or len(args) != 2:
            return None
        destination = op.register(args[0])
        vector_literal = mnemonic == "ldr" and vector
        if not vector_literal and (destination is None or destination.root == "sp" or
                destination.bits not in ({64} if mnemonic == "ldrsw" else {32, 64})):
            return None
        base = None
        address = _literal_address(row, address_operand)
    else:
        base = base_match[1]
        indexed = _indexed_address(op, address_operand.rstrip("!"), width) if context.architecture == "arm64" else None
        if indexed:
            if pair or unscaled or pre_index or post_index:
                raise ValueError("Register offsets cannot pair, unscale or write back")
            address, typed_address = indexed
        else:
            address = op.address(address_operand.rstrip("!"))
    is_store = mnemonic.startswith("st")
    if (pre_index or post_index) and any(
            op.register(destination) is not None and op.register(base) is not None and
            op.register(destination).root == op.register(base).root for destination in args[:address_index]):
        raise ValueError("Unproven access/writeback alias")
    if pair and not is_store and (args[0].lower()==args[1].lower() or op.register(args[0]) is not None and op.register(args[0]) == op.register(args[1])):
        raise ValueError("Constrained-unpredictable pair load destinations")
    address_name = f"memory_address_{row['addr']:x}"
    statements = [f"uint{op.bits}_t {address_name} = {address};"]
    operations = []
    for index, destination in enumerate(args[:address_index]):
        memory_address = address_name if index == 0 else f"({address_name} + {width // 8})"
        address_expr = typed_address or Expression("address", op.bits, name=address if index == 0 else f"({address} + {width // 8})")
        if is_store:
            root = vector_operands[index][1] if vector else None
            if vector:
                context.vector_registers.add(root)
            source = Expression("register", 128, name=root) if vector else value(op, destination)
            if vector and width < 128:
                source = Expression("extract", width, (source,), value=0)
            source_text = f"(uint{width}_t){root}" if vector and width < 128 else root if vector else op.read(destination)
            statements.append(f"store{width}({memory_address}, {source_text});")
            operations.append(MicroOperation("store", width, (address_expr, source), attributes={"effect": "write"}))
        else:
            expression = Expression("load", width, (address_expr,))
            loaded = f"load{width}({memory_address})"
            if mnemonic in {"ldrsw", "ldrsb", "ldrsh"}:
                expression = resize(expression, op.width(destination), signed=True)
                loaded = f"(int{width}_t){loaded}"
            if vector:
                root = vector_operands[index][1]
                context.vector_registers.add(root)
                expression = resize(expression, 128)
                statements.append(f"{root} = {loaded if width == 128 else '(vector128_t)' + loaded};")
                operations.append(MicroOperation("assign", 128, (expression,), root, expression,
                    {"destination_width": 128, "storage_width": 128, "bit_offset": 0, "zero_upper": False,
                     "memory_width": width, "upper_lanes": "zero" if width < 128 else "full"}))
            else:
                statements.append(op.write(destination, loaded))
                operations.append(assignment(op, destination, expression))
    if pair and not is_store and not vector and base is not None:
        _order_pair_loads(operations, op.register(args[0]), op.register(base))
    if pre_index or post_index:
        new_base = address_name if pre_index else f"({address_name} + {op.read(args[-1])})"
        statements.append(op.write(base, new_base))
        operations.append(MicroOperation("address_writeback", op.bits, output=op.register(base).root,
            attributes={"mode": "pre_index" if pre_index else "post_index", "address": address,
                        "offset": args[-1] if post_index else "included_in_address", "after_access": True}))
    return lifted(context, row, "memory", statements, operations,
                  memory_effect="write" if is_store else "read")
