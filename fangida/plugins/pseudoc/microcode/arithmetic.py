"""Fixed-width arithmetic, carry/borrow, products and division exceptions."""
from __future__ import annotations

from .common import assignment, binary, lifted, value
from .ir import Expression, MicroOperation, constant
from .arm64_operands import arithmetic_operand, register_operand, shifted_register

# A64 宽乘法：助记符 -> (是否带符号, 累加方式)。累加方式 add/sub 读第四个 64 位操作数，neg 取负。
_A64_WIDENING = {"umaddl": (False, "add"), "smaddl": (True, "add"), "umsubl": (False, "sub"),
                 "smsubl": (True, "sub"), "umnegl": (False, "neg"), "smnegl": (True, "neg")}
_A64_MULTIPLY_FORMS = frozenset({"umulh", "smulh", "mneg", "negs", "neg", *_A64_WIDENING})


def _a64_multiply(context, row, args, op, mnemonic):
    """A64 乘法补全：umulh/smulh（128 位乘积的高 64 位）、u/s{madd,msub,neg}l（32x32->64 再累加）
    以及 mneg。均不写标志；128 位乘积用 __uint128_t 位向量表示，带符号形式先符号扩展到 128 位，
    乘积按 2^128 取模后的高 64 位即为带符号乘积的高半（|积| < 2^126，不会溢出）。"""
    if mnemonic in {"umulh", "smulh"} and len(args) == 3:
        register_operand(op, args[0], 64, read=False)
        left, left_value = register_operand(op, args[1], 64)
        right, right_value = register_operand(op, args[2], 64)
        signed = mnemonic == "smulh"
        extension = "sext" if signed else "zext"
        product = Expression("mul", 128, (Expression(extension, 128, (left_value,)),
                                          Expression(extension, 128, (right_value,))))
        expression = Expression("extract", 64, (product,), value=64)
        if signed:
            text = f"(uint64_t)((__uint128_t)((__int128_t)(int64_t)({left}) * (__int128_t)(int64_t)({right})) >> 64)"
        else:
            text = f"(uint64_t)(((__uint128_t)({left}) * (__uint128_t)({right})) >> 64)"
        return lifted(context, row, "integer_arithmetic", [op.write(args[0], text)],
                      [assignment(op, args[0], expression)])
    if mnemonic in _A64_WIDENING and len(args) == (3 if mnemonic.endswith("negl") else 4):
        signed, action = _A64_WIDENING[mnemonic]
        register_operand(op, args[0], 64, read=False)
        left, left_value = register_operand(op, args[1], 32)
        right, right_value = register_operand(op, args[2], 32)
        extension = "sext" if signed else "zext"
        product = binary("mul", 64, Expression(extension, 64, (left_value,)), Expression(extension, 64, (right_value,)))
        source_type = "int32_t" if signed else "uint32_t"
        product_text = f"((uint64_t)(int64_t)({source_type})({left}) * (uint64_t)(int64_t)({source_type})({right}))" if signed else \
            f"((uint64_t)({source_type})({left}) * (uint64_t)({source_type})({right}))"
        if action == "neg":
            expression = Expression("neg", 64, (product,))
            text = f"(uint64_t)(0 - {product_text})"
        else:
            addend, addend_value = register_operand(op, args[3], 64)
            expression = binary(action, 64, addend_value, product)
            text = f"(uint64_t)({addend} {'+' if action == 'add' else '-'} {product_text})"
        return lifted(context, row, "integer_arithmetic", [op.write(args[0], text)],
                      [assignment(op, args[0], expression)])
    if mnemonic == "mneg" and len(args) == 3:
        width = op.width(args[0])
        register_operand(op, args[0], width, read=False)
        left, left_value = register_operand(op, args[1], width)
        right, right_value = register_operand(op, args[2], width)
        expression = Expression("neg", width, (binary("mul", width, left_value, right_value),))
        return lifted(context, row, "integer_arithmetic",
                      [op.write(args[0], f"(uint{width}_t)(0 - (uint{width}_t)({left}) * (uint{width}_t)({right}))")],
                      [assignment(op, args[0], expression)])
    if (mnemonic == "negs" and len(args) in {2, 3}) or (mnemonic == "neg" and len(args) == 3):
        # NEG/NEGS（移位寄存器形式）是 SUB/SUBS Rd, ZR, Rm{, shift}：标志等同 0 - Rm。
        width = op.width(args[0])
        register_operand(op, args[0], width, read=False)
        right, right_value, attributes = shifted_register(op, args[1], args[2] if len(args) == 3 else None, width)
        zero = constant(0, width)
        statements, operations = [], []
        if mnemonic == "negs":
            statements.append(f"flags = arm_sub_flags{width}(0, {right});")
            operations.append(MicroOperation("flags_sub", width, (zero, right_value),
                                             attributes={"family": "arm", "carry": False, **attributes}))
        operations.append(assignment(op, args[0], Expression("neg", width, (right_value,))))
        statements.append(op.write(args[0], f"(uint{width}_t)(0 - {right})", width))
        return lifted(context, row, "integer_arithmetic", statements, operations,
                      flag_effect="write" if mnemonic == "negs" else "preserve")
    return None


def _arm32_multiply(context, row, args, op, mnemonic):
    """AArch32 mla/mls（32 位乘加/乘减）与 umull/smull（32x32->64，分别写低/高 32 位）。

    umull/smull 的两个结果都由原输入算出：若某个目的寄存器同时是源，就先写不是源的那个；
    两个目的都与源重叠（或 RdLo == RdHi，架构上不可预测）时无法顺序表达，保持 opaque。
    """
    registers = [op.register(arg) for arg in args]
    if any(register is None or register.bits != 32 for register in registers):
        raise ValueError("AArch32 multiply requires core registers")
    if mnemonic in {"mla", "mls"}:
        product = binary("mul", 32, value(op, args[1]), value(op, args[2]))
        expression = binary("add" if mnemonic == "mla" else "sub", 32, value(op, args[3]), product)
        text = f"(uint32_t)({op.read(args[3])} {'+' if mnemonic == 'mla' else '-'} {op.read(args[1])} * {op.read(args[2])})"
        return lifted(context, row, "integer_arithmetic", [op.write(args[0], text)],
                      [assignment(op, args[0], expression)])
    low, high, left, right = registers
    sources = {left.root, right.root}
    if low.root == high.root or (low.root in sources and high.root in sources):
        raise ValueError("Overlapping AArch32 long-multiply destinations")
    signed = mnemonic == "smull"
    extension = "sext" if signed else "zext"
    product = binary("mul", 64, Expression(extension, 64, (value(op, args[2]),)), Expression(extension, 64, (value(op, args[3]),)))
    cast = "(uint64_t)(int64_t)(int32_t)" if signed else "(uint64_t)"
    temporary = f"long_product_{row['addr']:x}"
    statements = [f"uint64_t {temporary} = {cast}{op.read(args[2])} * {cast}{op.read(args[3])};"]
    writes = [(args[0], Expression("truncate", 32, (product,)), f"(uint32_t){temporary}"),
              (args[1], Expression("extract", 32, (product,), value=32), f"(uint32_t)({temporary} >> 32)")]
    if low.root in sources:
        writes.reverse()  # 先写不覆盖输入的高半
    operations = []
    for destination, expression, text in writes:
        statements.append(op.write(destination, text))
        operations.append(assignment(op, destination, expression))
    return lifted(context, row, "integer_arithmetic", statements, operations)


def lift(context, row, args, op):
    mnemonic = str(row["mnemonic"]).lower()
    x86 = context.architecture.startswith("x86")
    family = "x86" if x86 else "arm"
    if context.architecture == "arm64" and mnemonic in _A64_MULTIPLY_FORMS:
        result = _a64_multiply(context, row, args, op, mnemonic)
        if result is not None:
            return result
    if context.architecture == "arm" and ((mnemonic in {"mla", "mls"} and len(args) == 4) or
                                          (mnemonic in {"umull", "smull"} and len(args) == 4)):
        return _arm32_multiply(context, row, args, op, mnemonic)
    stem = mnemonic[:-1] if not x86 and mnemonic in {"adds", "subs", "adcs", "sbcs"} else mnemonic
    if context.architecture == "arm64" and stem in {"add", "sub"} and len(args) in {3, 4}:
        width = op.width(args[0])
        extension_alias = any(op.register(token) is not None and op.register(token).root == "sp" for token in args[:2])
        right, right_value, operand_attributes = arithmetic_operand(op, args[2], args[3] if len(args) == 4 else None, width,
                                                                   extension_alias=extension_alias)
        immediate_form = operand_attributes["operand_form"] == "immediate"
        extended_form = operand_attributes["operand_form"] == "extended_register"
        stack_form = immediate_form or extended_form
        changes_flags = mnemonic.endswith("s")
        register_operand(op, args[0], width, allow_sp=stack_form and not changes_flags,
                         allow_zero=changes_flags or not stack_form, read=False)
        left, left_value = register_operand(op, args[1], width, allow_sp=stack_form,
                                           allow_zero=not stack_form)
        expression = binary(stem, width, left_value, right_value)
        text = f"({left} {'+' if stem == 'add' else '-'} {right})"
        statements, operations = [], []
        if changes_flags:
            statements.append(f"flags = arm_{stem}_flags{width}({left}, {right});")
            operations.append(MicroOperation(f"flags_{stem}", width, (left_value, right_value),
                attributes={"family": "arm", "carry": False, **operand_attributes}))
        operations.append(assignment(op, args[0], expression))
        statements.append(op.write(args[0], f"(uint{width}_t){text}", width))
        return lifted(context, row, "integer_arithmetic", statements, operations,
                      flag_effect="write" if changes_flags else "preserve")
    if context.architecture == "arm64" and mnemonic in {"smull", "umull"} and len(args) == 3:
        register_operand(op, args[0], 64, read=False)
        left, left_value = register_operand(op, args[1], 32)
        right, right_value = register_operand(op, args[2], 32)
        signed = mnemonic == "smull"
        extension = "sext" if signed else "zext"
        expression = binary("mul", 64, Expression(extension, 64, (left_value,)),
                            Expression(extension, 64, (right_value,)))
        source_type, result_type = ("int32_t", "int64_t") if signed else ("uint32_t", "uint64_t")
        text = f"((uint64_t)(({result_type})({source_type})({left}) * ({result_type})({source_type})({right})))"
        return lifted(context, row, "integer_arithmetic", [op.write(args[0], text)],
            [assignment(op, args[0], expression)])
    if context.architecture == "arm64" and mnemonic in {"madd", "msub"} and len(args) == 4:
        width = op.width(args[0])
        register_operand(op, args[0], width, read=False)
        left, left_value = register_operand(op, args[1], width)
        right, right_value = register_operand(op, args[2], width)
        addend, addend_value = register_operand(op, args[3], width)
        expression = binary("add" if mnemonic == "madd" else "sub", width, addend_value,
                            binary("mul", width, left_value, right_value))
        text = f"(uint{width}_t)({addend} {'+' if mnemonic == 'madd' else '-'} ((uint{width}_t)({left}) * (uint{width}_t)({right})))"
        return lifted(context, row, "integer_arithmetic", [op.write(args[0], text)],
            [assignment(op, args[0], expression)])
    if stem in {"add", "sub", "adc", "sbb", "sbc"} and len(args) == (2 if x86 else 3):
        destination, width = args[0], op.width(args[0])
        left_operand, right_operand = (args[0] if x86 else args[1]), args[-1]
        left, right = op.read(left_operand, width), op.read(right_operand, width)
        left_value, right_value = value(op, left_operand, width), value(op, right_operand, width)
        addition = stem in {"add", "adc"}
        opcode = "add" if addition else "sub"
        expression = binary(opcode, width, left_value, right_value)
        text = f"({left} {'+' if addition else '-'} {right})"
        statements, operations = [], []
        for side, operand in (("left", left_operand), ("right", right_operand)):
            if "[" in operand:
                capture = f"arithmetic_{side}_{row['addr']:x}"
                statements.append(f"uint{width}_t {capture} = {left if side == 'left' else right};")
                if side == "left":
                    left = capture
                else:
                    right = capture
        text = f"({left} {'+' if addition else '-'} {right})"
        carry_operation = stem in {"adc", "sbb", "sbc"}
        if carry_operation:
            context.flags = True
            carry_name = f"carry_{row['addr']:x}"
            carry = "flags.CF" if x86 else "flags.C" if addition else "!flags.C"
            statements.append(f"uint{width}_t {carry_name} = {carry};")
            carry_expression = Expression("register", width, name="flags.CF" if x86 else "flags.C")
            if not x86 and not addition:
                carry_expression = binary("xor", width, carry_expression, constant(1, width))
            expression = binary(opcode, width, expression, carry_expression)
            text = f"({text} {'+' if addition else '-'} {carry_name})"
            operations.append(MicroOperation("carry_input", width, (carry_expression,), attributes={"borrow": not addition}))
        changes_flags = x86 or mnemonic.endswith("s")
        if changes_flags:
            flag_args = f"{left}, {right}" + (f", {carry_name}" if carry_operation else "")
            action = "adc" if carry_operation and addition else "sbb" if carry_operation and x86 else "sbc" if carry_operation else opcode
            statements.append(f"flags = {family}_{action}_flags{width}({flag_args});")
            operations.append(MicroOperation(f"flags_{opcode}", width, (left_value, right_value), attributes={
                "family": family, "carry": carry_operation, "carry_is_borrow": not addition and x86}))
        statements.append(op.write(destination, f"(uint{width}_t){text}", width))
        operations.append(assignment(op, destination, expression))
        return lifted(context, row, "integer_arithmetic", statements, operations,
                      flag_effect="write" if changes_flags else "preserve")
    if x86 and mnemonic in {"inc", "dec", "neg"} and len(args) == 1:
        width, left = op.width(args[0]), op.read(args[0])
        source = value(op, args[0])
        statements = []
        if "[" in args[0]:
            capture = f"unary_input_{row['addr']:x}"
            statements.append(f"uint{width}_t {capture} = {left};")
            left = capture
        expression = Expression("neg", width, (source,)) if mnemonic == "neg" else binary(
            "add" if mnemonic == "inc" else "sub", width, source, constant(1, width))
        text = f"-({left})" if mnemonic == "neg" else f"({left} {'+' if mnemonic == 'inc' else '-'} 1)"
        return lifted(context, row, "integer_arithmetic",
            [*statements, f"flags = x86_{mnemonic}_flags{width}({left}, flags);", op.write(args[0], f"(uint{width}_t)({text})")],
            [MicroOperation("flags_unary", width, (source,), attributes={"operation": mnemonic, "preserve_cf": mnemonic != "neg"}),
             assignment(op, args[0], expression)], flag_effect="partial" if mnemonic != "neg" else "write")
    if not x86 and mnemonic == "neg" and len(args) == 2:
        width = op.width(args[0])
        return lifted(context, row, "integer_arithmetic", [op.write(args[0], f"(uint{width}_t)-({op.read(args[1])})")],
            [assignment(op, args[0], Expression("neg", width, (value(op, args[1]),)))])
    if (x86 and mnemonic == "imul" and len(args) in {2, 3}) or (not x86 and mnemonic == "mul" and len(args) == 3):
        width = op.width(args[0])
        left_operand = args[0] if len(args) == 2 else args[1]
        right_operand = args[-1]
        expression = binary("mul", width, value(op, left_operand, width), value(op, right_operand, width))
        statements = []
        operations = []
        left, right = op.read(left_operand), op.read(right_operand, width)
        for side, operand in (("left", left_operand), ("right", right_operand)):
            if "[" in operand:
                capture = f"multiply_{side}_{row['addr']:x}"
                statements.append(f"uint{width}_t {capture} = {left if side == 'left' else right};")
                if side == "left":
                    left = capture
                else:
                    right = capture
        if x86:
            statements.append(f"flags = x86_imul_flags{width}({left}, {right}, flags);")
            operations.append(MicroOperation("flags_multiply", width, expression.args, attributes={"signed": True, "defined": ["CF", "OF"]}))
        statements.append(op.write(args[0], f"low_product{width}({left}, {right})"))
        operations.append(assignment(op, args[0], expression))
        return lifted(context, row, "integer_arithmetic", statements, operations,
                      flag_effect="partial_undefined" if x86 else "preserve")
    if not x86 and mnemonic in {"udiv", "sdiv"} and len(args) == 3:
        width = op.width(args[0])
        expression = binary("arm_" + mnemonic, width, value(op, args[1]), value(op, args[2]))
        return lifted(context, row, "integer_arithmetic",
            [op.write(args[0], f"arm_{mnemonic}{width}({op.read(args[1])}, {op.read(args[2])})")],
            [assignment(op, args[0], expression)], memory_effect="none")
    if x86 and mnemonic in {"mul", "imul", "div", "idiv"} and len(args) == 1:
        width = op.width(args[0])
        low, high = {8: ("al", "ah"), 16: ("ax", "dx"), 32: ("eax", "edx"), 64: ("rax", "rdx")}[width]
        pair = f"wide_{row['addr']:x}"
        inputs = (value(op, low), value(op, args[0], width)) if "mul" in mnemonic else (value(op, high), value(op, low), value(op, args[0], width))
        signed_operation = mnemonic.startswith("i")
        helper_args = f"{op.read(low)}, {op.read(args[0], width)}" if "mul" in mnemonic else f"{op.read(high)}, {op.read(low)}, {op.read(args[0], width)}"
        statements = [f"wide_result_t {pair} = x86_{mnemonic}{width}({helper_args});",
            op.write(low, f"{pair}.low"), op.write(high, f"{pair}.high"), f"flags = {pair}.flags;"]
        roles = ("low", "high") if "mul" in mnemonic else ("quotient", "remainder")
        # wide_outputs（新增、可选）：每个写回寄存器切片的根、宽度与位偏移，供可读伪 C 精确还原两个结果
        # （rax/rdx 或 al/ah…）。旧结果没有此字段时可读层按原样保持 unresolved_operation。
        wide_outputs = [_wide_output(op, slice_name, role) for slice_name, role in zip((low, high), roles)]
        return lifted(context, row, "integer_arithmetic", statements,
            [MicroOperation("multiply_wide" if "mul" in mnemonic else "divide_wide", width, inputs,
                attributes={"signed": signed_operation, "outputs": list(dict.fromkeys((op.register(low).root, op.register(high).root))),
                            "output_slices": [low, high], "wide_outputs": wide_outputs,
                            "possible_traps": [] if "mul" in mnemonic else ["zero_divisor", "quotient_overflow"]})],
            flag_effect="partial_undefined" if "mul" in mnemonic else "undefined")
    return None


def _wide_output(op, slice_name, role):
    """x86 宽乘/宽除的一个写回切片：寄存器根、目的宽度、位偏移与是否清零高位（供可读伪 C 精确还原）。"""
    register = op.register(slice_name)
    return {"output": register.root, "destination_width": register.bits, "storage_width": op.bits,
            "bit_offset": register.shift, "zero_upper": register.bits == 32 and op.bits == 64, "role": role}
