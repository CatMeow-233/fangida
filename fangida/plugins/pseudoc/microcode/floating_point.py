"""Scalar FP arithmetic, lane effects and explicit FP environment dependency."""
from __future__ import annotations

import re

from .comparison import floating_operand
from .common import assignment, lifted, value
from .ir import Expression, MicroOperation

# 模块级预编译正则（与原字符串模式及标志位一致）。
_XMM_REGISTER = re.compile(r"xmm([0-9]|[12][0-9]|3[01])")
_MEMORY_DWORD_QWORD = re.compile(r"(?:dword|qword)\s", re.I)
_SCALAR_FP_REGISTER = re.compile(r"[sd]([0-9]|[12][0-9]|3[01])")
# AArch64 浮点向量排列（单/双精度）：通道宽度与总宽度。
_FP_ARRANGEMENT = re.compile(r"v([0-9]|[12][0-9]|3[01])\.(2s|4s|2d)")
_FP_ARRANGEMENT_LANES = {"2s": (32, 64), "4s": (32, 128), "2d": (64, 128)}
# 按元素形式的第三个操作数 vN.s[i] / vN.d[i]：每个通道都乘以 vN 的第 i 个元素（先精确地广播该元素）。
_FP_ELEMENT = re.compile(r"v([0-9]|[12][0-9]|3[01])\.([sd])\[(0x[0-9a-f]+|[0-9]+)\]")
# AArch64 专门分支认领的助记符（标量 SIMD 转换、fcsel、向量浮点算术）；其余指令跳过这些检查。
_A64_FP_EXTRA = frozenset({"scvtf", "ucvtf", "fcvtzs", "fcvtzu", "fcsel", "fadd", "fsub", "fmul", "fdiv"})
# AArch64 写标量 SIMD/FP 寄存器（bN/hN/sN/dN）或 64 位排列的向量时，硬件把 V 寄存器其余高位（[127:W]）清零：
# 与通用寄存器写 Wn 相同，用 zero_upper 表示（destination_width 为实际写入宽度、storage_width 为 128）。
_ARM_SCALAR_WRITE = {"storage_width": 128, "bit_offset": 0, "zero_upper": True}


def lift(context, row, args, op):
    mnemonic = str(row["mnemonic"]).lower()
    x86 = context.architecture.startswith("x86")
    if context.architecture == "arm64" and mnemonic in _A64_FP_EXTRA:
        if mnemonic in {"scvtf", "ucvtf", "fcvtzs", "fcvtzu"}:
            simd = _arm_simd_scalar_conversion(context, row, args, op, mnemonic)
            if simd is not None:
                return simd
        elif mnemonic == "fcsel":
            picked = _arm_fcsel(context, row, args, op, mnemonic)
            if picked is not None:
                return picked
        else:
            vector_fp = _arm_vector_fp(context, row, args, op, mnemonic)
            if vector_fp is not None:
                return vector_fp
    conversion = _conversion(context, row, args, op, mnemonic, x86)
    if conversion is not None:
        return conversion
    stem = mnemonic[:-2] if x86 and mnemonic.endswith(("ss", "sd")) else mnemonic.removeprefix("f")
    if stem not in {"add", "sub", "mul", "div"} or len(args) != (2 if x86 else 3):
        return None
    if x86 and not mnemonic.endswith(("ss", "sd")):
        return None
    if not x86 and (context.architecture != "arm64" or not mnemonic.startswith("f")):
        return None
    width = (32 if mnemonic.endswith("ss") else 64) if x86 else (32 if args[0].startswith("s") else 64)
    left_arg, right_arg = (args[0] if x86 else args[1]), args[-1]
    left, left_expr = floating_operand(context, op, left_arg, width)
    right, right_expr = floating_operand(context, op, right_arg, width)
    destination = args[0].lower()
    root = destination if x86 else "v" + destination[1:]
    if x86 and not _XMM_REGISTER.fullmatch(destination):
        raise ValueError("Unsupported scalar FP destination")
    context.vector_registers.add(root)
    expression = Expression("f" + stem, width, (left_expr, right_expr), domain="floating")
    # Helpers carry rounding, NaN, exception and lane semantics instead of
    # applying integer conversions to an FP register's raw bits.
    calculation = f"fp_{stem}{width}({left}, {right}, fp_environment)"
    helper = f"x86_scalar_write{width}" if x86 else f"arm_scalar_write{width}"
    statement = f"{root} = {helper}({root}, {calculation});" if x86 else f"{root} = {helper}({calculation});"
    context.fp_environment = True
    attributes = {"domain": "floating", "rounding": "fp_environment", "exceptions": "fp_environment",
                  "upper_lanes": "preserve" if x86 else "zero", "storage_width": 128}
    if not x86:
        # AArch64 写标量 sN/dN 时硬件把 V 寄存器的 [127:W] 清零（x86 传统 SSE 标量运算保留高位）。
        attributes.update(_ARM_SCALAR_WRITE, destination_width=width)
    return lifted(context, row, "floating_point", [statement],
        [MicroOperation("f" + stem, width, (left_expr, right_expr), root, expression, attributes)])


def _arm_simd_scalar_conversion(context, row, args, op, mnemonic):
    """AArch64 标量 SIMD 形式的整数↔浮点转换：源/目的都是 b/h/s/d 标量寄存器（整数位于该寄存器低位）。

    例如 scvtf d0, d0（d0 中的 64 位整数转成 double 写回 d0）、ucvtf s1, s1、fcvtzs d2, d1（double 截成
    64 位带符号整数写回 d2）。结果依赖 FPCR 舍入/异常，渲染为前导声明的占位辅助（fp_environment），
    与标量 FP 处理一致；带 GPR 操作数的形式仍由 _conversion 处理。带定点小数位（fbits）的形式不在此。
    """
    to_float = mnemonic in {"scvtf", "ucvtf"}
    to_int = mnemonic in {"fcvtzs", "fcvtzu"}
    if not (to_float or to_int) or len(args) != 2:
        return None
    dest, src = _SCALAR_FP_REGISTER.fullmatch(args[0].lower().strip()), _SCALAR_FP_REGISTER.fullmatch(args[1].lower().strip())
    if dest is None or src is None:
        return None  # 至少一个操作数是通用寄存器：交给 _conversion（GPR 源/目的，名字已声明）
    dest_width = 32 if args[0].lower().startswith("s") else 64
    src_width = 32 if args[1].lower().startswith("s") else 64
    root, source_root = "v" + dest.group(1), "v" + src.group(1)
    context.vector_registers.update((root, source_root))
    context.fp_environment = True
    source_register = Expression("register", 128, name=source_root)
    if to_float:
        signed = mnemonic == "scvtf"
        source_value = Expression("truncate", src_width, (source_register,)) if src_width != 128 else source_register
        expression = Expression("signed_to_float" if signed else "unsigned_to_float", dest_width, (source_value,), domain="floating")
        calculation = f"fp_from_{'signed' if signed else 'unsigned'}{src_width}_to{dest_width}((int{src_width}_t){source_root}, fp_environment)"
        attributes = {"source_width": src_width, "source_signed": signed, "rounding": "fp_environment"}
    else:
        signed = mnemonic == "fcvtzs"
        source_value = Expression("truncate", src_width, (source_register,)) if src_width != 128 else source_register
        expression = Expression("float_to_signed" if signed else "float_to_unsigned", dest_width, (source_value,))
        calculation = f"arm_fp_to_{'signed' if signed else 'unsigned'}{dest_width}(float{src_width}_low({source_root}), fp_environment, 1)"
        attributes = {"source_width": src_width, "destination_signed": signed, "rounding": "toward_zero",
                      "invalid_result": "saturating_with_nan_zero", "exceptions": "fp_environment"}
    attributes.update(domain="floating", exceptions="fp_environment", upper_lanes="zero",
                      destination_width=dest_width, **_ARM_SCALAR_WRITE)
    statement = f"{root} = arm_scalar_write{dest_width}({calculation});"
    kind = "integer_to_float" if to_float else "float_to_integer"
    return lifted(context, row, "conversion", [statement],
        [MicroOperation(kind, dest_width, (source_value,), root, expression, attributes)])


def _arm_vector_fp(context, row, args, op, mnemonic):
    """AArch64 向量浮点算术 fadd/fsub/fmul/fdiv（vN.T，含 fmul 的按元素形式 vN.s[i]/vN.d[i]）。

    每个通道独立做单/双精度浮点运算，结果依赖 FPCR 的舍入与异常，无法离线精确求值，渲染为前导声明的
    按通道浮点占位辅助 vec_f{op}{lane}_{total}（fp_environment），语义与标量浮点占位一致；融合乘加
    （fmadd/fmla…）、饱和、表查找、多结构访存等其它向量浮点形式仍保持 opaque。
    按元素 fmul 的第二个实参是“把 vM 的第 i 个元素精确广播到各通道”的整数表达式（与 dup vD.T, vM.T[i]
    相同），因此占位仍是逐通道运算，元素下标不会丢失。64 位排列（2s）写入时清零 V 寄存器高 64 位。
    """
    if mnemonic not in {"fadd", "fsub", "fmul", "fdiv"} or len(args) != 3:
        return None
    dest = _FP_ARRANGEMENT.fullmatch(args[0].lower().strip())
    left = _FP_ARRANGEMENT.fullmatch(args[1].lower().strip())
    if dest is None or left is None or dest.group(2) != left.group(2):
        return None
    element = _FP_ELEMENT.fullmatch(args[2].lower().strip())
    right = _FP_ARRANGEMENT.fullmatch(args[2].lower().strip())
    lane, total = _FP_ARRANGEMENT_LANES[dest.group(2)]
    if element is not None:
        if mnemonic != "fmul" or ({"s": 32, "d": 64}[element.group(2)]) != lane:
            return None  # 只认与排列同精度的按元素 fmul
        raw = element.group(3)
        index = int(raw, 16 if raw.startswith("0x") else 10)
        if not 0 <= index < 128 // lane:
            return None
        right_root = "v" + element.group(1)
    elif right is not None and right.group(2) == dest.group(2):
        right_root = "v" + right.group(1)
    else:
        return None
    root, left_root = "v" + dest.group(1), "v" + left.group(1)
    context.vector_registers.update((root, left_root, right_root))
    context.fp_environment = True
    stem = mnemonic[1:]
    opcode = f"vec_f{stem}{lane}"
    left_expr = Expression("register", 128, name=left_root)
    right_expr = Expression("register", 128, name=right_root)
    right_text = right_root
    if element is not None:
        from .vector import _field, _replicate
        right_expr = _replicate(_field(right_expr, lane * index, lane), lane, total)
        right_text = f"vector_broadcast{lane}x{total // lane}(lane{lane}({right_root}, {index}))"
    expression = Expression(opcode, total, (left_expr, right_expr), domain="floating")
    statement = f"{root} = arm_vector_f{stem}{lane}({left_root}, {right_text}, fp_environment);"
    return lifted(context, row, "floating_point", [statement],
        [MicroOperation(opcode, total, (left_expr, right_expr), root, expression,
            {"domain": "floating", "rounding": "fp_environment", "exceptions": "fp_environment",
             "lane_width": lane, "upper_lanes": "zero" if total < 128 else "full",
             "destination_width": total, "storage_width": 128, "bit_offset": 0, "zero_upper": total < 128})])


def _arm_fcsel(context, row, args, op, mnemonic):
    """AArch64 fcsel Dd, Dn, Dm, cond：按条件选择标量浮点寄存器的值（精确拷贝，不依赖 FPCR）。

    与整数 csel 相同：条件成立取第一个源，否则取第二个源；结果写入目的寄存器低位并清零高位。
    """
    from .conditions import condition
    if mnemonic != "fcsel" or len(args) != 4:
        return None
    dest, left, right = (_SCALAR_FP_REGISTER.fullmatch(arg.lower().strip()) for arg in args[:3])
    if dest is None or left is None or right is None:
        return None
    width = 32 if args[0].lower().startswith("s") else 64
    if any((32 if arg.lower().startswith("s") else 64) != width for arg in args[1:3]):
        return None
    predicate = condition("arm", args[3].lower().strip(), context.comparison_origin)
    root = "v" + dest.group(1)
    left_root, right_root = "v" + left.group(1), "v" + right.group(1)
    context.vector_registers.update((root, left_root, right_root))
    true_value = Expression("truncate", width, (Expression("register", 128, name=left_root),))
    false_value = Expression("truncate", width, (Expression("register", 128, name=right_root),))
    statement = f"{root} = arm_scalar_write{width}({predicate.render()} ? float{width}_low({left_root}) : float{width}_low({right_root}));"
    return lifted(context, row, "conditional", [statement],
        [MicroOperation("select", width, (true_value, false_value), root,
            attributes={"condition": predicate.to_dict(), "destination": args[0], "domain": "floating",
                        "destination_width": width, "upper_lanes": "zero", **_ARM_SCALAR_WRITE})])


def _conversion(context, row, args, op, mnemonic, x86):
    if len(args) != 2:
        return None
    integer_to_float = (x86 and mnemonic in {"cvtsi2ss", "cvtsi2sd"}) or (
        context.architecture == "arm64" and mnemonic in {"scvtf", "ucvtf"})
    float_to_integer = (x86 and mnemonic in {"cvttss2si", "cvttsd2si", "cvtss2si", "cvtsd2si"}) or (
        context.architecture == "arm64" and mnemonic in {"fcvtzs", "fcvtzu"})
    scalar_conversion = (x86 and mnemonic in {"cvtss2sd", "cvtsd2ss"}) or (context.architecture == "arm64" and mnemonic == "fcvt")
    if not (integer_to_float or float_to_integer or scalar_conversion):
        return None
    context.fp_environment = True
    if integer_to_float:
        width = (32 if mnemonic.endswith("ss") else 64) if x86 else (32 if args[0].startswith("s") else 64)
        source_width = op.width(args[1])
        if source_width not in {32, 64} or ("[" in args[1] and not _MEMORY_DWORD_QWORD.match(args[1])):
            raise ValueError("Unproven integer conversion source width")
        signed_input = x86 or mnemonic == "scvtf"
        source_text, source_value = op.read(args[1]), value(op, args[1])
        expression = Expression("signed_to_float" if signed_input else "unsigned_to_float", width, (source_value,), domain="floating")
        calculation = f"fp_from_{'signed' if signed_input else 'unsigned'}{source_width}_to{width}({source_text}, fp_environment)"
        kind = "integer_to_float"
        attributes = {"source_width": source_width, "source_signed": signed_input, "rounding": "fp_environment"}
    elif float_to_integer:
        width = op.width(args[0])
        if width not in {32, 64} or op.register(args[0]) is None:
            raise ValueError("Invalid floating conversion integer destination")
        source_width = (32 if "ss" in mnemonic else 64) if x86 else (32 if args[1].startswith("s") else 64)
        source_text, source_value = floating_operand(context, op, args[1], source_width)
        signed_output = x86 or mnemonic == "fcvtzs"
        rounding = "toward_zero" if mnemonic.startswith("cvtt") or not x86 else "fp_environment"
        calculation = f"{'x86' if x86 else 'arm'}_fp_to_{'signed' if signed_output else 'unsigned'}{width}({source_text}, fp_environment, {int(rounding == 'toward_zero')})"
        expression = Expression("float_to_signed" if signed_output else "float_to_unsigned", width, (source_value,))
        attributes = {"source_width": source_width, "destination_signed": signed_output, "rounding": rounding,
                      "invalid_result": "integer_indefinite_or_trap" if x86 else "saturating_with_nan_zero",
                      "exceptions": "fp_environment"}
        attributes.update(assignment(op, args[0], expression).attributes)
        return lifted(context, row, "conversion", [op.write(args[0], calculation)],
            [MicroOperation("float_to_integer", width, (source_value,), op.register(args[0]).root,
                            expression, attributes)])
    else:
        source_width = (32 if mnemonic == "cvtss2sd" else 64) if x86 else (32 if args[1].startswith("s") else 64)
        width = (64 if source_width == 32 else 32) if x86 else (32 if args[0].startswith("s") else 64)
        source_text, source_value = floating_operand(context, op, args[1], source_width)
        calculation = f"fp_convert{source_width}_to{width}({source_text}, fp_environment)"
        expression = Expression("float_resize", width, (source_value,), domain="floating")
        kind, attributes = "float_resize", {"source_width": source_width, "rounding": "fp_environment"}
    destination = args[0].lower()
    if x86:
        if not _XMM_REGISTER.fullmatch(destination):
            raise ValueError("Invalid scalar FP conversion destination")
        root = destination
    else:
        if not _SCALAR_FP_REGISTER.fullmatch(destination):
            raise ValueError("Invalid scalar FP conversion destination")
        root = "v" + destination[1:]
    context.vector_registers.add(root)
    helper = f"x86_scalar_write{width}" if x86 else f"arm_scalar_write{width}"
    statement = f"{root} = {helper}({root}, {calculation});" if x86 else f"{root} = {helper}({calculation});"
    attributes.update(domain="floating", exceptions="fp_environment", upper_lanes="preserve" if x86 else "zero")
    if x86:
        attributes["preserved_inputs"] = [root]
    else:
        attributes.update(_ARM_SCALAR_WRITE, destination_width=width)
    return lifted(context, row, "conversion", [statement],
        [MicroOperation(kind, width, (source_value,), root, expression, attributes)])
