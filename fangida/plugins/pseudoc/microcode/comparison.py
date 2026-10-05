"""Integer/FP comparison origins, flag tests, SETcc/CMOVcc and ARM selections."""
from __future__ import annotations

import re

from .common import assignment, binary, lifted, value
from .conditions import ComparisonOrigin, condition
from .ir import Expression, MicroOperation, constant
from .arm64_operands import arithmetic_operand, register_operand, shifted_register

# 模块级预编译正则（与原字符串模式及标志位一致）。
_XMM_REGISTER = re.compile(r"xmm([0-9]|[12][0-9]|3[01])")
_SCALAR_FP_REGISTER = re.compile(r"[sd]([0-9]|[12][0-9]|3[01])")
# ARM 条件码取反（cinc/cinv/cneg 别名展开用）；al/nv 没有可用的反条件，查表失败即保持 opaque。
_INVERTED_ARM_CONDITIONS = {"eq": "ne", "ne": "eq", "hs": "lo", "lo": "hs", "cs": "cc", "cc": "cs",
                            "mi": "pl", "pl": "mi", "vs": "vc", "vc": "vs", "hi": "ls", "ls": "hi",
                            "ge": "lt", "lt": "ge", "gt": "le", "le": "gt"}


def floating_operand(context, op, operand: str, width: int) -> tuple[str, Expression]:
    token = operand.lower().strip()
    if token.lstrip("#") in {"0", "0.0"}:
        return "0.0", Expression("float_constant", width, value=0.0, domain="floating")
    if _XMM_REGISTER.fullmatch(token):
        context.vector_registers.add(token)
        return f"float{width}_low({token})", Expression("float_register", width, name=token, domain="floating")
    if context.architecture == "arm64" and _SCALAR_FP_REGISTER.fullmatch(token):
        root = "v" + token[1:]
        context.vector_registers.add(root)
        return f"float{width}_low({root})", Expression("float_register", width, name=root, domain="floating")
    if "[" in token:
        address = op.address(token)
        return f"load_float{width}({address})", Expression("load", width,
            (Expression("address", op.bits, name=address),), domain="floating")
    raise ValueError("Unsupported floating operand")


def lift(context, row, args, op):
    mnemonic = str(row["mnemonic"]).lower()
    family = "x86" if context.architecture.startswith("x86") else "arm"
    if mnemonic == "cmp" and (len(args) == 2 or context.architecture == "arm64" and len(args) == 3):
        width = op.width(args[0])
        attributes = {}
        if context.architecture == "arm64":
            source = op.register(args[0])
            right, right_value, attributes = arithmetic_operand(op, args[1], args[2] if len(args) == 3 else None, width,
                                                               extension_alias=source is not None and source.root == "sp")
            stack_form = attributes["operand_form"] in {"immediate", "extended_register"}
            left, left_value = register_operand(op, args[0], width, allow_sp=stack_form,
                                               allow_zero=not stack_form)
        else:
            left, right = op.read(args[0], width), op.read(args[1], width)
            left_value, right_value = value(op, args[0], width), value(op, args[1], width)
        left_name, right_name = f"cmp_left_{row['addr']:x}", f"cmp_right_{row['addr']:x}"
        context.comparison_origin = ComparisonOrigin(row["addr"], family, width, "integer", left_name, right_name)
        statements = [f"uint{width}_t {left_name} = (uint{width}_t)({left});",
                      f"uint{width}_t {right_name} = (uint{width}_t)({right});",
                      f"flags = {family}_sub_flags{width}({left_name}, {right_name});"]
        operation = MicroOperation("compare", width, (left_value, right_value),
            attributes={"domain": "bitvector", "operation": "sub", "flag_family": family,
                        "signedness": "consumer_condition", "captures": [left_name, right_name], **attributes})
        return lifted(context, row, "comparison", statements, [operation], flag_effect="write")
    if mnemonic in {"test", "tst", "cmn"} and (len(args) == 2 or context.architecture == "arm64" and mnemonic in {"tst", "cmn"} and len(args) == 3):
        width = op.width(args[0])
        context.comparison_origin = None
        attributes = {}
        if context.architecture == "arm64" and len(args) == 3:
            if mnemonic == "cmn":
                source = op.register(args[0])
                right, right_value, attributes = arithmetic_operand(op, args[1], args[2], width,
                                                                   extension_alias=source is not None and source.root == "sp")
                stack_form = attributes["operand_form"] in {"immediate", "extended_register"}
                left, left_value = register_operand(op, args[0], width, allow_sp=stack_form,
                                                   allow_zero=not stack_form)
            else:
                left, left_value = register_operand(op, args[0], width)
                right, right_value, attributes = shifted_register(op, args[1], args[2], width, rotate=True)
        else:
            left, right = op.read(args[0], width), op.read(args[1], width)
            left_value, right_value = value(op, args[0], width), value(op, args[1], width)
        expression = binary("and" if mnemonic != "cmn" else "add", width,
                            left_value, right_value)
        logic_family = "arm32" if context.architecture == "arm" else family
        previous_flags = ", flags" if context.architecture == "arm" else ""
        shifter_unknown = context.architecture == "arm" and mnemonic == "tst" and op.register(args[1]) is None
        helper = f"{logic_family}_logic_flags{width}"
        if shifter_unknown:
            helper = f"arm32_logic_shifted_flags{width}"
            previous_flags += ", symbolic_shifter_carry()"
        statement = (f"flags = {helper}({left} & {right}{previous_flags});" if mnemonic != "cmn" else
                     f"flags = {family}_add_flags{width}({left}, {right});")
        return lifted(context, row, "comparison", [statement],
            [MicroOperation("test" if mnemonic != "cmn" else "compare_add", width, expression.args,
                            expression=expression, attributes={"flag_family": family,
                                "preserve_cv": context.architecture == "arm" and mnemonic != "cmn" and not shifter_unknown,
                                "shifter_carry": "unknown" if shifter_unknown else "preserve" if context.architecture == "arm" else "not_used", **attributes})],
            flag_effect="partial" if context.architecture == "arm" and mnemonic != "cmn" else "write")
    if mnemonic in {"comiss", "ucomiss", "comisd", "ucomisd", "fcmp", "fcmpe"} and len(args) == 2:
        if mnemonic.startswith("f") and context.architecture != "arm64":
            return None  # ARM32 VFP flag transfer requires a separate FPSCR state.
        width = (32 if mnemonic.endswith("ss") else 64) if family == "x86" else (32 if args[0].startswith("s") else 64)
        left, left_value = floating_operand(context, op, args[0], width)
        right, right_value = floating_operand(context, op, args[1], width)
        left_name, right_name = f"fp_left_{row['addr']:x}", f"fp_right_{row['addr']:x}"
        context.comparison_origin = ComparisonOrigin(row["addr"], family, width, "floating", left_name, right_name)
        context.fp_environment = True
        scalar_type = "float" if width == 32 else "double"
        statements = [f"{scalar_type} {left_name} = {left};", f"{scalar_type} {right_name} = {right};",
                      f"flags = {family}_{mnemonic}_compare{width}({left_name}, {right_name}, fp_environment);"]
        return lifted(context, row, "comparison", statements,
            [MicroOperation("compare_float", width, (left_value, right_value), attributes={
                "domain": "floating", "unordered": "explicit", "flag_family": family,
                "nan_exception": "signaling_nan" if mnemonic in {"ucomiss", "ucomisd", "fcmp"} else "any_nan"})],
            flag_effect="write")
    if family == "x86" and (mnemonic.startswith("set") or mnemonic.startswith("cmov")):
        code = mnemonic[3:] if mnemonic.startswith("set") else mnemonic[4:]
        predicate = condition(family, code, context.comparison_origin)
        if mnemonic.startswith("set") and len(args) == 1:
            destination = assignment(op, args[0], constant(0, 8))
            inputs = destination.inputs[:1] if destination.opcode == "store" else ()
            return lifted(context, row, "conditional", [op.write(args[0], f"({predicate.render()} ? 1 : 0)")],
                [MicroOperation("set_condition", 8, inputs, output=destination.output,
                    attributes={**destination.attributes, "condition": predicate.to_dict(), "destination": args[0], "true_value": 1})],
                memory_effect="write" if destination.opcode == "store" else "none")
        if mnemonic.startswith("cmov") and len(args) == 2:
            # A CMOV memory source is read unconditionally, even if false.
            source = f"cmov_source_{row['addr']:x}"
            width = op.width(args[0])
            if op.register(args[0]) is None or width not in {16, 32, 64}:
                raise ValueError("Invalid conditional move destination")
            statements = [f"uint{width}_t {source} = {op.read(args[1], width)};",
                          op.write(args[0], f"({predicate.render()} ? {source} : {op.read(args[0])})")]
            destination = assignment(op, args[0], constant(0, width))
            return lifted(context, row, "conditional", statements,
                [MicroOperation("select", width, (value(op, args[1], width), value(op, args[0], width)),
                    output=destination.output,
                    attributes={**destination.attributes, "condition": predicate.to_dict(), "source_read": "unconditional",
                                "false_operation": "identity", "destination": args[0]})])
    if family == "arm" and mnemonic in {"csel", "csinc", "csinv", "csneg"} and len(args) == 4:
        predicate = condition(family, args[3], context.comparison_origin)
        width = op.width(args[0])
        alternative = op.read(args[2])
        if mnemonic == "csinc":
            alternative = f"({alternative} + 1)"
        elif mnemonic == "csinv":
            alternative = f"~({alternative})"
        elif mnemonic == "csneg":
            alternative = f"-({alternative})"
        destination = assignment(op, args[0], constant(0, width))
        return lifted(context, row, "conditional",
            [op.write(args[0], f"({predicate.render()} ? {op.read(args[1])} : {alternative})")],
            [MicroOperation("select", width, (value(op, args[1]), value(op, args[2])),
                output=destination.output,
                attributes={**destination.attributes, "condition": predicate.to_dict(), "false_operation": mnemonic, "destination": args[0]})])
    if context.architecture == "arm64" and mnemonic in {"cinc", "cinv", "cneg"} and len(args) == 3:
        # cinc/cinv/cneg Rd, Rn, cond 是 csinc/csinv/csneg Rd, Rn, Rn, invert(cond) 的别名：
        # 条件成立时 Rd = Rn + 1 / ~Rn / -Rn，否则 Rd = Rn。按别名展开为同一个 select。
        inverted = _INVERTED_ARM_CONDITIONS[args[2].lower().strip()]
        predicate = condition(family, inverted, context.comparison_origin)
        width = op.width(args[0])
        source = op.read(args[1])
        alternative = {"cinc": f"({source} + 1)", "cinv": f"~({source})", "cneg": f"-({source})"}[mnemonic]
        destination = assignment(op, args[0], constant(0, width))
        action = {"cinc": "csinc", "cinv": "csinv", "cneg": "csneg"}[mnemonic]
        return lifted(context, row, "conditional",
            [op.write(args[0], f"({predicate.render()} ? {source} : {alternative})")],
            [MicroOperation("select", width, (value(op, args[1]), value(op, args[1])),
                output=destination.output,
                attributes={**destination.attributes, "condition": predicate.to_dict(), "false_operation": action,
                            "destination": args[0], "alias_of": action})])
    if family == "arm" and mnemonic in {"cset", "csetm"} and len(args) == 2:
        predicate = condition(family, args[1], context.comparison_origin)
        width = op.width(args[0])
        truth = 1 if mnemonic == "cset" else (1 << width) - 1
        destination = assignment(op, args[0], constant(0, width))
        return lifted(context, row, "conditional", [op.write(args[0], f"({predicate.render()} ? {truth} : 0)")],
            [MicroOperation("set_condition", width, output=destination.output,
                attributes={**destination.attributes, "condition": predicate.to_dict(), "true_value": truth, "destination": args[0]})])
    if family == "arm" and mnemonic in {"ccmp", "ccmn"} and len(args) == 4:
        predicate = condition(family, args[3], context.comparison_origin)
        width = op.width(args[0])
        nzcv = int(args[2].lstrip("#"), 0)
        if not 0 <= nzcv <= 15:
            raise ValueError("Invalid conditional NZCV immediate")
        context.comparison_origin = None
        action = "sub" if mnemonic == "ccmp" else "add"
        statements = [f"if ({predicate.render()}) {{ flags = arm_{action}_flags{width}({op.read(args[0])}, {op.read(args[1], width)}); }}",
                      f"else {{ flags = arm_nzcv({nzcv}); }}"]
        return lifted(context, row, "comparison", statements,
            [MicroOperation("conditional_compare", width, (value(op, args[0]), value(op, args[1], width)),
                attributes={"condition": predicate.to_dict(), "operation": action, "false_nzcv": nzcv})], flag_effect="conditional_write")
    return None
