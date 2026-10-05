"""Lift machine effects into named source values, locals and typed predicates."""
from __future__ import annotations

import logging

from .abi import incoming_registers, signature, initial_widths, return_width, available_registers, _signature_and_incoming
from .calls import restore_call, restore_transfer
from .expressions import Expressions, _signed_value, cast, format_value, unsigned_arms
from .model import Block, Statement, Value, Variable
from .ordering import ordered_load, ordered_store
from .stack import Frame
from .types import constraints, integer_type, valid_type, incoming_types
from ..microcode.evaluate import declared_division_semantics
from ..native_operands import identifier

_log = logging.getLogger(__name__)


# 各 ABI 的被调用者保存寄存器（只用于识别函数序言/尾声里的保存与恢复）。
_CALLEE_SAVED = {
    "sysv64": frozenset({"rbx", "rbp", "r12", "r13", "r14", "r15"}),
    "win64": frozenset({"rbx", "rbp", "rdi", "rsi", "r12", "r13", "r14", "r15"}),
    "cdecl": frozenset({"ebx", "ebp", "esi", "edi"}),
}

_RELATION_OPERATORS = {"eq": "==", "ne": "!=", "gt": ">", "ge": ">=", "lt": "<", "le": "<="}
# 只看符号位（N/SF）的条件码：结果 < 0 / >= 0。
_SIGN_CODES = {"x86": {"s": "lt", "ns": "ge"}, "arm": {"mi": "lt", "pl": "ge"}}
# 只看零标志的条件码。
_ZERO_CODES = {"x86": {"e": "eq", "z": "eq", "ne": "ne", "nz": "ne"}, "arm": {"eq": "eq", "ne": "ne"}}
# AArch64 NZCV：标志名、在系统寄存器中的位置、标志置位时成立的条件码（来源未知时用于 unresolved_condition）。
_NZCV_FLAGS = (("N", 31, "mi"), ("Z", 30, "eq"), ("C", 29, "hs"), ("V", 28, "vs"))
# 进位相关条件码用 C（进位置位）与 Z 的组合表示；对加法而言 x86 与 ARM 的 C 都是进位输出。
# x86 MUL/IMUL 后可还原的条件码（CF = OF = 乘积溢出）：True 表示溢出时成立。
_MULTIPLY_CODES = {"o": True, "b": True, "c": True, "nae": True, "no": False, "ae": False, "nb": False, "nc": False}
_ADD_CARRY_CODES = {
    "x86": {"b": "C", "c": "C", "nae": "C", "ae": "!C", "nb": "!C", "nc": "!C",
            "a": "!C&!Z", "nbe": "!C&!Z", "be": "C|Z", "na": "C|Z"},
    "arm": {"hs": "C", "cs": "C", "lo": "!C", "cc": "!C", "hi": "C&!Z", "ls": "!C|Z"},
}


def definition_name(function, context, entry):
    """被重建函数在可读 C 中的定义名：调用摘要中的名字 > 显示名 > 函数名；自动生成的 sub_ 名写作
    recovered_function（原始地址保留在出处信息中）。函数头与自递归调用使用同一个名字。"""
    summary = context.get("callees", {}).get(entry, {})
    name = identifier(summary.get("name", function.get("display_name") or function.get("name", "function")))
    return "recovered_function" if name.startswith("sub_") else name


def _mentions(expression, roots):
    from .abi import expression_registers
    try:
        return bool(expression_registers(expression) & roots)
    except (TypeError, AttributeError):
        return True


class Recovery:
    def __init__(self, function, records, blocks, architecture, context, signature_records=None):
        self.function, self.records, self.blocks = function, records, blocks
        self.bits = 64 if architecture in {"x86_64", "arm64"} else 32
        signature_function = {**function, "start": function.get("source_original_start", function.get("start"))}
        # 与 signature(...) 相同；额外取回其内部对同一输入算出的 incoming_registers，供下面复用。
        self.profile, signature_incoming = _signature_and_incoming(signature_function, signature_records or records, architecture, context)
        self.abi = self.profile["abi"]
        self.frame = Frame(blocks, function.get("start", records[0]["addr"]), self.abi)
        widths, types, self.pointers = constraints(records, self.bits)
        if (signature_records or records) is records:
            # 同一输入：constraints 是纯函数，widths 此后只读，original_types 未被使用。
            original_widths = widths
        else:
            original_widths, original_types, _ = constraints(signature_records or records,self.bits)
        initial = initial_widths(signature_records or records,signature_function["start"], self.abi)
        incoming_type_evidence = incoming_types(signature_records or records, signature_function["start"], self.abi)
        for parameter in self.profile["parameters"]:
            root = parameter.get("register")
            if parameter.get("evidence") != "declared_prototype":
                width = initial.get(root,original_widths.get(root,self.bits))
                ctype = incoming_type_evidence.get(root, "")
                parameter["type"] = ctype if "*" in ctype else integer_type(width, ctype == "signed")
        if not self.profile.get("return_type"):
            from .abi import never_returns
            if never_returns(function, records, function["start"]):
                # 已证明不返回的函数（abort 包装、longjmp 包装等）：没有返回值可言。
                self.profile["return_type"] = "void"
            else:
                width = return_width(records,function["start"],self.abi)
                self.profile["return_type"] = integer_type(width,types.get(self.abi.return_register,"").startswith("int"))
        for row in records:
            for operation in row["operations"]:
                if operation["opcode"] == "call":
                    summary = context.get("callees", {}).get(operation.get("attributes", {}).get("target"), {})
                    for parameter in summary.get("parameters", ()):
                        root, ctype = parameter.get("register"), valid_type(parameter.get("type"), "")
                        if root and "*" in ctype and widths.get(root, self.bits) == self.bits:
                            types[root] = ctype
        # signature_function 一定含 "start" 键，两处入口相同；同一 records 与同一 ABI 对象下结果相同。
        self.incoming = signature_incoming if signature_incoming is not None else incoming_registers(
            signature_records or records, signature_function.get("start", records[0]["addr"]), self.abi)
        roots = sorted({root for row in records for root in row.get("reads", []) + row.get("writes", [])
                        if root not in {"flags", "fp_environment"} and not root.startswith("flags.")})
        parameters = {item["register"]: item for item in self.profile["parameters"] if item.get("register")}
        roots = sorted(set(roots) | set(parameters))
        self.variables, self.used_names = {}, set()
        for root in roots:
            parameter = parameters.get(root)
            name = self.fresh(parameter.get("name", "argument") if parameter else "result" if root == self.abi.return_register else f"value_{len(self.variables) + 1}")
            width = widths.get(root, self.bits)
            ctype = types.get(root, integer_type(width))
            parameter_type = valid_type(parameter.get("type"), ctype) if parameter else ctype
            self.variables[root] = Variable(name, ctype, width, root, parameter is not None,
                [parameter["evidence"]] if parameter else ["machine_width"])
            if parameter and (parameter_type != ctype or any(op.get("output")==root or op["opcode"] == "call" and root in self.abi.volatile or op["opcode"] == "system_transition" for row in records for op in row["operations"])):
                self.variables["parameter:"+root] = Variable(name, parameter_type, initial.get(root,width), "input:"+root, True, [parameter["evidence"]])
                self.variables[root] = Variable(self.fresh("result" if root==self.abi.return_register else "argument_value"),ctype,width,root,False,["machine_width"])
        for slot in self.frame.slots:
            slot["name"] = self.fresh(slot["name"])
            ctype = f"uint8_t[{slot['size']}]" if slot["overlap"] else integer_type(slot["size"] * 8)
            self.variables[f"stack:{slot['offset']}"] = Variable(slot["name"], ctype, slot["size"] * 8,
                f"stack:{slot['offset']}", slot["parameter"], ["stable_frame_offset", "access_width"])
        self.expressions = Expressions(self.variables, self.frame, self.bits)
        self.calls, self.unresolved = [], []
        self.callees, self.symbols = context.get("callees", {}), function.get("pseudoc_symbols", {})
        # 经指针槽位调用的已核实调用点（原始指令地址 → {name, slot}），可选。
        self.site_names = context.get("call_site_names") or {}
        # Apple arm64：可变参数全部经栈传递（每个占 8 字节槽），固定参数仍用寄存器。
        self.variadic_on_stack = architecture == "arm64" and str(context.get("kind", "")).lower() in {"macho", "mach-o"}
        # 调用点（返回地址入栈之前）第一个栈实参相对栈指针的偏移。
        self.outgoing_base = self.abi.stack_argument_base - (self.abi.word if architecture in {"x86", "x86_64"} else 0)
        # 自递归调用按本函数自己的签名恢复（见 calls.restore_call 的 own）：原始入口、定义名、形参与返回类型。
        own_start = signature_function["start"]
        self.own_signature = self._own_signature(function, context, own_start)
        # 按本函数签名恢复的自递归调用个数：有自递归调用时签名保留全部栈形参（实参按同一列表给出）。
        self.own_calls = 0

    def _own_signature(self, function, context, start):
        """自递归调用要用的签名：形参按函数定义中的顺序（与 reconstruct 输出签名时遍历 variables 的顺序相同），
        寄存器形参写成 ("register", 寄存器, 类型)，栈形参写成 ("stack", 调用点第 i 个栈实参, 类型)。
        栈形参不是按字对齐的单个标量（数组、跨字）时无法逐个对应实参，返回 None（按普通调用恢复）。"""
        parameters = []
        for key, variable in self.variables.items():
            if not variable.parameter:
                continue
            if key.startswith("stack:"):
                offset = int(key.split(":", 1)[1]) - self.abi.stack_argument_base
                if ("[" in variable.ctype or offset < 0 or offset % self.abi.word
                        or variable.width > self.abi.word * 8 or self.abi.name == "unknown"):
                    return None
                parameters.append(("stack", offset // self.abi.word, variable.ctype))
            else:
                parameters.append(("register", key.split(":", 1)[1] if key.startswith("parameter:") else key, variable.ctype))
        return {"target": start, "name": definition_name(function, context, start), "parameters": parameters,
                "return_type": self.profile.get("return_type")}

    @property
    def prologue_pushes(self):
        """入口块开头连续的压栈指令（中间只允许帧指针脚手架）的地址。"""
        cached = self.__dict__.get("_prologue_pushes")
        if cached is None:
            cached, start = set(), self.function.get("start")
            block = self.blocks.get(start)
            for row in block.records if block is not None else ():
                kinds = [operation["opcode"] for operation in row["operations"]]
                if kinds and all(kind == "stack_push" for kind in kinds):
                    cached.add(row["addr"])
                elif all((row["addr"], index) in self.frame.scaffolding for index in range(len(kinds))):
                    continue
                else:
                    break
            self.__dict__["_prologue_pushes"] = cached
        return cached

    @property
    def stack_address_escapes(self):
        """栈地址是否被复制到其它寄存器（lea/mov/add 基于 sp/帧指针）：此时栈内容可能经指针被读取。"""
        cached = self.__dict__.get("_stack_address_escapes")
        if cached is None:
            roots = {self.abi.stack_pointer, self.abi.frame_pointer}
            cached = self.__dict__["_stack_address_escapes"] = any(
                operation["opcode"] in {"assign", "address_writeback"} and operation.get("output") not in roots
                and _mentions(operation.get("expression", {}), roots)
                for row in self.records for operation in row["operations"])
        return cached

    def stack_argument(self, at, index):
        """调用点 at 处第 index 个栈实参槽的当前值；栈指针偏移未知或该槽从未被访问时返回 None。"""
        offset = self.frame.before.get(at, {}).get(self.abi.stack_pointer)
        if offset is None or self.abi.name == "unknown":
            return None
        width = self.abi.word * 8
        offset += self.outgoing_base + index * self.abi.word
        slot = self.frame.slot(offset, width)
        if slot is None:
            return None
        if not slot["overlap"] and slot["size"] * 8 == width:
            return Value("variable", width, name=slot["name"], ctype=integer_type(width), effect=slot.get("escaped", False))
        return Value("slot_access", width, name=slot["name"], number=offset - slot["offset"], effect=slot.get("escaped", False))

    def writeback_step(self, operation):
        """基址回写的立即数增量；栈/帧指针、寄存器偏移或无法解析的地址返回 None（保持原来的未识别处理）。"""
        root = operation.get("output")
        attributes = operation.get("attributes", {})
        if root not in self.variables or root in {self.abi.stack_pointer, self.abi.frame_pointer}:
            return None
        from .stack import _address_tree, affine
        try:
            shape = affine(_address_tree(attributes.get("address", "")), {root: 0})
        except Exception:
            # 语法错误已由 parse_address 处理为 None；到这里的是非字符串地址、嵌套过深等意外情况，
            # 仍按未识别回写处理，但留下调试日志以免掩盖上游缺陷。
            _log.debug("回写地址无法分析，按未识别处理", exc_info=True)
            return None
        if not shape or shape[0] != 1:
            return None
        step = shape[1]
        if attributes.get("mode") == "post_index":
            try:
                step += int(str(attributes.get("offset", "")).lstrip("#"), 0)
            except ValueError:
                return None
        elif attributes.get("mode") != "pre_index":
            return None
        return step

    def site(self, row, at):
        """调用/跳转指令的原始地址对应的已核实导入名；没有时返回 None。"""
        if not self.site_names:
            return None
        address = row.get("original_address", row.get("addr", at)) if isinstance(row, dict) else at
        return self.site_names.get(address)

    def fresh(self, name):
        name = identifier(name)
        if name in {"auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else", "enum", "extern", "float", "for", "goto", "if", "inline", "int", "long", "register", "restrict", "return", "short", "signed", "sizeof", "static", "struct", "switch", "typedef", "union", "unsigned", "void", "volatile", "while", "_Bool", "_Atomic", "_Complex", "_Generic", "_Imaginary", "_Noreturn", "_Static_assert", "_Thread_local"}:
            name += "_value"
        base, index = name, 2
        while name in self.used_names:
            name, index = f"{base}_{index}", index + 1
        self.used_names.add(name)
        return name

    def temporary(self, prefix, width, ctype=None):
        name = self.fresh(f"{prefix}_{len(self.variables) + 1}")
        self.variables[name] = Variable(name, ctype or integer_type(width), width, "temporary", evidence=["captured_value"])
        return Value("variable", width, name=name, ctype=self.variables[name].ctype)

    def assign(self, block, root, value, operation, at):
        if root not in self.variables:
            return
        variable = self.variables[root]
        attributes = operation.get("attributes", {})
        width, shift = attributes.get("destination_width", operation.get("width", self.bits)), attributes.get("bit_offset", 0)
        if width < variable.width and not attributes.get("zero_upper"):
            old = self.expressions.variable(root)
            # 部分写入（setcc al、mov bl, …）是对寄存器整数值的位段合并：指针类型的变量先按地址整数参与运算，
            # 合并结果是整数（再按变量类型转换）。不能对指针做 &/|，也不能把合并结果标成指针。
            merged = variable.ctype
            if "*" in variable.ctype:
                merged = integer_type(variable.width)
                old = cast(old, merged, variable.width)
            mask = ((1 << width) - 1) << shift
            preserved = Value("and", variable.width, (old, Value("constant", variable.width, number=((1 << variable.width) - 1) ^ mask)))
            inserted = cast(value, integer_type(width), width)
            if shift:
                inserted = Value("shl", variable.width, (cast(inserted, integer_type(variable.width), variable.width), Value("constant", variable.width, number=shift)))
            value = Value("or", variable.width, (preserved, inserted), ctype=merged)
        elif width < variable.width and _signed_value(value):
            # 写 W 位并清零高位（x86-64 写 32 位寄存器）：带符号类型的值（movsx 的结果、x86_idiv_quo_32 的
            # 返回值…）直接转换成更宽的类型时 C 会做符号扩展，而机器清零高位。先转为 W 位无符号再扩展。
            value = cast(value, integer_type(width), width)
        value = cast(value, variable.ctype, variable.width)
        block.statements.append(Statement("assign", value, variable.name, at))

    def wide_arithmetic(self, block, operation, at, snapshots=None):
        """x86 单操作数 MUL/IMUL、DIV/IDIV：把 multiply_wide/divide_wide 精确还原为写回两个寄存器切片的赋值。

        乘法：低半 = (uintW)(a*b)，高半 = 2W 位乘积（无符号零扩展/带符号符号扩展）的高 W 位；
        除法：商与余数由前导中会在 #DE（除零、商溢出）时陷入的 x86_(u|i)div_quo/rem_W 给出。
        两个结果都要读到原始输入，而输出会覆盖 rax/rdx：先把次结果（高半/余数）算进临时变量，再写主结果
        （低半/商）的目的，最后把临时变量写回次结果的目的；两次求值都在任何写回之前读输入，两个调用的实参
        文本相同。输入统一转为 W 位无符号类型（带符号的值不会在扩展时被符号扩展）；只有带副作用的输入
        （内存源操作数）先快照一次，内存只读一次。商的调用携带 #DE（有副作用，结果无人使用时也保留）；
        余数与商在同一条件下陷入，因此余数的调用是纯的，无人使用时整句删除。缺少 wide_outputs 时返回 False。
        snapshots：乘法同时是会被读取的标志来源（CF/OF）时，run 已把两个输入快照到比较变量，直接复用。
        """
        attributes = operation["attributes"]
        outputs = attributes.get("wide_outputs")
        opcode, operands = operation["opcode"], operation.get("inputs", ())
        expected = 2 if opcode == "multiply_wide" else 3
        roles = {"low", "high"} if opcode == "multiply_wide" else {"quotient", "remainder"}
        # 先核对信息完整（两个目的寄存器都是已知变量、角色齐全、输入个数正确），再发射语句，避免半途回退。
        if not outputs or len(outputs) != 2 or len(operands) != expected:
            return False
        if {descriptor.get("role") for descriptor in outputs} != roles or any(
                descriptor.get("output") not in self.variables for descriptor in outputs):
            return False
        width, signed = operation["width"], bool(attributes.get("signed"))
        captured = []
        if snapshots is not None and len(snapshots) == len(operands):
            captured, operands = list(snapshots), ()
        for expression in operands:
            value = self.expressions.lift(expression, at)
            value = cast(value, integer_type(value.width), value.width)
            if not value.pure:
                # 内存源操作数（div qword ptr [rbx] 等）：两个结果共用一次读取。
                temporary = self.temporary("wide_operand", value.width, integer_type(value.width))
                self.assign(block, temporary.name, value, {"width": temporary.width}, at)
                value = temporary
            captured.append(value)
        unsigned = integer_type(width)
        if opcode == "multiply_wide" and len(captured) == 2:
            wide = integer_type(2 * width)

            def extend(operand):
                if signed:
                    return cast(cast(operand, integer_type(width, True), width), integer_type(2 * width, True), 2 * width)
                return cast(operand, wide, 2 * width)
            product = Value("mul", 2 * width, (extend(captured[0]), extend(captured[1])), ctype=integer_type(2 * width, signed))
            shifted = Value("lshr", 2 * width, (cast(product, wide, 2 * width), Value("constant", 2 * width, number=width, ctype=wide)), ctype=wide)
            results = {"low": Value("mul", width, (captured[0], captured[1]), ctype=unsigned),
                       "high": cast(shifted, unsigned, width)}
        else:
            kind, result_type = ("idiv" if signed else "udiv"), integer_type(width, signed)
            results = {"quotient": Value("call", width, tuple(captured), name=f"x86_{kind}_quo_{width}", ctype=result_type, effect=True),
                       "remainder": Value("call", width, tuple(captured), name=f"x86_{kind}_rem_{width}", ctype=result_type)}
        primary, secondary = ("low", "high") if opcode == "multiply_wide" else ("quotient", "remainder")
        descriptors = {descriptor["role"]: descriptor for descriptor in outputs}
        # 次结果先进临时变量（读到的是指令执行前的输入），主结果直接写回，最后写回次结果。
        deferred = results[secondary]
        temporary = self.temporary("high_half" if secondary == "high" else "remainder", width, deferred.ctype)
        block.statements.append(Statement("assign", deferred, temporary.name, at))
        for role, value in ((primary, results[primary]), (secondary, temporary)):
            descriptor = descriptors[role]
            self.assign(block, descriptor["output"], value,
                        {"width": descriptor["destination_width"], "attributes": descriptor}, at)
        return True

    def predicate(self, predicate, comparisons, at):
        kind = predicate.get("kind")
        if kind in {"zero_test", "bit_test"}:
            left = self.expressions.lift(predicate["value"], at)
            if kind == "bit_test":
                bit = self.expressions.lift(predicate["bit"], at)
                left = Value("and", left.width, (left, Value("shl", left.width, (Value("constant", left.width, number=1), bit))))
            return Value("compare", 1, (left, Value("constant", left.width, number=0)), name="==" if predicate["relation"] == "eq" else "!=", ctype="bool")
        comparison = comparisons.get(predicate.get("origin"))
        relation = predicate.get("relation")
        if not comparison and comparisons.get("latest"):
            # 没有分析器给出的直接比较来源时，按最近一次（或汇合点共享的）标志来源还原。
            value = self.flag_predicate(comparisons["latest"], predicate)
            if value is not None:
                return value
        if comparison and relation != "flags":
            left, right = comparison
            if predicate.get("domain") == "floating":
                unordered = Value("call", 1, (left, right), name="isunordered", ctype="bool")
                if relation == "unordered":
                    return unordered
                if relation == "ordered":
                    return Value("logical_not", 1, (unordered,))
                clause = Value("compare", 1, (left, right), name={"eq": "==", "ne": "!=", "gt": ">", "ge": ">=", "lt": "<", "le": "<="}[relation], ctype="bool")
                return Value("logical_or" if predicate.get("unordered") else "logical_and", 1,
                    (unordered if predicate.get("unordered") else Value("logical_not", 1, (unordered,)), clause))
            width = predicate["width"]
            ctype = integer_type(width, predicate.get("domain") == "signed")
            return Value("compare", 1, (cast(left, ctype, width), cast(right, ctype, width)),
                name={"eq": "==", "ne": "!=", "gt": ">", "ge": ">=", "lt": "<", "le": "<="}[relation], ctype="bool")
        self.unresolved.append({"address": at, "kind": "condition", "code": predicate.get("code")})
        return Value("call", 1, (Value("string", name=str(predicate.get("code", "unknown"))),), name="unresolved_condition", ctype="bool", effect=True)

    def explicit_registers(self):
        """各块入口处：所有到达路径上、最近一次调用之后都被显式赋值的寄存器。

        与 run() 中逐条维护的规则相同（跳过序言脚手架；调用清空；其它有输出的操作加入），
        只是跨块按“交集”传播，使 ldr x0, … ; cbz x0, … ; bl f 这类跨分支的实参也被列出。
        函数入口为空集，因此只是原样传入的入口参数不会被当作实参。
        """
        from .cfg import predecessors
        parents = predecessors(self.blocks)
        entry = self.function["start"]
        scaffolding = self.frame.scaffolding

        def transfer(block, current):
            current = set(current)
            for row in block.records:
                for index, operation in enumerate(row["operations"]):
                    if (row["addr"], index) in scaffolding:
                        continue
                    if operation["opcode"] == "call":
                        current.clear()
                    elif operation.get("output"):
                        current.add(operation["output"])
            return frozenset(current)

        inbound, after = {}, {}
        for _ in range(len(self.blocks) + 1):
            changed = False
            for address, block in self.blocks.items():
                if address == entry:
                    start = frozenset()
                else:
                    values = [after[parent] for parent in parents[address] if parent in after]
                    if not values:
                        continue
                    start = frozenset.intersection(*values)
                inbound[address] = start
                result = transfer(block, start)
                if after.get(address) != result:
                    after[address], changed = result, True
            if not changed:
                break
        return inbound

    @staticmethod
    def flag_predicate(model, predicate):
        """由标志来源模型（见 flagmodel）还原条件码对应的 C 条件；无法精确表达时返回 None。

        model 为 (kind, 快照变量元组, 宽度)。每种来源只还原能由其操作数精确表达的条件：
        例如 inc/dec 不写进位，因而不还原无符号条件；移位只知道 Z/N，只还原相等与符号位。
        """
        from ..microcode.conditions import INTEGER_RELATIONS, evaluate_condition
        kind, values, width = model
        family, code = predicate.get("family"), predicate.get("code")
        relations = INTEGER_RELATIONS.get(family, {})
        zero = Value("constant", width, number=0)

        def compare(left, right, relation, domain):
            ctype = integer_type(width, domain == "signed")
            return Value("compare", 1, (cast(left, ctype, width), cast(right, ctype, width)),
                         name=_RELATION_OPERATORS[relation], ctype="bool")

        def either(left, right):
            return Value("logical_or", 1, (left, right))

        def both(left, right):
            return Value("logical_and", 1, (left, right))

        if kind.startswith("ccmp:"):
            # ccmp a, b, #nzcv, cond：cond 成立时标志来自 inner(a, b)，否则为常量 nzcv。
            _, inner, nzcv = kind.split(":")
            condition, rest = values[0], values[1:]
            inner_value = Recovery.flag_predicate((inner, rest, width), predicate)
            if inner_value is None:
                return None
            try:
                constant = evaluate_condition(predicate, flags={"N": bool(int(nzcv) & 8), "Z": bool(int(nzcv) & 4),
                                                                "C": bool(int(nzcv) & 2), "V": bool(int(nzcv) & 1)})
            except (TypeError, ValueError, KeyError):
                return None
            if constant is None:
                return None
            return either(Value("logical_not", 1, (condition,)), inner_value) if constant else both(condition, inner_value)

        sign = _SIGN_CODES.get(family, {}).get(code)
        equality = _ZERO_CODES.get(family, {}).get(code)
        if kind in {"flags_umul", "flags_smul"}:
            # x86 MUL/IMUL：CF = OF = W 位乘积超出 W 位（无符号 / 带符号），由前导 umul/smul_overflow_W 精确给出；
            # SF/ZF/AF/PF 机器未定义，相应条件不还原。
            if family != "x86" or code not in _MULTIPLY_CODES or width not in {8, 16, 32, 64}:
                return None
            unsigned = integer_type(width)
            overflow = Value("call", 1, tuple(cast(value, unsigned, width) for value in values),
                             name=f"{'s' if kind == 'flags_smul' else 'u'}mul_overflow_{width}", ctype="bool")
            return overflow if _MULTIPLY_CODES[code] else Value("logical_not", 1, (overflow,))
        if kind == "flags_bit_test":
            # x86 bt/bts/btr/btc：CF = (操作数 >> 取模后的位索引) & 1；只还原 CF 条件（b/ae），
            # ZF/SF/OF 机器未定义，相应条件不还原。
            if family != "x86":
                return None
            operand, bit_index = values
            unsigned = integer_type(width)
            selected = Value("and", width, (Value("lshr", width, (cast(operand, unsigned, width),
                cast(bit_index, unsigned, width)), ctype=unsigned), Value("constant", width, number=1, ctype=unsigned)), ctype=unsigned)
            if code in {"b", "c", "nae"}:
                return compare(selected, zero, "ne", "bitvector")
            if code in {"ae", "nb", "nc"}:
                return compare(selected, zero, "eq", "bitvector")
            return None
        if kind in {"flags_sub", "flags_sub_nc", "flags_sub_cinv"}:
            left, right = values
            if code in relations:
                domain, relation = relations[code]
                if kind == "flags_sub_nc" and domain == "unsigned":
                    return None  # inc/dec 保留原进位，无符号条件取决于更早的指令
                if kind == "flags_sub_cinv" and domain == "unsigned":
                    # x86 加常数：CF 是进位（a >= -k），恰是减法借位的反面。
                    relation = {"lt": "ge", "ge": "lt", "gt": "lt", "le": "ge"}[relation]
                return compare(left, right, relation, domain)
            if sign:
                return compare(Value("sub", width, (left, right), ctype=integer_type(width)), zero, sign, "signed")
            return None
        if kind == "flags_add":
            left, right = values
            total = Value("add", width, (left, right), ctype=integer_type(width))
            if equality:
                return compare(total, zero, equality, "bitvector")
            if sign:
                return compare(total, zero, sign, "signed")
            carry = _ADD_CARRY_CODES.get(family, {}).get(code)
            if carry:
                # 无符号加法的进位：截断后的和小于任一加数。
                flags = {"C": compare(total, left, "lt", "unsigned"), "!C": compare(total, left, "ge", "unsigned"),
                         "Z": compare(total, zero, "eq", "bitvector"), "!Z": compare(total, zero, "ne", "bitvector")}
                if "|" in carry:
                    first, second = carry.split("|")
                    return either(flags[first], flags[second])
                if "&" in carry:
                    first, second = carry.split("&")
                    return both(flags[first], flags[second])
                return flags[carry]
            if code in relations and relations[code][0] == "signed" and width <= 32:
                # N == V 等价于精确和 >= 0：在 64 位中求精确和再比较。
                narrow, wide = integer_type(width, True), "int64_t"
                exact = Value("add", 64, (cast(cast(left, narrow, width), wide, 64), cast(cast(right, narrow, width), wide, 64)), ctype=wide)
                return Value("compare", 1, (exact, Value("constant", 64, number=0)),
                             name=_RELATION_OPERATORS[relations[code][1]], ctype="bool")
            return None
        if kind == "flags_sar":
            left, count = values
            if sign:
                return compare(left, zero, sign, "signed")
            if equality:
                return compare(Value("lshr", width, (left, count), ctype=integer_type(width)), zero, equality, "bitvector")
            return None
        if kind in {"test", "flags_logic", "flags_result"}:
            result = Value("and", width, values, ctype=integer_type(width)) if kind == "test" else values[0]
            if equality:
                return compare(result, zero, equality, "bitvector")
            if sign:
                return compare(result, zero, sign, "signed")
            if kind == "flags_result":
                return None  # 只知道 Z/N
            # 逻辑运算清零进位与溢出：带符号关系即结果与 0 的带符号比较。
            if code in relations and relations[code][0] == "signed":
                return compare(result, zero, relations[code][1], "signed")
            carry = _ADD_CARRY_CODES.get(family, {}).get(code)
            if carry == "!C&!Z":
                return compare(result, zero, "ne", "bitvector")
            if carry == "C|Z":
                return compare(result, zero, "eq", "bitvector")
            return None
        return None

    @staticmethod
    def flag_bit(model, name):
        """标志来源模型（见 flagmodel）下单个 AArch64 标志 N/Z/C/V 的 C 布尔表达式；不能精确表达时返回 None。

        flags_sub 等同 a - b：N 为差的符号位，Z 为 a == b，C 为不借位 a >= b（无符号），V 为带符号溢出
        ((a ^ b) & (a ^ (a - b))) < 0；flags_add 等同 s = a + b：C 为进位 s < a（无符号），V 为
        ((a ^ s) & (b ^ s)) < 0；test/flags_logic（ands/tst/bics、加 0）的 C、V 为 0；ccmp 条件不成立时
        取常量 nzcv 中的对应位。其余来源（只知道 Z/N 的移位、x86 inc/dec 等）返回 None。
        """
        kind, values, width = model
        if kind.startswith("ccmp:"):
            _, inner, nzcv = kind.split(":")
            condition, flag = values[0], Recovery.flag_bit((inner, values[1:], width), name)
            if flag is None:
                return None
            # cond ? flag : 常量位，写成 !cond || flag（常量为 1）或 cond && flag（常量为 0）。
            if int(nzcv) >> {"N": 3, "Z": 2, "C": 1, "V": 0}[name] & 1:
                return Value("logical_or", 1, (Value("logical_not", 1, (condition,)), flag))
            return Value("logical_and", 1, (condition, flag))
        unsigned, signed = integer_type(width), integer_type(width, True)
        zero = Value("constant", width, number=0)

        def compare(left, right, operator, ctype):
            return Value("compare", 1, (cast(left, ctype, width), cast(right, ctype, width)), name=operator, ctype="bool")

        def operation(opcode, left, right):
            return Value(opcode, width, (cast(left, unsigned, width), cast(right, unsigned, width)), ctype=unsigned)

        if kind in {"flags_sub", "flags_add"}:
            left, right = values
            result = operation("sub" if kind == "flags_sub" else "add", left, right)
            if name == "N":
                return compare(result, zero, "<", signed)
            if name == "Z":
                return compare(left, right, "==", unsigned) if kind == "flags_sub" else compare(result, zero, "==", unsigned)
            if name == "C":
                return compare(left, right, ">=", unsigned) if kind == "flags_sub" else compare(result, left, "<", unsigned)
            overflow = (operation("and", operation("xor", left, right), operation("xor", left, result)) if kind == "flags_sub"
                        else operation("and", operation("xor", left, result), operation("xor", right, result)))
            return compare(overflow, zero, "<", signed)
        if kind in {"test", "flags_logic"}:
            result = operation("and", *values) if kind == "test" else values[0]
            if name == "N":
                return compare(result, zero, "<", signed)
            if name == "Z":
                return compare(result, zero, "==", unsigned)
            return Value("constant", 1, number=0, ctype="bool")
        return None

    def saved_flags(self, comparisons, at):
        """mrs xN, nzcv 的值：N/Z/C/V 依次放在第 31..28 位，其余位为 0。

        每个标志由当前（或汇合点共享的）标志来源精确还原；来源未知或无法精确表达时写成对应条件码的
        unresolved_condition（N/Z/C/V 分别等价于 mi/eq/hs/vs）并记为未恢复的条件，不用匿名的未知值冒充。
        """
        model, total = comparisons.get("latest"), None
        for name, bit, code in _NZCV_FLAGS:
            flag = self.flag_bit(model, name) if model is not None else None
            if flag is None:
                flag = self.predicate({"family": "arm", "code": code, "relation": "flags"}, comparisons, at)
            if flag.op == "constant" and not flag.number:
                continue  # 逻辑运算清零的 C/V
            part = Value("shl", 64, (cast(flag, "uint64_t", 64), Value("constant", 64, number=bit)), ctype="uint64_t")
            total = part if total is None else Value("or", 64, (total, part), ctype="uint64_t")
        return total if total is not None else Value("constant", 64, number=0, ctype="uint64_t")

    @staticmethod
    def share_flag_captures(reaching, captured):
        """让汇合点的多个标志来源写同一组比较变量，返回 块地址 -> 代表来源。

        reaching 给出每个块入口处可能生效的比较集合。集合内比较的种类、宽度与操作数宽度
        一致时，把它们并成一组并共用代表来源的比较变量：每条到达路径上最后执行的比较
        正好是最后一次写这组变量的语句，所以汇合点读到的就是实际生效的比较操作数。
        种类或宽度不一致的集合不合并，该块的条件保持未还原。
        """
        def signature(origin):
            kind, values, width = captured[origin]
            return kind, width, tuple(value.width for value in values)

        parent = {}

        def find(origin):
            while parent.get(origin, origin) != origin:
                origin = parent[origin]
            return origin

        usable = {}
        for address, origins in reaching.items():
            if not origins or any(origin not in captured for origin in origins):
                continue
            if len({signature(origin) for origin in origins}) != 1:
                continue
            first, *rest = sorted({find(origin) for origin in origins})
            for root in rest:
                parent[root] = first
            usable[address] = origins
        for origins in usable.values():
            for origin in origins:
                root = find(origin)
                if root != origin:
                    captured[origin] = captured[root]
        return {address: find(next(iter(origins))) for address, origins in usable.items()}

    def run(self):
        from .flagflow import consumed_flag_sources, flag_sources, reaching_flag_sets, reads_nzcv
        from .flagmodel import writes_flags
        sources = flag_sources(self.blocks)
        reaching = reaching_flag_sets(self.blocks, self.function.get("start", self.records[0]["addr"]), sources=sources)
        available = available_registers(self.blocks, self.function["start"], self.abi, self.incoming)
        outgoing = {}
        # 只为会被条件读取的标志来源分配比较变量（序言脚手架里的 sub rsp 等不还原）。
        captured_flags, flag_inputs = {}, {}
        for key in sorted(consumed_flag_sources(self.blocks, reaching, sources)):
            if key in self.frame.scaffolding:
                continue
            kind, inputs, width = sources[key]
            values = tuple(self.temporary("comparison", expression["width"]) for expression in inputs)
            if kind.startswith("ccmp:"):
                values = (self.temporary("condition", 1, "bool"),) + values
            captured_flags[key], flag_inputs[key] = (kind, values, width), inputs
        flag_origin = self.share_flag_captures(reaching, captured_flags)
        explicit_in = self.explicit_registers()
        for block in self.blocks.values():
            comparisons, initialized = {}, set(available.get(block.address, ()))
            if block.address in flag_origin:
                comparisons["latest"] = captured_flags[flag_origin[block.address]]
            if block.address == self.function["start"]:
                for key, variable in self.variables.items():
                    if key.startswith("parameter:"):
                        root = key.split(":",1)[1]
                        block.statements.append(Statement("assign",cast(Value("variable",variable.width,name=variable.name,ctype=variable.ctype),self.variables[root].ctype,self.variables[root].width),self.variables[root].name,block.address))
            # 上一次调用之后、所有到达路径上都显式赋值过的寄存器（函数入口为空：入口参数不算）。
            explicit = set(explicit_in.get(block.address, ()))
            for row in block.records:
                at = row["addr"]
                if writes_flags(row) and not any((at, index) in sources for index in range(len(row["operations"]))):
                    comparisons.pop("latest", None)  # cmpxchg、未识别指令等整行改写标志
                for index, operation in enumerate(row["operations"]):
                    opcode, attributes = operation["opcode"], operation.get("attributes", {})
                    # 本操作声明的通用除法语义（division_semantics）：作用于下面 lift 的 udiv/sdiv/urem/srem。
                    self.expressions.division_semantics = declared_division_semantics(attributes)
                    if (at, index) in self.frame.scaffolding:
                        if writes_flags(row, operation):
                            comparisons.pop("latest", None)
                        continue
                    if opcode != "call" and operation.get("output"):
                        explicit.add(operation["output"])  # mov/add/csel/cset 等显式写入
                    model = captured_flags.get((at, index))
                    if model is not None:
                        # 会被读取的标志来源：把（归一后的）操作数快照到比较变量。
                        snapshots = model[1]
                        if model[0].startswith("ccmp:"):
                            # ccmp 先按此前的标志求出自身条件，再快照比较操作数。
                            condition = self.predicate(attributes["condition"], comparisons, at)
                            block.statements.append(Statement("assign", condition, snapshots[0].name, at))
                            snapshots = snapshots[1:]
                        for expression, temporary in zip(flag_inputs[(at, index)], snapshots):
                            value = self.expressions.lift(expression, at)
                            if model[0] == "flags_bit_test" and "*" in (value.ctype or ""):
                                # bt 的操作数参与移位与按位与：指针（含被推断为指针的寄存器）先按地址整数取值，
                                # 否则复制传播后会出现 (uint8_t *)p >> n 这样不合法的 C。
                                value = cast(value, integer_type(temporary.width), temporary.width)
                            block.statements.append(Statement("assign", value, temporary.name, at))
                        if opcode == "compare":
                            comparisons[at] = snapshots  # 分析器给出的直接比较来源
                        comparisons["latest"] = model
                        if opcode != "multiply_wide":
                            continue
                        # x86 单操作数 MUL/IMUL 既建立 CF/OF 又写回 rax/rdx：快照后继续还原乘积（复用快照）。
                        flag_snapshots = snapshots
                    elif writes_flags(row, operation):
                        comparisons.pop("latest", None)
                        if opcode in {"compare", "compare_add", "conditional_compare", "test", "bit_test"}:
                            # 只写标志且无人读取：不建比较变量，但保留操作数里的内存读取等副作用。
                            # bit_test 的写回副作用（bts/btr/btc 的 bit_modify）是本行的另一条操作，单独处理。
                            for expression in operation.get("inputs", ()):
                                value = self.expressions.lift(expression, at)
                                if not value.pure:
                                    block.statements.append(Statement("expression", value, address=at))
                            continue
                    if opcode == "assign":
                        if "proven_frame_offset" in attributes:
                            value = self.expressions.frame_address(attributes["proven_frame_offset"])
                        elif (at, index) in self.frame.frame_addresses:
                            # add x0, sp, #8 这类算术取址：还原为局部变量地址，而不是“未知 sp + 8”。
                            value = self.expressions.frame_address(self.frame.frame_addresses[(at, index)])
                        elif reads_nzcv(operation):
                            # mrs xN, nzcv：由标志来源还原各标志（标志寄存器本身不是 C 变量）。
                            value = self.saved_flags(comparisons, at)
                        elif attributes.get("c11_memory_order") and (value := ordered_load(
                                self.expressions, operation.get("expression"), attributes, at, self.unresolved,
                                str(row["mnemonic"]))) is not None:
                            pass  # AArch64 ldar/ldapr 系列：写成前导的原子加载（见 ordering.py）
                        else:
                            value = self.expressions.lift(operation["expression"], at)
                            if value.effect and operation.get("output") == "x30" and attributes.get("pointer_authentication"):
                                # 返回地址（LR）的认证（autiasp 等）：可读 C 不建模返回地址，认证失败只影响返回
                                # 本身；与 LR 签名一样不单独成句（结果被当作数据使用时仍照常出现）。
                                value = Value(value.op, value.width, value.args, value.name, value.number, value.ctype)
                        self.assign(block, operation.get("output"), value, operation, at)
                        initialized.add(operation.get("output"))
                    elif (opcode in {"fadd", "fsub", "fmul", "fdiv", "integer_to_float",
                                     "float_to_integer", "float_resize"} or opcode.startswith("vec_f")) \
                            and operation.get("output") and "expression" in operation:
                        # 已提升的标量/向量浮点运算与转换：渲染为前导声明的 fp_environment 占位辅助（fadd_W、
                        # signed_to_float_W、float_to_signed_W、float_resize_W、vec_fadd32_128…），结果依赖 FPCR
                        # 舍入/异常，不是精确可求值的整数运算，但也不再是 unresolved_operation。结果不能精确离线
                        # 复现，记一条 fp_environment 未解析项，使重建不自称完整恢复。
                        value = self.expressions.lift(operation["expression"], at)
                        self.assign(block, operation["output"], value, operation, at)
                        initialized.add(operation["output"])
                        self.unresolved.append({"address": at, "kind": "fp_environment_operation", "mnemonic": str(row["mnemonic"])})
                    elif opcode == "compare_float":
                        # Vector lane storage and FP ABI are not source
                        # scalars unless explicitly reconstructed. Keep
                        # the precise NaN/FP-environment operation in IR.
                        self.unknown(block, row)
                        continue
                    elif opcode == "branch":
                        block.predicate = self.predicate(attributes["condition"], comparisons, at)
                    elif opcode == "return":
                        value = None if self.profile.get("return_type") == "void" else self.expressions.variable(self.abi.return_register)
                        if value is not None:
                            ctype = self.profile["return_type"]
                            import re
                            scalar = re.fullmatch(r"u?int(8|16|32|64)_t",ctype)
                            value = cast(value,ctype,int(scalar[1]) if scalar else value.width)
                        block.statements.append(Statement("return", value, address=at))
                    elif opcode == "call":
                        value, evidence = restore_call(operation, self.expressions, self.abi, self.callees, self.symbols, initialized, at,
                            stack_argument=lambda index, at=at: self.stack_argument(at, index), variadic_on_stack=self.variadic_on_stack,
                            explicit=frozenset(explicit), site=self.site(row, at), own=self.own_signature)
                        if evidence.get("argument_evidence") == "own_signature":
                            self.own_calls += 1
                        explicit.clear()
                        self.calls.append(evidence)
                        if not evidence["argument_count_known"]:
                            self.unresolved.append({"address": at, "kind": "call_signature"})
                        elif evidence.get("argument_count_assumed"):
                            self.unresolved.append({"address": at, "kind": "call_signature_assumed"})
                        if evidence["return_extension"] == "unknown_upper_bits":
                            self.unresolved.append({"address": at, "kind": "call_return_upper_bits"})
                        if value.ctype == "void":
                            block.statements.append(Statement("expression", value, address=at))
                            self.assign(block, operation.get("output"), Value("unknown", self.bits), operation, at)
                        else:
                            self.assign(block, operation.get("output"), value, operation, at)
                        volatile = tuple(self.abi.volatile)+tuple(root for root in self.variables if root.startswith(("v","xmm")))
                        for root in volatile or tuple(self.variables):
                            if root != operation.get("output") and root in self.variables and not root.startswith(("stack:","parameter:")):
                                block.statements.append(Statement("assign", Value("unknown", self.variables[root].width), self.variables[root].name, at))
                        initialized.difference_update(volatile or tuple(self.variables))
                        if operation.get("output"):
                            initialized.add(operation["output"])
                    elif opcode == "store":
                        ordered = ordered_store(self.expressions, operation, at, self.unresolved, str(row["mnemonic"])) \
                            if attributes.get("c11_memory_order") else None
                        if ordered is not None:
                            destination, value, release = ordered
                        else:
                            destination = self.expressions.memory(operation["inputs"][0], operation["width"], at)
                            value = self.expressions.lift(operation["inputs"][1], at)
                            release = None
                        # Keep the address's dependencies alive as well as the stored value.
                        if release is not None:
                            # AArch64 stlr 系列：写成前导的原子存储 arm_store_release_W(p, v)（见 ordering.py）。
                            block.statements.append(Statement("expression", release, address=at))
                        elif destination.op == "variable" and not destination.effect:
                            block.statements.append(Statement("assign", cast(value,destination.ctype,operation["width"]), destination.name, at))
                        else:
                            block.statements.append(Statement("store", Value("store", operation["width"], (destination, cast(value,integer_type(operation["width"]),operation["width"])), effect=True), address=at))
                    elif opcode == "bit_modify":
                        # x86 bts/btr/btc 的写回：寄存器形式按 assign 写回；内存形式按 store。
                        if operation.get("output"):
                            value = self.expressions.lift(operation["expression"], at)
                            self.assign(block, operation["output"], value, operation, at)
                            initialized.add(operation["output"])
                        else:
                            destination = self.expressions.memory(operation["inputs"][0], operation["width"], at)
                            value = self.expressions.lift(operation["inputs"][1], at)
                            if destination.op == "variable" and not destination.effect:
                                block.statements.append(Statement("assign", cast(value, destination.ctype, operation["width"]), destination.name, at))
                            else:
                                block.statements.append(Statement("store", Value("store", operation["width"], (destination, cast(value, integer_type(operation["width"]), operation["width"])), effect=True), address=at))
                    elif opcode in {"stack_push", "stack_pop"}:
                        state = self.frame.before.get(at, {})
                        offset = state.get(self.abi.stack_pointer)
                        offset = offset + attributes["delta"] if offset is not None and opcode == "stack_push" else offset
                        slot = self.frame.slot(offset, operation["width"]) if offset is not None else None
                        if slot is None and offset is not None and attributes.get("destination") != self.abi.stack_pointer:
                            # 被调用者保存寄存器的压栈/出栈：该栈槽没有其它显式访问，不属于 C 层状态。
                            saved = (operation["inputs"][0].get("name") if opcode == "stack_push" and operation.get("inputs")
                                     and operation["inputs"][0].get("opcode") == "register" else
                                     next(iter(attributes.get("outputs", ())), None) if opcode == "stack_pop" else None)
                            callee_saved = saved in _CALLEE_SAVED.get(self.abi.name, ())
                            # 序言开头连续压栈里为对齐栈而压入的其它寄存器（如 push rax）：栈地址没有外泄时同样
                            # 不可观察。调用前压入的实参不在序言里，不受影响。
                            alignment = (opcode == "stack_push" and at in self.prologue_pushes
                                         and operation["inputs"][0].get("opcode") == "register"
                                         and not self.stack_address_escapes)
                            if callee_saved or alignment:
                                if opcode == "stack_pop" and saved in self.variables:
                                    # 恢复出的值对本函数未知：显式标为未知（无人读取时会被删除）。
                                    variable = self.variables[saved]
                                    block.statements.append(Statement("assign", Value("unknown", variable.width), variable.name, at))
                                continue
                        if slot is None or attributes.get("destination") == self.abi.stack_pointer:
                            self.unknown(block, row)
                            continue
                        storage = Value("variable", operation["width"], name=slot["name"], ctype=integer_type(operation["width"]), effect=True) if not slot["overlap"] else Value(
                            "slot_access", operation["width"], name=slot["name"], number=offset-slot["offset"], effect=True)
                        if opcode == "stack_push":
                            value = self.expressions.lift(operation["inputs"][0], at)
                            block.statements.append(Statement("store", Value("store", operation["width"], (storage, value), effect=True), address=at))
                        else:
                            self.assign(block, attributes.get("destination"), storage, {"width": operation["width"]}, at)
                    elif opcode in {"set_condition", "select"}:
                        predicate = self.predicate(attributes["condition"], comparisons, at)
                        inputs = operation.get("inputs", ())
                        left = self.expressions.lift(inputs[0], at) if opcode == "select" else Value("constant", operation["width"], number=attributes.get("true_value", 1))
                        right = self.expressions.lift(inputs[1], at) if opcode == "select" else Value("constant", operation["width"], number=0)
                        # CMOV reads its memory source even when the condition
                        # is false; a C ternary alone would suppress that load.
                        if opcode == "select" and not left.pure:
                            captured = self.temporary("loaded_value", left.width, left.ctype)
                            block.statements.append(Statement("assign", left, captured.name, at))
                            left = captured
                        action = attributes.get("false_operation")
                        if action in {"csinc", "csinv", "csneg"}:
                            right = Value("add" if action == "csinc" else "not" if action == "csinv" else "neg", right.width,
                                (right, Value("constant", right.width, number=1)) if action == "csinc" else (right,))
                        if operation.get("output"):
                            # 窄于 64 位时带符号类型的臂先转为无符号（见 unsigned_arms），结果再扩展（写 32 位寄存器清零
                            # 高位、并入更宽变量）时不会被符号扩展；64 位的选择不会再扩展，不加转换。
                            if operation["width"] < 64:
                                left, right = unsigned_arms((left, right), operation["width"])
                            self.assign(block, operation["output"], Value("select", operation["width"], (predicate, left, right)), operation, at)
                        else:
                            self.unknown(block, row)
                    elif opcode == "discard":
                        value = self.expressions.lift(operation["inputs"][0], at)
                        if not value.pure:
                            block.statements.append(Statement("expression", value, address=at))
                    elif opcode == "trap":
                        block.statements.append(Statement("expression", Value("call", name="trap", effect=True), address=at))
                    elif opcode in {"memory_fill", "memory_copy"}:
                        # x86 rep stos/movs：整段填充/按元素升序复制写成显式辅助调用（目的、填充值或源、
                        # 元素个数）；随后的指针与计数更新仍是普通赋值。
                        # 原型为整数（docs/microcode.md）：目的/源寄存器被推断为指针时显式转为整数。
                        arguments = tuple(self.expressions.integer_argument(self.expressions.lift(expression, at))
                                          for expression in operation.get("inputs", ()))
                        helper = f"x86_rep_{'stos' if opcode == 'memory_fill' else 'movs'}{operation['width']}"
                        block.statements.append(Statement("expression", Value("call", args=arguments, name=helper, ctype="void", effect=True), address=at))
                    elif opcode == "system_register_write" and attributes.get("system_register") and operation.get("inputs"):
                        # AArch64 msr tpidr_el0/fpcr/fpsr…：写成 ACLE 的 __arm_wsr64("名字", 值)。
                        name = Value("string_literal", name=str(attributes["system_register"]), ctype="const char *")
                        written = self.expressions.lift(operation["inputs"][0], at)
                        block.statements.append(Statement("expression", Value("call", args=(name, written), name="__arm_wsr64", ctype="void", effect=True), address=at))
                    elif opcode == "system_transition":
                        arguments = tuple(self.expressions.lift(expression, at) for expression in operation.get("inputs", ()))
                        block.statements.append(Statement("opaque", Value("call", args=arguments, name="arm64_supervisor_call", ctype="void", effect=True), address=at))
                        self.unresolved.append({"address": at, "kind": "system_transition", "transition": attributes.get("transition"), "effects": "handler_dependent"})
                        for root, variable in self.variables.items():
                            if not root.startswith(("stack:", "parameter:")) and variable.storage != "temporary":
                                value = Value("call", variable.width, (Value("constant", self.bits, number=row.get("original_address", at)), Value("string", name=root)), name="handler_dependent_value", ctype=variable.ctype)
                                block.statements.append(Statement("assign", value, variable.name, at))
                        initialized.clear()
                    elif opcode == "jump":
                        # Frontier materialization consumes the target once,
                        # including an indirect memory load's side effect.
                        continue
                    elif opcode == "nop" or opcode.startswith("flags_"):
                        continue
                    elif opcode == "address_writeback" and self.writeback_step(operation) is not None:
                        # 前/后变址寻址的基址回写（ldr w0, [x1], #16 等）：base = base + 立即数。
                        step, root = self.writeback_step(operation), operation["output"]
                        if step:
                            value = self.expressions.lift({"opcode": "add", "width": self.bits, "args": [
                                {"opcode": "register", "width": self.bits, "name": root},
                                {"opcode": "constant", "width": self.bits, "value": step}]}, at)
                            self.assign(block, root, value, operation, at)
                        initialized.add(root)
                    elif opcode in {"multiply_wide", "divide_wide"} and attributes.get("wide_outputs"):
                        # x86 单操作数 MUL/IMUL、DIV/IDIV：精确还原写回 rax/rdx（或 al/ah…）的两个结果。
                        if self.wide_arithmetic(block, operation, at, flag_snapshots if model is not None else None):
                            initialized.update(output["output"] for output in attributes["wide_outputs"])
                        else:
                            self.unknown(block, row)
                            initialized.clear()
                            break
                    else:
                        self.unknown(block, row)
                        initialized.clear()
                        break
            if block.terminal == "branch" and block.predicate is None:
                block.predicate = Value("call", 1, name="unresolved_condition", effect=True)
                self.unresolved.append({"address": block.address, "kind": "condition"})
            outgoing[block.address] = set(initialized)
        self.expressions.division_semantics = ""  # 以下不属于任何操作：恢复默认语义
        self.materialize_frontiers(outgoing)
        return self

    def materialize_frontiers(self, outgoing):
        """Keep transfer operands alive without inventing a C return value."""
        additions = []
        address = min(self.blocks) - 1
        for block in list(self.blocks.values()):
            successors = list(block.successors)
            for index, successor in enumerate(successors):
                if successor is not None:
                    continue
                descriptor = block.frontiers[index] if index < len(block.frontiers) else None
                descriptor = descriptor or {"address": block.address, "target": None, "kind": "fallthrough"}
                at = descriptor["address"]
                if descriptor["kind"] == "fallthrough":
                    target = Value("constant", self.bits, number=descriptor["target"]) if isinstance(descriptor.get("target"), int) else Value("unknown", self.bits)
                    value = Value("call", self.bits, (target,), name="unresolved_fallthrough", ctype="void", effect=True)
                else:
                    expression_at = block.records[-1]["addr"] if block.records else at
                    value, evidence = restore_transfer(descriptor, self.expressions, self.abi, self.callees, self.symbols, outgoing.get(block.address, set()), expression_at,
                        stack_argument=lambda index, at=expression_at: self.stack_argument(at, index), variadic_on_stack=self.variadic_on_stack,
                        site=self.site(block.records[-1] if block.records else None, at))
                    evidence["address"] = at
                    self.calls.append(evidence)
                item = {"address": at, "kind": "control_flow_target", "transfer_kind": descriptor["kind"], "target": descriptor.get("target")}
                if descriptor["kind"] != "fallthrough":
                    # 目标已知的尾调用（只是没有 C 返回约定）：记下名字，供函数头说明，不当作“未解析跳转”。
                    if evidence.get("target_kind") == "import_pointer_slot":
                        # 经已核实指针槽位离开本函数：目标是该导入函数（运行时绑定）。
                        item.update(import_name=evidence["name"], import_slot=evidence.get("import_slot"))
                    elif isinstance(descriptor.get("target"), int) and not str(evidence.get("name", "")).startswith("unknown_function"):
                        item["target_name"] = evidence["name"]
                    if "import_name" in item or "target_name" in item:
                        item["arguments_known"] = bool(evidence.get("argument_count_known"))
                self.unresolved.append(item)
                while address in self.blocks:
                    address -= 1
                additions.append(Block(address, statements=[Statement("transfer", value, address=at)], terminal="frontier"))
                successors[index] = address
                address -= 1
            block.successors = tuple(successors)
        self.blocks.update((block.address, block) for block in additions)

    def unknown(self, block, row):
        block.statements.append(Statement("opaque", Value("call", args=(Value("string", name=row["mnemonic"]),), name="unresolved_operation", effect=True), address=row["addr"]))
        self.unresolved.append({"address": row["addr"], "kind": "operation", "mnemonic": row["mnemonic"]})
        roots = tuple(self.variables) if not row.get("supported") else row.get("writes", ())
        for root in roots:
            if root in self.variables and not root.startswith(("stack:","parameter:")):
                variable = self.variables[root]
                block.statements.append(Statement("assign", Value("unknown", variable.width), variable.name, row["addr"]))
