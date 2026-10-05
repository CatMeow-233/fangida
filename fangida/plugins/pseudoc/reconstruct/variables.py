"""变量整理：按定义-使用网（web）拆分寄存器变量、按值域确定类型、按用途命名。

一个机器寄存器在函数里常被重复用于不相关的值（字符串指针、32 位累加器、返回值…）。
这里先求到达定义，把到达同一使用点的定义并成一个 web；每个 web 单独确定 C 类型：
- 所有定义的值都是不超过 32 位的无符号值（零扩展载入、32 位运算、非负小常量）→ uint32_t；
- 所有定义都是指针（字符串字面量、返回指针的调用），或使用处把它当指针（作为
  指针参数传入、作为载入的基址）且定义都是指针宽度 → 对应的指针类型。
类型不同的 web 拆成不同变量。使用处若需要原来的类型，显式转换回原类型，因此
每个使用点看到的值与拆分前逐位相同；随后的化简只删除值不变的转换。
最后按用途命名：返回值 result、循环计数 i/j/k、已知函数的参数名与返回值名。
"""
from __future__ import annotations

import re

from .cfg import predecessors, natural_loops
from .model import Value, Variable
from .prototypes import lookup
from .readability import Rewriter, integer_info, _literal_like, _wide_literal, WIDE_STRING_TYPE
from .types import integer_type

_GENERIC = re.compile(r"(?:value|argument_value|result|arg|local)_?\d*(?:_\d+)*")
_CHAR_POINTERS = frozenset({"char *", "const char *"})
_NON_VARIABLE_LEAVES = frozenset({"unknown", "string", "string_literal", "function", "global", "slot_access", "constant"})


def _pointer(ctype):
    return isinstance(ctype, str) and ctype.endswith("*")


def _natural(value, ctype):
    """赋值右侧去掉“转为变量类型”的那层转换后的值。"""
    if value.op == "cast" and value.ctype == ctype:
        return value.args[0]
    return value


def _narrow(value, bits):
    """值一定落在 [0, 2^32) 内（与类型无关）。"""
    if value.op == "constant":
        return type(value.number) is int and 0 <= value.number < 1 << 32
    if value.op in {"compare", "logical_and", "logical_or", "logical_not"}:
        return True
    info = integer_info(value.ctype, bits)
    if info is not None and not info[0] and info[1] <= 32:
        return True
    if value.op == "select":
        return _narrow(value.args[1], bits) and _narrow(value.args[2], bits)
    if value.op == "and" and len(value.args) == 2:
        return any(arg.op == "constant" and type(arg.number) is int and 0 <= arg.number < 1 << 32 for arg in value.args)
    return False


def _pointer_value(value, bits=64):
    if _literal_like(value, bits):
        if _wide_literal(value, bits):
            inner = value
            while inner.op == "cast" and inner.args:
                inner = inner.args[0]
            # 宽字符串字面量（或两臂都是宽字符串的条件表达式）才按 wchar_t 指针；混合时不定类型。
            return WIDE_STRING_TYPE if inner.op == "string_literal" else None
        return "const char *"
    if value.op == "select":
        left, right = _pointer_value(value.args[1]), _pointer_value(value.args[2])
        if left and right:
            return left if left == right else "const char *" if {left, right} <= _CHAR_POINTERS else None
        return None
    if _pointer(value.ctype) and value.op != "cast":
        return value.ctype
    if value.op == "cast" and _pointer(value.ctype) and _pointer(value.args[0].ctype):
        return value.ctype
    return None


class _UnionFind:
    def __init__(self):
        self.parent = {}

    def find(self, item):
        parent = self.parent.setdefault(item, item)
        if parent != item:
            parent = self.parent[item] = self.find(parent)
        return parent

    def union(self, left, right):
        left, right = self.find(left), self.find(right)
        if left != right:
            self.parent[right] = left


def split_webs(blocks, entry, recovery):
    """拆分并重定类型；返回是否改动。"""
    bits = recovery.bits
    candidates = {variable.name: variable for key, variable in recovery.variables.items()
                  if variable.storage == key and not variable.parameter and "[" not in variable.ctype
                  and (integer_info(variable.ctype, bits) or _pointer(variable.ctype))}
    if not candidates or len(blocks) > 1024:
        return False
    candidates = _worth_splitting(blocks, candidates, recovery, bits)
    if not candidates:
        return False
    # 原类型在下面可能被就地改写，先记下。
    original_types = {name: variable.ctype for name, variable in candidates.items()}
    parents = predecessors(blocks)
    # 位向量到达定义：每个定义（含每个变量的“入口值”伪定义）占一位。
    identifiers = [("entry", name) for name in candidates]
    position = {item: index for index, item in enumerate(identifiers)}
    name_mask = {name: 1 << position[("entry", name)] for name in candidates}
    generated, killed = {}, {}
    for address, block in blocks.items():
        last = {}
        for index, statement in enumerate(block.statements):
            if statement.kind == "assign" and statement.destination in candidates:
                key = (address, index)
                position[key] = len(identifiers)
                identifiers.append(key)
                name_mask[statement.destination] |= 1 << position[key]
                last[statement.destination] = key
        generated[address] = sum(1 << position[key] for key in last.values())
        killed[address] = last
    for address, last in killed.items():
        mask = 0
        for name in last:
            mask |= name_mask[name]
        killed[address] = mask
    entry_bits = sum(1 << position[("entry", name)] for name in candidates)
    after = {address: 0 for address in blocks}

    def incoming(address):
        state = entry_bits if address == entry else 0
        for parent in parents[address]:
            state |= after[parent]
        return state

    for _ in range(len(blocks) * 2 + 2):
        changed = False
        for address in blocks:
            state = (incoming(address) & ~killed[address]) | generated[address]
            if after[address] != state:
                after[address], changed = state, True
        if not changed:
            break
    else:
        return False

    def reaching_of(state, name):
        bits_set, found = state & name_mask[name], []
        while bits_set:
            low = bits_set & -bits_set
            found.append(identifiers[low.bit_length() - 1])
            bits_set ^= low
        return found

    webs = _UnionFind()
    uses = {}          # (address, index) -> {name: 某个到达定义}；predicate 用 index = -1
    evidence = {}      # 定义 id -> 指针类型证据
    returned = set()   # 到达 return 语句使用点的定义
    definitions = {}
    for address, block in blocks.items():
        state = incoming(address)
        for index, statement in enumerate(block.statements + [None]):
            value = block.predicate if statement is None else statement.value
            site = (address, -1 if statement is None else index)
            if value is not None:
                names = value.variable_names & candidates.keys()
                mapping = {}
                hints = _statement_evidence(value, names, bits) if names else {}
                for name in names:
                    reaching = reaching_of(state, name)
                    if not reaching:
                        continue
                    webs.find(reaching[0])
                    for other in reaching[1:]:
                        webs.union(reaching[0], other)
                    mapping[name] = reaching[0]
                    if statement is not None and statement.kind == "return":
                        returned.update(reaching)
                    if name in hints:
                        evidence.setdefault(reaching[0], []).extend(hints[name])
                if mapping:
                    uses[site] = mapping
            if statement is not None and statement.kind == "assign" and statement.destination in candidates:
                definition = (address, index)
                webs.find(definition)
                definitions[definition] = statement
                state = (state & ~name_mask[statement.destination]) | (1 << position[definition])
    # 每个 web 的成员定义与证据
    members = {}
    for definition in list(webs.parent):
        members.setdefault(webs.find(definition), []).append(definition)
    pointer_hints = {}
    for definition, hints in evidence.items():
        pointer_hints.setdefault(webs.find(definition), []).extend(hints)
    entry_roots = {root for root, items in members.items() if any(item[0] == "entry" for item in items)}
    info = {}
    for root, items in members.items():
        if root in entry_roots:
            name = next(item[1] for item in items if item[0] == "entry")
            ctype = original_types[name]
        else:
            name = definitions[items[0]].destination
            original = original_types[name]
            values = [_natural(definitions[item].value, original) for item in items]
            ctype = _choose_type(original, values, pointer_hints.get(root, ()), bits) or original
        role = "" if root in entry_roots else _role(name, [definitions[item].value for item in items])
        info[root] = (name, ctype, any(item in returned for item in items), role)
    groups = {}
    for root, (name, ctype, reaches_return, role) in info.items():
        groups.setdefault(name, {}).setdefault((ctype, reaches_return, role), []).append(root)
    # 同一变量里类型相同、且是否作为返回值也相同的 web 共用一个名字。保留原名字的一组：
    # 含入口值的一组（类型不能变）> 作为返回值的一组 > 保持原类型的一组 > 第一组（就地改类型）。
    names = {}
    for name in sorted(groups):
        keys = sorted(groups[name], key=lambda key: (key[0], not key[1]))
        if len(keys) == 1 and keys[0][0] == original_types[name]:
            names[(name,) + keys[0]] = name
            continue
        entry_keys = [key for key in keys if any(root in entry_roots for root in groups[name][key])]
        anchor = (entry_keys[0] if entry_keys else next((key for key in keys if key[1]), None)
                  or next((key for key in keys if key[0] == original_types[name] and not key[2]), None)
                  or next((key for key in keys if key[0] == original_types[name]), None) or keys[0])
        for key in keys:
            ctype = key[0]
            width = integer_info(ctype, bits)[1] if integer_info(ctype, bits) else bits
            if key == anchor:
                if ctype != original_types[name]:
                    variable = candidates[name]
                    variable.ctype, variable.width = ctype, width
                    variable.evidence = list(variable.evidence) + ["def_use_web"]
                names[(name,) + key] = name
            else:
                fresh = recovery.fresh(_base_name(name, ctype))
                recovery.variables["web:" + fresh] = Variable(fresh, ctype, width, candidates[name].storage, False, ["def_use_web"])
                names[(name,) + key] = fresh
    renamed = {}
    for root, (name, ctype, reaches_return, role) in info.items():
        if root in entry_roots:
            continue
        renamed[root] = (names[(name, ctype, reaches_return, role)], ctype)
    if all(new == definitions[root].destination and ctype == original_types[new] for root, (new, ctype) in renamed.items()):
        return False

    def rewrite_uses(value, mapping):
        def visit(rewrite, value, _):
            if value.op == "variable" and value.name in mapping:
                new, ctype = mapping[value.name]
                original = original_types[value.name]
                variable = Value("variable", value.width if ctype == original else (integer_info(ctype, bits) or (False, bits))[1],
                                 name=new, ctype=ctype)
                return variable if ctype == original else Value("cast", value.width, (variable,), ctype=original)
            args = tuple(rewrite(arg) for arg in value.args)
            if all(new is old for new, old in zip(args, value.args)):
                return value
            return Value(value.op, value.width, args, value.name, value.number, value.ctype, value.effect)
        return Rewriter(visit, _NON_VARIABLE_LEAVES)(value)

    for address, block in blocks.items():
        for index, statement in enumerate(block.statements + [None]):
            site = (address, -1 if statement is None else index)
            mapping = {}
            for name, definition in uses.get(site, {}).items():
                root = webs.find(definition)
                if root in renamed:
                    new, ctype = renamed[root]
                    if new != name or ctype != original_types[name]:
                        mapping[name] = (new, ctype)
            if statement is None:
                if mapping and block.predicate is not None:
                    block.predicate = rewrite_uses(block.predicate, mapping)
                continue
            value = rewrite_uses(statement.value, mapping) if mapping and statement.value is not None else statement.value
            if statement.kind == "assign" and statement.destination in candidates:
                root = webs.find((address, index))
                if root in renamed:
                    new, ctype = renamed[root]
                    original = original_types[statement.destination]
                    if ctype != original:
                        natural = _natural(value, original)
                        width = (integer_info(ctype, bits) or (False, bits))[1]
                        value = natural if natural.ctype == ctype else Value("cast", width, (natural,), ctype=ctype)
                    statement.destination = new
            statement.value = value
    return True


def _role(name, values):
    """web 的用途：循环计数（v = v ± 常量）、已知函数的返回值，或空。用途不同的 web 分成不同变量。"""
    if any(_steps_itself(value, name) for value in values):
        return "counter"
    results = set()
    for value in values:
        while value.op == "cast" or value.op == "call" and value.name.startswith("unknown_return_upper"):
            value = value.args[0]
        prototype = lookup(value.name) if value.op == "call" else None
        results.add(prototype.returns_name if prototype is not None else None)
    if len(results) == 1 and None not in results and "" not in results:
        return "call:" + results.pop()
    return ""


def _worth_splitting(blocks, candidates, recovery, bits):
    """只保留拆分后可能换类型或分出返回值的变量（廉价的逐语句预检，避免整函数数据流）。"""
    definitions, returned, hinted = {}, set(), set()
    for block in blocks.values():
        for statement in block.statements:
            value = statement.value
            if statement.kind == "assign" and statement.destination in candidates:
                definitions.setdefault(statement.destination, []).append(value)
            if value is None:
                continue
            if statement.kind == "return":
                returned.update(value.variable_names)
            for call in _calls(value) if value.op in {"call", "cast", "store"} or not value.pure else ():
                prototype = lookup(call.name)
                if prototype is not None:
                    for argument in call.args:
                        while argument.op == "cast":
                            argument = argument.args[0]
                        if argument.op == "variable":
                            hinted.add(argument.name)
            if not value.pure:
                for name in _load_bases(value):
                    hinted.add(name)

    kept = {}
    for name, variable in candidates.items():
        values = [_natural(value, variable.ctype) for value in definitions.get(name, ())]
        if not values:
            continue
        info = integer_info(variable.ctype, bits)
        if (name in hinted or name in returned and len(values) > 1 or _pointer(variable.ctype) or
                len(values) > 1 and any(_steps_itself(value, name) or _role(name, [value]) for value in values) or
                info is not None and info[1] > 32 and any(_narrow(value, bits) for value in values) or
                any(_pointer_value(value) for value in values) or
                any(value.ctype in {"size_t", "long"} for value in values)):
            kept[name] = variable
    return kept


def _load_bases(value):
    pending, found = [value], set()
    while pending:
        item = pending.pop()
        if item.op == "load" and item.args:
            address = item.args[0]
            base = address.args[0] if address.op in {"add", "sub"} and address.args else address
            while base.op == "cast":
                base = base.args[0]
            if base.op == "variable":
                found.add(base.name)
        pending.extend(item.args)
    return found


def retype_parameters(blocks, recovery):
    """未声明原型的整数参数若被当作已知原型的指针实参传入：参数改为该指针类型。

    函数体内原来的使用点一律显式转换回原整数类型，逐位不变；签名只是换了更直观的类型。
    """
    bits = recovery.bits
    changed = {}
    for variable in recovery.variables.values():
        byte_pointer = variable.ctype in {"uint8_t *", "int8_t *"}
        if (not variable.parameter or "declared_prototype" in variable.evidence or variable.storage.startswith("stack:")
                or (integer_info(variable.ctype, bits) or (False, 0))[1] != bits and not byte_pointer):
            continue
        hints = []
        for block in blocks.values():
            for statement in block.statements:
                if statement.value is not None and variable.name in statement.value.variable_names:
                    hints += _prototype_evidence(statement.value, variable.name)
        if not hints:
            continue
        chosen = next((preferred for preferred in ("const char *", "char *") if preferred in hints), hints[0])
        if byte_pointer and chosen not in {"const char *", "char *"}:
            continue  # 字节指针只在当作字符串传入时改成 char 指针（元素宽度相同）
        changed[variable.name] = (variable.ctype, chosen)
        variable.ctype = chosen
        variable.evidence = list(variable.evidence) + ["pointer_argument_use"]
    if not changed:
        return False

    def visit(rewrite, value, _):
        if value.op == "variable" and value.name in changed and value.ctype == changed[value.name][0]:
            original, chosen = changed[value.name]
            return Value("cast", value.width, (Value("variable", bits, name=value.name, ctype=chosen),), ctype=original)
        args = tuple(rewrite(arg) for arg in value.args)
        if all(new is old for new, old in zip(args, value.args)):
            return value
        return Value(value.op, value.width, args, value.name, value.number, value.ctype, value.effect)

    rewrite = Rewriter(visit, _NON_VARIABLE_LEAVES)
    names = changed.keys()
    for block in blocks.values():
        for statement in block.statements:
            if statement.value is not None and not names.isdisjoint(statement.value.variable_names):
                statement.value = rewrite(statement.value)
        if block.predicate is not None and not names.isdisjoint(block.predicate.variable_names):
            block.predicate = rewrite(block.predicate)
    return True


def _prototype_evidence(value, name):
    """变量 name 直接作为已知原型的指针形参传入时，该形参的类型。"""
    found = []
    for call in _calls(value):
        prototype = lookup(call.name)
        if prototype is None:
            continue
        for index, argument in enumerate(call.args[:len(prototype.parameters)]):
            while argument.op == "cast":
                argument = argument.args[0]
            ctype = prototype.parameters[index][1]
            if argument.op == "variable" and argument.name == name and _pointer(ctype):
                found.append(ctype)
    return found


def _statement_evidence(value, names, bits):
    """一条语句里各变量被当作指针使用的证据（一次遍历）：{名字: [指针类型]}。"""
    found = {}

    def base_name(item):
        while item.op == "cast" and item.width == bits:
            item = item.args[0]
        return item.name if item.op == "variable" and item.name in names else None

    if not value.pure:
        for call in _calls(value):
            prototype = lookup(call.name)
            if prototype is None:
                continue
            for index, argument in enumerate(call.args[:len(prototype.parameters)]):
                while argument.op == "cast":
                    argument = argument.args[0]
                ctype = prototype.parameters[index][1]
                if argument.op == "variable" and argument.name in names and _pointer(ctype):
                    found.setdefault(argument.name, []).append(ctype)
    pending = [value]
    while pending:
        item = pending.pop()
        if item.op == "load" and item.args:
            address = item.args[0]
            name = base_name(address.args[0] if address.op in {"add", "sub"} and address.args else address)
            if name is not None:
                found.setdefault(name, []).append(integer_type(item.width) + " *")
        elif item.op == "index" and item.args:
            name = base_name(item.args[0])
            if name is not None:
                base = item.args[0]
                while base.op == "cast":
                    base = base.args[0]
                found.setdefault(name, []).append(base.ctype if _pointer(base.ctype) else (item.ctype or integer_type(item.width)) + " *")
        if not item.args:
            continue
        if item.variable_names.isdisjoint(names):
            continue
        pending.extend(item.args)
    return found


def _choose_type(original, values, hints, bits):
    info = integer_info(original, bits)
    if info is not None and info[1] > 32 and values and all(_narrow(value, bits) for value in values):
        return "uint32_t"
    declared = {value.ctype for value in values}
    if info is not None and len(declared) == 1:
        only = next(iter(declared))
        only_info = integer_info(only, bits)
        if only != original and only_info is not None and only_info[1] == info[1] and only in {"size_t", "long"}:
            # 定义全来自同一声明类型（如 strlen 的 size_t）：沿用该类型。
            return only
    pointers = [_pointer_value(value) for value in values]
    if values and all(pointers):
        if len(set(pointers)) == 1:
            return pointers[0]
        if set(pointers) <= _CHAR_POINTERS:
            return "const char *"
        return None
    if _pointer(original) and values and not hints and all(
            not _pointer(value.ctype) and value.op != "string_literal" and (integer_info(value.ctype, bits) or value.op == "constant")
            for value in values):
        # 推测为指针的寄存器，在这一段里只装整数（常量、计数、算术）且没有被当指针用：按整数显示。
        return integer_type(bits)
    # 使用处的指针证据：定义都必须是指针宽度的值（整数⇄指针往返逐位不变）。
    if hints and info is not None and info[1] == bits and all(
            (integer_info(value.ctype, bits) or (False, 0))[1] == bits or _pointer(value.ctype) for value in values):
        for preferred in ("const char *", "char *"):
            if preferred in hints:
                return preferred
        return hints[0]
    return None


def _base_name(name, ctype):
    # 先给出通用名字（去掉原名的数字后缀，避免 value_11_2 这样的叠加），由 name_variables 按用途再改名。
    return re.sub(r"(?:_\d+)+$", "", name) or "value"


# ---------------------------------------------------------------------------
# 命名
# ---------------------------------------------------------------------------

def name_variables(blocks, entry, recovery):
    """按用途给通用名字（arg_N/value_N/argument_value…）的变量起名。"""
    variables = {variable.name: variable for variable in recovery.variables.values()}
    taken = set()  # 被调函数名：局部变量不能与之同名（否则会遮蔽函数）
    returned = set()
    call_results = {}
    assigned = {}
    parameter_uses = {}
    for block in blocks.values():
        for statement in block.statements:
            value = statement.value
            if statement.kind == "return" and value is not None:
                returned.update(value.variable_names)
            if statement.kind == "assign":
                assigned.setdefault(statement.destination, []).append(value)
            # 调用都带副作用：纯表达式里不会有调用，跳过遍历。
            if value is not None and not value.pure:
                for call in _calls(value):
                    taken.add(call.name)
                    prototype = lookup(call.name)
                    if prototype is None:
                        continue
                    for index, argument in enumerate(call.args[:len(prototype.parameters)]):
                        while argument.op == "cast":
                            argument = argument.args[0]
                        if argument.op == "variable":
                            parameter_uses.setdefault(argument.name, prototype.parameters[index][0])
    for name, values in assigned.items():
        results = set()
        for value in values:
            while value.op == "cast" or value.op == "call" and value.name.startswith("unknown_return_upper"):
                value = value.args[0]
            prototype = lookup(value.name) if value.op == "call" else None
            results.add(prototype.returns_name if prototype is not None and prototype.returns_name else None)
        if len(results) == 1 and None not in results:
            call_results[name] = results.pop()
    for block in blocks.values():
        for statement in block.statements:
            if statement.value is not None and statement.value.has_constants:
                taken.update(_named_constants(statement.value))
    taken.add(str(recovery.function.get("name", "")))
    recovery.used_names.update(name for name in taken if name)
    # 只有存在 v = v ± 常量 形式的赋值时才需要求循环。
    stepping = any(_steps_itself(value, name) for name, values in assigned.items() if _GENERIC.fullmatch(name) for value in values)
    counters = _loop_counters(blocks, entry) if stepping else {}
    mapping = {}
    # 参数先起名：它们出现在签名里，最值得拿到最直接的名字。
    for name, variable in sorted(variables.items(), key=lambda item: not item[1].parameter):
        if not _GENERIC.fullmatch(name) or name in mapping or "[" in variable.ctype:
            continue
        if name.startswith("result") and name in returned:
            continue
        new = None
        if variable.parameter and name.startswith("arg_") and name in parameter_uses:
            new = parameter_uses[name]
        elif not variable.parameter and name in counters:
            new = counters[name]
        elif not variable.parameter and name in call_results:
            new = call_results[name]
        elif not variable.parameter and name in parameter_uses and name not in returned:
            new = parameter_uses[name]
        elif not variable.parameter and variable.ctype in _CHAR_POINTERS:
            new = "str"
        elif not variable.parameter and _pointer(variable.ctype) and not name.startswith("local"):
            new = "ptr"
        elif name.startswith("result") and name not in returned and not variable.parameter:
            new = "value"
        if new and new != name:
            mapping[name] = recovery.fresh(new)
    if not mapping:
        return {}
    for variable in recovery.variables.values():
        if variable.name in mapping:
            variable.name = mapping[variable.name]
    for slot in recovery.frame.slots:
        if slot.get("name") in mapping:
            slot["name"] = mapping[slot["name"]]

    def visit(rewrite, value, _):
        if value.op == "variable" and value.name in mapping:
            return Value(value.op, value.width, value.args, mapping[value.name], value.number, value.ctype, value.effect)
        args = tuple(rewrite(arg) for arg in value.args)
        if all(new is old for new, old in zip(args, value.args)):
            return value
        return Value(value.op, value.width, args, value.name, value.number, value.ctype, value.effect)

    rewrite = Rewriter(visit, _NON_VARIABLE_LEAVES)
    names = mapping.keys()
    for block in blocks.values():
        for statement in block.statements:
            if statement.value is not None and not names.isdisjoint(statement.value.variable_names):
                statement.value = rewrite(statement.value)
            if statement.destination in mapping:
                statement.destination = mapping[statement.destination]
        if block.predicate is not None and not names.isdisjoint(block.predicate.variable_names):
            block.predicate = rewrite(block.predicate)
    return mapping


def _named_constants(value):
    """表达式里以名字出现的函数地址（不会是变量）。"""
    if value.op == "function":
        return (value.name,)
    found = []
    for arg in value.args:
        if arg.has_constants:
            found.extend(_named_constants(arg))
    return found


def _calls(value):
    pending, found = [value], []
    while pending:
        item = pending.pop()
        if item.op == "call":
            found.append(item)
        pending.extend(item.args)
    return found


def _steps_itself(value, name):
    while value.op == "cast":
        value = value.args[0]
    if value.op not in {"add", "sub"} or len(value.args) != 2 or value.args[1].op != "constant":
        return False
    left = value.args[0]
    while left.op == "cast":
        left = left.args[0]
    return left.op == "variable" and left.name == name


def _loop_counters(blocks, entry):
    """循环里形如 v = v ± 常量 且出现在循环内条件中的变量：按出现顺序命名 i、j、k。"""
    try:
        loops = natural_loops(blocks, entry)
    except Exception:
        return {}
    names, result = ("i", "j", "k"), {}
    for header in sorted(loops, key=lambda item: (len(loops[item]), item), reverse=True):
        members = loops[header]
        conditions = set()
        for member in members:
            predicate = blocks[member].predicate if member in blocks else None
            if predicate is not None:
                conditions |= predicate.variable_names
        for member in sorted(members):
            for statement in blocks[member].statements if member in blocks else ():
                if statement.kind != "assign" or statement.destination in result or statement.destination not in conditions:
                    continue
                value = statement.value
                while value.op == "cast":
                    value = value.args[0]
                if value.op in {"add", "sub"} and len(value.args) == 2 and value.args[1].op == "constant":
                    left = value.args[0]
                    while left.op == "cast":
                        left = left.args[0]
                    if left.op == "variable" and left.name == statement.destination and len(result) < len(names):
                        result[statement.destination] = names[len(result)]
    return result
