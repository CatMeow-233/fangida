"""Copy propagation and live-variable elimination with side-effect barriers."""
from __future__ import annotations

from dataclasses import replace

from .model import Value
from .types import integer_type


# 重建器自己生成的占位“调用”，不是真实调用，不会写入任何栈槽。
_PSEUDO_CALLS = frozenset({"unknown_arguments", "unresolved_condition", "isunordered", "unresolved_stack_address",
                           "handler_dependent_value", "unresolved_fallthrough"})


def uninitialized_stack_reads(blocks, entry, slots):
    """Must-initialization for source stack storage, including overlapping writes."""
    from .cfg import predecessors
    locals_by_name = {slot["name"]: slot for slot in slots if not slot["parameter"]}
    universe = set(locals_by_name)
    # 地址已外泄（显式取址或作为实参传出）的槽：之后的任一真实调用都可能通过该地址写入它，
    # 因此调用之后的读取不再算作“读取未初始化的栈槽”。
    escaped = {name for name, slot in locals_by_name.items() if slot.get("escaped")}
    parents = predecessors(blocks)
    after = {address: set() if address == entry else set(universe) for address in blocks}

    def events(block):
        for statement in block.statements:
            value = statement.value
            write = None
            if statement.kind == "store":
                destination, value = value.args
                slot = locals_by_name.get(destination.name)
                if slot and destination.width == slot["size"] * 8 and (destination.op == "variable" or destination.op == "slot_access" and destination.number == 0):
                    write = destination.name
            reads, pending = set(), [value]
            calls = False
            while pending:
                item = pending.pop()
                if item is None:
                    continue
                if item.op == "address_of":
                    continue  # &local 只取地址，不读取其内容
                if item.op == "call" and item.name not in _PSEUDO_CALLS:
                    calls = True
                if item.op in {"variable", "slot_access"} and item.name in universe and not (item.op=="variable" and locals_by_name[item.name]["overlap"]):
                    reads.add(item.name)
                pending.extend(item.args)
            yield reads, write
            if calls:
                for name in escaped:
                    yield set(), name
            if statement.kind == "assign" and statement.destination in universe:
                yield set(), statement.destination

    for _ in range(len(blocks) + 1):
        changed = False
        for address, block in blocks.items():
            defined = set.intersection(*(after[parent] for parent in parents[address])) if address != entry and parents[address] else set()
            for _, write in events(block):
                if write:
                    defined.add(write)
            if defined != after[address]:
                after[address], changed = defined, True
        if not changed:
            break
    unknown = set()
    for address, block in blocks.items():
        defined = set.intersection(*(after[parent] for parent in parents[address])) if address != entry and parents[address] else set()
        for reads, write in events(block):
            unknown.update(reads - defined)
            if write:
                defined.add(write)
    return unknown


# 规范化（无替换的 substitute）结果按 Value 实例缓存；结果等于自身时存哨兵，避免自引用环。
_NO_COPIES: dict = {}
_SAME = object()


def substitute(value, copies):
    if value is None:
        return None
    # 子树里没有任何可被替换的名字时，结果只取决于 value 本身：
    # 等价于 substitute(value, {})，可按实例缓存（Value 不可变）。非 dict 的映射走原递归路径。
    if type(copies) is dict and (not copies or copies.keys().isdisjoint(value.variable_names)):
        return _normalized(value)
    return _substitute(value, copies)


def _normalized(value):
    cache = value.__dict__
    cached = cache.get("_dataflow_normalized")
    if cached is None:
        result = _substitute(value, _NO_COPIES)
        cache["_dataflow_normalized"] = _SAME if result is value else result
        return result
    return value if cached is _SAME else cached


def _substitute(value, copies):
    if value.op == "variable" and value.name in copies:
        return copies[value.name]
    original = value.args
    args = tuple(substitute(arg, copies) for arg in original)
    if len(args) == 2 and args[0] == args[1] and args[0].pure:
        if value.op in {"and", "or"}:
            return args[0]
        if value.op in {"sub", "xor"}:
            return Value("constant", value.width, number=0, ctype=value.ctype)
    if value.op == "cast" and args and args[0].op == "constant" and type(args[0].number) is int and "*" not in value.ctype:
        number = args[0].number & ((1 << value.width) - 1)
        if value.ctype.startswith("int") and number & (1 << (value.width - 1)):
            number -= 1 << value.width
        return Value("constant", value.width, number=number, ctype=value.ctype)
    if value.op == "cast" and args and args[0].ctype == value.ctype:
        return args[0]
    if value.op == "cast" and args and args[0].op == "cast" and args[0].width >= value.width and args[0].args[0].width == value.width and args[0].args[0].ctype == value.ctype:
        return args[0].args[0]
    if value.op == "load" and args and args[0].op == "add" and value.width in {8, 16, 32, 64}:
        base, offset = args[0].args
        if base.op == "cast" and base.width == base.args[0].width and "*" in base.args[0].ctype:
            base = base.args[0]
        size = value.width // 8
        index = offset if size == 1 else None
        if offset.op == "shl" and offset.args[1].op == "constant" and 1 << offset.args[1].number == size:
            index = offset.args[0]
        if index is not None and base.ctype == integer_type(value.width) + " *":
            # A64 SXTW was cast into the unsigned address domain before its
            # shift. Recover its signed index when expressing array elements.
            if index.op == "cast" and index.args[0].ctype.startswith("int") and index.width == index.args[0].width:
                index = index.args[0]
            return Value("index", value.width, (base, index), ctype=value.ctype, effect=value.effect)
    # 子表达式全部原样保留时直接复用原对象（与 replace() 结果相等，且保留各项缓存）。
    if all(new is old for new, old in zip(args, original)):
        return value
    if type(value) is Value:
        # 与 dataclasses.replace(value, args=args) 等价（全部字段都是 init 字段），省去反射开销。
        return Value(value.op, value.width, args, value.name, value.number, value.ctype, value.effect)
    return replace(value, args=args)


def _copy_candidate(value):
    if value is None:
        return False
    cache = value.__dict__
    cached = cache.get("_dataflow_copy_candidate")
    if cached is None:
        # 与原递归定义相同；Value 不可变，结果按实例缓存。
        cached = bool(value.pure) and value.op not in {"slot_access", "index", "load", "global"} and all(
            _copy_candidate(child) for child in value.args)
        cache["_dataflow_copy_candidate"] = cached
    return cached


def _copy_states(blocks):
    """Must-copy facts at block entry; disagreement or cycles stay unknown."""
    from .cfg import predecessors
    parents = predecessors(blocks)
    after, before = {}, {}
    # 块的转移函数只取决于入口事实的内容：入口与上一轮相等时直接复用上一轮的出口事实。
    # （事实字典只按名字查找/比较，键顺序不影响任何结果。）
    transfers = {}
    for _ in range(len(blocks) + 1):
        changed = False
        for address, block in blocks.items():
            states = [after[parent] for parent in parents[address] if parent in after]
            copies = {name: value for name, value in states[0].items()
                      if all(state.get(name) == value for state in states[1:])} if states and len(states) == len(parents[address]) else {}
            before[address] = incoming = dict(copies)
            previous = transfers.get(address)
            if previous is not None and previous[0] == incoming:
                copies = previous[1]
                if after.get(address) != copies:
                    after[address], changed = copies, True
                continue
            # copies 此时是本块新建的字典，可以就地更新（before/after/transfers 中的字典不会被改动）。
            dependents = _dependents(copies)
            for statement in block.statements:
                value = substitute(statement.value, copies)
                destination = statement.destination
                if destination:
                    _kill(copies, dependents, destination)
                    if _copy_candidate(value) and destination not in value.variable_names and _size(value) <= 32:
                        _insert(copies, dependents, destination, value)
                if statement.kind == "opaque":
                    copies, dependents = {}, {}
            transfers[address] = (incoming, copies)
            if after.get(address) != copies:
                after[address], changed = copies, True
        if not changed:
            return before
    return {}  # A bounded pass cannot prove an unstable loop's copy facts.


# 复制事实的就地维护：dependents[名字] 记录（可能过期的）以该名字为输入的复制项。
# _kill 与原来的
#     copies = {n: e for n, e in copies.items() if n != destination and destination not in e.variable_names}
# 删除的条目完全相同，且幸存条目保持原有相对顺序；随后插入的新条目同样追加在末尾。
def _dependents(copies):
    dependents = {}
    for name, value in copies.items():
        for variable in value.variable_names:
            dependents.setdefault(variable, []).append(name)
    return dependents


def _kill(copies, dependents, destination):
    copies.pop(destination, None)
    for name in dependents.pop(destination, ()):
        value = copies.get(name)
        if value is not None and destination in value.variable_names:
            del copies[name]


def _insert(copies, dependents, destination, value):
    copies[destination] = value
    for variable in value.variable_names:
        dependents.setdefault(variable, []).append(destination)


def optimize(blocks):
    incoming_copies = _copy_states(blocks)
    for block in blocks.values():
        copies = dict(incoming_copies.get(block.address, {}))
        dependents = _dependents(copies)
        for statement in block.statements:
            statement.value = substitute(statement.value, copies)
            destination = statement.destination
            if destination:
                _kill(copies, dependents, destination)
                value = statement.value
                if _copy_candidate(value) and destination not in value.variable_names and _size(value) <= 32:
                    _insert(copies, dependents, destination, value)
            if statement.kind == "opaque":
                copies, dependents = {}, {}  # Loads/calls are never copy candidates; explicit
                # writes invalidate dependencies while immutable values survive.
        block.predicate = substitute(block.predicate, copies)
    before = {address: set() for address in blocks}
    after = {address: set() for address in blocks}
    for _ in range(len(blocks) + 1):
        changed = False
        for address, block in reversed(list(blocks.items())):
            live = set().union(*(before[target] for target in block.successors if target in blocks))
            after[address] = set(live)
            if block.predicate:
                live.update(block.predicate.variable_names)
            for statement in reversed(block.statements):
                if statement.kind == "assign" and statement.destination not in live and statement.value.pure:
                    continue
                if statement.destination:
                    live.discard(statement.destination)
                live.update(_uses(statement))
            if live != before[address]:
                before[address], changed = live, True
        if not changed:
            break
    # Repeat because removing a dead copy can make its own inputs dead.
    for _ in range(4):
        removed = False
        for address, block in blocks.items():
            live = set(after[address])
            if block.predicate:
                live.update(block.predicate.variable_names)
            kept = []
            for statement in reversed(block.statements):
                if statement.kind == "assign" and statement.destination not in live:
                    if statement.value.pure:
                        removed = True
                        continue
                    statement = replace(statement, kind="expression", destination="")
                if statement.destination:
                    live.discard(statement.destination)
                live.update(_uses(statement))
                kept.append(statement)
            block.statements = list(reversed(kept))
        if not removed:
            break
    return before


def remove_unused_private_stores(blocks, slots):
    private = {slot["name"] for slot in slots if not slot.get("escaped") and not slot["parameter"]}
    observed = set()
    for block in blocks.values():
        if block.predicate:
            observed.update(block.predicate.variable_names)
        for statement in block.statements:
            value = statement.value.args[1] if statement.kind == "store" else statement.value
            if value:
                observed.update(value.variable_names)
    for block in blocks.values():
        block.statements = [statement for statement in block.statements if not (statement.kind=="store" and statement.value.args[0].name in private-observed and statement.value.args[1].pure)]


def combine_zero_initialization(blocks, slots):
    from .model import Value, Statement
    sizes = {slot["name"]: slot["size"] for slot in slots if slot["overlap"]}
    for block in blocks.values():
        result, index = [], 0
        while index < len(block.statements):
            statement=block.statements[index]
            if statement.kind != "store":
                result.append(statement);index+=1;continue
            destination, value=statement.value.args
            if destination.op!="slot_access" or destination.number!=0 or destination.name not in sizes or value.op!="constant" or value.number!=0:
                result.append(statement);index+=1;continue
            end, cursor=index,0
            while end<len(block.statements):
                item=block.statements[end]
                if item.kind!="store":break
                left,right=item.value.args
                if left.op!="slot_access" or left.name!=destination.name or left.number!=cursor or right.op!="constant" or right.number!=0:break
                cursor+=left.width//8;end+=1
            if cursor==sizes[destination.name]:
                result.append(Statement("expression",Value("call",args=(Value("variable",name=destination.name,ctype="uint8_t *"),Value("constant",32,number=0),Value("constant",64,number=cursor)),name="memset",effect=True),address=statement.address));index=end
            else:
                result.append(statement);index+=1
        block.statements=result


def _uses(statement):
    # Statement.uses() 的只读版本：直接返回缓存的 frozenset，不复制。
    return statement.value.variable_names if statement.value is not None else frozenset()


def _size(value):
    """节点数，超过 32 时截为 33（与原先的有界遍历返回值一致），按实例缓存。"""
    cache = value.__dict__
    cached = cache.get("_dataflow_size")
    if cached is None:
        cached = 1
        for child in value.args:
            cached += _size(child)
            if cached > 32:
                cached = 33
                break
        cache["_dataflow_size"] = cached
    return cached
