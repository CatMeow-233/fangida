"""Build control regions from saved semantic terminators, never from bytes."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar

from .model import Block

# 只读 CFG 视图的作用域缓存：一次重建（或一次签名恢复）内，同一个 records 列表对象只构建一次。
# 作用域外 cfg_view 与 build_cfg 完全相同；缓存项持有列表的强引用，id 不会在作用域内被复用。
_VIEW_SCOPE: ContextVar[dict | None] = ContextVar("pseudoc_cfg_view_scope", default=None)


@contextmanager
def view_scope():
    token = _VIEW_SCOPE.set({})
    try:
        yield
    finally:
        _VIEW_SCOPE.reset(token)


def cfg_view(records):
    """只读使用的 CFG（调用方不得修改返回的块）；作用域内对同一 records 列表复用一次构建。"""
    cache = _VIEW_SCOPE.get()
    if cache is None or type(records) is not list:
        return build_cfg(records)
    entry = cache.get(id(records))
    if entry is not None and entry[0] is records and entry[1] == len(records):
        return entry[2]
    blocks = build_cfg(records)
    cache[id(records)] = (records, len(records), blocks)
    return blocks


_TERMINAL_OPCODES = frozenset({"branch", "jump", "return", "trap"})


def _terminal(row):
    # 与 next((op for op in row["operations"] if op["opcode"] in {...}), None) 相同的顺序与异常行为。
    # 另外：核心 CFG 证明不返回的调用（提升时带 noreturn 属性）也终结基本块，且没有任何后继。
    for op in row["operations"]:
        opcode = op["opcode"]
        if opcode in _TERMINAL_OPCODES or opcode == "call" and op.get("attributes", {}).get("noreturn"):
            return op
    return None


def build_cfg(records):
    rows = {row["addr"]: row for row in records}
    leaders = {records[0]["addr"]} if records else set()
    count = len(records)
    terminals = []
    for index, row in enumerate(records):
        terminal = _terminal(row)
        terminals.append(terminal)
        if terminal and terminal["opcode"] != "call":
            # 不返回调用的 target 是被调函数，不是本函数内的块首。
            attributes = terminal.get("attributes", {})
            leaders.update(target for target in (attributes.get("target"), attributes.get("fallthrough")) if target in rows)
        if index + 1 < count and (terminal or row["addr"] + row["size"] != records[index + 1]["addr"]):
            leaders.add(records[index + 1]["addr"])
    blocks, current = {}, None
    # 每个块最后一行在 records 中的位置：其终结操作已在上面算过（行只读，结果相同）。
    last_index = {}
    for index, row in enumerate(records):
        if row["addr"] in leaders:
            current = Block(row["addr"])
            blocks[current.address] = current
        current.records.append(row)
        last_index[id(current)] = index
    instruction_blocks = {row["addr"]: block.address for block in blocks.values() for row in block.records}
    for block in blocks.values():
        last = block.records[-1]
        terminal = terminals[last_index[id(block)]]
        if terminal:
            block.terminal = terminal["opcode"]
            attributes = terminal.get("attributes", {})
            targets = ((attributes.get("target"), attributes.get("fallthrough")) if block.terminal == "branch" else
                       (attributes.get("target"),) if block.terminal == "jump" else ())
        else:
            targets = (last["addr"] + last["size"],)
        block.successors = tuple(instruction_blocks.get(target) for target in targets)
        frontiers = []
        for index, target in enumerate(targets):
            if target in instruction_blocks:
                frontiers.append(None)
                continue
            attributes = terminal.get("attributes", {}) if terminal else {}
            fallthrough = not terminal or block.terminal == "branch" and index == 1 or attributes.get("frontier_kind") == "fallthrough"
            target = attributes.get("external_fallthrough" if block.terminal == "branch" and index == 1 else "external_target", target)
            descriptor = {"address": last.get("original_address", last["addr"]), "target": target,
                          "kind": "fallthrough" if fallthrough else "direct_jump" if isinstance(target, int) else "indirect_jump"}
            if not fallthrough and attributes.get("target_expression"):
                descriptor["target_expression"] = attributes["target_expression"]
            frontiers.append(descriptor)
        block.frontiers = tuple(frontiers)
    return blocks


def predecessors(blocks):
    result = {address: set() for address in blocks}
    for block in blocks.values():
        for target in block.successors:
            if target in result:
                result[target].add(block.address)
    return result


def reachable(blocks, entry):
    seen, pending = set(), [entry]
    while pending:
        address = pending.pop()
        if address in seen or address not in blocks:
            continue
        seen.add(address)
        pending.extend(blocks[address].successors)
    return {address: block for address, block in blocks.items() if address in seen}


def coalesce(blocks, entry):
    """Merge unique linear successors so effects still bound propagation."""
    parents = predecessors(blocks)
    for address in list(blocks):
        if address not in blocks:
            continue
        block = blocks[address]
        while len(block.successors) == 1:
            child = block.successors[0]
            if child == address or child == entry or child not in blocks or len(parents[child]) != 1:
                break
            target = blocks.pop(child)
            block.records.extend(target.records)
            block.successors, block.terminal = target.successors, target.terminal
            block.frontiers = target.frontiers
            for successor in target.successors:
                if successor in parents:
                    parents[successor].discard(child)
                    parents[successor].add(address)
    return blocks


def regions(blocks, entry):
    """Bitset dominators/postdominators and natural loops, bounded by IR rows."""
    addresses = list(blocks)
    position = {address: index for index, address in enumerate(addresses)}
    all_bits = (1 << len(addresses)) - 1
    parents = predecessors(blocks)
    dom = {address: 1 << position[address] if address == entry else all_bits for address in addresses}
    for _ in range(len(blocks) + 1):
        changed = False
        for address in addresses:
            if address == entry:
                continue
            intersection = all_bits
            for parent in parents[address]:
                intersection &= dom[parent]
            value = intersection | (1 << position[address])
            if value != dom[address]:
                dom[address], changed = value, True
        if not changed:
            break
    exit_bit = 1 << len(addresses)
    post = {address: all_bits | exit_bit for address in addresses}
    for _ in range(len(blocks) + 1):
        changed = False
        for address in reversed(addresses):
            intersection = all_bits | exit_bit
            for child in blocks[address].successors or (None,):
                intersection &= post[child] if child in blocks else exit_bit
            value = intersection | (1 << position[address])
            if value != post[address]:
                post[address], changed = value, True
        if not changed:
            break
    joins = {}
    for address in addresses:
        candidates = [other for other in addresses if other != address and post[address] & (1 << position[other])]
        joins[address] = max(candidates, key=lambda other: post[other].bit_count()) if candidates else None
    loops = {}
    for source, block in blocks.items():
        for target in block.successors:
            if target in blocks and dom[source] & (1 << position[target]):
                members, pending = {target, source}, [source] if source != target else []
                while pending:
                    node = pending.pop()
                    for parent in parents[node]:
                        if parent not in members:
                            members.add(parent)
                            pending.append(parent)
                loops.setdefault(target, set()).update(members)
    return joins, loops


def dominator_tree(blocks, entry):
    """(逆后序列表, 直接支配者) —— Cooper–Harvey–Kennedy 迭代算法；只含从入口可达的块。"""
    order, visited = [], set()
    if entry in blocks:
        stack = [(entry, iter(blocks[entry].successors))]
        visited.add(entry)
        while stack:
            node, successors = stack[-1]
            for successor in successors:
                if successor in blocks and successor not in visited:
                    visited.add(successor)
                    stack.append((successor, iter(blocks[successor].successors)))
                    break
            else:
                stack.pop()
                order.append(node)
    order.reverse()
    rank = {address: index for index, address in enumerate(order)}
    parents = predecessors(blocks)
    idom = {entry: entry} if entry in blocks else {}

    def intersect(left, right):
        while left != right:
            while rank[left] > rank[right]:
                left = idom[left]
            while rank[right] > rank[left]:
                right = idom[right]
        return left

    changed = True
    while changed:
        changed = False
        for address in order[1:]:
            processed = [parent for parent in parents[address] if parent in idom]
            if not processed:
                continue
            new = processed[0]
            for parent in processed[1:]:
                new = intersect(parent, new)
            if idom.get(address) != new:
                idom[address], changed = new, True
    return order, idom


def natural_loops(blocks, entry, tree=None):
    """{循环头: 成员集合}：回边 s→h（h 支配 s）对应的自然循环，同一循环头合并。"""
    order, idom = tree or dominator_tree(blocks, entry)
    parents = predecessors(blocks)

    def dominates(left, right):
        while True:
            if left == right:
                return True
            parent = idom.get(right)
            if parent is None or parent == right:
                return False
            right = parent

    loops = {}
    for source in order:
        for target in blocks[source].successors:
            if target in idom and dominates(target, source):
                members, pending = {target, source}, [source] if source != target else []
                while pending:
                    node = pending.pop()
                    for parent in parents[node]:
                        if parent not in members and parent in idom:
                            members.add(parent)
                            pending.append(parent)
                loops.setdefault(target, set()).update(members)
    return loops
