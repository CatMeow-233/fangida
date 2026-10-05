"""Affine frame tracking, stack arguments and overlapping local storage."""
from __future__ import annotations

import ast
from functools import lru_cache

from .cfg import predecessors


def parse_address(text):
    try:
        tree = ast.parse(text, mode="eval").body
        if any(not isinstance(node, (ast.Expression, ast.BinOp, ast.UnaryOp, ast.Name, ast.Constant,
                                    ast.Add, ast.Sub, ast.Mult, ast.USub, ast.UAdd, ast.Load)) for node in ast.walk(tree)):
            return None
        return tree
    except (SyntaxError, ValueError):
        return None


@lru_cache(maxsize=4096)
def _parse_address_cached(text):
    return parse_address(text)


def _address_tree(text):
    """parse_address 的只读共享版本：同一地址文本只解析一次（有界 LRU，纯函数）。

    返回的 AST 在调用方之间共享，调用方只能读取、不得修改。公开的 parse_address
    仍每次返回新树。非精确 str 的输入走原路径，异常行为不变。
    """
    if type(text) is str:
        return _parse_address_cached(text)
    return parse_address(text)


def affine(node, offsets):
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return (0, node.value)
    if isinstance(node, ast.Name) and node.id in offsets and offsets[node.id] is not None:
        return (1, offsets[node.id])
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        value = affine(node.operand, offsets)
        return (-value[0], -value[1]) if value else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub)):
        left, right = affine(node.left, offsets), affine(node.right, offsets)
        if left is not None and right is not None:
            sign = 1 if isinstance(node.op, ast.Add) else -1
            return left[0] + sign * right[0], left[1] + sign * right[1]
    return None


def machine_offset(expr, offsets):
    opcode = expr.get("opcode")
    if opcode == "register":
        value = offsets.get(expr.get("name"))
        return (1, value) if value is not None else None
    if opcode == "constant":
        width, value = expr["width"], expr["value"]
        return 0, value - (1 << width) if value & (1 << (width - 1)) else value
    if opcode == "address":
        return affine(_address_tree(expr.get("name", "")), offsets)
    if opcode in {"add", "sub"} and len(expr.get("args", ())) == 2:
        left, right = (machine_offset(arg, offsets) for arg in expr["args"])
        if left is not None and right is not None:
            sign = 1 if opcode == "add" else -1
            return left[0] + sign * right[0], left[1] + sign * right[1]
    return None


class Frame:
    def __init__(self, blocks, entry, abi):
        self.abi, self.before, self.scaffolding, self.accesses = abi, {}, set(), []
        self.allocations = set()
        parents = predecessors(blocks)
        states = {address: None for address in blocks}
        states[entry] = {abi.stack_pointer: 0}
        # A differing join offset is unknown; do not name an uncertain slot.
        after = {}
        for _ in range(len(blocks) + 1):
            changed = False
            for address, block in blocks.items():
                if address != entry:
                    available = [after[parent] for parent in parents[address] if parent in after]
                    if not available:
                        continue
                    merged = {root: value for root, value in available[0].items()
                              if all(other.get(root) == value for other in available[1:])}
                    states[address] = merged
                if states[address] is None:
                    continue
                current = dict(states[address])
                for row in block.records:
                    # 不动点阶段的 before 会在循环后整体清空、期间无人读取：只保留键的求值
                    # （异常行为不变），不再为每行复制状态。
                    self.before[row["addr"]] = current
                    for index, operation in enumerate(row["operations"]):
                        self._advance(current, row, index, operation)
                if after.get(address) != current:
                    after[address], changed = current, True
            if not changed:
                break
        self.before.clear()
        self.scaffolding.clear()
        self.allocations.clear()
        # 以算术方式取得的栈地址（如 ARM64 add x0, sp, #8；x86 用 lea 时是 address 表达式，另行处理）：
        # (行地址, 操作序号) -> 帧偏移。下游把它们还原为局部变量的地址，而不是“未知的 sp + 8”。
        self.frame_addresses: dict[tuple[int, int], int] = {}
        for address, block in blocks.items():
            current = dict(states[address] or {})
            for row in block.records:
                self.before[row["addr"]] = dict(current)
                for index, operation in enumerate(row["operations"]):
                    if (operation["opcode"] == "assign"
                            and operation.get("output") not in {abi.stack_pointer, abi.frame_pointer}
                            and "proven_frame_offset" not in operation.get("attributes", {})
                            and operation.get("expression", {}).get("opcode") in {"add", "sub", "register"}):
                        value = machine_offset(operation["expression"], current)
                        if value and value[0] == 1 and abs(value[1]) <= 8 * 1024 * 1024:
                            self.frame_addresses[(row["addr"], index)] = value[1]
                    self._advance(current, row, index, operation)
        saved = {}
        preserved = {abi.frame_pointer, "x30", "r14"}
        if abi.name == "aapcs64":
            preserved.update(f"x{index}" for index in range(19, 29))
        first = blocks.get(entry)
        for row in first.records if first else ():
            for index, operation in enumerate(row["operations"]):
                if operation["opcode"] == "store":
                    source = operation["inputs"][1]
                    offset = self.offset(row["addr"], operation["inputs"][0])
                    if offset is not None and offset < 0 and source.get("opcode") == "register" and source.get("name") in preserved:
                        saved[(offset, operation["width"], source["name"])] = (row["addr"], index)
        for key, saved_at in list(saved.items()):
            start, width, _ = key
            for block in blocks.values():
                for row in block.records:
                    for index, operation in enumerate(row["operations"]):
                        if operation["opcode"] == "store" and (row["addr"], index) != saved_at:
                            offset = self.offset(row["addr"], operation["inputs"][0])
                            if offset is not None and offset < start + width // 8 and start < offset + operation["width"] // 8:
                                saved.pop(key, None)
        restored = set()
        for key, saved_at in list(saved.items()):
            start, width, _ = key
            # Explicit non-restore accesses make the saved value observable.
            for block in blocks.values():
                for row in block.records:
                    for operation in row["operations"]:
                        def observes(expression):
                            if expression.get("opcode") == "load":
                                offset = self.offset(row["addr"], expression["args"][0])
                                if offset is not None and offset < start + width // 8 and start < offset + expression["width"] // 8:
                                    return not (operation["opcode"] == "assign" and operation.get("output") == key[2] and offset == start and expression["width"] == width)
                            return any(observes(arg) for arg in expression.get("args", ()))
                        if any(observes(expression) for expression in operation.get("inputs", ())):
                            saved.pop(key, None)
        for block in blocks.values():
            for row in block.records:
                for index, operation in enumerate(row["operations"]):
                    expression = operation.get("expression", {})
                    if operation["opcode"] == "assign" and expression.get("opcode") == "load":
                        key = (self.offset(row["addr"], expression["args"][0]), expression["width"], operation.get("output"))
                        if key in saved:
                            restored.add(saved[key])
                            restored.add((row["addr"], index))
        self.scaffolding.update(restored)
        for block in blocks.values():
            for row in block.records:
                for index, operation in enumerate(row["operations"]):
                    if (row["addr"], index) in restored:
                        continue
                    def visit(expr):
                        if expr.get("opcode") == "load" and expr.get("args"):
                            offset = self.offset(row["addr"], expr["args"][0])
                            if offset is not None:
                                self.accesses.append((offset, expr["width"]))
                        for arg in expr.get("args", ()):
                            visit(arg)
                    for expr in operation.get("inputs", ()):
                        visit(expr)
                    if operation["opcode"] == "store":
                        offset = self.offset(row["addr"], operation["inputs"][0])
                        if offset is not None:
                            self.accesses.append((offset, operation["width"]))
        self.escaped_offsets = set()
        # 显式取址（assign 地址表达式）的偏移，按操作顺序记录；下面每个槽的 explicit 判定复用，
        # 不再对每个槽重新遍历全部操作并重复计算偏移（self.before 此后不再变化）。
        explicit_offsets = []
        for block in blocks.values():
            for row in block.records:
                for operation in row["operations"]:
                    expression = operation.get("expression", {})
                    if operation["opcode"] == "assign" and expression.get("opcode") == "address":
                        offset = self.offset(row["addr"], expression)
                        if offset is not None:
                            self.escaped_offsets.add(offset)
                            explicit_offsets.append(offset)
        # 算术取得的栈地址与 lea 一样是显式取址。
        for offset in self.frame_addresses.values():
            self.escaped_offsets.add(offset)
            explicit_offsets.append(offset)
        self.addressable_range = None
        for block in blocks.values():
            for row in block.records:
                for operation in row["operations"]:
                    if operation.get("attributes", {}).get("proven_frame_offset") is not None and operation.get("output") not in {abi.stack_pointer, abi.frame_pointer}:
                        self.escaped_offsets.add(operation["attributes"]["proven_frame_offset"])
        escaped_allocations = {allocation for allocation in self.allocations if any(allocation[0] <= offset < allocation[1] for offset in self.escaped_offsets)}
        if escaped_allocations:
            for lower, upper in escaped_allocations:
                self.accesses.append((lower, (upper-lower)*8))
        if self.escaped_offsets and not escaped_allocations:
            lower = min((state.get(abi.stack_pointer, 0) for state in self.before.values()), default=0)
            upper = max((state[abi.frame_pointer] for state in self.before.values() if abi.frame_pointer in state), default=0)
            if lower < upper and upper - lower <= 65536 and all(lower <= offset < upper for offset in self.escaped_offsets):
                self.addressable_range = lower, upper
                self.accesses.append((lower, (upper - lower) * 8))
        self.slots = self._slots()
        call_escapes = {state[root] for block in blocks.values() for row in block.records if any(op["opcode"]=="call" for op in row["operations"])
            for state in [self.before[row["addr"]]] for root in abi.arguments if root in state}
        for slot in self.slots:
            explicit = any(slot["offset"] <= offset < slot["offset"]+slot["size"] for offset in explicit_offsets)
            slot["escaped"] = explicit or any(slot["offset"] <= offset < slot["offset"]+slot["size"] for offset in call_escapes)
            if any(slot["offset"] == lower and slot["size"] == upper-lower for lower,upper in escaped_allocations):
                slot["overlap"] = True
        # A saved frame pointer can also be ordinary data. Hide its push/pop
        # only when no explicit access observes that stack slot.
        for block in blocks.values():
            for row in block.records:
                for index, operation in enumerate(row["operations"]):
                    opcode = operation["opcode"]
                    if opcode in {"stack_push", "stack_pop"}:
                        offset = self.before[row["addr"]].get(abi.stack_pointer)
                        if offset is not None:
                            offset += operation["attributes"]["delta"] if opcode == "stack_push" else 0
                            if self.slot(offset, operation["width"]):
                                self.scaffolding.discard((row["addr"], index))

    def _advance(self, state, row, index, operation):
        opcode, root = operation["opcode"], operation.get("output")
        attributes = operation.get("attributes", {})
        if opcode == "assign":
            previous = state.get(root)
            offset = (1, attributes["proven_frame_offset"]) if "proven_frame_offset" in attributes else machine_offset(operation.get("expression", {}), state)
            if offset and offset[0] == 1 and abs(offset[1]) <= 8 * 1024 * 1024:
                state[root] = offset[1]
                if root == self.abi.stack_pointer and previous is not None and offset[1] < previous and previous-offset[1] <= 65536:
                    self.allocations.add((offset[1], previous))
                if root in {self.abi.stack_pointer, self.abi.frame_pointer}:
                    self.scaffolding.add((row["addr"], index))
            else:
                state.pop(root, None)
        elif opcode in {"stack_push", "stack_pop"}:
            if root in state:
                state[root] += attributes["delta"]
            register = attributes.get("destination")
            source = operation.get("inputs", [{}])[0].get("name")
            if register == self.abi.frame_pointer or source == self.abi.frame_pointer:
                self.scaffolding.add((row["addr"], index))
            for changed in attributes.get("outputs", ()):
                if changed != root:
                    state.pop(changed, None)
            if register == self.abi.stack_pointer:
                state.pop(root, None)
        elif opcode == "address_writeback":
            value = affine(_address_tree(attributes["address"]), state)
            if value and value[0] == 1:
                adjustment = int(str(attributes.get("offset", "0")).lstrip("#"), 0) if attributes["mode"] == "post_index" else 0
                state[root] = value[1] + adjustment
                if root in {self.abi.stack_pointer, self.abi.frame_pointer}:
                    self.scaffolding.add((row["addr"], index))
            else:
                state.pop(root, None)
        elif opcode == "stack_leave":
            if self.abi.frame_pointer in state:
                state[self.abi.stack_pointer] = state[self.abi.frame_pointer] + self.abi.word
            state.pop(self.abi.frame_pointer, None)
            self.scaffolding.add((row["addr"], index))
        elif opcode in {"opaque", "call", "system_transition"}:
            if opcode in {"opaque", "system_transition"} or self.abi.name == "unknown":
                state.clear()
            else:
                for root in self.abi.volatile:
                    state.pop(root, None)
        elif root:
            state.pop(root, None)

    def offset(self, address, expression):
        value = machine_offset(expression, self.before.get(address, {}))
        return value[1] if value and value[0] == 1 else None

    def _slots(self):
        intervals = sorted(set((offset, offset + width // 8) for offset, width in self.accesses if width % 8 == 0))
        groups = []
        for start, end in intervals:
            if groups and start < groups[-1][1]:
                groups[-1][1] = max(groups[-1][1], end)
                groups[-1][2].append((start, end))
            else:
                groups.append([start, end, [(start, end)]])
        return [{"offset": start, "size": end - start, "overlap": len(accesses) > 1 or end - start not in {1, 2, 4, 8} or self.addressable_range == (start, end),
                 "name": f"local_{index + 1}" if start < self.abi.stack_argument_base else f"stack_arg_{index + 1}",
                 "parameter": start >= self.abi.stack_argument_base,
                 "accesses": [{"offset": left, "width": (right - left) * 8} for left, right in accesses]}
                for index, (start, end, accesses) in enumerate(groups)]

    def slot(self, offset, width):
        return next((slot for slot in self.slots if slot["offset"] <= offset and offset + width // 8 <= slot["offset"] + slot["size"]), None)
