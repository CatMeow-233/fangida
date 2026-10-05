"""Control-flow structuring via dominator trees and natural-loop regions.

每个基本块恰好输出一次：只有一个前驱的块嵌套在该前驱的分支里；有多个（非回边）
前驱的“汇合块”放在其直接支配者的代码之后、与该支配者同一层，因此 goto 只会向
外层/同层的标签跳转，不会跳进别的 if 分支内部。离开循环的出口块放在循环之后，
以 break 或 goto 到达。很短且以 return 结尾的尾块直接复制到各跳转处（等价于原
控制流）。最后在语法树上把空分支、else-if 链、同一变量与多个常量的比较（switch）、
while/do-while 等写成更常见的形式；这些改写都不改变执行顺序与求值次数。
"""
from __future__ import annotations

from .cfg import regions, predecessors, dominator_tree, natural_loops
from .expressions import format_value, format_number
from .model import Statement, Value


def negate(value):
    if value.op == "compare":
        return Value("compare", 1, value.args, name={"==": "!=", "!=": "==", ">": "<=", ">=": "<", "<": ">=", "<=": ">"}[value.name], ctype="bool")
    if value.op == "logical_not" and value.args and value.args[0].ctype == "bool":
        return value.args[0]
    return Value("logical_not", 1, (value,))


def statement_text(statement):
    if statement.kind == "machine_region":
        from .regions import region_text
        return region_text(statement)
    if statement.kind == "assign":
        return f"{statement.destination} = {format_value(statement.value)};"
    if statement.kind == "return":
        return f"return {format_value(statement.value)};" if statement.value is not None else "return;"
    if statement.kind == "store":
        left, right = statement.value.args
        return f"{format_value(left)} = {format_value(right)};"
    if statement.kind == "expression" and statement.value.op in {"index", "load", "slot_access", "global", "variable"}:
        return f"(void){format_value(statement.value)};"
    if statement.kind == "expression" and statement.value.op not in {"call", "string_literal"}:
        return f"(void)({format_value(statement.value)});"  # 只为副作用求值的表达式
    return f"{format_value(statement.value)};"


# ---------------------------------------------------------------------------
# 语法树
# ---------------------------------------------------------------------------

class Simple:
    """普通语句（statement 非空）或控制转移（kind 为 goto/break/continue/unresolved）。"""
    __slots__ = ("kind", "statement", "target")

    def __init__(self, kind, statement=None, target=None):
        self.kind, self.statement, self.target = kind, statement, target

    def __eq__(self, other):
        return (type(other) is Simple and self.kind == other.kind and self.statement == other.statement
                and self.target == other.target)

    __hash__ = None


class Label:
    __slots__ = ("address",)

    def __init__(self, address):
        self.address = address


class If:
    __slots__ = ("condition", "then", "otherwise")

    def __init__(self, condition, then=None, otherwise=None):
        self.condition, self.then, self.otherwise = condition, then or [], otherwise or []


class Loop:
    __slots__ = ("condition", "body", "do_while", "header")

    def __init__(self, condition, body=None, do_while=False, header=None):
        self.condition, self.body, self.do_while, self.header = condition, body or [], do_while, header


class Switch:
    """switch 语句：cases 为 [(常量 Value, 语句列表)]。"""
    __slots__ = ("value", "cases", "default")

    def __init__(self, value, cases=None, default=None):
        self.value, self.cases, self.default = value, cases or [], default or []


_TRANSFER_STATEMENTS = frozenset({"return", "transfer", "machine_region"})
_CONTINUE = "continue"
MAX_DEPTH = 48
DUPLICATE_STATEMENTS = 3


def _ends_with_transfer(nodes):
    """语句列表的每条执行路径都以显式转移结束（不会落到列表之后）。"""
    if not nodes:
        return False
    last = nodes[-1]
    if isinstance(last, Simple):
        if last.kind in {"goto", "break", "continue", "unresolved"}:
            return True
        return last.statement is not None and last.statement.kind in _TRANSFER_STATEMENTS
    if isinstance(last, If):
        return _ends_with_transfer(last.then) and _ends_with_transfer(last.otherwise)
    return False


class Structurer:
    def __init__(self, blocks, entry, variable_types=None, refine_returns=None, coerce=None):
        """refine_returns（可选）：以最终要打印的 return 语句列表调用（已合并 `x = v; return x`），
        可就地改写其值并返回新的返回类型（或原类型）；结果放在 self.return_type。

        coerce（可选，见 typecheck.TypeCoercion）：输出之前对每条语句、if/while 条件与 switch 的控制表达式做
        指针/整数一致性检查（只在 C 不接受隐式转换处显式转换）；返回类型被细化时先更新其 return_type。"""
        self.blocks, self.entry = blocks, entry
        self.refine_returns = refine_returns
        self.coerce = coerce
        self.return_type = None
        # 变量名 → C 类型；只用于把 `x = v; return x;` 合并时保留 x 的类型转换。
        self.variable_types = variable_types
        self.seen, self.labels = set(), set()
        self.names = {address: f"block_{index + 1}" for index, address in enumerate(blocks)}
        self.structured_branches = self.structured_loops = 0
        self.used_names, self.assigned_names = set(), set()
        self.printed_statements = []
        self.folded_from = {}
        self._joins = None
        self._analyze()

    @property
    def joins(self):
        """兼容旧属性：后支配者汇合点（新算法不再使用，按需计算）。"""
        if self._joins is None:
            self._joins = regions(self.blocks, self.entry)[0]
        return self._joins

    # -- 分析 -------------------------------------------------------------
    def _analyze(self):
        blocks, entry = self.blocks, self.entry
        tree = dominator_tree(blocks, entry)
        order, idom = tree
        self.rpo = {address: index for index, address in enumerate(order)}
        self.parents = predecessors(blocks)
        self.idom = idom
        self.children = {address: [] for address in blocks}
        for address in order[1:]:
            if address in idom:
                self.children[idom[address]].append(address)

        def dominates(left, right):
            while True:
                if left == right:
                    return True
                parent = idom.get(right)
                if parent is None or parent == right:
                    return False
                right = parent

        self.dominates = dominates
        self.forward_parents = {address: {parent for parent in parents if parent in self.rpo and not dominates(address, parent)}
                                for address, parents in self.parents.items()}
        self.loops = natural_loops(blocks, entry, tree)
        by_size = sorted(self.loops, key=lambda item: len(self.loops[item]))
        self.loop_of = {address: [header for header in by_size if address in self.loops[header]] for address in blocks} if self.loops else {}
        self._subtrees = {}
        self.inline = {address: set() for address in blocks}
        self.merges = {address: [] for address in blocks}
        self.after_loop = {address: [] for address in blocks}
        for address in order[1:]:
            parent = idom.get(address)
            if parent is None:
                continue
            exited = [header for header in self.loop_of.get(parent, ()) if address not in self.loops[header]]
            # 循环头直接通往循环外的出口（while 条件不成立）也放到循环之后，便于写成 while (cond)。
            if exited and (parent in exited or not self._closed(address)):
                # 离开循环后还会继续执行的块放在（最外层被离开的）循环之后。
                self.after_loop[exited[-1]].append(address)
            elif len(self.forward_parents[address]) >= 2:
                self.merges[parent].append(address)
            else:
                self.inline[parent].add(address)

    def _subtree(self, address):
        cached = self._subtrees.get(address)
        if cached is None:
            cached, pending = {address}, [address]
            while pending:
                node = pending.pop()
                for child in self.children.get(node, ()):
                    cached.add(child)
                    pending.append(child)
            self._subtrees[address] = cached
        return cached

    def _closed(self, address):
        """该块的支配子树只经由 return/未解析转移离开（复制或就地嵌套都不会落到别处）。"""
        nodes = self._subtree(address)
        return all(successor is None or successor in nodes for node in nodes for successor in self.blocks[node].successors)

    # -- 生成语法树 --------------------------------------------------------
    def _statements(self, block):
        return [Simple("statement", statement) for statement in block.statements]

    def _jump(self, target, follow, context):
        if target is None:
            return [Simple("unresolved")]
        if target == follow or follow == (_CONTINUE, target):
            return []
        loops = context["loops"]
        if loops:
            header, members, loop_follow = loops[-1]
            if target == header:
                return [Simple("continue")]
            if target == loop_follow and target not in members:
                return [Simple("break")]
        duplicate = self._duplicate(target, context)
        if duplicate is not None:
            return duplicate
        return [Simple("goto", target=target)]

    def _duplicate(self, target, context):
        """很短、无分支、最终以 return/转移结束的尾链：复制到跳转处。"""
        chain, node, count = [], target, 0
        while True:
            if node is None or node not in self.blocks or node in self.loops or node in chain:
                return None
            block = self.blocks[node]
            if block.terminal == "branch" or any(statement.kind == "machine_region" for statement in block.statements):
                return None
            count += len(block.statements)
            if count > DUPLICATE_STATEMENTS + 1:
                return None
            chain.append(node)
            if not block.successors:
                break
            if len(block.successors) != 1:
                return None
            node = block.successors[0]
        if not any(statement.kind in _TRANSFER_STATEMENTS for statement in self.blocks[chain[-1]].statements):
            return None
        return [Simple("statement", statement) for address in chain for statement in self.blocks[address].statements]

    def _branch(self, source, target, follow, context, depth):
        if target is not None and target in self.inline.get(source, ()) and target not in self.seen:
            if depth >= MAX_DEPTH:
                # 嵌套过深：改为 goto，块本身放到函数末尾输出。
                self.overflow.append(target)
                return [Simple("goto", target=target)]
            return self._tree(target, follow, context, depth + 1)
        return self._jump(target, follow, context)

    def _sequence(self, address, merges, follow, context, depth):
        """块自身的代码，后接按序排列的汇合块；每段代码落空时进入下一段。"""
        merges = [merge for merge in merges if merge not in self.seen]
        followers = merges + [follow]
        nodes = self._code(address, followers[0], context, depth)
        for index, merge in enumerate(merges):
            if merge in self.seen:
                continue
            nodes += self._labelled(merge, followers[index + 1], context, depth)
        return nodes

    def _labelled(self, address, follow, context, depth):
        """address 的标签后接它的代码。循环头的标签由 _loop 放在循环之前，这里不再重复放置
        （否则同一位置出现两个同名标签，C 中是标签重定义）。"""
        nodes = [] if address in self.loops and address not in self.seen else [Label(address)]
        return nodes + self._tree(address, follow, context, depth)

    def _code(self, address, follow, context, depth):
        block = self.blocks[address]
        self.seen.add(address)
        nodes = self._statements(block)
        successors = block.successors
        if not successors:
            return nodes
        if block.terminal == "branch" and len(successors) == 2:
            true, false = successors
            if true == false:
                if block.predicate is not None and not block.predicate.pure:
                    nodes.append(Simple("statement", Statement("expression", block.predicate, address=address)))
                return nodes + self._branch(address, true, follow, context, depth)
            then = self._branch(address, true, follow, context, depth)
            otherwise = self._branch(address, false, follow, context, depth)
            self.structured_branches += 1
            nodes.append(If(block.predicate, then, otherwise))
            return nodes
        return nodes + self._branch(address, successors[0], follow, context, depth)

    def _tree(self, address, follow, context, depth):
        if address in self.seen:
            return self._jump(address, follow, context)
        if address in self.loops:
            return self._loop(address, follow, context, depth)
        return self._sequence(address, self.merges[address], follow, context, depth)

    def _loop(self, header, follow, context, depth):
        members = self.loops[header]
        after = sorted(self.after_loop[header] + [merge for merge in self.merges[header] if merge not in members],
                       key=lambda item: self.rpo.get(item, 1 << 30))
        inside = [merge for merge in self.merges[header] if merge in members]
        loop_follow = after[0] if after else follow
        inner = {"loops": context["loops"] + [(header, members, loop_follow)]}
        body = self._sequence(header, inside, (_CONTINUE, header), inner, depth + 1)
        self.structured_loops += 1
        nodes = [Label(header), Loop(None, body, header=header)]
        followers = after + [follow]
        for index, item in enumerate(after):
            if item in self.seen:
                continue
            nodes += self._labelled(item, followers[index + 1], context, depth)
        return nodes

    # -- 语法树整理 --------------------------------------------------------
    def _simplify(self, nodes):
        """去掉空分支（空 then 时取反条件）。"""
        result = []
        for node in nodes:
            if isinstance(node, If):
                node.then, node.otherwise = self._simplify(node.then), self._simplify(node.otherwise)
                if not node.then and not node.otherwise:
                    if not node.condition.pure:
                        result.append(Simple("statement", Statement("expression", node.condition)))
                    self.structured_branches -= 1
                    continue
                if not node.then:
                    node.condition, node.then, node.otherwise = negate(node.condition), node.otherwise, []
                result.append(node)
            elif isinstance(node, Loop):
                node.body = self._simplify(node.body)
                result.append(node)
            else:
                result.append(node)
        return result

    def _flatten(self, nodes):
        """then 分支一定转移走时，else 的内容直接放在 if 之后（else-if 链保留）；再整理循环形式。"""
        result = []
        for node in nodes:
            if isinstance(node, If):
                node.then, node.otherwise = self._flatten(node.then), self._flatten(node.otherwise)
                if node.otherwise and _ends_with_transfer(node.then) and not (
                        len(node.otherwise) == 1 and isinstance(node.otherwise[0], If)):
                    tail, node.otherwise = node.otherwise, []
                    result.append(node)
                    result.extend(tail)
                    continue
                result.append(node)
            elif isinstance(node, Loop):
                node.body = self._flatten(node.body)
                result.append(self._loop_form(node))
            elif isinstance(node, Switch):
                node.cases = [(value, self._flatten(case)) for value, case in node.cases]
                node.default = self._flatten(node.default)
                result.append(node)
            else:
                result.append(node)
        return result

    def _loop_form(self, loop):
        body = loop.body
        if loop.condition is None and body and isinstance(body[0], If) and body[0].then == [Simple("break")] and not body[0].otherwise:
            loop.condition, loop.body = negate(body[0].condition), body[1:]
            return loop
        if (loop.condition is None and len(body) > 1 and isinstance(body[-1], If) and body[-1].then == [Simple("break")]
                and not body[-1].otherwise and not _has_continue(body[:-1]) and not any(isinstance(node, Label) for node in body)):
            loop.condition, loop.body, loop.do_while = negate(body[-1].condition), body[:-1], True
        return loop

    def _fold_returns(self, nodes):
        """相邻的 `x = v; return x;` 写成 `return v;`（return 之后不再读取 x）；递归处理各层。"""
        from .dataflow import substitute
        from .readability import simplify_value
        result = []
        for node in nodes:
            if isinstance(node, If):
                node.then, node.otherwise = self._fold_returns(node.then), self._fold_returns(node.otherwise)
            elif isinstance(node, Loop):
                node.body = self._fold_returns(node.body)
            elif isinstance(node, Switch):
                node.cases = [(value, self._fold_returns(body)) for value, body in node.cases]
                node.default = self._fold_returns(node.default)
            previous = result[-1] if result else None
            if (self.variable_types is not None and isinstance(node, Simple) and node.statement is not None
                    and node.statement.kind == "return" and node.statement.value is not None
                    and isinstance(previous, Simple) and previous.statement is not None
                    and previous.statement.kind == "assign"
                    and previous.statement.destination in self.variable_types
                    and previous.statement.destination in node.statement.value.variable_names
                    and (previous.statement.value.pure or _single_unconditional_use(node.statement.value, previous.statement.destination))):
                name, value = previous.statement.destination, previous.statement.value
                ctype = self.variable_types[name]
                if value.ctype != ctype:
                    value = Value("cast", value.width, (value,), ctype=ctype)
                folded = simplify_value(substitute(node.statement.value, {name: value}))
                statement = Statement("return", folded, address=node.statement.address)
                # 记下被并入 return 的赋值地址（调用证据按调用所在的赋值语句地址记录）。
                self.folded_from[id(statement)] = previous.statement.address
                result[-1] = Simple("statement", statement)
                continue
            result.append(node)
        return result

    def _drop_unreachable(self, nodes):
        """无条件转移（return/goto/break/continue/未解析转移，或两臂都转移的 if）之后、
        下一个仍被 goto 引用的标签之前的语句不可达，删除。

        尾块复制到跳转处之后，原位置的汇合块可能已没有任何前驱，这里把它去掉，
        避免在 return 之后输出永远不会执行的代码。返回 (新列表, 是否删除过)。
        """
        result, dead, dropped = [], False, False
        for node in nodes:
            if isinstance(node, Label):
                if node.address in self.labels:
                    dead = False
                if not dead:
                    result.append(node)
                continue
            if dead:
                dropped = True
                continue
            if isinstance(node, If):
                node.then, then_dropped = self._drop_unreachable(node.then)
                node.otherwise, otherwise_dropped = self._drop_unreachable(node.otherwise)
                dropped = dropped or then_dropped or otherwise_dropped
            elif isinstance(node, Loop):
                node.body, body_dropped = self._drop_unreachable(node.body)
                dropped = dropped or body_dropped
            elif isinstance(node, Switch):
                cases = []
                for value, body in node.cases:
                    body, case_dropped = self._drop_unreachable(body)
                    dropped = dropped or case_dropped
                    cases.append((value, body))
                node.cases = cases
                node.default, default_dropped = self._drop_unreachable(node.default)
                dropped = dropped or default_dropped
            result.append(node)
            if not isinstance(node, (Loop, Switch)) and _ends_with_transfer([node]):
                dead = True
        return result, dropped

    def _prune_labels(self, nodes):
        result = []
        for node in nodes:
            if isinstance(node, Label) and node.address not in self.labels:
                continue
            if isinstance(node, If):
                node.then, node.otherwise = self._prune_labels(node.then), self._prune_labels(node.otherwise)
            elif isinstance(node, Loop):
                node.body = self._prune_labels(node.body)
            elif isinstance(node, Switch):
                node.cases = [(value, self._prune_labels(body)) for value, body in node.cases]
                node.default = self._prune_labels(node.default)
            result.append(node)
        return result

    def _switch(self, nodes):
        """同一纯值与互不相同的整数常量逐个比较的 if/else-if 链（至少 3 个分支）写成 switch。"""
        result = []
        for node in nodes:
            if isinstance(node, If):
                node.then, node.otherwise = self._switch(node.then), self._switch(node.otherwise)
                converted = self._as_switch(node)
                result.append(converted if converted is not None else node)
            elif isinstance(node, Loop):
                node.body = self._switch(node.body)
                result.append(node)
            elif isinstance(node, Switch):
                result.append(node)
            else:
                result.append(node)
        return result

    def _as_switch(self, node):
        cases, current, subject = [], node, None
        while True:
            condition = current.condition
            if condition.op != "compare" or condition.name not in {"==", "!="}:
                break
            left, right = condition.args
            if right.op != "constant" or type(right.number) is not int or not left.pure:
                break
            if subject is None:
                subject = left
            elif left != subject:
                break
            matched, rest = (current.then, current.otherwise) if condition.name == "==" else (current.otherwise, current.then)
            if not matched or any(right.number == value.number for value, _ in cases):
                break
            cases.append((right, matched))
            if len(rest) == 1 and isinstance(rest[0], If):
                current = rest[0]
                continue
            current = rest
            break
        if len(cases) < 3:
            return None
        # 剩余部分（不再是同一变量的等值比较）整体作为 default。
        default = [current] if isinstance(current, If) else current
        if any(_has_loop_break(body) for _, body in cases) or _has_loop_break(default):
            return None
        return Switch(subject, cases, default)

    # -- 旧版按后支配者逐块展开的接口（保留以兼容旧调用方；render 不再使用） ----
    def transfer(self, target, indent, loop=None):
        if target is None:
            return [indent + "unresolved_control_flow();"]
        if loop and target == loop[0]:
            return [indent + "continue;"]
        if loop and target not in loop[1]:
            if target == loop[2]:
                return [indent + "break;"]
        self.labels.add(target)
        return [indent + f"goto {self.names[target]};"]

    def walk(self, start, stop=None, depth=1, loop=None):
        lines, address = [], start
        indent = "    " * depth
        if start is None:
            return self.transfer(None, indent, loop)
        if depth >= 48:
            return self.transfer(start, indent, loop)
        while address is not None and address != stop:
            if address not in self.blocks:
                lines += self.transfer(None, indent, loop)
                break
            if loop and address == loop[0] and address in self.seen:
                lines += self.transfer(address, indent, loop)
                break
            if loop and address not in loop[1]:
                lines += self.transfer(address, indent, loop)
                break
            if address in self.seen:
                lines += self.transfer(address, indent, loop)
                break
            block = self.blocks[address]
            members = self.loops.get(address)
            if members and (loop is None or address != loop[0]) and block.terminal != "branch":
                exits = {target for member in members for target in self.blocks[member].successors if target not in members}
                if len(exits) <= 1:
                    outside = next(iter(exits), None)
                    self.seen.add(address)
                    lines.append(f"@label:{address}")
                    lines.append(indent + "while (1) {")
                    lines.extend(indent + "    " + statement_text(statement) for statement in block.statements)
                    child = block.successors[0] if block.successors else None
                    if child != address:
                        lines += self.walk(child, address, depth + 1, (address, members, outside))
                    lines.append(indent + "}")
                    self.structured_loops += 1
                    address = outside
                    continue
            if members and (loop is None or address != loop[0]) and block.terminal == "branch":
                true, false = block.successors
                if (true in members) != (false in members):
                    inside, outside = (true, false) if true in members else (false, true)
                    predicate = block.predicate if inside == true else negate(block.predicate)
                    self.seen.add(address)
                    lines.append(f"@label:{address}")
                    if not block.statements:
                        lines.append(indent + f"while ({format_value(predicate)}) {{")
                    else:
                        lines.append(indent + "while (1) {")
                        lines.extend(indent + "    " + statement_text(statement) for statement in block.statements)
                        lines.append(indent + "    " + f"if ({format_value(negate(predicate))}) break;")
                    lines += self.walk(inside, address, depth + 1, (address, members, outside))
                    lines.append(indent + "}")
                    if outside is None:
                        lines += self.transfer(None, indent, loop)
                    self.structured_loops += 1
                    address = outside
                    continue
            self.seen.add(address)
            lines.append(f"@label:{address}")
            lines.extend(indent + statement_text(statement) for statement in block.statements)
            if not block.successors:
                break
            if block.terminal == "branch":
                true, false = block.successors
                if loop and (true == loop[0] or false == loop[0]):
                    back = true if true == loop[0] else false
                    other = false if back == true else true
                    predicate = block.predicate if back == true else negate(block.predicate)
                    lines.append(indent + f"if ({format_value(predicate)}) continue;")
                    if other is None:
                        lines += self.transfer(None, indent, loop)
                    address = other
                    continue
                if loop and ((true not in loop[1]) != (false not in loop[1])):
                    outside = true if true not in loop[1] else false
                    inside = false if outside == true else true
                    predicate = block.predicate if outside == true else negate(block.predicate)
                    lines.append(indent + f"if ({format_value(predicate)}) {{")
                    lines += self.transfer(outside, indent + "    ", loop)
                    lines.append(indent + "}")
                    address = inside
                    continue
                join = self.joins.get(address)
                if join in self.seen:
                    join = stop
                lines.append(indent + f"if ({format_value(block.predicate)}) {{")
                lines += self.walk(true, join, depth + 1, loop) if true is None or true != join else []
                if false is None or false != join:
                    lines.append(indent + "} else {")
                    lines += self.walk(false, join, depth + 1, loop)
                lines.append(indent + "}")
                self.structured_branches += 1
                address = join
                continue
            address = block.successors[0]
            if address is None:
                lines += self.transfer(None, indent, loop)
        return lines


    # -- 输出 -------------------------------------------------------------
    def _collect_labels(self, nodes):
        for node in nodes:
            if isinstance(node, Simple) and node.kind == "goto":
                self.labels.add(node.target)
            elif isinstance(node, If):
                self._collect_labels(node.then)
                self._collect_labels(node.otherwise)
            elif isinstance(node, Loop):
                self._collect_labels(node.body)
            elif isinstance(node, Switch):
                for _, body in node.cases:
                    self._collect_labels(body)
                self._collect_labels(node.default)

    def _note(self, value):
        if value is not None:
            self.used_names.update(value.variable_names)

    def _print(self, nodes, depth):
        indent = "    " * depth
        lines = []
        for node in nodes:
            if isinstance(node, Label):
                if node.address in self.labels:
                    lines.append(self.names[node.address] + ":")
            elif isinstance(node, Simple):
                if node.kind == "statement":
                    statement = node.statement
                    self.printed_statements.append(statement)
                    self._note(statement.value)
                    if statement.destination:
                        self.assigned_names.add(statement.destination)
                    lines.append(indent + statement_text(statement))
                elif node.kind == "goto":
                    lines.append(indent + f"goto {self.names[node.target]};")
                elif node.kind == "unresolved":
                    lines.append(indent + "unresolved_control_flow();")
                else:
                    lines.append(indent + node.kind + ";")
            elif isinstance(node, If):
                lines += self._print_if(node, depth)
            elif isinstance(node, Loop):
                self._note(node.condition)
                if node.do_while:
                    lines.append(indent + "do {")
                    lines += self._print(node.body, depth + 1)
                    lines.append(indent + f"}} while ({format_value(node.condition)});")
                else:
                    lines.append(indent + f"while ({format_value(node.condition) if node.condition is not None else '1'}) {{")
                    lines += self._print(node.body, depth + 1)
                    lines.append(indent + "}")
            elif isinstance(node, Switch):
                self._note(node.value)
                lines.append(indent + f"switch ({format_value(node.value)}) {{")
                for value, body in node.cases:
                    lines.append(indent + f"case {format_number(value.number, value.width)}:")
                    lines += self._print(body, depth + 1)
                    if not _ends_with_transfer(body):
                        lines.append(indent + "    break;")
                if node.default:
                    lines.append(indent + "default:")
                    lines += self._print(node.default, depth + 1)
                lines.append(indent + "}")
        return lines

    def _print_if(self, node, depth, prefix="if"):
        indent = "    " * depth
        self._note(node.condition)
        lines = [indent + f"{prefix} ({format_value(node.condition)}) {{"] if prefix == "if" else [indent + f"}} else if ({format_value(node.condition)}) {{"]
        lines += self._print(node.then, depth + 1)
        if len(node.otherwise) == 1 and isinstance(node.otherwise[0], If):
            lines += self._print_if(node.otherwise[0], depth, prefix="else if")
            return lines
        if node.otherwise:
            lines.append(indent + "} else {")
            lines += self._print(node.otherwise, depth + 1)
        lines.append(indent + "}")
        return lines

    def render(self):
        self.overflow = []
        context = {"loops": []}
        nodes = self._tree(self.entry, None, context, 1) if self.entry in self.blocks else []
        while self.overflow:
            pending, self.overflow = self.overflow, []
            for address in pending:
                if address not in self.seen:
                    nodes += self._labelled(address, None, context, 1)
        for address in self.blocks:
            if address not in self.seen:
                nodes += self._labelled(address, None, context, 1)
        nodes = self._flatten(self._switch(self._simplify(nodes)))
        self._collect_labels(nodes)
        nodes = self._prune_labels(nodes)
        nodes, dropped = self._drop_unreachable(nodes)
        if dropped:
            # 删掉的死代码里可能有 goto：重新统计仍被引用的标签。
            self.labels = set()
            self._collect_labels(nodes)
            nodes = self._prune_labels(nodes)
        nodes = self._fold_returns(nodes)
        if self.refine_returns is not None:
            statements = {}
            _collect_returns(nodes, statements)
            self.return_type = self.refine_returns(list(statements.values()))
        if self.coerce is not None:
            if self.return_type:
                self.coerce.return_type = self.return_type
            self._coerce(nodes, set())
        return self._print(nodes, 1)

    def _coerce(self, nodes, done):
        """逐条检查语句与条件的 C 类型一致性（复制到多处的尾块共享语句对象，只处理一次）。"""
        for node in nodes:
            if isinstance(node, Simple):
                if node.statement is not None and id(node.statement) not in done:
                    done.add(id(node.statement))
                    self.coerce.statement(node.statement)
            elif isinstance(node, If):
                node.condition = self.coerce.condition(node.condition)
                self._coerce(node.then, done)
                self._coerce(node.otherwise, done)
            elif isinstance(node, Loop):
                if node.condition is not None:
                    node.condition = self.coerce.condition(node.condition)
                self._coerce(node.body, done)
            elif isinstance(node, Switch):
                node.value = self.coerce.scalar(node.value)
                for _, body in node.cases:
                    self._coerce(body, done)
                self._coerce(node.default, done)


def _collect_returns(nodes, found):
    """语法树中所有 return 语句（同一对象只取一次；复制的尾块可能共享语句对象）。"""
    for node in nodes:
        if isinstance(node, Simple):
            if node.statement is not None and node.statement.kind == "return" and node.statement.value is not None:
                found.setdefault(id(node.statement), node.statement)
        elif isinstance(node, If):
            _collect_returns(node.then, found)
            _collect_returns(node.otherwise, found)
        elif isinstance(node, Loop):
            _collect_returns(node.body, found)
        elif isinstance(node, Switch):
            for _, body in node.cases:
                _collect_returns(body, found)
            _collect_returns(node.default, found)


def _single_unconditional_use(value, name):
    """name 在表达式中恰好出现一次，且不在条件求值的分支里（?: 的两臂、&&/|| 的右侧）。

    有副作用的值（载入、调用）只能这样内联，才能保持“恰好求值一次”。
    """
    count = 0

    def visit(item, conditional):
        nonlocal count
        if item.op == "variable" and item.name == name:
            count += 1 if not conditional else 2
            return
        for index, arg in enumerate(item.args):
            visit(arg, conditional or item.op == "select" and index > 0 or item.op in {"logical_and", "logical_or"} and index > 0)

    visit(value, False)
    return count == 1


def _has_continue(nodes):
    for node in nodes:
        if isinstance(node, Simple) and node.kind == "continue":
            return True
        if isinstance(node, If) and (_has_continue(node.then) or _has_continue(node.otherwise)):
            return True
        if isinstance(node, Switch) and (any(_has_continue(body) for _, body in node.cases) or _has_continue(node.default)):
            return True
    return False


def _has_loop_break(nodes):
    for node in nodes:
        if isinstance(node, Simple) and node.kind == "break":
            return True
        if isinstance(node, If) and (_has_loop_break(node.then) or _has_loop_break(node.otherwise)):
            return True
    return False
