"""ABI selection and parameter evidence; platform inference stays explicit."""
from __future__ import annotations

import ast
from dataclasses import dataclass
from functools import lru_cache

from .cfg import build_cfg, cfg_view, predecessors, reachable


@dataclass(frozen=True)
class ABI:
    name: str
    arguments: tuple[str, ...]
    volatile: tuple[str, ...]
    return_register: str
    stack_pointer: str
    frame_pointer: str
    stack_argument_base: int
    word: int
    confidence: str


def select_abi(architecture, context):
    requested = context.get("abi") or context.get("calling_convention")
    kind = str(context.get("kind", context.get("format", ""))).lower()
    name = requested or ({"arm64": "aapcs64", "arm": "aapcs32"}.get(architecture))
    if not name and architecture == "x86_64":
        name = "win64" if kind in {"pe", "exe", "dll"} else "sysv64" if kind in {"elf", "macho", "mach-o"} else "unknown"
    if not name and architecture == "x86":
        name = "cdecl" if kind in {"elf", "macho", "mach-o"} else "unknown"
    name = {"sysv": "sysv64", "system_v": "sysv64", "ms_x64": "win64", "aapcs": "aapcs32"}.get(name, name)
    confidence = "declared" if requested else "platform_default" if name != "unknown" else "unknown"
    specifications = {
        "sysv64": (("rdi", "rsi", "rdx", "rcx", "r8", "r9"), ("rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"), "rax", "rsp", "rbp", 8, 8),
        "win64": (("rcx", "rdx", "r8", "r9"), ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11"), "rax", "rsp", "rbp", 40, 8),
        "aapcs64": (tuple(f"x{i}" for i in range(8)), tuple(f"x{i}" for i in range(19)), "x0", "sp", "x29", 0, 8),
        "aapcs32": (tuple(f"r{i}" for i in range(4)), ("r0", "r1", "r2", "r3", "r12", "r14"), "r0", "r13", "r11", 0, 4),
        "cdecl": ((), ("eax", "ecx", "edx"), "eax", "esp", "ebp", 4, 4),
    }
    expected = {"sysv64": "x86_64", "win64": "x86_64", "aapcs64": "arm64", "aapcs32": "arm", "cdecl": "x86"}
    if name in specifications and expected[name] == architecture:
        return ABI(name, *specifications[name], confidence)
    wide = architecture in {"x86_64", "arm64"}
    ret, sp, fp = {"x86_64": ("rax", "rsp", "rbp"), "x86": ("eax", "esp", "ebp"),
                   "arm64": ("x0", "sp", "x29"), "arm": ("r0", "r13", "r11")}[architecture]
    return ABI("unknown", (), (), ret, sp, fp, 8 if wide else 4, 8 if wide else 4, "unknown")


@lru_cache(maxsize=8192)
def _address_names(text):
    """地址文本中出现的全部名字（ast.walk 顺序无关，返回不可变 frozenset）；纯函数，有界缓存。"""
    try:
        tree = ast.parse(text, mode="eval")
        return frozenset(node.id for node in ast.walk(tree) if isinstance(node, ast.Name))
    except (SyntaxError, ValueError):
        return frozenset()


def expression_registers(expression):
    result = set()
    _collect_registers(expression, result)
    return result


_REGISTER_OPCODES = frozenset({"register", "float_register"})


def _collect_registers(expression, result):
    """expression_registers 的累加实现：同样的先序遍历与异常顺序，但不为每个节点新建集合。"""
    opcode = expression.get("opcode")
    if opcode in _REGISTER_OPCODES:
        result.add(expression["name"])
    if opcode == "address":
        name = expression.get("name", "")
        if type(name) is str:
            # 只读共享的 frozenset：update 只读取它，不会修改缓存。
            result.update(_address_names(name))
        else:
            try:
                tree = ast.parse(name, mode="eval")
                result.update(node.id for node in ast.walk(tree) if isinstance(node, ast.Name))
            except (SyntaxError, ValueError):
                pass
    for arg in expression.get("args", ()):
        _collect_registers(arg, result)


def instruction_definitions(row, abi=None, machine_roots=()):
    """Explicit writes plus optional ABI clobbers; old callers remain valid."""
    defined = set(row.get("writes", ()))
    for operation in row.get("operations", ()):
        if operation["opcode"] == "call" and abi is not None:
            defined.update(abi.volatile)
        elif operation["opcode"] == "system_transition":
            # An unknown exception handler is a full state boundary. This
            # is not the ordinary function-call volatile-register contract.
            defined.update(machine_roots)
            if abi is not None:
                defined.update(abi.arguments)
    return defined


def incoming_registers(records, entry, abi=None):
    blocks = reachable(cfg_view(records), entry)
    parents = predecessors(blocks)
    machine_roots = {root for row in records for root in (*row.get("reads", ()), *row.get("writes", ()))}
    # 每行的定义集合只依赖只读的行内容，按原顺序算一次后复用（只读共享）。
    definitions = [instruction_definitions(row, abi, machine_roots) for row in records]
    universe = set().union(*definitions) if records else set()
    by_row = {id(row): defined for row, defined in zip(records, definitions)}
    before = {address: set() if address == entry else set(universe) for address in blocks}
    after = {address: set() if address == entry else set(universe) for address in blocks}
    # 每个块的定义集合与迭代无关，只算一次。
    block_definitions = {address: set().union(*(by_row[id(row)] for row in block.records))
                         for address, block in blocks.items()}
    for _ in range(len(blocks) + 1):
        changed = False
        for address, block in blocks.items():
            inputs = set.intersection(*(after[parent] for parent in parents[address])) if parents[address] and address != entry else set()
            outputs = inputs | block_definitions[address]
            if inputs != before[address] or outputs != after[address]:
                before[address], after[address], changed = inputs, outputs, True
        if not changed:
            break
    incoming = set()
    for address, block in blocks.items():
        defined = set(before[address])
        for row in block.records:
            reads = set()
            for operation in row["operations"]:
                for expression in operation.get("inputs", ()):
                    reads.update(expression_registers(expression))
                attributes = operation.get("attributes", {})
                if operation["opcode"] == "assign" and attributes.get("destination_width", 0) < attributes.get("storage_width", 0) and not attributes.get("zero_upper"):
                    reads.add(operation["output"])
            incoming.update(reads - defined)
            defined.update(by_row[id(row)])
    return incoming


def signature(function, records, architecture, context):
    return _signature_and_incoming(function, records, architecture, context)[0]


def _signature_and_incoming(function, records, architecture, context):
    """signature() 的实现；同时返回其内部已算出的 incoming_registers 结果（records 为空时为 None）。

    供 Recovery 复用同一输入（同一 records、入口与 ABI 对象）上的结果，避免重复做数据流不动点。
    返回的集合只读共享。
    """
    abi = select_abi(architecture, {**context, **{key: function[key] for key in ("abi", "calling_convention") if key in function}})
    computed = incoming_registers(records, function.get("start", records[0]["addr"] if records else 0), abi) if records else None
    incoming = computed if computed is not None else set()
    parameters = [{"register": root, "name": f"arg_{index + 1}", "argument_index": index, "evidence": "read_before_definition"}
                  for index, root in enumerate(abi.arguments) if root in incoming]
    declared = function.get("prototype")
    if isinstance(declared, dict) and isinstance(declared.get("parameters"), list):
        parameters = [{**item, "register": item.get("register", abi.arguments[index] if index < len(abi.arguments) else None),
                       "name": item.get("name", f"arg_{index + 1}"), "evidence": "declared_prototype"}
                      for index, item in enumerate(declared["parameters"][:64]) if isinstance(item, dict)]
    return {"abi": abi, "parameters": parameters, "return_type": declared.get("return_type") if isinstance(declared, dict) else None,
            "signature_complete": isinstance(declared, dict) and isinstance(declared.get("parameters"), list) and isinstance(declared.get("return_type"), str), "name": function.get("name", "function")}, computed


def initial_widths(records, entry, abi=None):
    """Widths of incoming values in the entry block, before register reuse."""
    blocks = cfg_view(records)
    block = blocks.get(entry)
    widths, defined = {}, set()
    machine_roots = {root for row in records for root in (*row.get("reads", ()), *row.get("writes", ()))}
    if not block:
        return widths
    def visit(expression, requested=None):
        opcode=expression.get('opcode'); width=requested or expression.get('width',64)
        if opcode=='register' and expression['name'] not in defined:
            widths[expression['name']]=max(widths.get(expression['name'],0),width)
        if opcode=='address':
            for root in expression_registers(expression)-defined:
                widths[root]=max(widths.get(root,0),width)
        for child in expression.get('args',()):
            visit(child,width if opcode in {'extract','truncate'} else None)
    for row in block.records:
        for operation in row['operations']:
            if operation['opcode']=='return':continue
            for expression in operation.get('inputs',()):visit(expression)
        defined.update(instruction_definitions(row, abi, machine_roots))
    return widths


def available_registers(blocks, entry, abi, incoming=()):
    """Must-available values at block entry, including ABI call barriers."""
    parents = predecessors(blocks)
    universe = set(incoming) | {root for block in blocks.values() for row in block.records for root in row.get("writes", ())}
    after = {address: set(incoming) if address == entry else set(universe) for address in blocks}
    before = {}
    for _ in range(len(blocks) + 1):
        changed = False
        for address, block in blocks.items():
            state = set(incoming) if address == entry else set.intersection(*(after[parent] for parent in parents[address])) if parents[address] else set()
            before[address] = set(state)
            for row in block.records:
                for operation in row["operations"]:
                    if operation["opcode"] in {"opaque", "system_transition"}:
                        state.clear()
                    elif operation["opcode"] == "call":
                        state.difference_update(abi.volatile or universe)
                        state = {root for root in state if not root.startswith(("v", "xmm"))}
                        if operation.get("output"):
                            state.add(operation["output"])
                    else:
                        if operation.get("output"):
                            state.add(operation["output"])
                        state.update(operation.get("attributes", {}).get("outputs", ()))
            if state != after[address]:
                after[address], changed = state, True
        if not changed:
            break
    return before


def reaches_return(records, entry):
    """重建图中从入口能否到达任何 return 操作（不返回调用、陷阱和尾跳转都不算）。"""
    blocks = reachable(cfg_view(records), entry)
    return any(operation["opcode"] == "return" for block in blocks.values()
               for row in block.records for operation in row["operations"])


def never_returns(function, records, entry):
    """核心分析已证明函数不返回（function["noreturn"]），且重建图里也确实没有可达的 return。

    两个条件同时成立才把返回类型写成 void：只凭“没看到 return”不够（快照可能截断）。
    """
    return bool(function.get("noreturn")) and bool(records) and not reaches_return(records, entry)


def return_width(records, entry, abi):
    """Largest possible logical return width from reaching definitions."""
    blocks=reachable(cfg_view(records),entry);parents=predecessors(blocks)
    bits=abi.word*8;after={address:bits for address in blocks};returned=[]
    for _ in range(len(blocks)+1):
        changed=False;returned=[]
        for address,block in blocks.items():
            width=max((after[parent] for parent in parents[address]),default=bits) if address!=entry else bits
            for row in block.records:
                for operation in row['operations']:
                    if operation.get('output')==abi.return_register:
                        attrs=operation.get('attributes',{}); destination=attrs.get('destination_width',operation.get('width',bits))
                        width=destination if destination==bits or attrs.get('zero_upper') else bits
                    elif operation['opcode'] in {'opaque', 'system_transition'}:width=bits
                    if operation['opcode']=='return':returned.append(width)
            if after[address]!=width:after[address],changed=width,True
        if not changed:break
    return max(returned,default=bits)
