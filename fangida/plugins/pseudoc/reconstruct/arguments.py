"""过程间参数用法：由已完成指令快照的读写寄存器与调用图，求每个函数实际使用的参数寄存器。

单个函数的签名恢复只看“入口后先读后写”的寄存器；函数一旦调用别的函数，就无法知道
未改写的参数寄存器会不会被原样转交给被调函数使用，调用处只能写 unknown_arguments()。
这里沿调用图（含尾跳转）做不动点传播：

* 直接使用：入口到读取处的所有路径上都没写过、却被读取的参数寄存器。
* 转交使用：调用（或尾跳转）处尚未写过、而被调函数需要的参数寄存器。
* 导入函数与已知库函数按原型确定参数个数；指向本库自身导出函数的 PLT 桩按本地函数处理。

完整性按寄存器严格判定：除“已证实读取”的寄存器外，再求“可能读取”的寄存器——未知的
去向（间接调用/跳转、未解码等出口、原型个数不定的导入、未知目标）只会让此时“尚未被本函数
写过”的参数寄存器变得不确定（已被覆盖的寄存器里不可能还是调用者传入的值）。两者相等时，
参数个数即已确定（complete）；否则只给出已证实的寄存器，调用处保留 unknown_arguments()。
只读指令快照（不调用解码器、不修改记录）。参数寄存器集合用位掩码表示。
"""
from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

_ARM64_REGISTER = re.compile(r"[wx]([0-9]|[12][0-9]|30)")
_X86_ALIASES = {
    "rdi": ("rdi", "edi", "di", "dil"), "rsi": ("rsi", "esi", "si", "sil"),
    "rdx": ("rdx", "edx", "dx", "dl", "dh"), "rcx": ("rcx", "ecx", "cx", "cl", "ch"),
    "r8": ("r8", "r8d", "r8w", "r8b"), "r9": ("r9", "r9d", "r9w", "r9b"),
    "rax": ("rax", "eax", "ax", "al", "ah"), "r10": ("r10", "r10d", "r10w", "r10b"),
    "r11": ("r11", "r11d", "r11w", "r11b"),
}
_X86_ROOTS = {alias: root for root, aliases in _X86_ALIASES.items() for alias in aliases}
# 清零写法：两个源操作数相同时结果与原值无关（xor esi, esi；eor w1, w1, w1；sub x0, x1, x1），不算读取。
_ZERO_IDIOMS = frozenset({"xor", "sub", "sbb", "pxor", "xorps", "xorpd", "eor"})


def register_root(architecture: str, name: str) -> str:
    """把子寄存器名规范为参数寄存器根名（w1→x1、edi→rdi）；其余名字原样返回。"""
    name = str(name).lower()
    if architecture == "arm64":
        match = _ARM64_REGISTER.fullmatch(name)
        return "x" + match.group(1) if match else name
    if architecture == "x86_64":
        return _X86_ROOTS.get(name, name)
    return name


def _sequence(value: Any) -> Any:
    return value if isinstance(value, (list, tuple)) else ()


class _Bits:
    """寄存器名 → 参数寄存器位（非参数寄存器为 0），按名字缓存。"""

    def __init__(self, architecture: str, arguments: tuple[str, ...]) -> None:
        self.architecture = architecture
        self.index = {root: 1 << position for position, root in enumerate(arguments)}
        self.cache: dict[str, int] = {}

    def mask(self, names: Any) -> int:
        result = 0
        cache = self.cache
        for name in _sequence(names):
            bit = cache.get(name)
            if bit is None:
                bit = cache[name] = self.index.get(register_root(self.architecture, name), 0)
            result |= bit
        return result


class _Local:
    """单个函数的局部事实：直接使用的参数位、调用点（目标, 已写入位）与本地不确定位。

    indirect：只因间接调用（blr/call reg）而不确定的位；按“间接调用的目标只读取调用前显式
    写入的寄存器”这一通行约定时，这些位不计入不确定。
    """

    __slots__ = ("direct", "sites", "uncertain", "indirect")

    def __init__(self, direct: int, sites: list[tuple[int, int]], uncertain: int, indirect: int = 0) -> None:
        self.direct, self.sites, self.uncertain, self.indirect = direct, sites, uncertain, indirect

    @property
    def complete(self) -> bool:  # 兼容诊断用法：本地没有不确定的去向
        return not self.uncertain


# 指令事件：(读取位, 写入位, 种类, 目标)；种类 0 普通、1 直接调用、2 间接调用、3 尾跳转、4 间接出口。
def _local_facts(function: Mapping[str, Any], bits: _Bits, everything: int) -> _Local | None:
    entry = function.get("start")
    blocks = [block for block in _sequence(function.get("blocks")) if isinstance(block, Mapping)]
    if not isinstance(entry, int) or not blocks:
        return None
    by_start = {block.get("start"): block for block in blocks}
    if entry not in by_start:
        return None
    uncertain = 0
    cfg = function.get("cfg") if isinstance(function.get("cfg"), Mapping) else {}
    exits: dict[int, tuple[int, int | None]] = {}
    for item in _sequence(cfg.get("frontier")):
        source = item.get("from") if isinstance(item, Mapping) else None
        reason = item.get("reason") if isinstance(item, Mapping) else None
        if reason == "other_function" and isinstance(item.get("to"), int) and isinstance(source, int):
            exits[source] = (3, item["to"])  # 尾跳转（或落入）另一个函数：按转交处理
        elif isinstance(source, int):
            # 间接跳转、未解码、越界、截断等出口：此时尚未写过的参数寄存器可能被未知代码读取。
            exits.setdefault(source, (4, None))
        else:
            uncertain = everything           # 不知道从哪里离开：全部参数寄存器都不确定
    mask = bits.mask
    events: dict[int, list[tuple[int, int, int, int | None]]] = {}
    generated: dict[int, int] = {}
    for start, block in by_start.items():
        rows = []
        gen = 0
        for row in _sequence(block.get("instructions")):
            if not isinstance(row, Mapping):
                continue
            branch = row.get("branch_info")
            kind, target = 0, None
            if isinstance(branch, Mapping) and branch.get("kind") == "call":
                target = branch.get("target")
                kind = 1 if isinstance(target, int) else 2
            written = mask(row.get("writes"))
            operands = row.get("operands") or ()
            zeroing = (str(row.get("mnemonic", "")).lower() in _ZERO_IDIOMS and len(operands) >= 2
                       and str(operands[-1]).strip().lower() == str(operands[-2]).strip().lower())
            rows.append((0 if zeroing else mask(row.get("reads")), written, kind, target))
            gen |= everything if kind else written  # 调用之后全部参数寄存器都被覆盖
            exit_kind = exits.get(row.get("addr"))
            if exit_kind is not None:
                rows.append((0, 0, exit_kind[0], exit_kind[1]))
        events[start], generated[start] = rows, gen
    # 必经已写入（按位与）不动点；入口为空集。
    successors = {start: [target for target in _sequence(block.get("successors")) if target in by_start]
                  for start, block in by_start.items()}
    parents: dict[int, list[int]] = {start: [] for start in by_start}
    for start, targets in successors.items():
        for target in targets:
            parents[target].append(start)
    after: dict[int, int] = {}
    inbound: dict[int, int] = {}
    for _ in range(len(by_start) + 2):
        changed = False
        for start in by_start:
            if start == entry:
                value = 0
            else:
                incoming = [after[parent] for parent in parents[start] if parent in after]
                if not incoming:
                    continue
                value = incoming[0]
                for other in incoming[1:]:
                    value &= other
            inbound[start] = value
            result = value | generated[start]
            if after.get(start) != result:
                after[start], changed = result, True
        if not changed:
            break
    if len(inbound) != len(by_start) or any("successors" not in block for block in by_start.values()):
        # 块之间的边不完整（缺少 successors 或有块从入口不可达）：无法确定看全了函数，保守处理。
        uncertain = everything
    direct = 0
    indirect = 0
    sites: list[tuple[int, int]] = []
    for start, rows in events.items():
        if start not in inbound:
            continue
        current = inbound[start]
        for reads, written, kind, target in rows:
            direct |= reads & ~current
            if kind == 1 or kind == 3:
                sites.append((target, current))
            elif kind == 2:
                indirect |= everything & ~current   # 间接调用：尚未写过的入口值可能被未知目标读取
            elif kind == 4:
                uncertain |= everything & ~current  # 间接跳转/异常出口：同上，且不适用调用约定
            current = everything if kind in (1, 2) else current | written
    return _Local(direct, sites, uncertain | indirect, indirect & ~uncertain)


def argument_usage(functions: Iterable[Mapping[str, Any]], architecture: str, arguments: tuple[str, ...],
                   volatile: tuple[str, ...] = (), *, known_arity: Mapping[int, int | None] | None = None,
                   aliases: Mapping[int, int] | None = None,
                   variadic_fixed: Mapping[int, int] | None = None) -> dict[int, dict[str, Any]]:
    """{函数起点: {"registers": [按 ABI 顺序的参数寄存器], "complete": bool}}。

    known_arity：已知原型的目标（导入桩、库函数）→ 寄存器参数个数；None 表示个数不定（变参等）。
    aliases：调用目标 → 实际执行的本地函数起点（例如指向本库导出函数的 PLT 桩）。
    variadic_fixed：变参目标 → 固定参数占用的寄存器个数。严格判定时变参部分不确定；按
    间接调用同一约定（变参只来自调用前显式写入的寄存器）时只计固定参数。
    volatile 保留为兼容参数：调用之后全部参数寄存器都视为已被覆盖。
    """
    if not arguments:
        return {}
    known = dict(known_arity or {})
    alias = dict(aliases or {})
    bits = _Bits(architecture, arguments)
    everything = (1 << len(arguments)) - 1
    local: dict[int, _Local] = {}
    for function in functions:
        start = function.get("start")
        if not isinstance(start, int) or start in local or start in known or start in alias:
            continue
        facts = _local_facts(function, bits, everything)
        if facts is not None:
            local[start] = facts
    for facts in local.values():
        facts.sites = [(alias.get(target, target), defined) for target, defined in facts.sites]
    arity_bits = {target: (None if arity is None else (1 << min(arity, len(arguments))) - 1)
                  for target, arity in known.items()}
    fixed_bits = {target: (1 << min(count, len(arguments))) - 1 for target, count in (variadic_fixed or {}).items()}
    # 两个单调增大的不动点（位集合有限，必然收敛；递归调用取最小不动点即“沿某条有限路径读取”）：
    # uses —— 已证实读取；maybe —— 可能读取（含所有不确定去向）。
    uses = {start: facts.direct for start, facts in local.items()}
    maybe = {start: facts.direct | facts.uncertain for start, facts in local.items()}
    # 同样的传播，但按间接调用约定：只因间接调用产生的不确定位不计入。
    assumed = {start: facts.direct | (facts.uncertain & ~facts.indirect) for start, facts in local.items()}
    changed = True
    while changed:
        changed = False
        for start, facts in local.items():
            proven, possible, likely = uses[start], maybe[start], assumed[start]
            new_proven, new_possible, new_likely = proven, possible, likely
            for target, defined in facts.sites:
                free = ~defined
                if target in arity_bits:
                    bits_needed = arity_bits[target]
                    fixed = fixed_bits.get(target, 0)
                    new_proven |= (fixed if bits_needed is None else bits_needed) & free
                    new_possible |= (everything if bits_needed is None else bits_needed) & free
                    new_likely |= ((fixed if target in fixed_bits else everything)
                                   if bits_needed is None else bits_needed) & free
                elif target in local:
                    new_proven |= uses[target] & free
                    new_possible |= maybe[target] & free
                    new_likely |= assumed[target] & free
                else:
                    new_possible |= everything & free  # 未知目标
                    new_likely |= everything & free
            if new_proven != proven or new_possible != possible or new_likely != likely:
                uses[start], maybe[start], assumed[start], changed = new_proven, new_possible, new_likely, True
    return {start: {"registers": [root for position, root in enumerate(arguments) if uses[start] >> position & 1],
                    "complete": maybe[start] == uses[start],
                    # 只在“间接调用的目标只读取调用前显式写入的寄存器”这一约定下才完整。
                    "complete_assuming_indirect_calls": assumed[start] == uses[start]}
            for start in local}
