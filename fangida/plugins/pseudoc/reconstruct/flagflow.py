"""Unique reaching flag definitions across CFG edges, with explicit barriers."""
from collections import deque

from .cfg import predecessors
from .flagmodel import SOURCE_OPCODES as _SOURCE_OPCODES, flag_source, writes_flags

# 块摘要的“标志不变”标记：块内没有任何写标志的操作，入口处的标志原样流出。
_KEEP = object()


def flag_sources(blocks):
    """每个可建模标志来源操作的归一模型：{(地址, 操作序号): (kind, 输入, 宽度)}。

    一次重建内只计算一次，到达分析、活跃分析与 lower 共用，避免反复求值移位计数等。
    """
    sources = {}
    for block in blocks.values():
        for row in block.records:
            for index, operation in enumerate(row["operations"]):
                if operation["opcode"] in _SOURCE_OPCODES:
                    model = flag_source(row, operation)
                    if model is not None:
                        sources[(row["addr"], index)] = model
    return sources


def reads_nzcv(operation):
    """AArch64 ``mrs xN, nzcv``：把 N/Z/C/V 作为数值读出，同样是标志来源的读取者。"""
    return operation["opcode"] == "assign" and (operation.get("attributes") or {}).get("system_register") == "nzcv"


def _events(row, sources):
    """按执行顺序产出一条记录对标志的影响：('source', 来源) / ('barrier', None) / ('read', None)。

    读取（条件分支、条件选择、ccmp 的条件、mrs xN, nzcv）先于同一操作自身对标志的写入。整行写标志
    但没有可建模来源的指令（cmpxchg、未识别指令等）在行首就是屏障。
    """
    operations = row["operations"]
    address = row["addr"]
    if writes_flags(row) and not any((address, index) in sources for index in range(len(operations))):
        yield "barrier", None
    for index, operation in enumerate(operations):
        attributes = operation.get("attributes") or {}
        if isinstance(attributes.get("condition"), dict) or reads_nzcv(operation):
            yield "read", None
        if (address, index) in sources:
            yield "source", (address, index)
        elif writes_flags(row, operation):
            yield "barrier", None


def _summary(block, sources):
    """块的转移函数：_KEEP（不写标志）、None（最后是屏障）或 frozenset({最后一个来源})。"""
    result = _KEEP
    for row in block.records:
        for event, origin in _events(row, sources):
            if event == "source":
                result = frozenset({origin})
            elif event == "barrier":
                result = None
    return result


def _transfer(block, origins, sources=None):
    """块内最后一次设置标志的位置；遇到屏障时为 None（标志未知）。"""
    summary = _summary(block, flag_sources({block.address: block}) if sources is None else sources)
    return origins if summary is _KEEP else summary


def reaching_flag_sets(blocks, entry, max_steps=None, sources=None):
    """每个块入口处可能生效的标志定义集合。

    汇合点的不同前驱可以由不同的比较设置标志（例如多个 cmp/b.ge 汇入同一个 b.ne）：
    只要每条到达路径上最后一次设置标志的都是集合中的某个比较，调用方就可以让这些
    比较写同一组比较变量，从而在汇合点还原真实条件。任一路径上标志未知（入口、
    屏障、未访问到的前驱）时结果为 None。迭代超过上限时整体保守地返回 None。
    sources 可传入 flag_sources(blocks) 的结果以复用。
    """
    if sources is None:
        sources = flag_sources(blocks)
    summaries = {address: _summary(block, sources) for address, block in blocks.items()}
    parents = predecessors(blocks)
    successors = {address: [target for target in block.successors if target in blocks]
                  for address, block in blocks.items()}
    after = {}
    pending, queued = deque(blocks), set(blocks)
    limit = max_steps if max_steps is not None else 64 * (len(blocks) + 1)
    steps = 0
    while pending:
        steps += 1
        if steps > limit:
            return {address: None for address in blocks}
        address = pending.popleft()
        queued.discard(address)
        incoming = [after[parent] for parent in parents[address] if parent in after]
        if address == entry or not incoming or any(value is None for value in incoming):
            origins = None
        else:
            origins = frozenset().union(*incoming)
        summary = summaries[address]
        result = origins if summary is _KEEP else summary
        if address not in after or after[address] != result:
            after[address] = result
            for target in successors[address]:
                if target not in queued:
                    pending.append(target)
                    queued.add(target)
    before = {}
    for address in blocks:
        if address == entry or any(parent not in after for parent in parents[address]):
            before[address] = None
            continue
        incoming = [after[parent] for parent in parents[address]]
        before[address] = (None if not incoming or any(value is None for value in incoming)
                           else frozenset().union(*incoming))
    return before


def consumed_flag_sources(blocks, reaching, sources=None):
    """会被某个条件读取的标志来源集合。

    只有这些来源需要把操作数快照到比较变量；其余 add/sub/and 等指令设置的标志在被
    读取前就被覆盖或从未读取，不必生成临时变量。reaching 为 reaching_flag_sets 的结果。
    """
    if sources is None:
        sources = flag_sources(blocks)
    live = set()
    for address, block in blocks.items():
        current = reaching.get(address)
        for row in block.records:
            for event, origin in _events(row, sources):
                if event == "read":
                    if current:
                        live.update(current)
                elif event == "source":
                    current = frozenset({origin})
                else:
                    current = None
    return live


def reaching_flags(blocks, entry):
    parents = predecessors(blocks)
    after, before = {}, {}
    for _ in range(len(blocks) + 1):
        changed = False
        for address, block in blocks.items():
            values = [after[parent] for parent in parents[address] if parent in after]
            origin = values[0] if address != entry and values and all(value == values[0] for value in values) else None
            before[address] = origin
            for row in block.records:
                for index, operation in enumerate(row['operations']):
                    opcode = operation['opcode']
                    if opcode in {'compare', 'test', 'flags_logic', 'flags_sub'} and not operation.get('attributes',{}).get('carry'):
                        origin = (row['addr'], index)
                    elif opcode.startswith('flags_') or opcode in {'flag_write', 'compare_float', 'compare_add', 'conditional_compare', 'call', 'opaque', 'system_transition'}:
                        origin = None
            if address not in after or after[address] != origin:
                after[address], changed = origin, True
        if not changed:
            break
    # A predecessor not visited in the fixed point cannot establish flags.
    for address in before:
        if any(parent not in after for parent in parents[address]):
            before[address] = None
    return before

