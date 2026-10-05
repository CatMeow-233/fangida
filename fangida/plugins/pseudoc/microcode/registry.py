"""Independent semantic-handler registration; source decoding is never invoked."""
from __future__ import annotations

import json
from threading import RLock

from . import arithmetic, bitwise, comparison, conditional, control_flow, data_transfer, floating_point, memory, stack, system
from .common import lifted, snapshot_root, snapshot_roots
from .ir import MicroOperation

# x86 中写入可能不发生（目的保持原值）的指令：bsf/bsr 在源为零时不改目的（AMD 明确规定，
# 编译器依赖这一点），cmovcc/fcmovcc 条件不成立时不写，rep 前缀串指令在计数为零时什么都
# 不写，cmpxchg 系列只在比较失败时写累加器。按空格分词逐个匹配（lock cmpxchg、rep lodsd）。
_X86_MAY_SKIP_WRITES = ("bsf", "bsr", "cmov", "fcmov", "rep", "cmpxchg")


def _writes_may_be_skipped(architecture, mnemonic):
    """指令的寄存器写入是否可能不发生（条件执行等）。"""
    if architecture == "arm":
        return conditional.may_be_conditional(mnemonic)
    if architecture.startswith("x86"):
        return any(word.startswith(_X86_MAY_SKIP_WRITES) for word in mnemonic.split())
    return False


def _whole_root(op, token):
    """快照写寄存器名是否整体定义它的根。

    x86 的 8/16 位视图（al、ah、dx…）保留其余位，不是整体定义；64 位模式下的 32 位写零扩展，
    与 common.assignment 的 zero_upper 规则一致。向量、标志等没有通用寄存器视图的名字
    （快照不区分其写入宽度）按整体写处理。
    """
    register = op.register(token.lower().strip())
    if register is None:
        return True
    return register.bits == op.bits or (register.bits == 32 and op.bits == 64 and not register.shift)


def _snapshot_effects(context, row, op, mnemonic):
    """指令快照（Capstone regs_access）给出的读写寄存器，规范化为 microcode 根。

    返回 (快照读根, 快照写根, 并入读集合的根, 并入写集合的根)。前两项原样记录在 opaque 操作的
    属性里；后两项是 opaque 指令读写集的下界，不改变它“效果未知、屏障”的语义。

    下游（reconstruct/abi 的 instruction_definitions/incoming_registers）把行的 writes 当作
    “必定整体定义”，而读只从操作的输入表达式取（opaque 操作没有输入，快照读在那里不可见）。
    因此只有“必定写”的根并入写集合，下列“可能写”的根改记为读（旧值可能保留，等价于读取）：
    - 写入可能不发生：AArch32 条件执行（ldrne、popne…）、x86 bsf/bsr/cmovcc/rep 串指令/cmpxchg；
    - 读改写：同一根也在快照读集合中（lock xadd、bsf rdi, rdi、cpuid 的 eax/ecx）。若记为定义，
      指令自己对入参的读取在 ABI 推断中不可见，后续读取也被遮住，参数就会从签名中消失；
    - 部分写：x86 的 8/16 位子寄存器写保留其余位。
    AArch32 条件执行还要读标志来求值条件，flags 并入读集合。

    处理器部分执行后在操作数对象上留下的写（context.current_operands.writes，例如条件基础指令
    提升成功、但无法安全改写为条件选择）按同样规则筛选。快照缺失或格式异常时快照部分为空。
    """
    architecture = context.architecture
    try:
        snapshot_reads = snapshot_roots(architecture, op, row.get("reads"))
        snapshot_writes = snapshot_roots(architecture, op, row.get("writes"))
        tokens = row.get("writes")
        candidates = [(snapshot_root(architecture, op, token), _whole_root(op, token))
                      for token in (tokens if isinstance(tokens, (list, tuple)) else ()) if type(token) is str]
    except (AttributeError, TypeError, ValueError):
        snapshot_reads, snapshot_writes, candidates = (), (), []
    reads = set(snapshot_reads)
    operands = getattr(context, "current_operands", None)
    partial_reads, partial_writes = getattr(operands, "reads", None), getattr(operands, "writes", None)
    if isinstance(partial_reads, set):
        reads.update(partial_reads)
    if isinstance(partial_writes, set) and partial_writes:
        candidates.extend((root, True) for root in partial_writes)  # Operands.write 已把部分写记为读
        partial_writes.clear()  # 改由下面的筛选结果并入；common.lifted 不再无条件合并
    skipped = _writes_may_be_skipped(architecture, mnemonic)
    definite, possible = set(), set()
    for root, whole in candidates:
        if root is None:
            continue
        if root == "flags" or not (skipped or root in reads or not whole):
            definite.add(root)  # flags 由 flag_effect="unknown" 无论如何记为写
        else:
            possible.add(root)
    if skipped and architecture == "arm":
        possible.add("flags")
    return (snapshot_reads, snapshot_writes, tuple(sorted(reads | possible)),
            tuple(sorted(definite - possible)))


class LifterRegistry:
    def __init__(self):
        self._handlers = []
        self._lock = RLock()
        # 注册时（持锁）生成的不可变快照；lift 读取单个属性即可获得一致视图，
        # 无需每条指令加锁并复制列表。
        self._handler_chain = ()

    def register(self, name, handler, *, first=False):
        if not isinstance(name, str) or not name or not callable(handler):
            raise ValueError("A named semantic lifter must be callable")
        with self._lock:
            if any(existing == name for existing, _ in self._handlers):
                raise ValueError(f"Semantic lifter already registered: {name}")
            self._handlers.insert(0 if first else len(self._handlers), (name, handler))
            self._handler_chain = tuple(handler for _, handler in self._handlers)

    def names(self):
        with self._lock:
            return tuple(name for name, _ in self._handlers)

    def lift(self, context, row, args, op):
        handlers = self._handler_chain
        try:
            for handler in handlers:
                result = handler(context, row, args, op)
                if result is not None:
                    if result.flag_effect not in {"preserve", "partial_non_condition"} and result.category != "comparison":
                        context.comparison_origin = None
                    return result
            # 没有处理器认领时再尝试 AArch32 条件执行（addeq/movne…）：剥离条件码后用同一
            # 处理器链提升基础指令，再改写为条件选择；无法安全表达时抛出异常，落入 opaque。
            result = conditional.lift(handlers, context, row, args, op)
            if result is not None:
                return result
        except (ValueError, TypeError, KeyError):
            pass
        context.comparison_origin = None
        context.opaque += 1
        mnemonic = str(row.get("mnemonic", "unknown")).lower()
        category = "opaque"
        if mnemonic.startswith(("rep", "lock")) or mnemonic in {"cmpxchg", "xadd", "ldaxr", "stlxr", "ldxr", "stxr"}:
            category = "memory"
        elif mnemonic.startswith(("v", "f")) or "ps" in mnemonic or "pd" in mnemonic:
            category = "floating_point"
        elif mnemonic in {"syscall", "sysenter", "svc", "int", "cpuid", "rdtsc", "msr", "mrs"}:
            category = "system"
        raw = mnemonic + " " + ", ".join(args)
        statements = [f"asm_opaque({json.dumps(raw[:256], ensure_ascii=True)}); /* effects symbolic */", "flags = symbolic_flags();"]
        if (row.get("branch_info") or {}).get("kind") in {"call", "jump"}:
            context.incomplete = True
            statements.append("return unresolved_control_flow();")
        snapshot_reads, snapshot_writes, reads, writes = _snapshot_effects(context, row, op, mnemonic)
        return lifted(context, row, category, statements,
            [MicroOperation("opaque", attributes={"instruction": raw[:256], "register_effects": "unknown",
                                                  "memory_effects": "unknown", "barrier": True,
                                                  "snapshot_reads": list(snapshot_reads),
                                                  "snapshot_writes": list(snapshot_writes)})],
            flag_effect="unknown", memory_effect="unknown", supported=False,
            extra_reads=reads, extra_writes=writes)


DEFAULT_LIFTERS = LifterRegistry()
for name, module in (("control_flow", control_flow), ("comparison", comparison),
                     ("data_transfer", data_transfer), ("integer_arithmetic", arithmetic),
                     ("bitwise", bitwise), ("memory", memory), ("stack", stack),
                     ("floating_point", floating_point), ("system", system)):
    DEFAULT_LIFTERS.register(name, module.lift)
