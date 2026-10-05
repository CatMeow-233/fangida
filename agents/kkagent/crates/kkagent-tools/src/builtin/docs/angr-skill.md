
# angr API（精编）

angr 核心 API 的常用部分。**同目录的 `angr-api.md` 是完整参考**，具体类/方法签名不确定时用 grep 查它，禁止凭记忆写参数。装包：`pip install angr`。

## 加载与基础对象

```python
import angr, claripy
proj = angr.Project('./binary', auto_load_libs=False)   # 关键：关掉自动加载 libc
proj = angr.Project('./bin', load_options={'auto_load_libs': False})
proj.entry                       # 入口地址
proj.arch.bits, proj.arch.memory_endness   # 架构信息
proj.loader.main_object           # 主模块
addr = proj.loader.find_symbol('main').rebased_addr
```

## 状态（SimState）

```python
state = proj.factory.entry_state(args=['./binary'])    # stdin 定制用 SimFile 实例（如 angr.SimFile(size=16)），不是裸类
state = proj.factory.entry_state(args=['./binary'], add_options={angr.options.LAZY_SOLVES})
state = proj.factory.blank_state(addr=0x400000)      # 从任意地址开始，无初始化
state = proj.factory.call_state(addr, arg1, arg2)    # 模拟调用函数
state = proj.factory.full_init_state()               # 完整初始化（慢）

# 内存/寄存器
state.memory.store(addr, b'data')
data = state.memory.load(addr, 16)                    # 返回符号表达式（BitVec）
state.mem[addr].uint32_t          # 便捷访问，可赋值
state.regs.rax = 0x41             # 直接读/写寄存器（x86: rax/rip/rsp...）
print(state.solver.eval(state.regs.rax))

# 输入输出
state.posix.dumps(0)              # stdin 内容
state.posix.dumps(1)              # stdout 内容
state.posix.files                 # 文件表

# 约束
state.add_constraints(cond)       # 给状态加约束（路径条件）
state.solver.eval(expr)           # 求一个满足约束的解
state.solver.eval(expr, cast_to=bytes)
state.solver.eval_upto(expr, 5)   # 最多 5 个解
state.solver.min(expr); state.solver.max(expr)
state.solver.satisfiable()        # 约束是否可满足
state.solver.simplify(expr)
```

## 符号值（claripy）

```python
import claripy
x = claripy.BVS('x', 64)          # 64 位符号变量
y = claripy.BVV(0x41, 8)          # 8 位具体值
expr = claripy.Concat(x[63:56], x[55:48], y)
cond = claripy.If(x == 0, y, x)   # 条件表达式
solver = claripy.Solver()         # 独立求解器
solver.add(cond); solver.eval(x, 1)
```

## 执行与寻路（SimulationManager）

```python
simgr = proj.factory.simulation_manager(state)
simgr = proj.factory.simgr(state)                      # 等价写法
simgr.explore(find=0x401234, avoid=[0x401000])         # 经典：找 good、避 bad
simgr.run(n=100)                                       # 最多 100 个基本块
simgr.step()                                           # 单步
simgr.active / simgr.found / simgr.deadended / simgr.avoided   # 状态桶（stash）
simgr.move(from_stash='active', to_stash='deadended', filter_func=lambda s: ...)
simgr.use_technique(angr.exploration_techniques.DFS()) # 换探索策略
```

**典型解题骨架（找 flag / 找 good path）**：
```python
import angr
proj = angr.Project('./chall', auto_load_libs=False)
state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)
simgr.explore(find=0x401234, avoid=[0x401000])
if simgr.found:
    s = simgr.found[0]
    print(s.posix.dumps(0))        # 满足约束的 stdin 即答案
    print(s.solver.eval(s.posix.dumps(0), cast_to=bytes))
```

## 符号化的正确姿势

```python
# 把 stdin 换成符号流
flag_chars = [claripy.BVS(f'c{i}', 8) for i in range(32)]
for i, c in enumerate(flag_chars):
    state.add_constraints(c >= 0x20); state.add_constraints(c <= 0x7e)
state.memory.store(stdin_addr, claripy.Concat(*flag_chars))
state.posix.files[0].pos = 0     # 重置读取位置（如用了 preconstrain）
```

## 常见提速/避坑

- `auto_load_libs=False` 几乎必用；需要 libc 函数行为时用 `proj.hook_symbol('puts', simproc)` 或 simprocedures 自动替代（默认开启）。
- 卡在某个循环/大函数时：`proj.hook(addr, replacement_func, length=5)` 把复杂函数替换成等价 Python 逻辑，或直接 `state.add_constraints(state.regs.rax == expected)` 约束掉。
- 只想执行一小段：`factory.blank_state(addr=...)` 比 entry_state 快得多。
- 汇编级调试：`proj.factory.block(addr).capstone.insns` 看指令，`.pp()` 看 VEX IR。
- 选项组合：`angr.options.unicorn`（用 Unicorn 加速符号执行，仅 x86/ARM64 部分场景）、`angr.options.LAZY_SOLVES`、`angr.options.SYMBOLIC_WRITE_ADDRESSES`（按需）。

## 更多对象（在 angr-api.md 中查全）

- `proj.factory.block(addr, size)` → CapstoneBlock / Block
- `proj.analyses.CFGFast()` / `CFGEmulated()`（画控制流图、定位可达路径）
- `state.history`（bb_addrs / events，回溯执行轨迹）
- `state.inspect`（在内存读写/跳转时挂回调，如 `state.inspect.b('mem_write', when=angr.BP_BEFORE, action=...)`）
- `angr.SimProcedure`（自写系统函数替代）
- 技巧：`angr.exploration_techniques.Explorer(find=..., avoid=...)` 可替代 explore
