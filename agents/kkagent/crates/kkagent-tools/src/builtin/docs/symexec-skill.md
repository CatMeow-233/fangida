---
name: symexec
description: 符号执行与模拟执行内嵌参考（angr 精编 + Unicorn 2 Python 全量 API）。逆向算法还原、自动寻 flag 输入、约束求解、脱环境模拟执行 VM/加密算法时先加载本技能；含 explore(find/avoid) 解题骨架、符号化 stdin 姿势、Unicorn hook/按需映射模板；完整 API 签名禁止凭记忆写，按本目录资源文件 grep。
---

# 符号 / 模拟执行内嵌参考（路由）

本技能目录内嵌 angr 与 Unicorn 的完整 API 文档。**类/方法签名不确定时必须 grep 资源文件，
禁止凭记忆编参数。**

| 场景 | 用什么 | 读哪个资源 |
|---|---|---|
| 求满足校验的输入（flag 检查器）、自动寻路 | angr 符号执行 | `angr-skill.md` 精编 + `angr-api.md` 全量 |
| 复现一段加密/VM 算法、绕过环境依赖跑裸机器码 | Unicorn 模拟执行 | `unicorn-skill.md` 精编 + `unicorn-python-api.md` 全量 |
| 符号执行太慢 | angr + `angr.options.unicorn`，或改用 Unicorn 手动模拟热点函数 | 两者 |

## angr 解题骨架（十秒版）

```python
import angr
proj = angr.Project('./chall', auto_load_libs=False)   # auto_load_libs=False 几乎必用
simgr = proj.factory.simulation_manager(proj.factory.entry_state())
simgr.explore(find=ADDR_FLAG_OK, avoid=[ADDR_FAIL])    # 静态先定位好两个地址
if simgr.found:
    print(simgr.found[0].posix.dumps(0))               # 即满足约束的 stdin
```

## Unicorn 模拟骨架（十秒版）

```python
from unicorn import *
from unicorn.x86_const import *
uc = Uc(UC_ARCH_X86, UC_MODE_64)
uc.mem_map(0x400000, 0x1000); uc.mem_map(0x100000, 0x10000)
uc.mem_write(0x400000, open('chall.bin','rb').read())   # 或从 ELF 抽函数字节
uc.reg_write(UC_X86_REG_RSP, 0x100000 + 0x10000 - 0x100)
uc.emu_start(0x400000, 0x400000 + LEN)
print(hex(uc.reg_read(UC_X86_REG_RAX)))
```

## 选型规则

- 校验逻辑完整可见、路径爆炸可控 → angr `explore`。
- 只有一个函数要跑（加密/VM handler）、或需要精确控制内存布局 → Unicorn。
- Unicorn 不模拟系统调用：`syscall` 指令要 `UC_HOOK_INSN` 手动实现或改写跳过。
- angr 卡循环：`proj.hook(addr, python_func, length=N)` 把复杂函数替换成 Python 等价逻辑，
  或 `blank_state(addr=...)` 只执行目标片段。
