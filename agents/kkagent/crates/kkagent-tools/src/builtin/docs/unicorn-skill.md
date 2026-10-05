
# Unicorn Engine Python API（精编）

Unicorn 2.x Python 绑定的常用 API。**同目录的 `unicorn-python-api.md` 是完整参考**，枚举值（寄存器编号、错误码）不确定时用 grep 查它，禁止凭记忆硬编码。

## 安装与导入

```bash
pip install unicorn        # Unicorn 2，包名就是 unicorn
```

```python
from unicorn import *
from unicorn.x86_const import *    # 按架构导入常量：arm_const / arm64_const / mips_const / riscv_const / ppc_const / sparc_const / s390x_const / m68k_const / tricore_const
```

## 核心 API

### 引擎初始化

```python
uc = Uc(UC_ARCH_X86, UC_MODE_64)                    # 架构 + 模式
uc = Uc(UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_LITTLE_ENDIAN)
uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)                 # Thumb 指令集
# 架构: UC_ARCH_ARM/ARM64/MIPS/X86/PPC/SPARC/M68K/RISCV/S390X/TRICORE
# 模式: UC_MODE_16/32/64, UC_MODE_LITTLE_ENDIAN/BIG_ENDIAN,
#       UC_MODE_ARM/THUMB/MCLASS(ARM), UC_MODE_MICRO(MIPS)
```

### 内存

```python
uc.mem_map(address, size, perms=UC_PROT_ALL)   # UC_PROT_READ/WRITE/EXEC/NONE
uc.mem_write(addr, data)                        # bytes / bytearray
data = uc.mem_read(addr, size)
uc.mem_protect(addr, size, perms)
uc.mem_unmap(addr, size)
uc.mem_regions()                                # [(begin, end, perms)]
```

### 寄存器

```python
uc.reg_write(UC_X86_REG_RIP, 0x400000)
uc.reg_write(UC_X86_REG_RSP, STACK_TOP)
rax = uc.reg_read(UC_X86_REG_RAX)
# ARM: UC_ARM_REG_R0..R12, SP, LR, PC, CPSR
# ARM64: UC_ARM64_REG_X0..X30, SP, PC, PSTATE
# MIPS: UC_MIPS_REG_ZERO, AT, V0, A0..A3, SP, RA, PC
# 段寄存器/描述符: UC_X86_REG_GS_BASE, UC_X86_REG_FS_BASE
```

### 执行

```python
uc.emu_start(begin, until, timeout=0, count=0)
# until=0: 一直跑（或跑出映射内存/非法指令时报错）
# timeout: 微秒；count: 指令条数上限
# 出错抛 UcError，errno 见下方错误码
```

### Hook（回调签名按 hook 类型不同）

```python
# 代码 hook: 每条指令前回调
def hook_code(uc, address, size, user_data): ...
uc.hook_add(UC_HOOK_CODE, hook_code, user_data=None, begin=1, end=0)

# 内存访问: mem_type=UC_MEM_READ/WRITE/FETCH
def hook_mem(uc, access, address, size, value, user_data): ...
uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem)

# 访问未映射内存（模拟 I/O、按需映射）: 返回 True 表示已处理，继续执行
def hook_unmapped(uc, access, address, size, value, user_data):
    return True
uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_unmapped)

# 单条指令 hook（需要 arg1=指令 id）
uc.hook_add(UC_HOOK_INSN, hook_syscall, None, 1, 0, UC_X86_INS_SYSCALL)

# 基本块 hook（block 开始事件）
uc.hook_add(UC_HOOK_BLOCK, hook_block)   # (uc, address, size, user_data)

uc.hook_del(h)
```

### 错误码（UcError.errno，常用）

```python
UC_ERR_OK=0  UC_ERR_NOMEM  UC_ERR_ARCH  UC_ERR_HANDLE  UC_ERR_MODE
UC_ERR_READ_UNMAPPED=6  UC_ERR_WRITE_UNMAPPED=7  UC_ERR_FETCH_UNMAPPED=8
UC_ERR_HOOK  UC_ERR_INSN_INVALID  UC_ERR_MAP  UC_ERR_WRITE_PROT  UC_ERR_READ_PROT
UC_ERR_FETCH_PROT  UC_ERR_ARG  UC_ERR_READ_UNALIGNED  UC_ERR_WRITE_UNALIGNED  UC_ERR_TIMEOUT
```

### 上下文与查询

```python
ctx = uc.context_save()      # 快照（可用于回溯）
uc.context_restore(ctx)
page_size = uc.query(UC_QUERY_PAGE_SIZE)
mode = uc.query(UC_QUERY_MODE)
uc.ctl_get_mode(); uc.ctl_get_arch()
uc.ctl_exits_enabled(True)   # 配合 emu_start 的 until 或 count 退出
```

## 常用模板

**跑一段裸机器码（x86-64 shellcode / 函数片段）**：
```python
from unicorn import *
from unicorn.x86_const import *
CODE = 0x400000; STACK = 0x100000; SIZE = 0x10000
uc = Uc(UC_ARCH_X86, UC_MODE_64)
uc.mem_map(CODE, 0x1000); uc.mem_map(STACK, SIZE)
uc.mem_write(CODE, bytes.fromhex('4831c048ffc0c3'))   # xor rax,rax; inc rax; ret
uc.reg_write(UC_X86_REG_RSP, STACK + SIZE - 0x100)
try:
    uc.emu_start(CODE, CODE + 5)
except UcError as e:
    print('errno', e.errno)
print(hex(uc.reg_read(UC_X86_REG_RAX)))
```

**带代码 trace 的执行**：
```python
def hook_code(uc, address, size, _):
    print(f'0x{address:x}: {uc.mem_read(address, size).hex()}')
uc.hook_add(UC_HOOK_CODE, hook_code)
```

**按需映射（处理未映射访问）**：
```python
def hook_unmapped(uc, access, address, size, value, _):
    if access == UC_MEM_READ_UNMAPPED and address in known_regions:
        uc.mem_write(address, b'\x00' * size); return True
    return False
```

## 注意

- Unicorn 不模拟系统调用：遇到 `syscall` 指令要么 hook `UC_HOOK_INSN` 手动实现，要么 hook `UC_HOOK_MEM_FETCH_UNMAPPED` 拦截跳进 OS 区域的执行。
- 模拟加密/VM 题时，把“输入”写进内存/寄存器，跑完后读输出；不确定的常量一律到 `unicorn-python-api.md` grep（如 `UC_X86_REG_`、`UC_ERR_`）。
