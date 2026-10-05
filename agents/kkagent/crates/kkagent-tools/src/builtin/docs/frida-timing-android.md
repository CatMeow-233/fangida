# Android 上用 hook 控制时机（取代 setTimeout/setInterval 轮询）

原则：凡是"等 XXX 完成再 patch"都用加载器事件，不用延迟。延迟是概率正确，hook 是确定正确。

## dlopen 生命周期与锚点

```
android_dlopen_ext → 映射/重定位 → soinfo::call_constructors()
  ├─ call_function("DT_INIT")   ← 壳解压完成点
  └─ call_array(init_array)     ← 壳的二层初始化/反调试/线程孵化
→ dlopen 返回 → JNI_OnLoad
```

| 时机 | hook | 备注 |
|---|---|---|
| 壳解压完、init_array 未跑 | linker 特征码锚（下节） | patch 反调试黄金窗口 |
| init 全部结束 | call_constructors onLeave | JNI_OnLoad 前 |
| dlopen 完整返回 | android_dlopen_ext onLeave | 最简单；dlopen 内死掉则无效 |
| 线程孵化点 | pthread_create onEnter（查 args[2] 归属） | 注意壳可用裸 clone 绕过 |
| attach 已运行进程 | 初始指纹扫描 | 兜底 |

linker 符号：dynsym 常被裁剪，但**很多镜像 .symtab 完整**（API34 模拟器实测），
`enumerateSymbols()` 按名找 `__dl__ZN6soinfo17call_constructorsEv`；符号地址可能与文件
分析有偏差，锚点用特征码扫描（±0x1000 窗口），勿用固定偏移。

## 指纹门控

已知偏移+已知明文字节，同时解决"是不是目标"和"解压了没有"（解压前是密文，patch 早了
会被覆盖）。字节值必须从解密产物读原文核对，不手抄。

## linker 回调铁律

- 回调内**禁用 frida 模块 API**（enumerateModules/findModuleByAddress）——linker 持锁
  上下文重入会崩进程。全程直接内存访问：x19=soinfo → `[x19+0x98]`=init_array 指针 →
  `base = 指针 − 已知vaddr`（或 ELF 魔数页回扫）→ readByteArray/patchCode。
- soinfo 字段偏移随 API 版本变化，读出的 soname 做合法性检查（可打印/.so），不对就停用。

## 裸 svc / brk 中和（模式匹配，与样本无关）

```js
// movz w8/x8,#129|93|131; svc #0 → movz 处改 ret（kill 路径整个函数短路）
Memory.scanSync(base, span, "01 00 00 d4")  // 前一条是 movz w8,#imm∈{129,93,131}
// brk #1 → ret:  扫 "20 00 20 d4"
// kill 前 8 条内的 str xzr,[xN,#imm]（临死拉垫背清 ctx 对象）→ NOP(0xd503201f)
```

JS 坑：`&`/`|` 返回有符号 32 位，掩码含 bit31 时比较恒 false、writeU32 收负数抛
"expected an unsigned integer"——位运算结果传 API 前 `>>> 0`。
`Memory.alloc` 页随 JS 引用 GC 释放——全局数组保活。

## 异常安全网（最后兜底）

`Process.setExceptionHandler`：pc 在已中和武器(计数>0)的壳库内 → 处置后 `return true`。
处置用**睡眠 gadget**，勿用 pthread_exit——裸 clone 线程走 pthread_exit 清理会破坏
bionic 残及 agent（进程活着但会话断连）。跳过指令对平坦化跳表会死循环回同一 pc，
检测区必须线程级处置。未确认武器形态的库不挂网（吞真崩溃会把症状推离病因）。
