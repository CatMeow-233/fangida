# Frida 17.x 逐版本 API 变更明细

来源：frida.re 官方 release posts（每条注明 URL）。标记：
[NEW] 新增 / [REMOVED] 移除 / [RENAMED] 改名 / [CHANGED] 签名或返回类型 / [BEHAVIOR] 行为变化。
纯 bugfix/CI/平台支持未收录，除非影响 API 行为。

## 17.0.0 (2025-05-17) — 大版本，破坏性集中在这里
https://frida.re/news/2025/05/17/frida-17-0-0-released/

- [REMOVED] 运行时内置 bridges：`frida-objc-bridge`、`frida-swift-bridge`、`frida-java-bridge`
  不再随 GumJS 打包。agent 侧需 frida-compile 显式打包（bridges 已 ESM 化）；
  frida-tools 14.0.0 的 REPL 与 frida-trace 仍内置，一次性脚本不受影响。
- [REMOVED] 静态 Module 方法：`Module.ensureInitialized()`、`Module.findBaseAddress()`、
  `Module.getBaseAddress()`、`Module.findExportByName()`、`Module.getExportByName()`、
  `Module.findSymbolByName()`、`Module.getSymbolByName()`、静态 `Module.enumerateExports()` 等。
  迁移：
  - `Module.getSymbolByName(null, 'open')` → `Module.getGlobalExportByName('open')`（新 API，Module 静态）
  - `Module.getExportByName('libc.so', 'open')` → `Process.getModuleByName('libc.so').getExportByName('open')`
  - 基址 → `Process.getModuleByName(m).base`
  - 官方推荐：模块只查一次存变量，再复用实例方法
- [REMOVED] `Memory.readU8/U16/U32/U64/.../writeByteArray` 等读写函数 → NativePointer
  实例方法 `ptr.readU32()` / `ptr.writeU32(v)`；write 系列返回 this 支持链式
- [REMOVED] 回调对象风格枚举（`{onMatch, onComplete}`）与 `*Sync` 变体；未加后缀的
  枚举直接返回数组（`Memory.scan()` 例外，保持异步）
- [CHANGED] Gum 构建去 Node/npm 依赖；frida-compile 独立
- 配套：TypeScript 绑定 19.0.0；frida-tools 14.0.0
- 官方迁移文档：/docs/bridges（bridge 打包教程）

## 17.1.0 (2025-06-05)
https://frida.re/news/2025/06/05/frida-17-1-0-released/

- [NEW] Windows: `Module#enumerateSections()`
- [CHANGED] Windows: `Module#enumerateImports()` 条目暴露 slot 信息
- [BEHAVIOR] Interceptor 单例泄漏修复（长期 hook 的资源行为变化）；Thumb 断点逻辑修复
- [CHANGED] Compiler 后端换 ESBuild + typescript-go；新增 bundle 输出格式/类型检查开关

## 17.2.0 (2025-06-18)
https://frida.re/news/2025/06/18/frida-17-2-0-released/

- [NEW] `Frida.PackageManager`（Python/C 同面）：`pm.search(query, limit=)` →
  `PackageSearchResult(.packages, .total)`；`pm.install(specs=[...])` →
  `PackageInstallResult`；`pm.on("install-progress", cb)`；spec 形如
  `"frida-java-bridge@7.0.4"`；无 opts 时按 package.json 安装；可指向任意 npm registry
- [NEW] frida-tools 14.2.0: `frida-pm search|install`（免 Node.js）
- [CHANGED] Node: `Device.openChannel()` 返回更具体类型（暴露 `destroy()`）
- 包维护者：package.json keywords 需含 `frida-gum`（bridge 加 `frida-gum-bridge`）才能被搜到

## 17.3.0 (2025-09-15)
https://frida.re/news/2025/09/15/frida-17-3-0-released/

- [NEW] CModule 暴露下划线前缀符号给 JS
- [NEW] barebone 后端：XNU 注入（iOS 14 QEMU 验证）
- [BEHAVIOR] fruity：tunnel 超时自动回退 usbmux；CoreDevice 配对 FIFO 匹配

## 17.4.0 (2025-10-12)
https://frida.re/news/2025/10/12/frida-17-4-0-released/

- [NEW] simmy 后端（CoreSimulator，Apple 模拟器一等公民设备）
- [NEW] `VariantReader.list_members()`
- [BEHAVIOR] darwin：dyld_sim 早期插桩；fruity：InvalidHostID 自动解配对
- [FIX] frida-java-bridge 7.0.9：Android 16 上 `Java.deoptimize*()` / `Java.backtrace()` 修复
- [BEHAVIOR] iOS 18 模拟器 sysroot 检测修复（dyld_sim 从 `_dyld_image_count` 隐藏）

## 17.5.0 (2025-11-04)
https://frida.re/news/2025/11/04/frida-17-5-0-released/

- [NEW] `CompilerOptions.platform` / `CompilerOptions.externals`
- [NEW] darwin `AllImageInfos` 报告 Dyld Shared Cache UUID/slide
- [REMOVED] Swift delegate 式事件回调 → AsyncStream + Swift Concurrency；核心 API 全部
  async 化（`attach(to:)`、`createScript`、`script.load()` 等）；去 Foundation/Dispatch 依赖
- [NEW] Swift `DeviceListModel`（SwiftUI）、可移植 `Icon` 枚举

## 17.5.2 (2025-12-15)
https://frida.re/news/2025/12/15/frida-17-5-2-released/

- [BEHAVIOR] Windows `Module` 导出条目 `type` 反映真实类型（不再恒报 function）
- [RENAMED] Swift `Frida_Private` → `FridaCore`；Swift RPC API 精化；新增大量 Swift 绑定

## 17.6.0 (2026-01-18)
https://frida.re/news/2026/01/18/frida-17-6-0-released/

- [NEW] Interceptor force-attach 标志（小函数强行内联 hook，可能越界覆写，慎用）
- [BEHAVIOR] Android Zygote 插桩重写：patch `android.os.Process.setArgV0Native()` 走
  "zymbiote" payload（abstract socket），不再 ptrace；spawn-gating 语义不变；
  未插桩子进程零残留（RASP 检测痕迹消失）
- [REMOVED] system_server 注入：不再代管 app 启动超时，需要就自己注入
- [BEHAVIOR] frida-java-bridge 与 frida-core 解耦（libart 更新不再影响 core）
- [BEHAVIOR] Android `enumerateRanges()` 处理 APK libs；`Process.enumerateThreads()`
  处理新 Android `__pthread_start` 后缀；arm64 Interceptor 自动避开不可行 fast patch

## 17.6.1 (2026-01-20)
- [BEHAVIOR] `NativeCallback` 构造失败改为抛 JS 异常（此前崩 libffi）

## 17.7.0 (2026-02-13)
https://frida.re/news/2026/02/13/frida-17-7-0-released/

- [NEW] `SyscallTracer`（Linux eBPF）
- [CHANGED] Node：GVariant 64 位整数 → `BigInt`（返回与传参都是）
- [CHANGED] 图标宽高 → uint16；macOS PNG 图标省略宽高

## 17.7.1 (2026-02-13)
- [BEHAVIOR] Android spawn 完成推迟到 `setArgV0()`（ART 就绪，java-bridge attach 更稳）

## 17.7.2 (2026-02-14)
- [REMOVED] Node：uint64 GVariant 冗余数字转换不再接受，必须 `BigInt`

## 17.8.0 (2026-03-09)
https://frida.re/news/2026/03/09/frida-17-8-0-released/

- [NEW] frida-tools 14.6.1：`frida-strace` CLI（`-f` 可重复、`-p`、`-u $user`）
- [NEW] `CoreProfileService`（iOS ktrace/kdebug 系统调用跟踪）
- [NEW] GumJS SQLite 查询结果含列元数据
- [BEHAVIOR] Android：ART/Dalvik VM 进程内运行 frida-helper.dex（ROM 兼容性大幅改善）
- [BEHAVIOR] iOS 非调试 app 可经 `ProcessControlService` + 信号挂起 spawn

## 17.9.0 (2026-03-26)
https://frida.re/news/2026/03/26/frida-17-9-0-released/

- [NEW] Python `Device.override_option()`；后端选项 `control-endpoint`
  （fruity 限 tcp:；droidy 任意 ADB endpoint，默认 `tcp:27042`）
- [BEHAVIOR] Linux spawn gating → eBPF 实现；支持注入 group-stopped PID

## 17.9.2 (2026-04-28)
- [NEW] `WebRequestHandler`/`WebRequest`/`WebResponse`；PortalService 端点注册
- [NEW] frida-trace syscall-trace 增加 `include-syscall` 选项

## 17.9.4 (2026-05-02)
- [NEW] macOS 应用 API 重写（NSWorkspace/LaunchServices），支持按 bundle id spawn

## 17.9.8 (2026-05-11)
- [NEW] `Memory.alloc(size, { protection })`（默认 'rw'；iOS 26+ 需 RWX 必须分配时给）
- [FIX] `NativeCallback` 结构体返回（含嵌套）此前崩溃，已修复
- `@types/frida-gum` 19.1.0

## 17.10.0 (2026-05-31)
https://frida.re/news/2026/05/31/frida-17-10-0-released/

- [REMOVED] C devkit：旧 attach flags → 组合式 options 结构（scratch 寄存器、relocation
  策略、replacement/listener data）
- [CHANGED] GumJS：`Interceptor.attach()/replace()/replaceFast()` 可接受 options 对象
  （target 可移入 options；自定义 redirect emitter、redirect-space 提示、全局默认选项）
- [NEW] `UnwindBroker`/`UnwindSectionsProvider`；32 位 ARM EH ABI；Interceptor 创建即获
  unwind 支持（异常/回栈穿过 trampoline）
- [NEW] Exceptor handler-only 模式（装信号 handler 但不 hook signal/sigaction）
- [NEW] Python/Node `SessionOptions`（exceptor 模式、unwind broker、exit monitor 等）
- [BEHAVIOR] `Memory`/代码 patch 完成后页权限收回 RX；Stalker arm64 slab 不再要求就近
  分配；longjmp/异常展开后被跳过的 invocation frame 正确回收，flush 不再卡死

## 17.10.1 (2026-06-02)
- [NEW] `Memory.findPointers()`（范围分块 + SSE2/NEON 内核并行）
- [FIX] x86 stdcall onLeave 帧回收崩溃

## 17.11.0 (2026-06-05)
- [NEW] `GumExportDetails.size`：`enumerateExports()` 条目新增 size（ELF 取 st_size，
  无信息平台为 -1）
- [BEHAVIOR] barebone：内核态 Interceptor/Stalker 可用；W^X over RPC（NativeCallback/
  patchCode 走 RPC）；Linux 无 ptrace 注入回退 `/proc/$pid/mem`

## 17.12.0 (2026-06-10)
https://frida.re/news/2026/06/10/frida-17-12-0-released/

- [NEW] `ControlFlowGraph` / `BasicBlock`（GumJS；CFG 构造、支配树、最近支配点枚举）
- [NEW] `Process.findFunctionRange()`（无符号二进制定函数边界）
- [NEW] Interceptor 按函数 / 按 listener 的 flush
- [BEHAVIOR] x86 `can_relocate()` 场景感知：在线重定位跨 call/syscall 会被拒（以前能装的
  hook 现在可能拒绝）
- [BEHAVIOR] Windows Stalker 线程退出检测（不再跟进 ntdll 拆卸）；Linux agent 经
  `/proc/<pid>/fd` 加载

## 17.13.0 (2026-06-15)
- [NEW] 进程枚举 `argv` 参数（Windows/macOS/Linux/FreeBSD，full scope）
- [NEW] `ControlFlowGraph.toJSON()`（后续 17.14.1 改形状）

## 17.14.0 (2026-06-16)
- [NEW] `Script.interrupt()`（中止当前 JS，脚本保持加载）；`Script.terminate()`（中止并卸载）
- [BEHAVIOR] QuickJS 轮询中断标志；V8 `Isolate::TerminateExecution()`
- [BEHAVIOR] `enumerate_processes()` 的 argv 提升到 metadata scope

## 17.14.1 (2026-06-17)
- [CHANGED] `ControlFlowGraph.toJSON()`：successors/predecessors/immediateDominator 改为
  起始地址（修循环图栈溢出）；解析方需按地址查块

## 17.15.0 (2026-06-19)
- [NEW] `Process.getThreadById(id)` / `Process.findThreadById(id)`
- [NEW] `Process.getFunctionRange()`（throw 版）
- [BEHAVIOR] Darwin：解析模块导出不再 dlopen（不触发模块初始化器/`+load`）

## 17.15.4 (2026-07-06)
- [NEW] `Checksum` 的 `copy` / `peek` 方法

## 17.16.0 (2026-07-17)
https://frida.re/news/2026/07/17/frida-17-16-0-released/

- [NEW] `SpawnGatingScope`（fail-safe、作用域化；Linux eBPF gater 经此 opt-in）
- [NEW] `spawn_gating_disabled(reason)` Device 信号（watchdog 干预时发出；挂起的进程
  会被统一恢复）
- [NEW] Python：GIR 自动生成 + `frida.aio`（asyncio）；Swift 绑定同样自动生成
- [NEW] x86 `CpuContext` 暴露 XMM 寄存器
- [REMOVED] C API `gum_alloc_n_pages()` 系列 → `gum_memory_allocate()`/`gum_memory_free()`
- [BEHAVIOR] 模块卸载时 Interceptor hook 直接丢弃（不再恢复 prologue 到未映射内存）
- [BEHAVIOR] V8 可在 iOS app 沙箱内 JIT；arm64-writer 新增 PACIA/MOVK 发射器

## 17.16.2 (2026-07-19)
- [BEHAVIOR] `Device#spawn(stdio='inherit')`：helper 的 stdio 改为随请求传递（不再常开）

## 17.16.3 / 17.16.4 (2026-07-20/22)
- [RESTORED] Python：17.16.0 重写丢失的公开面恢复——`frida.core` 的 `cancellable` 装饰器、
  `RPCResult`、`make_rpc_call_request()`、`make_auth_callback()`、`ScriptExportsAsync`；
  facade 的 `get_device()`、`get_device_matching()`、`enumerate_devices()`、`shutdown()`、
  `Cancellable.connect/disconnect()`；`on()/off()` 信号重载类型检查
- 结论：Python 侧至少 17.16.4

## 17.17.0 (2026-08-05)
https://frida.re/news/2026/08/05/frida-17-17-0-released/

- [NEW] barebone agent 进 Linux 内核（.ko + `insmod` + `/dev/frida`，GVariant 消息；
  `frida-server --device=barebone`；仅匹配构建内核）
- [FIX] Python：`linker_notifier_offsets` 关键字、`Script.enable_debugger()` 默认端口、
  证书选项编组恢复

## 其他备注

- 17.9.x/17.15.x/17.16.1 等未列出的 patch 均为 bugfix，无 API 变化
- 整个 17.x 期间 Java/ObjC/Swift bridge 的 JS 面、ESM/CJS 处理、QuickJS/V8 选择无再变化
  （相对 17.0.0 的 bridges 拆包而言）
