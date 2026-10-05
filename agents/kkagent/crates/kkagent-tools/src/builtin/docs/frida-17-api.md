
# Frida 17.x API 变更速查

覆盖 17.0.0（2025-05-17）→ 17.17.0（2026-08-05）。逐版本完整明细在
`frida-17-changelog.md`，本文件只放高频结论。写脚本一律按 17.x 现行 API 写，
需要兼容 16 时用下面的 shim。

## 一、最高频报错 → 修复对照（全部来自 17.0.0）

| 旧写法 (≤16) | 17.x 写法 |
|---|---|
| `Module.getExportByName(null, "open")` | `Module.getGlobalExportByName("open")` |
| `Module.findExportByName(null, "open")` | `Module.findGlobalExportByName("open")` |
| `Module.getExportByName("libc.so", "open")` | `Process.getModuleByName("libc.so").getExportByName("open")` |
| `Module.findBaseAddress("libfoo.so")` / `getBaseAddress` | `Process.getModuleByName("libfoo.so").base`（find 语义用 `Process.findModuleByName(...)?.base`） |
| `Module.findSymbolByName(m, s)` / `getSymbolByName` | 模块实例 `mod.findSymbolByName(s)`；`null` 模块全局查找用 `Module.getGlobalExportByName(s)` |
| `Module.ensureInitialized()` / 静态 `Module.enumerateExports()` 等 | 已删：先 `Process.getModuleByName(m)` 拿实例再调实例方法（`mod.enumerateExports()`） |
| `Memory.readU32(p)` / `Memory.writeU32(p, v)` 等 | `p.readU32()` / `p.writeU32(v)`（NativePointer 方法；write 返回 this，可链式 `.add(4).writeU32(13)`） |
| `Process.enumerateModules({onMatch, onComplete})`、`enumerateXxxSync()` | 直接 `const mods = Process.enumerateModules()` 返回数组；`Memory.scan()` 例外仍是异步 |
| REPL/agent 里直接用 `Java` / `ObjC` / `Swift` | bridges 从 GumJS 运行时移除：agent 用 frida-compile 打包 `frida-java-bridge` / `frida-objc-bridge` / `frida-swift-bridge`（已 ESM 化）；frida-tools 14.0+ 的 REPL 和 frida-trace 仍内置，一次性脚本不受影响 |

易错点（网上资料经常写错，已对官方文档核实）：

- 全局导出查找是 **`Module.getGlobalExportByName`（Module 的静态方法）**，不存在
  `Process.getGlobalExportByName`。
- 实例方法保留 `ByName` 后缀：`mod.getExportByName(name)`，没有 `mod.getExport`。
- 静态 `Module` 只剩 `Module.load(path)` 和 `find/getGlobalExportByName`；模块枚举只在
  `Process.enumerateModules()`。
- `Process.getModuleByName` 找不到会抛异常，`findModuleByName` 返回 null。

### 16/17 双兼容 shim

```js
const exp = (mod, name) => mod === null
    ? (Module.getGlobalExportByName !== undefined
        ? Module.getGlobalExportByName(name)          // 17.x
        : Module.getExportByName(null, name))          // 16.x
    : Process.getModuleByName(mod).getExportByName(name);
const base = mod => Process.findModuleByName(mod)?.base;  // 两版通用
```

## 二、版本时间线（一行一版，★=有破坏性）

- **17.0.0** ★ 移除静态 Module API / Memory 读写 / 回调式枚举；bridges 拆包；TS 19.0.0；配 frida-tools 14.0.0
- 17.1.0 Windows 补齐 `Module#enumerateSections()`；imports 暴露 slot；编译器换 ESBuild
- 17.2.0 新 `Frida.PackageManager` + `frida-pm` CLI（免 Node 装包）；Node `openChannel()` 返回类型收紧
- 17.3.0 CModule 下划线符号暴露给 JS；barebone 支持 XNU 注入
- 17.4.0 simmy 后端（Apple 模拟器）；dyld_sim 早期插桩；java-bridge 修 Android 16 的 `deoptimize*`/`backtrace`
- 17.5.0 Swift 绑定大改（delegate→AsyncStream）；`CompilerOptions.platform/externals`
- 17.5.2 Windows 导出条目 `type` 不再恒报 function
- 17.6.0 Interceptor force-attach；Android spawn 重写（不再 ptrace、不再注入 system_server）；java-bridge 与 core 解耦
- 17.7.0 eBPF `SyscallTracer`；Node GVariant 64 位整数变 `BigInt`（★Node 侧）
- 17.8.0 `frida-strace` CLI；GumJS SQLite 列元数据；Android 上 ART 进程内运行
- 17.9.0 `Device.override_option()`；`control-endpoint` 后端选项
- 17.9.8 `Memory.alloc(size, {protection:'rwx'})`；NativeCallback 结构体返回修复
- 17.10.0 ★(C devkit) attach flags→options 结构；GumJS `Interceptor.attach/replace/replaceFast` 接受 options 对象；patchCode 后页权限收回 RX
- 17.10.1 `Memory.findPointers()`（SIMX 并行扫描）
- 17.11.0 `enumerateExports()` 条目新增 `size` 字段（无平台为 -1）
- 17.12.0 `ControlFlowGraph`/`BasicBlock`；`Process.findFunctionRange()`；Interceptor 按函数/按 listener flush；x86 在线重定位更严格（部分 hook 会被拒）
- 17.13.0 进程枚举新增 `argv`（元数据级）
- 17.14.0 `Script.interrupt()` / `Script.terminate()`
- 17.14.1 `ControlFlowGraph.toJSON()` 形状变更：邻接块以起始地址表示（★解析该 JSON 的脚本）
- 17.15.0 `Process.getThreadById/findThreadById`；`getFunctionRange()`；Darwin 解析导出不再触发 dlopen
- 17.16.0 `SpawnGatingScope` + `spawn_gating_disabled` 信号；Python GIR 重写 + `frida.aio`；x86 CpuContext 暴露 XMM；C 侧 `gum_alloc_n_pages()` 移除；模块卸载时 hook 直接丢弃
- 17.16.3/4 Python 17.16.0 重写弄丢的公开名（`frida.core` 装饰器、facade 方法等）全部恢复
- 17.17.0 barebone agent 进 Linux 内核（.ko + /dev/frida）；Python `linker_notifier_offsets` 等修复

## 三、写新脚本值得用的 17.x API

```js
Memory.findPointers(pattern-ish)            // 17.10.1 并行 SIMD 指针扫描
Memory.alloc(n, { protection: 'rwx' })      // 17.9.8 iOS 26+ 等 W^X 场景必须
Process.findFunctionRange(addr)             // 17.12.0 无符号二进制定函数边界
Process.getThreadById(tid)                  // 17.15.0
const cfg = mod.buildControlFlowGraph?..    // 17.12.0 ControlFlowGraph/BasicBlock
Module.getGlobalExportByName('open')        // 17.0 替代 null 模块查找
// Interceptor 17.10.0 起支持 options 对象（进阶：自定义 redirect emitter 等）
```

CLI：`frida-pm search/install`（17.2.0，免 Node）、`frida-strace`（17.8.0，eBPF/CoreProfile）。

## 四、行为陷阱（脚本没报错但结果不对时查这里）

1. **`Memory.patchCode()` 之后页权限被收回 RX**（17.10.0）：patch 完还要写字的流程会崩；
   需要可写代码页用 `Memory.alloc(n,{protection:'rwx'})`，不要指望 patchCode 留 RWX。
2. **x86 在线重定位更严**（17.12.0）：跨 call/syscall 的重定位会被拒，以前能装的 hook
   现在可能直接失败——不是 bug，改用 offline/patchCode 路径。
3. **`ControlFlowGraph.toJSON()`**（17.14.1）：邻接块用起始地址数字，不再嵌套对象。
4. **Windows `enumerateExports()` 的 `type` 字段**（17.5.2）按真实类型给，别再默认 function。
5. **Darwin 解析模块导出不再触发 dlopen**（17.15.0）：不会连带跑 Oc 的 `+load`，早期镜像
   的时序和以前不同。
6. **模块卸载时 Interceptor hook 直接丢弃**（17.16.0），不再尝试恢复 prologue。
7. **Android spawn 底层全换**（17.6.0）：不再 ptrace、不再注入 system_server（app 启动超时
   恢复系统默认，自己需要就手动注入 system_server）、ART 进程内运行（17.8.0）；
   spawn-gating 语义不变，但依赖旧注入痕迹的检测脚本行为会变。
8. **Node 绑定 GVariant 64 位整数是 `BigInt`**（17.7.0+），传参也必须 BigInt。
9. Python 绑定在 17.16.0/17.16.1/17.16.2 有公开名缺失回归，**17.16.4 才修复完**——
   用 Python 侧 API 至少锁 17.16.4。

## 五、版本配对

Frida 17.0.0 ↔ frida-tools 14.0.0（bridges 内置于 REPL）；17.8.0 ↔ frida-tools 14.6.1
（frida-strace）。pip 一起升：`pip install -U frida frida-tools`。
`@types/frida-gum` 19.x 随各版本递增（19.1→17.9.8，19.3→17.10.0，19.4→17.10.1，
19.6→17.12.0，19.8→17.15.4，19.10→17.16.0）。

### CLI 纠偏（frida-tools 14 / Frida 17，17.17.0 实测）

**禁止写 `--no-pause`，已删除**——spawn（`-f`）默认自动 resume（日志特征
`Spawned ... Resuming main thread!`），旧命令里的 `--no-pause` 会直接
`unrecognized arguments`。要停在 spawn 阶段用 `--pause`（REPL 里 `%resume` 恢复）。

**禁止建议 `frida-inject`，17.x 不再发布该二进制**。注入运行中进程：
`frida -p <pid> -l x.js`（或 `-n 进程名`）；按包名等 spawn 用 `--await`；配套工具
现为 frida / frida-apk / frida-compile / frida-create / frida-discover / frida-itrace /
frida-join / frida-kill / frida-ls / frida-ls-devices / frida-pm / frida-ps /
frida-pull / frida-push / frida-rm / frida-strace / frida-trace。

`-f` 指包名（spawn）与 `-p/-n/-N`（attach）语义不可混；spawn 场景脚本在 resume 前
加载完成（gating），是"时机早于一切 Java 代码"的默认保障，不需要也不存在 no-pause。

## 五点五、时机控制：用 hook，不要用延迟

写 Frida 脚本时凡是"等壳解压完/等 so 加载完再 patch"的需求，禁止 setTimeout/setInterval
轮询——hook 加载器事件才是确定性时机。Android 上按需选层：`call_function("DT_INIT")`
onLeave（壳解压完、init_array 未跑，patch 反调试黄金窗口）→ `call_constructors` onLeave
→ `android_dlopen_ext` onLeave → 初始指纹扫描（attach 已运行进程）。mangled 名、指纹
门控写法与陷阱见 `frida-timing-android.md`。

## 六、配套资源文件

- 用户问"17.X.Y 改了什么/能不能用某 API"→ 查 `changelog.md` 该版本条目（含官方 post 链接）
- 迁移时想确认某个 API 是哪个版本引入/移除 → `changelog.md` 按版本排列，可 grep
- 需要 Swift/Python/C devkit 侧的次要变更 → 正文刻意省略的部分都在 `changelog.md` 里
- Android 上控制脚本执行时机（等壳解压/等 so 加载）→ `timing-android.md`（linker hook 点位表 + 指纹门控）
