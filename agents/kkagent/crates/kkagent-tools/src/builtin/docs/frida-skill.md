---
name: frida
description: Frida 动态插单权威参考（16 全量经典 API + 17.x 迁移速查）。写/改 Frida 脚本、hook native/Java/ObjC、dump 自解密内存、绕反调试，或遇到 "Module.getExportByName is not a function"、bridge 不见了等 16→17 报错时，先加载本技能再动手；含 Interceptor/Stalker/Memory 模板、双版本兼容 shim、逐版本 changelog 与 Android 时机控制点位表。
---

# Frida 16/17 内嵌参考（路由）

本技能目录内嵌了完整的 Frida 16 与 17 文档，**写脚本前禁止凭记忆猜 API**，按需读资源：

| 场景 | 读哪个资源 |
|---|---|
| 写 hook / 常规 16.x 脚本（Module/Interceptor/Stalker/Memory/Java/ObjC/rpc/CLI/实战模板） | `frida-16-api.md` |
| 目标环境是 Frida 17.x，或从 16 迁移 / 报 "not a function" | `frida-17-api.md`（含 16→17 对照表与双兼容 shim） |
| 确认某 17 小版本改了什么 / API 有无 | `frida-17-changelog.md`（17.0.0→17.17.0 逐版本） |
| Android 等壳解压/so 加载时机的确定性控制 | `frida-timing-android.md`（linker hook 点位表 + 指纹门控） |

## 最速判断当前目标版本

```bash
frida --version          # 注入端版本
# 或在脚本里：console.log(Frida.version)
```

## 十秒速记（详细内容看资源文件）

- 16：`Module.getExportByName(null, 'open')` 可用；bridges（Java/ObjC）内置。
- 17：全局导出查找必须 `Module.getGlobalExportByName('open')`；模块操作先
  `Process.getModuleByName(m)` 拿实例；bridges 需 frida-compile 打包
  （frida-tools 14 的 REPL 仍内置）；`--no-pause` 已删除；17.16.4 之前 Python 绑定有回归。
- 双版本兼容 shim：

```js
const exp = (mod, name) => mod === null
    ? (Module.getGlobalExportByName !== undefined
        ? Module.getGlobalExportByName(name)          // 17.x
        : Module.getExportByName(null, name))          // 16.x
    : Process.getModuleByName(mod).getExportByName(name);
const base = mod => Process.findModuleByName(mod)?.base;  // 两版通用
```

## CTF 动态分析纪律

1. 先静态（定位关键函数/字符串/加密算法）再动态（hook 验证），不要盲目 attach。
2. 反调试绕过优先 `Interceptor.replace` 掉 `ptrace/strcmp/memcmp/strstr` 族。
3. dump 自解密数据用 `Memory.scanSync` 特征扫描 + `hexdump`，在解密回调 onLeave 时机做。
4. VM/自修改代码用 Stalker `onCallSummary` 先看热点再精细跟踪，记得 `Stalker.exclude` 掉 libc。
5. 需要结果回传用 `send()`/`rpc.exports`，不要 console.log 大段二进制。
