# Frida 16.x API 参考（经典 GumJS）

> 覆盖 Frida 16.0 – 16.7（默认运行时 duktape，可选 quickjs）。本文件按官方 frida-gum 文档整理，
> 面向 CTF 动态分析 / hook / 反混淆。写脚本前先查本文件；17.x 的差异见 `frida-17-api.md`。

## 0. 运行模型速览

- Frida = 注入目标进程的 JS 引擎（GumJS）+ gum 核心（Interceptor/Stalker/Memory…）。
- 脚本经 `frida -l x.js`（attach）或 `frida -f 包名 -l x.js`（spawn，停在入口，resume 后跑）注入。
- 双向通信：`send(msg)` / `recv(cb)`；`rpc.exports` 暴露给主机端 Python/JS 调用。
- `Java`（Android/ART）、`ObjC`（Apple）、`Swift` bridge 内置于运行时（17 起才拆包，16 无需打包）。

## 1. Module（16 经典静态 API）

```js
const open = Module.getExportByName(null, 'open');            // 全局查找导出地址（找不到抛异常）
const openP = Module.findExportByName(null, 'open');          // 找不到返回 null
const open2 = Module.getExportByName('libc.so', 'open');      // 指定模块
const open2P = Module.findExportByName('libc.so', 'open');

const base = Module.findBaseAddress('libfoo.so');             // null / NativePointer
const base2 = Module.getBaseAddress('libfoo.so');             // 找不到抛异常

Module.enumerateModules();                 // [{name, base, size, path}]
Module.enumerateExports('libfoo.so');      // [{type, name, address}]
Module.enumerateImports('libfoo.so');      // [{type, name, module, address, slot?}]
Module.enumerateSymbols('libfoo.so');      // 含调试符号
Module.findSymbolByName('libfoo.so', 'foo');   // null / NativePointer
Module.getSymbolByName('libfoo.so', 'foo');
Module.load('/data/local/tmp/libx.so');    // dlopen 并返回 Module 对象
Module.ensureInitialized('libfoo.so');
```

进程 / 线程：

```js
Process.id; Process.arch; Process.platform; Process.pointerSize;
Process.enumerateThreads();               // [{id, state, context}]
Process.getCurrentThreadId();
Process.setExceptionHandler(fn);          // 捕获目标进程异常（反调试绕过常用）
Thread.backtrace(this.context, Backtracer.ACCURATE)
      .map(DebugSymbol.fromAddress);      // 栈回溯 + 符号化
```

符号化：

```js
DebugSymbol.fromAddress(ptr('0x1234'));    // {address, name, moduleName, fileName, lineNumber}
DebugSymbol.getFunctionByName('open');
DebugSymbol.findFunctionsNamed('encrypt');
```

## 2. Memory

```js
const p = Memory.alloc(16);                       // 堆上分配（在目标进程内），返回 NativePointer
Memory.allocUtf8String('flag{test}');
Memory.allocAnsiString('...');

// 16 里两套读写都可用（Memory.* 静态版在 17 被移除，建议直接用指针方法）
Memory.readU8(p); Memory.readU16(p); Memory.readU32(p); Memory.readU64(p);
Memory.writeU8(p, v); Memory.writeU32(p, v); Memory.writeU64(p, v);
Memory.readCString(p); Memory.readUtf16String(p);
// 推荐（16/17 通用）：NativePointer 实例方法
p.readU32(); p.readCString(); p.readByteArray(len);
p.writeU32(v); p.writeUtf8String(s); p.writeByteArray(bytes);

Memory.protect(addr, size, 'rw-');                // 改页权限
Memory.patchCode(addr, size, fn);                 // 修改代码段（自动处理权限+缓存刷新）
Memory.scan(base, size, 'de ad be ef', {          // 内存特征扫描
  onMatch(address, size) { send({hit: address}); },
  onError(reason) {}, onComplete() {}
});
Memory.scanSync(base, size, '48 8b ?? 00');       // 同步版，返回 [{address, size}]
```

## 3. Interceptor（最常用）

```js
// hook 函数入口/返回
Interceptor.attach(Module.getExportByName(null, 'open'), {
  onEnter(args) {
    this.path = args[0].readCString();            // args 是 NativePointer 数组
    console.log('[open]', this.path);
  },
  onLeave(retval) {
    retval.replace(ptr(0));                       // 改返回值
    console.log('->', retval.toInt32());
  }
});

// 整体替换函数实现
const strdup = new NativeFunction(Module.getExportByName(null, 'strdup'), 'pointer', ['pointer']);
Interceptor.replace(Module.getExportByName(null, 'strcmp'),
  new NativeCallback((a, b) => 0, 'int', ['pointer', 'pointer']));

// 直接改函数地址（无回调开销）
Interceptor.replaceFast(getExportByName(null, 'rand'), new NativeCallback(() => 42, 'long', []));

Interceptor.flush();                              // 确保所有 hook 立即生效
Interceptor.detachAll();
```

NativeFunction / NativeCallback：

```js
const f = new NativeFunction(addr, 'int', ['pointer', 'int']);   // 返回类型, 参数类型
const cb = new NativeCallback((x) => x * 2, 'int', ['int']);
// 类型: void/pointer/int/uint/long/ulong/char/uchar/float/double/size_t/... 
// 结构体按值传：['int', 'int'] 数组表示，或对象 {type:'struct', fields:[...]}
```

指令解析 / 汇编：

```js
Instruction.parse(ptr('0x1234'));        // {address, mnemonic, opStr, regsRead...}
const insns = Instruction.parse(addr);
```

## 4. Stalker（指令级跟踪， VM 题神器）

```js
const tid = Process.getCurrentThreadId();
Stalker.follow(tid, {
  events: { call: true, ret: false, exec: false, block: false },
  onReceive(events) { /* 二进制事件流，用 Stalker.parse 解析 */ },
  onCallSummary(summary) { /* addr -> count 映射，比 parse 快 */ },
  transform(iterator) {
    let insn = iterator.next();
    const start = insn.address;
    do {
      // 在此处 iterator.putCallout(cb) 可逐指令插桩
      iterator.keep();
    } while ((insn = iterator.next()) !== null);
  }
});
Stalker.unfollow(tid);
Stalker.exclude({ base: Module.findBaseAddress('libc.so'), size: 0x1000000 }); // 排除库，大幅提速
```

技巧：跟踪自解密/VM handler 时用 `onCallSummary` 先看热点，再对热点块 `putCallout` 打印上下文。

## 5. Java（Android）

```js
Java.perform(function () {
  const System = Java.use('java.lang.System');
  System.exit.implementation = function (code) {           // 替换实现
    console.log('blocked System.exit(' + code + ')');
  };

  // 重载选择
  const Cipher = Java.use('javax.crypto.Cipher');
  Cipher.doFinal.overload('[B').implementation = function (input) {
    const out = this.doFinal(input);
    send({alg: this.getAlgorithm(), in: Java.arrayToJni? null : null});
    return out;
  };

  // 实例枚举 / 主动调用
  Java.choose('com.app.Flag', {
    onMatch(inst) { console.log('field=', inst.flag.value); },
    onComplete() {}
  });

  const ByteString = Java.use('com.android.okhttp.okio.ByteString');
  // 字节数组与 JS 互转
  function jbytesToArr(b) { return Java.array('byte', b); }
});
Java.performNow(fn);        // 不自动 attach VM 的版本（在非 Java 线程用）
Java.scheduleOnMainThread(fn);
Java.enumerateLoadedClasses({ onMatch(name){}, onComplete(){} });
```

## 6. ObjC（Apple）

```js
if (ObjC.available) {
  const NSString = ObjC.classes.NSString;
  // hook 类方法 / 实例方法（'- ' 实例，'+ ' 类）
  Interceptor.attach(ObjC.classes.NSString['- initWithUTF8String:'].implementation, {
    onEnter(args) { console.log('str=', args[2].readCString()); }   // args[0]=self, args[1]=_cmd
  });
  // 主动调用
  const s = ObjC.classes.NSString.stringWithString_('hello');
}
```

## 7. 通信与 RPC

```js
// 脚本 -> 主机
send({type: 'hit', addr: '0x1234'});
send(b'\x01\x02', binaryDataArrayBuffer);         // 消息 + 二进制
recv('input', function onMessage(msg) { ... });    // 主机 -> 脚本（阻塞式队列）
process.nextTick(function () { recv('input', onMessage); });  // 重挂监听的惯用法

// 主机可调的函数
rpc.exports = {
  decrypt(data) { return doDecrypt(data); },       // 返回值会序列化传回
  add(a, b) { return a + b; }
};
# Python 侧: script.exports_sync.decrypt(b'xxxx')
```

## 8. 其他高频

```js
// 定时器在目标进程 JS 循环里跑
setTimeout(fn, ms); setInterval(fn, ms);

// 指针运算
p.add(0x10); p.sub(8); p.and(0xfffff000); p.compare(q); p.equals(q);
ptr('0x1234'); ptr('0'); NULL;

// 字节与字符串
hexdump(ptr(addr), {length: 64, ansi: false});
arrayBufferToString / String.fromCharCode.apply(null, new Uint8Array(buf));

// CModule（把 C 代码编译进目标进程，低开销 hook）
const cm = new CModule(`
#include <glib.h>
void my_hook(GumInvocationContext * ic) { ... }
`);
```

## 9. CLI 速查（16.x / frida-tools 12–13）

```bash
frida -U -f com.target.app -l hook.js       # USB + spawn 安卓包
frida -U -n com.target.app -l hook.js       # attach 已运行（-n 攥前台名）
frida -p 1234 -l hook.js                    # attach 本机 pid
frida-trace -U -i "open*" -f com.app        # 自动 trace 导出函数
frida-trace -U -I "libfoo.so" -f com.app    # trace 整个模块
frida-ls-devices / frida-ps -U
# spawn 场景 16 默认停在入口，脚本加载完成后自动 resume（--no-pause 仍可用但非必需）
```

Python 绑定：

```python
import frida
device = frida.get_usb_device()                # 或 get_local_device()
pid = device.spawn(['./chall'])                # 本地 spawn
session = device.attach(pid)
script = session.create_script(open('hook.js').read())
script.on('message', lambda m, d: print(m))
script.load()
device.resume(pid)
script.exports_sync.dump_flag()
```

## 10. CTF 实战模板

**反调试绕过（ptrace/strstr 等 nop 掉）**：

```js
['ptrace', 'strstr', 'strcmp', 'memcmp'].forEach(name => {
  const p = Module.findExportByName(null, name);
  if (p) Interceptor.replace(p, new NativeCallback(() => 0, 'int', ['int','pointer','int','int']));
});
```

**dump 自解密后的内存**：

```js
// 在解密完成回调里（如 JNI 方法 onLeave / init_array 后），扫描特征再 dump
const hits = Memory.scanSync(Module.findBaseAddress('libfoo.so'), 0x300000, '66 6c 61 67'); // "flag"
hits.forEach(h => console.log(hexdump(h.address, {length: 64})));
```

**监控 keychain / SharedPreferences / 文件读写**：hook `open/openat/fopen/fread` 打印路径与 buffer。

**方法数爆炸时的定位法**：先 `Java.enumerateLoadedClasses` 筛包名，再对候选类一次性
`Object.keys(cls.$methods)` 枚举重载，attach 打印参数。
