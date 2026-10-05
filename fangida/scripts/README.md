# Fangida scripts

Embed trusted Python scripts with `ScriptContext`. Reads use a private copy of
an analysis result. A caller must explicitly grant each write capability:
`rename`, `comment`, and `export`. A project store is required for rename and
comment, and an `export_root` is required for export. Paths passed to
`export_json` must resolve within that root. An annotation never edits the
binary or the saved analysis snapshot.

First save an analysis with `fangida /path/to/sample.elf --project
project.sqlite3`. The following code then loads its current snapshot; replace
the path with that same existing file:

```python
from fangida.project import ProjectStore
from fangida.scripts import ScriptCapabilities, ScriptContext

store = ProjectStore("project.sqlite3")
ctx = ScriptContext.from_project(
    store, "/path/to/sample.elf",
    capabilities=ScriptCapabilities.from_names(["rename", "comment", "export"]),
    export_root="/path/to/exports",
)
print(ctx.functions())
ctx.rename_symbol(0x401000, "entry_point")
ctx.set_comment(0x401000, "Review the initialization path")
ctx.export_json("result.json")
```

`run_script("example.py", ctx)` runs a **trusted** helper file in a child
process, passes `analysis` as a global dict, calls `main(analysis)` if defined,
and captures bounded stdout/stderr. It has a wall-time and output limit. The
runner does not expose store-backed writes to its child. Neither the capability
checks nor subprocess execution constitute a Python security sandbox: scripts
can import modules and invoke operating-system APIs with their user's normal
permissions. Only run scripts from trusted sources.

For example, save the following as `example.py`:

```python
def main(analysis):
    return {"kind": analysis["kind"], "function_records": len(analysis["functions"])}
```

Then run it against a saved context:

```python
from fangida.project import ProjectStore
from fangida.scripts import ScriptContext, run_script

ctx = ScriptContext.from_project(ProjectStore("project.sqlite3"), "/path/to/sample.elf")
print(run_script("example.py", ctx, timeout_seconds=5, max_output_bytes=65536).stdout)
```

脚本可直接导入同一目录内的辅助模块或 Python 包；文件名和目录可包含
空格及中文。传入的分析快照和捕获的标准输出、标准错误统一使用 UTF-8，
不依赖宿主机器的默认编码。脚本的工作目录继承调用方。

脚本结束、超时或超过输出限制时，运行器会清理它启动的普通后代进程。
POSIX 使用独立会话和进程组；Windows 使用 Job Object，子进程先挂起，
加入 Job 后才恢复执行，避免启动与监管之间的竞态。如果 Windows 无法
建立进程监管，启动会失败并回收子进程。脚本仍拥有用户的正常系统权限，
这些生命周期措施不构成安全沙箱。

## Plugin contract and lifecycle

The current built-in analysis plugins conform to `fangida.plugins.manager.Plugin`:
`name`, `version`, `capabilities()`, `analyze(AnalysisTask) -> AnalysisResult`,
and `teardown()`. `PluginManager.load(name)` lazily imports and instantiates a
built-in plugin; repeated analyses reuse that instance. `PluginManager.teardown()`
releases loaded instances. Supported names are currently defined in the
manager's `MODULES` mapping. Third-party entry point discovery, initialization
hooks, and hot reloading are not implemented. Analysis plugins and user scripts
are distinct interfaces.

The draft architecture refers to `revinre.xpt`, but does not define whether it
is an extension or a module name. No alias or file format is assigned pending
that clarification.
