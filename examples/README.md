# Fangida examples

Run these from the repository root after
`python -m pip install -e '.[disasm,config]'`. The examples use `/bin/ls` as a
Linux input; replace it with a native executable on macOS or Windows. Fangida
does not execute the input file.

## Native binary

If a C compiler is available, build the included small input on Linux or
macOS. It has a conditional branch and a direct call for inspection:

```sh
cc -g -O0 examples/native_sample.c -o native_sample
fangida ./native_sample --output native-sample.json
fangida ./native_sample --threads 2 --output native-sample-two-workers.json
fangida-bench ./native_sample --runs 5 --compare-threads 2
```

The comparison returns one-worker and two-worker timings plus
`same_evidence_and_scope`. Check `semantic_parallel_functions` and
`semantic_workers_used` in each coverage record before interpreting timing.
This sample has eligible functions, but extra threads can still be slower. The
ratio is local to the input and machine. If your settings
set `analyze_threads` below 2, raise that budget before comparing two workers.
The optional desktop browser also accepts
`fangida-gui ./native_sample --threads 2`.

To inspect an existing Linux binary instead:

```sh
fangida /bin/ls --output ls.json
fangida /bin/ls --fast --output ls-fast.json
fangida /bin/ls --interactive
fangida-bench /bin/ls --runs 3
```

Inspect `status`, `warnings`, `stats`, `functions`, and
`metadata.disassembly` in the JSON. The default deeper pass follows bounded
direct control flow from evidenced function seeds. `--fast` skips that pass.
Where Capstone is unavailable, x86 can use a locally installed GNU `objdump`;
ARM decoding requires Capstone. A `partial` status is expected. Native threads
can process independent sized-symbol functions and direct-call discoveries
that pass a conflict check. A conflicting batch is replayed serially. If
Ghidra is installed and `GHIDRA_HOME` points to it, try
`fangida /bin/ls --ghidra` for
optional bounded Ghidra evidence.

## Android or JVM input

```sh
fangida /path/to/app.apk --output app.json
fangida /path/to/classes.dex --output dex.json
fangida /path/to/library.jar --output jar.json
```

Use an APK/DEX/JAR you may inspect. The result can contain class and method
records, `metadata.api_calls` with direct invocation evidence, extracted
Kotlin metadata fields, and bytecode-derived `pseudoc` outlines on methods.
An outline is not reconstructed Java/Kotlin source. As a small local JVM
sample, if a Java compiler is installed:

```sh
printf '%s\n' 'public class Hello { public static void main(String[] args) { System.out.println("Hi"); } }' > Hello.java
javac Hello.java
fangida Hello.class --output hello-class.json
```

To analyze **different** Android files concurrently, share one service and
configure its parse budget. Provide two paths you are allowed to inspect:

```python
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

from fangida.dispatcher import AnalysisService
from fangida.settings import load_settings

paths = ["/path/to/first.apk", "/path/to/second.apk"]
settings = replace(load_settings(), parse_threads=2).validated()
with AnalysisService(settings) as service:
    service.manager.load("apk_analyzer")  # Initialize the shared plugin first.
    with ThreadPoolExecutor(max_workers=2) as requests:
        results = list(requests.map(service.analyze, paths))
print([(result.kind, result.status) for result in results])
```

The plugin uses separate worker processes for these file requests, capped by
`min(parse_threads, 4)`. It does not distribute the members of one APK among
workers. Actual timing depends on file sizes, parsing work, and storage.

## Save a project and add an annotation

```sh
fangida ./native_sample --project demo.sqlite3 --output native-sample.json
fangida-project demo.sqlite3 history --file ./native_sample
fangida-project demo.sqlite3 page 1 functions --limit 10
fangida-project demo.sqlite3 comment ./native_sample 0x0 'Reviewed this input'
fangida-project demo.sqlite3 annotations ./native_sample
```

For a project that already contains snapshots, replace `1` with the new ID
shown by `history`. Address `0x0` is simply an example annotation address;
choose an actual function address from the result to annotate a function.
Annotations are separate from snapshots and tied to the current file bytes.

## Python script context

The project command above creates the database and snapshot needed here.
Run a short script with a read-only result plus explicit annotation/export
grants:

```sh
python - ./native_sample <<'PY'
import sys
from fangida.project import ProjectStore
from fangida.scripts import ScriptCapabilities, ScriptContext

path = sys.argv[1]
context = ScriptContext.from_project(
    ProjectStore("demo.sqlite3"), path,
    capabilities=ScriptCapabilities.from_names(["rename", "comment", "export"]),
    export_root="exports",
)
functions = context.functions()
print("Identified function records:", len(functions))
if functions and isinstance(functions[0].get("start"), int):
    context.rename_symbol(functions[0]["start"], "reviewed_function")
context.set_comment(0, "Reviewed with a trusted script")
print("Exported:", context.export_json("native-sample-snapshot.json"))
PY
```

The exported file is `exports/native-sample-snapshot.json`. Renames/comments persist in
the project annotation layer and do not rewrite that snapshot or the binary.
`ScriptContext` grants are API checks, not a security sandbox for arbitrary
Python. [`fangida/scripts/README.md`](../fangida/scripts/README.md) explains
the bounded, read-only trusted-script runner.

## MCP stdio, end to end

After installation, this Python snippet starts `fangida-mcp`, completes its
JSON-RPC handshake, opens a binary, pages function records, and closes it:

```sh
python - ./native_sample <<'PY'
import json
import subprocess
import sys

with subprocess.Popen(["fangida-mcp"], stdin=subprocess.PIPE,
                      stdout=subprocess.PIPE, text=True) as server:
    def request(identifier, method, params):
        server.stdin.write(json.dumps({"jsonrpc": "2.0", "id": identifier,
                                       "method": method, "params": params}) + "\n")
        server.stdin.flush()
        reply = json.loads(server.stdout.readline())
        if "error" in reply:
            raise RuntimeError(reply["error"])
        return reply["result"]

    request(1, "initialize", {"protocolVersion": "2025-11-25",
                              "capabilities": {},
                              "clientInfo": {"name": "fangida-example", "version": "1"}})
    server.stdin.write(json.dumps({"jsonrpc": "2.0",
                                   "method": "notifications/initialized"}) + "\n")
    server.stdin.flush()

    opened = request(2, "tools/call", {"name": "open_file",
                                        "arguments": {"path": sys.argv[1]}})
    handle = opened["structuredContent"]["handle"]
    print("Opened:", opened["structuredContent"])
    functions = request(3, "tools/call", {"name": "list_functions",
                                           "arguments": {"handle": handle, "limit": 5}})
    print("First functions:", functions["structuredContent"])
    request(4, "tools/call", {"name": "close_file", "arguments": {"handle": handle}})
    server.stdin.close()
PY
```

`get_pseudoc` and `xref_query` return a tool error if that result lacks the
requested evidence. The default MCP tools also read an existing project with
`open_project`, `project_history`, `project_page`, `open_project_snapshot`, and
`project_annotations`. Enabling `--allow-writes` exposes project creation,
analysis saving, and persistent rename/comment operations. The separate
`rename_symbol` tool changes only the MCP session's snapshot. An optional local
HTTP endpoint can be started with `fangida-mcp-http`; it uses MCP session IDs
and request/response POSTs at `/mcp` rather than a server-initiated event
stream.
