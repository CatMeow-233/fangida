# Optional Ghidra bridge

This adapter invokes Ghidra's `support/analyzeHeadless` launcher on demand. It
uses a temporary project and runs `FangidaExport.java` after Ghidra's built-in
analysis. Ghidra is not imported or started when the module loads. Configure:

```bash
export GHIDRA_HOME=/path/to/ghidra
# or: export FANGIDA_GHIDRA_HEADLESS=/path/to/ghidra/support/analyzeHeadless
```

```python
from fangida.core.kkagent.ghidra_bridge import GhidraBridge, GhidraUnavailable

bridge = GhidraBridge.from_environment(
    timeout_seconds=120, max_cpu=2,
    max_decompiled_functions=16, max_decompile_seconds=30,
)
if bridge.available():
    snapshot = bridge.analyze("/absolute/path/to/native/binary")
    print(snapshot.to_dict())
```

The result includes Ghidra functions, **memory** references with kind and
address-space metadata, bounded per-instruction p-code operations, and a
bounded number of Ghidra decompiler pseudo-C functions. The pseudo-C is
produced by Ghidra, with `producer: "ghidra"`; it is not Fangida's own lifter.
Set `max_decompiled_functions=0` to skip decompilation. The
`max_decompile_seconds` budget is shared across the selected functions and
also capped by the process deadline. Per-function output is capped at 131,072
characters, aggregate output at 524,288 characters, and truncation is marked
on each entry. Failures and timeouts yield partial results and explicit
warnings. The bridge does not infer a CFG.

Cross-address-space references retain their spaces; non-memory references are
omitted and counted. Caps on functions, references, instructions, p-code
operations per instruction, output bytes, CPU, and process time limit resource
use. Ghidra's own analysis time is reserved below the process deadline. If
analysis times out, the snapshot includes an `analysis_timed_out` statistic
and warning. Incomplete exports and schema mismatches raise
`GhidraAnalysisError`; an absent launcher raises `GhidraUnavailable`.

The Python adapter uses Ghidra's documented `-import`, `-postScript`,
`-scriptPath`, `-analysisTimeoutPerFile`, `-max-cpu`, `-readOnly`, and
`-deleteProject` options. The script uses public `FunctionManager`,
`ReferenceManager`, `Instruction.getPcode()`, and `DecompInterface` APIs. A real
Ghidra installation is needed for an integration test; peer tests use a fake
launcher to exercise command construction, schema validation, diagnostics,
and timeouts. The bridge wire schema is version 2.

References: [Ghidra headless analyzer documentation](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/RuntimeScripts/support/analyzeHeadlessREADME.md),
[HeadlessScript API](https://ghidra.re/ghidra_docs/api/ghidra/app/util/headless/HeadlessScript.html),
[ReferenceManager API](https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/ReferenceManager.html), and
[Instruction API](https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Instruction.html),
[DecompInterface API](https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html).

Package `FangidaExport.java` as package data in the distribution; for setuptools:

```toml
[tool.setuptools.package-data]
"fangida.core.kkagent.ghidra_bridge" = ["*.java"]
```

The adapter handles one file at a time and removes the project after each
analysis. It is a deliberate on-demand capability. A persistent JVM sidecar,
cross-request cache, cancellation API, and result paging require a later
integration layer. Ghidra itself is Apache-2.0; this bridge calls an installed
copy and does not redistribute Ghidra binaries.
