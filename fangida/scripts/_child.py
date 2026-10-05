"""Subprocess entry point for trusted read-only scripts; no security sandbox."""
from __future__ import annotations

import json
from pathlib import Path
import runpy
import sys


def main() -> None:
    snapshot = json.load(sys.stdin)
    # run_path does not put a file's directory on sys.path as Python normally
    # does when executing that file. Allow helpers and packages next to it.
    sys.path.insert(0, str(Path(sys.argv[1]).parent))
    namespace = runpy.run_path(sys.argv[1], init_globals={"analysis": snapshot})
    entry = namespace.get("main")
    if entry is not None:
        if not callable(entry):
            raise TypeError("script's main must be callable")
        result = entry(snapshot)
        if result is not None:
            print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
