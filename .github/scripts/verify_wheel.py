"""Verify the installed wheel in isolated Python, without source-tree imports."""
from importlib import metadata, resources
import json
from pathlib import Path
import tempfile
from threading import get_ident

import fangida
from fangida.models import AnalysisResult
from fangida.scripts import ScriptContext, run_script
from fangida.loaders import BinaryImage, DEFAULT_LOADERS
from fangida.core.kkagent.binary import BinaryImage as LegacyBinaryImage
from fangida.processors import list_processors
from fangida.plugins.interfaces import Plugin
from fangida.plugins.manager import Plugin as LegacyPlugin
from fangida.xrefs import XrefStage


def main() -> None:
    source_tree = Path.cwd().resolve()
    package = Path(fangida.__file__).resolve()
    assert not package.is_relative_to(source_tree), f"Imported checkout instead of wheel: {package}"
    assert BinaryImage is LegacyBinaryImage, "Legacy loader model import changed"
    assert Plugin is LegacyPlugin, "Legacy plugin interface import changed"
    assert {"elf", "pe", "macho"} <= set(DEFAULT_LOADERS.names()), "Missing installed loaders"
    assert {"x86", "x86_64", "arm", "arm64"} <= set(list_processors()), "Missing installed processors"
    with XrefStage(separate_thread=True) as stage:
        assert stage.run(get_ident) != get_ident(), "Installed xref stage did not separate threads"
    packaged_resources = (
        ("fangida.core.kkagent.ghidra_bridge", "FangidaExport.java"),
        ("fangida.core.apk_analyzer", "PROTOCOL.md"),
        ("fangida.scripts", "README.md"),
    )
    for module, filename in packaged_resources:
        content = resources.files(module).joinpath(filename).read_text(encoding="utf-8")
        assert content.strip(), f"Missing or empty wheel resource: {module}/{filename}"

    scripts = {
        item.name: item for item in metadata.distribution("fangida").entry_points
        if item.group == "console_scripts"
    }
    for name in ("fangida", "fangida-mcp", "fangida-bench", "fangida-gui",
                 "fangida-project", "fangida-mcp-http"):
        assert name in scripts, f"Missing installed console script: {name}"
        assert callable(scripts[name].load()), f"Invalid console script: {name}"

    with tempfile.TemporaryDirectory(prefix="fangida-wheel-") as directory:
        folder = Path(directory) / "脚本 空格"
        folder.mkdir()
        (folder / "helper.py").write_text("VALUE = '模块导入成功'\n", encoding="utf-8")
        script = folder / "检查.py"
        script.write_text(
            "from helper import VALUE\n"
            "def main(analysis):\n"
            "    return {'value': VALUE, 'kind': analysis['kind']}\n",
            encoding="utf-8",
        )
        context = ScriptContext(AnalysisResult("sample", "elf", "kkagent", "partial"))
        result = run_script(script, context)
        assert json.loads(result.stdout) == {"value": "模块导入成功", "kind": "elf"}
    print(f"Installed wheel resources and console scripts verified: {package}")


if __name__ == "__main__":
    main()
