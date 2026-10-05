"""已完成结果的附加展示行；只借用数据，不执行任何分析。"""
from __future__ import annotations

import re
from typing import Any


def _address(value: Any) -> str:
    return f"{value:#x}" if type(value) is int else str(value if value is not None else "?")


def _values(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return ", ".join(map(str, value))
    return str(value) if value is not None else ""


def display_text(table: str, row: dict[str, Any]) -> str | None:
    """为代码视图格式化一条现有记录，其余视图保留原 JSON 详情。"""
    if table == "Pseudocode":
        code = row.get("pseudoc")
        return code if isinstance(code, str) else None
    if table != "Disassembly":
        return None

    metadata = row.get("arch_meta")
    metadata = metadata if isinstance(metadata, dict) else {}
    operands = _values(row.get("operands", ()))
    instruction = f"{_address(row.get('addr'))}  {row.get('mnemonic', '?')} {operands}".rstrip()
    lines = [instruction, ""]
    source = row.get("source") or metadata.get("container_member")
    if source:
        lines.append(f"来源：{source}")
    address_space = row.get("address_space") or metadata.get("address_space")
    if address_space:
        lines.append(f"地址空间：{address_space}")
    size = row.get("size")
    if type(size) is int:
        lines.append(f"长度：{size} 字节")
    # 原生 IR 通常仅保存解码结果。仅展示快照实际提供的字节，不重读源文件。
    raw = next((row[key] for key in ("bytes", "raw_bytes", "bytes_hex")
                if row.get(key) is not None), None)
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.hex(" ")
    elif isinstance(raw, (list, tuple)) and all(type(part) is int and 0 <= part <= 255 for part in raw):
        raw = " ".join(f"{part:02x}" for part in raw)
    if raw is not None:
        lines.append(f"字节：{raw}")
    for key, label in (("reads", "读取寄存器"), ("writes", "写入寄存器")):
        if row.get(key):
            lines.append(f"{label}：{_values(row[key])}")
    branch = row.get("branch_info")
    if isinstance(branch, dict) and branch:
        kind = str(branch.get("kind", "branch"))
        description = f"分支：{kind}"
        if branch.get("target") is not None:
            description += f" → {_address(branch['target'])}"
        elif kind in {"jump", "call", "branch"}:
            description += " → 未解析"
        if branch.get("conditional"):
            description += "（条件分支）"
        lines.append(description)
    references = metadata.get("memory_references")
    if isinstance(references, (list, tuple)) and references:
        lines.append("内存引用：" + ", ".join(_address(value) for value in references))
    if row.get("comment"):
        lines.extend(("", f"注释：{row['comment']}"))
    return "\n".join(lines).rstrip() + "\n"


#: 伪代码视图额外借用的字段（只保存引用，不复制大文本或指令图）。
PSEUDOCODE_VIEW_FIELDS = ("machine_pseudoc", "pseudoc_style", "pseudoc_reconstruction",
                          "microcode_complete", "xrefs_out")


_C_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def user_renames(functions: Any) -> dict[str, str]:
    """用户重命名过的函数：原名 → 新名（只取原名是 C 标识符、且新旧不同的记录）。"""
    renames: dict[str, str] = {}
    for function in functions if isinstance(functions, list) else ():
        if not isinstance(function, dict):
            continue
        original, name = function.get("original_name"), function.get("name")
        if (isinstance(original, str) and isinstance(name, str) and name and original != name
                and _C_IDENTIFIER.fullmatch(original)):
            renames.setdefault(original, name)
    return renames


def apply_renames(code: str, renames: dict[str, str]) -> str:
    """把代码文本中作为标识符出现的原名替换为新名；字符串/字符字面量与注释保持原样。"""
    if not renames or not isinstance(code, str):
        return code
    names = "|".join(re.escape(name) for name in sorted(renames, key=len, reverse=True))
    pattern = re.compile(r'("(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|//[^\n]*|/\*.*?\*/)'
                         rf"|(?<![A-Za-z0-9_])({names})(?![A-Za-z0-9_])", re.S)
    return pattern.sub(lambda match: match.group(1) if match.group(1) is not None else renames[match.group(2)], code)


def generated_pseudocode_row(function: dict[str, Any], generated: dict[str, Any]) -> dict[str, Any]:
    """按需生成结果的伪代码视图行：字段与 extra_tables 的行相同，另带 pseudoc_on_demand 标记。

    只借用函数记录中的展示字段，不写回快照（生成结果只在本次会话内显示）。
    """
    from .pseudocode import status_flags
    row = {key: function[key] for key in (
        "name", "start", "code_offset", "size", "source", "address_space", "descriptor") if key in function}
    row.update((key, generated[key]) for key in (
        "pseudoc_producer", "pseudoc", "pseudoc_truncated", "machine_pseudoc", "pseudoc_style",
        "pseudoc_reconstruction") if key in generated)
    if "xrefs_out" in function:
        row["xrefs_out"] = function["xrefs_out"]
    row["pseudoc_status"] = status_flags(row)
    row["pseudoc_on_demand"] = True
    row["pseudoc_max_instructions"] = generated.get("max_instructions")
    return row


def extra_tables(snapshot: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    from .pseudocode import status_flags
    pseudocode = []
    # 伪代码是分析时生成的文本：用户重命名后，显示时把调用处与函数头里的旧名换成新名。
    renames = user_renames(snapshot.get("functions"))
    for function in snapshot.get("functions", []):
        if not isinstance(function, dict) or not function.get("pseudoc"):
            continue
        row = {key: function[key] for key in (
            "name", "start", "code_offset", "size", "source", "address_space", "descriptor",
            "pseudoc_producer", "pseudoc", "pseudoc_truncated") if key in function}
        # 新增字段只供代码视图的函数头、视图切换和状态列使用；原有字段保持不变。
        row.update((key, function[key]) for key in PSEUDOCODE_VIEW_FIELDS if key in function)
        if renames:
            for key in ("pseudoc", "machine_pseudoc"):
                if isinstance(row.get(key), str):
                    row[key] = apply_renames(row[key], renames)
        row["pseudoc_status"] = status_flags(function)
        pseudocode.append(row)
    calls = snapshot.get("metadata", {}).get("api_calls", [])
    return {"Pseudocode": pseudocode, "API Calls": calls if isinstance(calls, list) else []}
