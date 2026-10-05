"""MCP 工具清单与输入 JSON Schema；写工具只在允许写入时列出。"""
from __future__ import annotations

from typing import Any

from . import _facade


def _schema(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": required,
            "additionalProperties": False}


def _tools(allow_writes: bool) -> list[dict[str, Any]]:
    # 常量与 _schema 在调用时经门面取一次，函数体保持与拆分前逐字一致。
    m = _facade()
    _schema, COLLECTIONS = m._schema, m.COLLECTIONS
    MAX_PAGE_SIZE, MAX_SCAN_BYTES = m.MAX_PAGE_SIZE, m.MAX_SCAN_BYTES
    handle = {"type": "string", "description": "Handle returned by open_file"}
    project = {"type": "string", "description": "Handle returned by open_project or create_project"}
    database = {"type": "string", "description": "Handle returned by open_database or create_database"}
    snapshot_id = {"type": "integer", "minimum": 1}
    address = {"type": ["integer", "string"], "description": "Integer or 0x-prefixed hex address"}
    page = {"offset": {"type": "integer", "minimum": 0, "default": 0},
            "limit": {"type": "integer", "minimum": 1, "maximum": MAX_PAGE_SIZE, "default": 100}}
    definitions = [
        ("open_file", "Analyze a local file and retain a result snapshot.",
         _schema({"path": {"type": "string"}, "max_bytes": {"type": "integer", "minimum": 1,
                                                     "maximum": MAX_SCAN_BYTES},
                  "use_ghidra": {"type": "boolean", "description": "Request optional installed Ghidra supplement"},
                  "deep_analysis": {"type": "boolean", "description": "Analyze native function CFGs"},
                  "full_analysis": {"type": "boolean", "description": "Sweep all native executable regions, recover function roots, CFG and xrefs"}}, ["path"])),
        ("close_file", "Release a result snapshot handle.", _schema({"handle": handle}, ["handle"])),
        ("list_functions", "Page identified functions; reports unavailable when none were identified.",
         _schema({"handle": handle,
                  "include_details": {"type": "boolean", "default": True,
                                      "description": "False returns compact function summaries without IR"},
                  **page}, ["handle"])),
        ("analysis_summary", "Read compact analysis status, counts and coverage without IR, CFG or pcode.",
         _schema({"handle": handle}, ["handle"])),
        ("get_disasm", "Page disassembled instructions if the analyzer supplied them.",
         _schema({"handle": handle, "address": address,
                  "source": {"type": "string", "description": "Archive member or source file filter"},
                  **page}, ["handle"])),
        ("get_cfg", "Page an existing function CFG snapshot, including incomplete frontiers; blocks omit instructions.",
         _schema({"handle": handle, "address": address,
                  "source": {"type": "string", "description": "Archive member filter; empty string selects the main file"},
                  "address_space": {"type": "string", "minLength": 1,
                                    "description": "Address space filter, such as native or file_offset"},
                  "collection": {"type": "string", "enum": ["blocks", "edges", "frontier", "noreturn_calls"],
                                 "default": "blocks"},
                  **page}, ["handle", "address"])),
        ("get_pseudoc", "Get existing pseudo-C at a function or interior instruction address.",
         _schema({"handle": handle, "address": address,
                  "source": {"type": "string", "description": "Archive member filter; empty string selects the main file"},
                  "style": {"type": "string", "enum": ["readable", "machine"]},
                  "address_space": {"type": "string", "minLength": 1},
                  "generate": {"type": "boolean", "default": False,
                               "description": "Generate native pseudo-C on demand when none was saved; "
                                              "cached in this session, never written to a database"},
                  "max_instructions": {"type": "integer", "minimum": 1, "maximum": 8192,
                                       "description": "Per-function instruction limit for generate "
                                                      "(default: settings pseudoc_max_instructions, 512); "
                                                      "with generate it always regenerates at this limit"}}, ["handle"])),
        ("get_microcode", "Page saved typed semantic IR and instruction effects; never re-decode the source.",
         _schema({"handle": handle, "address": address,
                  "source": {"type": "string"}, "address_space": {"type": "string", "minLength": 1},
                  "category": {"type": "string", "minLength": 1}, **page}, ["handle", "address"])),
        ("get_microcode_facts", "Page saved microcode constant/branch facts; unknown values stay explicit.",
         _schema({"handle": handle, "address": address,
                  "source": {"type": "string"}, "address_space": {"type": "string", "minLength": 1},
                  "kind": {"type": "string", "minLength": 1}, **page}, ["handle", "address"])),
        ("simplify_micro_expression", "Simplify a typed bitvector expression without assembly execution.",
         _schema({"expression": {"type": "object"}}, ["expression"])),
        ("xref_query", "Page cross references to or from an address, if available.",
         _schema({"handle": handle, "address": address,
                  "direction": {"type": "string", "enum": ["to", "from", "both"]},
                  "source": {"type": "string", "description": "Container member of the queried endpoint"},
                  "address_space": {"type": "string"},
                  **page}, ["handle", "address"])),
        ("list_api_calls", "Page direct JVM/DEX invocation evidence when available.",
         _schema({"handle": handle, **page}, ["handle"])),
        ("export_result", "Read a paged JSON analysis snapshot without writing a file.",
         _schema({"handle": handle, **page}, ["handle"])),
        ("open_project", "Open an existing compatible project database.",
         _schema({"path": {"type": "string"}}, ["path"])),
        ("close_project", "Release a project handle.",
         _schema({"project": project}, ["project"])),
        ("project_history", "Page saved snapshot metadata in a project.",
         _schema({"project": project, "path": {"type": "string"}, **page}, ["project"])),
        ("project_page", "Read a page of one saved snapshot collection.",
         _schema({"project": project, "snapshot_id": snapshot_id,
                  "collection": {"type": "string", "enum": sorted(COLLECTIONS)}, **page},
                 ["project", "snapshot_id", "collection"])),
        ("open_project_snapshot", "Load a saved snapshot into this MCP session for analysis tools.",
         _schema({"project": project, "snapshot_id": snapshot_id},
                 ["project", "snapshot_id"])),
        ("project_annotations", "Page annotations for the current bytes of a file.",
         _schema({"project": project, "path": {"type": "string"}, **page},
                 ["project", "path"])),
        ("open_database", "Open an existing analysis database without requiring the original binary.",
         _schema({"path": {"type": "string"},
                  "read_only": {"type": "boolean", "default": True}}, ["path"])),
        ("close_database", "Release an analysis database handle.",
         _schema({"database": database}, ["database"])),
        ("database_history", "Page analysis snapshots saved in a database.",
         _schema({"database": database, "path": {"type": "string"}, **page}, ["database"])),
        ("database_page", "Read a saved analysis collection without the original binary.",
         _schema({"database": database, "snapshot_id": snapshot_id,
                  "collection": {"type": "string", "enum": sorted(COLLECTIONS)},
                  "include_details": {"type": "boolean", "default": True,
                                      "description": "False returns compact function summaries for the functions collection"},
                  **page},
                 ["database", "snapshot_id", "collection"])),
        ("open_database_snapshot", "Load a saved analysis for list_functions, get_disasm and xref_query.",
         _schema({"database": database, "snapshot_id": snapshot_id}, ["database"])),
        ("database_annotations", "Page names and comments attached to a saved snapshot's source hash.",
         _schema({"database": database, "snapshot_id": snapshot_id, **page},
                 ["database", "snapshot_id"])),
    ]
    if allow_writes:
        definitions.extend([
            ("rename_symbol", "Rename a function in this session snapshot only.",
             _schema({"handle": handle, "address": address,
                      "name": {"type": "string", "minLength": 1}},
                     ["handle", "address", "name"])),
            ("create_project", "Create a persistent project database.",
             _schema({"path": {"type": "string"}}, ["path"])),
            ("analyze_to_project", "Analyze a file and save a persistent project snapshot.",
             _schema({"project": project, "path": {"type": "string"},
                      "max_bytes": {"type": "integer", "minimum": 1, "maximum": MAX_SCAN_BYTES},
                      "use_ghidra": {"type": "boolean"}, "deep_analysis": {"type": "boolean"},
                      "full_analysis": {"type": "boolean"}},
                     ["project", "path"])),
            ("project_rename_symbol", "Persist a symbol rename annotation for current file bytes.",
             _schema({"project": project, "path": {"type": "string"}, "address": address,
                      "name": {"type": "string", "minLength": 1}},
                     ["project", "path", "address", "name"])),
            ("project_set_comment", "Persist a comment annotation for current file bytes.",
             _schema({"project": project, "path": {"type": "string"}, "address": address,
                      "text": {"type": "string"}},
                     ["project", "path", "address", "text"])),
            ("create_database", "Create an analysis database through the storage plugin.",
             _schema({"path": {"type": "string"}}, ["path"])),
            ("save_to_database", "Save an existing result handle without running analysis again.",
             _schema({"database": database, "handle": handle}, ["database", "handle"])),
            ("database_rename_symbol", "Persist a symbol name without requiring the original binary.",
             _schema({"database": database, "snapshot_id": snapshot_id, "address": address,
                      "name": {"type": "string", "minLength": 1}},
                     ["database", "snapshot_id", "address", "name"])),
            ("database_set_comment", "Persist a comment without requiring the original binary.",
             _schema({"database": database, "snapshot_id": snapshot_id, "address": address,
                      "text": {"type": "string"}},
                     ["database", "snapshot_id", "address", "text"])),
        ])
    mutating = {"rename_symbol", "create_project", "analyze_to_project",
                "project_rename_symbol", "project_set_comment", "create_database",
                "save_to_database", "database_rename_symbol", "database_set_comment"}
    return [{"name": name, "description": description, "inputSchema": schema,
             "annotations": {"readOnlyHint": name not in mutating and not (name == "open_database" and allow_writes),
                             "destructiveHint": False, "openWorldHint": False}}
            for name, description, schema in definitions]
