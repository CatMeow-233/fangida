"""Lazy SQLite storage plugin for portable analysis databases.

The original input is never embedded.  A compressed instruction pool is shared
by CFGs, per-function listings and full disassembly, while collection chunks
provide paging without materialising an entire analysis snapshot.
"""
from __future__ import annotations

from collections import OrderedDict
from contextlib import contextmanager
from dataclasses import fields
import json
import os
from pathlib import Path
import sqlite3
from threading import Lock
from typing import Any, Iterator, Mapping
import weakref
import zlib

from ..models import AnalysisResult
from ..project import (COLLECTIONS, MAX_PAGE_SIZE, PROJECT_SCHEMA_VERSION,
                       ProjectStore, SourceChangedError, _DIGEST_RE, _now,
                       _source_path, fingerprint)
from ..storage import StorageError, StorageSchemaError

FORMAT = "fangida.analysis_db"
STORAGE_SCHEMA_VERSION = 1
CHUNK_ITEMS = 512
MAX_CHUNK_BYTES = 128 * 1024 * 1024
_REF = "$fdb_instruction"
_LITERAL = "$fdb_literal"
_POOL = "__instructions__"
_MANIFEST = "__manifest__"
# JSON 标量的精确类型：pack/expand 对它们原样返回，热循环里内联判断可省掉一次函数调用。
# typing.Mapping 的 isinstance 要经过 typing/abc 两层 __instancecheck__，非常慢，
# 因此先用精确类型快速分支，其余对象仍走原来的 isinstance 判断链，语义不变。
_SCALARS = frozenset({str, int, float, bool, type(None)})


def _disassembly_records(payload: Mapping[str, Any], metadata: Mapping[str, Any]) -> list[Any]:
    """Merge existing listings only; storage never decodes missing instructions."""
    indexed: dict[tuple[str, int], Mapping[str, Any]] = {}

    def collect(values: Any, source: str = "") -> None:
        if not isinstance(values, list):
            return
        for value in values:
            if type(value) is not dict and not isinstance(value, Mapping):
                continue
            address = value.get("addr", value.get("address", value.get("offset")))
            if type(address) is not int or address < 0:
                continue
            if source and "source" not in value:
                value = {**value, "source": source}
            indexed[(str(value.get("source", "")), address)] = value

    for values in (payload.get("instructions"), metadata.get("disassembly"),
                   metadata.get("full_disassembly"), metadata.get("instructions")):
        collect(values)
    bytecode = payload.get("kind") in {"apk", "dex", "jar", "class"}
    for function in payload.get("functions", []):
        if type(function) is not dict and not isinstance(function, Mapping):
            continue
        source = str(function.get("source", "")) if bytecode else ""
        collect(function.get("instructions"), source)
        collect(function.get("disassembly"), source)
        blocks = function.get("blocks", [])
        if isinstance(blocks, list):
            for block in blocks:
                if type(block) is dict or isinstance(block, Mapping):
                    collect(block.get("instructions"), source)
    return [indexed[key] for key in sorted(indexed, key=lambda key: (key[1], key[0]))]


def _json_bytes(value: Any) -> bytes:
    try:
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False,
                             separators=(",", ":")).encode("utf-8")
    except (ValueError, TypeError, RecursionError) as error:
        raise StorageError("Analysis contains unsupported or excessively nested JSON data") from error
    if len(encoded) > MAX_CHUNK_BYTES:
        raise StorageError("Analysis chunk exceeds the supported size limit")
    return encoded


def _import_annotations(value: Any, content_hash: str) -> dict[str, dict[int, str]]:
    result: dict[str, dict[int, str]] = {"renames": {}, "comments": {}}
    if value is None:
        return result
    if not isinstance(value, Mapping) or not isinstance(value.get("sha256"), str):
        raise StorageError("Saved user annotations require their source SHA-256")
    if value["sha256"] != content_hash:
        raise SourceChangedError("Annotation source hash differs from the original input")
    for kind in ("renames", "comments"):
        values = value.get(kind, {})
        if not isinstance(values, Mapping):
            raise StorageError(f"Saved {kind} must be a mapping")
        for key, text in values.items():
            if type(key) is int:
                address = key
            elif isinstance(key, str) and key.isascii() and key.isdecimal():
                try:
                    address = int(key)
                except ValueError as error:
                    raise StorageError("Invalid saved annotation address") from error
            else:
                raise StorageError("Saved annotation addresses must be unsigned integers")
            try:
                ProjectStore._address(address)
            except ValueError as error:
                raise StorageError("Invalid saved annotation address") from error
            if kind == "renames":
                valid = (isinstance(text, str) and bool(text) and len(text) <= 512
                         and not any(character in text for character in "\r\n\0"))
            else:
                valid = isinstance(text, str) and len(text) <= 16_384 and "\0" not in text
            if not valid:
                raise StorageError(f"Invalid saved {kind} value")
            if address in result[kind] and result[kind][address] != text:
                raise StorageError("Conflicting saved annotation addresses")
            if text:
                result[kind][address] = text
    return result


def _decode_chunk(row: sqlite3.Row, expected_count: int) -> list[Any]:
    size = row["raw_size"]
    if type(size) is not int or not 0 < size <= MAX_CHUNK_BYTES:
        raise StorageSchemaError("Invalid decompressed chunk size")
    try:
        decoder = zlib.decompressobj()
        raw = decoder.decompress(row["data"], size + 1)
        if (len(raw) != size or not decoder.eof or decoder.unused_data
                or decoder.unconsumed_tail):
            raise StorageSchemaError("Corrupt or oversized compressed chunk")
        def invalid_constant(value: str) -> None:
            raise ValueError(f"Invalid JSON constant: {value}")
        values = json.loads(raw, parse_constant=invalid_constant)
    except (zlib.error, UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise StorageSchemaError("Invalid compressed analysis JSON") from error
    if not isinstance(values, list) or len(values) != expected_count:
        raise StorageSchemaError("Analysis chunk item count is inconsistent")
    return values


class _Encoder:
    """Borrow input records; copy only the current bounded serialization chunk."""

    def __init__(self, annotations: dict[str, dict[int, str]] | None = None) -> None:
        self.instructions: list[Mapping[str, Any]] = []
        self.by_address: dict[int, list[tuple[int, Mapping[str, Any]]]] = {}
        self.current_instruction: int | None = None
        self.dependencies: dict[int, set[int]] = {}
        self.annotations = annotations

    def reference(self, index: int) -> dict[str, int]:
        if self.current_instruction is not None:
            if self.current_instruction == index:
                raise StorageError("Analysis contains cyclic instruction records")
            self.dependencies.setdefault(self.current_instruction, set()).add(index)
        return {_REF: index}

    def pack(self, value: Any) -> Any:
        kind = type(value)
        if kind in _SCALARS:
            return value
        if kind is dict or (kind is not list and kind is not tuple and isinstance(value, Mapping)):
            if (type(value.get("addr")) is int and type(value.get("size")) is int
                    and isinstance(value.get("mnemonic"), str)):
                address = value["addr"]
                candidates = self.by_address.setdefault(address, [])
                for index, previous in candidates:
                    if previous is value or previous == value:
                        return self.reference(index)
                index = len(self.instructions)
                self.instructions.append(value)
                candidates.append((index, value))
                return self.reference(index)
            return self.pack_mapping(value)
        if kind is list or kind is tuple or isinstance(value, (list, tuple)):
            pack = self.pack
            return [item if type(item) in _SCALARS else pack(item) for item in value]
        return value

    def pack_mapping(self, value: Mapping[str, Any]) -> dict[str, Any]:
        if self.annotations:
            address = value.get("address", value.get("start", value.get("addr")))
            restored = None
            if type(address) is int:
                name = self.annotations["renames"].get(address)
                if (name is not None and value.get("name") == name
                        and "original_name" in value):
                    restored = dict(value)
                    restored["name"] = restored.pop("original_name")
                comment = self.annotations["comments"].get(address)
                if comment is not None and value.get("comment") == comment:
                    if restored is None:
                        restored = dict(value)
                    if "original_comment" in restored:
                        restored["comment"] = restored.pop("original_comment")
                    else:
                        restored.pop("comment", None)
            if restored is not None:
                value = restored
        pack = self.pack
        packed = {key: (item if type(item) in _SCALARS else pack(item))
                  for key, item in value.items()}
        # Escape literal user data which resembles an internal reference.
        if len(packed) == 1 and (_REF in packed or _LITERAL in packed):
            return {_LITERAL: packed}
        return packed

    def instruction(self, index: int) -> dict[str, Any]:
        self.current_instruction = index
        try:
            return self.pack_mapping(self.instructions[index])
        finally:
            self.current_instruction = None

    def validate_dependencies(self) -> None:
        states: dict[int, int] = {}
        for root in self.dependencies:
            if states.get(root) == 2:
                continue
            stack = [(root, False)]
            while stack:
                index, leaving = stack.pop()
                if leaving:
                    states[index] = 2
                    continue
                if states.get(index) == 1:
                    raise StorageError("Analysis contains cyclic instruction records")
                if states.get(index) == 2:
                    continue
                states[index] = 1
                stack.append((index, True))
                stack.extend((child, False) for child in self.dependencies.get(index, ()))


class _Reader:
    def __init__(self, connection: sqlite3.Connection, snapshot_id: int) -> None:
        self.connection, self.snapshot_id = connection, snapshot_id
        self.collections: dict[str, sqlite3.Row] = {}
        self.chunks: OrderedDict[tuple[str, int], list[Any]] = OrderedDict()
        self.instructions: dict[int, dict[str, Any]] = {}
        self.resolving: set[int] = set()

    def descriptor(self, collection: str) -> sqlite3.Row:
        if collection not in self.collections:
            row = self.connection.execute(
                "SELECT * FROM fdb_collections WHERE snapshot_id=? AND collection=?",
                (self.snapshot_id, collection)).fetchone()
            if row is None:
                raise StorageSchemaError(f"Missing analysis collection: {collection}")
            count, chunks = row["item_count"], row["chunk_count"]
            if (type(count) is not int or count < 0 or type(chunks) is not int
                    or chunks != (count + CHUNK_ITEMS - 1) // CHUNK_ITEMS):
                raise StorageSchemaError("Invalid analysis collection count")
            self.collections[collection] = row
        return self.collections[collection]

    def items(self, collection: str, offset: int, limit: int, *, expand: bool = True
              ) -> list[Any]:
        descriptor = self.descriptor(collection)
        if descriptor["alias"] is not None:
            target = descriptor["alias"]
            if (collection != "disassembly" or target not in {
                    "metadata.disassembly", "metadata.full_disassembly"}
                    or target == collection or self.descriptor(target)["alias"] is not None
                    or self.descriptor(target)["item_count"] != descriptor["item_count"]):
                raise StorageSchemaError("Invalid analysis collection alias")
            return self.items(target, offset, limit, expand=expand)
        stop = min(offset + limit, descriptor["item_count"])
        values: list[Any] = []
        if offset >= stop:
            return values
        for chunk_index in range(offset // CHUNK_ITEMS, (stop - 1) // CHUNK_ITEMS + 1):
            key = (collection, chunk_index)
            if key in self.chunks:
                chunk = self.chunks[key]
                self.chunks.move_to_end(key)
            else:
                row = self.connection.execute(
                    "SELECT * FROM fdb_chunks WHERE snapshot_id=? AND collection=? AND chunk_index=?",
                    (self.snapshot_id, collection, chunk_index)).fetchone()
                expected = min(CHUNK_ITEMS, descriptor["item_count"] - chunk_index * CHUNK_ITEMS)
                if (row is None or row["ordinal_start"] != chunk_index * CHUNK_ITEMS
                        or row["item_count"] != expected):
                    raise StorageSchemaError("Missing or inconsistent analysis chunk")
                chunk = _decode_chunk(row, expected)
                self.chunks[key] = chunk
                if len(self.chunks) > 8:
                    self.chunks.popitem(last=False)
            start = max(0, offset - chunk_index * CHUNK_ITEMS)
            end = min(len(chunk), stop - chunk_index * CHUNK_ITEMS)
            for item in chunk[start:end]:
                values.append(self.expand(item) if expand else item)
        return values

    def _pool_record(self, index: int) -> Any:
        """读取一条指令池原始记录；块已在 LRU 中时直接取，等价于 items(_POOL, index, 1)。"""
        key = (_POOL, index // CHUNK_ITEMS)
        chunk = self.chunks.get(key)
        if chunk is None:
            return self.items(_POOL, index, 1, expand=False)[0]
        self.chunks.move_to_end(key)
        return chunk[index - key[1] * CHUNK_ITEMS]

    def expand(self, value: Any) -> Any:
        if isinstance(value, dict):
            if len(value) == 1 and _REF in value:
                index = value[_REF]
                if type(index) is int:
                    # 已解析的指令只可能来自通过边界检查的索引；共享引用直接复用。
                    cached = self.instructions.get(index)
                    if cached is not None:
                        return cached
                if (type(index) is not int or index < 0
                        or index >= self.descriptor(_POOL)["item_count"]):
                    raise StorageSchemaError("Invalid instruction reference")
                if index in self.resolving:
                    raise StorageSchemaError("Cyclic instruction references")
                if index not in self.instructions:
                    self.resolving.add(index)
                    try:
                        record = self._pool_record(index)
                        instruction = self.expand(record)
                        if not isinstance(instruction, dict):
                            raise StorageSchemaError("Invalid instruction pool record")
                        self.instructions[index] = instruction
                    finally:
                        self.resolving.remove(index)
                return self.instructions[index]
            if len(value) == 1 and _LITERAL in value:
                literal = value[_LITERAL]
                if not isinstance(literal, dict):
                    raise StorageSchemaError("Invalid escaped literal")
                return {key: self.expand(item) for key, item in literal.items()}
            expand = self.expand
            return {key: (item if type(item) in _SCALARS else expand(item))
                    for key, item in value.items()}
        if isinstance(value, list):
            expand = self.expand
            return [item if type(item) in _SCALARS else expand(item) for item in value]
        return value


class SQLiteAnalysisDatabase:
    """Snapshot-addressed database; opening never invokes source analysis."""

    @property
    def fresh_snapshots(self) -> bool:
        """可选协议属性：get_snapshot 每次返回全新且不再被引用的对象图，调用方可直接接管。

        子类可能缓存或复用快照，因此只有本类自身作此保证；未声明的提供者视为 False。
        """
        return type(self) is SQLiteAnalysisDatabase

    # Reuse transaction and annotation-address rules without exposing legacy
    # source-addressed cache operations on this distinct storage interface.
    _transaction = ProjectStore._transaction
    _sync_file = staticmethod(ProjectStore._sync_file)
    _snapshot_id = staticmethod(ProjectStore._snapshot_id)
    _address = staticmethod(ProjectStore._address)
    history = ProjectStore.history

    def __init__(self, database: str | Path, *, read_only: bool = False,
                 create: bool = False) -> None:
        if type(read_only) is not bool or type(create) is not bool:
            raise ValueError("read_only and create must be boolean")
        if read_only and create:
            raise ValueError("A read-only database cannot be created")
        self.path = Path(database).expanduser().resolve()
        self.read_only, self._closed = read_only, False
        if not self.path.exists():
            if not create:
                raise FileNotFoundError(f"Analysis database does not exist: {self.path}")
            self.path.parent.mkdir(parents=True, exist_ok=True)
            try:
                descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                # A concurrent creator must finish before we consider its format.
                raise StorageError(f"Database was created concurrently: {self.path}") from None
            os.close(descriptor)
            try:
                self._create_database()
            except Exception:
                for suffix in ("", "-wal", "-shm"):
                    Path(f"{self.path}{suffix}").unlink(missing_ok=True)
                raise
        self._validate_database()

    def _check_open(self) -> None:
        if self._closed:
            raise StorageError("Analysis database is closed")

    @contextmanager
    def _connect(self, *, read_only: bool = False) -> Iterator[sqlite3.Connection]:
        self._check_open()
        effective_read_only = read_only or self.read_only
        mode = "ro" if effective_read_only else "rw"
        try:
            connection = sqlite3.connect(f"{self.path.as_uri()}?mode={mode}", uri=True,
                                         timeout=15, isolation_level=None)
            try:
                connection.row_factory = sqlite3.Row
                connection.execute("PRAGMA foreign_keys=ON")
                connection.execute("PRAGMA busy_timeout=15000")
                if effective_read_only:
                    connection.execute("PRAGMA query_only=ON")
                yield connection
            finally:
                connection.close()
        except sqlite3.Error as error:
            raise StorageError(f"Analysis database operation failed: {error}") from error

    def _require_write(self) -> None:
        self._check_open()
        if self.read_only:
            raise StorageError("Analysis database is read-only")

    def _create_database(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("BEGIN IMMEDIATE")
            try:
                ProjectStore._create_v1(connection)
                ProjectStore._migrate_v2(connection)
                connection.execute(f"PRAGMA user_version={PROJECT_SCHEMA_VERSION}")
                connection.execute("CREATE TABLE fdb_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                connection.executemany("INSERT INTO fdb_meta(key,value) VALUES (?,?)", [
                    ("format", FORMAT), ("storage_schema_version", str(STORAGE_SCHEMA_VERSION)),
                    ("chunk_items", str(CHUNK_ITEMS)), ("created_at", _now())])
                connection.execute("""CREATE TABLE fdb_collections (
                    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
                    collection TEXT NOT NULL, item_count INTEGER NOT NULL,
                    chunk_count INTEGER NOT NULL, alias TEXT,
                    PRIMARY KEY(snapshot_id, collection))""")
                connection.execute("""CREATE TABLE fdb_chunks (
                    snapshot_id INTEGER NOT NULL, collection TEXT NOT NULL,
                    chunk_index INTEGER NOT NULL, ordinal_start INTEGER NOT NULL,
                    item_count INTEGER NOT NULL, raw_size INTEGER NOT NULL, data BLOB NOT NULL,
                    PRIMARY KEY(snapshot_id, collection, chunk_index),
                    FOREIGN KEY(snapshot_id, collection)
                        REFERENCES fdb_collections(snapshot_id, collection) ON DELETE CASCADE)""")
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def _validate_database(self) -> None:
        if not self.path.is_file():
            raise StorageSchemaError("Analysis database is not a regular file")
        with self.path.open("rb") as stream:
            if stream.read(16) != b"SQLite format 3\x00":
                raise StorageSchemaError("File is not a Fangida SQLite analysis database")
        required = {
            "files": {"id", "path", "content_hash", "size", "updated_at"},
            "snapshots": {"id", "file_id", "content_hash", "status", "result_schema",
                          "created_at", "result_json", "invalidated_at"},
            "snapshot_entries": {"snapshot_id", "collection", "ordinal", "value_json"},
            "annotations": {"file_id", "content_hash", "address", "kind", "value", "updated_at"},
            "fdb_meta": {"key", "value"},
            "fdb_collections": {"snapshot_id", "collection", "item_count", "chunk_count", "alias"},
            "fdb_chunks": {"snapshot_id", "collection", "chunk_index", "ordinal_start",
                           "item_count", "raw_size", "data"},
        }
        try:
            with self._connect(read_only=True) as connection:
                if connection.execute("PRAGMA user_version").fetchone()[0] != PROJECT_SCHEMA_VERSION:
                    raise StorageSchemaError("Unsupported base project schema version")
                tables = {row["name"] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'")}
                for table, columns in required.items():
                    if table not in tables:
                        raise StorageSchemaError(f"Missing analysis database table: {table}")
                    actual = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
                    if not columns.issubset(actual):
                        raise StorageSchemaError(f"Invalid analysis database table: {table}")
                metadata = dict(connection.execute("SELECT key,value FROM fdb_meta"))
                if metadata.get("format") != FORMAT:
                    raise StorageSchemaError("File is not a Fangida analysis database")
                if metadata.get("storage_schema_version") != str(STORAGE_SCHEMA_VERSION):
                    raise StorageSchemaError("Unsupported analysis storage schema version")
                if metadata.get("chunk_items") != str(CHUNK_ITEMS):
                    raise StorageSchemaError("Unsupported analysis chunk layout")
        except StorageSchemaError:
            raise
        except StorageError as error:
            raise StorageSchemaError("Cannot validate analysis database schema") from error

    @staticmethod
    def _collection(connection: sqlite3.Connection, snapshot_id: int, collection: str,
                    count: int, *, alias: str | None = None) -> None:
        connection.execute("""INSERT INTO fdb_collections
            (snapshot_id,collection,item_count,chunk_count,alias) VALUES (?,?,?,?,?)""",
            (snapshot_id, collection, count, (count + CHUNK_ITEMS - 1) // CHUNK_ITEMS, alias))

    @staticmethod
    def _chunk(connection: sqlite3.Connection, snapshot_id: int, collection: str,
               chunk_index: int, values: list[Any]) -> None:
        raw = _json_bytes(values)
        connection.execute("""INSERT INTO fdb_chunks
            (snapshot_id,collection,chunk_index,ordinal_start,item_count,raw_size,data)
            VALUES (?,?,?,?,?,?,?)""", (snapshot_id, collection, chunk_index,
                chunk_index * CHUNK_ITEMS, len(values), len(raw), zlib.compress(raw, level=1)))

    def save_analysis(self, source_path: str | Path, result: AnalysisResult | Mapping[str, Any],
                      *, expected_hash: str | None = None) -> int:
        try:
            return self._save_analysis(source_path, result, expected_hash=expected_hash)
        except RecursionError as error:
            raise StorageError("Analysis contains cyclic or excessively nested data") from error

    def _save_analysis(self, source_path: str | Path, result: AnalysisResult | Mapping[str, Any],
                       *, expected_hash: str | None = None) -> int:
        self._require_write()
        source = _source_path(source_path)
        for candidate in (self.path, Path(f"{self.path}-wal"), Path(f"{self.path}-shm")):
            if candidate.exists() and source.samefile(candidate):
                raise StorageError("Original input must be separate from the analysis database and sidecars")
        content_hash, size = fingerprint(source)
        if expected_hash is not None:
            if not isinstance(expected_hash, str) or not _DIGEST_RE.fullmatch(expected_hash):
                raise ValueError("expected_hash must be a lowercase SHA-256 hex digest")
            if expected_hash != content_hash:
                raise SourceChangedError(f"Source changed during analysis: {source}")
        if isinstance(result, AnalysisResult):
            payload = {item.name: getattr(result, item.name) for item in fields(result)}
        elif isinstance(result, Mapping):
            payload = dict(result)
        else:
            raise TypeError("result must be an AnalysisResult or a mapping")
        if not isinstance(payload.get("status"), str) or not isinstance(payload.get("schema_version"), str):
            raise ValueError("result requires status and schema_version strings")
        metadata = payload.get("metadata", {})
        if not isinstance(metadata, Mapping):
            raise ValueError("metadata must be a mapping")
        imported_annotations = _import_annotations(metadata.get("user_annotations"), content_hash)
        top_collections = {key: payload[key] for key in COLLECTIONS - {"disassembly"} if key in payload}
        metadata_collections = {f"metadata.{key}": metadata[key]
                                for key in ("disassembly", "full_disassembly") if key in metadata}
        collections = {**top_collections, **metadata_collections}
        for key, values in collections.items():
            if not isinstance(values, list):
                raise ValueError(f"{key} must be a list")
        disassembly_records = _disassembly_records(payload, metadata)
        light = {key: value for key, value in payload.items() if key not in top_collections}
        light["metadata"] = {key: value for key, value in metadata.items()
                             if key not in {"disassembly", "full_disassembly", "analysis_database", "user_annotations"}}
        encoder = _Encoder(imported_annotations if any(imported_annotations.values()) else None)
        manifest = {"payload": encoder.pack(light), "collections": list(collections),
                    "format": FORMAT, "storage_schema_version": STORAGE_SCHEMA_VERSION}
        # Validate lightweight fields before beginning any mutation.
        _json_bytes([manifest])
        with self._transaction() as connection:
            file_id = self._sync_file(connection, source, content_hash, size)
            cursor = connection.execute("""INSERT INTO snapshots
                (file_id,content_hash,status,result_schema,created_at,result_json) VALUES (?,?,?,?,?,?)""",
                (file_id, content_hash, payload["status"], payload["schema_version"], _now(),
                 json.dumps({"format": FORMAT, "storage_schema_version": STORAGE_SCHEMA_VERSION,
                             "source_size": size})))
            snapshot_id = int(cursor.lastrowid)
            for kind, values in imported_annotations.items():
                annotation_kind = "rename" if kind == "renames" else "comment"
                connection.executemany("""INSERT INTO annotations
                    (file_id,content_hash,address,kind,value,updated_at) VALUES (?,?,?,?,?,?)
                    ON CONFLICT(file_id,content_hash,address,kind)
                    DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at""",
                    ((file_id, content_hash, self._address(address), annotation_kind, text, _now())
                     for address, text in values.items()))
            for name, values in collections.items():
                self._collection(connection, snapshot_id, name, len(values))
                for start in range(0, len(values), CHUNK_ITEMS):
                    self._chunk(connection, snapshot_id, name, start // CHUNK_ITEMS,
                                [encoder.pack(value) for value in values[start:start + CHUNK_ITEMS]])
            for name in COLLECTIONS - {"disassembly"}:
                if name not in collections:
                    self._collection(connection, snapshot_id, name, 0)
            disassembly_alias = None
            for candidate in ("metadata.full_disassembly", "metadata.disassembly"):
                if candidate in collections and disassembly_records == collections[candidate]:
                    disassembly_alias = candidate
                    break
            self._collection(connection, snapshot_id, "disassembly", len(disassembly_records),
                             alias=disassembly_alias)
            if disassembly_alias is None:
                for start in range(0, len(disassembly_records), CHUNK_ITEMS):
                    self._chunk(connection, snapshot_id, "disassembly", start // CHUNK_ITEMS,
                                [encoder.pack(value) for value in disassembly_records[start:start + CHUNK_ITEMS]])
            self._collection(connection, snapshot_id, _MANIFEST, 1)
            self._chunk(connection, snapshot_id, _MANIFEST, 0, [manifest])
            # Pool records are serialized once; a rare nested instruction can
            # append to the pool while its containing record is being packed.
            pool_count = len(encoder.instructions)
            self._collection(connection, snapshot_id, _POOL, pool_count)
            start = 0
            while start < len(encoder.instructions):
                values: list[Any] = []
                while len(values) < CHUNK_ITEMS and start + len(values) < len(encoder.instructions):
                    values.append(encoder.instruction(start + len(values)))
                self._chunk(connection, snapshot_id, _POOL, start // CHUNK_ITEMS, values)
                start += len(values)
            if pool_count != len(encoder.instructions):
                pool_count = len(encoder.instructions)
                connection.execute("UPDATE fdb_collections SET item_count=?,chunk_count=? "
                                   "WHERE snapshot_id=? AND collection=?",
                                   (pool_count, (pool_count + CHUNK_ITEMS - 1) // CHUNK_ITEMS,
                                    snapshot_id, _POOL))
            encoder.validate_dependencies()
            if fingerprint(source) != (content_hash, size):
                raise SourceChangedError(f"Source changed during save: {source}")
            return snapshot_id

    @staticmethod
    def _snapshot(connection: sqlite3.Connection, snapshot_id: int | None) -> sqlite3.Row:
        if snapshot_id is None:
            row = connection.execute("""SELECT s.*,f.path AS source_path,f.size AS source_size
                FROM snapshots s JOIN files f ON s.file_id=f.id ORDER BY s.id DESC LIMIT 1""").fetchone()
        else:
            ProjectStore._snapshot_id(snapshot_id)
            row = connection.execute("""SELECT s.*,f.path AS source_path,f.size AS source_size
                FROM snapshots s JOIN files f ON s.file_id=f.id WHERE s.id=?""", (snapshot_id,)).fetchone()
        if row is None:
            raise KeyError(f"Unknown snapshot: {snapshot_id}")
        try:
            descriptor = json.loads(row["result_json"])
        except (ValueError, TypeError) as error:
            raise StorageSchemaError("Invalid analysis snapshot descriptor") from error
        if (not isinstance(descriptor, dict) or descriptor.get("format") != FORMAT
                or descriptor.get("storage_schema_version") != STORAGE_SCHEMA_VERSION
                or type(descriptor.get("source_size")) is not int or descriptor["source_size"] < 0):
            raise StorageSchemaError("Unsupported analysis snapshot descriptor")
        return row

    @staticmethod
    def _annotations(connection: sqlite3.Connection, snapshot: sqlite3.Row) -> dict[str, Any]:
        result: dict[str, Any] = {"sha256": snapshot["content_hash"], "renames": {}, "comments": {}}
        for row in connection.execute("""SELECT address,kind,value FROM annotations
                WHERE file_id=? AND content_hash=? ORDER BY address,kind""",
                (snapshot["file_id"], snapshot["content_hash"])):
            try:
                address = int(row["address"], 16)
            except (ValueError, TypeError) as error:
                raise StorageSchemaError("Invalid annotation address") from error
            if not 0 <= address <= 0xFFFFFFFFFFFFFFFF or row["kind"] not in {"rename", "comment"}:
                raise StorageSchemaError("Invalid annotation record")
            key = "renames" if row["kind"] == "rename" else "comments"
            result[key][address] = row["value"]
        return result

    @staticmethod
    def _overlay(value: Any, annotations: dict[str, Any], seen: set[int] | None = None) -> None:
        if seen is None:
            seen = set()
        if isinstance(value, (dict, list)):
            identity = id(value)
            if identity in seen:
                return
            seen.add(identity)
        if isinstance(value, dict):
            address = value.get("address", value.get("start", value.get("addr")))
            if type(address) is int:
                if address in annotations["renames"] and "name" in value:
                    value.setdefault("original_name", value["name"])
                    value["name"] = annotations["renames"][address]
                if address in annotations["comments"]:
                    if "comment" in value:
                        value.setdefault("original_comment", value["comment"])
                    value["comment"] = annotations["comments"][address]
            for item in list(value.values()):
                SQLiteAnalysisDatabase._overlay(item, annotations, seen)
        elif isinstance(value, list):
            for item in value:
                SQLiteAnalysisDatabase._overlay(item, annotations, seen)

    def get_snapshot(self, snapshot_id: int | None = None) -> dict[str, Any]:
        try:
            return self._get_snapshot(snapshot_id)
        except RecursionError as error:
            raise StorageSchemaError("Analysis database contains excessively nested data") from error

    def _get_snapshot(self, snapshot_id: int | None = None) -> dict[str, Any]:
        with self._connect(read_only=True) as connection:
            connection.execute("BEGIN")
            snapshot = self._snapshot(connection, snapshot_id)
            reader = _Reader(connection, snapshot["id"])
            manifest = reader.items(_MANIFEST, 0, 1)[0]
            if (not isinstance(manifest, dict) or manifest.get("format") != FORMAT
                    or manifest.get("storage_schema_version") != STORAGE_SCHEMA_VERSION
                    or not isinstance(manifest.get("payload"), dict)
                    or not isinstance(manifest.get("collections"), list)
                    or not isinstance(manifest["payload"].get("metadata"), dict)):
                raise StorageSchemaError("Invalid analysis snapshot manifest")
            payload = manifest["payload"]
            for name in manifest["collections"]:
                if not isinstance(name, str) or name not in COLLECTIONS | {
                        "metadata.disassembly", "metadata.full_disassembly"}:
                    raise StorageSchemaError("Invalid snapshot collection")
                values = reader.items(name, 0, reader.descriptor(name)["item_count"])
                if name.startswith("metadata."):
                    payload["metadata"][name.removeprefix("metadata.")] = values
                else:
                    payload[name] = values
            annotations = self._annotations(connection, snapshot)
            if annotations["renames"] or annotations["comments"]:
                self._overlay(payload, annotations)
            metadata = payload.setdefault("metadata", {})
            metadata["user_annotations"] = {"sha256": annotations["sha256"],
                "renames": {str(key): value for key, value in annotations["renames"].items()},
                "comments": {str(key): value for key, value in annotations["comments"].items()}}
            metadata["analysis_database"] = {"path": str(self.path), "snapshot_id": snapshot["id"],
                "format": FORMAT, "source_sha256": snapshot["content_hash"],
                "source_size": json.loads(snapshot["result_json"])["source_size"],
                "read_only": self.read_only}
            return payload

    def page(self, snapshot_id: int, collection: str, *, offset: int = 0,
             limit: int = 100) -> dict[str, Any]:
        try:
            return self._page(snapshot_id, collection, offset=offset, limit=limit)
        except RecursionError as error:
            raise StorageSchemaError("Analysis database contains excessively nested data") from error

    def _page(self, snapshot_id: int, collection: str, *, offset: int = 0,
              limit: int = 100) -> dict[str, Any]:
        self._snapshot_id(snapshot_id)
        if collection not in COLLECTIONS:
            raise ValueError(f"Unknown collection: {collection}")
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= MAX_PAGE_SIZE:
            raise ValueError("invalid collection pagination")
        with self._connect(read_only=True) as connection:
            connection.execute("BEGIN")
            snapshot = self._snapshot(connection, snapshot_id)
            reader = _Reader(connection, snapshot_id)
            total = reader.descriptor(collection)["item_count"]
            items = reader.items(collection, offset, limit)
            annotations = self._annotations(connection, snapshot)
            if annotations["renames"] or annotations["comments"]:
                self._overlay(items, annotations)
            following = offset + len(items)
            return {"items": items, "total": total,
                    "next_offset": following if following < total else None}

    def annotations(self, snapshot_id: int) -> dict[str, Any]:
        self._snapshot_id(snapshot_id)
        with self._connect(read_only=True) as connection:
            connection.execute("BEGIN")
            return self._annotations(connection, self._snapshot(connection, snapshot_id))

    def _set_snapshot_annotation(self, snapshot_id: int, address: int, kind: str, value: str) -> None:
        self._snapshot_id(snapshot_id)
        address_hex = self._address(address)
        with self._transaction() as connection:
            snapshot = self._snapshot(connection, snapshot_id)
            if value == "":
                connection.execute("DELETE FROM annotations WHERE file_id=? AND content_hash=? AND address=? AND kind=?",
                                   (snapshot["file_id"], snapshot["content_hash"], address_hex, kind))
            else:
                connection.execute("""INSERT INTO annotations
                    (file_id,content_hash,address,kind,value,updated_at) VALUES (?,?,?,?,?,?)
                    ON CONFLICT(file_id,content_hash,address,kind)
                    DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at""",
                    (snapshot["file_id"], snapshot["content_hash"], address_hex, kind, value, _now()))

    def rename_symbol(self, snapshot_id: int, address: int, name: str) -> None:
        if not isinstance(name, str) or not name or len(name) > 512 or any(char in name for char in "\r\n\0"):
            raise ValueError("name must be a non-empty, single-line string of at most 512 characters")
        self._set_snapshot_annotation(snapshot_id, address, "rename", name)

    def set_comment(self, snapshot_id: int, address: int, text: str) -> None:
        if not isinstance(text, str) or len(text) > 16_384 or "\0" in text:
            raise ValueError("comment must be a string of at most 16384 characters")
        self._set_snapshot_annotation(snapshot_id, address, "comment", text)

    def info(self) -> dict[str, Any]:
        with self._connect(read_only=True) as connection:
            latest = connection.execute("SELECT MAX(id) FROM snapshots").fetchone()[0]
            return {"path": str(self.path), "format": FORMAT,
                    "storage_schema_version": STORAGE_SCHEMA_VERSION, "read_only": self.read_only,
                    "snapshot_count": connection.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0],
                    "latest_snapshot_id": latest,
                    "source_count": connection.execute("SELECT COUNT(*) FROM files").fetchone()[0],
                    "stores_original_binary": False,
                    "codec": "zlib-json-shared-instructions", "chunk_items": CHUNK_ITEMS}

    def close(self) -> None:
        self._closed = True

    def __enter__(self) -> SQLiteAnalysisDatabase:
        self._check_open()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


class PluginImpl:
    name = "sqlite_storage"
    version = "0.1.0"

    def __init__(self) -> None:
        self._databases: weakref.WeakSet[SQLiteAnalysisDatabase] = weakref.WeakSet()
        self._lock = Lock()
        self._closed = False

    def capabilities(self) -> tuple[str, ...]:
        return ("analysis_database", "snapshots", "annotations", "pagination", "read_only")

    def open_database(self, path: str | Path, *, read_only: bool = False,
                      create: bool = False) -> SQLiteAnalysisDatabase:
        with self._lock:
            if self._closed:
                raise StorageError("Storage plugin is closed")
            database = SQLiteAnalysisDatabase(path, read_only=read_only, create=create)
            self._databases.add(database)
            return database

    def teardown(self) -> None:
        with self._lock:
            for database in tuple(self._databases):
                database.close()
            self._databases.clear()
            self._closed = True
