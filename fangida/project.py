"""Persistent, content-addressed analysis snapshots and user annotations.

The project database stores JSON results and annotations, never changes an input
binary. Each operation opens its own SQLite connection, so ProjectStore can be
shared by independent threads and reopened by another process.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, fields, is_dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Iterator, Mapping

from .models import AnalysisResult


PROJECT_SCHEMA_VERSION = 2
MAX_PAGE_SIZE = 1000
COLLECTIONS = frozenset({"functions", "strings", "imports", "exports", "xrefs",
                         "warnings", "disassembly"})
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")


class ProjectError(Exception):
    """Base class for errors reading or writing a project database."""


class ProjectSchemaError(ProjectError):
    """The database has an unsupported or inconsistent schema version."""


class SourceChangedError(ProjectError):
    """The source changed during hashing or differs from the expected hash."""


def _dataclass_json(value: Any) -> Any:
    """json 的 default 钩子：嵌套 dataclass 实例按 asdict 展开，与先整体 asdict 再编码等价。

    只用于原来会对整个结果做 asdict 的输入；其余对象与 JSONEncoder.default 一样报错。
    """
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    raise TypeError(f"Object of type {value.__class__.__name__} is not JSON serializable")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _source_path(path: str | Path, *, must_exist: bool = True) -> Path:
    resolved = Path(path).expanduser().resolve(strict=must_exist)
    if must_exist and not resolved.is_file():
        raise ValueError(f"Not a regular file: {resolved}")
    return resolved


def fingerprint(path: str | Path) -> tuple[str, int]:
    """SHA-256 and byte length, rejecting files changed during the read."""
    source = _source_path(path)
    before = source.stat()
    signature = (before.st_dev, before.st_ino, before.st_size,
                 before.st_mtime_ns, before.st_ctime_ns)
    digest = sha256()
    size = 0
    with source.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    after = source.stat()
    if signature != (after.st_dev, after.st_ino, after.st_size,
                     after.st_mtime_ns, after.st_ctime_ns) or size != before.st_size:
        raise SourceChangedError(f"Source changed while hashing: {source}")
    return digest.hexdigest(), size


class ProjectStore:
    """SQLite-backed snapshots. One instance can be used from several threads.

    ``save_analysis`` returns a snapshot ID. ``load_analysis`` returns the most
    recent valid snapshot for the exact current file bytes, or ``None``. The
    optional ``expected_hash`` lets callers reject a source changed during a
    potentially long analysis. Use ``fingerprint`` before starting analysis.
    """

    def __init__(self, database: str | Path, *, read_only: bool = False) -> None:
        if type(read_only) is not bool:
            raise ValueError("read_only must be boolean")
        self.read_only = read_only
        self.path = Path(database).expanduser().resolve()
        if read_only:
            if not self.path.is_file():
                raise FileNotFoundError(f"Project database does not exist: {self.path}")
            with self._connect() as connection:
                self._reject_storage_database(connection)
                version = int(connection.execute("PRAGMA user_version").fetchone()[0])
                if version != PROJECT_SCHEMA_VERSION:
                    raise ProjectSchemaError(
                        f"Project schema {version} needs version {PROJECT_SCHEMA_VERSION} for read-only access")
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            self._reject_storage_database(connection)
            # WAL allows a reader to continue while another connection writes.
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("BEGIN IMMEDIATE")
            try:
                version = int(connection.execute("PRAGMA user_version").fetchone()[0])
                if version > PROJECT_SCHEMA_VERSION:
                    raise ProjectSchemaError(
                        f"Project schema {version} is newer than supported {PROJECT_SCHEMA_VERSION}")
                if version == 0:
                    self._create_v1(connection)
                    connection.execute("PRAGMA user_version=1")
                    version = 1
                if version == 1:
                    self._migrate_v2(connection)
                    connection.execute("PRAGMA user_version=2")
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    @staticmethod
    def _reject_storage_database(connection: sqlite3.Connection) -> None:
        """Keep legacy JSON projects from reading/writing compact storage DBs."""
        if connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='fdb_meta'").fetchone():
            raise ProjectSchemaError("This is a storage-plugin analysis database; open it through the storage plugin")

    @contextmanager
    def _connect(self, *, read_only: bool = False) -> Iterator[sqlite3.Connection]:
        read_only = read_only or self.read_only
        database = f"{self.path.as_uri()}?mode=ro" if read_only else str(self.path)
        connection = sqlite3.connect(database, timeout=15, isolation_level=None,
                                     uri=read_only)
        try:
            connection.row_factory = sqlite3.Row
            if read_only:
                connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=15000")
            yield connection
        finally:
            connection.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        self._require_write()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def _require_write(self) -> None:
        if self.read_only:
            raise ProjectError("Project database is read-only")

    @staticmethod
    def _create_v1(connection: sqlite3.Connection) -> None:
        connection.execute("""CREATE TABLE files (
            id INTEGER PRIMARY KEY,
            path TEXT NOT NULL UNIQUE,
            content_hash TEXT NOT NULL,
            size INTEGER NOT NULL,
            updated_at TEXT NOT NULL
        )""")
        connection.execute("""CREATE TABLE snapshots (
            id INTEGER PRIMARY KEY,
            file_id INTEGER NOT NULL REFERENCES files(id),
            content_hash TEXT NOT NULL,
            status TEXT NOT NULL,
            result_schema TEXT NOT NULL,
            created_at TEXT NOT NULL,
            result_json TEXT NOT NULL
        )""")
        connection.execute("""CREATE TABLE snapshot_entries (
            snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
            collection TEXT NOT NULL,
            ordinal INTEGER NOT NULL,
            value_json TEXT NOT NULL,
            PRIMARY KEY (snapshot_id, collection, ordinal)
        )""")
        connection.execute("CREATE INDEX snapshots_lookup ON snapshots(file_id, content_hash, id DESC)")

    @staticmethod
    def _migrate_v2(connection: sqlite3.Connection) -> None:
        connection.execute("ALTER TABLE snapshots ADD COLUMN invalidated_at TEXT")
        connection.execute("""CREATE TABLE annotations (
            file_id INTEGER NOT NULL REFERENCES files(id),
            content_hash TEXT NOT NULL,
            address TEXT NOT NULL,
            kind TEXT NOT NULL CHECK (kind IN ('rename', 'comment')),
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (file_id, content_hash, address, kind)
        )""")
        connection.execute("CREATE INDEX annotations_lookup ON annotations(file_id, content_hash)")

    @staticmethod
    def _sync_file(connection: sqlite3.Connection, source: Path,
                   content_hash: str, size: int) -> int:
        row = connection.execute("SELECT id, content_hash FROM files WHERE path=?",
                                 (str(source),)).fetchone()
        if row is None:
            cursor = connection.execute(
                "INSERT INTO files(path, content_hash, size, updated_at) VALUES (?, ?, ?, ?)",
                (str(source), content_hash, size, _now()))
            return int(cursor.lastrowid)
        file_id = int(row["id"])
        if row["content_hash"] != content_hash:
            # History is retained, but old snapshots cannot become valid again
            # if a file cycles back to previously seen bytes.
            connection.execute(
                "UPDATE snapshots SET invalidated_at=? WHERE file_id=? AND invalidated_at IS NULL",
                (_now(), file_id))
            connection.execute(
                "UPDATE files SET content_hash=?, size=?, updated_at=? WHERE id=?",
                (content_hash, size, _now(), file_id))
        return file_id

    def save_analysis(self, source_path: str | Path, result: AnalysisResult | Mapping[str, Any],
                      *, expected_hash: str | None = None) -> int:
        self._require_write()
        source = _source_path(source_path)
        content_hash, size = fingerprint(source)
        if expected_hash is not None:
            if not isinstance(expected_hash, str) or not _DIGEST_RE.fullmatch(expected_hash):
                raise ValueError("expected_hash must be a lowercase SHA-256 hex digest")
            if content_hash != expected_hash:
                raise SourceChangedError(f"Source changed during analysis: {source}")
        # 精确的 AnalysisResult 不再 asdict 深拷贝整图（完整分析有数百万节点）：JSON 文本只取决于值，
        # 浅层字段视图配合 default 钩子展开嵌套 dataclass，与 asdict 后编码逐字节一致。
        # 子类可能覆写 to_dict，metadata 非 dict 时后面的 .get 依赖 asdict 的转换，均保持原路径。
        owned = type(result) is AnalysisResult and isinstance(result.metadata, dict)
        if owned:
            payload = {item.name: getattr(result, item.name) for item in fields(result)}
        elif isinstance(result, AnalysisResult):
            payload = result.to_dict()
        elif isinstance(result, Mapping):
            payload = dict(result)
        else:
            raise TypeError("result must be an AnalysisResult or a mapping")
        if not isinstance(payload.get("status"), str) or not isinstance(payload.get("schema_version"), str):
            raise ValueError("result requires status and schema_version strings")
        # 与 json.dumps(value, ensure_ascii=False, allow_nan=False) 选项相同，复用一个编码器实例；
        # default 钩子只用于原来会 asdict 的输入，映射输入里的 dataclass 仍抛 TypeError。
        encode = json.JSONEncoder(ensure_ascii=False, allow_nan=False,
                                  default=_dataclass_json if owned else None).encode
        result_json = encode(payload)
        # 条目仍在事务开始前全部编码成列表：编码错误先于任何写入抛出，写锁时长不变。
        entries: list[tuple[str, int, str]] = []
        for collection in COLLECTIONS:
            metadata = payload.get("metadata", {})
            values = (metadata.get("full_disassembly", metadata.get("disassembly", []))
                      if collection == "disassembly" else payload.get(collection, []))
            if not isinstance(values, list):
                raise ValueError(f"{collection} must be a list")
            entries.extend((collection, ordinal, encode(value)) for ordinal, value in enumerate(values))
        with self._transaction() as connection:
            file_id = self._sync_file(connection, source, content_hash, size)
            cursor = connection.execute(
                """INSERT INTO snapshots(file_id, content_hash, status, result_schema,
                                         created_at, result_json)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (file_id, content_hash, payload["status"], payload["schema_version"],
                 _now(), result_json))
            snapshot_id = int(cursor.lastrowid)
            connection.executemany(
                "INSERT INTO snapshot_entries(snapshot_id, collection, ordinal, value_json) VALUES (?, ?, ?, ?)",
                ((snapshot_id, collection, ordinal, value) for collection, ordinal, value in entries))
            # Detect modifications made while the database transaction ran.
            if fingerprint(source) != (content_hash, size):
                raise SourceChangedError(f"Source changed during save: {source}")
            return snapshot_id

    def load_analysis(self, source_path: str | Path) -> dict[str, Any] | None:
        source = _source_path(source_path)
        content_hash, size = fingerprint(source)
        if self.read_only:
            with self._connect() as connection:
                file_row = connection.execute(
                    "SELECT id, content_hash FROM files WHERE path=?", (str(source),)).fetchone()
                row = None
                if file_row is not None and file_row["content_hash"] == content_hash:
                    row = connection.execute(
                        """SELECT result_json FROM snapshots WHERE file_id=? AND content_hash=?
                           AND invalidated_at IS NULL ORDER BY id DESC LIMIT 1""",
                        (file_row["id"], content_hash)).fetchone()
                if fingerprint(source) != (content_hash, size):
                    raise SourceChangedError(f"Source changed during cache lookup: {source}")
                return json.loads(row["result_json"]) if row else None
        with self._transaction() as connection:
            file_id = self._sync_file(connection, source, content_hash, size)
            row = connection.execute(
                """SELECT result_json FROM snapshots WHERE file_id=? AND content_hash=?
                   AND invalidated_at IS NULL ORDER BY id DESC LIMIT 1""",
                (file_id, content_hash)).fetchone()
            if fingerprint(source) != (content_hash, size):
                raise SourceChangedError(f"Source changed during cache lookup: {source}")
            return json.loads(row["result_json"]) if row else None

    def get_snapshot(self, snapshot_id: int) -> dict[str, Any]:
        snapshot_id = self._snapshot_id(snapshot_id)
        with self._connect() as connection:
            row = connection.execute("SELECT result_json FROM snapshots WHERE id=?",
                                     (snapshot_id,)).fetchone()
            if row is None:
                raise KeyError(f"Unknown snapshot: {snapshot_id}")
            return json.loads(row["result_json"])

    def page(self, snapshot_id: int, collection: str, *, offset: int = 0,
             limit: int = 100) -> dict[str, Any]:
        """Return an indexed page with total and next_offset, without decoding the full snapshot."""
        snapshot_id = self._snapshot_id(snapshot_id)
        if collection not in COLLECTIONS:
            raise ValueError(f"Unknown collection: {collection}")
        if type(offset) is not int or offset < 0:
            raise ValueError("offset must be a non-negative integer")
        if type(limit) is not int or not 1 <= limit <= MAX_PAGE_SIZE:
            raise ValueError(f"limit must be between 1 and {MAX_PAGE_SIZE}")
        with self._connect() as connection:
            if connection.execute("SELECT 1 FROM snapshots WHERE id=?", (snapshot_id,)).fetchone() is None:
                raise KeyError(f"Unknown snapshot: {snapshot_id}")
            total = int(connection.execute(
                "SELECT COUNT(*) FROM snapshot_entries WHERE snapshot_id=? AND collection=?",
                (snapshot_id, collection)).fetchone()[0])
            rows = connection.execute(
                """SELECT value_json FROM snapshot_entries
                   WHERE snapshot_id=? AND collection=? ORDER BY ordinal LIMIT ? OFFSET ?""",
                (snapshot_id, collection, limit, offset)).fetchall()
            items = [json.loads(row["value_json"]) for row in rows]
            following = offset + len(items)
            return {"items": items, "total": total,
                    "next_offset": following if following < total else None}

    def history(self, source_path: str | Path | None = None, *, offset: int = 0,
                limit: int = 100) -> dict[str, Any]:
        """Return immutable snapshot metadata, including invalidation timestamps."""
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= MAX_PAGE_SIZE:
            raise ValueError("invalid history pagination")
        path = str(_source_path(source_path, must_exist=False)) if source_path is not None else None
        where = "WHERE f.path=?" if path is not None else ""
        args: tuple[Any, ...] = (path,) if path is not None else ()
        with self._connect() as connection:
            total = int(connection.execute(
                f"SELECT COUNT(*) FROM snapshots s JOIN files f ON s.file_id=f.id {where}", args
            ).fetchone()[0])
            rows = connection.execute(
                f"""SELECT s.id, f.path, s.content_hash, s.status, s.result_schema,
                           s.created_at, s.invalidated_at
                    FROM snapshots s JOIN files f ON s.file_id=f.id {where}
                    ORDER BY s.id DESC LIMIT ? OFFSET ?""", (*args, limit, offset)).fetchall()
            items = [dict(row) for row in rows]
            following = offset + len(items)
            return {"items": items, "total": total,
                    "next_offset": following if following < total else None}

    def invalidate(self, source_path: str | Path) -> int:
        """Invalidate current snapshots explicitly; retain history and annotations."""
        self._require_write()
        source = _source_path(source_path, must_exist=False)
        with self._transaction() as connection:
            cursor = connection.execute(
                """UPDATE snapshots SET invalidated_at=? WHERE file_id=(
                       SELECT id FROM files WHERE path=?) AND invalidated_at IS NULL""",
                (_now(), str(source)))
            return cursor.rowcount

    @staticmethod
    def _snapshot_id(value: int) -> int:
        if type(value) is not int or value <= 0:
            raise ValueError("snapshot_id must be a positive integer")
        return value

    @staticmethod
    def _address(value: int) -> str:
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("address must be an unsigned 64-bit integer")
        return f"{value:016x}"

    def _set_annotation(self, source_path: str | Path, address: int,
                        kind: str, value: str | None) -> None:
        self._require_write()
        source = _source_path(source_path)
        address_hex = self._address(address)
        content_hash, size = fingerprint(source)
        with self._transaction() as connection:
            file_id = self._sync_file(connection, source, content_hash, size)
            if value is None or value == "":
                connection.execute(
                    "DELETE FROM annotations WHERE file_id=? AND content_hash=? AND address=? AND kind=?",
                    (file_id, content_hash, address_hex, kind))
            else:
                connection.execute(
                    """INSERT INTO annotations(file_id, content_hash, address, kind, value, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?)
                       ON CONFLICT(file_id, content_hash, address, kind)
                       DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at""",
                    (file_id, content_hash, address_hex, kind, value, _now()))
            if fingerprint(source) != (content_hash, size):
                raise SourceChangedError(f"Source changed during annotation: {source}")

    def rename_symbol(self, source_path: str | Path, address: int, name: str) -> None:
        if not isinstance(name, str) or not name or len(name) > 512 or any(c in name for c in "\r\n\0"):
            raise ValueError("name must be a non-empty, single-line string of at most 512 characters")
        self._set_annotation(source_path, address, "rename", name)

    def set_comment(self, source_path: str | Path, address: int, text: str) -> None:
        if not isinstance(text, str) or len(text) > 16_384 or "\0" in text:
            raise ValueError("comment must be a string of at most 16384 characters")
        self._set_annotation(source_path, address, "comment", text)

    def annotations(self, source_path: str | Path, *, read_only: bool = True) -> dict[str, Any]:
        """Get current-hash annotations keyed by address, without modifying the DB by default."""
        source = _source_path(source_path)
        content_hash, size = fingerprint(source)
        connection_context = self._connect(read_only=True) if read_only else self._transaction()
        with connection_context as connection:
            if read_only:
                row = connection.execute("SELECT id FROM files WHERE path=?", (str(source),)).fetchone()
                file_id = int(row["id"]) if row is not None else None
            else:
                file_id = self._sync_file(connection, source, content_hash, size)
            result: dict[str, Any] = {"sha256": content_hash, "renames": {}, "comments": {}}
            if file_id is None:
                if fingerprint(source) != (content_hash, size):
                    raise SourceChangedError(f"Source changed during annotation lookup: {source}")
                return result
            rows = connection.execute(
                """SELECT address, kind, value FROM annotations
                   WHERE file_id=? AND content_hash=? ORDER BY address, kind""",
                (file_id, content_hash)).fetchall()
            for row in rows:
                field = "renames" if row["kind"] == "rename" else "comments"
                result[field][int(row["address"], 16)] = row["value"]
            if fingerprint(source) != (content_hash, size):
                raise SourceChangedError(f"Source changed during annotation lookup: {source}")
            return result
