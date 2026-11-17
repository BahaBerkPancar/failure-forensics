"""SQLite store (WAL mode) and the OpenTelemetry span exporter that fills it."""

from __future__ import annotations

import json
import os
import sqlite3
import time
import warnings
from collections.abc import Iterable, Sequence
from contextlib import closing
from pathlib import Path
from typing import Any

from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
from opentelemetry.trace import StatusCode

from .classify import Failure, Rule, classify_run
from .models import SpanRecord

DEFAULT_DB = ".ff/traces.db"

_V1 = """
CREATE TABLE IF NOT EXISTS runs (
    trace_id TEXT PRIMARY KEY, name TEXT NOT NULL, case_id TEXT,
    tags TEXT NOT NULL DEFAULT '{}', start_ns INTEGER NOT NULL, end_ns INTEGER NOT NULL,
    status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS spans (
    trace_id TEXT NOT NULL, span_id TEXT NOT NULL, parent_id TEXT, name TEXT NOT NULL,
    start_ns INTEGER NOT NULL, end_ns INTEGER NOT NULL, status TEXT NOT NULL,
    attributes TEXT NOT NULL DEFAULT '{}', PRIMARY KEY (trace_id, span_id)
);
CREATE TABLE IF NOT EXISTS failures (
    id INTEGER PRIMARY KEY AUTOINCREMENT, trace_id TEXT NOT NULL, span_id TEXT NOT NULL,
    step TEXT NOT NULL, kind TEXT NOT NULL, message TEXT NOT NULL, signature TEXT NOT NULL,
    end_ns INTEGER NOT NULL
);
"""
_V2 = """
CREATE INDEX IF NOT EXISTS idx_failures_signature ON failures(signature);
CREATE INDEX IF NOT EXISTS idx_failures_trace ON failures(trace_id);
CREATE INDEX IF NOT EXISTS idx_runs_start ON runs(start_ns);
"""
MIGRATIONS = [_V1, _V2]  # index i brings the schema to version i + 1
SCHEMA_VERSION = len(MIGRATIONS)


def resolve_db_path(path: str | os.PathLike[str] | None = None) -> Path:
    return Path(path or os.environ.get("FF_DB") or DEFAULT_DB)


def _enable_wal(conn: sqlite3.Connection) -> None:
    """Switch to WAL once. The switch needs an exclusive lock that the busy timeout does not always
    cover, so concurrent first openers retry briefly; later opens only read the mode."""
    for attempt in range(100):
        try:
            if conn.execute("PRAGMA journal_mode").fetchone()[0].lower() != "wal":
                conn.execute("PRAGMA journal_mode=WAL")
            return
        except sqlite3.OperationalError:
            if attempt == 99:
                raise
            time.sleep(0.05)


def _connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    _enable_wal(conn)
    conn.execute("PRAGMA synchronous=NORMAL")
    _migrate(conn)
    return conn


def _current_version(conn: sqlite3.Connection) -> int:
    try:
        return conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] or 0
    except sqlite3.OperationalError:  # table does not exist yet
        return 0


def _migrate(conn: sqlite3.Connection) -> None:
    """Bring the schema up to date. Safe for concurrent openers: the work happens in one
    BEGIN IMMEDIATE transaction (others wait on the busy timeout), the DDL is idempotent, and the
    version is re-read after the lock is taken."""
    if _current_version(conn) == SCHEMA_VERSION:
        return
    old = conn.isolation_level
    conn.isolation_level = None  # manual transaction control
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
            current = _current_version(conn)
            if current > SCHEMA_VERSION:
                raise RuntimeError(
                    f"database schema v{current} is newer than this tool (v{SCHEMA_VERSION})"
                )
            for version in range(current + 1, SCHEMA_VERSION + 1):
                for stmt in MIGRATIONS[version - 1].split(";"):
                    if stmt.strip():
                        conn.execute(stmt)
                conn.execute("INSERT INTO schema_version (version) VALUES (?)", (version,))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.isolation_level = old


class Store:
    def __init__(self, path: str | os.PathLike[str] | None = None):
        self.path = resolve_db_path(path)
        with closing(_connect(self.path)):
            pass  # creates the file and applies migrations

    def _conn(self) -> sqlite3.Connection:
        return _connect(self.path)

    def schema_version(self) -> int:
        with closing(self._conn()) as c:
            return c.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]

    def checkpoint(self) -> None:
        with closing(self._conn()) as c:
            c.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    # -- writing ---------------------------------------------------------------------
    def insert_spans(self, spans: Iterable[SpanRecord]) -> None:
        rows = [
            (s.trace_id, s.span_id, s.parent_id, s.name, s.start_ns, s.end_ns, s.status,
             json.dumps(s.attributes, ensure_ascii=False))
            for s in spans
        ]
        if not rows:
            return
        with closing(self._conn()) as c, c:
            c.executemany("INSERT OR REPLACE INTO spans VALUES (?,?,?,?,?,?,?,?)", rows)

    def get_spans(self, trace_id: str) -> list[SpanRecord]:
        with closing(self._conn()) as c:
            rows = c.execute(
                "SELECT * FROM spans WHERE trace_id=? ORDER BY start_ns, end_ns DESC", (trace_id,)
            ).fetchall()
        return [
            SpanRecord(r["trace_id"], r["span_id"], r["parent_id"], r["name"], r["start_ns"],
                       r["end_ns"], r["status"], json.loads(r["attributes"]))
            for r in rows
        ]

    def finalize_run(self, trace_id: str, rules: Sequence[Rule] = ()) -> Failure | None:
        """Classify a finished run and write its `runs` / `failures` rows."""
        spans = self.get_spans(trace_id)
        root = next((s for s in spans if s.attributes.get("ff.kind") == "run"), None)
        if root is None:
            raise LookupError(f"no root span stored for run {trace_id}")
        failure = classify_run(spans, rules)
        a = root.attributes
        with closing(self._conn()) as c, c:
            c.execute("DELETE FROM failures WHERE trace_id=?", (trace_id,))
            c.execute(
                "INSERT OR REPLACE INTO runs VALUES (?,?,?,?,?,?,?)",
                (trace_id, root.name, a.get("ff.case_id"), a.get("ff.tags", "{}"),
                 root.start_ns, root.end_ns, "failed" if failure else "ok"),
            )
            if failure:
                c.execute(
                    "INSERT INTO failures (trace_id, span_id, step, kind, message, signature, end_ns)"
                    " VALUES (?,?,?,?,?,?,?)",
                    (trace_id, failure.span_id, failure.step, failure.kind, failure.message,
                     failure.signature, failure.end_ns),
                )
        return failure

    def gc(self, cutoff_ns: int) -> tuple[int, int]:
        """Delete runs that started before `cutoff_ns` (with spans and failures), plus orphan spans:
        spans of runs that never finished, whose earliest span is older than `cutoff_ns`.
        Returns (runs deleted, orphan spans deleted)."""
        with closing(self._conn()) as c, c:
            ids = [r[0] for r in c.execute("SELECT trace_id FROM runs WHERE start_ns < ?", (cutoff_ns,))]
            for table in ("failures", "spans", "runs"):
                c.executemany(f"DELETE FROM {table} WHERE trace_id=?", [(i,) for i in ids])
            orphans = c.execute(
                "DELETE FROM spans WHERE trace_id NOT IN (SELECT trace_id FROM runs) AND trace_id IN"
                " (SELECT trace_id FROM spans GROUP BY trace_id HAVING MIN(start_ns) < ?)",
                (cutoff_ns,),
            ).rowcount
            return len(ids), orphans

    # -- reading ---------------------------------------------------------------------
    def list_runs(self, failed: bool = False, since_ns: int | None = None) -> list[dict[str, Any]]:
        sql = (
            "SELECT r.*, f.step AS fail_step, f.kind AS fail_kind, f.message AS fail_message "
            "FROM runs r LEFT JOIN failures f ON f.trace_id = r.trace_id WHERE 1=1"
        )
        args: list[Any] = []
        if failed:
            sql += " AND r.status='failed'"
        if since_ns is not None:
            sql += " AND r.start_ns >= ?"
            args.append(since_ns)
        sql += " ORDER BY r.start_ns, r.trace_id"
        with closing(self._conn()) as c:
            return [_run_dict(r) for r in c.execute(sql, args)]

    def get_run(self, prefix: str) -> dict[str, Any]:
        with closing(self._conn()) as c:
            rows = c.execute(
                "SELECT r.*, f.step AS fail_step, f.kind AS fail_kind, f.message AS fail_message,"
                " f.span_id AS fail_span FROM runs r LEFT JOIN failures f ON f.trace_id=r.trace_id"
                " WHERE r.trace_id LIKE ? ESCAPE '\\'",
                (prefix.replace("\\", "").replace("%", "").replace("_", "\\_") + "%",),
            ).fetchall()
        if not rows:
            raise LookupError(f"no run matches '{prefix}'")
        if len(rows) > 1:
            raise LookupError(f"run id prefix '{prefix}' is ambiguous ({len(rows)} matches)")
        d = _run_dict(rows[0])
        d["fail_span"] = rows[0]["fail_span"]
        return d

    def failures_with_runs(self) -> list[dict[str, Any]]:
        with closing(self._conn()) as c:
            rows = c.execute(
                "SELECT f.*, r.start_ns, r.tags, r.name AS run_name, r.case_id FROM failures f"
                " JOIN runs r ON r.trace_id=f.trace_id ORDER BY r.start_ns, f.id"
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["tags"] = json.loads(d["tags"] or "{}")
            out.append(d)
        return out

    def count_runs(self) -> int:
        with closing(self._conn()) as c:
            return c.execute("SELECT COUNT(*) FROM runs").fetchone()[0]


def _run_dict(r: sqlite3.Row) -> dict[str, Any]:
    d = dict(r)
    d["tags"] = json.loads(d.get("tags") or "{}")
    return d


class SQLiteSpanExporter(SpanExporter):
    """Writes finished OTel spans to the store."""

    def __init__(self, store: Store):
        self.store = store

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        try:
            self.store.insert_spans(_to_record(s) for s in spans)
        except Exception as e:  # noqa: BLE001 - never break the host pipeline
            warnings.warn(f"failure-forensics could not export {len(spans)} span(s): {e}", stacklevel=2)
            return SpanExportResult.FAILURE
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        pass

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True


def _to_record(span: ReadableSpan) -> SpanRecord:
    ctx = span.get_span_context()
    attrs = {k: list(v) if isinstance(v, tuple) else v for k, v in (span.attributes or {}).items()}
    return SpanRecord(
        trace_id=format(ctx.trace_id, "032x"),
        span_id=format(ctx.span_id, "016x"),
        parent_id=format(span.parent.span_id, "016x") if span.parent else None,
        name=span.name,
        start_ns=span.start_time or 0,
        end_ns=span.end_time or 0,
        status="error" if span.status.status_code == StatusCode.ERROR else "ok",
        attributes=attrs,
    )
