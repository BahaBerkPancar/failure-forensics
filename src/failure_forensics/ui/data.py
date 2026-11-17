"""Read-only data functions behind the UI. No Streamlit imports: everything here is plain Python
over a SQLite connection opened with `mode=ro`, so it can be tested without a browser."""

from __future__ import annotations

import difflib
import json
import re
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

from ..classify import normalise_message

SECOND_NS = 1_000_000_000
MINUTE_NS = 60 * SECOND_NS
HOUR_NS = 3_600 * SECOND_NS
DAY_NS = 24 * HOUR_NS
BUCKETS = {"second": SECOND_NS, "minute": MINUTE_NS, "hour": HOUR_NS, "day": DAY_NS}


def open_readonly(path: str | Path) -> sqlite3.Connection:
    """Open the store read-only. Any write on this connection raises `sqlite3.OperationalError`."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"no database at {p}")
    conn = sqlite3.connect(f"file:{quote(str(p.resolve()))}?mode=ro", uri=True, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("SELECT 1 FROM runs LIMIT 1")
        conn.execute("SELECT 1 FROM spans LIMIT 1")
        conn.execute("SELECT 1 FROM failures LIMIT 1")
    except sqlite3.DatabaseError as e:
        conn.close()
        raise ValueError(f"{p} is not a failure-forensics database ({e})") from e
    return conn


# -- formatting helpers ------------------------------------------------------------------
def fmt_ts(ns: int) -> str:
    return datetime.fromtimestamp(ns / 1e9, tz=UTC).strftime("%Y-%m-%d %H:%M:%S")


def fmt_dur(ns: float) -> str:
    ms = ns / 1e6
    return f"{ms / 1000:.2f} s" if ms >= 1000 else f"{ms:.1f} ms"


def short_id(trace_id: str) -> str:
    return trace_id[:12]


# -- runs --------------------------------------------------------------------------------
@dataclass
class RunFilter:
    status: str | None = None  # "ok" | "failed" | None
    name: str | None = None
    tag: tuple[str, str] | None = None  # (key, value)
    since_ns: int | None = None
    until_ns: int | None = None
    step: str | None = None  # culprit step
    signature: str | None = None  # cluster
    case_id: str | None = None  # substring match
    kind: str | None = None  # culprit failure kind


@dataclass
class RunRow:
    trace_id: str
    name: str
    case_id: str | None
    tags: dict[str, Any]
    start_ns: int
    end_ns: int
    status: str
    culprit_step: str | None = None
    culprit_kind: str | None = None
    message: str | None = None
    signature: str | None = None

    @property
    def duration_ns(self) -> int:
        return max(0, self.end_ns - self.start_ns)


_RUN_SELECT = (
    "SELECT r.trace_id, r.name, r.case_id, r.tags, r.start_ns, r.end_ns, r.status,"
    " f.step AS culprit_step, f.kind AS culprit_kind, f.message AS message, f.signature AS signature"
    " FROM runs r LEFT JOIN failures f ON f.trace_id = r.trace_id"
)


def _run_row(r: sqlite3.Row) -> RunRow:
    return RunRow(r["trace_id"], r["name"], r["case_id"], json.loads(r["tags"] or "{}"), r["start_ns"],
                  r["end_ns"], r["status"], r["culprit_step"], r["culprit_kind"], r["message"],
                  r["signature"])


def _like_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def query_runs(conn: sqlite3.Connection, flt: RunFilter | None = None, limit: int | None = None,
               newest_first: bool = True) -> list[RunRow]:
    flt = flt or RunFilter()
    where, args = ["1=1"], []
    if flt.status:
        where.append("r.status = ?")
        args.append(flt.status)
    if flt.name:
        where.append("r.name = ?")
        args.append(flt.name)
    if flt.since_ns is not None:
        where.append("r.start_ns >= ?")
        args.append(flt.since_ns)
    if flt.until_ns is not None:
        where.append("r.start_ns < ?")
        args.append(flt.until_ns)
    if flt.step:
        where.append("f.step = ?")
        args.append(flt.step)
    if flt.kind:
        where.append("f.kind = ?")
        args.append(flt.kind)
    if flt.signature:
        where.append("f.signature = ?")
        args.append(flt.signature)
    if flt.case_id:
        where.append("r.case_id LIKE ? ESCAPE '\\'")
        args.append(f"%{_like_escape(flt.case_id)}%")
    order = "DESC" if newest_first else "ASC"
    sql = f"{_RUN_SELECT} WHERE {' AND '.join(where)} ORDER BY r.start_ns {order}, r.trace_id"
    rows = [_run_row(r) for r in conn.execute(sql, args)]
    if flt.tag:  # tags are JSON text; match exactly on the parsed value
        key, value = flt.tag
        rows = [r for r in rows if str(r.tags.get(key)) == value]
    return rows[:limit] if limit else rows


def facets(conn: sqlite3.Connection) -> dict[str, Any]:
    """The values the filter widgets offer."""
    names = [r[0] for r in conn.execute("SELECT DISTINCT name FROM runs ORDER BY name")]
    steps = [r[0] for r in conn.execute("SELECT DISTINCT step FROM failures ORDER BY step")]
    kinds = [r[0] for r in conn.execute("SELECT DISTINCT kind FROM failures ORDER BY kind")]
    tags: dict[str, set[str]] = defaultdict(set)
    for (raw,) in conn.execute("SELECT DISTINCT tags FROM runs"):
        for k, v in json.loads(raw or "{}").items():
            tags[k].add(str(v))
    lo, hi = conn.execute("SELECT MIN(start_ns), MAX(start_ns) FROM runs").fetchone()
    return {"names": names, "steps": steps, "kinds": kinds,
            "tags": {k: sorted(v) for k, v in sorted(tags.items())}, "first_ns": lo, "last_ns": hi}


# -- clusters ----------------------------------------------------------------------------
@dataclass
class ClusterRow:
    signature: str
    step: str
    kind: str
    message: str
    count: int
    share: float  # of all runs in scope
    first_seen_ns: int
    last_seen_ns: int
    examples: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return f"{self.step} / {self.kind}"


def clusters(conn: sqlite3.Connection, since_ns: int | None = None, until_ns: int | None = None,
             examples: int = 3) -> list[ClusterRow]:
    """Failures grouped by signature, restricted to runs that started inside the window."""
    where, args = ["1=1"], []
    if since_ns is not None:
        where.append("r.start_ns >= ?")
        args.append(since_ns)
    if until_ns is not None:
        where.append("r.start_ns < ?")
        args.append(until_ns)
    cond = " AND ".join(where)
    total = conn.execute(f"SELECT COUNT(*) FROM runs r WHERE {cond}", args).fetchone()[0]
    groups: dict[str, ClusterRow] = {}
    for f in conn.execute(
        "SELECT f.signature, f.step, f.kind, f.message, f.trace_id, r.start_ns FROM failures f"
        f" JOIN runs r ON r.trace_id = f.trace_id WHERE {cond} ORDER BY r.start_ns, f.id", args
    ):
        c = groups.get(f["signature"])
        if c is None:
            c = groups[f["signature"]] = ClusterRow(f["signature"], f["step"], f["kind"],
                                                    normalise_message(f["message"]), 0, 0.0,
                                                    f["start_ns"], f["start_ns"])
        c.count += 1
        c.last_seen_ns = max(c.last_seen_ns, f["start_ns"])
        if len(c.examples) < examples:
            c.examples.append(f["trace_id"])
    for c in groups.values():
        c.share = c.count / total if total else 0.0
    return sorted(groups.values(), key=lambda c: (-c.count, c.signature))


def auto_bucket(first_ns: int | None, last_ns: int | None, max_buckets: int = 48) -> str:
    """The finest bucket size that keeps a chart of [first, last] under `max_buckets` bars."""
    if first_ns is None or last_ns is None:
        return "hour"
    span = last_ns - first_ns
    for name, size in BUCKETS.items():
        if span / size < max_buckets:
            return name
    return "day"


def cluster_series(conn: sqlite3.Connection, bucket: str = "hour", since_ns: int | None = None,
                   until_ns: int | None = None) -> list[dict[str, Any]]:
    """Failure counts per bucket and cluster: rows of {bucket_ns, signature, label, count}.
    Buckets are aligned to UTC seconds, minutes, hours or days; buckets with no failures are not listed."""
    size = BUCKETS.get(bucket)
    if size is None:
        raise ValueError(f"bucket must be one of {', '.join(BUCKETS)}")
    where, args = ["1=1"], []
    if since_ns is not None:
        where.append("r.start_ns >= ?")
        args.append(since_ns)
    if until_ns is not None:
        where.append("r.start_ns < ?")
        args.append(until_ns)
    counts: dict[tuple[int, str], int] = defaultdict(int)
    labels: dict[str, str] = {}
    for f in conn.execute(
        "SELECT f.signature, f.step, f.kind, f.message, r.start_ns FROM failures f"
        f" JOIN runs r ON r.trace_id = f.trace_id WHERE {' AND '.join(where)}", args
    ):
        counts[(f["start_ns"] // size * size, f["signature"])] += 1
        labels[f["signature"]] = f"{f['step']} / {f['kind']}: {normalise_message(f['message'])[:90]}"
    return [{"bucket_ns": b, "signature": s, "label": labels[s], "count": n}
            for (b, s), n in sorted(counts.items())]


@dataclass
class Overview:
    runs: int
    failed: int
    failure_rate: float
    clusters: int
    top: list[ClusterRow]
    first_ns: int | None
    last_ns: int | None


def overview(conn: sqlite3.Connection, since_ns: int | None = None, until_ns: int | None = None,
             top: int = 5) -> Overview:
    where, args = ["1=1"], []
    if since_ns is not None:
        where.append("start_ns >= ?")
        args.append(since_ns)
    if until_ns is not None:
        where.append("start_ns < ?")
        args.append(until_ns)
    runs, failed, lo, hi = conn.execute(
        "SELECT COUNT(*), COALESCE(SUM(status='failed'), 0), MIN(start_ns), MAX(start_ns) FROM runs"
        f" WHERE {' AND '.join(where)}", args).fetchone()
    cl = clusters(conn, since_ns, until_ns)
    return Overview(runs, int(failed), failed / runs if runs else 0.0, len(cl), cl[:top], lo, hi)


# -- run detail --------------------------------------------------------------------------
@dataclass
class SpanRow:
    span_id: str
    parent_id: str | None
    name: str
    depth: int
    offset_ns: int  # from the run start
    duration_ns: int
    status: str
    is_root: bool
    is_culprit: bool
    input: str | None
    output: str | None
    error: str | None  # "Type: message" for exceptions
    marked: str | None  # "kind: detail" for marked failures
    attributes: dict[str, Any]


@dataclass
class RunDetail:
    run: RunRow
    culprit_span_id: str | None
    spans: list[SpanRow]


def _span_text(value: Any) -> str | None:
    return None if value is None else str(value)


def run_detail(conn: sqlite3.Connection, prefix: str) -> RunDetail:
    """One run with its span tree flattened in display order (parents before children, children by
    start time). `prefix` may be a unique id prefix."""
    like = prefix.replace("\\", "").replace("%", "").replace("_", "\\_") + "%"
    rows = conn.execute(f"{_RUN_SELECT} WHERE r.trace_id LIKE ? ESCAPE '\\'", (like,)).fetchall()
    if not rows:
        raise LookupError(f"no run matches '{prefix}'")
    if len(rows) > 1:
        raise LookupError(f"run id prefix '{prefix}' is ambiguous ({len(rows)} matches)")
    run = _run_row(rows[0])
    culprit = conn.execute("SELECT span_id FROM failures WHERE trace_id = ?", (run.trace_id,)).fetchone()
    culprit_id = culprit[0] if culprit else None
    spans = conn.execute(
        "SELECT * FROM spans WHERE trace_id = ? ORDER BY start_ns, end_ns DESC", (run.trace_id,)).fetchall()
    ids = {s["span_id"] for s in spans}
    children: dict[str | None, list[sqlite3.Row]] = defaultdict(list)
    for s in spans:  # a span whose parent was never stored is shown as a root
        children[s["parent_id"] if s["parent_id"] in ids else None].append(s)
    out: list[SpanRow] = []

    def walk(parent: str | None, depth: int) -> None:
        for s in children.get(parent, []):
            a = json.loads(s["attributes"] or "{}")
            error = None
            if a.get("ff.error.type"):
                error = f"{a['ff.error.type']}: {a.get('ff.error.message', '')}".rstrip(": ")
            marked = None
            if a.get("ff.failure.kind"):
                marked = f"{a['ff.failure.kind']}: {a.get('ff.failure.detail', '')}".rstrip(": ")
            out.append(SpanRow(
                s["span_id"], s["parent_id"], s["name"], depth, max(0, s["start_ns"] - run.start_ns),
                max(0, s["end_ns"] - s["start_ns"]), s["status"], a.get("ff.kind") == "run",
                s["span_id"] == culprit_id, _span_text(a.get("ff.input")), _span_text(a.get("ff.output")),
                error, marked, a))
            walk(s["span_id"], depth + 1)

    walk(None, 0)
    return RunDetail(run, culprit_id, out)


# -- nearest passing run and diff --------------------------------------------------------
def nearest_passing(conn: sqlite3.Connection, trace_id: str) -> tuple[RunRow | None, str]:
    """The passing run to compare a failing run against, and why it was chosen.

    1. A passing run with the same `case_id` (and run name), closest in time to the failing run.
    2. Otherwise a passing run with the same name and identical tags, closest in time.
    Returns (None, "none") when neither exists."""
    me = run_detail(conn, trace_id).run
    passing = query_runs(conn, RunFilter(status="ok", name=me.name))
    passing = [r for r in passing if r.trace_id != me.trace_id]

    def closest(cands: list[RunRow]) -> RunRow | None:
        return min(cands, key=lambda r: (abs(r.start_ns - me.start_ns), r.trace_id), default=None)

    if me.case_id:
        hit = closest([r for r in passing if r.case_id == me.case_id])
        if hit:
            return hit, "same case"
    hit = closest([r for r in passing if r.tags == me.tags])
    return (hit, "same name and tags") if hit else (None, "none")


@dataclass
class StepPair:
    name: str
    occurrence: int  # 1-based among steps of this name
    failing: SpanRow | None
    passing: SpanRow | None
    verdict: str  # same | output differs | status differs | only in failing | only in passing
    input_differs: bool
    first_divergence: bool = False


def _steps(detail: RunDetail) -> list[SpanRow]:
    return [s for s in detail.spans if not s.is_root]


def diff_runs(failing: RunDetail, passing: RunDetail) -> list[StepPair]:
    """Align steps by (name, n-th occurrence) and compare them in the failing run's order.

    A pair differs when its status differs, its recorded output differs, or the step exists in only
    one run. The first differing pair, in the failing run's start order, is the first divergence;
    steps that only the passing run has are listed after the failing run's steps. Inputs are compared
    too but only reported (`input_differs`): a step whose input differs and output matches is not a
    divergence, because the interesting question is where the visible results part ways."""
    def keyed(detail: RunDetail) -> dict[tuple[str, int], SpanRow]:
        seen: dict[str, int] = defaultdict(int)
        out = {}
        for s in _steps(detail):
            seen[s.name] += 1
            out[(s.name, seen[s.name])] = s
        return out

    f, p = keyed(failing), keyed(passing)
    pairs: list[StepPair] = []
    for key in [*f, *(k for k in p if k not in f)]:
        a, b = f.get(key), p.get(key)
        if a and not b:
            verdict = "only in failing"
        elif b and not a:
            verdict = "only in passing"
        elif a.status != b.status:
            verdict = "status differs"
        elif a.output != b.output:
            verdict = "output differs"
        else:
            verdict = "same"
        pairs.append(StepPair(key[0], key[1], a, b, verdict,
                              bool(a and b and a.input != b.input)))
    for pair in pairs:
        if pair.verdict != "same":
            pair.first_divergence = True
            break
    return pairs


_TOKEN = re.compile(r"\w+|\s+|[^\w\s]")


def _excerpt(tokens: list[str], lo: int, hi: int) -> str:
    return ("..." if lo else "") + "".join(tokens[lo:hi]) + ("..." if hi < len(tokens) else "")


def first_change(a: str | None, b: str | None, context: int = 8) -> tuple[str, str] | None:
    """The first place two texts part, as two short excerpts (a few tokens of context around the first
    differing block), or None when they are equal. Tokens are words, whitespace runs and punctuation."""
    if a is None or b is None or a == b:
        return None
    ta, tb = _TOKEN.findall(a), _TOKEN.findall(b)
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, ta, tb, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        lo_a, lo_b = max(0, i1 - context), max(0, j1 - context)
        hi_a, hi_b = min(len(ta), i2 + context), min(len(tb), j2 + context)
        return _excerpt(ta, lo_a, hi_a), _excerpt(tb, lo_b, hi_b)
    return None
