"""UI data layer (no Streamlit): exact expectations on the committed demo databases."""

import hashlib
import shutil
import sqlite3
from pathlib import Path

import pytest

from failure_forensics.store import Store
from failure_forensics.ui import data

from .conftest import SEC, span

ROOT = Path(__file__).resolve().parents[1]
TOY, T2S = ROOT / "examples" / "demo.db", ROOT / "examples" / "t2s" / "demo.db"


def rid(conn, case, generator):
    """Trace id of the one run of `case` made by `generator` (the demo DB is regenerated, ids change)."""
    hits = [r.trace_id for r in data.query_runs(conn) if r.case_id == case and r.tags.get("generator") == generator]
    assert len(hits) == 1
    return hits[0]


@pytest.fixture(scope="module")
def toy(tmp_path_factory):
    dst = tmp_path_factory.mktemp("ui") / "toy.db"
    shutil.copy(TOY, dst)
    with data.open_readonly(dst) as conn:
        yield conn


@pytest.fixture(scope="module")
def t2s(tmp_path_factory):
    dst = tmp_path_factory.mktemp("ui") / "t2s.db"
    shutil.copy(T2S, dst)
    with data.open_readonly(dst) as conn:
        yield conn


def test_read_only_open_refuses_writes(tmp_path):
    dst = tmp_path / "t.db"
    shutil.copy(TOY, dst)
    before = hashlib.sha256(dst.read_bytes()).hexdigest()
    with data.open_readonly(dst) as conn:
        for sql in ("INSERT INTO runs VALUES ('x','n',NULL,'{}',0,1,'ok')", "DELETE FROM spans",
                    "CREATE TABLE evil (a)", "UPDATE failures SET kind='x'", "PRAGMA journal_mode=DELETE"):
            with pytest.raises(sqlite3.OperationalError):
                conn.execute(sql).fetchall()
        data.overview(conn)
        data.clusters(conn)
    assert hashlib.sha256(dst.read_bytes()).hexdigest() == before


def test_open_rejects_missing_and_foreign_files(tmp_path):
    with pytest.raises(FileNotFoundError):
        data.open_readonly(tmp_path / "nope.db")
    other = tmp_path / "other.db"
    sqlite3.connect(other).execute("CREATE TABLE t (a)").connection.close()
    with pytest.raises(ValueError, match="not a failure-forensics database"):
        data.open_readonly(other)


def test_overview_toy(toy):
    o = data.overview(toy)
    assert (o.runs, o.failed, o.clusters) == (100, 58, 6)
    assert o.failure_rate == 0.58
    assert [(c.step, c.kind, c.count) for c in o.top] == [
        ("tool", "exception", 16), ("tool", "exception", 10), ("policy", "blocked", 9),
        ("tool", "timeout", 9), ("answer", "empty_output", 7)]
    assert data.auto_bucket(o.first_ns, o.last_ns) == "second"


def test_overview_t2s_and_window(t2s):
    o = data.overview(t2s)
    assert (o.runs, o.failed, o.clusters) == (288, 50, 5)
    assert o.failure_rate == pytest.approx(50 / 288)
    # a window that starts after the last failure has runs but no failures
    last_fail = max(r.start_ns for r in data.query_runs(t2s, data.RunFilter(status="failed")))
    late = data.overview(t2s, since_ns=last_fail + 1)
    assert late.failed == 0 and late.clusters == 0 and late.top == [] and late.runs > 0
    empty = data.overview(t2s, since_ns=o.last_ns + 1)
    assert (empty.runs, empty.failed, empty.failure_rate) == (0, 0, 0.0)


def test_clusters_exact(t2s):
    got = [(c.step, c.kind, c.message, c.count, len(c.examples)) for c in data.clusters(t2s)]
    assert got == [
        ("validate", "blocked", "FUNCTION_NOT_ALLOWED", 40, 3),
        ("compare", "wrong_result", "rows differ from gold SQL: expected <n> row(s), got <n>", 4, 3),
        ("execute", "timeout", "Query exceeded the statement timeout", 3, 3),
        ("validate", "blocked", "COLUMN_NOT_ALLOWED", 2, 2),
        ("compare", "wrong_result", "rows differ from gold SQL: same row count (<n>), different rows", 1, 1),
    ]
    top = data.clusters(t2s)[0]
    assert top.share == pytest.approx(40 / 288) and top.label == "validate / blocked"
    assert top.first_seen_ns <= top.last_seen_ns


def test_cluster_series_buckets(t2s, toy):
    for bucket in ("second", "minute", "hour", "day"):
        series = data.cluster_series(t2s, bucket)
        assert sum(s["count"] for s in series) == 50
        size = data.BUCKETS[bucket]
        assert all(s["bucket_ns"] % size == 0 for s in series)
    assert len(data.cluster_series(t2s, "day")) == 5  # five clusters, all on one day
    assert sum(s["count"] for s in data.cluster_series(toy, "hour")) == 58
    labels = {s["label"] for s in data.cluster_series(t2s, "day")}
    assert "validate / blocked: FUNCTION_NOT_ALLOWED" in labels and "validate / blocked: COLUMN_NOT_ALLOWED" in labels
    assert all(len(label.split(": ", 1)[1]) <= 90 for label in labels)
    with pytest.raises(ValueError):
        data.cluster_series(t2s, "week")


def test_auto_bucket():
    assert data.auto_bucket(None, None) == "hour"
    assert data.auto_bucket(0, 10 * SEC) == "second"
    assert data.auto_bucket(0, 30 * 60 * SEC) == "minute"
    assert data.auto_bucket(0, 20 * 3600 * SEC) == "hour"
    assert data.auto_bucket(0, 30 * 86400 * SEC) == "day"


def test_query_runs_filters(t2s):
    def q(**kw):
        return data.query_runs(t2s, data.RunFilter(**kw))

    assert len(q()) == 288
    assert len(q(status="failed")) == 50 and len(q(status="ok")) == 238
    assert len(q(name="t2s.attack")) + len(q(name="t2s.question")) == 288
    assert len(q(step="validate")) == 42 and len(q(kind="timeout")) == 3
    assert len(q(tag=("generator", "gold"))) == 72
    assert len(q(tag=("generator", "gold"), status="failed")) == 0
    assert len(q(case_id="q00")) == 36
    assert len(q(case_id="%")) == 0  # LIKE wildcards in user input are literal
    sig = data.clusters(t2s)[1].signature
    assert {r.case_id for r in q(signature=sig)} >= {"q009"}
    runs = q(status="failed")
    assert [r.start_ns for r in runs] == sorted((r.start_ns for r in runs), reverse=True)
    assert len(data.query_runs(t2s, limit=5)) == 5
    asc = data.query_runs(t2s, newest_first=False, limit=2)
    assert asc[0].start_ns <= asc[1].start_ns
    late = data.overview(t2s).last_ns
    assert q(since_ns=late + 1) == [] and len(q(until_ns=late + 1)) == 288


def test_facets(toy):
    f = data.facets(toy)
    assert f["names"] == ["toy_pipeline"]
    assert f["steps"] == ["answer", "policy", "tool"]
    assert f["tags"] == {"topic": ["orders", "stock"]}
    assert f["first_ns"] < f["last_ns"]


def test_run_detail_failing(t2s):
    d = data.run_detail(t2s, rid(t2s, "q009", "mutated:wrong-join"))  # q009, wrong join
    assert d.run.status == "failed" and d.run.culprit_kind == "wrong_result"
    assert [(s.name, s.depth) for s in d.spans] == [
        ("t2s.question", 0), ("generate", 1), ("validate", 1), ("execute", 1), ("compare", 1)]
    root, *steps = d.spans
    assert root.is_root and root.offset_ns == 0 and root.duration_ns == d.run.duration_ns
    assert [s.offset_ns for s in steps] == sorted(s.offset_ns for s in steps)
    culprit = [s for s in d.spans if s.is_culprit]
    assert [s.name for s in culprit] == ["compare"] and d.culprit_span_id == culprit[0].span_id
    assert culprit[0].marked.startswith("wrong_result: rows differ") and culprit[0].error is None
    assert '"match": false' in culprit[0].output


def test_run_detail_errors_and_lookup(toy):
    failing = next(r for r in data.query_runs(toy, data.RunFilter(kind="exception")))
    d = data.run_detail(toy, failing.trace_id[:8])
    tool = next(s for s in d.spans if s.is_culprit)
    assert tool.name == "tool" and tool.status == "error" and tool.error
    with pytest.raises(LookupError, match="no run matches"):
        data.run_detail(toy, "ffffffffffff0")
    with pytest.raises(LookupError, match="ambiguous"):
        data.run_detail(toy, "")
    with pytest.raises(LookupError):
        data.run_detail(toy, "%")  # wildcard characters are not wildcards


def test_nearest_passing_same_case(t2s):
    ok, why = data.nearest_passing(t2s, rid(t2s, "q009", "mutated:wrong-join"))
    assert why == "same case" and ok.status == "ok" and ok.case_id == "q009"
    assert ok.trace_id.startswith(rid(t2s, "q009", "gold"))


def test_nearest_passing_fallback_and_none(tmp_path):
    store = Store(tmp_path / "s.db")
    tags = '{"suite": "a"}'
    spans = []
    for i, (tid, start, fail) in enumerate((("a" * 32, 0, False), ("b" * 32, 100, True), ("c" * 32, 200, False))):
        base = {"ff.kind": "run", "ff.tags": tags if tid != "c" * 32 else '{"suite": "b"}'}
        spans.append(span(tid, f"0{i}", None, "pipe", start * SEC, start * SEC + 10, "error" if fail else "ok", **base))
        spans.append(span(tid, f"1{i}", f"0{i}", "step", start * SEC + 1, start * SEC + 5, "error" if fail else "ok",
                          **({"ff.failure.kind": "wrong_result", "ff.failure.detail": "x"} if fail else {})))
    store.insert_spans(spans)
    for tid in ("a" * 32, "b" * 32, "c" * 32):
        store.finalize_run(tid)
    with data.open_readonly(tmp_path / "s.db") as conn:
        hit, why = data.nearest_passing(conn, "b" * 12)
        assert why == "same name and tags" and hit.trace_id == "a" * 32  # tags differ for c
        assert data.nearest_passing(conn, "a" * 12) == (None, "none")  # no other passing run shares its tags
    store.insert_spans([span("d" * 32, "00", None, "other", 0, 10, "error", **{"ff.kind": "run", "ff.tags": "{}"}),
                        span("d" * 32, "01", "00", "s", 1, 5, "error", **{"ff.failure.kind": "unsafe"})])
    store.finalize_run("d" * 32)
    with data.open_readonly(tmp_path / "s.db") as conn:
        assert data.nearest_passing(conn, "d" * 12) == (None, "none")


def test_diff_first_divergence_is_the_first_differing_output(t2s):
    failing = data.run_detail(t2s, rid(t2s, "q009", "mutated:wrong-join"))
    passing = data.run_detail(t2s, rid(t2s, "q009", "gold"))
    pairs = data.diff_runs(failing, passing)
    assert [(p.name, p.occurrence, p.verdict, p.first_divergence) for p in pairs] == [
        ("generate", 1, "output differs", True),  # wrong join: the SQL itself differs
        ("validate", 1, "output differs", False),
        ("execute", 1, "output differs", False),
        ("compare", 1, "status differs", False),
    ]
    assert all(p.input_differs for p in pairs[1:3]) and not pairs[0].input_differs


def test_diff_retries_and_missing_steps(t2s):
    failing = data.run_detail(t2s, rid(t2s, "q001", "mutated:harmless-function"))  # blocked twice, no execute/compare
    other, _ = data.nearest_passing(t2s, rid(t2s, "q001", "mutated:harmless-function"))
    pairs = data.diff_runs(failing, data.run_detail(t2s, other.trace_id))
    assert [(p.name, p.occurrence, p.verdict) for p in pairs] == [
        ("generate", 1, "output differs"), ("validate", 1, "output differs"),
        ("generate", 2, "only in failing"), ("validate", 2, "only in failing"),
        ("execute", 1, "only in passing"), ("compare", 1, "only in passing")]
    assert [p.first_divergence for p in pairs] == [True, False, False, False, False, False]


def test_diff_identical_runs_have_no_divergence(t2s):
    d = data.run_detail(t2s, rid(t2s, "q009", "gold"))
    pairs = data.diff_runs(d, d)
    assert pairs and all(p.verdict == "same" and not p.first_divergence for p in pairs)


def test_first_change_excerpts():
    assert data.first_change("a", "a") is None and data.first_change(None, "a") is None
    a = "SELECT x FROM t WHERE c.id = o.id AND z > 1"
    assert data.first_change(a, a.replace("o.id", "o.cid"), 2) == ("...o.id AND...", "...o.cid AND...")
    assert data.first_change("abc", "") == ("abc", "")
