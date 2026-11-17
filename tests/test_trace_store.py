import asyncio
import sqlite3
import threading

import pytest

import failure_forensics as ff
from failure_forensics.store import MIGRATIONS, SCHEMA_VERSION, Store


def by_name(spans):
    return {s.name: s for s in spans}


def test_span_tree_nesting_and_record(db):
    with ff.run("pipe", case_id="c1", tags={"k": "v"}) as r, ff.step("outer") as s:
        s.record(input={"q": "hi"})
        with ff.step("inner", size=3) as i:
            i.record(output=[1, 2])
    spans = by_name(db.get_spans(r.trace_id))
    assert spans["pipe"].parent_id is None
    assert spans["outer"].parent_id == spans["pipe"].span_id
    assert spans["inner"].parent_id == spans["outer"].span_id
    assert spans["outer"].attributes["ff.input"] == '{"q": "hi"}'
    assert spans["inner"].attributes["ff.output"] == "[1, 2]"
    assert spans["inner"].attributes["ff.attr.size"] == 3
    run = db.get_run(r.trace_id)
    assert run["status"] == "ok" and run["case_id"] == "c1" and run["tags"] == {"k": "v"}


def test_exception_recorded_and_culprit_is_inner_step(db):
    with pytest.raises(ValueError), ff.run("pipe") as r, ff.step("outer"), ff.step("inner"):
        raise ValueError("boom 42")
    spans = by_name(db.get_spans(r.trace_id))
    a = spans["inner"].attributes
    assert a["ff.error.type"] == "ValueError" and a["ff.error.message"] == "boom 42"
    assert len(a["ff.error.tb_hash"]) == 8
    run = db.get_run(r.trace_id)
    assert (run["fail_step"], run["fail_kind"]) == ("inner", "exception")


def test_decorator_sync_and_async(db):
    @ff.step("sync_step")
    def f(x):
        return x + 1

    @ff.step("async_step")
    async def g(x):
        await asyncio.sleep(0)
        return await h(x)

    @ff.step("async_inner")
    async def h(x):
        raise RuntimeError("nope")

    async def main():
        with pytest.raises(RuntimeError), ff.run("apipe") as r:
            f(1)
            await g(1)
        return r.trace_id

    tid = asyncio.run(main())
    spans = by_name(db.get_spans(tid))
    assert spans["async_inner"].parent_id == spans["async_step"].span_id
    assert spans["sync_step"].parent_id == spans["apipe"].span_id
    assert f.__name__ == "f" and g.__name__ == "g"


def test_concurrent_runs_in_threads_do_not_mix(db):
    ids = {}

    def work(n):
        with ff.run(f"r{n}") as r:
            for j in range(3):
                with ff.step(f"s{n}-{j}"):
                    pass
        ids[n] = r.trace_id

    ts = [threading.Thread(target=work, args=(n,)) for n in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    for n, tid in ids.items():
        names = {s.name for s in db.get_spans(tid)}
        assert names == {f"r{n}", *(f"s{n}-{j}" for j in range(3))}


def test_mark_failure_without_exception(db):
    with ff.run("pipe") as r, ff.step("validate"):
        ff.mark_failure("blocked", "SELECT * not allowed for 'ssn'")
        ff.mark_failure("other", "ignored: first mark wins")
    run = db.get_run(r.trace_id)
    assert (run["fail_step"], run["fail_kind"]) == ("validate", "blocked")
    assert run["status"] == "failed"


def test_step_outside_run_is_noop(db):
    with ff.step("alone") as s:
        s.record(input=1)
    ff.mark_failure("blocked", "x")
    assert db.count_runs() == 0


def test_nested_run_rejected(db):
    with ff.run("a"), pytest.raises(RuntimeError), ff.run("b"):
        pass


def test_redaction_and_truncation_before_storage(db):
    ff.configure(str(db.path), max_len=30)
    with ff.run("pipe", tags={"owner": "bob@example.com"}) as r, ff.step(
        "s", password="hunter2", note="mail me at carol@example.com"
    ) as s:
        s.record(input={"token": "abc", "text": "y" * 100})
    raw = sqlite3.connect(db.path).execute("SELECT attributes FROM spans").fetchall()
    blob = " ".join(x[0] for x in raw)
    assert "hunter2" not in blob and "carol@" not in blob and "bob@" not in blob
    spans = by_name(db.get_spans(r.trace_id))
    assert "chars]" in spans["s"].attributes["ff.input"]


def test_store_roundtrip_and_wal(db):
    with ff.run("p") as r, ff.step("s"):
        pass
    assert sqlite3.connect(db.path).execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert db.schema_version() == SCHEMA_VERSION
    assert len(db.get_spans(r.trace_id)) == 2
    assert db.list_runs()[0]["trace_id"] == r.trace_id
    assert db.get_run(r.trace_id[:8])["name"] == "p"
    with pytest.raises(LookupError):
        db.get_run("zzzz")


def test_migration_from_v1(tmp_path):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE schema_version (version INTEGER NOT NULL)")
    for stmt in MIGRATIONS[0].split(";"):
        if stmt.strip():
            conn.execute(stmt)
    conn.execute("INSERT INTO schema_version VALUES (1)")
    conn.execute("INSERT INTO runs VALUES ('t','n',NULL,'{}',1,2,'ok')")
    conn.commit()
    conn.close()
    store = Store(path)
    assert store.schema_version() == SCHEMA_VERSION
    assert store.count_runs() == 1
    idx = [r[0] for r in sqlite3.connect(path).execute("SELECT name FROM sqlite_master WHERE type='index'")]
    assert "idx_failures_signature" in idx


def test_newer_schema_refused(tmp_path):
    path = tmp_path / "new.db"
    Store(path)
    conn = sqlite3.connect(path)
    conn.execute("INSERT INTO schema_version VALUES (99)")
    conn.commit()
    conn.close()
    with pytest.raises(RuntimeError):
        Store(path)


def test_gc(seeded):
    from tests.conftest import T0
    assert seeded.gc(T0 + 50 * 1_000_000_000) == (1, 0)  # only run "a" is older
    assert seeded.count_runs() == 2
    assert all(f["trace_id"] != "a" * 32 for f in seeded.failures_with_runs())
    assert seeded.get_spans("a" * 32) == []


def test_case_id_tags_and_run_name_are_redacted(db):
    with ff.run(
        "pipe for bob@example.com",
        case_id="case bob@example.com",
        tags={"password": "hunter2", "owner": "carol@example.com", "cfg": {"password": "hunter2"}, "n": 3},
    ) as r:
        pass
    blob = " ".join(str(v) for v in db.get_run(r.trace_id).values())
    assert "@example.com" not in blob and "hunter2" not in blob
    assert db.get_run(r.trace_id)["tags"]["n"] == "3"


def test_run_is_a_new_trace_even_with_a_host_span_active(db):
    from opentelemetry.sdk.trace import TracerProvider

    host = TracerProvider().get_tracer("host")
    with host.start_as_current_span("http-request") as req:
        host_trace = format(req.get_span_context().trace_id, "032x")
        with ff.run("a") as r1, ff.step("s"):
            pass
        with ff.run("b") as r2:
            pass
    assert len({host_trace, r1.trace_id, r2.trace_id}) == 3
    root = next(s for s in db.get_spans(r1.trace_id) if s.name == "a")
    assert root.parent_id is None and root.attributes["ff.kind"] == "run"
    assert db.get_run(r1.trace_id)["status"] == "ok" and db.count_runs() == 2


def test_setup_failure_never_raises_into_the_host(tmp_path, monkeypatch):
    from failure_forensics import trace

    def boom(*a, **k):
        raise OSError("disk on fire")

    monkeypatch.setattr(trace, "_state", None)
    monkeypatch.setattr(trace, "configure", boom)
    ran = []

    def pipeline():
        with ff.run("p") as r:
            with ff.step("s") as s:
                s.record(input=1)
            ran.append(1)
        return r

    with pytest.warns(UserWarning, match="tracing disabled"):
        r = pipeline()
    assert ran == [1] and r.trace_id == ""


def test_pipeline_exception_still_propagates_when_tracing_is_off(monkeypatch):
    from failure_forensics import trace

    monkeypatch.setattr(trace, "_state", None)
    monkeypatch.setattr(trace, "configure", lambda *a, **k: (_ for _ in ()).throw(OSError("x")))
    def pipeline():
        with ff.run("p"):
            raise ValueError("real")

    with pytest.warns(UserWarning), pytest.raises(ValueError):
        pipeline()


def test_handled_error_inside_a_run_does_not_fail_it(db):
    with ff.run("p") as r:
        for attempt in range(2):
            try:
                with ff.step("tool"):
                    if attempt == 0:
                        raise ConnectionError("flaky")
            except ConnectionError:
                continue
    assert db.get_run(r.trace_id)["status"] == "ok"
    assert db.failures_with_runs() == []


def test_run_with_no_stored_spans_warns(db, monkeypatch):
    monkeypatch.setattr(Store, "get_spans", lambda self, t: [])
    with pytest.warns(UserWarning, match="could not store run"), ff.run("p"):
        pass


def test_export_failure_warns(db, monkeypatch):
    def boom(self, spans):
        raise sqlite3.OperationalError("disk full")

    monkeypatch.setattr(Store, "insert_spans", boom)
    with pytest.warns(UserWarning) as caught, ff.run("p"):
        pass
    assert any("could not export" in str(w.message) for w in caught)


def test_concurrent_openers_migrate_safely(tmp_path):
    import subprocess
    import sys

    path = tmp_path / "race.db"
    errors = []

    def open_store():
        try:
            Store(path)
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    code = f"from failure_forensics.store import Store; Store({str(path)!r})"
    procs = [subprocess.Popen([sys.executable, "-c", code]) for _ in range(3)]
    threads = [threading.Thread(target=open_store) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert [p.wait() for p in procs] == [0, 0, 0]
    assert errors == []
    conn = sqlite3.connect(path)
    assert conn.execute("SELECT COUNT(*), MAX(version) FROM schema_version").fetchone() == (
        SCHEMA_VERSION, SCHEMA_VERSION)


def test_gc_removes_orphan_spans_of_unfinished_runs(seeded):
    from tests.conftest import T0, span

    seeded.insert_spans([span("d" * 32, "31", None, "pipe", 5, 6, **{"ff.kind": "run"})])  # never finalised
    seeded.insert_spans([span("e" * 32, "41", None, "pipe", 10**12, 10**12 + 1, **{"ff.kind": "run"})])
    runs, orphans = seeded.gc(T0 + 10 * 1_000_000_000)
    assert (runs, orphans) == (1, 1)
    assert seeded.get_spans("d" * 32) == [] and len(seeded.get_spans("e" * 32)) == 1  # recent orphan kept
