import os

import pytest

import failure_forensics as ff
from failure_forensics.models import SpanRecord
from failure_forensics.store import Store

SEC = 1_000_000_000
T0 = 1_700_000_000 * SEC  # 2023-11-14 22:13:20 UTC


@pytest.fixture
def db(tmp_path):
    """A fresh store per test; tracing is configured to write into it."""
    path = tmp_path / "t.db"
    store = ff.configure(str(path))
    yield store
    ff.configure(str(tmp_path / "other.db"))  # shuts down the test provider


def span(trace, sid, parent, name, start, end, status="ok", **attrs):
    return SpanRecord(trace, sid, parent, name, T0 + start, T0 + end, status, attrs)


@pytest.fixture
def seeded(tmp_path):
    """Three hand-built runs with fixed timestamps (for golden CLI output)."""
    store = Store(tmp_path / "seed.db")
    a, b, c = "a" * 32, "b" * 32, "c" * 32
    store.insert_spans([
        span(a, "01", None, "pipe", 0, 40_000_000, **{"ff.kind": "run", "ff.case_id": "q1", "ff.tags": '{"topic": "stock"}'}),
        span(a, "02", "01", "plan", 1_000_000, 11_000_000, **{"ff.input": '"how many?"', "ff.output": '{"tool": "lookup"}'}),
        span(a, "03", "01", "tool", 12_000_000, 30_000_000, **{"ff.output": "5"}),
        span(b, "11", None, "pipe", 100 * SEC, 100 * SEC + 50_000_000, "error",
             **{"ff.kind": "run", "ff.case_id": "q2", "ff.tags": '{"topic": "orders"}',
                "ff.error.type": "ConnectionError", "ff.error.message": "reset at 10.0.0.7"}),
        span(b, "12", "11", "plan", 100 * SEC + 1_000_000, 100 * SEC + 5_000_000),
        span(b, "13", "11", "tool", 100 * SEC + 6_000_000, 100 * SEC + 20_000_000, "error",
             **{"ff.error.type": "ConnectionError", "ff.error.message": "reset at 10.0.0.7", "ff.error.tb_hash": "deadbeef"}),
        span(c, "21", None, "pipe", 200 * SEC, 200 * SEC + 9_000_000, "error",
             **{"ff.kind": "run", "ff.case_id": "q3", "ff.tags": '{"topic": "stock"}'}),
        span(c, "22", "21", "policy", 200 * SEC + 1_000_000, 200 * SEC + 2_000_000, "error",
             **{"ff.failure.kind": "blocked", "ff.failure.detail": "write not allowed: 'DROP x'"}),
    ])
    for t in (a, b, c):
        store.finalize_run(t)
    return store


def pytest_collection_modifyitems(config, items):
    """Tests marked `pg` need a disposable PostgreSQL: skip them when TEST_DATABASE_URL is unset."""
    if os.environ.get("TEST_DATABASE_URL"):
        return
    skip = pytest.mark.skip(reason="TEST_DATABASE_URL is not set")
    for item in items:
        if "pg" in item.keywords:
            item.add_marker(skip)
