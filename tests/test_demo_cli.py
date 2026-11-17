import json
import subprocess
import sys
from pathlib import Path

import pytest

from failure_forensics.cli import main
from failure_forensics.cluster import cluster_failures
from failure_forensics.store import Store

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def demo_db(tmp_path_factory):
    path = tmp_path_factory.mktemp("demo") / "demo.db"
    subprocess.run(
        [sys.executable, str(ROOT / "examples" / "toy_pipeline.py"), "--cases", "100", "--seed", "7", "--db", str(path)],
        check=True, cwd=ROOT,
    )
    return path


def test_demo_clusters_exact(demo_db):
    clusters = cluster_failures(Store(demo_db), by_tag="topic")
    got = [(c.count, c.step, c.kind, c.message) for c in clusters]
    assert got == [
        (10, "tool", "exception", "ConnectionError: connection reset by peer at <n>:<n>"),
        (10, "tool", "exception", "KeyError: 'sku-500'"),
        (9, "policy", "blocked", "write statement not allowed: <str>"),
        (9, "tool", "timeout", "TimeoutError: tool call exceeded <n>s deadline"),
        (7, "answer", "empty_output", "step produced no output"),
        (7, "answer", "wrong_result", "expected <n>, got <n>"),
        (6, "tool", "exception", "KeyError: 'sku-404'"),
    ]
    assert sum(c.count for c in clusters) == 58
    assert clusters[0].share == 0.10
    for c in clusters:
        assert sum(c.by_tag.values()) == c.count and set(c.by_tag) <= {"stock", "orders"}
        assert len(c.examples) == 3


def test_demo_redacts_emails(demo_db):
    import sqlite3
    blob = " ".join(r[0] for r in sqlite3.connect(demo_db).execute("SELECT attributes FROM spans"))
    assert "@example.com" not in blob and "[REDACTED:email]" in blob


def test_cli_clusters_json_and_top(demo_db, capsys):
    assert main(["clusters", "--db", str(demo_db), "--top", "2", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert [c["count"] for c in data] == [10, 10]


def test_cli_show_failing_run_marks_culprit(demo_db, capsys):
    store = Store(demo_db)
    failed = store.list_runs(failed=True)
    run = next(r for r in failed if r["fail_kind"] == "timeout")
    assert main(["show", run["trace_id"][:10], "--db", str(demo_db)]) == 0
    out = capsys.readouterr().out
    assert "<-- culprit" in out and "culprit: tool (timeout)" in out


# --- golden outputs on hand-built, fixed-timestamp data -----------------------------------

def run_cli(seeded, capsys, *argv):
    code = main([*argv, "--db", str(seeded.path)])
    return code, capsys.readouterr().out


def test_golden_runs(seeded, capsys):
    code, out = run_cli(seeded, capsys, "runs")
    assert code == 0
    assert out == """\
RUN           STATUS  STARTED (UTC)        DURATION  NAME  CASE  CULPRIT
aaaaaaaaaaaa  ok      2023-11-14 22:13:20  40.0ms    pipe  q1    -
bbbbbbbbbbbb  failed  2023-11-14 22:15:00  50.0ms    pipe  q2    tool:exception
cccccccccccc  failed  2023-11-14 22:16:40  9.0ms     pipe  q3    policy:blocked
3 run(s)
"""
    code, out = run_cli(seeded, capsys, "runs", "--failed")
    assert out.count("failed") == 2 and "aaaaaaaaaaaa" not in out


def test_golden_show(seeded, capsys):
    code, out = run_cli(seeded, capsys, "show", "bbbb")
    assert code == 0
    assert out == """\
run bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  pipe  case=q2  FAILED  50.0ms
started 2023-11-14 22:15:00 UTC  tags={"topic": "orders"}

   [FAIL] pipe                                  50.0ms
             error: ConnectionError: reset at 10.0.0.7 [tb -]
   [ok  ]   plan                                 4.0ms
>> [FAIL]   tool                                14.0ms   <-- culprit
               error: ConnectionError: reset at 10.0.0.7 [tb deadbeef]

culprit: tool (exception): ConnectionError: reset at 10.0.0.7
"""


def test_golden_failures_and_clusters(seeded, capsys):
    _, out = run_cli(seeded, capsys, "failures")
    assert out == """\
RUN           STEP    KIND       MESSAGE
bbbbbbbbbbbb  tool    exception  ConnectionError: reset at 10.0.0.7
cccccccccccc  policy  blocked    write not allowed: 'DROP x'
2 failure(s)
"""
    _, out = run_cli(seeded, capsys, "clusters")
    lines = out.splitlines()
    assert lines[0].startswith("COUNT  SHARE  STEP")
    assert lines[1].split()[:5] == ["1", "33.3%", "policy", "blocked", "write"]
    _, out = run_cli(seeded, capsys, "clusters", "--by-tag", "topic")
    assert "tool/exception by topic: orders=1" in out and "policy/blocked by topic: stock=1" in out


def test_cli_json_and_gc(seeded, capsys):
    _, out = run_cli(seeded, capsys, "runs", "--json")
    assert [r["status"] for r in json.loads(out)] == ["ok", "failed", "failed"]
    _, out = run_cli(seeded, capsys, "runs", "--since", "1h")
    assert "0 run(s)" in out
    _, out = run_cli(seeded, capsys, "gc", "--keep-days", "1")
    assert out.strip() == "deleted 3 run(s) older than 1 day(s)"
    _, out = run_cli(seeded, capsys, "runs")
    assert "0 run(s)" in out


def test_cli_errors_exit_3(tmp_path, capsys):
    assert main(["runs", "--db", str(tmp_path / "missing.db")]) == 3
    assert "no database" in capsys.readouterr().err
    with pytest.raises(SystemExit) as e:
        main(["runs", "--bogus"])
    assert e.value.code == 3
    assert main([]) == 0


@pytest.mark.parametrize("argv", [["clusters", "--top", "0"], ["clusters", "--top", "-2"],
                                  ["gc", "--keep-days", "-1"], ["gc", "--keep-days", "nan"],
                                  ["gc", "--keep-days", "inf"]])
def test_cli_rejects_bad_numbers(argv, seeded, capsys):
    with pytest.raises(SystemExit) as e:
        main([*argv, "--db", str(seeded.path)])
    assert e.value.code == 3


def test_cli_db_error_after_open_exits_3(tmp_path, capsys):
    bad = tmp_path / "bad.db"
    bad.write_text("this is not a database")
    assert main(["runs", "--db", str(bad)]) == 3
    assert capsys.readouterr().err.startswith("ff:")


def test_readme_snippet_runs(tmp_path, monkeypatch):
    import re

    text = (ROOT / "README.md").read_text()
    code = re.search(r"```python\n(.*?)```", text, re.DOTALL).group(1)
    monkeypatch.setenv("FF_DB", str(tmp_path / "readme.db"))
    import failure_forensics as ff

    ff.configure()
    exec(compile(code, "README.md", "exec"), {})  # noqa: S102
    store = Store(tmp_path / "readme.db")
    run = store.list_runs()[0]
    assert (run["fail_step"], run["fail_kind"]) == ("answer", "wrong_result")
    ff.configure(str(tmp_path / "other.db"))
