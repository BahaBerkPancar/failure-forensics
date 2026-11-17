import ast
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import failure_forensics as ff
from failure_forensics.cli import main
from failure_forensics.export import (
    ClusterError,
    collect_cases,
    merge_suite,
    parse_suite,
    render_pytest,
    render_suite,
    resolve_cluster,
    suite_for,
)

ROOT = Path(__file__).resolve().parent.parent


def traced(case_id, question, *, fail=None, out="ok", tags=None):
    """One run: step `tool` records the question, then raises `fail` or returns `out`."""
    try:
        with ff.run("p", case_id=case_id, tags=tags or {}):
            with ff.step("tool") as s:
                s.record(input=question)
                if fail:
                    raise fail
                s.record(output=out)
            if out == "WRONG":
                ff.mark_failure("wrong_result", "expected 8, got 7")
    except Exception:  # noqa: BLE001, S110
        pass


@pytest.fixture
def store(db):
    traced("c1", "how many?", fail=KeyError("sku-1"), tags={"topic": "stock"})
    traced("c1", "how many?", fail=KeyError("sku-2"), tags={"topic": "stock"})  # same input: deduped
    traced("c1", "how many?", out="8")  # a passing run of case c1
    traced("c2", "other?", fail=KeyError("sku-3"))  # no passing run
    traced("c3", "third", fail=ValueError("x"))  # other cluster
    return db


# --- minimal copy of the mrd suite shape (mrd/formats.py: Suite, Metric, Case; extra keys forbidden) ---

def check_mrd_shape(suite):
    assert set(suite) == {"name", "metrics", "cases"}
    assert isinstance(suite["name"], str) and suite["name"]
    assert suite["metrics"] and suite["cases"]
    for m in suite["metrics"]:
        assert set(m) <= {"name", "kind", "higher_is_better", "weight"} and {"name", "kind"} <= set(m)
        assert m["kind"] in ("pass_fail", "score") and isinstance(m["name"], str) and m["name"]
    for c in suite["cases"]:
        assert set(c) <= {"id", "input", "expected", "tags"} and {"id", "input"} <= set(c)
        assert isinstance(c["id"], str) and c["id"]
        assert isinstance(c.get("tags", []), list) and all(isinstance(t, str) for t in c.get("tags", []))
    for key in ("metrics", "cases"):
        names = [x["name" if key == "metrics" else "id"] for x in suite[key]]
        assert len(names) == len(set(names))


def key_sig(store):
    return resolve_cluster(store, "tool | exception | KeyError")


def test_collect_dedupes_and_pairs_passing_run(store):
    cases, skipped = collect_cases(store, key_sig(store))
    assert skipped == 0 and len(cases) == 2  # 3 failing runs, 2 distinct inputs
    by_input = {c.input: c for c in cases}
    c1, c2 = by_input["how many?"], by_input["other?"]
    assert len(c1.run_ids) == 2 and c1.has_expected and c1.expected == "8"
    assert not c2.has_expected and c2.error_type == "KeyError"
    assert c1.id == collect_cases(store, key_sig(store))[0][0].id  # stable
    assert c1.id.startswith("ff-") and "topic:stock" in c1.tags


def test_limit(store):
    cases, _ = collect_cases(store, key_sig(store), limit=1)
    assert len(cases) == 1


def test_resolve_cluster_errors(store):
    with pytest.raises(ClusterError, match="no cluster matches"):
        resolve_cluster(store, "nope")
    with pytest.raises(ClusterError, match="ambiguous"):
        resolve_cluster(store, "tool | exception")
    with pytest.raises(ClusterError):
        resolve_cluster(store, "")


def test_mrd_suite_shape_and_needs_review(store):
    cases, _ = collect_cases(store, key_sig(store))
    suite = suite_for(cases, "demo")
    check_mrd_shape(suite)
    text = render_suite(suite)
    assert parse_suite(text) == suite
    by_input = {c["input"]: c for c in suite["cases"]}
    assert by_input["how many?"]["expected"] == "8" and "needs_review" not in by_input["how many?"]["tags"]
    assert by_input["other?"]["expected"] is None and "needs_review" in by_input["other?"]["tags"]
    tags = by_input["other?"]["tags"]
    assert "step:tool" in tags and "kind:exception" in tags
    assert any(t.startswith("signature:tool | exception | KeyError") for t in tags)


def test_yaml_roundtrip_and_mrd_validation(db, tmp_path):
    import yaml

    inputs = ["emoji \U0001f600", 1e-05, 1e16, {"n": {"deep": [1.5, None, True, "2024-01-02", "yes"]}, "k": 3}]
    for i, v in enumerate(inputs):
        try:
            with ff.run("p", case_id=f"y{i}"), ff.step("tool") as s:
                s.record(input=v)
                raise KeyError("boom")
        except KeyError:
            pass
    cases, _ = collect_cases(db, resolve_cluster(db, "tool | exception | KeyError"))
    path = tmp_path / "s.yaml"
    path.write_text(render_suite(suite_for(cases, "rt")), encoding="utf-8")
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))  # what mrd does
    check_mrd_shape(loaded)
    got = [c["input"] for c in loaded["cases"]]
    assert got == inputs and isinstance(got[1], float) and isinstance(got[2], float)
    assert "\U0001f600" in loaded["cases"][0]["input"] and len(loaded["cases"][0]["input"]) == len("emoji ") + 1


def test_merge_rejects_odd_suites(store, tmp_path, capsys):
    base = ["export", "--cluster", "tool | exception | KeyError", "--to", "mrd", "--db", str(store.path)]
    for text in ("name: x\ncases:\n  - {id: a, input: 1}\n",  # no metrics
                 "name: x\nmetrics: [{name: c, kind: pass_fail}]\ncases: [1]\n",  # case is not a mapping
                 "just text\n"):
        f = tmp_path / "bad.yaml"
        f.write_text(text)
        assert main([*base, "--merge", str(f), "--out", str(tmp_path / "o.yaml")]) == 3
    f.write_text("name: x\nmetrics: [{name: c, kind: pass_fail}]\ncases:\n  - {id: 2024-01-02, input: 2024-01-02}\n")
    assert main([*base, "--merge", str(f), "--out", str(tmp_path / "o.yaml")]) == 0  # YAML dates survive
    capsys.readouterr()


def test_merge_appends_without_duplicates(store):
    cases, _ = collect_cases(store, key_sig(store))
    first = suite_for(cases[:1], "demo")
    merged, added, present = merge_suite(first, cases)
    assert (added, present) == (1, 1) and len(merged["cases"]) == 2
    check_mrd_shape(merged)
    again, added, present = merge_suite(merged, cases)
    assert (added, present) == (0, 2) and again["cases"] == merged["cases"]


def test_cli_mrd_export_and_merge(store, tmp_path, capsys):
    out = tmp_path / "cases.yaml"
    assert main(["export", "--cluster", "tool | exception | KeyError", "--to", "mrd", "--out", str(out),
                 "--limit", "1", "--db", str(store.path)]) == 0
    assert len(parse_suite(out.read_text())["cases"]) == 1
    assert main(["export", "--cluster", "tool | exception | KeyError", "--to", "mrd", "--out", str(out),
                 "--merge", str(out), "--db", str(store.path)]) == 0
    text = capsys.readouterr().out
    assert "merged: 1 new, 1 already" in text
    suite = parse_suite(out.read_text())
    check_mrd_shape(suite)
    assert len(suite["cases"]) == 2


# --- pytest export --------------------------------------------------------------------------

def run_generated(tmp_path, source, stub_body, extra_env=None):
    test_file = tmp_path / "test_gen.py"
    test_file.write_text(source)
    (tmp_path / "stub.py").write_text(stub_body)
    env = {**os.environ, "PYTHONPATH": str(tmp_path), "PYTHONDONTWRITEBYTECODE": "1", **(extra_env or {})}
    return subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--no-header",
                           str(test_file)], cwd=tmp_path, env=env, check=False, capture_output=True, text=True, timeout=120)


def test_pytest_export_compiles_and_replays(store, tmp_path):
    cases, _ = collect_cases(store, key_sig(store))
    src = render_pytest(cases, "stub:answer")
    compile(src, "gen", "exec")
    bad = run_generated(tmp_path, src, "def answer(q):\n    raise KeyError('sku-1')\n")
    assert bad.returncode == 1 and "still fails the same way: KeyError" in bad.stdout
    good = run_generated(tmp_path, src, "def answer(q):\n    return 'fine'\n")
    assert good.returncode == 0 and "2 passed" in good.stdout
    other = run_generated(tmp_path, src, "def answer(q):\n    raise RuntimeError('different')\n")
    assert other.returncode == 1 and "RuntimeError" in other.stdout  # a different error is not a pass


def test_semantic_failure_uses_expected_checker_or_skips(db, tmp_path):
    traced("w1", "q-with-gold", out="8")
    traced("w1", "q-with-gold", out="WRONG")
    traced("w2", "q-no-gold", out="WRONG")
    sig = resolve_cluster(db, "p | wrong_result")
    cases, _ = collect_cases(db, sig)
    src = render_pytest(cases, "stub:answer")
    stub = "def answer(q):\n    return '8'\n"
    r = run_generated(tmp_path, src, stub)
    assert r.returncode == 0 and "1 passed, 1 skipped" in r.stdout  # no gold: skipped with a reason
    r = run_generated(tmp_path, src, "def answer(q):\n    return '7'\n")
    assert r.returncode == 1 and "1 failed" in r.stdout
    src = render_pytest(cases, "stub:answer", "stub:check")
    r = run_generated(tmp_path, src, stub + "def check(i, result, case):\n    return result == '8'\n")
    assert r.returncode == 0 and "2 passed" in r.stdout


HOSTILE = [
    "it's a \"quote\"; \\ backslash",
    "'''triple''' and \"\"\"triple\"\"\"\nnewline\r\nline",
    "__import__('os').system('touch PWNED')",
    "'); __import__('os').system('touch PWNED'); ('",
    "\"\"\"\n__import__('os').system('touch PWNED')\n\"\"\"",
    "@@CASES@@ @@ENTRY@@ \x00 \u2028 \u00e9 \U0001f600",
    {"k'": ["\"\"\"", "#", "\\"], "n": 1.5, "b": True, "z": None},
]


def test_hostile_inputs_make_an_inert_valid_file(db, tmp_path):
    for i, bad in enumerate(HOSTILE):
        try:
            with ff.run("p", case_id=f"h{i}"), ff.step("tool") as s:
                s.record(input=bad)
                raise KeyError("boom")
        except KeyError:
            pass
    cases, _ = collect_cases(db, resolve_cluster(db, "tool | exception | KeyError"))
    assert len(cases) == len(HOSTILE)
    src = render_pytest(cases, "stub:answer")
    tree = ast.parse(src)
    # the dangerous text exists only inside string constants: no call or name refers to it
    assert not [n for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id == "__import__"]
    calls = {n.func.id for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert calls <= {"_load", "getattr", "type"}  # only the template's own calls
    seen = tmp_path / "seen.json"
    stub = (
        "import json, os\n"
        "def answer(q):\n"
        f"    p = {str(seen)!r}\n"
        "    old = json.load(open(p)) if os.path.exists(p) else []\n"
        "    json.dump(old + [q], open(p, 'w'))\n"
        "    return 'ok'\n"
    )
    r = run_generated(tmp_path, src, stub)
    assert r.returncode == 0, r.stdout + r.stderr
    assert not (tmp_path / "PWNED").exists()
    replayed = json.loads(seen.read_text())
    assert sorted(map(json.dumps, replayed)) == sorted(json.dumps(c.input) for c in cases)  # byte-exact


def test_hostile_signature_cannot_inject(db, tmp_path):
    msg = "'''\n__import__('os').system('touch PWNED')\n@@CASES@@"
    try:
        with ff.run("p", case_id="s1"), ff.step("tool") as s:
            s.record(input="x")
            raise RuntimeError(msg)
    except RuntimeError:
        pass
    cases, _ = collect_cases(db, resolve_cluster(db, "tool | exception"))
    src = render_pytest(cases, "stub:answer")
    ast.parse(src)
    r = run_generated(tmp_path, src, "def answer(q):\n    return 1\n")
    assert r.returncode == 0 and not (tmp_path / "PWNED").exists()


@pytest.mark.parametrize("entry", ["os.system", "a:b:c", "mod:fn()", "mod:fn; import os", "'x':y", ":f", "m:"])
def test_bad_entry_specs_rejected(store, entry):
    cases, _ = collect_cases(store, key_sig(store))
    with pytest.raises(ValueError):
        render_pytest(cases, entry)


# --- redaction, CLI ---------------------------------------------------------------------------

def test_redaction_is_counted_and_listed(db, tmp_path, capsys):
    traced("r1", "mail bob@example.com about it", fail=KeyError("k1"))
    traced("r2", "plain question", fail=KeyError("k2"))
    out = tmp_path / "c.yaml"
    args = ["export", "--cluster", "tool | exception", "--to", "mrd", "--out", str(out), "--db", str(db.path)]
    assert main(args) == 0
    text = capsys.readouterr().out
    assert "redacted: 1 case(s)" in text and "already-redacted" in text
    assert "bob@example.com" not in out.read_text() and "[REDACTED:email]" in out.read_text()
    assert main([*args, "--show-redacted"]) == 0
    listed = capsys.readouterr().out.splitlines()
    ids = [c["id"] for c in parse_suite(out.read_text())["cases"] if "REDACTED" in json.dumps(c["input"])]
    assert f"  {ids[0]}" in listed
    assert main([*args, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["redacted"] == ids


def test_cli_exit_codes(store, tmp_path, capsys):
    base = ["--db", str(store.path)]
    sig = ["--cluster", "tool | exception | KeyError"]
    out = str(tmp_path / "t" / "test_x.py")
    assert main(["export", "--cluster", "nope", "--to", "mrd", *base]) == 3
    assert main(["export", "--cluster", "tool | exception", "--to", "mrd", *base]) == 3  # ambiguous
    assert main(["export", *sig, "--to", "pytest", "--out", out, *base]) == 3  # no --entry
    assert main(["export", *sig, "--to", "pytest", "--entry", "bad entry", "--out", out, *base]) == 3
    assert main(["export", *sig, "--to", "pytest", "--entry", "m:f", "--merge", "x.yaml", "--out", out, *base]) == 3
    assert main(["export", *sig, "--to", "mrd", "--entry", "m:f", *base]) == 3
    assert main(["export", *sig, "--to", "mrd", "--merge", str(tmp_path / "missing.yaml"), *base]) == 3
    with pytest.raises(SystemExit) as e:
        main(["export", *sig, "--to", "other", *base])
    assert e.value.code == 3
    with pytest.raises(SystemExit) as e:
        main(["export", *sig, "--to", "mrd", "--limit", "0", *base])
    assert e.value.code == 3
    assert main(["export", *sig, "--to", "mrd", "--db", str(tmp_path / "none.db")]) == 3
    capsys.readouterr()
    assert main(["export", *sig, "--to", "pytest", "--entry", "m:f", "--out", out, *base]) == 0
    assert Path(out).read_text().startswith("# Generated by failure-forensics")
    assert main(["export", *sig, "--to", "pytest", "--entry", "m:f", "--out", out, *base]) == 0  # regenerate ok
    Path(out).write_text("# my own file\n")
    assert main(["export", *sig, "--to", "pytest", "--entry", "m:f", "--out", out, *base]) == 3
    assert Path(out).read_text() == "# my own file\n"
    assert "refusing to overwrite" in capsys.readouterr().err


def test_default_pytest_path_uses_slug(store, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main(["export", "--cluster", "tool | exception | KeyError", "--to", "pytest", "--entry", "m:f",
                 "--db", str(store.path)]) == 0
    assert (tmp_path / "tests/regressions/test_tool_exception_keyerror_sku_n.py").exists()


def test_failures_without_recorded_input_exit_3(db, capsys):
    try:
        with ff.run("p", case_id="n1"), ff.step("tool"):
            raise KeyError("k")
    except KeyError:
        pass
    assert main(["export", "--cluster", "tool | exception", "--to", "mrd", "--db", str(db.path)]) == 3
    assert "no failing run with a recorded input" in capsys.readouterr().err


@pytest.mark.skipif(shutil.which("uv") is None, reason="uv not installed")
def test_run_loop_script_closes_the_loop():
    r = subprocess.run([str(ROOT / "examples/loop/run_loop.sh")], check=False, capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "failed in" in r.stdout and "passed in" in r.stdout and "loop closed" in r.stdout
