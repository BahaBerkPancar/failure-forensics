"""Pages built headlessly with Streamlit's AppTest (no browser, no network). Needs the `ui` extra."""

import hashlib
import shutil
from pathlib import Path

import pytest

pytest.importorskip("streamlit")
pytest.importorskip("pandas")
from streamlit.testing.v1 import AppTest

from failure_forensics.store import Store
from failure_forensics.ui import views

from .conftest import SEC, span

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "src" / "failure_forensics" / "ui" / "app.py"
SCRIPT = "from failure_forensics.ui import views\nviews.{page}({db!r})\n"


@pytest.fixture
def t2s_db(tmp_path):
    dst = tmp_path / "t2s.db"
    shutil.copy(ROOT / "examples" / "t2s" / "demo.db", dst)
    return dst


def wrong_join_id(db):
    from failure_forensics.ui import data

    with data.open_readonly(db) as conn:
        runs = [r for r in data.query_runs(conn) if r.case_id == "q009" and r.tags["generator"] == "mutated:wrong-join"]
    return runs[0].trace_id[:12]


def page(name, db, **state):
    at = AppTest.from_string(SCRIPT.format(page=name, db=str(db)), default_timeout=30)
    for k, v in state.items():
        at.session_state[k] = v
    return at


def texts(at):
    out = [e.value for e in at.markdown] + [e.value for e in at.caption] + [e.value for e in at.text]
    out += [e.value for e in at.title] + [e.value for e in at.subheader] + [e.value for e in at.info]
    return out


@pytest.mark.parametrize("name", ["overview_page", "runs_page", "run_page", "clusters_page", "diff_page"])
def test_every_page_builds_on_both_demo_dbs(name, t2s_db, tmp_path):
    toy = tmp_path / "toy.db"
    shutil.copy(ROOT / "examples" / "demo.db", toy)
    for db in (t2s_db, toy):
        at = page(name, db).run()
        assert not at.exception, [e.value for e in at.exception]


def test_overview_numbers(t2s_db):
    at = page("overview_page", t2s_db).run()
    assert [m.value for m in at.metric] == ["288", "50", "17.4%", "5"]
    assert [m.label for m in at.metric] == ["Runs", "Failed runs", "Failure rate", "Clusters"]
    assert at.title[0].value == "Overview"


def test_overview_with_a_window(t2s_db):
    # "Last hour" counted back from the newest run still holds everything of this demo
    at = page("overview_page", t2s_db, window="Last hour").run()
    assert not at.exception and at.metric[0].value == "288"


def test_runs_page_filters_and_empty_state(t2s_db):
    at = page("runs_page", t2s_db).run()
    assert not at.exception and any("288 runs" in t for t in texts(at))
    at.selectbox[0].select("failed").run()  # Status
    assert any("50 runs" in t for t in texts(at))
    at.text_input[0].set_value("no-such-case").run()
    assert any("No runs match these filters" in t for t in texts(at))


def test_run_page_shows_culprit_and_waterfall(t2s_db):
    at = page("run_page", t2s_db)
    at.query_params["run"] = wrong_join_id(t2s_db)
    at.run()
    assert not at.exception
    assert any("compare / wrong_result" in e.value for e in at.text)
    assert len(at.expander) == 4 and any("culprit" in e.label for e in at.expander)
    assert at.button[0].label == "Compare with passing run"
    assert len(at.get("vega_lite_chart")) == 1


def test_diff_page_names_first_divergence(t2s_db):
    at = page("diff_page", t2s_db)
    at.query_params["run"] = wrong_join_id(t2s_db)
    at.run()
    assert not at.exception
    assert "First difference" in [s.value for s in at.subheader]
    assert any(e.value == "generate" for e in at.text)  # a step that ran once has no #n
    assert any("same case" in c.value for c in at.caption)


def test_repeated_steps_are_numbered(t2s_db):
    from failure_forensics.ui import data

    pairs = []
    with data.open_readonly(t2s_db) as conn:
        blocked = next(r for r in data.query_runs(conn, data.RunFilter(kind="blocked"))
                       if r.tags["generator"] == "mutated:harmless-function")
        other, _ = data.nearest_passing(conn, blocked.trace_id)
        pairs = data.diff_runs(data.run_detail(conn, blocked.trace_id), data.run_detail(conn, other.trace_id))
    assert [views._pair_title(p) for p in pairs] == [
        "generate", "validate", "generate #2", "validate #2", "execute", "compare"]


def test_clusters_page_lists_clusters(t2s_db):
    at = page("clusters_page", t2s_db).run()
    assert not at.exception and at.title[0].value == "Clusters"


def test_empty_store_shows_empty_states(tmp_path):
    db = tmp_path / "empty.db"
    Store(db)
    for name in ("overview_page", "runs_page", "run_page", "clusters_page", "diff_page"):
        at = page(name, db).run()
        assert not at.exception, name
        assert at.info, name  # a plain empty-state message, not a blank page


def test_store_without_failures(tmp_path):
    db = tmp_path / "ok.db"
    store = Store(db)
    store.insert_spans([span("a" * 32, "01", None, "pipe", 0, SEC, **{"ff.kind": "run", "ff.tags": "{}"})])
    store.finalize_run("a" * 32)
    over = page("overview_page", db).run()
    assert not over.exception and any("No failures in this window" in i.value for i in over.info)
    cl = page("clusters_page", db).run()
    assert any("No failures in this window" in i.value for i in cl.info)
    diff = page("diff_page", db).run()
    assert any("No failing runs" in i.value for i in diff.info)


def test_missing_database_is_an_error_not_a_traceback(tmp_path):
    at = page("overview_page", tmp_path / "nope.db").run()
    assert not at.exception and at.error and any("no database" in e.value for e in at.text)


PAYLOADS = ["![](https://evil/x.png)", "[x](javascript:alert(1))", ":red[x]", "<script>alert(1)</script>",
            ":smile:", "<img src=x onerror=alert(1)>"]
EVIL = " ".join(PAYLOADS)
MARKDOWN_ELEMENTS = ("markdown", "caption", "subheader", "title", "header", "error", "info", "warning",
                     "success", "metric")


def evil_db(tmp_path):
    """A failing run, a passing run of the same case, all names, tags, kinds and messages hostile."""
    db = tmp_path / "evil.db"
    store = Store(db)
    for t, status, start in (("e" * 32, "error", 5 * SEC), ("f" * 32, "ok", 0)):
        fail = status == "error"
        store.insert_spans([
            span(t, "01", None, "run " + EVIL, start, start + 10 * SEC, status,
                 **{"ff.kind": "run", "ff.tags": json_tags(), "ff.case_id": "case " + EVIL}),
            span(t, "02", "01", "step " + EVIL, start + SEC, start + 2 * SEC, status,
                 **{"ff.input": EVIL, "ff.output": '"' + EVIL + ("x" if fail else "") + '"',
                    **({"ff.failure.kind": "wrong_result", "ff.failure.detail": EVIL} if fail else {})}),
        ])
        store.finalize_run(t)
    return db


def json_tags():
    import json

    return json.dumps({"k " + EVIL: "v " + EVIL})


def assert_no_live_markup(at):
    for kind in MARKDOWN_ELEMENTS:
        for el in at.get(kind):
            value = str(getattr(el, "value", "")) + str(getattr(el, "label", ""))
            for bad in PAYLOADS:
                assert bad not in value, (kind, value)
    for e in at.expander:
        for bad in PAYLOADS:
            assert bad not in e.label, e.label


def test_hostile_values_are_never_rendered_as_markup(tmp_path):
    db = evil_db(tmp_path)
    for name in ("run_page", "diff_page", "runs_page", "clusters_page", "overview_page"):
        at = page(name, db)
        at.query_params["run"] = "e" * 12
        at.run()
        assert not at.exception, name
        assert_no_live_markup(at)
    # the hostile text is still visible, as plain text
    at = page("run_page", db)
    at.query_params["run"] = "e" * 12
    at.run()
    shown = [e.value for e in at.text] + [e.value for e in at.get("code")]
    assert any(EVIL in v for v in shown)
    assert any("Tags" == c.value for c in at.caption)
    assert at.expander and all("\\<script\\>" in e.label for e in at.expander)
    diff = page("diff_page", db)
    diff.query_params["run"] = "e" * 12
    diff.run()
    assert diff.subheader and any(s.value == "First difference" for s in diff.subheader)
    assert any(EVIL in v for v in [e.value for e in diff.text] + [e.value for e in diff.get("code")])


def test_hostile_cluster_section_and_database_errors(tmp_path):
    db = evil_db(tmp_path)
    at = page("clusters_page", db).run()
    # select the first cluster the way a click would
    at.session_state["clusters_table"] = {"selection": {"rows": [0], "columns": []}}
    at.run()
    assert not at.exception
    assert_no_live_markup(at)
    assert any(EVIL in e.value for e in at.text)  # the cluster message, as text
    bad = tmp_path / "bad [x](javascript:alert(1)) :red[x] <script>.db"
    bad.write_text("not a database")
    err = page("overview_page", bad).run()
    assert not err.exception and err.error
    assert_no_live_markup(err)


def test_esc_neutralises_all_markdown():
    out = views.esc(EVIL)
    for bad in PAYLOADS:
        assert bad not in out
    assert views.esc("www.evil.com") == "www\\.evil\\.com" and views.esc("plain") == "plain"


def test_whole_app_runs_read_only(t2s_db, monkeypatch):
    before = hashlib.sha256(t2s_db.read_bytes()).hexdigest()
    monkeypatch.setenv("FF_UI_DB", str(t2s_db))
    at = AppTest.from_file(str(APP), default_timeout=30).run()
    assert not at.exception, [e.value for e in at.exception]
    assert at.title[0].value == "Overview" and at.metric[0].value == "288"
    for name in ("runs_page", "run_page", "clusters_page", "diff_page"):
        assert not page(name, t2s_db).run().exception
    assert hashlib.sha256(t2s_db.read_bytes()).hexdigest() == before


def test_app_without_database_says_so(monkeypatch):
    monkeypatch.delenv("FF_UI_DB", raising=False)
    at = AppTest.from_file(str(APP), default_timeout=30).run()
    assert not at.exception and any("ff ui --db" in e.value for e in at.error)


def test_waterfall_spec_marks_only_the_culprit(t2s_db):
    from failure_forensics.ui import data
    from failure_forensics.ui.style import LIGHT

    with data.open_readonly(t2s_db) as conn:
        spec = views.waterfall_spec(data.run_detail(conn, wrong_join_id(t2s_db)), LIGHT)
    rows = spec["data"]["values"]
    assert [r["kind"] for r in rows] == ["Run", "Completed", "Completed", "Completed", "Culprit"]
    assert [r["label"].strip() for r in rows] == ["t2s.question", "generate", "validate", "execute", "compare"]
    assert all(r["end"] > r["start"] for r in rows)
    colour = spec["layer"][0]["encoding"]["color"]["scale"]
    assert colour["range"][colour["domain"].index("Culprit")] == LIGHT["accent"]


@pytest.mark.parametrize("pal_name", ["LIGHT", "DARK"])
def test_chart_colours_one_accent_distinct_neutrals(pal_name, tmp_path):
    from failure_forensics.ui import data, style

    pal = getattr(style, pal_name)
    toy = tmp_path / "toy.db"
    shutil.copy(ROOT / "examples" / "demo.db", toy)
    with data.open_readonly(toy) as conn:  # six clusters: five kept, one folded into "Other clusters"
        ov = data.overview(conn)
        series = data.cluster_series(conn, "second")
        spec = views.failures_over_time_spec(series, "second", pal, ov.first_ns, ov.last_ns)
    scale = spec["encoding"]["color"]["scale"]
    domain, colours = scale["domain"], scale["range"]
    assert len(domain) == 6 and domain[-1] == "Other clusters" and len(colours) == 6
    assert colours.count(pal["accent"]) == 1 and colours[0] == pal["accent"]
    assert len(set(colours)) == 6  # nothing cycles or repeats
    assert colours[-1] == pal["other"] and pal["other"] not in pal["ramp"][:4]
    assert sum(v["count"] for v in spec["data"]["values"]) == 58
