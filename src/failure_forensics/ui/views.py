"""Streamlit pages. Everything that comes out of the database is shown with `st.text`, `st.code`,
`st.json` or a dataframe, never as HTML or Markdown (`esc` is for the few labels that must be Markdown)."""

from __future__ import annotations

import json
import re
from contextlib import closing
from typing import Any

import pandas as pd
import streamlit as st

from . import data
from .style import CSS, palette

WINDOWS = {"All runs": None, "Last hour": data.HOUR_NS, "Last 24 hours": data.DAY_NS,
           "Last 7 days": 7 * data.DAY_NS}
PAGES: dict[str, Any] = {}  # filled by app.py so tables can jump to a page
MAX_TABLE_ROWS = 1000
MAX_TEXT = 4000
OTHER = "Other clusters"
_MD_PUNCT = re.compile(r"([!-/:-@\[-`{-~])")


def esc(text: object) -> str:
    """Backslash-escape every ASCII punctuation mark (valid Markdown), so links, images, colour directives,
    emoji shortcodes, HTML and bare-URL autolinks all stay literal. Only for labels that cannot be plain text
    (expander titles, select options); everything else goes through st.text / st.code."""
    return _MD_PUNCT.sub(r"\\\1", str(text))


def css() -> None:
    st.html(CSS)  # constant stylesheet from style.py, no data


def _open(db: str):
    try:
        return closing(data.open_readonly(db))
    except (FileNotFoundError, ValueError) as e:
        st.error("Cannot open the database.")
        st.text(str(e))
        st.stop()


def _tags_text(tags: dict) -> str:
    return ", ".join(f"{k}={v}" for k, v in tags.items()) or "none"


def header(title: str, sub: str) -> None:
    st.title(title)
    st.caption(sub)


def _plural(n: int, word: str) -> str:
    return f"{n:,} {word}" if n == 1 else f"{n:,} {word}s"


# -- shared state ------------------------------------------------------------------------
def window_bounds(conn) -> tuple[int | None, int | None]:
    """The sidebar window, counted back from the newest run (the data, not the wall clock)."""
    span = WINDOWS.get(st.session_state.get("window", "All runs"))
    last = data.facets(conn)["last_ns"]
    if span is None or last is None:
        return None, None
    return last - span, None


def sidebar(db: str) -> None:
    css()
    with st.sidebar:
        st.html('<div class="ff-brand">failure-forensics</div>'
                '<div class="ff-brand-sub">Where did the run go wrong</div>')
        for key in ("overview", "runs", "run", "clusters", "diff"):
            if key in PAGES:
                st.page_link(PAGES[key])
        st.selectbox("Window", list(WINDOWS), key="window", help="Counted back from the newest run")
        with _open(db) as conn:
            f = data.facets(conn)
            total = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
        name = db.replace("\\", "/").rsplit("/", 1)[-1]
        st.text(f"{name}\n{_plural(total, 'run')}")
        if f["last_ns"] is not None:
            st.caption(f"Newest {data.fmt_ts(f['last_ns'])} UTC")


def _remember_run(trace_id: str) -> None:
    st.session_state["run"] = trace_id


def open_run(trace_id: str) -> None:
    _remember_run(trace_id)
    st.query_params["run"] = trace_id
    if "run" in PAGES:
        st.switch_page(PAGES["run"])


def _current_run() -> str | None:
    return st.query_params.get("run") or st.session_state.get("run")


# -- tables ------------------------------------------------------------------------------
def runs_frame(runs: list[data.RunRow]) -> pd.DataFrame:
    return pd.DataFrame({
        "Run": [r.trace_id[:12] for r in runs],
        "Status": [r.status for r in runs],
        "Started (UTC)": [data.fmt_ts(r.start_ns) for r in runs],
        "Duration": [data.fmt_dur(r.duration_ns) for r in runs],
        "Case": [r.case_id or "" for r in runs],
        "Culprit": [f"{r.culprit_step} / {r.culprit_kind}" if r.culprit_kind else "" for r in runs],
        "Message": [r.message or "" for r in runs],
    })


def runs_table(runs: list[data.RunRow], key: str) -> None:
    """A selectable table; picking a row opens that run."""
    shown = runs[:MAX_TABLE_ROWS]
    ev = st.dataframe(
        runs_frame(shown), hide_index=True, on_select="rerun", selection_mode="single-row", key=key,
        column_config={"Message": st.column_config.TextColumn(width="large"),
                       "Run": st.column_config.TextColumn(width="small")},
    )
    if len(runs) > len(shown):
        st.caption(f"Showing the newest {len(shown):,} of {len(runs):,} runs. Narrow the filters to see the rest.")
    else:
        st.caption(f"{_plural(len(runs), 'run')}. Select a row to open it.")
    rows = ev.selection.rows if ev and ev.selection else []
    if rows:
        open_run(shown[rows[0]].trace_id)


def pretty(text: str | None) -> str:
    """The text to show: JSON values are re-indented, long values are cut for display."""
    if text is None:
        return ""
    try:
        text = json.dumps(json.loads(text), indent=2, ensure_ascii=False)
    except ValueError:
        pass
    if len(text) > MAX_TEXT:
        text = text[:MAX_TEXT] + f"\n... [{len(text) - MAX_TEXT:,} more characters not shown]"
    return text


def show_value(label: str, text: str | None) -> None:
    st.caption(label)
    if text is None:
        st.text("not recorded")
        return
    st.code(pretty(text), language=None, wrap_lines=True)


# -- overview ----------------------------------------------------------------------------
def _bucket_labels(bucket: str, start: int, end: int) -> list[int]:
    size = data.BUCKETS[bucket]
    return list(range(start // size * size, end // size * size + size, size))


def _tick(bucket: str, ns: int) -> str:
    from datetime import UTC, datetime

    fmt = {"second": "%H:%M:%S", "minute": "%H:%M", "hour": "%d %b %H:00", "day": "%d %b"}[bucket]
    return datetime.fromtimestamp(ns / 1e9, tz=UTC).strftime(fmt)


def _vega_config(pal: dict) -> dict:
    return {
        "background": None,
        "view": {"stroke": None},
        "axis": {"labelColor": pal["muted"], "titleColor": pal["muted"], "gridColor": pal["line"],
                 "domainColor": pal["line"], "tickColor": pal["line"], "labelFontSize": 12,
                 "titleFontSize": 12, "titleFontWeight": 400,
                 "labelFont": "SF Mono, Menlo, Consolas, monospace",
                 "titleFont": "Avenir Next, Segoe UI, system-ui, sans-serif"},
        "legend": {"labelColor": pal["text2"], "titleColor": pal["muted"], "labelFontSize": 12,
                   "labelFont": "Avenir Next, Segoe UI, system-ui, sans-serif", "symbolType": "square",
                   "orient": "bottom", "titleFontSize": 12, "titleFontWeight": 400},
    }


def failures_over_time_spec(series: list[dict], bucket: str, pal: dict, first_ns: int, last_ns: int) -> dict:
    """Stacked bars per bucket. The biggest cluster takes the accent, the rest sit in neutral steps."""
    totals: dict[str, int] = {}
    for s in series:
        totals[s["label"]] = totals.get(s["label"], 0) + s["count"]
    ranked = sorted(totals, key=lambda k: (-totals[k], k))
    keep = ranked[:5]
    # exactly one accent (the largest cluster), distinct neutrals for the next four, a fixed pale grey for the rest
    colours = [pal["accent"], *pal["ramp"][:4]][: len(keep)]
    domain = list(keep)
    if len(ranked) > len(keep):
        domain.append(OTHER)
        colours.append(pal["other"])
    ticks = _bucket_labels(bucket, first_ns, last_ns)
    counts = {(s["bucket_ns"], s["label"] if s["label"] in keep else OTHER): 0 for s in series}
    for s in series:
        counts[(s["bucket_ns"], s["label"] if s["label"] in keep else OTHER)] += s["count"]
    for b in ticks:  # a zero row for every bucket, so quiet buckets stay on the axis
        counts.setdefault((b, domain[0]), 0)
    values = [{"t": _tick(bucket, b), "order": ticks.index(b), "cluster": c, "rank": domain.index(c), "count": n}
              for (b, c), n in counts.items()]
    return {
        "data": {"values": values},
        "height": 260,
        "mark": {"type": "bar", "cornerRadiusTopLeft": 2, "cornerRadiusTopRight": 2},
        "encoding": {
            "x": {"field": "t", "type": "ordinal", "sort": {"field": "order", "op": "min"},
                  "axis": {"title": None, "labelAngle": 0, "labelOverlap": True, "ticks": False}},
            "y": {"field": "count", "type": "quantitative",
                  "axis": {"title": "Failures per " + bucket, "tickMinStep": 1, "format": "d"}},
            "color": {"field": "cluster", "type": "nominal", "scale": {"domain": domain, "range": colours},
                      "legend": {"title": None, "columns": 1, "labelLimit": 600}},
            "order": {"field": "rank", "type": "quantitative", "sort": "descending"},
            "tooltip": [{"field": "t", "title": "Bucket (UTC)"}, {"field": "cluster", "title": "Cluster"},
                        {"field": "count", "title": "Failures"}],
        },
        "config": _vega_config(pal),
    }


def overview_page(db: str) -> None:
    with _open(db) as conn:
        since, until = window_bounds(conn)
        ov = data.overview(conn, since, until)
        header("Overview", _window_sub(ov))
        if ov.runs == 0:
            st.info("No runs in this window. Widen the window in the sidebar.")
            return
        c1, c2, c3, c4 = st.columns(4, gap="large")
        c1.metric("Runs", f"{ov.runs:,}")
        c2.metric("Failed runs", f"{ov.failed:,}")
        c3.metric("Failure rate", f"{ov.failure_rate * 100:.1f}%")
        c4.metric("Clusters", f"{ov.clusters:,}")
        if ov.failed == 0:
            st.subheader("Failures over time")
            st.info("No failures in this window.")
            return
        bucket = data.auto_bucket(ov.first_ns, ov.last_ns)
        series = data.cluster_series(conn, bucket, since, until)
        st.subheader("Failures over time")
        st.caption("Each bar is one UTC " + bucket + ". The largest cluster is the coloured part of every bar.")
        st.vega_lite_chart(failures_over_time_spec(series, bucket, palette(), ov.first_ns, ov.last_ns),
                           theme=None)
        st.subheader("Biggest clusters")
        full = data.clusters(conn, since, until)
        ticks = _bucket_labels(bucket, ov.first_ns, ov.last_ns)
        per = {(s["signature"], s["bucket_ns"]): s["count"] for s in series}
        frame = pd.DataFrame({
            "Cluster": [c.label for c in full[:8]],
            "Message": [c.message for c in full[:8]],
            "Failures": [c.count for c in full[:8]],
            "Share of runs": [f"{c.share * 100:.1f}%" for c in full[:8]],
            "Over time": [[per.get((c.signature, t), 0) for t in ticks] for c in full[:8]],
        })
        st.dataframe(frame, hide_index=True, column_config={
            "Failures": st.column_config.ProgressColumn("Failures", min_value=0, max_value=full[0].count,
                                                        format="%d"),
            "Over time": st.column_config.LineChartColumn("Over time", y_min=0),
            "Message": st.column_config.TextColumn(width="large"),
        })
        if len(full) > 8:
            st.caption(f"{len(full) - 8} smaller clusters are on the Clusters page.")


def _window_sub(ov: data.Overview) -> str:
    if ov.first_ns is None:
        return "No runs recorded"
    a, b = data.fmt_ts(ov.first_ns), data.fmt_ts(ov.last_ns)
    return f"{a} to {b} UTC" if a != b else f"{a} UTC"


# -- runs --------------------------------------------------------------------------------
def runs_page(db: str) -> None:
    header("Runs", "Every traced run with its culprit step. Filter, then pick a row.")
    with _open(db) as conn:
        since, until = window_bounds(conn)
        f = data.facets(conn)
        clusters = data.clusters(conn, since, until)
        a, b, c = st.columns(3, gap="medium")
        status = a.selectbox("Status", ["All", "failed", "ok"])
        name = b.selectbox("Pipeline", ["All", *f["names"]])
        case = c.text_input("Case id contains")
        d, e, g = st.columns(3, gap="medium")
        tag_key = d.selectbox("Tag", ["Any", *f["tags"]])
        tag_val = e.selectbox("Tag value", ["Any", *(f["tags"].get(tag_key, []) if tag_key != "Any" else [])],
                              disabled=tag_key == "Any")
        step = g.selectbox("Culprit step", ["All", *f["steps"]])
        labels = {c.signature: f"{c.label}: {c.message}" for c in clusters}
        sig = st.selectbox("Cluster", ["All", *labels], format_func=lambda s: s if s == "All" else labels[s])
        flt = data.RunFilter(
            status=None if status == "All" else status, name=None if name == "All" else name,
            tag=(tag_key, tag_val) if tag_key != "Any" and tag_val != "Any" else None,
            since_ns=since, until_ns=until, step=None if step == "All" else step,
            signature=None if sig == "All" else sig, case_id=case or None)
        runs = data.query_runs(conn, flt)
    if not runs:
        st.info("No runs match these filters." if any([status != "All", name != "All", case, step != "All",
                sig != "All", tag_key != "Any"]) else "No runs in this window.")
        return
    runs_table(runs, key="runs_table")


# -- run detail --------------------------------------------------------------------------
def waterfall_spec(detail: data.RunDetail, pal: dict) -> dict:
    spans = detail.spans
    total = max((s.offset_ns + s.duration_ns for s in spans), default=1) or 1
    floor = total * 0.006  # keep very short steps visible; the label shows the true duration
    failed_above = {s.span_id for s in spans if s.status == "error" and not s.is_culprit}
    rows = []
    for i, s in enumerate(spans):
        kind = ("Culprit" if s.is_culprit else "Errored" if s.span_id in failed_above else
                "Run" if s.is_root else "Completed")
        rows.append({
            "order": i, "label": " " * s.depth + s.name, "kind": kind,
            "start": s.offset_ns / 1e6, "end": (s.offset_ns + max(s.duration_ns, floor)) / 1e6,
            "dur": data.fmt_dur(s.duration_ns),
        })
    colours = {"Culprit": pal["accent"], "Errored": pal["ramp"][0], "Completed": pal["ramp"][2],
               "Run": pal["ramp"][4]}
    present = [k for k in colours if any(r["kind"] == k for r in rows)]
    y = {"field": "label", "type": "ordinal", "sort": {"field": "order"},
         "axis": {"title": None, "labelLimit": 260, "domain": False, "ticks": False, "labelPadding": 8,
                  "labelColor": pal["text2"], "labelFont": "SF Mono, Menlo, Consolas, monospace"}}
    return {
        "data": {"values": rows},
        "height": {"step": 32},
        "encoding": {"y": y},
        "layer": [
            {"mark": {"type": "bar", "size": 16, "cornerRadius": 3},
             "encoding": {
                 "x": {"field": "start", "type": "quantitative",
                       "scale": {"domain": [0, total / 1e6 * 1.14], "nice": False},
                       "axis": {"title": "Milliseconds since the run started", "format": ".1f"}},
                 "x2": {"field": "end"},
                 "color": {"field": "kind", "type": "nominal",
                           "scale": {"domain": present, "range": [colours[k] for k in present]},
                           "legend": {"title": None, "orient": "top", "direction": "horizontal"}},
                 "tooltip": [{"field": "label", "title": "Step"}, {"field": "dur", "title": "Duration"},
                             {"field": "kind", "title": "State"}]}},
            {"mark": {"type": "text", "align": "left", "dx": 8, "fontSize": 12,
                      "font": "SF Mono, Menlo, Consolas, monospace", "color": pal["muted"]},
             "encoding": {"x": {"field": "end", "type": "quantitative"}, "text": {"field": "dur"}}},
        ],
        "config": _vega_config(pal),
    }


def _status_line(run: data.RunRow) -> None:
    # fixed constants only: the stored status is never put into markup
    if run.status == "failed":
        st.html('<span class="ff-chip"><span class="ff-dot fail"></span>failed</span>')
    else:
        st.html('<span class="ff-chip"><span class="ff-dot ok"></span>ok</span>')


def pick_run(conn, label: str, only_failed: bool, since, until) -> str | None:
    runs = data.query_runs(conn, data.RunFilter(status="failed" if only_failed else None,
                                                since_ns=since, until_ns=until))
    if not runs:
        return None
    ids = [r.trace_id for r in runs]
    by_id = {r.trace_id: r for r in runs}
    wanted = _current_run()
    if wanted and not any(i.startswith(wanted) for i in ids) and not only_failed:
        try:  # outside the window: look it up on its own
            extra = data.run_detail(conn, wanted).run
            by_id[extra.trace_id] = extra
            ids.insert(0, extra.trace_id)
            wanted = extra.trace_id
        except LookupError:
            wanted = None
    elif wanted:
        wanted = next((i for i in ids if i.startswith(wanted)), None)
    index = ids.index(wanted) if wanted in ids else 0

    def fmt(i: str) -> str:
        r = by_id[i]
        tail = f"{r.culprit_step} / {r.culprit_kind}" if r.culprit_kind else r.status
        return f"{i[:12]}   {r.case_id or '-'}   {tail}"

    choice = st.selectbox(label, ids, index=index, format_func=fmt)
    _remember_run(choice)
    return choice


def run_page(db: str) -> None:
    with _open(db) as conn:
        since, until = window_bounds(conn)
        header("Run", "Step timings, inputs and outputs of one run.")
        rid = pick_run(conn, "Run", False, since, until)
        if rid is None:
            st.info("No runs in this window.")
            return
        detail = data.run_detail(conn, rid)
        passing, _ = data.nearest_passing(conn, rid) if detail.run.status == "failed" else (None, "")
    run = detail.run
    a, b, c, d = st.columns([2, 2, 1, 1], gap="large")
    a.caption("Run id")
    a.text(run.trace_id)
    b.caption("Case")
    b.text(run.case_id or "none")
    c.caption("Duration")
    c.text(data.fmt_dur(run.duration_ns))
    d.caption("Status")
    with d:
        _status_line(run)
    st.caption("Started " + data.fmt_ts(run.start_ns) + " UTC")
    st.caption("Pipeline")
    st.text(run.name)
    st.caption("Tags")
    st.text(_tags_text(run.tags))
    if run.culprit_kind:
        with st.container(key="culprit"):
            st.caption("Culprit step")
            st.text(f"{run.culprit_step} / {run.culprit_kind}")
            st.text(run.message or "")
        if passing and st.button("Compare with passing run") and "diff" in PAGES:
            st.switch_page(PAGES["diff"])
    st.subheader("Waterfall")
    st.vega_lite_chart(waterfall_spec(detail, palette()), theme=None)
    st.subheader("Steps")
    for s in detail.spans:
        if s.is_root:
            continue
        title = f"{esc(s.name)}  ·  {data.fmt_dur(s.duration_ns)}" + ("  ·  culprit" if s.is_culprit else "")
        with st.expander(title, expanded=s.is_culprit):
            if s.error:
                show_value("Error", s.error)
            if s.marked:
                show_value("Marked failure", s.marked)
            left, right = st.columns(2, gap="large")
            with left:
                show_value("Input", s.input)
            with right:
                show_value("Output", s.output)


# -- clusters ----------------------------------------------------------------------------
def clusters_page(db: str) -> None:
    header("Clusters", "Failures with the same step, kind and normalised message.")
    with _open(db) as conn:
        since, until = window_bounds(conn)
        rows = data.clusters(conn, since, until)
        if not rows:
            st.info("No failures in this window.")
            return
        frame = pd.DataFrame({
            "Step": [c.step for c in rows], "Kind": [c.kind for c in rows],
            "Signature": [c.message for c in rows], "Failures": [c.count for c in rows],
            "Share of runs": [f"{c.share * 100:.1f}%" for c in rows],
            "First seen (UTC)": [data.fmt_ts(c.first_seen_ns) for c in rows],
            "Last seen (UTC)": [data.fmt_ts(c.last_seen_ns) for c in rows],
            "Example runs": [", ".join(e[:12] for e in c.examples) for c in rows],
        })
        ev = st.dataframe(frame, hide_index=True, on_select="rerun", selection_mode="single-row",
                          key="clusters_table",
                          column_config={"Signature": st.column_config.TextColumn(width="large"),
                                         "Example runs": st.column_config.TextColumn(width="large")})
        st.caption("Select a cluster to list its runs.")
        picked = ev.selection.rows if ev and ev.selection else []
        if not picked:
            return
        c = rows[picked[0]]
        st.subheader("Runs in this cluster")
        st.text(f"{c.step} / {c.kind}")
        st.text(c.message)
        runs = data.query_runs(conn, data.RunFilter(signature=c.signature, since_ns=since, until_ns=until))
    runs_table(runs, key="cluster_runs")


# -- diff --------------------------------------------------------------------------------
VERDICT_TEXT = {"same": "Same", "output differs": "Output differs", "status differs": "Status differs",
                "only in failing": "Only in the failing run", "only in passing": "Only in the passing run"}


def _pair_title(p: data.StepPair) -> str:
    return f"{p.name} #{p.occurrence}" if p.occurrence > 1 else p.name


def _side(label: str, span: data.SpanRow | None, part: str | None = None) -> None:
    if span is None:
        st.caption(label)
        st.text("not run")
        return
    show_value(f"{label}  ·  {data.fmt_dur(span.duration_ns)}", span.output)
    if part is not None:
        st.caption("Where it parts from the other run")
        st.code(part, language=None, wrap_lines=True)
    if span.error:
        show_value("Error", span.error)
    if span.marked:
        show_value("Marked failure", span.marked)


def diff_page(db: str) -> None:
    header("Diff", "A failing run next to the nearest passing run of the same case.")
    with _open(db) as conn:
        since, until = window_bounds(conn)
        rid = pick_run(conn, "Failing run to inspect", True, since, until)
        if rid is None:
            st.info("No failing runs in this window.")
            return
        failing = data.run_detail(conn, rid)
        other, basis = data.nearest_passing(conn, rid)
        if other is None:
            st.info("No passing run of this case or pipeline to compare with.")
            return
        passing = data.run_detail(conn, other.trace_id)
    pairs = data.diff_runs(failing, passing)
    a, b = st.columns(2, gap="large")
    for col, label, d in ((a, "Failing", failing), (b, "Passing", passing)):
        with col:
            st.caption(f"{label} run")
            st.text(f"{d.run.trace_id[:12]}  {d.run.case_id or ''}")
            st.caption(f"Started {data.fmt_ts(d.run.start_ns)} UTC")
            st.text("Tags: " + _tags_text(d.run.tags))
    st.caption(f"Matched on: {basis}. Steps are paired by name and by how many times that step has run.")
    first = next((p for p in pairs if p.first_divergence), None)
    same_before = [p for p in pairs if p is not first and p.verdict == "same"
                   and (first is None or pairs.index(p) < pairs.index(first))]
    if first is None:
        st.info("Every step matches. The runs differ only in timing or in where the failure was flagged.")
    if same_before:
        with st.expander(f"{_plural(len(same_before), 'identical step')} before the first difference"):
            for p in same_before:
                st.text(f"{_pair_title(p)}  {data.fmt_dur(p.failing.duration_ns)} vs {data.fmt_dur(p.passing.duration_ns)}")
    if first is not None:
        st.subheader("First difference")
        with st.container(key="diverge"):
            st.caption(VERDICT_TEXT[first.verdict])
            st.text(_pair_title(first))
            if first.input_differs:
                st.caption("The step's input differs too.")
        change = data.first_change(first.failing.output if first.failing else None,
                                   first.passing.output if first.passing else None)
        left, right = st.columns(2, gap="large")
        with left:
            _side("Failing output", first.failing, change[0] if change else None)
        with right:
            _side("Passing output", first.passing, change[1] if change else None)
    rest = [p for p in pairs if p is not first and p not in same_before]
    if rest:
        st.subheader("Other steps")
        for p in rest:
            with st.expander(f"{esc(_pair_title(p))}  ·  {VERDICT_TEXT[p.verdict].lower()}"):
                left, right = st.columns(2, gap="large")
                with left:
                    _side("Failing output", p.failing)
                with right:
                    _side("Passing output", p.passing)
