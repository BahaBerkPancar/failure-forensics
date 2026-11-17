"""`ff` command line: runs, show, failures, clusters, gc, t2s run. Exit 0 ok, 3 on usage/db errors."""

from __future__ import annotations

import argparse
import json
import math
import re
import sqlite3
import sys
import time
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from typing import Any

from . import __version__
from .cluster import cluster_failures
from .redact import truncate
from .store import Store, resolve_db_path

EXIT_ERROR = 3


class _Parser(argparse.ArgumentParser):
    def error(self, message: str):  # usage errors exit 3, not argparse's 2
        self.print_usage(sys.stderr)
        self.exit(EXIT_ERROR, f"{self.prog}: error: {message}\n")


class _CliError(Exception):
    pass


def _positive_int(value: str) -> int:
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{value}' is not an integer") from None
    if n <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return n


def _days(value: str) -> float:
    try:
        d = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{value}' is not a number") from None
    if not math.isfinite(d) or d < 0:
        raise argparse.ArgumentTypeError("must be a finite number >= 0")
    return d


def _fmt_ts(ns: int) -> str:
    return datetime.fromtimestamp(ns / 1e9, tz=UTC).strftime("%Y-%m-%d %H:%M:%S")


def _fmt_dur(ns: int) -> str:
    ms = ns / 1e6
    return f"{ms / 1000:.2f}s" if ms >= 1000 else f"{ms:.1f}ms"


def _short(trace_id: str) -> str:
    return trace_id[:12]


def _parse_since(value: str) -> int:
    m = re.fullmatch(r"(\d+)([smhdw])", value.strip())
    if m:
        unit = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}[m.group(2)]
        delta = timedelta(**{unit: int(m.group(1))})
        return time.time_ns() - int(delta.total_seconds() * 1e9)
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        raise _CliError(f"bad --since '{value}' (use 30m, 24h, 7d or an ISO date)") from None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return int(dt.timestamp() * 1e9)


def _table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h) for i, h in enumerate(headers)]
    lines = ["  ".join(h.ljust(w) for h, w in zip(headers, widths, strict=True)).rstrip()]
    for r in rows:
        lines.append("  ".join(c.ljust(w) for c, w in zip(r, widths, strict=True)).rstrip())
    return "\n".join(lines)


def _open(args: argparse.Namespace) -> Store:
    path = resolve_db_path(args.db)
    if not path.exists():
        raise _CliError(f"no database at {path} (run a pipeline first, or pass --db / set FF_DB)")
    try:
        return Store(path)
    except Exception as e:
        raise _CliError(f"cannot open database {path}: {e}") from e


def _emit(args: argparse.Namespace, data: Any, text: str) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False) if args.json else text)


def cmd_runs(args: argparse.Namespace) -> None:
    since = _parse_since(args.since) if args.since else None
    runs = _open(args).list_runs(failed=args.failed, since_ns=since)
    rows = [
        [_short(r["trace_id"]), r["status"], _fmt_ts(r["start_ns"]), _fmt_dur(r["end_ns"] - r["start_ns"]),
         r["name"], r["case_id"] or "-",
         f"{r['fail_step']}:{r['fail_kind']}" if r["fail_kind"] else "-"]
        for r in runs
    ]
    text = _table(["RUN", "STATUS", "STARTED (UTC)", "DURATION", "NAME", "CASE", "CULPRIT"], rows)
    data = [{k: v for k, v in r.items() if k != "fail_message"} | {"message": r["fail_message"]} for r in runs]
    _emit(args, data, text + f"\n{len(runs)} run(s)")


def cmd_show(args: argparse.Namespace) -> None:
    store = _open(args)
    try:
        run = store.get_run(args.run_id)
    except LookupError as e:
        raise _CliError(str(e)) from None
    spans = store.get_spans(run["trace_id"])
    culprit = run.get("fail_span")
    children: dict[str | None, list] = {}
    for s in spans:
        children.setdefault(s.parent_id, []).append(s)
    lines = [
        (
            f"run {run['trace_id']}  {run['name']}  case={run['case_id'] or '-'}  "
            f"{run['status'].upper()}  {_fmt_dur(run['end_ns'] - run['start_ns'])}"
        ),
        f"started {_fmt_ts(run['start_ns'])} UTC  tags={json.dumps(run['tags'], sort_keys=True)}",
        "",
    ]

    def walk(parent: str | None, depth: int) -> None:
        for s in children.get(parent, []):
            mark = ">>" if s.span_id == culprit else "  "
            state = "FAIL" if s.status == "error" else "ok"
            label = f"{'  ' * depth}{s.name}"
            tail = "   <-- culprit" if s.span_id == culprit else ""
            lines.append(f"{mark} [{state:<4}] {label:<34} {_fmt_dur(s.duration_ns):>9}{tail}")
            pad = " " * 13 + "  " * depth
            a = s.attributes
            for key, label_ in (("ff.input", "in"), ("ff.output", "out")):
                if key in a:
                    lines.append(f"{pad}{label_}:  {truncate(str(a[key]), 70)}")
            if a.get("ff.failure.kind"):
                lines.append(f"{pad}marked {a['ff.failure.kind']}: {a.get('ff.failure.detail', '')}")
            if a.get("ff.error.type"):
                lines.append(f"{pad}error: {a['ff.error.type']}: {a.get('ff.error.message', '')} "
                             f"[tb {a.get('ff.error.tb_hash', '-')}]")
            walk(s.span_id, depth + 1)

    walk(None, 0)
    if run["fail_kind"]:
        lines += ["", f"culprit: {run['fail_step']} ({run['fail_kind']}): {run['fail_message']}"]
    data = {"run": run, "spans": [asdict(s) for s in spans]}
    _emit(args, data, "\n".join(lines))


def cmd_failures(args: argparse.Namespace) -> None:
    fails = _open(args).failures_with_runs()
    rows = [[_short(f["trace_id"]), f["step"], f["kind"], truncate(f["message"], 70)] for f in fails]
    text = _table(["RUN", "STEP", "KIND", "MESSAGE"], rows) + f"\n{len(fails)} failure(s)"
    _emit(args, [{k: f[k] for k in ("trace_id", "step", "kind", "message", "signature", "case_id")}
                 for f in fails], text)


def cmd_clusters(args: argparse.Namespace) -> None:
    clusters = cluster_failures(_open(args), by_tag=args.by_tag)
    if args.top:
        clusters = clusters[: args.top]
    rows = [
        [str(c.count), f"{c.share * 100:.1f}%", c.step, c.kind, truncate(c.message, 60),
         _fmt_ts(c.first_seen_ns), _fmt_ts(c.last_seen_ns), ",".join(_short(e) for e in c.examples)]
        for c in clusters
    ]
    headers = ["COUNT", "SHARE", "STEP", "KIND", "MESSAGE", "FIRST SEEN", "LAST SEEN", "EXAMPLES"]
    lines = [_table(headers, rows)]
    if args.by_tag:
        for c in clusters:
            lines.append(f"  {c.step}/{c.kind} by {args.by_tag}: "
                         + ", ".join(f"{k}={v}" for k, v in c.by_tag.items()))
    _emit(args, [asdict(c) for c in clusters], "\n".join(lines))


def cmd_gc(args: argparse.Namespace) -> None:
    cutoff = time.time_ns() - int(args.keep_days * 86400 * 1e9)
    runs, orphans = _open(args).gc(cutoff)
    text = f"deleted {runs} run(s) older than {args.keep_days:g} day(s)"
    if orphans:
        text += f" and {orphans} orphan span(s)"
    _emit(args, {"deleted_runs": runs, "deleted_orphan_spans": orphans}, text)


def cmd_t2s_run(args: argparse.Namespace) -> None:
    try:
        from .integrations import t2s
    except ImportError as e:
        raise _CliError(str(e)) from None
    try:
        summary = t2s.run_suite(args.generator, args.db, timeout_ms=args.timeout_ms, setup=not args.no_setup,
                                log=lambda m: print(m, file=sys.stderr))
    except (RuntimeError, ValueError, OSError) as e:
        raise _CliError(str(e)) from None
    lines = [f"{summary['runs']} run(s) with generator {summary['generator']}"]
    lines += [f"  {k}: {v}" for k, v in summary["outcomes"].items()]
    _emit(args, summary, "\n".join(lines))


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="ff", description="Find where an AI pipeline run went wrong.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--db", help="SQLite file (default: $FF_DB or ./.ff/traces.db)")
    common.add_argument("--json", action="store_true", help="machine-readable output")
    sub = parser.add_subparsers(dest="command", parser_class=_Parser)

    p = sub.add_parser("runs", parents=[common], help="list runs")
    p.add_argument("--failed", action="store_true", help="only failed runs")
    p.add_argument("--since", help="30m, 24h, 7d or an ISO date")
    p.set_defaults(fn=cmd_runs)

    p = sub.add_parser("show", parents=[common], help="waterfall of one run")
    p.add_argument("run_id", help="run id or unique prefix")
    p.set_defaults(fn=cmd_show)

    p = sub.add_parser("failures", parents=[common], help="the culprit step of every failed run")
    p.set_defaults(fn=cmd_failures)

    p = sub.add_parser("clusters", parents=[common], help="failures grouped by signature")
    p.add_argument("--top", type=_positive_int, help="only the N biggest clusters")
    p.add_argument("--by-tag", help="second-level grouping by this run tag")
    p.set_defaults(fn=cmd_clusters)

    p = sub.add_parser("gc", parents=[common], help="delete old runs")
    p.add_argument("--keep-days", type=_days, required=True, help="keep runs newer than this")
    p.set_defaults(fn=cmd_gc)

    p = sub.add_parser("t2s", help="trace text-to-sql-guardrails (needs the t2s extra)")
    t2s_sub = p.add_subparsers(dest="t2s_command", parser_class=_Parser)
    r = t2s_sub.add_parser("run", parents=[common], help="run all questions and attack prompts")
    r.add_argument("--generator", required=True, help="gold, mutated:<name>[+<name>] or recorded:<path.jsonl>")
    r.add_argument("--timeout-ms", type=_positive_int, default=1000, help="statement timeout (default 1000)")
    r.add_argument("--no-setup", action="store_true", help="reuse the schema from an earlier run")
    r.set_defaults(fn=cmd_t2s_run)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "fn", None):
        parser.print_help()
        return 0
    try:
        args.fn(args)
    except _CliError as e:
        print(f"ff: {e}", file=sys.stderr)
        return EXIT_ERROR
    except (sqlite3.Error, OSError, RuntimeError) as e:
        print(f"ff: database error: {e}", file=sys.stderr)
        return EXIT_ERROR
    return 0
