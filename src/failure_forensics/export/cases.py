"""Collect one test case per distinct failing input of a cluster.

Everything here comes from the store, so inputs and outputs are the values that were already
redacted and truncated when they were recorded; nothing is re-read from the pipeline.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

from ..models import SpanRecord
from ..store import Store

_REDACTED = re.compile(r"\[REDACTED[:\]]")
_TRUNCATED = re.compile(r"\.\.\.\[\+\d+ chars\]")


class ClusterError(Exception):
    """The cluster spec matches nothing, matches several clusters, or has no usable inputs."""


@dataclass
class ExportCase:
    id: str
    input: Any
    step: str
    kind: str
    signature: str
    error_type: str | None = None  # exception class name recorded at the culprit step
    expected: Any = None
    has_expected: bool = False
    tags: list[str] = field(default_factory=list)  # original run tags as "key:value"
    run_ids: list[str] = field(default_factory=list)
    redacted: bool = False  # the stored input contains redaction markers
    truncated: bool = False  # the stored input was cut at the store's max length


def slugify(text: str, limit: int = 40) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")[:limit].strip("_")
    return slug or "cluster"


def case_id(value: Any) -> str:
    """Stable id: hash of the canonical JSON of the input."""
    canon = json.dumps(value, sort_keys=True, ensure_ascii=True, default=str)
    return "ff-" + hashlib.sha256(canon.encode()).hexdigest()[:12]


def resolve_cluster(store: Store, spec: str) -> str:
    """Return the full signature for an exact signature or a unique prefix."""
    sigs = sorted({f["signature"] for f in store.failures_with_runs()})
    if spec in sigs:
        return spec
    hits = [s for s in sigs if s.startswith(spec)]
    if not spec.strip() or not hits:
        raise ClusterError(f"no cluster matches '{spec}' (see `ff clusters`)")
    if len(hits) > 1:
        listing = "; ".join(hits[:5])
        raise ClusterError(f"cluster prefix '{spec}' is ambiguous ({len(hits)} matches: {listing})")
    return hits[0]


def _root(spans: list[SpanRecord]) -> SpanRecord | None:
    return next((s for s in spans if s.attributes.get("ff.kind") == "run"), None)


def case_input_text(spans: list[SpanRecord]) -> str | None:
    """The run's input: the root's recorded input, else the first step (by start) that has one."""
    root = _root(spans)
    if root is not None and "ff.input" in root.attributes:
        return str(root.attributes["ff.input"])
    for s in sorted(spans, key=lambda s: (s.start_ns, -s.end_ns)):
        if s is not root and "ff.input" in s.attributes:
            return str(s.attributes["ff.input"])
    return None


def final_output_text(spans: list[SpanRecord]) -> str | None:
    """The run's output: the root's recorded output, else that of the last step to finish."""
    root = _root(spans)
    if root is not None and "ff.output" in root.attributes:
        return str(root.attributes["ff.output"])
    outs = [s for s in spans if s is not root and "ff.output" in s.attributes]
    if not outs:
        return None
    return str(max(outs, key=lambda s: (s.end_ns, s.start_ns)).attributes["ff.output"])


def parse_value(text: str) -> Any:
    """Stored values are JSON text; a truncated one is no longer valid JSON and stays a string."""
    try:
        return json.loads(text, parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))
    except ValueError:
        return text


def _nearest_passing(ok_runs: list[dict[str, Any]], failing: dict[str, Any]) -> dict[str, Any] | None:
    cands = [r for r in ok_runs if r["case_id"] == failing["case_id"]]
    if not cands or failing["case_id"] is None:
        return None
    return min(cands, key=lambda r: (abs(r["start_ns"] - failing["start_ns"]), r["start_ns"]))


def collect_cases(store: Store, signature: str, limit: int | None = None) -> tuple[list[ExportCase], int]:
    """Distinct failing inputs of a cluster, oldest first. Returns (cases, runs skipped for lack of an input)."""
    ok_runs = [r for r in store.list_runs() if r["status"] == "ok"]
    cases: dict[str, ExportCase] = {}
    skipped = 0
    for f in store.failures_with_runs():
        if f["signature"] != signature:
            continue
        spans = store.get_spans(f["trace_id"])
        raw = case_input_text(spans)
        if raw is None:
            skipped += 1
            continue
        value = parse_value(raw)
        cid = case_id(value)
        tags = sorted(f"{k}:{v}" for k, v in f["tags"].items())
        if cid in cases:
            c = cases[cid]
            c.run_ids.append(f["trace_id"])
            c.tags = sorted(set(c.tags) | set(tags))
            continue
        if limit is not None and len(cases) >= limit:
            continue
        culprit = next((s for s in spans if s.span_id == f["span_id"]), None)
        case = ExportCase(
            id=cid, input=value, step=f["step"], kind=f["kind"], signature=signature,
            error_type=(culprit.attributes.get("ff.error.type") if culprit else None) or None,
            tags=tags, run_ids=[f["trace_id"]],
            redacted=bool(_REDACTED.search(raw)), truncated=bool(_TRUNCATED.search(raw)),
        )
        passing = _nearest_passing(ok_runs, f)
        if passing is not None:
            out = final_output_text(store.get_spans(passing["trace_id"]))
            if out is not None:
                case.expected, case.has_expected = parse_value(out), True
        cases[cid] = case
    if not cases:
        raise ClusterError(
            f"cluster '{signature}' has no failing run with a recorded input "
            "(record one with `run.record(input=...)` or `step.record(input=...)`)"
        )
    return list(cases.values()), skipped
