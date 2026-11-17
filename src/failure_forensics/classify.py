"""Failure classification: which step broke first, and how."""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from .models import SpanRecord

BUILTIN_KINDS = {"exception", "timeout", "refusal", "blocked", "wrong_result", "empty_output", "unsafe"}


@dataclass
class Failure:
    span_id: str
    step: str
    kind: str
    message: str = ""
    end_ns: int = 0
    trace_id: str = ""

    @property
    def signature(self) -> str:
        return signature(self.step, self.kind, self.message)


# A rule receives all spans of one run and returns a Failure, or None.
Rule = Callable[[Sequence[SpanRecord]], "Failure | None"]


def kind_from_mark(kind: str) -> str:
    k = kind.strip().lower() or "unknown"
    return k if k in BUILTIN_KINDS else f"marked:{k}"


def _errored(span: SpanRecord) -> bool:
    a = span.attributes
    return bool(a.get("ff.error.type")) or (span.status == "error" and not a.get("ff.failure.kind"))


def _error_failure(span: SpanRecord) -> Failure:
    a = span.attributes
    etype = str(a.get("ff.error.type", "Error"))
    is_timeout = bool(a.get("ff.error.timeout")) or "timeout" in etype.lower()
    msg = f"{etype}: {a.get('ff.error.message', '')}".rstrip(": ")
    return Failure(span.span_id, span.name, "timeout" if is_timeout else "exception", msg,
                   span.end_ns, span.trace_id)


def semantic_failure(span: SpanRecord) -> Failure | None:
    """A failure the pipeline flagged itself (`mark_failure`) or an expected-but-empty output."""
    a = span.attributes
    if a.get("ff.failure.kind"):
        return Failure(span.span_id, span.name, kind_from_mark(str(a["ff.failure.kind"])),
                       str(a.get("ff.failure.detail", "")), span.end_ns, span.trace_id)
    if a.get("ff.expect_output") and a.get("ff.output") in ('""', "[]", "{}", "null") and not _errored(span):
        return Failure(span.span_id, span.name, "empty_output", "step produced no output",
                       span.end_ns, span.trace_id)
    return None


def _same_error(a: SpanRecord, b: SpanRecord) -> bool:
    return all(a.attributes.get(k) == b.attributes.get(k) for k in ("ff.error.type", "ff.error.message"))


def _error_culprit(spans: Sequence[SpanRecord], root: SpanRecord) -> Failure:
    """Deepest error on the chain from the failed root.

    At each level, follow the errored child whose error is the same one the parent raised (the
    exception that propagated); otherwise the latest-ending errored child, but only if nothing
    finished after it (a wrapped exception). A node that failed after a handled child error is
    blamed itself. Errors that were caught and handled never sit on that chain.
    """
    children: dict[str | None, list[SpanRecord]] = {}
    for s in spans:
        children.setdefault(s.parent_id, []).append(s)
    node = root
    while True:
        errored = [c for c in children.get(node.span_id, []) if _errored(c)]
        if not errored:
            return _error_failure(node)
        same = [c for c in errored if _same_error(c, node)]
        if same:
            node = max(same, key=lambda c: (c.end_ns, c.span_id))
            continue
        # Different error: the node wrapped a child's exception only if that child was the last
        # thing to finish. Anything that ended after it means the child's error was handled and
        # the node failed on its own.
        latest = max(errored, key=lambda c: (c.end_ns, c.span_id))
        if any(c.end_ns > latest.end_ns for c in children.get(node.span_id, [])):
            return _error_failure(node)
        node = latest


def classify_run(spans: Sequence[SpanRecord], rules: Sequence[Rule] = ()) -> Failure | None:
    """Decide whether a run failed and which step is the culprit.

    A run fails if its root errored, or any step was marked failed (marks, expected-but-empty
    output and custom rules are semantic: they always count). A handled error (the root
    succeeded) never fails a run. Among the candidates the earliest-ending one is the culprit.
    """
    by_id = {s.span_id: s for s in spans}
    root = next((s for s in spans if s.attributes.get("ff.kind") == "run"), None)
    candidates: list[Failure] = [f for s in spans if (f := semantic_failure(s))]
    if root is not None and _errored(root) and not root.attributes.get("ff.failure.kind"):
        candidates.append(_error_culprit(spans, root))
    for rule in rules:
        f = rule(spans)
        if f:
            if not f.end_ns and f.span_id in by_id:
                f.end_ns = by_id[f.span_id].end_ns
            if not f.trace_id and spans:
                f.trace_id = spans[0].trace_id
            candidates.append(f)
    if not candidates:
        return None
    return min(candidates, key=lambda f: (f.end_ns, f.span_id))


_QUOTED = re.compile(r"'[^'\n]*'|\"[^\"\n]*\"")
_UUID = re.compile(r"\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b")
_PATH = re.compile(r"(?<![\w<])(?:[A-Za-z]:)?/(?:[\w.\-~@]+/)*[\w.\-~@]+")
_HEXID = re.compile(r"\b0x[0-9a-fA-F]+\b|\b(?=[0-9a-f]*\d)[0-9a-f]{8,}\b")
_NUM = re.compile(r"(?<![\w.])\d+(?:\.\d+)*")


_STABLE_KEY = re.compile(r"""KeyError: (['"])(?!.*[0-9a-f]{8})([^'"]{1,40})\1""", re.IGNORECASE)


def normalise_message(msg: str, limit: int = 200) -> str:
    # A KeyError's quoted key is the diagnosis (different missing keys are different bugs), so its
    # shape stays ('sku-<n>'), unless it looks like an id (8+ hex chars) or is long.
    m = _STABLE_KEY.fullmatch(msg.strip())
    if m:
        q = m.group(1)
        return f"KeyError: {q}{re.sub(r'\d+', '<n>', m.group(2))}{q}"
    s = _QUOTED.sub("<str>", msg)
    s = _UUID.sub("<uuid>", s)
    s = _PATH.sub("<path>", s)
    s = _HEXID.sub("<hex>", s)
    s = _NUM.sub("<n>", s)
    return re.sub(r"\s+", " ", s).strip()[:limit]


def signature(step: str, kind: str, message: str) -> str:
    return f"{step} | {kind} | {normalise_message(message)}"
