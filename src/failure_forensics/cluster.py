"""Group failures by signature (step + kind + normalised message)."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from .classify import normalise_message
from .store import Store


@dataclass
class Cluster:
    signature: str
    step: str
    kind: str
    message: str
    count: int
    share: float  # fraction of all runs
    first_seen_ns: int
    last_seen_ns: int
    examples: list[str] = field(default_factory=list)
    by_tag: dict[str, int] = field(default_factory=dict)


def cluster_failures(store: Store, by_tag: str | None = None, examples: int = 3) -> list[Cluster]:
    total = store.count_runs()
    groups: dict[str, Cluster] = {}
    tag_counts: dict[str, Counter[str]] = {}
    for f in store.failures_with_runs():
        sig = f["signature"]
        c = groups.get(sig)
        if c is None:
            c = groups[sig] = Cluster(sig, f["step"], f["kind"], normalise_message(f["message"]), 0, 0.0,
                                      f["start_ns"], f["start_ns"])
            tag_counts[sig] = Counter()
        c.count += 1
        c.first_seen_ns = min(c.first_seen_ns, f["start_ns"])
        c.last_seen_ns = max(c.last_seen_ns, f["start_ns"])
        if len(c.examples) < examples:
            c.examples.append(f["trace_id"])
        if by_tag:
            tag_counts[sig][str(f["tags"].get(by_tag, "-"))] += 1
    for sig, c in groups.items():
        c.share = c.count / total if total else 0.0
        c.by_tag = dict(sorted(tag_counts[sig].items()))
    return sorted(groups.values(), key=lambda c: (-c.count, c.signature))
