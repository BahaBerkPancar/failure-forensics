"""Plain data records shared by the store, classifier and CLI."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SpanRecord:
    trace_id: str
    span_id: str
    parent_id: str | None
    name: str
    start_ns: int
    end_ns: int
    status: str = "ok"  # "ok" or "error"
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def duration_ns(self) -> int:
        return max(0, self.end_ns - self.start_ns)
