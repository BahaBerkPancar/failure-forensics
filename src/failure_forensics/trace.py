"""Tracing API: `run`, `step`, `mark_failure` on top of OpenTelemetry."""

from __future__ import annotations

import contextvars
import functools
import hashlib
import inspect
import json
import threading
import traceback
import warnings
from dataclasses import dataclass, field
from typing import Any

from opentelemetry.context import Context
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import Status, StatusCode, Tracer

from .classify import Rule
from .redact import Redactor, truncate
from .store import SQLiteSpanExporter, Store, resolve_db_path

_UNSET: Any = object()


@dataclass
class _State:
    store: Store
    provider: TracerProvider
    tracer: Tracer
    redactor: Redactor
    max_len: int
    rules: list[Rule] = field(default_factory=list)


_state: _State | None = None
_lock = threading.Lock()
_current_run: contextvars.ContextVar[Any] = contextvars.ContextVar("ff_run", default=None)
_current_handle: contextvars.ContextVar[Any] = contextvars.ContextVar("ff_handle", default=None)


def configure(
    db_path: str | None = None,
    *,
    max_len: int = 500,
    redactor: Redactor | None = None,
    rules: list[Rule] | None = None,
) -> Store:
    """(Re)configure tracing. Called lazily with defaults on first use (`FF_DB` or ./.ff/traces.db)."""
    global _state
    with _lock:
        if _state is not None:
            _state.provider.shutdown()
        store = Store(resolve_db_path(db_path))
        provider = TracerProvider(resource=Resource.create({"service.name": "failure-forensics"}))
        provider.add_span_processor(
            BatchSpanProcessor(
                SQLiteSpanExporter(store),
                schedule_delay_millis=60_000,
                max_queue_size=65_536,  # a queue overflow would silently drop spans
            )
        )
        _state = _State(store, provider, provider.get_tracer("failure_forensics"),
                        redactor or Redactor(), max_len, list(rules or []))
        return store


def _get() -> _State:
    if _state is None:
        configure()
    assert _state is not None
    return _state


def get_store() -> Store:
    return _get().store


class _Handle:
    """Shared behaviour of a run and a step: record data, mark failures, capture errors."""

    span: Any = None
    name: str = ""

    def record(self, input: Any = _UNSET, output: Any = _UNSET) -> None:
        if self.span is None:
            return
        st = _get()
        if input is not _UNSET:
            self.span.set_attribute("ff.input", st.redactor.json_text(input, st.max_len))
        if output is not _UNSET:
            self.span.set_attribute("ff.output", st.redactor.json_text(output, st.max_len))

    def set(self, **attrs: Any) -> None:
        if self.span is not None:
            _set_attrs(self.span, attrs)

    def mark_failure(self, kind: str, detail: str = "") -> None:
        if self.span is None or self.span.attributes.get("ff.failure.kind"):
            return  # first mark wins
        st = _get()
        self.span.set_attribute("ff.failure.kind", kind)
        self.span.set_attribute("ff.failure.detail", truncate(st.redactor.text(detail), st.max_len))
        self.span.set_status(Status(StatusCode.ERROR, kind))

    def _capture_error(self, exc: BaseException) -> None:
        st = _get()
        frames = traceback.extract_tb(exc.__traceback__)
        tb = "|".join(f"{f.filename.rsplit('/', 1)[-1]}:{f.name}" for f in frames)
        a = self.span.set_attribute
        a("ff.error.type", type(exc).__name__)
        a("ff.error.message", truncate(st.redactor.text(str(exc)), st.max_len))
        a("ff.error.tb_hash", hashlib.sha1(tb.encode()).hexdigest()[:8])
        a("ff.error.timeout", isinstance(exc, TimeoutError))
        self.span.set_status(Status(StatusCode.ERROR, type(exc).__name__))


def _set_attrs(span: Any, attrs: dict[str, Any]) -> None:
    st = _get()
    for key, value in attrs.items():
        if st.redactor.is_sensitive_key(key):
            value = "[REDACTED]"
        elif isinstance(value, str):
            value = truncate(st.redactor.text(value), st.max_len)
        elif not isinstance(value, (bool, int, float)):
            value = st.redactor.json_text(value, st.max_len)
        span.set_attribute(f"ff.attr.{key}", value)


class run(_Handle):
    """One pipeline run = the root span. Use as a context manager; runs cannot be nested.

    The root span always starts a new trace, even when the host has an active OpenTelemetry span.
    Setup problems (for example an unwritable database) become a warning and the run is simply
    not traced; the pipeline itself is never affected.
    """

    def __init__(self, name: str, case_id: str | None = None, tags: dict[str, Any] | None = None):
        self.name = name
        self.case_id = case_id
        self.tags = dict(tags or {})
        self.trace_id = ""
        self._active = False

    def __enter__(self):
        if _current_run.get() is not None:
            raise RuntimeError("ff.run cannot be nested; use ff.step for sub-steps")
        try:
            st = _get()
            red = st.redactor
            self.name = truncate(red.text(str(self.name)), st.max_len)
            tags = {
                red.text(str(k)): (
                    "[REDACTED]" if red.is_sensitive_key(k)
                    else red.text(v) if isinstance(v, str)
                    else red.json_text(v, st.max_len)
                )
                for k, v in self.tags.items()
            }
            attrs: dict[str, Any] = {"ff.kind": "run", "ff.tags": json.dumps(tags, ensure_ascii=False)}
            if self.case_id is not None:
                attrs["ff.case_id"] = truncate(red.text(str(self.case_id)), st.max_len)
            self._cm = st.tracer.start_as_current_span(
                self.name, context=Context(), attributes=attrs, record_exception=False,
                set_status_on_exception=False,
            )
            self.span = self._cm.__enter__()
        except Exception as e:  # noqa: BLE001 - tracing must never break the pipeline
            warnings.warn(f"failure-forensics tracing disabled for this run: {e}", stacklevel=2)
            self.span = None
            return self
        self._active = True
        self.trace_id = format(self.span.get_span_context().trace_id, "032x")
        self._tokens = (_current_run.set(self), _current_handle.set(self))
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if not self._active:
            return False
        self._active = False
        if exc is not None:
            self._capture_error(exc)
        _current_handle.reset(self._tokens[1])
        _current_run.reset(self._tokens[0])
        self._cm.__exit__(None, None, None)
        st = _get()
        try:
            if not st.provider.force_flush():
                warnings.warn(f"failure-forensics: flush timed out for run {self.trace_id}", stacklevel=2)
            st.store.finalize_run(self.trace_id, st.rules)
        except Exception as e:  # noqa: BLE001 - tracing must never break the pipeline
            warnings.warn(f"failure-forensics could not store run {self.trace_id}: {e}", stacklevel=2)
        return False


class step(_Handle):
    """A pipeline step: decorator (sync or async) or context manager. No-op outside `ff.run`.

    `expect_output=True` makes an empty recorded output ("", [], {}, None) an `empty_output` failure.
    """

    def __init__(self, name: str, *, expect_output: bool = False, **attrs: Any):
        self.name = name
        self.expect_output = expect_output
        self.attrs = attrs

    def __call__(self, fn):
        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def awrapper(*args, **kwargs):
                with step(self.name, expect_output=self.expect_output, **self.attrs):
                    return await fn(*args, **kwargs)

            return awrapper

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            with step(self.name, expect_output=self.expect_output, **self.attrs):
                return fn(*args, **kwargs)

        return wrapper

    def __enter__(self):
        self.span = None
        if _current_run.get() is None:
            return self
        st = _get()
        self._cm = st.tracer.start_as_current_span(
            self.name, attributes={"ff.kind": "step"}, record_exception=False,
            set_status_on_exception=False,
        )
        self.span = self._cm.__enter__()
        if self.expect_output:
            self.span.set_attribute("ff.expect_output", True)
        _set_attrs(self.span, self.attrs)
        self._token = _current_handle.set(self)
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if self.span is None:
            return False
        if exc is not None:
            self._capture_error(exc)
        _current_handle.reset(self._token)
        self._cm.__exit__(None, None, None)
        return False


def mark_failure(kind: str, detail: str = "") -> None:
    """Flag a semantic failure (e.g. "blocked", "wrong_result") on the current step."""
    handle = _current_handle.get()
    if handle is not None:
        handle.mark_failure(kind, detail)
