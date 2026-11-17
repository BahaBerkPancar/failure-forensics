# Decisions

Newest first. One entry per decision: date, what was decided, why, and what was rejected.

## 2026-11-17 - Review fixes: handled errors, hex ids, KeyError keys, root context
- **Handled errors do not fail a run** (supersedes the "earliest end wins" rule below). A run fails if its root raised or a step was marked failed (`mark_failure`, empty `expect_output`, custom rule). When the root raised, the culprit is the deepest errored step on the chain from the root, following the child that raised the same error (else the latest-ending errored child); a marked failure that ended earlier wins. A caught-and-retried exception can therefore never become the culprit. Rejected: "earliest failing span" (blamed retries that succeeded).
- **Redaction**: key-name matching now works inside text, so `'password': 'x'`, JSON strings, dict reprs in exception messages and `Authorization: Basic x` are masked (the credential, not just the scheme). Plain 32/40-char hex values (trace ids, md5, git SHAs) are kept because masking them made traces unreadable; only 48+ char hex is masked on its own, and any length next to a secret key name. Risk accepted: a bare 32-hex API key in free text is not caught.
- **KeyError keys stay in the signature** (`KeyError: 'sku-404'`), because different missing keys are different bugs. Keys that look like ids (6+ digits, 8+ hex chars, longer than 40) are still normalised so clusters do not explode.
- **Each `ff.run` is a new trace** (started from an empty OTel context) so a host's active span never becomes its parent, and two runs in one request stay separate. The root is found by `ff.kind == "run"`.
- **Span queue**: kept the BatchSpanProcessor but raised the queue to 65 536 spans; a run flushes at its end. Rejected SimpleSpanProcessor (a SQLite write per span on the pipeline thread).
- **Migrations** run in one `BEGIN IMMEDIATE` transaction with idempotent DDL, so concurrent openers are safe. Export failures, flush timeouts and runs with no stored spans produce warnings.

## 2026-11-17 - Signature = step + kind + normalised message
The cluster key is `step | kind | message` with quoted literals, UUIDs, paths, hex ids and numbers replaced by placeholders (in that order, so a number inside a path or a quoted string is swallowed first). Same bug with different ids or timings lands in one cluster; different steps or kinds never merge. Rejected: clustering by exception type only (hides different causes) and embedding/LLM similarity (not offline, not deterministic).

## 2026-11-17 - The first failing step is the culprit
A failure propagates up: when `tool` raises, its parent step and the run span also end in error. The culprit is the failing span with the earliest end time, which is the innermost step where it started. Marked (non-exception) failures count the same way. Only the culprit is stored in `failures`; the other spans keep their status. Rejected: storing every failing span (one bug would count several times in cluster sizes).

## 2026-11-17 - OpenTelemetry API with our own SQLite exporter, no collector
Real pipelines can already emit OTel spans, and the SDK gives context propagation (sync, async, threads) for free. A collector or Jaeger would need Docker and a network port for a tool whose point is a local, offline forensics file. So: a private `TracerProvider` (the global one is left alone), a `BatchSpanProcessor` plus our `SpanExporter` writing SQLite in WAL mode, and `force_flush` at the end of each run so a run is complete and classified when `ff.run` exits. Each write opens its own short connection, which keeps the exporter thread safe. Classification runs at run end and is stored, so the CLI never re-classifies.

## 2026-11-17 - empty_output is opt-in per step
An empty list is often a correct answer, so treating every empty output as a failure would create false clusters. `ff.step(name, expect_output=True)` marks the steps where empty means broken.

## 2026-11-17 - Tracing never breaks the pipeline
Exporter and finalize errors become a warning instead of an exception; `ff.step` outside a run is a no-op. Exceptions from the pipeline itself always propagate unchanged.

## 2026-11-17 - Project created from the `python-app` template
Why: same layout, test setup and CI as the other projects, so nothing has to be set up by hand.
