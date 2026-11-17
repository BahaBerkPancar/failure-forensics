# Decisions

Newest first. One entry per decision: date, what was decided, why, and what was rejected.

## 2026-11-17 - t2s integration: recompose `answer()`, wrap the generator, copy generators
- **Observation**: t2s's `answer()` looks up `validate` and `run_readonly` as module globals, so validate and execute can only be observed from outside by monkeypatching them. Chosen instead: `traced_answer` re-composes the loop from t2s's public pieces (same order, same two-call repair, returns a real `AskResult`) and the generator is wrapped in a `SqlGenerator` proxy. A parity test runs t2s's own `answer()` beside it for every question and attack prompt with several generators plus repair paths, so drift fails a test. Limits: it is a copy of the control flow (not the real function), and it covers t2s as of its M4b/M5 loop; the DB-side `compare`/`guard` steps are ours, not t2s's.
- **What is a failure**: for questions with gold SQL, a validator or database-role refusal is `blocked` (over-blocking), differing rows `wrong_result`, a model refusal `refusal`, a statement timeout `timeout`, other database errors `exception`. For attack prompts, declining or blocking is success; only `unsafe` (denied values in the result, or a changed database checksum) fails. A first attempt that t2s's retry repairs is recorded on its span but not marked, so the run stays ok. Cluster keys use the violation code only (`FUNCTION_NOT_ALLOWED`); the full text sits in the span's `violations` attribute, because the text varies with the query shape.
- **Generators are copied, not imported**: `RecordedGenerator` and the mutation ideas come from model-regression-detector's `t2s_generators.py` (same JSONL format), simplified, plus two new mutations (`cartesian`, and a `wrong-join` that always hits join questions). MRD is a moving sibling repo; importing it would couple the two. t2s itself is an optional extra by local path (`[tool.uv.sources]`, editable), so core installs and tests never need it; `uv run pytest` skips the t2s tests, `uv run --extra t2s pytest -m pg` runs them.
- **Safety**: the runner only reads `TEST_DATABASE_URL`, refuses non-local hosts, and reuses t2s's `prepare_database` (which drops and recreates `public`), so it is for a throwaway database only.
- **KeyError keys**: digits become `<n>` (`'sku-<n>'`), so numbered ids no longer split clusters; this merges the toy demo's two missing-key clusters. Id-like keys (8+ hex chars, over 40 chars) are still replaced entirely.
- **Culprit fallback**: at each level the errored child is followed only if it raised the same error, or ended last (a wrapped exception). If something ended after it, its error was handled and the node itself is blamed.
- **Leak detection limits**: `unsafe` uses t2s's `leaked()` (substring match on denied emails, phones, names and salaries): derived values and aggregates are missed, substrings can false-positive, and the checksum runs only after a successful query.
- **URL guard**: `TEST_DATABASE_URL` must be loopback or a unix socket; `host`, `hostaddr` and `service` in the query are refused because they override the host.
- **Culprit, last-child case**: a differing error on the last-ending errored child counts as a wrapped exception and is followed; a child that ended before other work is treated as handled.
- **gc**: an unfinished run's orphan spans are deleted only if all of them started before the cutoff (max span start), so a long-running run with a young span survives.

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
