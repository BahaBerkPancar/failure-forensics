# failure-forensics

Traces every step of an AI pipeline, finds where a run went wrong, and groups similar failures.
Later milestones turn failures into regression test cases (first target: text-to-sql-guardrails).

A pipeline run is one OpenTelemetry trace; every step is a span. Spans land in a local SQLite file
(no collector, no Docker). Each failed run gets one **culprit** step (the first step that failed) and
an **error signature**, and runs with the same signature form a **cluster**.

## 30-second quick start

```bash
uv sync
./examples/run_demo.sh                       # 100 seeded runs of a toy pipeline, then `ff clusters`
uv run ff runs --failed --db examples/demo.db | head
uv run ff show <run id prefix> --db examples/demo.db   # waterfall, culprit step marked
```

The demo pipeline (question, plan, policy, tool, answer) injects six known failures (five clusters; the two missing-key errors share one signature): two kinds of tool
exception, a tool timeout, a policy block, a wrong answer and an empty answer. No network, no model.

## Instrument your own pipeline

```python
import failure_forensics as ff

question, gold = "How many units of sku-1 are in stock?", "8"

def generate(q):                              # stand-ins for your model call and checks
    return "SELECT stock FROM items WHERE sku = 'sku-1'"

@ff.step("validate")                          # decorator: sync or async functions
def validate(sql):
    assert sql.startswith("SELECT")

with ff.run("my_pipeline", case_id="q-17", tags={"suite": "smoke"}) as run:
    with ff.step("generate") as s:            # context manager: nested steps are fine
        sql = generate(question)
        s.record(input=question, output=sql)  # JSON-serialised, redacted, truncated
    validate(sql)
    with ff.step("answer", expect_output=True) as s:
        text = "7"
        s.record(output=text)                 # empty output becomes an `empty_output` failure
        if text != gold:
            ff.mark_failure("wrong_result", f"expected {gold}, got {text}")  # no exception needed
```

Then `ff runs --db .ff/traces.db` shows the failed run with `answer:wrong_result` as its culprit.
Spans go to `$FF_DB` or `./.ff/traces.db` (git-ignored). Call `ff.configure("path.db", max_len=500,
redactor=..., rules=[...])` to change that. Outside `ff.run`, `ff.step` does nothing.

## CLI

| Command | What it shows |
|---|---|
| `ff runs [--failed] [--since 24h]` | one line per run with its culprit |
| `ff show <run_id>` | indented waterfall with durations, inputs/outputs, culprit marked |
| `ff failures` | the culprit of every failed run |
| `ff clusters [--top N] [--by-tag KEY]` | signatures with count, share of runs, first/last seen, examples |
| `ff gc --keep-days N` | delete older runs |

All take `--db PATH` and `--json`. Exit code 0, or 3 on usage and database errors.
`failure-forensics` is an alias for `ff`.

## What counts as a failure

A run fails when its root raised, or when a step was marked failed (`mark_failure`, an
`expect_output` step that came back empty, or a custom rule). An exception that a step raised and the
pipeline handled (a retry, a fallback) does **not** fail the run. When the root raised, the culprit is
the deepest step on the chain of errored steps leading to it; a marked failure that ended earlier wins.

## Failure kinds

`exception`, `timeout` (a `TimeoutError`, or an exception type whose name contains "timeout"),
`refusal`, `blocked`, `wrong_result`, `empty_output`, `unsafe` and `marked:<custom>`. All besides
`exception` and `timeout` come from `ff.mark_failure(kind, detail)`; any other kind name becomes
`marked:<name>`. Add your own detection with rules: a function that gets all spans of a run and
returns a `ff.Failure` or `None`, passed as `ff.configure(rules=[...])`.

The signature is `step | kind | message`, where the message has quoted strings, UUIDs, paths, hex ids
and numbers replaced by placeholders, so "timed out after 2.5s" and "after 5.0s" cluster together.
One exception: the quoted key of a `KeyError` keeps its shape, with digits replaced (`KeyError:
'sku-<n>'`), because different missing keys are different bugs; a key that looks like an id (8+ hex
characters, or longer than 40 characters) is replaced entirely.

## Redaction defaults

Applied before anything is written, to inputs, outputs, step attributes, error messages and tags:
emails, phone numbers, IBANs (mod-97 checked), card numbers (Luhn checked), bearer tokens, `sk-...` /
GitHub / AWS style keys, hex strings of 48+ characters (32/40-character values such as trace ids and git SHAs are kept, unless they sit next to a secret key name), long mixed-case base64-like strings, `password=...` style
assignments (`password=x`, `'password': 'x'`, `"password": "x"`, `Authorization: Basic x`), and any dict key containing `password`, `passwd`, `secret`, `authorization`, `api_key`
or `token` (counters like `max_tokens` are kept). Add your own with `ff.Redactor(patterns=[...],
keys=[...])`. Values are cut to 500 characters by default.

## Limits

- Redaction is pattern based: it will miss secrets that look like ordinary text (for example a bare
  32-hex API key such as a Datadog key, which is kept on purpose because trace ids and md5 sums look
  the same) and can rarely hit a long number that happens to pass the Luhn check.
- Runs cannot be nested. Each `ff.run` starts its own trace, even when your host app has an active
  OpenTelemetry span; two runs in one request get two trace ids. Spans that your host's
  auto-instrumentation creates inside a step belong to the host's tracer provider, not ours, so they
  are not stored (ours is a private provider; the global one is untouched).
- If the database cannot be opened, the run is not traced and a warning is issued; the pipeline is
  unaffected. A run that ends with no stored spans also warns. Steps in plain threads you start yourself are not attached to the run
  (contexts do not cross threads); use `contextvars.copy_context().run(...)` or `asyncio.to_thread`.
- One culprit per run. Later failures in the same run are stored as spans but not clustered.
- Local SQLite only; no sampling, no exporters to other backends.

## Tracing text-to-sql-guardrails

`ff t2s run` traces every benchmark question and attack prompt of
[text-to-sql-guardrails](../text-to-sql-guardrails) (t2s) against its test database, with a
deterministic generator instead of a model. Nothing in t2s is edited, nothing calls an API.

```bash
uv sync --extra t2s                        # t2s as a local path extra: ../text-to-sql-guardrails
export TEST_DATABASE_URL=postgresql+psycopg://app:app@127.0.0.1:55432/app   # disposable, rebuilt!
./examples/t2s/run_demo.sh                 # gold + 3 mutated generators -> examples/t2s/demo.db
uv run --extra t2s ff t2s run --generator mutated:wrong-join --db traces.db
```

`--generator` is `gold`, `mutated:<name>[+<name>]` (`wrong-join`, `harmless-function`,
`drop-order-by`, `off-by-one-limit`, `cartesian`, `leaky`) or `recorded:<path.jsonl>` (lines of
`{"question": ..., "sql": ...}` or `"refusal"`). The schema is rebuilt with t2s's own
`prepare_database`, so `TEST_DATABASE_URL` must be a throwaway local PostgreSQL (non-local hosts are
refused); `--no-setup` reuses it. Every run is tagged with `generator`, `kind` (question/attack) and
`category`, so `ff clusters --by-tag generator` shows which generator causes which failure.

Steps per run: `generate` (once per attempt; model refusals), `validate`, `execute`, then `compare`
(a question's rows against its gold SQL) or `guard` (an attack prompt: denied data leaked, or the
database checksum changed). Failure kinds: `blocked` (the validator or the database role refused a
question that has a gold answer: over-blocking), `wrong_result`, `refusal`, `timeout`, `unsafe`.
For attack prompts a refusal or a block is the *right* outcome and is not a failure; only `unsafe` is.
A first attempt that fails and is repaired by t2s's retry is recorded on its spans but does not fail
the run.

Demo result (`examples/t2s/demo.db`, 4 x 72 runs; the generators' own failures are what you see):

| Cluster | Count | Comes from |
|---|---|---|
| `validate / blocked / FUNCTION_NOT_ALLOWED` | 40 | `harmless-function`: an extra `REVERSE()` predicate is not on t2s's function allowlist |
| `compare / wrong_result` | 5 | `wrong-join` (4 join questions) and 1 `cartesian` question whose duplicated rows still fit the limit |
| `execute / timeout` | 3 | `cartesian`: a forgotten join condition multiplies `order_items` twice |
| `validate / blocked / COLUMN_NOT_ALLOWED` | 2 | `cartesian`: unqualified columns become ambiguous after the extra cross joins |

The gold generator gives 40/40 correct questions and 32/32 declined attack prompts, and `leaky` (a
generator that answers every attack with `SELECT email FROM customers`) is stopped by the validator
every time, so no `unsafe` cluster appears against the real guardrails. Open any run with
`ff show <id> --db examples/t2s/demo.db`: the waterfall marks the culprit step.

Leak detection is t2s's own `leaked()`, so it inherits its gaps: values derived from denied data
(aggregates, hashes, substrings of other cells) are missed, short denied strings can match as
substrings of harmless cells (false positives), and the database checksum is only taken after a
query that ran successfully (a failed query is not checked).

How it works and its limits: t2s's `answer()` calls `validate` and `run_readonly` as module globals,
which cannot be observed without monkeypatching. `ff.integrations.t2s.traced_answer` therefore
re-composes `answer()` from t2s's public pieces in the same order, with the same two-call repair loop
(a parity test compares it with t2s's own `answer()` on every question, attack prompt and several
repair paths), and wraps the generator in a `SqlGenerator` proxy (`TracedGenerator`) that records each
call. If t2s changes its loop, the parity test fails and `traced_answer` needs the same change. The
`cartesian` timeouts depend on the machine (`--timeout-ms`, default 1000).

## Development

```bash
uv sync
uv run pytest && uv run ruff check .
# with the t2s extra and a disposable local PostgreSQL:
TEST_DATABASE_URL=postgresql+psycopg://app:app@127.0.0.1:55432/app uv run --extra t2s pytest -m pg
```

`uv run pytest` without `--extra t2s` skips the t2s tests (they `importorskip`).

- `AGENTS.md` - rules for coding agents (Claude Code reads it through `CLAUDE.md`)
- `DECISIONS.md` - why things are the way they are
- `CHANGELOG.md` - what changed in each release
- `plans/` - roadmap and milestone plans
