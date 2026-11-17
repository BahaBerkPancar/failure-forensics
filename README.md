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

The demo pipeline (question, plan, policy, tool, answer) injects six known failures: two kinds of tool
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
`refusal`, `blocked`, `wrong_result`, `empty_output` and `marked:<custom>`. The first six besides
`exception` and `timeout` come from `ff.mark_failure(kind, detail)`; any other kind name becomes
`marked:<name>`. Add your own detection with rules: a function that gets all spans of a run and
returns a `ff.Failure` or `None`, passed as `ff.configure(rules=[...])`.

The signature is `step | kind | message`, where the message has quoted strings, UUIDs, paths, hex ids
and numbers replaced by placeholders, so "timed out after 2.5s" and "after 5.0s" cluster together.
One exception: the quoted key of a `KeyError` is kept (`KeyError: 'sku-404'`), because different
missing keys are different bugs, unless it looks like an id (6+ digits, 8+ hex characters, or longer
than 40 characters).

## Redaction defaults

Applied before anything is written, to inputs, outputs, step attributes, error messages and tags:
emails, phone numbers, IBANs (mod-97 checked), card numbers (Luhn checked), bearer tokens, `sk-...` /
GitHub / AWS style keys, hex strings of 48+ characters (32/40-character values such as trace ids and git SHAs are kept, unless they sit next to a secret key name), long mixed-case base64-like strings, `password=...` style
assignments (`password=x`, `'password': 'x'`, `"password": "x"`, `Authorization: Basic x`), and any dict key containing `password`, `passwd`, `secret`, `authorization`, `api_key`
or `token` (counters like `max_tokens` are kept). Add your own with `ff.Redactor(patterns=[...],
keys=[...])`. Values are cut to 500 characters by default.

## Limits

- Redaction is pattern based: it will miss secrets that look like ordinary text and can rarely hit a
  long number that happens to pass the Luhn check.
- Runs cannot be nested. Each `ff.run` starts its own trace, even when your host app has an active
  OpenTelemetry span; two runs in one request get two trace ids. Spans that your host's
  auto-instrumentation creates inside a step belong to the host's tracer provider, not ours, so they
  are not stored (ours is a private provider; the global one is untouched).
- If the database cannot be opened, the run is not traced and a warning is issued; the pipeline is
  unaffected. A run that ends with no stored spans also warns. Steps in plain threads you start yourself are not attached to the run
  (contexts do not cross threads); use `contextvars.copy_context().run(...)` or `asyncio.to_thread`.
- One culprit per run. Later failures in the same run are stored as spans but not clustered.
- Local SQLite only; no sampling, no exporters to other backends.

## Development

```bash
uv sync
uv run pytest && uv run ruff check .
```

- `AGENTS.md` - rules for coding agents (Claude Code reads it through `CLAUDE.md`)
- `DECISIONS.md` - why things are the way they are
- `CHANGELOG.md` - what changed in each release
- `plans/` - roadmap and milestone plans
