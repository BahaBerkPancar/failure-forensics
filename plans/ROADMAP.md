# Build plan: failure-forensics

Written 2026-11-17 (away run). Source: vault `knowledge/project-ideas-backlog.md`, "Saved for later":
"trace each step of an AI workflow to find where it failed, and turn failures into test cases.
Stack: Python, OpenTelemetry, SQLite, Streamlit … the Text-to-SQL project could be that pipeline."

## What it is
A small forensics kit for LLM pipelines. Wrap each step of a pipeline (prompt build, model call,
parse, validate, execute, post-process) in a span; spans land in a local SQLite store; failures are
classified by **which step broke and how** (exception, guardrail block, wrong result, timeout,
refusal, empty output); similar failures are clustered; a UI shows a run's waterfall and the
clusters; and any failing trace can be exported as a **regression test case** — an mrd suite case
(`../model-regression-detector`) or a pytest file — so the same failure is caught next time.

## Ground rules
- No paid API calls (same as t2s M4b and MRD): demos use deterministic/mutated generators.
- Never read any `.env`. Tests never touch the network.
- OpenTelemetry SDK for spans (standard API, so real pipelines can adopt it), with our own
  SQLite exporter — no collector, no Docker needed.
- Redaction by default: span attributes are truncated and pass through a redactor (emails,
  phone numbers, keys/tokens patterns) before they are stored.
- Builders: Codex via `~/.mf/bin/codex-task` (Sonnet fallback); reviews by the `reviewer` agent;
  hub commits locally; created `--local`, so no GitHub repo until MF says.

## Milestones
| # | Name | Contents |
|---|------|----------|
| M1 | Tracing core + store + CLI | `@step` decorator / context manager on top of OTel, SQLite exporter (runs, spans, events, attributes), redaction, failure classifier with pluggable rules, clustering by (step, failure kind, normalized error signature), `ff` CLI: `runs`, `show <run>` (text waterfall), `failures`, `clusters`. Offline toy pipeline in `examples/` that fails in several known ways. |
| M2 | Text-to-SQL instrumentation | Wrap t2s (no edits to t2s) via its public functions/protocols: generator wrapper, validator, executor spans; run its questions + attack prompts with MRD-style mutated generators against the t2s test DB; real failure clusters (wrong join, blocked SELECT *, denied column, timeout). |
| M3 | UI | Streamlit app: runs table with filters, run waterfall (step timings, inputs/outputs, error), cluster view with counts over time, side-by-side diff of a failing vs passing run of the same case. |
| M4 | Failure → test case + showcase | `ff export --cluster X --to mrd|pytest`: writes mrd suite cases (with expected from the passing run or a human-provided gold) or a pytest regression file; README with screenshots and the loop "trace → cluster → export → gate in CI". |
