# Changelog

## Unreleased
- t2s `compare` failure says "same row count (N), different rows" when the counts match, instead of "expected N row(s), got N"; `examples/t2s/demo.db` regenerated (five clusters).
- `ff ui`: read-only local web UI (Streamlit, optional `ui` extra, localhost only, telemetry off) with Overview, Runs, Run detail (span waterfall, culprit highlighted), Clusters and Diff (failing run against the nearest passing run of the same case, first differing step marked); data layer in `failure_forensics.ui.data`.
- `ff t2s run` and `ff.integrations.t2s`: traces text-to-sql-guardrails step by step (generate, validate, execute, compare/guard) with deterministic generators (`gold`, `mutated:<name>`, `recorded:<path>`); new `unsafe` failure kind; optional `t2s` extra; `examples/t2s/run_demo.sh` and `examples/t2s/demo.db`.
- Culprit fallback: when the run body raises after a handled step error, the root is blamed, not the handled step.
- `KeyError` keys keep their shape with digits replaced (`'sku-<n>'`), so `sku-404` and `sku-500` now cluster together.
- `ff gc` keeps spans of unfinished runs that have any span younger than the cutoff.
- Redaction handles escaped quotes inside plain-quoted secret values; README notes that bare 32-hex API keys pass.
- Tracing API (`ff.run`, `ff.step`, `ff.mark_failure`) on OpenTelemetry, sync and async.
- SQLite store (WAL, schema versions and migrations) with an OTel span exporter.
- Redaction of emails, phones, IBAN/card numbers, tokens and keys, plus custom patterns and keys.
- Failure classification (first failing step wins, pluggable rules) and clustering by signature.
- `ff` CLI: `runs`, `show`, `failures`, `clusters`, `gc`, all with `--json`.
- Toy pipeline and `examples/run_demo.sh` with six known failure clusters.
- Handled (caught) errors no longer fail a run; the culprit is the deepest error on the chain from the failed root.
- Redaction covers quoted keys, JSON, dict reprs and `Authorization: Basic/Bearer`; case ids, tags and run names are redacted too.
- Each run is its own trace even inside a host's OpenTelemetry span.
- Safer startup and storage: tracing setup errors only warn, concurrent migrations are safe, `ff gc` removes orphan spans, CLI rejects bad `--top` / `--keep-days`.
- Project created.
