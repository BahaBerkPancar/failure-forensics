# Changelog

## Unreleased
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
