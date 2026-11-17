# failure-forensics

Traces every step of an AI pipeline, finds where a run went wrong, and turns failures into regression test cases (first target: text-to-sql-guardrails).

## Setup

```bash
uv sync
```

## Development

Run the tests:

```bash
uv run pytest && uv run ruff check .
```

## How this repo is organised

- `AGENTS.md` – rules for coding agents (Claude Code reads it through `CLAUDE.md`)
- `DECISIONS.md` – why things are the way they are
- `CHANGELOG.md` – what changed in each release
