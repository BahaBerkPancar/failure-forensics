#!/usr/bin/env bash
# Runs 100 seeded cases of the toy pipeline into examples/demo.db and prints the failure clusters.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
uv run --project "$ROOT" python "$ROOT/examples/toy_pipeline.py" --cases 100 --seed 7 --db "$ROOT/examples/demo.db"
uv run --project "$ROOT" ff clusters --db "$ROOT/examples/demo.db"
