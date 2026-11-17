#!/usr/bin/env bash
# The whole loop, offline: trace a buggy pipeline -> cluster -> export the top cluster to pytest ->
# the generated test FAILS on the buggy pipeline -> LOOP_FIXED=1 makes it PASS.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
FF=(uv run --project "$ROOT" ff)
export PYTHONPATH="$ROOT/examples/loop${PYTHONPATH:+:$PYTHONPATH}"

echo "== 1. trace 60 runs of the buggy pipeline"
uv run --project "$ROOT" python "$ROOT/examples/loop/pipeline.py" --db "$WORK/traces.db" --cases 60 || exit 1

echo; echo "== 2. cluster the failures"
"${FF[@]}" clusters --db "$WORK/traces.db" || exit 1
TOP=$("${FF[@]}" clusters --db "$WORK/traces.db" --top 1 --json \
  | uv run --project "$ROOT" python -c "import json,sys; print(json.load(sys.stdin)[0]['signature'])") || exit 1

echo; echo "== 3. export the top cluster as a pytest regression test"
"${FF[@]}" export --cluster "$TOP" --to pytest --entry pipeline:answer --db "$WORK/traces.db" \
  --out "$WORK/test_regression.py" || exit 1

echo; echo "== 4. gate: run the generated test on the buggy pipeline (expected: FAIL)"
OUT=$(cd "$WORK" && uv run --project "$ROOT" python -m pytest test_regression.py -q -p no:cacheprovider --no-header 2>&1)
BUGGY=$?
echo "$OUT" | grep -E "^FAILED" | sed 's/ - .*//' | head -2
echo "$OUT" | tail -1

echo; echo "== 5. gate again with LOOP_FIXED=1 (expected: PASS)"
(cd "$WORK" && LOOP_FIXED=1 uv run --project "$ROOT" python -m pytest test_regression.py -q \
  -p no:cacheprovider --no-header 2>&1 | tail -1; exit "${PIPESTATUS[0]}")
FIXED=$?

echo
if [ "$BUGGY" -eq 1 ] && [ "$FIXED" -eq 0 ]; then
  echo "loop closed: the test failed on the buggy pipeline and passes on the fixed one."
else
  echo "unexpected: buggy exit=$BUGGY fixed exit=$FIXED" >&2
  exit 1
fi
