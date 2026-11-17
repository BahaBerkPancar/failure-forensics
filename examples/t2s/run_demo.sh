#!/usr/bin/env bash
# Runs gold + three mutated "bad models" against the t2s test database into examples/t2s/demo.db
# and prints the failure clusters per generator. Needs the t2s extra and TEST_DATABASE_URL
# (e.g. postgresql+psycopg://app:app@127.0.0.1:55432/app); the schema there is rebuilt.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DB="$ROOT/examples/t2s/demo.db"
rm -f "$DB" "$DB-wal" "$DB-shm"
FF=(uv run --project "$ROOT" --extra t2s ff)
"${FF[@]}" t2s run --generator gold --db "$DB"
for g in mutated:wrong-join mutated:harmless-function mutated:cartesian; do
  "${FF[@]}" t2s run --generator "$g" --db "$DB" --no-setup
done
"${FF[@]}" clusters --by-tag generator --db "$DB"
