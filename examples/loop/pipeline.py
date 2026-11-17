"""A small stock-lookup pipeline with one real bug, for the trace -> cluster -> export -> gate loop.

`answer(question)` is the entry point the generated regression test calls. The bug: SKUs are
looked up exactly as typed, so "SKU-7" raises KeyError. Set LOOP_FIXED=1 to normalise
the key first. Unknown SKUs ("sku-999") raise ValueError in both versions: that is a different,
smaller cluster that the fix does not touch.

    python examples/loop/pipeline.py --db traces.db --cases 60      # trace traffic into a store
No network, no model.
"""

from __future__ import annotations

import argparse
import os
import random
import re
from pathlib import Path

import failure_forensics as ff

STOCK = {f"sku-{i}": (i * 5) % 30 + 1 for i in range(1, 25)}


def fixed() -> bool:
    return os.environ.get("LOOP_FIXED") == "1"


def parse(question: str) -> str:
    m = re.search(r"of (\S+) ", question)
    if not m:
        raise ValueError(f"no SKU in {question!r}")
    return m.group(1)


def lookup(sku: str) -> int:
    key = sku.strip().lower() if fixed() else sku  # the bug: keys are case and space sensitive
    if key.startswith("sku-") and key.removeprefix("sku-").isdigit() and int(key.removeprefix("sku-")) > 900:
        raise ValueError(f"unknown SKU {key}")
    return STOCK[key]


def answer(question: str) -> str:
    with ff.step("parse") as s:
        s.record(input=question)
        sku = parse(question)
        s.record(output=sku)
    with ff.step("lookup") as s:
        s.record(input=sku)
        units = lookup(sku)
        s.record(output=units)
    with ff.step("answer", expect_output=True) as s:
        text = f"{units} units of {sku.strip().lower()} in stock."
        s.record(output=text)
    return text


def questions(n: int, seed: int) -> list[str]:
    rng = random.Random(seed)
    out = []
    for _ in range(n):
        key = f"sku-{rng.randint(1, 24)}"
        x = rng.random()
        if x < 0.30:
            key = key.upper()  # trips the bug
        elif x < 0.34:
            key = "sku-999"  # unknown SKU: fails before and after the fix
        out.append(f"Units of {key} in stock?")
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--cases", type=int, default=60)
    ap.add_argument("--seed", type=int, default=3)
    args = ap.parse_args()
    for suffix in ("", "-wal", "-shm"):
        Path(args.db + suffix).unlink(missing_ok=True)
    store = ff.configure(args.db)
    for i, q in enumerate(questions(args.cases, args.seed)):
        try:
            with ff.run("stock_bot", case_id=f"q-{i:03d}"):
                answer(q)
        except Exception:  # noqa: BLE001, S110 - already recorded by the run
            pass
    store.checkpoint()


if __name__ == "__main__":
    main()
