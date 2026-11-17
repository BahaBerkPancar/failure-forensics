"""Offline toy pipeline: question -> plan -> policy -> tool -> answer, with seeded fault injection.

Run: python examples/toy_pipeline.py --cases 100 --seed 7 --db examples/demo.db
No network, no model: the "planner" and "tool" are plain functions.
"""

from __future__ import annotations

import argparse
import random
from pathlib import Path

import failure_forensics as ff

STOCK = {f"sku-{i}": (i * 7) % 40 + 1 for i in range(1, 30)}
ORDERS = {f"user{i}@example.com": (i * 3) % 9 + 1 for i in range(1, 20)}

# (fault, weight); the rest of the probability mass is healthy runs
FAULTS = [
    ("conn_error", 0.10),
    ("missing_key", 0.07),
    ("timeout", 0.09),
    ("blocked", 0.10),
    ("wrong_answer", 0.09),
    ("empty_answer", 0.05),
]


def pick_fault(rng: random.Random) -> str | None:
    x = rng.random()
    for fault, weight in FAULTS:
        if x < weight:
            return fault
        x -= weight
    return None


def make_case(i: int, rng: random.Random) -> dict:
    if rng.random() < 0.6:
        key = rng.choice(sorted(STOCK))
        return {"id": f"case-{i:03d}", "topic": "stock", "key": key,
                "question": f"How many units of {key} are in stock?", "gold": STOCK[key]}
    key = rng.choice(sorted(ORDERS))
    return {"id": f"case-{i:03d}", "topic": "orders", "key": key,
            "question": f"How many orders has {key} placed?", "gold": ORDERS[key]}


def plan(case: dict) -> dict:
    with ff.step("plan") as s:
        s.record(input=case["question"])
        result = {"tool": "lookup", "table": case["topic"], "key": case["key"]}
        s.record(output=result)
        return result


@ff.step("policy")
def policy(plan_: dict, fault: str | None) -> bool:
    if fault == "blocked":
        ff.mark_failure("blocked", f"write statement not allowed: 'DELETE FROM {plan_['table']}'")
        return False
    return True


def tool(plan_: dict, fault: str | None, rng: random.Random):
    with ff.step("tool", table=plan_["table"]) as s:
        s.record(input=plan_)
        if fault == "conn_error":
            raise ConnectionError(f"connection reset by peer at 10.0.{rng.randint(0, 9)}.{rng.randint(1, 250)}:5432")
        if fault == "missing_key":
            raise KeyError(rng.choice(["sku-404", "sku-500"]))  # two distinct missing keys
        if fault == "timeout":
            raise TimeoutError(f"tool call exceeded {rng.choice([2.0, 2.5, 5.0])}s deadline")
        table = STOCK if plan_["table"] == "stock" else ORDERS
        value = table[plan_["key"]]
        s.record(output=value)
        return value


def answer(case: dict, value: int, fault: str | None) -> str:
    with ff.step("answer", expect_output=True) as s:
        s.record(input=value)
        if fault == "empty_answer":
            text = ""
        elif fault == "wrong_answer":
            text = f"The answer is {value + 1}."
        else:
            text = f"The answer is {value}."
        s.record(output=text)
        if fault == "wrong_answer":
            ff.mark_failure("wrong_result", f"expected {case['gold']}, got {value + 1}")
        return text


def run_case(case: dict, rng: random.Random) -> None:
    fault = pick_fault(rng)
    with ff.run("toy_pipeline", case_id=case["id"], tags={"topic": case["topic"]}):
        p = plan(case)
        if not policy(p, fault):
            return
        value = tool(p, fault, rng)
        answer(case, value, fault)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", type=int, default=100)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--db", default="examples/demo.db")
    args = ap.parse_args()
    for suffix in ("", "-wal", "-shm"):
        Path(args.db + suffix).unlink(missing_ok=True)
    store = ff.configure(args.db)
    rng = random.Random(args.seed)
    for i in range(args.cases):
        try:
            run_case(make_case(i, rng), rng)
        except Exception:  # noqa: BLE001, S110 - the failure is already recorded by the run
            pass
    store.checkpoint()


if __name__ == "__main__":
    main()
