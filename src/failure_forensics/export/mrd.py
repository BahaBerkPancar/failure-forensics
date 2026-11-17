"""Write and merge a model-regression-detector suite.

The mrd suite format (`Suite`: name, metrics, cases of id/input/expected/tags, all with unknown
keys forbidden) is YAML, read by mrd with `yaml.safe_load`. We write and read it with the same
library (PyYAML, a dependency). Merging re-writes the file, so comments in it are dropped.
mrd's case model rejects unknown keys, so "needs review" is the tag `needs_review` (with
`expected: null`), not a field.
"""

from __future__ import annotations

from typing import Any

import yaml

from .cases import ExportCase

METRIC = {"name": "correct", "kind": "pass_fail"}


class MrdError(Exception):
    """An existing suite file cannot be merged."""


def _tags(c: ExportCase) -> list[str]:
    tags = [f"signature:{c.signature}", f"step:{c.step}", f"kind:{c.kind}", *c.tags]
    if not c.has_expected:
        tags.append("needs_review")
    return list(dict.fromkeys(tags))


def case_dict(c: ExportCase) -> dict[str, Any]:
    return {"id": c.id, "input": c.input, "expected": c.expected if c.has_expected else None, "tags": _tags(c)}


def suite_for(cases: list[ExportCase], name: str) -> dict[str, Any]:
    return {"name": name, "metrics": [dict(METRIC)], "cases": [case_dict(c) for c in cases]}


def render_suite(suite: dict[str, Any]) -> str:
    """Real YAML via PyYAML: unicode kept as UTF-8, floats always written so they load back as floats."""
    try:
        return yaml.safe_dump(suite, sort_keys=False, allow_unicode=True, default_flow_style=False, width=100)
    except yaml.YAMLError as e:
        raise MrdError(f"cannot write the suite: {e}") from None


def parse_suite(text: str) -> dict[str, Any]:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise MrdError(f"existing suite is not valid YAML: {e}") from None
    if (
        not isinstance(data, dict) or not isinstance(data.get("name"), str)
        or not isinstance(data.get("cases"), list) or not all(isinstance(c, dict) for c in data["cases"])
        or not isinstance(data.get("metrics"), list) or not data["metrics"]
    ):
        raise MrdError("existing file is not an mrd suite (needs a name, a non-empty metrics list and a cases list)")
    return data


def merge_suite(existing: dict[str, Any], cases: list[ExportCase]) -> tuple[dict[str, Any], int, int]:
    """Append cases whose id is not present yet. Returns (suite, added, already present)."""
    have = {c.get("id") for c in existing["cases"] if isinstance(c, dict)}
    new = [case_dict(c) for c in cases if c.id not in have]
    merged = {**existing, "cases": [*existing["cases"], *new]}
    return merged, len(new), len(cases) - len(new)
