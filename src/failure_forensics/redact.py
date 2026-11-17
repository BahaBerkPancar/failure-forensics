"""Redaction applied to every value before it is stored.

Text is scrubbed with regexes (emails, phone numbers, IBAN and card numbers that pass
their checksums, bearer tokens, API-key-like strings). Mappings are scrubbed by key name
(`password`, `token`, `secret`, `authorization`, ...). Callers can add their own patterns
and key names.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import asdict, is_dataclass
from typing import Any

MASK = "[REDACTED]"
_ALNUM = r"[A-Za-z0-9+/_\-]"

_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+")
_BEARER = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=\-]{8,}", re.IGNORECASE)
_PREFIXED_KEY = re.compile(
    r"\b(?:sk-[A-Za-z0-9_\-]{16,}|(?:ghp_|gho_|github_pat_|xox[abp]-|AKIA)[A-Za-z0-9_\-]{12,})"
)
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b")
_CARD = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")
# Plain 32/40-char hex values (trace ids, md5, git SHAs) are kept; only 48+ char hex (e.g. 256-bit keys)
# is masked on its own. Any length is masked next to a secret key name (see `_assignment`).
_HEX = re.compile(r"\b[0-9a-fA-F]{48,}\b")
_BLOB = re.compile(
    rf"(?<!{_ALNUM})(?=[A-Za-z0-9+/_\-]*[A-Z])(?=[A-Za-z0-9+/_\-]*[a-z])"
    rf"(?=[A-Za-z0-9+/_\-]*\d){_ALNUM}{{40,}}={{0,2}}"
)
_PHONES = (
    re.compile(r"(?<![\w.])\+\d{1,3}[\s.-]?\(?\d{1,4}\)?(?:[\s.-]?\d{2,4}){2,4}(?!\d)"),
    re.compile(r"(?<![\w.])\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\d)"),
    re.compile(r"(?<![\w.])0\d{3} ?\d{3} ?\d{2} ?\d{2}(?!\d)"),
)

DEFAULT_KEYS = ("password", "passwd", "secret", "authorization", "api_key", "api-key", "apikey", "token")
# Counters such as max_tokens are numbers, not secrets.
_SAFE_KEYS = re.compile(
    r"^(?:max|n|num|total|prompt|completion|input|output|cached)_tokens$|^tokens$"
    r"|^tokens?_(?:count|limit|usage|used|budget|len|length)$",
    re.IGNORECASE,
)


def _assignment(keys: tuple[str, ...]) -> re.Pattern[str]:
    """`key = value`, `key: value`, `'key': 'value'`, `"key": "value"` and JSON-escaped forms
    (`\\"key\\": \\"value\\"`), with an optional auth scheme (`Basic xyz`, `Bearer xyz`)."""
    alt = "|".join(re.escape(k) for k in keys)
    return re.compile(
        rf"(?P<key>[A-Za-z0-9_\-]*(?:{alt})[A-Za-z0-9_\-]*)"
        r"(?P<sep>\\?[\"']?\s*[=:]\s*)"
        r"(?:(?:Bearer|Basic|Digest|Token)\s+)?"
        r"(?:\\?\"[^\"]*\"|'[^']*'|[^\s,;}\]\"']+)",
        re.IGNORECASE,
    )


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
    return total % 10 == 0


def iban_ok(raw: str) -> bool:
    s = raw.replace(" ", "")
    if not 15 <= len(s) <= 34:
        return False
    rearranged = s[4:] + s[:4]
    try:
        number = "".join(str(int(c, 36)) for c in rearranged)
    except ValueError:
        return False
    return int(number) % 97 == 1


class Redactor:
    """Scrubs text and nested values. Instances are cheap and thread-safe."""

    def __init__(self, patterns: Iterable[str | re.Pattern[str]] = (), keys: Iterable[str] = ()):
        self.patterns = [re.compile(p) if isinstance(p, str) else p for p in patterns]
        self.keys = tuple(k.lower() for k in (*DEFAULT_KEYS, *keys))
        self._assignment = _assignment(self.keys)

    def is_sensitive_key(self, key: Any) -> bool:
        k = str(key).lower()
        if _SAFE_KEYS.match(k):
            return False
        return any(part in k for part in self.keys)

    def text(self, s: str) -> str:
        s = self._assignment.sub(self._mask_assignment, s)
        s = _EMAIL.sub("[REDACTED:email]", s)
        s = _BEARER.sub("Bearer [REDACTED:token]", s)
        s = _PREFIXED_KEY.sub("[REDACTED:key]", s)
        s = _IBAN.sub(lambda m: "[REDACTED:iban]" if iban_ok(m.group()) else m.group(), s)
        s = _CARD.sub(self._card, s)
        s = _HEX.sub("[REDACTED:hex]", s)
        s = _BLOB.sub("[REDACTED:key]", s)
        for phone in _PHONES:
            s = phone.sub("[REDACTED:phone]", s)
        for custom in self.patterns:
            s = custom.sub("[REDACTED:custom]", s)
        return s

    def _mask_assignment(self, m: re.Match[str]) -> str:
        if not self.is_sensitive_key(m.group("key")):
            return m.group()
        return f"{m.group('key')}{m.group('sep')}[REDACTED:secret]"

    @staticmethod
    def _card(m: re.Match[str]) -> str:
        digits = re.sub(r"\D", "", m.group())
        if 13 <= len(digits) <= 19 and luhn_ok(digits):
            return "[REDACTED:card]"
        return m.group()

    def scrub(self, obj: Any, _depth: int = 0) -> Any:
        """Mask values under sensitive keys in nested mappings (returns a copy)."""
        if _depth > 8:
            return obj
        if is_dataclass(obj) and not isinstance(obj, type):
            obj = asdict(obj)
        if isinstance(obj, dict):
            return {
                k: MASK if self.is_sensitive_key(k) else self.scrub(v, _depth + 1)
                for k, v in obj.items()
            }
        if isinstance(obj, (list, tuple, set, frozenset)):
            return [self.scrub(v, _depth + 1) for v in obj]
        return obj

    def json_text(self, value: Any, max_len: int = 500) -> str:
        """JSON-serialise any value safely, redact it, then truncate to `max_len` chars."""
        scrubbed = self.scrub(value)
        try:
            raw = json.dumps(scrubbed, default=_fallback, ensure_ascii=False)
        except (TypeError, ValueError, RecursionError):
            raw = repr(scrubbed)
        return truncate(self.text(raw), max_len)


def _fallback(o: Any) -> str:
    if isinstance(o, bytes):
        return o.decode("utf-8", "replace")
    return repr(o)


def truncate(s: str, max_len: int) -> str:
    if len(s) <= max_len:
        return s
    return f"{s[:max_len]}...[+{len(s) - max_len} chars]"
