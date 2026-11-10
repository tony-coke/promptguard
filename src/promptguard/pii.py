"""PII detection and redaction.

Finds emails, phone numbers, SSNs, credit card numbers (Luhn-checked),
and street addresses, and replaces them with typed placeholders like
[EMAIL_1]. Keeps a mapping so the originals can be restored if needed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

PHONE_RE = re.compile(
    r"(?<!\d)(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}(?!\d)"
)

SSN_RE = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")

# 13-19 digits, optionally grouped with spaces or dashes
CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")

ADDRESS_RE = re.compile(
    r"\d{1,6}\s+([A-Za-z0-9.'-]+\s){1,4}"
    r"(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|"
    r"Court|Ct|Way|Place|Pl|Circle|Cir)\b\.?",
    re.IGNORECASE,
)


def _luhn_ok(digits: str) -> bool:
    """Luhn checksum: true if the digit string could be a real card number."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _ssn_plausible(ssn: str) -> bool:
    area, group, serial = ssn.split("-")
    if area in ("000", "666") or area.startswith("9"):
        return False
    if group == "00" or serial == "0000":
        return False
    return True


@dataclass
class RedactionResult:
    text: str
    mapping: dict[str, str] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=dict)

    def restore(self) -> str:
        out = self.text
        for placeholder, original in self.mapping.items():
            out = out.replace(placeholder, original)
        return out


def redact(text: str) -> RedactionResult:
    mapping: dict[str, str] = {}
    counts: dict[str, int] = {}

    def _replace(pattern: re.Pattern, label: str, src: str, validator=None) -> str:
        def sub(m: re.Match) -> str:
            value = m.group(0)
            if validator is not None and not validator(value):
                return value
            counts[label] = counts.get(label, 0) + 1
            placeholder = f"[{label}_{counts[label]}]"
            mapping[placeholder] = value
            return placeholder

        return pattern.sub(sub, src)

    out = text
    out = _replace(SSN_RE, "SSN", out, _ssn_plausible)
    out = _replace(EMAIL_RE, "EMAIL", out)
    out = _replace(PHONE_RE, "PHONE", out)

    def card_validator(raw: str) -> bool:
        digits = re.sub(r"[ -]", "", raw)
        return 13 <= len(digits) <= 19 and _luhn_ok(digits)

    out = _replace(CARD_RE, "CARD", out, card_validator)
    out = _replace(ADDRESS_RE, "ADDRESS", out)

    return RedactionResult(text=out, mapping=mapping, counts=counts)
