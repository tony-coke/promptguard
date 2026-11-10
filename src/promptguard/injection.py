"""Heuristic prompt-injection detection.

Not a guarantee. This scores text based on known injection patterns and
phrasings. A determined attacker can phrase around any fixed rule set,
so this is one layer of defense, not a firewall. See README for the
OWASP LLM01 mapping and honest limitations.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

# Each pattern: (compiled regex, weight, human-readable reason)
_PATTERNS: list[tuple[re.Pattern, float, str]] = [
    # Instruction override
    (re.compile(r"\bignore (all |any )?(previous|prior|above) instructions\b"), 0.9,
     "attempts to override prior instructions"),
    (re.compile(r"\bdisregard (all |any )?(previous|prior|above)\b"), 0.8,
     "attempts to discard prior context"),
    (re.compile(r"\bforget (everything|all of that|your instructions)\b"), 0.7,
     "attempts to reset context"),

    # Role-play jailbreaks
    (re.compile(
        r"\byou are now\b.{0,40}\b(no (rules|restrictions|limits)|unrestricted|dan)\b"
     ), 0.9, "role-play jailbreak attempt"),
    (re.compile(r"\bact as (an? )?(unfiltered|unrestricted|jailbroken)\b"), 0.85,
     "role-play jailbreak attempt"),
    (re.compile(r"\bpretend (you have|there are) no (rules|restrictions|limits)\b"), 0.85,
     "role-play jailbreak attempt"),

    # Fake system prompts / delimiter injection
    (re.compile(r"(?:^|[.!?]\s+)\s*(system|assistant)\s*:", re.IGNORECASE), 0.6,
     "fake role/system delimiter"),
    (re.compile(r"\[/?(inst|system|sys)\]", re.IGNORECASE), 0.6,
     "fake instruction delimiter"),

    # Exfiltration of instructions
    (re.compile(r"\b(repeat|print|reveal|show) (your |the )?(system prompt|instructions)\b"), 0.8,
     "attempts to exfiltrate system prompt"),
    (re.compile(r"\bwhat (are|were) your (original )?instructions\b"), 0.7,
     "attempts to exfiltrate system prompt"),
]


def _normalize(text: str) -> str:
    # Drop zero-width and other invisible formatting characters
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    text = text.lower()
    text = re.sub(r"\s+", " ", text)
    return text.strip()


@dataclass
class InjectionResult:
    score: float
    level: str
    reasons: list[str] = field(default_factory=list)


def check_injection(text: str) -> InjectionResult:
    normalized = _normalize(text)
    score = 0.0
    reasons: list[str] = []

    for pattern, weight, reason in _PATTERNS:
        if pattern.search(normalized):
            score = max(score, weight)
            reasons.append(reason)

    score = min(score, 1.0)
    if score >= 0.7:
        level = "high"
    elif score >= 0.4:
        level = "medium"
    else:
        level = "low"

    return InjectionResult(score=score, level=level, reasons=reasons)
