"""Guards LLM output before it reaches a user or downstream system.

Checks for shell commands, leaked secrets/API keys, and unredacted PII.
Reuses the PII redactor from pii.py. Returns allow/flag/block plus the
specific findings, so the decision is explainable, not a black box.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from promptguard.pii import redact

_SHELL_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\brm\s+-rf\b"), "destructive shell command (rm -rf)"),
    (re.compile(r"\bcurl\b.{0,40}\|\s*(sh|bash)\b"), "pipe-to-shell download pattern"),
    (re.compile(r"\bwget\b.{0,40}\|\s*(sh|bash)\b"), "pipe-to-shell download pattern"),
    (re.compile(r";\s*(rm|dd|mkfs)\b"), "chained destructive command"),
    (re.compile(r"\bsudo\s+rm\b"), "elevated destructive command"),
]

_SECRET_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key"),
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "API secret key (sk- prefix)"),
    (re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "GitHub personal access token"),
    (re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"), "private key material"),
]


@dataclass
class GuardResult:
    decision: str  # "allow" | "flag" | "block"
    findings: list[str] = field(default_factory=list)
    redacted_text: str = ""


def check_output(text: str) -> GuardResult:
    findings: list[str] = []
    decision = "allow"

    for pattern, label in _SHELL_PATTERNS:
        if pattern.search(text):
            findings.append(f"shell: {label}")
            decision = "block"

    for pattern, label in _SECRET_PATTERNS:
        if pattern.search(text):
            findings.append(f"secret: {label}")
            decision = "block"

    redaction = redact(text)
    if redaction.mapping:
        findings.append(f"pii: {len(redaction.mapping)} item(s) redacted")
        if decision == "allow":
            decision = "flag"

    return GuardResult(
        decision=decision,
        findings=findings,
        redacted_text=redaction.text,
    )
