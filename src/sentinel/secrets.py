from __future__ import annotations

import re

SECRET_PATTERNS = (
    re.compile(r"sk-(?:proj|or|live)-[A-Za-z0-9_-]{12,}"),
    re.compile(r"AIza[A-Za-z0-9_-]{20,}"),
    re.compile(r"AQ\.[A-Za-z0-9_-]{20,}"),
    re.compile(r"(?i)(authorization\s*:\s*(?:bearer|token)\s+)[^\s,;]+"),
)


def redact_secrets(value: str, *, limit: int = 2_000) -> str:
    redacted = value
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(
            lambda match: f"{match.group(1)}[REDACTED]" if match.lastindex else "[REDACTED]",
            redacted,
        )
    return redacted[:limit]
