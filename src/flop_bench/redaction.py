from __future__ import annotations

import re

KEY_VALUE_SECRET_PATTERNS = [
    re.compile(r"(?i)(password|passphrase|secret|token|api[_-]?key)\s*[:=]\s*([^\s]+)"),
    re.compile(r"(?i)(AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|OPENAI_API_KEY)=([^\s]+)"),
]
BLOCK_SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
]


def redact(text: str, limit: int | None = None) -> str:
    redacted = text
    for pattern in KEY_VALUE_SECRET_PATTERNS:
        redacted = pattern.sub(
            lambda match: match.group(0).split(match.group(2))[0] + "<redacted>",
            redacted,
        )
    for pattern in BLOCK_SECRET_PATTERNS:
        redacted = pattern.sub("<redacted-private-key>", redacted)
    if limit is not None and len(redacted) > limit:
        return redacted[:limit] + "\n[truncated]"
    return redacted
