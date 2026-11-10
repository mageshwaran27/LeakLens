"""Masking + fingerprinting. Raw secrets must never be persisted/logged."""
from __future__ import annotations

import hashlib
import re


def mask_value(value: str) -> str:
    if not value:
        return ""
    v = value.strip().strip("\"'").strip()
    if len(v) <= 8:
        return v[:2] + "***" if len(v) > 2 else "***"
    return f"{v[:4]}...{v[-4:]}"


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


_SENSITIVE_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    re.compile(r"xox[bpas]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{16,}"),
    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
]


def redact_text(text: str) -> str:
    out = text or ""
    for pat in _SENSITIVE_PATTERNS:
        out = pat.sub("[REDACTED]", out)
    return out


def mask_line(line: str, secrets: list[str]) -> str:
    masked = line or ""
    for s in secrets:
        if s and s in masked:
            masked = masked.replace(s, mask_value(s))
    return redact_text(masked)
