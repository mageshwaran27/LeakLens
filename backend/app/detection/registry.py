"""Versioned detector registry. Coverage is NOT exhaustive (see docs)."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

REGISTRY_VERSION = "1.0.0"


@dataclass
class Detector:
    id: str
    name: str
    category: str
    pattern: str
    confidence: float
    severity: str
    validator: str = ""
    _rx: re.Pattern = field(init=False, repr=False, default=None)

    def __post_init__(self):
        self._rx = re.compile(self.pattern)


def _luhn_ok(digits: str) -> bool:
    ds = [int(d) for d in digits if d.isdigit()]
    if len(ds) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(ds)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def validate(detector_id: str, value: str) -> bool:
    if detector_id == "PII_CREDIT_CARD":
        digits = re.sub(r"\D", "", value)
        return _luhn_ok(digits)
    if detector_id == "JWT":
        return value.count(".") == 2
    if detector_id == "PRIVATE_KEY":
        return "PRIVATE KEY" in value
    return True


DETECTORS: list[Detector] = [
    Detector("AWS_ACCESS_KEY", "AWS Access Key", "AWS_CREDENTIAL", r"\bAKIA[0-9A-Z]{16}\b", 0.98, "HIGH"),
    Detector("AWS_SECRET_KEY", "AWS Secret Key", "AWS_CREDENTIAL", r"(?i)aws_(?:secret|session)[_\-]?key[\"'\s:=]+([A-Za-z0-9/+=]{32,})", 0.85, "HIGH"),
    Detector("GITHUB_TOKEN", "GitHub Token", "GITHUB_TOKEN", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", 0.97, "HIGH"),
    Detector("GOOGLE_API_KEY", "Google API Key", "GOOGLE_CREDENTIAL", r"\bAIza[0-9A-Za-z\-_]{35}\b", 0.95, "HIGH"),
    Detector("SLACK_TOKEN", "Slack Token", "SLACK_TOKEN", r"\bxox[bpas]-[A-Za-z0-9\-]{10,}\b", 0.95, "HIGH"),
    Detector("STRIPE_SECRET", "Stripe Secret", "STRIPE_SECRET", r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b", 0.95, "HIGH"),
    Detector("PRIVATE_KEY", "Private Key", "PRIVATE_KEY", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", 0.99, "HIGH"),
    Detector("JWT", "JWT", "JWT", r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b", 0.80, "MEDIUM"),
    Detector("BEARER_TOKEN", "Bearer Token", "BEARER_TOKEN", r"(?i)bearer\s+([A-Za-z0-9_\-\.~\+/]+=*)", 0.75, "MEDIUM"),
    Detector("DATABASE_URL", "Database URL", "DATABASE_CREDENTIAL", r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|sqlite)://[^\s\"']+", 0.90, "HIGH"),
    Detector("CONNECTION_STRING", "Connection String", "DATABASE_CREDENTIAL", r"(?i)\bServer=[^;]+;[^\"']*Password=[^;\"']+", 0.88, "HIGH"),
    Detector("GENERIC_API_KEY", "Generic API Key", "API_KEY", r"(?i)\bapi[_-]?key[\"'\s:=]+([A-Za-z0-9_\-]{16,})", 0.70, "MEDIUM"),
    Detector("GENERIC_SECRET", "Generic Secret", "GENERIC_SECRET", r"(?i)\bsecret[\"'\s:=]+([A-Za-z0-9_\-\.~\+/]{12,})", 0.60, "MEDIUM"),
    Detector("PASSWORD_ASSIGN", "Password Assignment", "PASSWORD", r"(?i)\bpassword[\"'\s:=]+([^\s\"',;]{6,})", 0.65, "MEDIUM"),
    Detector("WEBHOOK_SECRET", "Webhook Secret", "API_KEY", r"(?i)webhook[_-]?secret[\"'\s:=]+([A-Za-z0-9_\-]{12,})", 0.72, "MEDIUM"),
    Detector("OAUTH_SECRET", "OAuth Secret", "API_KEY", r"(?i)oauth[_-]?(?:client[_-]?secret)?[\"'\s:=]+([A-Za-z0-9_\-]{12,})", 0.65, "MEDIUM"),
    Detector("AZURE_KEY", "Azure Credential", "AZURE_CREDENTIAL", r"(?i)(?:azure|account[_-]?key)[\"'\s:=]+([A-Za-z0-9+/=]{44,})", 0.80, "HIGH"),
    Detector("PII_EMAIL", "Email Address (PII)", "PII_EMAIL", r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", 0.60, "LOW"),
    Detector("PII_PHONE", "Phone Number (PII)", "PII_PHONE", r"(?<!\d)(?:\+?1[\s.\-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}(?!\d)", 0.55, "LOW"),
    Detector("PII_IP", "IP Address (PII)", "PII_IP", r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b", 0.40, "LOW"),
    Detector("PII_CREDIT_CARD", "Credit Card (PII)", "PII_CREDIT_CARD", r"\b(?:\d[ \-]?){13,19}\b", 0.70, "MEDIUM"),
]


def scan_line(line: str) -> list[tuple[Detector, str, int]]:
    out: list[tuple[Detector, str, int]] = []
    for d in DETECTORS:
        for m in d._rx.finditer(line or ""):
            val = m.group(0)
            if d.id == "PII_CREDIT_CARD" and not validate(d.id, val):
                continue
            if d.id == "JWT" and not validate(d.id, val):
                continue
            out.append((d, val, m.start()))
    return out
