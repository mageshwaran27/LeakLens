"""Context extraction + transparent risk classification."""
from __future__ import annotations

import os
import re

from backend.app.detection.entropy import charset_score, shannon_entropy

POSITIVE_VARS = ["production", "prod", "database", "db_", "password", "passwd", "pwd", "secret",
                 "credential", "api_key", "apikey", "token", "private_key", "auth", "authorization",
                 "bearer", "stripe", "aws", "github"]
NEGATIVE_HINTS = ["example", "sample", "placeholder", "dummy", "test", "mock", "fixture",
                  "documentation", "readme", "your_", "change_me", "changeme", "<", "xxx",
                  "todo", "fake", "docs/", "doc/"]
PROD_HINTS = ["production", "prod", "release", "live", "deploy", "kubernetes", "k8s",
              "terraform", "docker", ".env", "application.properties", "application.yml"]

RECOMMENDATIONS = {
    "AWS_CREDENTIAL": "Remove the credential, rotate it in AWS IAM, and move it to a secrets manager.",
    "GITHUB_TOKEN": "Revoke the token on GitHub, remove it from source, use environment injection.",
    "PRIVATE_KEY": "Remove the private key, rotate the keypair, never commit key material.",
    "DATABASE_CREDENTIAL": "Rotate the database password, move connection strings to a vault.",
    "PASSWORD": "Remove hardcoded password and use a secrets manager.",
}


def extract_context(file_path: str, var_name: str, line: str, nearby: list[str]) -> dict:
    lp = (file_path or "").lower().replace("\\", "/")
    blob = " ".join([var_name or "", line or "", *nearby]).lower()
    return {
        "filename": os.path.basename(file_path or ""),
        "extension": os.path.splitext(file_path or "")[1].lower(),
        "directory": os.path.dirname(file_path or ""),
        "variable": var_name or "",
        "is_test": any(t in lp for t in ["test", "tests", "spec", "fixture", "mock", "__tests__"]),
        "is_docs": any(t in lp for t in ["readme", "docs/", "doc/", ".md", "tutorial", "guide"]),
        "is_example": any(t in blob for t in NEGATIVE_HINTS),
        "is_production": any(t in lp or t in blob for t in PROD_HINTS),
        "has_auth_kw": any(t in blob for t in ["auth", "bearer", "token", "credential", "password", "database"]),
        "has_placeholder": bool(re.search(r"(example|placeholder|dummy|fake|xxx|change[_-]?me|your_|<[^>]+>)", blob)),
    }


def guess_variable(line: str) -> str:
    m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_\-\.]*)\s*[:=]", line or "")
    return m.group(1) if m else ""


def classify(detector_conf: float, entropy: float, value_len: int, ctx: dict,
             validator_ok: bool, charset: float) -> tuple[str, float, str, list[str]]:
    evidence: list[str] = []
    score = detector_conf * 0.55
    if entropy >= 4.5:
        score += 0.12
        evidence.append("High entropy value")
    elif entropy >= 3.5:
        score += 0.06
        evidence.append("Moderate entropy value")
    if charset >= 0.75 and value_len >= 16:
        score += 0.05
        evidence.append("Mixed character set typical of generated secrets")
    if ctx.get("has_auth_kw"):
        score += 0.08
        evidence.append("Authentication/credential keyword nearby")
    if ctx.get("is_production"):
        score += 0.10
        evidence.append("Located in production/environment configuration")
    if validator_ok:
        score += 0.05
        evidence.append("Value passes structural validation")
    context_type = "REAL_SECRET"
    if ctx.get("has_placeholder"):
        score -= 0.30
        context_type = "PLACEHOLDER"
        evidence.append("Placeholder/example indicator present — confidence reduced")
    elif ctx.get("is_docs"):
        score -= 0.18
        context_type = "DOCUMENTATION_EXAMPLE"
        evidence.append("Located in documentation — confidence reduced")
    elif ctx.get("is_test"):
        score -= 0.12
        context_type = "TEST_SECRET"
        evidence.append("Located in tests/fixtures — confidence reduced")
    if ctx.get("is_example") and context_type == "REAL_SECRET":
        context_type = "EXAMPLE_SECRET"
    score = max(0.0, min(0.99, score))
    severity = "HIGH" if score >= 0.75 else ("MEDIUM" if score >= 0.45 else "LOW")
    return severity, round(score, 2), context_type, evidence
