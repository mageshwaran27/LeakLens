"""Feature helpers shared by training and inference.

Sets (schema v1.1.0):
  statistical: entropy, length, entropy_x_len, upper_ratio, digit_ratio,
               special_ratio, unique_ratio
  context:     has_auth_kw, has_placeholder, is_test, is_docs, is_prod, has_equals
  detector:    det_aws, det_github, det_stripe, det_slack, det_privkey, det_jwt,
               det_dburl, det_bearer, det_hex40, det_long_token
Detector bits are non-exfiltrating pattern hits (no values stored).
"""
from __future__ import annotations

import math
import re
from collections import Counter

FEATURE_VERSION = "1.1.0"

PATTERNS = {
    "det_aws": re.compile(r"AKIA[0-9A-Z]{12,}"),
    "det_github": re.compile(r"gh[pousr]_|github_pat_"),
    "det_stripe": re.compile(r"sk_(live|test)_"),
    "det_slack": re.compile(r"xox[bpar]-|xapp-"),
    "det_privkey": re.compile(r"BEGIN[^\n]*PRIVATE KEY"),
    "det_jwt": re.compile(r"eyJ[A-Za-z0-9\-_]{10,}\."),
    "det_dburl": re.compile(r"(postgresql|mysql|mongodb)(\+\w+)?://", re.IGNORECASE),
    "det_bearer": re.compile(r"Bearer\s+[A-Za-z0-9\-_~+/=]{16,}", re.IGNORECASE),
    "det_hex40": re.compile(r"\b[0-9a-fA-F]{32,}\b"),
    "det_long_token": re.compile(r"[A-Za-z0-9\-_~+/=]{24,}"),
}


def shannon(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def featurize_text(line: str, file_path: str, var: str, entropy: float) -> dict:
    blob = f"{var} {line} {file_path}".lower()
    lp = (file_path or "").lower()
    line_s = line or ""
    n = max(1, len(line_s))
    feats = {
        "entropy": entropy,
        "length": len(line_s),
        "entropy_x_len": entropy * len(line_s) / 100.0,
        "has_auth_kw": int(any(k in blob for k in ["auth", "token", "secret", "password", "credential", "api_key", "bearer"])),
        "has_placeholder": int(bool(re.search(r"(example|placeholder|dummy|fake|xxx|change[_-]?me|your_|<[^>]+>|sample|mock)", blob))),
        "is_test": int(any(k in lp for k in ["test", "spec", "fixture", "mock"])),
        "is_docs": int(any(k in lp for k in ["readme", "docs/", ".md", "tutorial"])),
        "is_prod": int(any(k in blob or k in lp for k in ["prod", "release", "deploy", "kubernetes", ".env", "database"])),
        "has_equals": int("=" in line_s or ":" in line_s),
        "upper_ratio": sum(1 for c in line_s if c.isupper()) / n,
        "digit_ratio": sum(1 for c in line_s if c.isdigit()) / n,
        "special_ratio": sum(1 for c in line_s if not c.isalnum() and not c.isspace()) / n,
        "unique_ratio": len(set(line_s)) / n,
    }
    for name, rx in PATTERNS.items():
        feats[name] = int(bool(rx.search(line_s)))
    return feats


NUMERIC_KEYS = ["entropy", "length", "entropy_x_len", "has_auth_kw", "has_placeholder",
                "is_test", "is_docs", "is_prod", "has_equals", "upper_ratio", "digit_ratio",
                "special_ratio", "unique_ratio",
                "det_aws", "det_github", "det_stripe", "det_slack", "det_privkey",
                "det_jwt", "det_dburl", "det_bearer", "det_hex40", "det_long_token"]


FEATURE_SETS = {
    "statistical": ["entropy", "length", "entropy_x_len", "upper_ratio",
                    "digit_ratio", "special_ratio", "unique_ratio"],
    "context": ["has_auth_kw", "has_placeholder", "is_test", "is_docs",
                "is_prod", "has_equals"],
    "detector": ["det_aws", "det_github", "det_stripe", "det_slack", "det_privkey",
                 "det_jwt", "det_dburl", "det_bearer", "det_hex40", "det_long_token"],
}


def feature_schema() -> dict:
    return {"feature_version": FEATURE_VERSION, "keys": list(NUMERIC_KEYS),
            "sets": {k: list(v) for k, v in FEATURE_SETS.items()},
            "note": "Detector bits are regex pattern hits; no secret values stored."}


def to_vector(d: dict) -> list[float]:
    return [float(d[k]) for k in NUMERIC_KEYS]
