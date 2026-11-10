"""Dataset safety audit — AUDIT ONLY by default.

Training-data safety: synthetic/non-functional rows keep their secret-like
values (the model must see the pattern). Production safety: real secrets must
never reach logs/DB/API/reports — enforced in backend/app/core/redaction.py.

Default mode scans the dataset, classifies secret-looking rows, and writes
reports/dataset/redaction_audit.json WITHOUT modifying anything.

Destructive mode (only for non-synthetic sources, never synthetic):

    python scripts/redact_dataset.py --sanitize

Schema of the audit report:

    {mode, rows_scanned, potentially_sensitive_rows, synthetic_rows,
     external_rows, redaction_performed, reasons, file}
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from _bootstrap import ensure_root

ensure_root()

from backend.app.core.redaction import redact_text  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "reports" / "dataset" / "redaction_audit.json"


def _reason(text: str) -> str:
    t = text or ""
    if "AKIA" in t:
        return "aws_like"
    if "BEGIN" in t and "PRIVATE KEY" in t:
        return "private_key_like"
    if "ghp_" in t or "gho_" in t:
        return "github_like"
    if "sk_live" in t or "sk_test" in t:
        return "stripe_like"
    if "xox" in t:
        return "slack_like"
    if "postgres://" in t or "mysql://" in t or "mongodb" in t:
        return "database_url_like"
    if "eyJ" in t:
        return "jwt_like"
    if "@" in t:
        return "pii_email_like"
    return "other_sensitive_like"


def _load_rows() -> tuple[list[dict], Path]:
    for cand in (ROOT / "datasets" / "processed" / "dataset_dedup.jsonl",
                 ROOT / "datasets" / "normalized" / "dataset.jsonl",
                 ROOT / "datasets" / "processed" / "dataset.jsonl"):
        if cand.exists():
            return ([json.loads(l) for l in cand.read_text(encoding="utf-8").splitlines() if l.strip()], cand)
    return [], ROOT / "datasets" / "processed" / "dataset_dedup.jsonl"


def main(sanitize: bool = False) -> dict:
    rows, src = _load_rows()
    sensitive = [r for r in rows if redact_text(r.get("text", "")) != r.get("text", "")]
    reasons = Counter(_reason(r.get("text", "")) for r in sensitive)
    report = {
        "mode": "sanitize" if sanitize else "audit_only",
        "file": str(src),
        "rows_scanned": len(rows),
        "potentially_sensitive_rows": len(sensitive),
        "synthetic_rows": sum(1 for r in rows if r.get("source_type") == "synthetic" or r.get("synthetic")),
        "external_rows": sum(1 for r in rows if r.get("source_type") not in ("synthetic", None) or r.get("external")),
        "redaction_performed": False,
        "redacted": 0,
        "reasons": dict(reasons),
        "note": "Synthetic rows are non-functional test values and are preserved for training.",
    }
    if sanitize:
        kept = [r for r in rows if r.get("source_type") == "synthetic" or r.get("synthetic")]
        changed = [r for r in rows if r not in kept]
        for r in changed:
            red = redact_text(r.get("text", ""))
            if red != r.get("text", ""):
                r["text"] = red
                report["redacted"] += 1
        src.write_text("\n".join(json.dumps(r) for r in rows) + ("\n" if rows else ""), encoding="utf-8")
        report["redaction_performed"] = True
        report["note"] = (f"Sanitized {report['redacted']} non-synthetic rows in {src}; "
                          f"{len(kept)} synthetic rows preserved untouched.")
    AUDIT.parent.mkdir(parents=True, exist_ok=True)
    AUDIT.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--sanitize", action="store_true",
                    help="Redact secret-looking text in NON-SYNTHETIC rows only. Never touches synthetic rows.")
    ap.add_argument("--apply", action="store_true", help="Deprecated alias of --sanitize.")
    a = ap.parse_args()
    main(sanitize=bool(a.sanitize or a.apply))
