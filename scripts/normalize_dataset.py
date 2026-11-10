"""Normalize + schema-validate merged dataset -> datasets/normalized/dataset.jsonl.

Required fields: record_id/text/contains_secret/secret_type/context_label.
Legacy v1 rows (label/is_positive) are mapped onto the v2 schema.
Rejects rows with missing/invalid fields; reports counts.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SECRET_TYPES = {"AWS_CREDENTIAL", "GITHUB_TOKEN", "GOOGLE_CREDENTIAL",
                "AZURE_CREDENTIAL", "SLACK_TOKEN", "STRIPE_SECRET",
                "DATABASE_CREDENTIAL", "PRIVATE_KEY", "JWT", "BEARER_TOKEN",
                "API_KEY", "PASSWORD", "GENERIC_SECRET", "PII_EMAIL",
                "PII_PHONE", "PII_IP", "PII_CREDIT_CARD"}
CONTEXTS = {"REAL_SECRET", "PLACEHOLDER", "EXAMPLE_SECRET", "TEST_SECRET",
            "DOCUMENTATION_EXAMPLE", "HIGH_ENTROPY_NON_SECRET",
            "FALSE_POSITIVE", "BENIGN_CONFIG"}
LEGACY_TO_CONTEXT = {"TRUE_SECRET": "REAL_SECRET", "TRUE_PII": "REAL_SECRET",
                     "PLACEHOLDER": "PLACEHOLDER", "EXAMPLE": "EXAMPLE_SECRET",
                     "TEST_SECRET": "TEST_SECRET", "DOCUMENTATION": "DOCUMENTATION_EXAMPLE",
                     "BENIGN_HIGH_ENTROPY": "HIGH_ENTROPY_NON_SECRET",
                     "BENIGN_CONFIG": "BENIGN_CONFIG", "FALSE_POSITIVE": "FALSE_POSITIVE"}


def normalize_row(r: dict, i: int) -> dict | None:
    r = dict(r)
    if not r.get("text"):
        return None
    if "contains_secret" not in r:
        if r.get("label") in LEGACY_TO_CONTEXT:
            r["context_label"] = LEGACY_TO_CONTEXT[r["label"]]
            r["contains_secret"] = 1 if r["label"] in ("TRUE_SECRET", "TRUE_PII") else 0
        else:
            return None
    if r.get("secret_type") not in SECRET_TYPES or r.get("context_label") not in CONTEXTS:
        return None
    r["contains_secret"] = int(bool(r["contains_secret"]))
    r.setdefault("record_id", f"row-{i:07d}")
    r.setdefault("language", "unknown")
    r.setdefault("file_ext", "")
    r.setdefault("leak_group", r.get("group", r["record_id"]))
    r.setdefault("template_id", "unknown")
    r.setdefault("synthetic", r.get("source_type") == "synthetic")
    r["text"] = r["text"][:2000]
    return r


def main() -> dict:
    src = ROOT / "datasets" / "processed" / "dataset.jsonl"
    out = ROOT / "datasets" / "normalized" / "dataset.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    if not src.exists():
        print("No processed dataset; run build_dataset.py first")
        return {"rows": 0}
    n, bad = 0, 0
    with open(src, encoding="utf-8") as fin, open(out, "w", encoding="utf-8") as fout:
        for i, line in enumerate(fin):
            if not line.strip():
                continue
            r = normalize_row(json.loads(line), i)
            if r is None:
                bad += 1
                continue
            fout.write(json.dumps(r) + "\n")
            n += 1
    print(f"Normalized {n} rows, rejected {bad} -> {out}")
    return {"rows": n, "rejected": bad}


if __name__ == "__main__":
    main()
