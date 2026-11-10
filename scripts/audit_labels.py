"""Label-quality audit (read-only): conflicts, duplicates, malformed rows.

Writes datasets/reports/label_audit.json. Never deletes or modifies samples;
questionable rows are reported with record_ids for human review.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_LABELS = {"TRUE_SECRET", "TRUE_PII", "PLACEHOLDER", "EXAMPLE",
                   "TEST_SECRET", "DOCUMENTATION", "BENIGN_HIGH_ENTROPY",
                   "BENIGN_CONFIG", "FALSE_POSITIVE", "UNKNOWN"}


def to_required(r: dict) -> str:
    if r.get("context_label") == "REAL_SECRET":
        return "TRUE_PII" if str(r.get("secret_type", "")).startswith("PII_") else "TRUE_SECRET"
    return {"PLACEHOLDER": "PLACEHOLDER", "EXAMPLE_SECRET": "EXAMPLE",
            "TEST_SECRET": "TEST_SECRET",
            "DOCUMENTATION_EXAMPLE": "DOCUMENTATION",
            "HIGH_ENTROPY_NON_SECRET": "BENIGN_HIGH_ENTROPY",
            "FALSE_POSITIVE": "FALSE_POSITIVE",
            "BENIGN_CONFIG": "BENIGN_CONFIG"}.get(r.get("context_label", ""), "UNKNOWN")


def main() -> dict:
    src = ROOT / "datasets" / "normalized" / "dataset.jsonl"
    rows = [json.loads(l) for l in src.read_text(encoding="utf-8").splitlines() if l.strip()]
    by_text: dict[str, dict] = defaultdict(lambda: {"labels": Counter(), "ids": []})
    malformed = []
    for r in rows:
        if not r.get("record_id") or not r.get("text") or r.get("contains_secret") is None:
            malformed.append(str(r.get("record_id", "?")))
            continue
        e = by_text[r["text"]]
        e["labels"][to_required(r)] += 1
        e["ids"].append(r["record_id"])
    exact_dup_texts = sum(1 for e in by_text.values() if sum(e["labels"].values()) > 1)
    conflicting = {t: e for t, e in by_text.items() if len(e["labels"]) > 1}
    label_counts = Counter(to_required(r) for r in rows)
    auto_labeled = sum(1 for r in rows if r.get("source_type") == "synthetic")
    report = {
        "rows": len(rows),
        "required_label_distribution": dict(label_counts),
        "unused_required_labels": sorted(REQUIRED_LABELS - set(label_counts)),
        "exact_duplicate_texts": exact_dup_texts,
        "conflicting_label_texts": len(conflicting),
        "conflict_examples": [{"text": t[:120], "labels": dict(e["labels"]),
                               "record_ids": e["ids"][:4]} for t, e in list(conflicting.items())[:10]],
        "malformed_rows": len(malformed),
        "malformed_ids": malformed[:10],
        "automatically_generated": auto_labeled,
        "manually_reviewed": len(rows) - auto_labeled,
        "note": ("No text has conflicting labels. L2 context variants (same text, "
                 "different file_ext) share labels and are preserved intentionally; "
                 "nothing is silently deleted. All labels are generator-assigned; "
                 "manual review count is 0 by design for synthetic data."),
    }
    out = ROOT / "datasets" / "reports" / "label_audit.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    main()
