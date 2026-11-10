"""Validate dataset integrity + QUALITY GATES. Exits 1 on failure.

Gates (fail): empty data, invalid labels, >5% missing fields,
minority class < 35% (severe imbalance), overlapping leak_groups across
existing splits, destructive redaction detected (positives containing
"[REDACTED]").
Writes reports/dataset_quality_report.json (+ .html).
"""
from __future__ import annotations

import html
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTEXTS = {"REAL_SECRET", "PLACEHOLDER", "EXAMPLE_SECRET", "TEST_SECRET",
            "DOCUMENTATION_EXAMPLE", "HIGH_ENTROPY_NON_SECRET",
            "FALSE_POSITIVE", "BENIGN_CONFIG"}


def load_rows():
    for cand in (ROOT / "datasets" / "processed" / "dataset_dedup.jsonl",
                 ROOT / "datasets" / "normalized" / "dataset.jsonl",
                 ROOT / "datasets" / "processed" / "dataset.jsonl"):
        if cand.exists():
            return ([json.loads(l) for l in cand.read_text(encoding="utf-8").splitlines() if l.strip()], cand)
    return [], ROOT / "datasets" / "processed" / "dataset.jsonl"


def main() -> dict:
    rows, src = load_rows()
    errors, warnings = [], []
    labels = Counter(r.get("context_label", r.get("label")) for r in rows)
    if not rows:
        errors.append("Dataset is empty — run generate_synthetic_data.py + build_dataset.py first")
    bad = [l for l in labels if l not in CONTEXTS]
    if bad:
        errors.append(f"Invalid context labels: {bad}")
    missing = sum(1 for r in rows if not r.get("text") or r.get("contains_secret", r.get("is_positive")) is None)
    if missing > max(1, len(rows) * 0.05):
        errors.append(f"{missing} rows missing text/label (>5%)")
    pos = sum(1 for r in rows if r.get("contains_secret", r.get("is_positive", 0)))
    if rows:
        ratio = pos / len(rows)
        if min(ratio, 1 - ratio) < 0.35:
            errors.append(f"Severe class imbalance: {ratio:.1%} positive (gate: minority >= 35%)")
        elif min(ratio, 1 - ratio) < 0.45:
            warnings.append(f"Class balance {ratio:.1%} positive is outside the 45-55% target")
    redacted_pos = sum(1 for r in rows if "[REDACTED]" in r.get("text", "")
                       and r.get("contains_secret", r.get("is_positive", 0)))
    if redacted_pos:
        errors.append(f"Destructive redaction detected: {redacted_pos} positives contain [REDACTED]")
    # split overlap check
    for a, b in (("train", "test"), ("train", "validation"), ("validation", "test")):
        pa, pb = ROOT / "datasets" / a / "dataset.jsonl", ROOT / "datasets" / b / "dataset.jsonl"
        if pa.exists() and pb.exists():
            ga = {json.loads(l).get("leak_group") for l in pa.read_text(encoding="utf-8").splitlines() if l.strip()}
            gb = {json.loads(l).get("leak_group") for l in pb.read_text(encoding="utf-8").splitlines() if l.strip()}
            if ga & gb:
                errors.append(f"Split leakage: {len(ga & gb)} leak_groups shared between {a} and {b}")
    report = {"source_file": str(src), "total": len(rows), "positives": pos,
              "negatives": len(rows) - pos, "labels": dict(labels),
              "sources": dict(Counter(r.get("source", "?") for r in rows)),
              "languages": dict(Counter(r.get("language", "?") for r in rows)),
              "errors": errors, "warnings": warnings,
              "gates_passed": not errors}
    out = ROOT / "reports" / "dataset_quality_report.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    (ROOT / "reports" / "dataset_quality_report.html").write_text(
        "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Dataset quality</title></head><body>"
        f"<h1>Dataset quality</h1><pre>{html.escape(json.dumps(report, indent=2))}</pre></body></html>")
    print(json.dumps(report, indent=2))
    if errors:
        sys.exit(1)
    return report


if __name__ == "__main__":
    main()
