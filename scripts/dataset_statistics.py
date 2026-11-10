"""Dataset statistics -> datasets/reports/{dataset_statistics,class_distribution}.json + quality_report.html.

Uses ACTUAL generated rows only (stdlib json/csv; no pandas).
"""
from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTDIR = ROOT / "datasets" / "reports"


def load(name: str) -> list[dict]:
    p = ROOT / "datasets" / name / "dataset.jsonl"
    if name == "hard_negative_test":
        p = ROOT / "datasets" / "processed" / "hard_negative_test.jsonl"
    if not p.exists():
        return []
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]


def describe(rows: list[dict]) -> dict:
    return {"rows": len(rows),
            "positives": sum(r.get("contains_secret", r.get("is_positive", 0)) for r in rows),
            "labels": dict(Counter(r.get("context_label", r.get("label")) for r in rows)),
            "categories": dict(Counter(r.get("secret_type", r.get("category")) for r in rows)),
            "languages": dict(Counter(r.get("language", "?") for r in rows)),
            "file_exts": dict(Counter(r.get("file_ext", "?") for r in rows)),
            "sources": dict(Counter(r.get("source", "?") for r in rows))}


def main() -> dict:
    OUTDIR.mkdir(parents=True, exist_ok=True)
    stats = {n: describe(load(n)) for n in ("train", "validation", "test", "hard_negative_test")}
    for r in stats.values():
        r["negatives"] = r["rows"] - r["positives"]
    (OUTDIR / "dataset_statistics.json").write_text(json.dumps(stats, indent=2))
    dist = {n: {"positive_share": (v["positives"] / v["rows"]) if v["rows"] else 0,
                "positives": v["positives"], "negatives": v["negatives"]}
            for n, v in stats.items()}
    (OUTDIR / "class_distribution.json").write_text(json.dumps(dist, indent=2))
    (OUTDIR / "quality_report.html").write_text(
        "<!DOCTYPE html><html><head><meta charset='utf-8'><title>LeakLens dataset quality</title></head>"
        f"<body><h1>LeakLens dataset quality (measured)</h1><pre>{html.escape(json.dumps(stats, indent=2))}</pre></body></html>")
    print(json.dumps(dist, indent=2))
    return stats


if __name__ == "__main__":
    main()
