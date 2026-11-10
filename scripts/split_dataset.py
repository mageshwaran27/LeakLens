"""Group-aware 70/15/15 split on `leak_group` (no group crosses splits).

Writes datasets/{train,validation,test}/dataset.jsonl + legacy splits/*.json,
datasets/processed/hard_negative_test.jsonl (from the eval-only holdout file),
and datasets/manifests/split_manifest.json. FAILS (exit 1) if any leak_group
appears in more than one split.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(8 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main(train: float = 0.70, val: float = 0.15, seed: int = 42) -> dict:
    src = ROOT / "datasets" / "processed" / "dataset_dedup.jsonl"
    if not src.exists():
        src = ROOT / "datasets" / "normalized" / "dataset.jsonl"
    rows = [json.loads(l) for l in src.read_text(encoding="utf-8").splitlines() if l.strip()]
    groups: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        groups[str(r.get("leak_group", r.get("group", r["record_id"])))].append(r)
    keys = sorted(groups)
    random.Random(seed).shuffle(keys)
    n = len(keys)
    n_tr, n_va = int(n * train), int(n * val)
    parts = {"train": keys[:n_tr], "validation": keys[n_tr:n_tr + n_va], "test": keys[n_tr + n_va:]}
    # overlap gate
    sets = {k: set(v) for k, v in parts.items()}
    leaks = (sets["train"] & sets["validation"]) | (sets["train"] & sets["test"]) | (sets["validation"] & sets["test"])
    if leaks:
        print(f"FATAL: {len(leaks)} leak_groups cross splits, e.g. {sorted(leaks)[:5]}")
        sys.exit(1)
    manifest = {"seed": seed, "ratios": {"train": train, "validation": val,
                                         "test": round(1 - train - val, 4)},
                "source_dataset": str(src),
                "source_dataset_sha256": sha256_file(src),
                "source_rows": len(rows),
                "method": "group-aware shuffle on leak_group (no group crosses splits)",
                "splits": {}, "overlap_check": {"leaked_groups": 0, "passed": True}}
    for name, ks in parts.items():
        recs = [r for k in ks for r in groups[k]]
        d = ROOT / "datasets" / name / "dataset.jsonl"
        d.parent.mkdir(parents=True, exist_ok=True)
        blob = "\n".join(json.dumps(r) for r in recs) + ("\n" if recs else "")
        d.write_text(blob, encoding="utf-8")
        # canonical group-aware split copies (Phase 4 layout)
        (ROOT / "datasets" / "splits" / f"{name}.jsonl").write_text(blob, encoding="utf-8")
        (ROOT / "datasets" / "splits" / f"{name}.json").parent.mkdir(parents=True, exist_ok=True)
        (ROOT / "datasets" / "splits" / f"{name}.json").write_text(
            json.dumps({"groups": ks, "rows": len(recs)}, indent=2))
        pos = sum(r.get("contains_secret", r.get("is_positive", 0)) for r in recs)
        manifest["splits"][name] = {
            "rows": len(recs), "groups": len(ks),
            "positives": pos, "negatives": len(recs) - pos,
            "positive_pct": round(100 * pos / max(1, len(recs)), 2),
            "negative_pct": round(100 * (len(recs) - pos) / max(1, len(recs)), 2),
            "labels": dict(Counter(r.get("context_label", r.get("label")) for r in recs)),
            "categories": dict(Counter(r.get("secret_type", r.get("category")) for r in recs)),
            "sources": dict(Counter(r.get("source", "?") for r in recs)),
            "languages": dict(Counter(r.get("language", "?") for r in recs))}
    # eval-only hard-negative holdout (never trained on, never tuned on)
    hold = ROOT / "datasets" / "synthetic" / "hardneg_holdout.jsonl"
    hn_dest = ROOT / "datasets" / "processed" / "hard_negative_test.jsonl"
    if hold.exists():
        hn_dest.write_text(hold.read_text(encoding="utf-8"), encoding="utf-8")
        manifest["hard_negative_test"] = {"rows": sum(1 for _ in hold.read_text(encoding="utf-8").splitlines() if _.strip()),
                                          "eval_only": True}
    man_p = ROOT / "datasets" / "manifests" / "split_manifest.json"
    man_p.parent.mkdir(parents=True, exist_ok=True)
    man_p.write_text(json.dumps(manifest, indent=2))
    audit_p = ROOT / "datasets" / "manifests" / "leakage_audit.json"
    audit = json.loads(audit_p.read_text()) if audit_p.exists() else {}
    audit["split_leakage_checks"] = {"leaked_groups": 0, "passed": True, "method": "leak_group disjointness"}
    audit_p.write_text(json.dumps(audit, indent=2))
    print(json.dumps({k: v["rows"] for k, v in manifest["splits"].items()}, indent=2))
    return manifest


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", type=float, default=0.70)
    ap.add_argument("--val", type=float, default=0.15)
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    main(a.train, a.val, a.seed)
