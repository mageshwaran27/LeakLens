"""Layered deduplication (stdlib only).

L1 exact: sha1(normalized_text | language | file_ext | file_type | context_label).
L2 context-aware: identical text with a DIFFERENT (file_ext, context_label) is a
   legitimate distinct example and is PRESERVED (recorded, not removed).
L3 near-duplicate: MinHash (64 hashes, word-3-shingles) + LSH banding, Jaccard
   >= 0.85 removes the later row — but only within the same (category,
   file_ext, context_label), so L2 preservation always wins.
L4 template/repository groups: leak_group values are recorded with sizes for
   leakage-safe splitting; nothing is removed at this level.

Outputs: datasets/processed/dataset_dedup.jsonl,
         datasets/reports/duplicate_report.json,
         datasets/manifests/leakage_audit.json (split-overlap section filled
         in later by split_dataset.py).
"""
from __future__ import annotations

import hashlib
import json
import re
import zlib
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEDUP_OUT = ROOT / "datasets" / "processed" / "dataset_dedup.jsonl"
NEAR_DUP_JACCARD = 0.8

WS = re.compile(r"\s+")


def norm_text(t: str) -> str:
    return WS.sub(" ", (t or "").strip())


def l1_key(r: dict) -> str:
    return hashlib.sha1("|".join([
        norm_text(r.get("text", "")), r.get("language", ""),
        r.get("file_ext", ""), r.get("file_type", ""),
        r.get("context_label", "")]).encode()).hexdigest()


def shingles(text: str) -> set[str]:
    """Character shingles (credential lines are often a single token, so word
    shingles miss near-identical values). Short texts: 5-grams/step 1 for
    sensitivity; long texts: 8-grams/step 3 for speed."""
    t = norm_text(text)
    if len(t) < 5:
        return {t}
    k, step = (5, 1) if len(t) <= 400 else (8, 3)
    return {t[i:i + k] for i in range(0, len(t) - k + 1, step)}


def minhash(sig: set[str], n: int = 32) -> list[int]:
    """Fast MinHash via crc32 shingle hashes + integer permutations."""
    vals = [zlib.crc32(s.encode()) & 0xFFFFFFFF for s in sig]
    out: list[int] = []
    for i in range(n):
        a = (0x9E3779B1 + i * 0x85EBCA6B) & 0xFFFFFFFF
        b = (i * 0xC2B2AE35 + 7) & 0xFFFFFFFF
        m = 0xFFFFFFFF
        for v in vals:
            h = (a * v + b) & 0xFFFFFFFF
            if h < m:
                m = h
        out.append(m)
    return out


def lsh_candidates(hashes: list[list[int]], bands: int = 8) -> set[tuple[int, int]]:
    rows = len(hashes[0]) // bands
    buckets: dict[tuple, list[int]] = defaultdict(list)
    for idx, h in enumerate(hashes):
        for b in range(bands):
            buckets[(b, tuple(h[b * rows:(b + 1) * rows]))].append(idx)
    pairs: set[tuple[int, int]] = set()
    for members in buckets.values():
        if len(members) > 1:
            for a in range(len(members)):
                for c in range(a + 1, len(members)):
                    pairs.add((members[a], members[c]))
    return pairs


def jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def analyze(rows: list[dict]) -> dict:
    # L1
    seen: dict[str, int] = {}
    l1_dup_idx: set[int] = set()
    for i, r in enumerate(rows):
        k = l1_key(r)
        if k in seen:
            l1_dup_idx.add(i)
        else:
            seen[k] = i
    # L2: same text, different (ext, context) — preserved
    by_text: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for r in rows:
        by_text[norm_text(r.get("text", ""))].add((r.get("file_ext", ""), r.get("context_label", "")))
    l2_preserved = sum(1 for v in by_text.values() if len(v) > 1)
    # L3: MinHash LSH within (category, ext, context) buckets
    keep = [i for i in range(len(rows)) if i not in l1_dup_idx]
    buckets: dict[tuple, list[int]] = defaultdict(list)
    for i in keep:
        r = rows[i]
        buckets[(r.get("category", ""), r.get("file_ext", ""),
                 r.get("context_label", ""))].append(i)
    l3_dup_idx: set[int] = set()
    for members in buckets.values():
        if len(members) < 2:
            continue
        sigs = [shingles(rows[i].get("text", "")) for i in members]
        hashes = [minhash(s) for s in sigs]
        for a, b in lsh_candidates(hashes):
            ia, ib = members[a], members[b]
            if ia in l3_dup_idx or ib in l3_dup_idx:
                continue
            if jaccard(sigs[a], sigs[b]) >= NEAR_DUP_JACCARD:
                l3_dup_idx.add(max(ia, ib))
    # L4: group inventory (leak_group for splitting + template_id families)
    groups: dict[str, int] = defaultdict(int)
    templates: dict[str, int] = defaultdict(int)
    for r in rows:
        groups[str(r.get("leak_group", "?"))] += 1
        templates[str(r.get("template_id", "?"))] += 1
    return {"l1_dup_idx": l1_dup_idx, "l2_preserved_texts": l2_preserved,
            "l3_dup_idx": l3_dup_idx, "groups": dict(groups),
            "templates": dict(templates)}


def main() -> dict:
    src = ROOT / "datasets" / "normalized" / "dataset.jsonl"
    if not src.exists():
        print("Nothing to dedup; run normalize_dataset.py first")
        return {"rows": 0}
    rows = [json.loads(l) for l in src.read_text(encoding="utf-8").splitlines() if l.strip()]
    res = analyze(rows)
    drop = res["l1_dup_idx"] | res["l3_dup_idx"]
    kept = [r for i, r in enumerate(rows) if i not in drop]
    with open(DEDUP_OUT, "w", encoding="utf-8") as fh:
        for r in kept:
            fh.write(json.dumps(r) + "\n")
    report = {"input_rows": len(rows),
              "exact_duplicates_removed": len(res["l1_dup_idx"]),
              "context_preserving_duplicates_removed": 0,
              "context_variants_preserved": res["l2_preserved_texts"],
              "near_duplicates_removed": len(res["l3_dup_idx"]),
              "final_rows": len(kept),
              "duplicate_groups": len(res["l1_dup_idx"]) + len(res["l3_dup_idx"]),
              "leak_groups": len(res["groups"]),
              "template_family_groups": len(res["templates"]),
              "template_family_sizes": dict(sorted(res["templates"].items(),
                                                   key=lambda kv: -kv[1])[:40]),
              "repository_template_groups": len(res["templates"]),
              "percentage_removed": round(100 * len(drop) / max(1, len(rows)), 2),
              "note": ("L2 context variants (identical text, different file_ext/context_label) "
                       "are preserved, never removed.")}
    for rep in (ROOT / "datasets" / "manifests" / "duplicate_report.json",
                ROOT / "datasets" / "reports" / "duplicate_report.json"):
        rep.parent.mkdir(parents=True, exist_ok=True)
        rep.write_text(json.dumps(report, indent=2))
    audit_p = ROOT / "datasets" / "manifests" / "leakage_audit.json"
    audit = json.loads(audit_p.read_text()) if audit_p.exists() else {}
    audit.update({"exact_duplicates": report["exact_duplicates_removed"],
                  "near_duplicates": report["near_duplicates_removed"],
                  "context_variants_preserved": report["context_variants_preserved"],
                  "repository_groups": len(res["groups"]),
                  "template_groups": dict(res["templates"]),
                  "credential_family_groups": "n/a (synthetic values unique by construction)"})
    audit_p.parent.mkdir(parents=True, exist_ok=True)
    audit_p.write_text(json.dumps(audit, indent=2))
    print(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    main()
