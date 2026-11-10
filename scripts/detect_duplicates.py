"""Report-only duplicate/leakage analysis on the normalized dataset.

Reuses the layered logic from deduplicate_dataset.py without writing outputs.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))  # see scripts/_bootstrap.py

from deduplicate_dataset import analyze  # noqa: E402


def main() -> dict:
    src = ROOT / "datasets" / "normalized" / "dataset.jsonl"
    rows = [json.loads(l) for l in src.read_text(encoding="utf-8").splitlines() if l.strip()] if src.exists() else []
    res = analyze(rows)
    out = {"rows": len(rows), "exact_duplicates": len(res["l1_dup_idx"]),
           "context_variants_preserved": res["l2_preserved_texts"],
           "near_duplicates": len(res["l3_dup_idx"]),
           "leak_groups": len(res["groups"])}
    print(json.dumps(out, indent=2))
    return out


if __name__ == "__main__":
    main()
