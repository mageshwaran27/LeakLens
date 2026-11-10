"""Merge synthetic buckets + legacy + external JSONL into datasets/processed/dataset.jsonl.

Sources merged (in order):
  datasets/synthetic/*/part.jsonl   (v2 buckets; holdout file EXCLUDED — eval only)
  datasets/synthetic/synthetic.jsonl (legacy v1, if present)
  datasets/external/*.jsonl          (curated external, if present)
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> dict:
    rows: list[dict] = []
    per_source: dict[str, int] = {}
    cands: list[Path] = sorted((ROOT / "datasets" / "synthetic").glob("*/part.jsonl"))
    legacy = ROOT / "datasets" / "synthetic" / "synthetic.jsonl"
    if not cands and legacy.exists():
        # v1 fallback only when no v2 buckets exist (v2 supersedes v1)
        cands.append(legacy)
    local_repo = ROOT / "datasets" / "local_repo" / "part.jsonl"
    if local_repo.exists():
        cands.append(local_repo)
    cands += sorted((ROOT / "datasets" / "external").glob("*.jsonl"))
    for src in cands:
        n = 0
        try:
            rel = src.relative_to(ROOT / "datasets").as_posix()
        except ValueError:
            rel = src.name
        for line in src.read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                r.setdefault("source_file", rel)
                rows.append(r)
                n += 1
        per_source[src.as_posix()] = n
    out = ROOT / "datasets" / "processed" / "dataset.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    print(f"Built {len(rows)} rows from {len(cands)} files -> {out}")
    return {"rows": len(rows), "per_source": per_source}


if __name__ == "__main__":
    main()
