"""Extract benign lines from this repository as an honestly-labeled slice.

Every candidate line is screened by the production detector registry AND the
production redaction filter; any line that matches is REJECTED (never stored).
Surviving lines contain no secret-like content by construction.

Labels are path-derived and conservative: markdown -> DOCUMENTATION_EXAMPLE,
code -> BENIGN_CONFIG, always contains_secret=0, source_type="local_repo".
Output: datasets/local_repo/part.jsonl (+ manifest entry on success).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

import sys as _sys
_sys.path.insert(0, str(ROOT))

from backend.app.core.redaction import redact_text  # noqa: E402
from backend.app.detection.registry import scan_line  # noqa: E402

SCAN_DIRS = ["backend/app", "leaklens", "scripts", "docs", "tests"]
SCAN_FILES = ["README.md", "alembic.ini"]
SKIP_NAMES = {"generate_synthetic_data.py", "audit_labels.py", "check_l3.py"}
SKIP_PARTS = {"__pycache__", "test-fixtures", "node_modules", ".git"}
EXT_LANG = {".py": "python", ".js": "javascript", ".md": "markdown", ".ini": "ini",
            ".cfg": "ini", ".txt": "text", ".json": "json", ".yaml": "yaml", ".yml": "yaml"}

LICENSE = "same-repo extract; screened by detector registry + redaction filter; no secret-like content"
MAX_LINES = 6000


def main() -> dict:
    recs: list[dict] = []
    rejected = 0
    day = datetime.now(timezone.utc).date().isoformat()
    for base in SCAN_DIRS + SCAN_FILES:
        p = ROOT / base
        files = sorted(p.rglob("*")) if p.is_dir() else [p]
        for f in files:
            if not f.is_file() or f.suffix not in EXT_LANG:
                continue
            if f.name in SKIP_NAMES or any(part in f.parts for part in SKIP_PARTS):
                continue
            try:
                text = f.read_text(encoding="utf-8", errors="strict")
            except (OSError, ValueError):
                continue
            rel = f.relative_to(ROOT).as_posix()
            lang = EXT_LANG[f.suffix]
            ctx = "DOCUMENTATION_EXAMPLE" if f.suffix == ".md" else "BENIGN_CONFIG"
            for lineno, line in enumerate(text.splitlines(), 1):
                s = line.strip()
                if len(s) < 8 or len(s) > 500:
                    continue
                if scan_line(s) or redact_text(s) != s:
                    rejected += 1
                    continue
                i = len(recs)
                recs.append({
                    "record_id": f"repo-{i:06d}", "text": s, "masked_value": s[:80],
                    "category": "GENERIC_SECRET", "secret_type": "GENERIC_SECRET",
                    "context_label": ctx,
                    "label": "DOCUMENTATION" if ctx == "DOCUMENTATION_EXAMPLE" else "BENIGN_CONFIG",
                    "contains_secret": 0, "is_positive": 0,
                    "original_label": ctx, "normalized_label": ctx,
                    "source": "leaklens-local-repo", "source_version": "working-tree",
                    "license": LICENSE, "access_date": day,
                    "repository_id": "local://leaklens", "group": f"repo-{i:06d}",
                    "leak_group": f"repo-{i:06d}", "template_id": f"repo-benign-{lang}",
                    "file_type": lang, "file_context": rel, "language": lang,
                    "file_ext": f.suffix, "environment": "development",
                    "synthetic": False, "source_type": "local_repo", "external": False,
                    "transformation": "extracted+screened", "split_hint": "train_pool",
                })
                if len(recs) >= MAX_LINES:
                    break
            if len(recs) >= MAX_LINES:
                break
        if len(recs) >= MAX_LINES:
            break
    out = ROOT / "datasets" / "local_repo" / "part.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(json.dumps(r) for r in recs) + "\n", encoding="utf-8")
    print(f"repo-benign: kept={len(recs)} rejected_secret_like={rejected} -> {out}")
    return {"kept": len(recs), "rejected": rejected}


if __name__ == "__main__":
    main()
