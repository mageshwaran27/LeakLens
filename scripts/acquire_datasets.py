"""External dataset acquisition adapters (offline-safe by default).

Supported corpora: SecretBench, Prowl Secrets Corpus (Hugging Face),
FPSecretBench, software issue/report corpora, GitGuardian sample secrets.

Default behavior: create the raw/external directory skeleton, write per-source
download instructions, and record access status in the manifest WITHOUT
downloading anything. With --try-remote, performs a short-timeout HTTPS
reachability check of each source's public page and records the outcome.
Never bypasses access control; never fabricates records.
"""
from __future__ import annotations

import argparse
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "datasets" / "manifests" / "dataset_manifest.json"

SOURCES = [
    {"name": "secretbench", "title": "SecretBench",
     "url": "https://link.springer.com/article/10.1007/s10664-023-10355-w",
     "license": "Restricted — access via authors/DataShield request; do not redistribute",
     "target_candidates": "~97,000 candidates",
     "instructions": "Request access from the authors. Export accepted candidate texts + labels to datasets/external/secretbench/*.jsonl (LeakLens record schema), then run build_dataset.py."},
    {"name": "prowl", "title": "Prowl Secrets Corpus (Hugging Face)",
     "url": "https://huggingface.co/datasets/prowl",
     "license": "Check dataset card at download time; respect redistribution terms",
     "target_candidates": "permitted corpus subset",
     "instructions": "Requires `datasets` + `pyarrow` (both currently unavailable in this env). Download the permitted split, convert rows to LeakLens schema into datasets/external/prowl/*.jsonl."},
    {"name": "fpsecretbench", "title": "FPSecretBench (hard negatives)",
     "url": "https://huggingface.co/",
     "license": "Check dataset card at download time",
     "target_candidates": "50,000-150,000 representative hard negatives",
     "instructions": "Download the false-positive/hard-negative split, map original labels to LeakLens context labels (preserve original_label), write datasets/external/fpsecretbench/*.jsonl."},
    {"name": "issue_reports", "title": "Software issue/report corpus",
     "url": "https://github.com/",
     "license": "Per-repository OSS licenses; manual curation only",
     "target_candidates": "20,000-50,000 representative examples",
     "instructions": "Curate manually from permissively licensed issue text. Never bulk-scrape credentials."},
    {"name": "gitguardian_samples", "title": "GitGuardian sample secrets",
     "url": "https://github.com/GitGuardian",
     "license": "Per-repo license; fixtures only",
     "target_candidates": "regression/integration fixtures",
     "instructions": "Use public sample/dummy secrets as scanner regression fixtures only, not as training corpus."},
]


def reachability(url: str, timeout: int = 10) -> str:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "LeakLens-acquire/1.0"}, method="HEAD")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return f"reachable (HTTP {r.status})"
    except Exception as e:  # noqa: BLE001
        return f"unreachable: {type(e).__name__}: {e}"[:200]


def main(try_remote: bool = False) -> dict:
    for sub in ("raw", "external"):
        for s in SOURCES:
            d = ROOT / "datasets" / sub / s["name"]
            d.mkdir(parents=True, exist_ok=True)
            (d / "README.md").write_text(
                f"# {s['title']}\n\n- Reference: {s['url']}\n- License/access: {s['license']}\n"
                f"- Target: {s['target_candidates']}\n\n## How to add\n\n{s['instructions']}\n")
    man = {"sources": []} if not MANIFEST.exists() else json.loads(MANIFEST.read_text())
    by_name = {s.get("name"): s for s in man["sources"]}
    for s in SOURCES:
        key = f"external-{s['name']}"
        entry = by_name.get(key, {"name": key, "source": s["url"], "license": s["license"],
                                  "version": "n/a", "record_count": 0, "accepted": 0,
                                  "rejected": 0, "preprocessing": "not downloaded",
                                  "allowed_use": "pending license review",
                                  "redaction_status": "unknown"})
        entry["access_status"] = reachability(s["url"]) if try_remote else "not attempted (offline-safe default)"
        entry["access_date"] = datetime.now(timezone.utc).date().isoformat()
        if "huggingface" in s["url"] or s["name"] in ("prowl", "fpsecretbench"):
            entry["status"] = "DEPENDENCY_MISSING"
            entry["status_reason"] = ("Requires `datasets` + `pyarrow` Python packages, "
                                      "neither installed in this environment; no download attempted.")
        elif s["name"] == "secretbench":
            entry["status"] = "ACCESS_RESTRICTED"
            entry["status_reason"] = ("Gated academic access via authors/DataShield request; "
                                      "no request made, no data fetched.")
        elif not try_remote:
            entry["status"] = "NOT_ATTEMPTED"
            entry["status_reason"] = "Offline-safe default: no network access attempted."
        elif entry["access_status"].startswith("reachable"):
            entry["status"] = "NOT_ATTEMPTED"
            entry["status_reason"] = "Source page reachable but no licensed artifact download attempted."
        else:
            entry["status"] = "DOWNLOAD_FAILED"
            entry["status_reason"] = entry["access_status"]
        by_name[key] = entry
    man["sources"] = list(by_name.values())
    man["updated"] = datetime.now(timezone.utc).isoformat()
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps(man, indent=2))
    print(json.dumps({s["name"]: by_name[f"external-{s['name']}']['access_status"] for s in SOURCES}, indent=2))
    return {"sources": len(SOURCES), "try_remote": try_remote}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--try-remote", action="store_true", help="HTTPS reachability check (10s timeout each).")
    main(ap.parse_args().try_remote)
