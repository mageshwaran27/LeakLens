"""Benchmark service: scanner throughput on a target path, persisted as JSON.

Metrics are honest throughput/count measurements (files, findings, timing,
severity/detector breakdowns). There is no labeled precision/recall here —
detection quality is measured separately by scripts/evaluate_model.py on the
labeled test split (see reports/model_evaluation.json).
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

from backend.app.core.redaction import redact_text
from backend.app.database.db import SessionLocal
from backend.app.models.entities import Activity
from backend.app.scanner.core import ScanConfig
from backend.app.scanner.pipeline import scan_path
from backend.app.services import jobs as jobmgr

BENCH_DIRNAME = "benchmark"
ROOT = Path(__file__).resolve().parents[3]


def bench_root() -> Path:
    d = ROOT / "reports" / BENCH_DIRNAME
    d.mkdir(parents=True, exist_ok=True)
    return d


def run_benchmark_job(job_id: str, target: str) -> dict:
    t0 = time.time()
    res = scan_path(target, ScanConfig(root=target))
    dt = time.time() - t0
    total_mb = 0.0
    try:
        for p in Path(target).rglob("*"):
            try:
                if p.is_file() and not p.is_symlink():
                    total_mb += p.stat().st_size
            except OSError:
                continue
    except OSError:
        pass
    total_mb /= 1e6
    out = {"target": target, "files_scanned": res["files_scanned"],
           "files_discovered": res["files_discovered"],
           "candidates": res["candidates"],
           "findings": len(res["findings"]), "duration_s": round(dt, 2),
           "files_per_sec": round(res["files_scanned"] / max(dt, 1e-6), 1),
           "mb_per_sec": round(total_mb / max(dt, 1e-6), 2),
           "by_severity": {}, "by_detector": {},
           "finished_at": datetime.now(timezone.utc).isoformat(),
           "note": "Throughput/count benchmark on an unlabeled target. "
                   "Not precision/recall — see model evaluation for labeled quality."}
    for f in res["findings"]:
        out["by_severity"][f["severity"]] = out["by_severity"].get(f["severity"], 0) + 1
        out["by_detector"][f["detector_id"]] = out["by_detector"].get(f["detector_id"], 0) + 1
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    d = bench_root()
    (d / f"{stamp}.json").write_text(json.dumps(out, indent=2))
    (d / "latest.json").write_text(json.dumps(out, indent=2))
    db = SessionLocal()
    try:
        db.add(Activity(kind="Benchmark finished",
                        message=redact_text(
                            f"Benchmark of {target}: {out['files_scanned']} files, "
                            f"{out['findings']} findings in {out['duration_s']}s")[:900]))
        db.commit()
    finally:
        db.close()
    return out


def submit_benchmark(target: str) -> str:
    return jobmgr.submit(run_benchmark_job, target=target)
