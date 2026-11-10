"""Scan service: runs pipeline, persists scan + findings + activity."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from backend.app.core.redaction import redact_text
from backend.app.database.db import SessionLocal
from backend.app.ml.inference.predict import ml_probability
from backend.app.models.entities import Activity, Finding, Scan
from backend.app.scanner.core import ScanConfig
from backend.app.scanner.pipeline import scan_path
from backend.app.services import jobs as jobmgr

logger = logging.getLogger("leaklens")

_CANCEL: dict[str, bool] = {}
_SEV_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


def _log(kind: str, message: str, project_id: str = "") -> None:
    db = SessionLocal()
    try:
        db.add(Activity(kind=kind, message=redact_text(message)[:900], project_id=project_id))
        db.commit()
    finally:
        db.close()


def _effective_excludes(explicit: list[str] | None) -> set[str]:
    """Explicit per-scan excludes win; else the saved default_excludes setting;
    else the built-in default list."""
    if explicit:
        return {e.strip() for e in explicit if e.strip()}
    db = SessionLocal()
    try:
        from backend.app.models.entities import AppSetting
        row = db.get(AppSetting, "default_excludes")
        if row and row.value.strip():
            return {e.strip() for e in row.value.split(",") if e.strip()}
    finally:
        db.close()
    from backend.app.scanner.core import DEFAULT_IGNORES
    return set(DEFAULT_IGNORES)


def run_scan_job(job_id: str, scan_id: str, root: str, use_ml: bool,
                 include_docs: bool, include_tests: bool,
                 excludes: list[str] | None = None, max_scan_bytes: int = 0,
                 severity_threshold: str = "low") -> dict:
    from backend.app.core.config import settings
    cfg = ScanConfig(root=root, include_docs=include_docs, include_tests=include_tests,
                     excludes=_effective_excludes(excludes),
                     max_scan_bytes=max_scan_bytes or settings.max_scan_bytes)
    _CANCEL[scan_id] = False

    def cb(done, total, cands, finds):
        jobs_update = {"files_scanned": done, "files_total": total,
                       "candidates": cands, "findings": finds}
        jobmgr.update_progress(job_id, **jobs_update)
        db = SessionLocal()
        try:
            s = db.get(Scan, scan_id)
            if s:
                s.files_discovered = total
                s.files_scanned = done
                s.candidates = cands
                s.findings_count = finds
                s.stage = "scanning"
                db.commit()
        finally:
            db.close()

    ml_fn = (lambda line, fp, var, ent: ml_probability(line, fp, var, ent)) if use_ml else None
    try:
        res = scan_path(root, cfg, use_ml=ml_fn, progress_cb=cb,
                        cancel_flag=lambda: _CANCEL.get(scan_id, False))
    except Exception as e:  # noqa: BLE001 — persist failure, never leak raw content
        err = redact_text(str(e))[:500]
        logger.error("scan failed scan_id=%s error=%s", scan_id, err)
        db = SessionLocal()
        try:
            s = db.get(Scan, scan_id)
            if s:
                s.status = "FAILED"
                s.stage = "failed"
                s.error = err
                s.finished_at = datetime.now(timezone.utc)
                db.commit()
        finally:
            db.close()
        _log("Scan failed", f"Scan {scan_id} failed", "")
        raise
    db = SessionLocal()
    try:
        s = db.get(Scan, scan_id)
        if s:
            if res["status"] == "CANCELLED":
                s.status = "CANCELLED"
                s.stage = "cancelled"
            else:
                s.status = "COMPLETED"
                s.stage = "done"
                s.files_discovered = res["files_discovered"]
                s.files_scanned = res["files_scanned"]
                s.candidates = res["candidates"]
                thr = _SEV_ORDER.get((severity_threshold or "low").upper(), 0)
                kept = [f for f in res["findings"]
                        if _SEV_ORDER.get(str(f.get("severity", "LOW")).upper(), 0) >= thr]
                s.findings_count = len(kept)
                s.duration_ms = res["duration_ms"]
                s.finished_at = datetime.now(timezone.utc)
                for f in kept:
                    db.add(Finding(
                        scan_id=scan_id, project_id=s.project_id,
                        detector_id=f["detector_id"], category=f["category"],
                        context_type=f["context_type"], severity=f["severity"],
                        confidence=f["confidence"], file_path=f["file_path"],
                        line_number=f["line_number"], column=f["column"],
                        masked_value=f["masked_value"][:200],
                        fingerprint=f["fingerprint"],
                        evidence=json.dumps(f["evidence"])[:4000],
                        recommendation=f["recommendation"][:2000]))
            db.commit()
    finally:
        db.close()
    proj = ""
    db2 = SessionLocal()
    try:
        s2 = db2.get(Scan, scan_id)
        proj = s2.project_id if s2 else ""
    finally:
        db2.close()
    _log("Scan completed", f"Scan {scan_id} finished: {res.get('status')}", proj)
    logger.info("scan finished scan_id=%s status=%s files=%s findings=%s",
                scan_id, res.get("status"), res.get("files_scanned"), len(res.get("findings", [])))
    return res


def cancel_scan(scan_id: str) -> None:
    _CANCEL[scan_id] = True
