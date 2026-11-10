"""REST API: projects, scans, findings, models, datasets, benchmarks, settings, activity."""
from __future__ import annotations

import json
import shutil
import uuid
import zipfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.redaction import redact_text
from backend.app.database.db import get_db
from backend.app.ml.registry import load_registry
from backend.app.models.entities import (Activity, AppSetting, DatasetVersion, Finding,
                                         ModelVersion, Project, Report, Scan)
from backend.app.schemas.schemas import (BenchmarkIn, BulkUpdate, FindingPatch, ProjectIn,
                                         ReportIn, ScanIn)
from backend.app.services import jobs as jobmgr
from backend.app.services.scan_service import cancel_scan, run_scan_job

router = APIRouter()

import logging as _logging
logger = _logging.getLogger("leaklens")

ROOT = Path(__file__).resolve().parents[3]
REPORTS_DIR = ROOT / "reports" / "generated"

VALID_FINDING_STATUS = {"OPEN", "RESOLVED", "IGNORED", "FALSE_POSITIVE"}
VALID_SEV = {"low", "medium", "high"}
REPORT_FORMATS = {"json": "json", "csv": "csv", "sarif": "sarif", "html": "html"}

SETTING_SPECS = {
    # key: (kind, default, description)
    "ml_enabled": ("bool", "1", "Use ML context scoring by default for new scans"),
    "include_docs_default": ("bool", "1", "Include documentation files in new scans by default"),
    "include_tests_default": ("bool", "1", "Include test files in new scans by default"),
    "severity_default": ("sev", "low", "Default minimum severity for new scans (low/medium/high)"),
    "default_excludes": ("text", "", "Comma-separated directory names to skip (blank = built-in list)"),
    "log_level": ("loglevel", "INFO", "Backend log level (applies after restart)"),
}


def _like_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

UPLOAD_ROOT = Path(__file__).resolve().parents[3] / "uploads"
MAX_UPLOAD_BYTES = 100 * 1024 * 1024
MAX_UPLOAD_FILES = 20000
MAX_EXTRACT_FILE_BYTES = 25 * 1024 * 1024
MAX_EXTRACT_TOTAL_BYTES = 500 * 1024 * 1024


def _finding_dict(f: Finding) -> dict:
    try:
        ev = json.loads(f.evidence or "[]")
    except Exception:
        ev = []
    return {"id": f.id, "scan_id": f.scan_id, "project_id": f.project_id,
            "detector_id": f.detector_id, "category": f.category,
            "context_type": f.context_type, "severity": f.severity,
            "confidence": f.confidence, "file_path": f.file_path,
            "line_number": f.line_number, "column": f.column,
            "masked_value": f.masked_value, "fingerprint": f.fingerprint,
            "evidence": ev, "recommendation": f.recommendation,
            "status": f.status, "created_at": f.created_at.isoformat() if f.created_at else None}


def _act(db: Session, kind: str, message: str, project_id: str = ""):
    db.add(Activity(kind=kind, message=redact_text(message)[:900], project_id=project_id))


# ---- projects ----
@router.get("/api/projects")
def list_projects(db: Session = Depends(get_db)):
    return [{"id": p.id, "name": p.name, "path": p.path,
             "description": p.description,
             "created_at": p.created_at.isoformat() if p.created_at else None}
            for p in db.query(Project).order_by(Project.created_at.desc()).all()]


@router.post("/api/projects", status_code=201)
def create_project(body: ProjectIn, db: Session = Depends(get_db)):
    if db.query(Project).filter_by(name=body.name).first():
        raise HTTPException(409, "Project name already exists")
    p = Project(name=body.name, path=body.path, description=redact_text(body.description))
    db.add(p)
    _act(db, "Project created", f"Project {body.name} created", "")
    db.commit()
    db.refresh(p)
    logger.info("project created id=%s name=%s", p.id, p.name)
    return {"id": p.id, "name": p.name, "path": p.path}


@router.get("/api/projects/{pid}")
def get_project(pid: str, db: Session = Depends(get_db)):
    p = db.get(Project, pid)
    if not p:
        raise HTTPException(404, "Project not found")
    scans = db.query(Scan).filter_by(project_id=pid).order_by(Scan.created_at.desc()).all()
    trend = [{"scan_id": s.id, "findings": s.findings_count,
              "created_at": s.created_at.isoformat() if s.created_at else None} for s in scans]
    return {"id": p.id, "name": p.name, "path": p.path,
            "scans": [{"id": s.id, "status": s.status, "findings_count": s.findings_count,
                       "files_scanned": s.files_scanned} for s in scans],
            "risk_trend": trend}


@router.delete("/api/projects/{pid}")
def delete_project(pid: str, db: Session = Depends(get_db)):
    p = db.get(Project, pid)
    if not p:
        raise HTTPException(404, "Project not found")
    db.delete(p)
    db.commit()
    logger.info("project deleted id=%s", pid)
    return {"deleted": pid}


# ---- uploads ----
@router.post("/api/uploads", status_code=201)
async def upload_project_zip(file: UploadFile = File(...)):
    """Accept a project .zip, extract it server-side for local scanning.

    The backend runs on the user's own machine, so the extracted files never
    leave the device. Guards: .zip only, 100MB cap, 20000-file cap, zip-slip
    protection (no absolute paths / .. entries are skipped).
    """
    name = (file.filename or "").strip()
    if not name.lower().endswith(".zip"):
        raise HTTPException(400, "Only .zip uploads are supported")
    blob = await file.read()
    if not blob:
        raise HTTPException(400, "Empty upload")
    if len(blob) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"ZIP exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)}MB limit")
    uid = uuid.uuid4().hex[:12]
    dest = UPLOAD_ROOT / uid
    dest.mkdir(parents=True, exist_ok=True)
    tmp = dest / "_upload.zip"
    tmp.write_bytes(blob)
    count = 0
    skipped = 0
    extracted_bytes = 0
    try:
        with zipfile.ZipFile(tmp) as zf:
            members = zf.infolist()
            if len(members) > MAX_UPLOAD_FILES:
                raise HTTPException(413, f"ZIP exceeds {MAX_UPLOAD_FILES}-file limit")
            for m in members:
                if m.is_dir():
                    continue
                # zip-slip guard
                p = Path(m.filename)
                if p.is_absolute() or ".." in p.parts:
                    skipped += 1
                    continue
                if m.file_size > MAX_EXTRACT_FILE_BYTES:
                    skipped += 1
                    continue
                if extracted_bytes + m.file_size > MAX_EXTRACT_TOTAL_BYTES:
                    skipped += 1
                    continue
                target = (dest / p).resolve()
                try:
                    target.relative_to(dest.resolve())
                except ValueError:
                    skipped += 1
                    continue
                if count >= MAX_UPLOAD_FILES:
                    skipped += 1
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(m) as src, open(target, "wb") as fh:
                    shutil.copyfileobj(src, fh, 1024 * 256)
                count += 1
                extracted_bytes += m.file_size
    except zipfile.BadZipFile:
        raise HTTPException(400, "Invalid or corrupt ZIP file")
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass
    # if the zip has a single top-level folder, use it as the scan root
    root = dest
    kids = [p for p in dest.iterdir() if p.is_dir()]
    files = [p for p in dest.iterdir() if p.is_file()]
    if len(kids) == 1 and not files:
        root = kids[0]
    logger.info("upload extracted id=%s files=%d skipped=%d bytes=%d", uid, count, skipped, extracted_bytes)
    return {"upload_id": uid, "name": name, "path": str(root),
            "files_extracted": count, "files_skipped": skipped}


@router.delete("/api/uploads/{upload_id}")
def delete_upload(upload_id: str):
    """Remove an extracted upload directory to reclaim disk space."""
    if not upload_id.replace("-", "").replace("_", "").isalnum() or len(upload_id) > 64:
        raise HTTPException(404, "Upload not found")
    dest = (UPLOAD_ROOT / upload_id).resolve()
    try:
        dest.relative_to(UPLOAD_ROOT.resolve())
    except ValueError:
        raise HTTPException(404, "Upload not found")
    if not dest.is_dir():
        raise HTTPException(404, "Upload not found")
    shutil.rmtree(dest, ignore_errors=True)
    logger.info("upload deleted id=%s", upload_id)
    return {"deleted": upload_id}


# ---- scans ----
@router.post("/api/scans", status_code=201)
def start_scan(body: ScanIn, db: Session = Depends(get_db)):
    proj = db.get(Project, body.project_id)
    if not proj:
        raise HTTPException(404, "Project not found")
    root = body.path or proj.path or "."
    if not Path(root).exists():
        raise HTTPException(400, f"Scan path does not exist: {root}")
    if body.severity_threshold.lower() not in VALID_SEV:
        raise HTTPException(422, "Invalid severity_threshold")
    if body.max_scan_bytes < 0 or body.max_scan_bytes > 10 * 1024 * 1024 * 1024:
        raise HTTPException(422, "Invalid max_scan_bytes")
    excludes = [e.strip() for e in (body.excludes or []) if e.strip()][:50]
    s = Scan(project_id=proj.id, status="QUEUED", stage="queued")
    db.add(s)
    _act(db, "Scan started", f"Scan started for {proj.name}", proj.id)
    db.commit()
    db.refresh(s)
    jid = jobmgr.submit(run_scan_job, scan_id=s.id, root=root, use_ml=body.use_ml,
                        include_docs=body.include_docs, include_tests=body.include_tests,
                        excludes=excludes, max_scan_bytes=body.max_scan_bytes,
                        severity_threshold=body.severity_threshold)
    s.stage = f"job:{jid}"
    db.commit()
    logger.info("scan started id=%s project=%s root=%s ml=%s", s.id, proj.id, root, body.use_ml)
    return {"scan_id": s.id, "job_id": jid, "status": "QUEUED"}


@router.get("/api/scans")
def list_scans(project_id: str = "", db: Session = Depends(get_db)):
    q = db.query(Scan).order_by(Scan.created_at.desc())
    if project_id:
        q = q.filter_by(project_id=project_id)
    return [{"id": s.id, "project_id": s.project_id, "status": s.status, "stage": s.stage,
             "files_discovered": s.files_discovered, "files_scanned": s.files_scanned,
             "candidates": s.candidates, "findings_count": s.findings_count,
             "duration_ms": s.duration_ms} for s in q.limit(200).all()]


@router.get("/api/scans/{sid}")
def get_scan(sid: str, db: Session = Depends(get_db)):
    s = db.get(Scan, sid)
    if not s:
        raise HTTPException(404, "Scan not found")
    return {"id": s.id, "project_id": s.project_id, "status": s.status, "stage": s.stage,
            "files_discovered": s.files_discovered, "files_scanned": s.files_scanned,
            "candidates": s.candidates, "findings_count": s.findings_count,
            "duration_ms": s.duration_ms, "error": s.error}


@router.get("/api/scans/{sid}/progress")
def scan_progress(sid: str, db: Session = Depends(get_db)):
    s = db.get(Scan, sid)
    if not s:
        raise HTTPException(404, "Scan not found")
    pct = round(100 * s.files_scanned / max(1, s.files_discovered), 1)
    return {"scan_id": sid, "status": s.status, "stage": s.stage,
            "files_discovered": s.files_discovered, "files_scanned": s.files_scanned,
            "candidates": s.candidates, "findings": s.findings_count, "percent": pct}


@router.post("/api/scans/{sid}/cancel")
def cancel(sid: str, db: Session = Depends(get_db)):
    s = db.get(Scan, sid)
    if not s:
        raise HTTPException(404, "Scan not found")
    cancel_scan(sid)
    if s.status in ("QUEUED", "CREATED"):
        s.status = "CANCELLED"
        db.commit()
    logger.info("scan cancel requested id=%s", sid)
    return {"scan_id": sid, "cancel_requested": True}


# ---- findings ----
@router.get("/api/findings")
def list_findings(project_id: str = Query(default="", max_length=64),
                  scan_id: str = Query(default="", max_length=64),
                  severity: str = Query(default="", max_length=16),
                  status: str = Query(default="", max_length=32),
                  category: str = Query(default="", max_length=128),
                  file_type: str = Query(default="", max_length=200),
                  confidence_min: float = Query(default=0.0, ge=0.0),
                  q: str = Query(default="", max_length=200),
                  db: Session = Depends(get_db)):
    query = db.query(Finding)
    if project_id:
        query = query.filter_by(project_id=project_id)
    if scan_id:
        query = query.filter_by(scan_id=scan_id)
    if severity:
        query = query.filter(Finding.severity == severity.upper())
    if status:
        query = query.filter(Finding.status == status.upper())
    if category:
        query = query.filter(Finding.category == category)
    if file_type:
        ft = _like_escape(file_type)
        query = query.filter(Finding.file_path.like(f"%{ft}%", escape="\\"))
    if confidence_min:
        query = query.filter(Finding.confidence >= confidence_min)
    if q:
        like = f"%{_like_escape(q)}%"
        query = query.filter(or_(Finding.file_path.like(like, escape="\\"),
                                 Finding.detector_id.like(like, escape="\\"),
                                 Finding.category.like(like, escape="\\"),
                                 Finding.masked_value.like(like, escape="\\")))
    return [_finding_dict(f) for f in query.order_by(Finding.created_at.desc()).limit(500).all()]


@router.get("/api/findings/{fid}")
def get_finding(fid: str, db: Session = Depends(get_db)):
    f = db.get(Finding, fid)
    if not f:
        raise HTTPException(404, "Finding not found")
    return _finding_dict(f)


@router.patch("/api/findings/{fid}")
def patch_finding(fid: str, body: FindingPatch, db: Session = Depends(get_db)):
    f = db.get(Finding, fid)
    if not f:
        raise HTTPException(404, "Finding not found")
    st = body.status.upper()
    if st not in VALID_FINDING_STATUS:
        raise HTTPException(422, "Invalid status")
    f.status = st
    _act(db, "Finding updated", f"Finding {fid} -> {st}", f.project_id)
    db.commit()
    return _finding_dict(f)


@router.post("/api/findings/bulk-update")
def bulk(body: BulkUpdate, db: Session = Depends(get_db)):
    st = body.status.upper()
    if st not in VALID_FINDING_STATUS:
        raise HTTPException(422, "Invalid status")
    n = 0
    for fid in body.ids:
        f = db.get(Finding, fid)
        if f:
            f.status = st
            n += 1
    db.commit()
    return {"updated": n}


# ---- models / datasets / benchmarks ----
@router.get("/api/models")
def models(db: Session = Depends(get_db)):
    reg = load_registry()
    db_models = [{"name": m.name, "version": m.version, "algorithm": m.algorithm,
                  "dataset_version": m.dataset_version, "is_production": bool(m.is_production)}
                 for m in db.query(ModelVersion).all()]
    return {"registry": reg, "database": db_models,
            "active": reg.get("production"), "detection_engine": "detection-1.0.0"}


@router.get("/api/models/active")
def active_model():
    reg = load_registry()
    return {"active": reg.get("production"), "models": reg.get("models", [])}


@router.get("/api/models/metrics")
def model_metrics():
    p = ROOT / "reports" / "model_evaluation.json"
    if p.exists():
        return json.loads(p.read_text())
    return {"status": "Not evaluated"}


@router.get("/api/datasets")
def datasets(db: Session = Depends(get_db)):
    man = ROOT / "datasets" / "manifests" / "dataset_manifest.json"
    manifest = json.loads(man.read_text()) if man.exists() else {"sources": []}
    versions = [{"version": v.version, "samples": v.samples} for v in db.query(DatasetVersion).all()]
    return {"manifest": manifest, "versions": versions}


@router.get("/api/datasets/statistics")
def dataset_stats():
    p = ROOT / "reports" / "dataset_quality_report.json"
    if p.exists():
        return json.loads(p.read_text())
    return {"status": "Not evaluated"}


# ---- reports ----
def _report_dict(r: Report) -> dict:
    size = None
    try:
        size = Path(r.path).stat().st_size if r.path else None
    except OSError:
        size = None
    return {"id": r.id, "project_id": r.project_id, "scan_id": r.scan_id,
            "format": r.format, "size_bytes": size,
            "created_at": r.created_at.isoformat() if r.created_at else None}


@router.post("/api/reports", status_code=201)
def create_report(body: ReportIn, db: Session = Depends(get_db)):
    from backend.app.reports.exporters import to_csv, to_html, to_json, to_sarif
    fmt = (body.format or "json").lower()
    if fmt not in REPORT_FORMATS:
        raise HTTPException(422, "Invalid format (json/csv/sarif/html)")
    proj = db.get(Project, body.project_id)
    if not proj:
        raise HTTPException(404, "Project not found")
    scan = db.get(Scan, body.scan_id)
    if not scan or scan.project_id != proj.id:
        raise HTTPException(404, "Scan not found for this project")
    rows = db.query(Finding).filter_by(scan_id=scan.id).order_by(Finding.created_at.desc()).all()
    findings = [_finding_dict(f) for f in rows]
    stats = {"files_scanned": scan.files_scanned, "findings": len(findings),
             "duration_ms": scan.duration_ms}
    if fmt == "json":
        content = to_json(proj.name, scan.id, stats, findings)
    elif fmt == "csv":
        content = to_csv(findings)
    elif fmt == "sarif":
        content = json.dumps(to_sarif(proj.name, findings), indent=2)
    else:
        content = to_html(proj.name, scan.id, stats, findings)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    rep = Report(project_id=proj.id, scan_id=scan.id, format=fmt, path="")
    db.add(rep)
    db.commit()
    db.refresh(rep)
    dest = REPORTS_DIR / f"{rep.id}.{REPORT_FORMATS[fmt]}"
    dest.write_text(content, encoding="utf-8")
    rep.path = str(dest)
    _act(db, "Report generated", f"{fmt.upper()} report for {proj.name}", proj.id)
    db.commit()
    logger.info("report generated id=%s project=%s scan=%s format=%s findings=%d",
                rep.id, proj.id, scan.id, fmt, len(findings))
    return _report_dict(rep)


@router.get("/api/reports")
def list_reports(project_id: str = Query(default="", max_length=64),
                 db: Session = Depends(get_db)):
    q = db.query(Report).order_by(Report.created_at.desc())
    if project_id:
        q = q.filter_by(project_id=project_id)
    return [_report_dict(r) for r in q.limit(200).all()]


@router.get("/api/reports/{rid}/download")
def download_report(rid: str, db: Session = Depends(get_db)):
    from fastapi.responses import FileResponse
    r = db.get(Report, rid)
    if not r or not r.path or not Path(r.path).is_file():
        raise HTTPException(404, "Report file not found")
    media = {"json": "application/json", "csv": "text/csv",
             "sarif": "application/json", "html": "text/html"}.get(r.format, "application/octet-stream")
    return FileResponse(r.path, media_type=media,
                        filename=f"leaklens-{r.format}-{r.id}.{REPORT_FORMATS.get(r.format, 'txt')}")


@router.delete("/api/reports/{rid}")
def delete_report(rid: str, db: Session = Depends(get_db)):
    r = db.get(Report, rid)
    if not r:
        raise HTTPException(404, "Report not found")
    try:
        if r.path:
            Path(r.path).unlink(missing_ok=True)
    except OSError:
        pass
    db.delete(r)
    db.commit()
    logger.info("report deleted id=%s", rid)
    return {"deleted": rid}


# ---- benchmarks ----
@router.post("/api/benchmarks/run", status_code=202)
def run_benchmark(body: BenchmarkIn, db: Session = Depends(get_db)):
    from backend.app.services.benchmark_service import submit_benchmark
    target = (body.path or "").strip() or str(ROOT / "test-fixtures" / "vulnerable-project")
    if not Path(target).exists():
        raise HTTPException(400, f"Benchmark target does not exist: {target}")
    jid = submit_benchmark(target)
    _act(db, "Benchmark started", f"Benchmark started for {target}")
    db.commit()
    logger.info("benchmark started job=%s target=%s", jid, target)
    return {"job_id": jid, "status": "QUEUED"}


@router.get("/api/benchmarks/jobs/{jid}")
def benchmark_job(jid: str):
    job = jobmgr.get(jid)
    if not job:
        raise HTTPException(404, "Benchmark job not found")
    return {"job_id": jid, **job}


@router.get("/api/benchmarks")
def list_benchmarks():
    from backend.app.services.benchmark_service import bench_root
    d = bench_root()
    runs = []
    for p in sorted(d.glob("*.json")):
        if p.name == "latest.json":
            continue
        try:
            m = json.loads(p.read_text())
            runs.append({"id": p.stem, "target": m.get("target"),
                         "files_scanned": m.get("files_scanned"),
                         "findings": m.get("findings"),
                         "duration_s": m.get("duration_s"),
                         "finished_at": m.get("finished_at")})
        except (OSError, ValueError):
            continue
    runs.sort(key=lambda r: r["id"], reverse=True)
    latest = None
    lp = d / "latest.json"
    if lp.exists():
        try:
            latest = json.loads(lp.read_text())
        except ValueError:
            latest = None
    model_metrics: dict = {}
    mp = ROOT / "reports" / "model_evaluation.json"
    if mp.exists():
        try:
            model_metrics = json.loads(mp.read_text())
        except ValueError:
            model_metrics = {}
    comparison: dict = {}
    cp = ROOT / "models" / "v1" / "model_comparison.json"
    if cp.exists():
        try:
            comparison = json.loads(cp.read_text())
        except ValueError:
            comparison = {}
    return {"runs": runs[:50], "latest": latest,
            "model_test_metrics": model_metrics, "model_comparison": comparison}


@router.get("/api/benchmarks/{bid}")
def get_benchmark(bid: str):
    from backend.app.services.benchmark_service import bench_root
    if not bid.replace("-", "").replace("_", "").isalnum():
        raise HTTPException(404, "Benchmark not found")
    p = bench_root() / f"{bid}.json"
    if not p.is_file():
        raise HTTPException(404, "Benchmark not found")
    try:
        return json.loads(p.read_text())
    except ValueError:
        raise HTTPException(500, "Benchmark file is corrupt")


# ---- dashboard / activity / settings ----
@router.get("/api/dashboard")
def dashboard(db: Session = Depends(get_db)):
    sev: dict[str, int] = {}
    for row in db.query(Finding.severity, func.count()).group_by(Finding.severity).all():
        sev[str(row[0])] = int(row[1])
    recent_scans = [
        {"id": s.id, "project_id": s.project_id, "status": s.status,
         "findings_count": s.findings_count, "files_scanned": s.files_scanned,
         "created_at": s.created_at.isoformat() if s.created_at else None}
        for s in db.query(Scan).order_by(Scan.created_at.desc()).limit(5).all()]
    recent_activity = [
        {"kind": a.kind, "message": a.message, "project_id": a.project_id,
         "created_at": a.created_at.isoformat() if a.created_at else None}
        for a in db.query(Activity).order_by(Activity.created_at.desc()).limit(5).all()]
    open_findings = db.query(Finding).filter(Finding.status == "OPEN").count()
    return {"projects": db.query(Project).count(), "scans": db.query(Scan).count(),
            "findings": db.query(Finding).count(),
            "high": db.query(Finding).filter_by(severity="HIGH").count(),
            "open": open_findings, "severity": sev,
            "recent_scans": recent_scans, "recent_activity": recent_activity,
            "app": settings.app_name, "detection_engine": "detection-1.0.0",
            "model": load_registry().get("production")}


@router.get("/api/activity")
def activity(db: Session = Depends(get_db)):
    return [{"kind": a.kind, "message": a.message, "project_id": a.project_id,
             "created_at": a.created_at.isoformat() if a.created_at else None}
            for a in db.query(Activity).order_by(Activity.created_at.desc()).limit(100).all()]


@router.get("/api/settings")
def get_settings(db: Session = Depends(get_db)):
    return {s.key: s.value for s in db.query(AppSetting).all()}


@router.post("/api/settings")
def save_settings(body: dict, db: Session = Depends(get_db)):
    if len(body) > 50:
        raise HTTPException(422, "Too many settings at once")
    for k, v in body.items():
        if not isinstance(k, str) or len(k) > 128:
            raise HTTPException(422, "Invalid setting key")
        if "secret" in k.lower() or "token" in k.lower() or "password" in k.lower():
            raise HTTPException(400, "Refusing to store credential-like setting")
        spec = SETTING_SPECS.get(k)
        sv = str(v)[:4096]
        if spec:
            kind = spec[0]
            if kind == "bool" and sv not in ("0", "1"):
                raise HTTPException(422, f"Setting {k} must be 0 or 1")
            if kind == "sev" and sv not in ("low", "medium", "high"):
                raise HTTPException(422, f"Setting {k} must be low/medium/high")
            if kind == "loglevel" and sv.upper() not in ("DEBUG", "INFO", "WARNING", "ERROR"):
                raise HTTPException(422, f"Setting {k} must be a log level")
        row = db.get(AppSetting, k)
        if row:
            row.value = sv
        else:
            db.add(AppSetting(key=k, value=sv))
    _act(db, "Settings changed", "Settings updated")
    db.commit()
    logger.info("settings saved keys=%s", sorted(body.keys()))
    return {"saved": list(body.keys()), "known": SETTING_SPECS}
