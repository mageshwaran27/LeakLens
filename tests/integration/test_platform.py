"""Platform coverage: uploads, scan options, findings filters, reports,
settings validation, benchmarks, dashboard — all against the isolated test DB."""
import io
import sys
import time
import uuid
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from fastapi.testclient import TestClient  # noqa: E402

from backend.app.core.security import hash_password  # noqa: E402
from backend.app.database.db import Base, SessionLocal, engine  # noqa: E402
from backend.app.main import app  # noqa: E402
from backend.app.models.entities import User  # noqa: E402

Base.metadata.create_all(bind=engine)
client = TestClient(app)
FIX = str(Path(__file__).resolve().parents[2] / "test-fixtures" / "vulnerable-project")
USER = "platform-tester"
PASSWORD = "platform-pass-1"


def _auth():
    r = client.post("/api/auth/setup", json={"username": USER, "password": PASSWORD})
    assert r.status_code in (201, 403), r.text
    if r.status_code == 403:
        db = SessionLocal()
        try:
            if not db.query(User).filter_by(username=USER).first():
                db.add(User(username=USER, password_hash=hash_password(PASSWORD)))
                db.commit()
        finally:
            db.close()
    r = client.post("/api/auth/login", json={"username": USER, "password": PASSWORD})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def _zip_bytes(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _wait_scan(h, sid, timeout_s=120):
    for _ in range(int(timeout_s / 0.5)):
        pr = client.get(f"/api/scans/{sid}/progress", headers=h).json()
        if pr["status"] in ("COMPLETED", "FAILED", "CANCELLED"):
            return pr
        time.sleep(0.5)
    raise AssertionError("scan did not finish in time")


def test_upload_flow():
    h = _auth()
    blob = _zip_bytes({"a/app.py": 'x = "AKIAIOSFODNN7EXAMPLE"\n', "notes.md": "hi\n"})
    r = client.post("/api/uploads", files={"file": ("p.zip", blob, "application/zip")}, headers=h)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["files_extracted"] == 2 and body["files_skipped"] == 0
    uid = body["upload_id"]
    # zip-slip entries are skipped, legit ones kept
    evil = _zip_bytes({"ok.py": "x = 1\n", "../evil.py": "x = 1\n", "/abs.py": "x = 1\n"})
    r = client.post("/api/uploads", files={"file": ("e.zip", evil, "application/zip")}, headers=h)
    assert r.status_code == 201, r.text
    assert r.json()["files_extracted"] == 1 and r.json()["files_skipped"] == 2
    client.delete(f"/api/uploads/{r.json()['upload_id']}", headers=h)
    # non-zip rejected, corrupt zip rejected
    r = client.post("/api/uploads", files={"file": ("t.txt", b"hello", "text/plain")}, headers=h)
    assert r.status_code == 400
    r = client.post("/api/uploads", files={"file": ("b.zip", b"not a zip", "application/zip")}, headers=h)
    assert r.status_code == 400
    # delete works once, then 404
    assert client.delete(f"/api/uploads/{uid}", headers=h).status_code == 200
    assert client.delete(f"/api/uploads/{uid}", headers=h).status_code == 404
    assert client.delete("/api/uploads/../nope", headers=h).status_code in (404, 422)


def test_scan_options_and_filters():
    h = _auth()
    name = f"opts-{uuid.uuid4().hex[:8]}"
    pid = client.post("/api/projects", json={"name": name, "path": FIX}, headers=h).json()["id"]
    try:
        # invalid path rejected
        r = client.post("/api/scans", json={"project_id": pid, "path": "C:/no/such/dir-xyz"}, headers=h)
        assert r.status_code == 400
        # invalid threshold rejected
        r = client.post("/api/scans", json={"project_id": pid, "path": FIX,
                                            "severity_threshold": "extreme"}, headers=h)
        assert r.status_code == 422
        # full scan
        sid_all = client.post("/api/scans", json={"project_id": pid, "path": FIX}, headers=h).json()["scan_id"]
        assert _wait_scan(h, sid_all)["status"] == "COMPLETED"
        all_n = client.get("/api/findings", params={"scan_id": sid_all}, headers=h).json()
        assert len(all_n) >= 3
        # high threshold persists a subset
        sid_high = client.post("/api/scans", json={"project_id": pid, "path": FIX,
                                                   "severity_threshold": "high"}, headers=h).json()["scan_id"]
        assert _wait_scan(h, sid_high)["status"] == "COMPLETED"
        high_n = client.get("/api/findings", params={"scan_id": sid_high}, headers=h).json()
        assert all(f["severity"] == "HIGH" for f in high_n)
        assert len(high_n) <= len(all_n)
        # excluding docs drops the docs finding
        sid_nd = client.post("/api/scans", json={"project_id": pid, "path": FIX,
                                                 "include_docs": False}, headers=h).json()["scan_id"]
        assert _wait_scan(h, sid_nd)["status"] == "COMPLETED"
        nd = client.get("/api/findings", params={"scan_id": sid_nd}, headers=h).json()
        assert all("docs/setup.md" not in f["file_path"] for f in nd)
        # wildcard-y search does not error and raw secret never leaks
        r = client.get("/api/findings", params={"project_id": pid, "q": "100%_weird"}, headers=h)
        assert r.status_code == 200
        assert "AKIAIOSFODNN7EXAMPLE" not in r.text
        # bulk update persists
        ids = [f["id"] for f in all_n[:2]]
        assert client.post("/api/findings/bulk-update",
                           json={"ids": ids, "status": "IGNORED"}, headers=h).json()["updated"] == 2
        got = client.get("/api/findings", params={"scan_id": sid_all, "status": "IGNORED"}, headers=h).json()
        assert {f["id"] for f in got} >= set(ids)
    finally:
        client.delete(f"/api/projects/{pid}", headers=h)


def test_reports_crud_download():
    h = _auth()
    name = f"rep-{uuid.uuid4().hex[:8]}"
    pid = client.post("/api/projects", json={"name": name, "path": FIX}, headers=h).json()["id"]
    try:
        sid = client.post("/api/scans", json={"project_id": pid, "path": FIX}, headers=h).json()["scan_id"]
        assert _wait_scan(h, sid)["status"] == "COMPLETED"
        for fmt in ("json", "csv", "sarif", "html"):
            r = client.post("/api/reports", json={"project_id": pid, "scan_id": sid, "format": fmt}, headers=h)
            assert r.status_code == 201, (fmt, r.text)
            rid = r.json()["id"]
            dl = client.get(f"/api/reports/{rid}/download", headers=h)
            assert dl.status_code == 200 and len(dl.content) > 0
            assert "AKIAIOSFODNN7EXAMPLE" not in dl.text
            assert client.delete(f"/api/reports/{rid}", headers=h).status_code == 200
            assert client.get(f"/api/reports/{rid}/download", headers=h).status_code == 404
        assert client.get("/api/reports", params={"project_id": pid}, headers=h).json() == []
        assert client.post("/api/reports", json={"project_id": pid, "scan_id": "nope",
                                                 "format": "json"}, headers=h).status_code == 404
    finally:
        client.delete(f"/api/projects/{pid}", headers=h)


def test_settings_validation():
    h = _auth()
    assert client.get("/api/settings", headers=h).status_code == 200
    r = client.post("/api/settings", json={"severity_default": "high", "ml_enabled": "1"}, headers=h)
    assert r.status_code == 200
    assert client.get("/api/settings", headers=h).json()["severity_default"] == "high"
    assert client.post("/api/settings", json={"severity_default": "extreme"}, headers=h).status_code == 422
    assert client.post("/api/settings", json={"ml_enabled": "yes"}, headers=h).status_code == 422
    assert client.post("/api/settings", json={"api_secret_x": "v"}, headers=h).status_code == 400
    assert client.post("/api/settings", json={"auth_token": "v"}, headers=h).status_code == 400


def test_benchmark_run_and_list():
    h = _auth()
    r = client.post("/api/benchmarks/run", json={"path": FIX}, headers=h)
    assert r.status_code == 202, r.text
    jid = r.json()["job_id"]
    done = None
    for _ in range(120):
        job = client.get(f"/api/benchmarks/jobs/{jid}", headers=h).json()
        if job["status"] in ("DONE", "FAILED"):
            done = job
            break
        time.sleep(0.5)
    assert done and done["status"] == "DONE", done
    assert done["result"]["files_scanned"] >= 1
    blist = client.get("/api/benchmarks", headers=h).json()
    assert blist["runs"] and blist["latest"]["files_scanned"] >= 1
    assert blist["model_test_metrics"].get("f1", 0) > 0.5
    rid = blist["runs"][0]["id"]
    assert client.get(f"/api/benchmarks/{rid}", headers=h).json()["findings"] >= 0
    assert client.post("/api/benchmarks/run", json={"path": "C:/no/such/bench"}, headers=h).status_code == 400


def test_dashboard_reflects_data():
    h = _auth()
    d = client.get("/api/dashboard", headers=h).json()
    assert set(("projects", "scans", "findings", "high", "open", "severity",
                "recent_scans", "recent_activity")) <= set(d.keys())
