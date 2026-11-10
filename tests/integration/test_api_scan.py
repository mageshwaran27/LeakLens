"""API + scan lifecycle integration: project -> scan -> progress -> findings -> update.

Uses the isolated test database from tests/conftest.py (never the dev DB).
Project names are unique per run and the project is deleted afterwards, so
this test is independently repeatable.
"""
import sys
import time
import uuid
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


def _auth():
    r = client.post("/api/auth/setup", json={"username": "tester", "password": "test-password-1"})
    assert r.status_code in (201, 403), r.text
    if r.status_code == 403:
        db = SessionLocal()
        try:
            if not db.query(User).filter_by(username="tester").first():
                db.add(User(username="tester", password_hash=hash_password("test-password-1")))
                db.commit()
        finally:
            db.close()
    r = client.post("/api/auth/login", json={"username": "tester", "password": "test-password-1"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def test_lifecycle():
    assert client.get("/health").status_code == 200
    h = _auth()
    name = f"e2e-{uuid.uuid4().hex[:8]}"
    r = client.post("/api/projects", json={"name": name, "path": FIX}, headers=h)
    assert r.status_code == 201, r.text
    pid = r.json()["id"]
    try:
        s = client.post("/api/scans", json={"project_id": pid, "path": FIX}, headers=h).json()
        sid = s["scan_id"]
        for _ in range(240):
            pr = client.get(f"/api/scans/{sid}/progress", headers=h).json()
            if pr["status"] in ("COMPLETED", "FAILED", "CANCELLED"):
                break
            time.sleep(0.5)
        assert pr["status"] == "COMPLETED", pr
        assert client.get(f"/api/scans/{sid}", headers=h).json()["status"] == "COMPLETED"
        findings = client.get("/api/findings", params={"project_id": pid}, headers=h).json()
        assert len(findings) >= 3
        assert all("AKIAIOSFODNN7EXAMPLE" not in str(f) for f in findings)
        fid = findings[0]["id"]
        assert client.patch(f"/api/findings/{fid}", json={"status": "RESOLVED"}, headers=h).json()["status"] == "RESOLVED"
        assert client.get("/api/dashboard", headers=h).json()["findings"] >= 1
        assert client.get("/api/models/active", headers=h).status_code == 200
    finally:
        client.delete(f"/api/projects/{pid}", headers=h)
