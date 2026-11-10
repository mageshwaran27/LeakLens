"""Local auth: setup-once, login, wrong password, logout, route protection."""
import sys
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

SUFFIX = uuid.uuid4().hex[:8]
ADMIN = f"admin-{SUFFIX}"
PASSWORD = "correct-horse-11"


def _ensure_user(username: str, password: str) -> None:
    """Order-independent: use open setup when available, else insert directly."""
    r = client.post("/api/auth/setup", json={"username": username, "password": password})
    assert r.status_code in (201, 403), r.text
    if r.status_code == 403:
        db = SessionLocal()
        try:
            if not db.query(User).filter_by(username=username).first():
                db.add(User(username=username, password_hash=hash_password(password)))
                db.commit()
        finally:
            db.close()


def test_setup_login_logout_flow():
    assert isinstance(client.get("/api/auth/status").json()["setup_required"], bool)
    _ensure_user(ADMIN, PASSWORD)
    assert client.get("/api/auth/status").json()["setup_required"] is False
    # open setup is closed once any user exists
    assert client.post("/api/auth/setup",
                       json={"username": "second", "password": PASSWORD}).status_code == 403
    # wrong password rejected
    assert client.post("/api/auth/login",
                       json={"username": ADMIN, "password": "wrong-pass"}).status_code == 401
    # credential shape validation (pydantic, order-independent)
    assert client.post("/api/auth/login",
                       json={"username": "ab", "password": "short"}).status_code == 422
    r = client.post("/api/auth/login", json={"username": ADMIN, "password": PASSWORD})
    assert r.status_code == 200, r.text
    token = r.json()["token"]
    assert token and r.json()["username"] == ADMIN
    h = {"Authorization": f"Bearer {token}"}
    # me works
    assert client.get("/api/auth/me", headers=h).json()["username"] == ADMIN
    # protected route works with token, 401 without
    assert client.get("/api/projects", headers=h).status_code == 200
    assert client.get("/api/projects").status_code == 401
    assert client.post("/api/projects", json={"name": "x"}).status_code == 401
    # logout revokes
    assert client.post("/api/auth/logout", headers=h).status_code == 200
    assert client.get("/api/auth/me", headers=h).status_code == 401
    assert client.get("/api/projects", headers=h).status_code == 401
