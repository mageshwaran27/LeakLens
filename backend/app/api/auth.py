"""Local-first authentication: first-run setup, login, logout, me.

Setup (POST /api/auth/setup) is allowed ONLY when no users exist yet —
there are no default credentials. All other auth endpoints use opaque
bearer tokens (stored hashed, 7-day expiry, revoked on logout).
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app.core.redaction import redact_text
from backend.app.core.security import hash_password, new_token, token_expiry, verify_password
from backend.app.database.db import get_db
from backend.app.models.entities import Activity, AuthToken, User

import logging as _logging
logger = _logging.getLogger("leaklens")

router = APIRouter(prefix="/api/auth")


class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=256)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def resolve_token(db: Session, token: str):
    """Return the User for a valid, unexpired bearer token, else None."""
    import hashlib
    if not token:
        return None
    digest = hashlib.sha256(token.encode()).hexdigest()
    row = db.get(AuthToken, digest)
    if not row:
        return None
    exp = row.expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    if exp <= _now():
        db.delete(row)
        db.commit()
        return None
    return db.get(User, row.user_id)


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    user = getattr(request.state, "user", None)
    if user is None:
        raise HTTPException(401, "Authentication required")
    return user


@router.get("/status")
def auth_status(db: Session = Depends(get_db)):
    return {"setup_required": db.query(User).count() == 0}


@router.post("/setup", status_code=201)
def setup(body: Credentials, db: Session = Depends(get_db)):
    if db.query(User).count() > 0:
        raise HTTPException(403, "Setup already completed")
    username = body.username.strip()
    if not username:
        raise HTTPException(422, "Username must not be blank")
    u = User(username=username, password_hash=hash_password(body.password))
    db.add(u)
    db.add(Activity(kind="User created",
                   message=redact_text(f"Initial admin account created")[:900]))
    db.commit()
    db.refresh(u)
    logger.info("auth setup completed username=%s", username)
    return {"id": u.id, "username": u.username}


@router.post("/login")
def login(body: Credentials, db: Session = Depends(get_db)):
    u = db.query(User).filter_by(username=body.username.strip()).first()
    if not u or not verify_password(body.password, u.password_hash):
        logger.warning("auth login failed username=%s", body.username.strip())
        raise HTTPException(401, "Invalid username or password")
    token, digest = new_token()
    exp = token_expiry()
    db.add(AuthToken(token_hash=digest, user_id=u.id, expires_at=exp))
    db.commit()
    logger.info("auth login username=%s", u.username)
    return {"token": token, "expires_at": exp.isoformat(), "username": u.username}


@router.post("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    import hashlib
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        digest = hashlib.sha256(auth[7:].strip().encode()).hexdigest()
        row = db.get(AuthToken, digest)
        if row:
            db.delete(row)
            db.commit()
    return {"ok": True}


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return {"id": user.id, "username": user.username,
            "created_at": user.created_at.isoformat() if user.created_at else None}
