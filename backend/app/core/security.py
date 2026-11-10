"""Local auth primitives: PBKDF2 password hashing + opaque bearer tokens.

No third-party auth dependencies (stdlib only). Passwords are never stored;
tokens are stored as SHA-256 hashes and expire. Nothing secret is logged.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

ITERATIONS = 600_000
TOKEN_TTL = timedelta(days=7)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    return (f"pbkdf2-sha256${ITERATIONS}"
            f"${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}")


def verify_password(password: str, reference: str) -> bool:
    try:
        algo, it, salt_b64, dk_b64 = reference.split("$")
        if algo != "pbkdf2-sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                 base64.b64decode(salt_b64), int(it))
        return secrets.compare_digest(dk, base64.b64decode(dk_b64))
    except Exception:
        return False


def new_token() -> tuple[str, str]:
    """Return (bearer_token, sha256_hex_for_storage)."""
    token = secrets.token_urlsafe(32)
    return token, hashlib.sha256(token.encode()).hexdigest()


def token_expiry() -> datetime:
    return datetime.now(timezone.utc) + TOKEN_TTL
