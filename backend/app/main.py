
"""FastAPI application entrypoint for LeakLens."""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.app.api.auth import router as auth_router
from backend.app.api.routes import router
from backend.app.core.config import settings
from backend.app.core.redaction import redact_text
from backend.app.database.db import Base, SessionLocal, engine


# --------------------------------------------------
# LOGGING
# --------------------------------------------------

logging.basicConfig(
    level=getattr(
        logging,
        settings.log_level.upper(),
        logging.INFO
    ),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s"
)

logger = logging.getLogger("leaklens")


# --------------------------------------------------
# DATABASE INITIALIZATION
# --------------------------------------------------

Base.metadata.create_all(bind=engine)

logger.info(
    "Startup: db=%s model=%s privacy=%s",
    settings.database_url,
    settings.active_model,
    settings.privacy_mode
)


# --------------------------------------------------
# FASTAPI APPLICATION
# --------------------------------------------------

app = FastAPI(
    title="LeakLens",
    version=settings.app_version,
    description="LeakLens API"
)


# --------------------------------------------------
# CORS CONFIGURATION
# --------------------------------------------------

app.add_middleware(
    CORSMiddleware,

    # Existing configured origins
    allow_origins=settings.cors_origin_list(),

    # Allow localhost and 127.0.0.1 on any development port
    allow_origin_regex=(
        r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$"
    ),

    allow_credentials=True,

    allow_methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS"
    ],

    allow_headers=["*"],

    expose_headers=["Content-Disposition"],

    max_age=600
)


# --------------------------------------------------
# API ROUTERS
# --------------------------------------------------

app.include_router(auth_router)
app.include_router(router)


# --------------------------------------------------
# PUBLIC AUTHENTICATION ENDPOINTS
# --------------------------------------------------

_AUTH_OPEN = {
    "/api/auth/login",
    "/api/auth/register",
    "/api/auth/setup",
    "/api/auth/status"
}


# --------------------------------------------------
# LOCAL AUTHENTICATION MIDDLEWARE
# --------------------------------------------------

@app.middleware("http")
async def local_auth(request: Request, call_next):
    """
    Protect API routes using bearer-token authentication.

    Public:
        Login
        Registration
        Setup
        Authentication status

    Protected:
        Other API endpoints

    OPTIONS requests:
        Allowed for CORS preflight.
    """

    path = request.url.path

    # Allow CORS preflight requests
    if request.method == "OPTIONS":
        return await call_next(request)

    # Allow non-API routes
    if not path.startswith("/api/"):
        return await call_next(request)

    # Allow public authentication endpoints
    if path in _AUTH_OPEN:
        return await call_next(request)

    # Validate bearer token
    from backend.app.api.auth import resolve_token

    user = None

    authorization = request.headers.get(
        "authorization",
        ""
    )

    if authorization.lower().startswith("bearer "):

        token = authorization[7:].strip()

        if token:
            db = SessionLocal()

            try:
                user = resolve_token(db, token)

            finally:
                db.close()

    # Reject unauthenticated requests
    if user is None:
        return JSONResponse(
            status_code=401,
            content={
                "detail": "Authentication required"
            }
        )

    request.state.user = user

    return await call_next(request)


# --------------------------------------------------
# GLOBAL EXCEPTION HANDLER
# --------------------------------------------------

@app.exception_handler(Exception)
async def global_exception_handler(
    request: Request,
    exc: Exception
):
    logger.exception(
        "Unhandled exception on %s",
        request.url.path
    )

    if isinstance(exc, HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "detail": exc.detail
            }
        )

    return JSONResponse(
        status_code=500,
        content={
            "detail": redact_text(str(exc))[:500]
        }
    )


# --------------------------------------------------
# HEALTH CHECK
# --------------------------------------------------

@app.get("/health")
def health():

    return {
        "status": "ok",
        "app": settings.app_name,
        "version": settings.app_version,
        "privacy_mode": settings.privacy_mode,
        "cloud_enabled": settings.cloud_analysis_enabled
    }


# --------------------------------------------------
# ROOT ENDPOINT
# --------------------------------------------------

@app.get("/")
def root():

    return {
        "app": "LeakLens",
        "docs": "/docs",
        "health": "/health"
    }


# --------------------------------------------------
# SERVER STATUS
# --------------------------------------------------

@app.get("/api/server-status")
def server_status():

    return {
        "status": "running",
        "application": "LeakLens",
        "authentication": "enabled"
    }
