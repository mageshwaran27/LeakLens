"""LeakLens central configuration. Local-first: cloud off by default."""
from __future__ import annotations

import os
from pathlib import Path

from pydantic_settings import BaseSettings

ROOT = Path(__file__).resolve().parents[2]
# Canonical database location: <project-root>/leaklens.db (absolute), unless
# LEAKLENS_DATABASE_URL is set. The legacy backend/leaklens.db file (if present
# from older runs) is superseded and no longer used — see README.
PROJECT_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    app_name: str = "LeakLens"
    app_version: str = "1.0.0"
    detection_engine_version: str = "1.0.0"
    database_url: str = f"sqlite:///{(PROJECT_ROOT / 'leaklens.db').as_posix()}"
    max_file_bytes: int = 1_000_000
    max_scan_bytes: int = 500_000_000
    default_excludes: str = ".git,node_modules,venv,.venv,dist,build,target,coverage,__pycache__,.idea,.vscode"
    privacy_mode: str = "LOCAL ONLY"
    cloud_analysis_enabled: bool = False
    store_raw_values: bool = False
    active_model: str = "leaklens-context-v1"
    cors_origins: str = ("http://localhost:3000,http://127.0.0.1:3000,"
                         "http://localhost:8000,http://127.0.0.1:8000,"
                         "http://localhost:8080,http://127.0.0.1:8080")
    log_level: str = "INFO"
    model_config = {"env_prefix": "LEAKLENS_", "env_file": ".env", "extra": "ignore"}

    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


settings = Settings()


def excluded_dirs() -> list[str]:
    return [e.strip() for e in settings.default_excludes.split(",") if e.strip()]
