"""Persistence models. Findings store masked_value + fingerprint only."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.database.db import Base


def _uid() -> str:
    return uuid.uuid4().hex[:12]


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uid)
    name: Mapped[str] = mapped_column(String(256), unique=True, nullable=False)
    path: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    scans: Mapped[list["Scan"]] = relationship(back_populates="project", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="CREATED")
    stage: Mapped[str] = mapped_column(String(64), default="queued")
    files_discovered: Mapped[int] = mapped_column(Integer, default=0)
    files_scanned: Mapped[int] = mapped_column(Integer, default=0)
    candidates: Mapped[int] = mapped_column(Integer, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    project: Mapped[Project] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), nullable=False)
    project_id: Mapped[str] = mapped_column(String(64), nullable=False)
    detector_id: Mapped[str] = mapped_column(String(128), default="")
    category: Mapped[str] = mapped_column(String(128), default="")
    context_type: Mapped[str] = mapped_column(String(64), default="")
    severity: Mapped[str] = mapped_column(String(16), default="LOW")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    file_path: Mapped[str] = mapped_column(String(1024), default="")
    line_number: Mapped[int] = mapped_column(Integer, default=0)
    column: Mapped[int] = mapped_column(Integer, default=0)
    masked_value: Mapped[str] = mapped_column(String(512), default="")
    fingerprint: Mapped[str] = mapped_column(String(128), default="")
    evidence: Mapped[str] = mapped_column(Text, default="[]")
    recommendation: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(32), default="OPEN")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    scan: Mapped[Scan] = relationship(back_populates="findings")


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uid)
    project_id: Mapped[str] = mapped_column(String(64), nullable=False)
    scan_id: Mapped[str] = mapped_column(String(64), nullable=False)
    format: Mapped[str] = mapped_column(String(16), default="json")
    path: Mapped[str] = mapped_column(String(1024), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Activity(Base):
    __tablename__ = "activities"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uid)
    kind: Mapped[str] = mapped_column(String(128), default="")
    message: Mapped[str] = mapped_column(String(1024), default="")
    project_id: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ModelVersion(Base):
    __tablename__ = "model_versions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uid)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[str] = mapped_column(String(32), default="1.0.0")
    algorithm: Mapped[str] = mapped_column(String(128), default="")
    dataset_version: Mapped[str] = mapped_column(String(64), default="")
    feature_version: Mapped[str] = mapped_column(String(64), default="")
    metrics_json: Mapped[str] = mapped_column(Text, default="{}")
    path: Mapped[str] = mapped_column(String(1024), default="")
    is_production: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class DatasetVersion(Base):
    __tablename__ = "dataset_versions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uid)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    samples: Mapped[int] = mapped_column(Integer, default=0)
    positives: Mapped[int] = mapped_column(Integer, default=0)
    negatives: Mapped[int] = mapped_column(Integer, default=0)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class AppSetting(Base):
    __tablename__ = "app_settings"
    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uid)
    username: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class AuthToken(Base):
    __tablename__ = "auth_tokens"
    token_hash: Mapped[str] = mapped_column(String(128), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
