"""Pydantic schemas."""
from __future__ import annotations

from pydantic import BaseModel, Field


class ProjectIn(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    path: str = ""
    description: str = ""


class ScanIn(BaseModel):
    project_id: str
    path: str = ""
    include_docs: bool = True
    include_tests: bool = True
    use_ml: bool = True
    severity_threshold: str = "low"
    excludes: list[str] = Field(default_factory=list)
    max_scan_bytes: int = 0


class FindingPatch(BaseModel):
    status: str


class BulkUpdate(BaseModel):
    ids: list[str]
    status: str


class ReportIn(BaseModel):
    project_id: str = Field(min_length=1, max_length=64)
    scan_id: str = Field(min_length=1, max_length=64)
    format: str = Field(default="json", max_length=16)


class BenchmarkIn(BaseModel):
    path: str = Field(default="", max_length=4096)
