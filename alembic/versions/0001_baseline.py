"""Baseline schema (projects, scans, findings, reports, activities,
model_versions, dataset_versions, app_settings, users, auth_tokens).

Matches backend/app/models/entities.py as of 2026-10-01.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "projects",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(256), nullable=False, unique=True),
        sa.Column("path", sa.String(1024), nullable=False, server_default=""),
        sa.Column("description", sa.Text(), server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "scans",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("project_id", sa.String(64), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("status", sa.String(32), server_default="CREATED"),
        sa.Column("stage", sa.String(64), server_default="queued"),
        sa.Column("files_discovered", sa.Integer(), server_default="0"),
        sa.Column("files_scanned", sa.Integer(), server_default="0"),
        sa.Column("candidates", sa.Integer(), server_default="0"),
        sa.Column("findings_count", sa.Integer(), server_default="0"),
        sa.Column("duration_ms", sa.Integer(), server_default="0"),
        sa.Column("error", sa.Text(), server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("scan_id", sa.String(64), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("project_id", sa.String(64), nullable=False),
        sa.Column("detector_id", sa.String(128), server_default=""),
        sa.Column("category", sa.String(128), server_default=""),
        sa.Column("context_type", sa.String(64), server_default=""),
        sa.Column("severity", sa.String(16), server_default="LOW"),
        sa.Column("confidence", sa.Float(), server_default="0.0"),
        sa.Column("file_path", sa.String(1024), server_default=""),
        sa.Column("line_number", sa.Integer(), server_default="0"),
        sa.Column("column", sa.Integer(), server_default="0"),
        sa.Column("masked_value", sa.String(512), server_default=""),
        sa.Column("fingerprint", sa.String(128), server_default=""),
        sa.Column("evidence", sa.Text(), server_default="[]"),
        sa.Column("recommendation", sa.Text(), server_default=""),
        sa.Column("status", sa.String(32), server_default="OPEN"),
        sa.Column("created_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "reports",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("project_id", sa.String(64), nullable=False),
        sa.Column("scan_id", sa.String(64), nullable=False),
        sa.Column("format", sa.String(16), server_default="json"),
        sa.Column("path", sa.String(1024), server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "activities",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("kind", sa.String(128), server_default=""),
        sa.Column("message", sa.String(1024), server_default=""),
        sa.Column("project_id", sa.String(64), server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "model_versions",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("version", sa.String(32), server_default="1.0.0"),
        sa.Column("algorithm", sa.String(128), server_default=""),
        sa.Column("dataset_version", sa.String(64), server_default=""),
        sa.Column("feature_version", sa.String(64), server_default=""),
        sa.Column("metrics_json", sa.Text(), server_default="{}"),
        sa.Column("path", sa.String(1024), server_default=""),
        sa.Column("is_production", sa.Integer(), server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "dataset_versions",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("version", sa.String(64), nullable=False),
        sa.Column("samples", sa.Integer(), server_default="0"),
        sa.Column("positives", sa.Integer(), server_default="0"),
        sa.Column("negatives", sa.Integer(), server_default="0"),
        sa.Column("notes", sa.Text(), server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "app_settings",
        sa.Column("key", sa.String(128), primary_key=True),
        sa.Column("value", sa.Text(), server_default=""),
    )
    op.create_table(
        "users",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("username", sa.String(128), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(512), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "auth_tokens",
        sa.Column("token_hash", sa.String(128), primary_key=True),
        sa.Column("user_id", sa.String(64), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True)),
    )


def downgrade() -> None:
    for table in ("auth_tokens", "users", "app_settings", "dataset_versions",
                  "model_versions", "activities", "reports", "findings",
                  "scans", "projects"):
        op.drop_table(table)
