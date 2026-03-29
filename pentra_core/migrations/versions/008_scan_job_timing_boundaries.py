"""008 — Add durable scan job timing boundaries.

Revision ID: 008_scan_job_timing_boundaries
Create Date: 2026-03-22
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "008_scan_job_timing_boundaries"
down_revision = "007_historical_findings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scan_jobs",
        sa.Column("scheduled_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "scan_jobs",
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.execute(
        """
        UPDATE scan_jobs
        SET scheduled_at = COALESCE(scheduled_at, created_at)
        WHERE scheduled_at IS NULL
        """
    )


def downgrade() -> None:
    op.drop_column("scan_jobs", "claimed_at")
    op.drop_column("scan_jobs", "scheduled_at")
