"""005 — Add scan scheduling support.

Revision ID: 005_scan_scheduling
Create Date: 2026-03-21
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "005_scan_scheduling"
down_revision = "004_job_dispatch_outbox"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("scheduled_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_scans_scheduled_at",
        "scans",
        ["scheduled_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_scans_scheduled_at", table_name="scans")
    op.drop_column("scans", "scheduled_at")
