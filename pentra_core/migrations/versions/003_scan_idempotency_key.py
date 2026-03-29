"""003 — Add DB-backed scan idempotency key constraint.

Revision ID: 003_scan_idempotency_key
Create Date: 2026-03-21
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "003_scan_idempotency_key"
down_revision = "002_attack_graph_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("idempotency_key", sa.String(length=128), nullable=True),
    )
    op.create_index(
        "ix_scans_idempotency_key",
        "scans",
        ["idempotency_key"],
        unique=False,
    )
    op.create_index(
        "uq_scans_idempotency_key",
        "scans",
        ["tenant_id", "created_by", "asset_id", "scan_type", "idempotency_key"],
        unique=True,
        postgresql_where=sa.text("idempotency_key IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_scans_idempotency_key", table_name="scans")
    op.drop_index("ix_scans_idempotency_key", table_name="scans")
    op.drop_column("scans", "idempotency_key")
