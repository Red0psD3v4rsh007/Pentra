"""AuditLog SQLAlchemy model — security event logging."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from pentra_common.db.base import Base, TenantMixin


class AuditLog(Base, TenantMixin):
    """Immutable audit trail for security-relevant actions.

    Captures who did what, to which resource, and when.  Used for
    compliance (SOC 2, ISO 27001) and incident investigation.

    This table is append-only — no UPDATE or DELETE operations.
    """

    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    # tenant_id inherited from TenantMixin
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, index=True
    )
    action: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True,
        comment="Action verb: login, create_scan, delete_asset, invite_member, etc.",
    )
    resource_type: Mapped[str] = mapped_column(
        String(50), nullable=False,
        comment="Entity type: scan, asset, project, tenant, user",
    )
    resource_id: Mapped[str] = mapped_column(
        String(100), nullable=False,
        comment="UUID or identifier of the affected resource",
    )
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    details: Mapped[dict] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb"),
        comment="Additional context — old/new values, request metadata",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()"),
        index=True,
    )
