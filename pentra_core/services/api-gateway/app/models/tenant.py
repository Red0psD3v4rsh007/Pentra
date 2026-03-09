"""Tenant and TenantQuota SQLAlchemy models."""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, Enum, ForeignKey, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from datetime import datetime
from pentra_common.db.base import Base, TimestampMixin


class Tenant(Base, TimestampMixin):
    """Organisation — top of the hierarchy: tenant → projects → assets → scans → findings."""

    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    tier: Mapped[str] = mapped_column(
        Enum("free", "pro", "enterprise", name="tenant_tier"),
        nullable=False,
        server_default=text("'free'"),
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("true")
    )
    metadata_: Mapped[dict] = mapped_column(
        "metadata", JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )

    # Relationships
    quota: Mapped[TenantQuota | None] = relationship(
        "TenantQuota", back_populates="tenant", uselist=False, lazy="joined"
    )
    users: Mapped[list] = relationship("User", back_populates="tenant", lazy="select")
    projects: Mapped[list] = relationship(
        "Project", back_populates="tenant", lazy="select"
    )


class TenantQuota(Base):
    """Per-tenant resource limits — enforced at scan creation."""

    __tablename__ = "tenant_quotas"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    max_concurrent_scans: Mapped[int] = mapped_column(Integer, nullable=False)
    max_daily_scans: Mapped[int] = mapped_column(Integer, nullable=False)
    max_assets: Mapped[int] = mapped_column(Integer, nullable=False)
    max_projects: Mapped[int] = mapped_column(Integer, nullable=False)
    scans_today: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("0")
    )
    active_scans: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("0")
    )
    updated_at = TimestampMixin.updated_at

    # Relationships
    tenant: Mapped[Tenant] = relationship("Tenant", back_populates="quota")
