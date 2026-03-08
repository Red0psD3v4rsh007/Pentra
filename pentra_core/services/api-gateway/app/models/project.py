"""Project SQLAlchemy model."""

from __future__ import annotations

import uuid

from sqlalchemy import String, Text, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from pentra_common.db.base import Base, SoftDeleteMixin, TenantMixin, TimestampMixin


class Project(Base, TenantMixin, TimestampMixin, SoftDeleteMixin):
    """Organisational grouping: tenant → projects → assets.

    Tenants use projects to organise their targets by application,
    business unit, or engagement scope.
    """

    __tablename__ = "projects"
    __table_args__ = (
        # Slug must be unique within a tenant
        {"comment": "Tenant-scoped project grouping for assets"},
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    # tenant_id inherited from TenantMixin
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_: Mapped[dict] = mapped_column(
        "metadata", JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    # Relationships
    tenant = relationship("Tenant", back_populates="projects")
    assets: Mapped[list] = relationship("Asset", back_populates="project", lazy="select")
