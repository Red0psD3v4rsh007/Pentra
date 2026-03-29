"""Asset-group SQLAlchemy models for reusable multi-target scopes."""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, String, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from pentra_common.db.base import Base, SoftDeleteMixin, TenantMixin, TimestampMixin


class AssetGroup(Base, TenantMixin, TimestampMixin, SoftDeleteMixin):
    """Reusable grouping of assets under a single project."""

    __tablename__ = "asset_groups"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )

    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_: Mapped[dict] = mapped_column(
        "metadata",
        JSONB,
        nullable=False,
        server_default=text("'{}'::jsonb"),
    )

    project: Mapped["Project"] = relationship(
        "Project",
        back_populates="asset_groups",
        lazy="select",
    )
    members: Mapped[list["AssetGroupMember"]] = relationship(
        "AssetGroupMember",
        back_populates="group",
        cascade="all, delete-orphan",
        lazy="select",
    )


class AssetGroupMember(Base, TenantMixin, TimestampMixin):
    """Membership link between an asset group and an asset."""

    __tablename__ = "asset_group_members"
    __table_args__ = (
        UniqueConstraint("asset_group_id", "asset_id", name="uq_asset_group_member"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )

    asset_group_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("asset_groups.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    group: Mapped["AssetGroup"] = relationship("AssetGroup", back_populates="members")
    asset: Mapped["Asset"] = relationship("Asset", lazy="select")
