# """Asset and AssetTag SQLAlchemy models."""

# from __future__ import annotations

# import uuid

# from sqlalchemy import Enum, String, Text, UniqueConstraint, text
# from sqlalchemy.dialects.postgresql import JSONB, UUID
# from sqlalchemy.orm import Mapped, mapped_column, relationship
# from datetime import datetime
# from pentra_common.db.base import Base, SoftDeleteMixin, TenantMixin, TimestampMixin


# class Asset(Base, TenantMixin, TimestampMixin, SoftDeleteMixin):
#     """Scan target — belongs to a project.

#     Hierarchy: tenant → project → asset → scans → findings.
#     """

#     __tablename__ = "assets"

#     id: Mapped[uuid.UUID] = mapped_column(
#         UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
#     )
#     # tenant_id inherited from TenantMixin
#     project_id: Mapped[uuid.UUID] = mapped_column(
#         UUID(as_uuid=True), nullable=False, index=True
#     )
#     created_by: Mapped[uuid.UUID | None] = mapped_column(
#         UUID(as_uuid=True), nullable=True
#     )
#     name: Mapped[str] = mapped_column(String(255), nullable=False)
#     asset_type: Mapped[str] = mapped_column(
#         Enum("web_app", "api", "network", "repository", "cloud", name="asset_type"),
#         nullable=False,
#     )
#     target: Mapped[str] = mapped_column(
#         Text, nullable=False, comment="URL / IP / CIDR / repo URL / cloud ARN"
#     )
#     description: Mapped[str | None] = mapped_column(Text, nullable=True)
#     is_verified: Mapped[bool] = mapped_column(
#         nullable=False, server_default=text("false"),
#         comment="Ownership verification flag",
#     )
#     metadata_: Mapped[dict] = mapped_column(
#         "metadata", JSONB, nullable=False, server_default=text("'{}'::jsonb")
#     )

#     # Relationships
#     project = relationship("Project", back_populates="assets")
#     tags: Mapped[list[AssetTag]] = relationship(
#         "AssetTag", back_populates="asset", cascade="all, delete-orphan", lazy="joined"
#     )
#     scans: Mapped[list] = relationship("Scan", back_populates="asset", lazy="select")


# class AssetTag(Base):
#     """Key-value tag on an asset (e.g. env=production, team=infra)."""

#     __tablename__ = "asset_tags"
#     __table_args__ = (
#         UniqueConstraint("asset_id", "key", name="uq_asset_tag_key"),
#     )

#     id: Mapped[uuid.UUID] = mapped_column(
#         UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
#     )
#     asset_id: Mapped[uuid.UUID] = mapped_column(
#         UUID(as_uuid=True), nullable=False, index=True
#     )
#     key: Mapped[str] = mapped_column(String(100), nullable=False)
#     value: Mapped[str] = mapped_column(String(255), nullable=False)

#     # Relationships
#     asset: Mapped[Asset] = relationship("Asset", back_populates="tags")


"""Asset and AssetTag SQLAlchemy models."""

from __future__ import annotations

import uuid

from sqlalchemy import Enum, String, Text, UniqueConstraint, ForeignKey, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from datetime import datetime
from pentra_common.db.base import Base, SoftDeleteMixin, TenantMixin, TimestampMixin


class Asset(Base, TenantMixin, TimestampMixin, SoftDeleteMixin):
    """Scan target — belongs to a project."""

    __tablename__ = "assets"

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

    asset_type: Mapped[str] = mapped_column(
        Enum("web_app", "api", "network", "repository", "cloud", name="asset_type"),
        nullable=False,
    )

    target: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="URL / IP / CIDR / repo URL / cloud ARN",
    )

    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    is_verified: Mapped[bool] = mapped_column(
        nullable=False,
        server_default=text("false"),
    )

    metadata_: Mapped[dict] = mapped_column(
        "metadata",
        JSONB,
        nullable=False,
        server_default=text("'{}'::jsonb"),
    )

    # Relationships
    project: Mapped["Project"] = relationship("Project", back_populates="assets")

    tags: Mapped[list["AssetTag"]] = relationship(
        "AssetTag",
        back_populates="asset",
        cascade="all, delete-orphan",
        lazy="joined",
    )

    scans: Mapped[list["Scan"]] = relationship(
        "Scan",
        back_populates="asset",
        lazy="select",
    )


class AssetTag(Base):
    """Key-value tag on an asset."""

    __tablename__ = "asset_tags"
    __table_args__ = (
        UniqueConstraint("asset_id", "key", name="uq_asset_tag_key"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )

    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    key: Mapped[str] = mapped_column(String(100), nullable=False)

    value: Mapped[str] = mapped_column(String(255), nullable=False)

    asset: Mapped["Asset"] = relationship("Asset", back_populates="tags")