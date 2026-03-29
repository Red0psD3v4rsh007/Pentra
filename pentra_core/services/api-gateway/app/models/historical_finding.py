"""Historical finding models — asset-scoped cross-scan lineage and occurrences."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from pentra_common.db.base import Base, TenantMixin, TimestampMixin


class HistoricalFinding(Base, TenantMixin, TimestampMixin):
    """Deduplicated cross-scan lineage for one asset-scoped finding family."""

    __tablename__ = "historical_findings"
    __table_args__ = (
        UniqueConstraint("asset_id", "lineage_key", name="uq_historical_finding_asset_lineage"),
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
    lineage_key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    vulnerability_type: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    route_group: Mapped[str | None] = mapped_column(Text, nullable=True)
    target: Mapped[str] = mapped_column(Text, nullable=False)
    latest_severity: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    latest_verification_state: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    latest_source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    first_seen_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    last_seen_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    latest_finding_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("findings.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))

    asset: Mapped["Asset"] = relationship("Asset")
    occurrences: Mapped[list["HistoricalFindingOccurrence"]] = relationship(
        "HistoricalFindingOccurrence",
        back_populates="historical_finding",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class HistoricalFindingOccurrence(Base, TenantMixin, TimestampMixin):
    """One archived occurrence of a historical finding in one completed scan."""

    __tablename__ = "historical_finding_occurrences"
    __table_args__ = (
        UniqueConstraint(
            "historical_finding_id",
            "scan_id",
            name="uq_historical_finding_occurrence_scan",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    historical_finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("historical_findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("findings.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    verification_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    historical_finding: Mapped[HistoricalFinding] = relationship(
        "HistoricalFinding",
        back_populates="occurrences",
    )
