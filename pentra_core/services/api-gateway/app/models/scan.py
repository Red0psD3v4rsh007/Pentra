# """Scan and ScanJob SQLAlchemy models."""

# from __future__ import annotations

# import uuid

# from sqlalchemy import DateTime, Enum, ForeignKey, Integer, SmallInteger, String, Text, text
# from sqlalchemy.dialects.postgresql import JSONB, UUID
# from sqlalchemy.orm import Mapped, mapped_column, relationship
# from datetime import datetime

# from pentra_common.db.base import Base, TenantMixin, TimestampMixin


# class Scan(Base, TenantMixin, TimestampMixin):
#     """Pentest scan — targets a single asset, decomposes into scan_jobs.

#     Status follows the MOD-01.5 revised 13-state machine.
#     """

#     __tablename__ = "scans"

#     id: Mapped[uuid.UUID] = mapped_column(
#         UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
#     )
#     # tenant_id inherited from TenantMixin
#     asset_id: Mapped[uuid.UUID] = mapped_column(
#         UUID(as_uuid=True),
#         ForeignKey("assets.id", ondelete="CASCADE"),
#         nullable=False,
#         index=True,
#     )
#     created_by: Mapped[uuid.UUID | None] = mapped_column(
#         UUID(as_uuid=True), nullable=True
#     )
#     scan_type: Mapped[str] = mapped_column(
#         Enum("recon", "vuln", "full", "exploit_verify", name="scan_type"),
#         nullable=False,
#     )
#     status: Mapped[str] = mapped_column(
#         String(30), nullable=False, server_default=text("'queued'"), index=True
#     )
#     priority: Mapped[str] = mapped_column(
#         Enum("critical", "high", "normal", "low", name="scan_priority"),
#         nullable=False,
#         server_default=text("'normal'"),
#     )
#     config: Mapped[dict] = mapped_column(
#         JSONB, nullable=False, server_default=text("'{}'::jsonb")
#     )
#     progress: Mapped[int] = mapped_column(
#         SmallInteger, nullable=False, server_default=text("0")
#     )
#     started_at: Mapped[datetime | None] = mapped_column(
#         DateTime(timezone=True), nullable=True
#     )
#     completed_at: Mapped[datetime | None] = mapped_column(
#         DateTime(timezone=True), nullable=True
#     )
#     error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
#     result_summary: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

#     # Relationships
#     asset = relationship("Asset", back_populates="scans")
#     jobs: Mapped[list[ScanJob]] = relationship(
#         "ScanJob", back_populates="scan", cascade="all, delete-orphan", lazy="select"
#     )
#     findings: Mapped[list] = relationship(
#         "Finding", back_populates="scan", cascade="all, delete-orphan", lazy="select"
#     )
#     dag = relationship(
#         "ScanDAG", back_populates="scan", uselist=False, lazy="select",
#     )
#     artifacts: Mapped[list] = relationship(
#         "ScanArtifact", back_populates="scan", cascade="all, delete-orphan", lazy="select",
#     )



# class ScanJob(Base, TenantMixin, TimestampMixin):
#     """Individual execution unit within a scan — one per tool per phase.

#     Created by scan-svc at scan submission time.
#     Consumed and updated by MOD-04 orchestrator.
#     """

#     __tablename__ = "scan_jobs"
#     __table_args__ = (
#         {"comment": "Execution units for scan pipeline — consumed by orchestrator"},
#     )

#     id: Mapped[uuid.UUID] = mapped_column(
#         UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
#     )
#     # tenant_id inherited from TenantMixin
#     scan_id: Mapped[uuid.UUID] = mapped_column(
#         UUID(as_uuid=True), nullable=False, index=True
#     )
#     phase: Mapped[int] = mapped_column(
#         SmallInteger, nullable=False,
#         comment="Pipeline phase 0–6: scope, recon, enum, vuln, exploit, ai, report",
#     )
#     tool: Mapped[str] = mapped_column(
#         String(50), nullable=False,
#         comment="Tool identifier: nmap, nuclei, zap, subfinder, etc.",
#     )
#     status: Mapped[str] = mapped_column(
#         String(20), nullable=False, server_default=text("'pending'"), index=True,
#     )
#     priority: Mapped[str] = mapped_column(
#         Enum("critical", "high", "normal", "low", name="scan_priority", create_type=False),
#         nullable=False,
#     )
#     worker_id: Mapped[str | None] = mapped_column(
#         String(100), nullable=True, comment="Pod/worker name assigned"
#     )
#     input_ref: Mapped[str | None] = mapped_column(
#         Text, nullable=True, comment="S3 key or Redis stream ID for input"
#     )
#     output_ref: Mapped[str | None] = mapped_column(
#         Text, nullable=True, comment="S3 key or Redis stream ID for output"
#     )
#     started_at: Mapped[datetime | None] = mapped_column(
#         DateTime(timezone=True), nullable=True
#     )
#     completed_at: Mapped[datetime | None] = mapped_column(
#         DateTime(timezone=True), nullable=True
#     )
#     error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
#     retry_count: Mapped[int] = mapped_column(
#         SmallInteger, nullable=False, server_default=text("0")
#     )
#     max_retries: Mapped[int] = mapped_column(SmallInteger, nullable=False)
#     timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
#     checkpoint_ref: Mapped[str | None] = mapped_column(
#         Text, nullable=True, comment="S3 key for Spot-interruption resume"
#     )

#     # Relationships
#     scan: Mapped[Scan] = relationship("Scan", back_populates="jobs")


"""Scan and ScanJob SQLAlchemy models."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    SmallInteger,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from pentra_common.db.base import Base, TenantMixin, TimestampMixin


class Scan(Base, TenantMixin, TimestampMixin):
    """Pentest scan targeting a single asset."""

    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )

    # tenant_id inherited from TenantMixin

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

    scan_type: Mapped[str] = mapped_column(
        Enum("recon", "vuln", "full", "exploit_verify", name="scan_type"),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        server_default=text("'queued'"),
        index=True,
    )

    priority: Mapped[str] = mapped_column(
        Enum("critical", "high", "normal", "low", name="scan_priority"),
        nullable=False,
        server_default=text("'normal'"),
    )

    config: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        server_default=text("'{}'::jsonb"),
    )

    progress: Mapped[int] = mapped_column(
        SmallInteger,
        nullable=False,
        server_default=text("0"),
    )

    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    result_summary: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Relationships

    asset: Mapped["Asset"] = relationship(
        "Asset",
        back_populates="scans",
    )

    jobs: Mapped[list["ScanJob"]] = relationship(
        "ScanJob",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="select",
    )

    findings: Mapped[list["Finding"]] = relationship(
        "Finding",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="select",
    )

    dag = relationship(
        "ScanDAG",
        back_populates="scan",
        uselist=False,
        lazy="select",
    )

    artifacts: Mapped[list["ScanArtifact"]] = relationship(
        "ScanArtifact",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="select",
    )


class ScanJob(Base, TenantMixin, TimestampMixin):
    """Execution unit within a scan pipeline."""

    __tablename__ = "scan_jobs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )

    # tenant_id inherited from TenantMixin

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    phase: Mapped[int] = mapped_column(
        SmallInteger,
        nullable=False,
        comment="Pipeline phase 0–6",
    )

    tool: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="Tool identifier",
    )

    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        server_default=text("'pending'"),
        index=True,
    )

    priority: Mapped[str] = mapped_column(
        Enum(
            "critical",
            "high",
            "normal",
            "low",
            name="scan_priority",
            create_type=False,
        ),
        nullable=False,
    )

    worker_id: Mapped[str | None] = mapped_column(String(100), nullable=True)

    input_ref: Mapped[str | None] = mapped_column(Text, nullable=True)

    output_ref: Mapped[str | None] = mapped_column(Text, nullable=True)

    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    retry_count: Mapped[int] = mapped_column(
        SmallInteger,
        nullable=False,
        server_default=text("0"),
    )

    max_retries: Mapped[int] = mapped_column(SmallInteger, nullable=False)

    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False)

    checkpoint_ref: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    scan: Mapped["Scan"] = relationship(
        "Scan",
        back_populates="jobs",
    )