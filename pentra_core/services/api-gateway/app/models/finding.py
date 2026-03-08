"""Finding SQLAlchemy model — shared across scanner, exploit verify, and AI analysis."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, SmallInteger, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import Numeric

from pentra_common.db.base import Base, TenantMixin


class Finding(Base, TenantMixin):
    """Vulnerability finding — produced by scanners, exploit verification, or AI analysis.

    The ``source_type`` discriminator identifies which pipeline stage
    generated this finding, enabling a single unified model.
    """

    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    # tenant_id inherited from TenantMixin
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, index=True
    )
    scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True, index=True,
        comment="Job that produced this finding (null for AI-generated)",
    )
    source_type: Mapped[str] = mapped_column(
        Enum("scanner", "exploit_verify", "ai_analysis", name="finding_source_type"),
        nullable=False,
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[str] = mapped_column(
        Enum("critical", "high", "medium", "low", "info", name="finding_severity"),
        nullable=False,
        index=True,
    )
    confidence: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, comment="0–100"
    )
    cve_id: Mapped[str | None] = mapped_column(String(20), nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(
        Numeric(3, 1), nullable=True, comment="0.0–10.0"
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    tool_source: Mapped[str] = mapped_column(
        String(50), nullable=False, comment="nmap, nuclei, metasploit, ai_triage, etc."
    )
    is_false_positive: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    fp_probability: Mapped[int | None] = mapped_column(
        SmallInteger, nullable=True, comment="AI-scored false-positive probability 0–100"
    )
    fingerprint: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True,
        comment="Content-hash for cross-tool deduplication",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )

    # Relationships
    scan = relationship("Scan", back_populates="findings")
