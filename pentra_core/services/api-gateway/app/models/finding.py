# """Finding SQLAlchemy model — shared across scanner, exploit verify, and AI analysis."""

# from __future__ import annotations

# import uuid
# from datetime import datetime

# from sqlalchemy import Boolean, DateTime, Enum, SmallInteger, String, Text, text
# from sqlalchemy.dialects.postgresql import JSONB, UUID
# from sqlalchemy.orm import Mapped, mapped_column, relationship
# from sqlalchemy.types import Numeric
# from datetime import datetime
# from pentra_common.db.base import Base, TenantMixin


# class Finding(Base, TenantMixin):
#     """Vulnerability finding — produced by scanners, exploit verification, or AI analysis.

#     The ``source_type`` discriminator identifies which pipeline stage
#     generated this finding, enabling a single unified model.
#     """

#     __tablename__ = "findings"

#     scan_id: Mapped[uuid.UUID] = mapped_column(
#     UUID(as_uuid=True),
#     ForeignKey("scans.id", ondelete="CASCADE"),
#     nullable=False,
#     index=True,
# )

#     id: Mapped[uuid.UUID] = mapped_column(
#         UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
#     )
#     # tenant_id inherited from TenantMixin
#     scan_id: Mapped[uuid.UUID] = mapped_column(
#         UUID(as_uuid=True), nullable=False, index=True
#     )
#     scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
#         UUID(as_uuid=True), nullable=True, index=True,
#         comment="Job that produced this finding (null for AI-generated)",
#     )
#     source_type: Mapped[str] = mapped_column(
#         Enum("scanner", "exploit_verify", "ai_analysis", name="finding_source_type"),
#         nullable=False,
#     )
#     title: Mapped[str] = mapped_column(String(500), nullable=False)
#     severity: Mapped[str] = mapped_column(
#         Enum("critical", "high", "medium", "low", "info", name="finding_severity"),
#         nullable=False,
#         index=True,
#     )
#     confidence: Mapped[int] = mapped_column(
#         SmallInteger, nullable=False, comment="0–100"
#     )
#     cve_id: Mapped[str | None] = mapped_column(String(20), nullable=True)
#     cvss_score: Mapped[float | None] = mapped_column(
#         Numeric(3, 1), nullable=True, comment="0.0–10.0"
#     )
#     description: Mapped[str | None] = mapped_column(Text, nullable=True)
#     evidence: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
#     remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
#     tool_source: Mapped[str] = mapped_column(
#         String(50), nullable=False, comment="nmap, nuclei, metasploit, ai_triage, etc."
#     )
#     is_false_positive: Mapped[bool] = mapped_column(
#         Boolean, nullable=False, server_default=text("false")
#     )
#     fp_probability: Mapped[int | None] = mapped_column(
#         SmallInteger, nullable=True, comment="AI-scored false-positive probability 0–100"
#     )
#     fingerprint: Mapped[str] = mapped_column(
#         String(64), nullable=False, index=True,
#         comment="Content-hash for cross-tool deduplication",
#     )
#     created_at: Mapped[datetime] = mapped_column(
#         DateTime(timezone=True), nullable=False, server_default=text("now()")
#     )

#     # Relationships
#     scan = relationship("Scan", back_populates="findings")


"""Finding SQLAlchemy model — shared across scanner, exploit verify, and AI analysis."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    SmallInteger,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import Numeric

from pentra_common.db.base import Base, TenantMixin


def _normalize_vulnerability_type(
    value: str | None,
    *,
    title: str = "",
    description: str = "",
) -> str | None:
    raw = str(value or "").strip().lower()
    text = " ".join(part for part in (raw, title, description) if part).lower()
    aliases = (
        ("auth_bypass", ("auth_bypass", "authorization bypass", "auth bypass", "cross_session")),
        (
            "workflow_bypass",
            ("workflow_bypass", "workflow bypass", "step_bypass", "skip_step", "swap_order", "repeat_step"),
        ),
        ("idor", ("idor", "insecure direct object reference", "object level authorization")),
        ("privilege_escalation", ("privilege_escalation", "privilege escalation")),
        ("sql_injection", ("sql_injection", "sql injection", "sqli")),
    )
    for normalized, patterns in aliases:
        if raw == normalized:
            return normalized
        if any(pattern in text for pattern in patterns):
            return normalized
    return raw or None


class Finding(Base, TenantMixin):
    """Vulnerability finding produced by scanners, exploit verification, or AI analysis."""

    __tablename__ = "findings"

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

    scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_jobs.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
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
        SmallInteger,
        nullable=False,
        comment="0–100",
    )

    cve_id: Mapped[str | None] = mapped_column(String(20), nullable=True)

    cvss_score: Mapped[float | None] = mapped_column(
        Numeric(3, 1),
        nullable=True,
        comment="0.0–10.0",
    )

    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    evidence: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)

    tool_source: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="nmap, nuclei, metasploit, ai_triage, etc.",
    )

    is_false_positive: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        server_default=text("false"),
    )

    fp_probability: Mapped[int | None] = mapped_column(
        SmallInteger,
        nullable=True,
        comment="AI-scored false-positive probability 0–100",
    )

    fingerprint: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        comment="Content-hash for cross-tool deduplication",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )

    # Relationships
    scan: Mapped["Scan"] = relationship(
        "Scan",
        back_populates="findings",
    )

    @property
    def exploitability(self) -> str | None:
        evidence = self.evidence or {}
        if not isinstance(evidence, dict):
            return None
        classification = evidence.get("classification") or {}
        if not isinstance(classification, dict):
            return None
        value = classification.get("exploitability")
        return str(value) if value else None

    @property
    def surface(self) -> str | None:
        evidence = self.evidence or {}
        if not isinstance(evidence, dict):
            return None
        classification = evidence.get("classification") or {}
        if not isinstance(classification, dict):
            return None
        value = classification.get("surface")
        return str(value) if value else None

    @property
    def execution_mode(self) -> str | None:
        evidence = self.evidence or {}
        if not isinstance(evidence, dict):
            return None
        classification = evidence.get("classification") or {}
        if isinstance(classification, dict):
            value = classification.get("execution_mode")
            if value:
                return str(value)
        metadata = evidence.get("metadata") or {}
        if isinstance(metadata, dict):
            value = metadata.get("execution_mode")
            if value:
                return str(value)
        return None

    @property
    def execution_provenance(self) -> str | None:
        evidence = self.evidence or {}
        if not isinstance(evidence, dict):
            return "inferred" if str(self.source_type) == "ai_analysis" else None
        classification = evidence.get("classification") or {}
        if isinstance(classification, dict):
            value = classification.get("execution_provenance")
            if value:
                return str(value)
        metadata = evidence.get("metadata") or {}
        if isinstance(metadata, dict):
            value = metadata.get("execution_provenance")
            if value:
                return str(value)
        return "inferred" if str(self.source_type) == "ai_analysis" else None

    @property
    def execution_reason(self) -> str | None:
        evidence = self.evidence or {}
        if not isinstance(evidence, dict):
            return None
        classification = evidence.get("classification") or {}
        if isinstance(classification, dict):
            value = classification.get("execution_reason")
            if value:
                return str(value)
        metadata = evidence.get("metadata") or {}
        if isinstance(metadata, dict):
            value = metadata.get("execution_reason")
            if value:
                return str(value)
        return None

    @property
    def verification_state(self) -> str | None:
        evidence = self.evidence or {}
        if not isinstance(evidence, dict):
            return None
        classification = evidence.get("classification") or {}
        if not isinstance(classification, dict):
            return None
        value = classification.get("verification_state")
        return str(value) if value else None

    @property
    def verification_confidence(self) -> int | None:
        evidence = self.evidence or {}
        if not isinstance(evidence, dict):
            return None
        classification = evidence.get("classification") or {}
        if not isinstance(classification, dict):
            return None
        value = classification.get("verification_confidence")
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @property
    def verified_at(self) -> datetime | None:
        evidence = self.evidence or {}
        if not isinstance(evidence, dict):
            return None
        metadata = evidence.get("metadata") or {}
        if not isinstance(metadata, dict):
            return None
        value = metadata.get("verified_at")
        if value is None:
            return None
        if isinstance(value, datetime):
            return value
        try:
            return datetime.fromisoformat(str(value))
        except ValueError:
            return None

    @property
    def vulnerability_type(self) -> str | None:
        evidence = self.evidence or {}
        if not isinstance(evidence, dict):
            return None
        classification = evidence.get("classification") or {}
        if not isinstance(classification, dict):
            classification = {}
        return _normalize_vulnerability_type(
            classification.get("vulnerability_type"),
            title=self.title,
            description=self.description or "",
        )
