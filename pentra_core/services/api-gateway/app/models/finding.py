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
from typing import Any
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


_RAW_EVIDENCE_KEYS = (
    "request",
    "response",
    "payload",
    "proof",
    "transcript",
    "excerpt",
    "content",
)
_TRUTH_STATES = frozenset(
    {"observed", "suspected", "reproduced", "verified", "rejected", "expired"}
)


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


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
    def evidence_reference_count(self) -> int:
        evidence = _as_dict(self.evidence)
        references = _as_list(evidence.get("references"))
        return sum(
            1
            for item in references
            if isinstance(item, dict) and any(item.get(key) for key in ("id", "evidence_type", "label"))
        )

    @property
    def raw_evidence_present(self) -> bool:
        evidence = _as_dict(self.evidence)
        return any(str(evidence.get(key) or "").strip() for key in _RAW_EVIDENCE_KEYS)

    @property
    def provenance_complete(self) -> bool:
        evidence = _as_dict(self.evidence)
        classification = _as_dict(evidence.get("classification"))
        metadata = _as_dict(evidence.get("metadata"))

        for container in (classification, metadata):
            value = container.get("provenance_complete")
            if isinstance(value, bool):
                return value

        has_source = bool(str(self.source_type or "").strip()) and bool(str(self.tool_source or "").strip())
        has_locator = bool(
            evidence.get("endpoint")
            or evidence.get("target")
            or evidence.get("storage_ref")
            or any(_as_dict(item).get("storage_ref") for item in _as_list(evidence.get("references")))
        )
        has_material = self.evidence_reference_count > 0 or self.raw_evidence_present
        return has_source and has_locator and has_material

    @property
    def replayable(self) -> bool:
        evidence = _as_dict(self.evidence)
        classification = _as_dict(evidence.get("classification"))
        metadata = _as_dict(evidence.get("metadata"))

        for container in (classification, metadata):
            value = container.get("replayable")
            if isinstance(value, bool):
                return value

        verification_context = _as_dict(metadata.get("verification_context"))
        if any(
            verification_context.get(key)
            for key in ("request_url", "endpoint", "command", "curl", "http_method")
        ):
            return True

        if (
            (evidence.get("endpoint") or evidence.get("target"))
            and self.raw_evidence_present
            and (
                evidence.get("storage_ref")
                or any(_as_dict(item).get("storage_ref") for item in _as_list(evidence.get("references")))
            )
        ):
            return True

        return False

    @property
    def truth_state(self) -> str:
        evidence = _as_dict(self.evidence)
        classification = _as_dict(evidence.get("classification"))
        metadata = _as_dict(evidence.get("metadata"))

        for container in (classification, metadata):
            value = str(container.get("truth_state") or "").strip().lower()
            if value in _TRUTH_STATES:
                return value

        if bool(self.is_false_positive):
            return "rejected"

        for container in (classification, metadata):
            if bool(container.get("expired")) or container.get("expired_at"):
                return "expired"

        verification_state = str(self.verification_state or "").strip().lower()
        if verification_state == "verified":
            return "verified" if self.provenance_complete and self.replayable else "reproduced"
        if verification_state == "suspected":
            return "suspected"
        if str(self.source_type) == "ai_analysis":
            return "suspected"
        return "observed"

    @property
    def truth_summary(self) -> dict[str, Any]:
        state = self.truth_state
        notes: list[str] = []
        evidence = _as_dict(self.evidence)
        metadata = _as_dict(evidence.get("metadata"))

        if self.is_false_positive:
            notes.append("Marked false positive and excluded from trusted output.")
        if not self.provenance_complete:
            notes.append("Provenance is incomplete, so this record stays below trusted finding level.")
        if self.evidence_reference_count == 0:
            notes.append("No persisted evidence references are linked yet.")
        if not self.raw_evidence_present:
            notes.append("No raw request, response, or payload proof is stored yet.")
        if state == "reproduced" and not self.replayable:
            notes.append("Verification exists, but replayable proof metadata is still incomplete.")
        if state == "suspected" and str(self.source_type) == "ai_analysis":
            notes.append("AI-generated reasoning requires verification before promotion.")
        if self.scan_job_id is None:
            notes.append("No producing scan job is linked to this record.")
        if str(metadata.get("last_verification_outcome") or "").strip().lower() == "failed":
            notes.append("Bounded verification did not reproduce the issue; negative evidence is retained.")
        negative_verifications = _as_list(metadata.get("negative_verifications"))
        if negative_verifications:
            notes.append(f"{len(negative_verifications)} negative verification attempt(s) are linked.")

        return {
            "state": state,
            "promoted": state == "verified" and self.provenance_complete and self.replayable and not self.is_false_positive,
            "provenance_complete": self.provenance_complete,
            "replayable": self.replayable,
            "evidence_reference_count": self.evidence_reference_count,
            "raw_evidence_present": self.raw_evidence_present,
            "scan_job_bound": self.scan_job_id is not None,
            "notes": notes,
        }

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
