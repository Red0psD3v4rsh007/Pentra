"""Finding schemas — shared across scanner, exploit verify, and AI analysis."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, Field


class FindingSeverity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class FindingSourceType(str, Enum):
    """Discriminator — identifies which pipeline stage produced the finding."""

    scanner = "scanner"                # Tool scan output (nuclei, nmap, zap, etc.)
    exploit_verify = "exploit_verify"  # Exploit verification result
    ai_analysis = "ai_analysis"        # AI-generated / re-scored finding


class FindingTruthState(str, Enum):
    observed = "observed"
    suspected = "suspected"
    reproduced = "reproduced"
    verified = "verified"
    rejected = "rejected"
    expired = "expired"


class FindingTruthSummary(BaseModel):
    state: FindingTruthState = FindingTruthState.observed
    promoted: bool = False
    provenance_complete: bool = False
    replayable: bool = False
    evidence_reference_count: int = 0
    raw_evidence_present: bool = False
    scan_job_bound: bool = False
    notes: list[str] = Field(default_factory=list)


class FindingResponse(BaseModel):
    id: UUID
    scan_id: UUID
    scan_job_id: UUID | None = None
    source_type: FindingSourceType
    title: str
    severity: FindingSeverity
    confidence: int = Field(..., ge=0, le=100)
    cve_id: str | None = None
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    description: str | None = None
    evidence: dict | None = None
    remediation: str | None = None
    tool_source: str
    vulnerability_type: str | None = None
    exploitability: str | None = None
    surface: str | None = None
    execution_mode: str | None = None
    execution_provenance: str | None = None
    execution_reason: str | None = None
    verification_state: str | None = None
    verification_confidence: int | None = Field(default=None, ge=0, le=100)
    verified_at: datetime | None = None
    truth_state: FindingTruthState = FindingTruthState.observed
    truth_summary: FindingTruthSummary = Field(default_factory=FindingTruthSummary)
    is_false_positive: bool
    fp_probability: int | None = Field(default=None, ge=0, le=100)
    created_at: datetime

    model_config = {"from_attributes": True}
