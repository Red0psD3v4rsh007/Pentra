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
    is_false_positive: bool
    fp_probability: int | None = Field(default=None, ge=0, le=100)
    created_at: datetime

    model_config = {"from_attributes": True}
