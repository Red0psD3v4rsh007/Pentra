"""Scan profile schemas — truthful execution contracts for launchable profiles."""

from __future__ import annotations

from pydantic import BaseModel

from pentra_common.schemas.scan import ScanPriority, ScanType

__all__ = ["ScanProfileContractResponse"]


class ScanProfileContractResponse(BaseModel):
    scan_type: ScanType
    profile_id: str
    name: str
    description: str
    duration: str
    priority: ScanPriority
    execution_mode: str
    target_policy: str
    scope_summary: str
    scheduled_tools: list[str]
    live_tools: list[str]
    conditional_live_tools: list[str]
    derived_tools: list[str]
    unsupported_tools: list[str]
    guardrails: list[str]
    honesty_notes: list[str]
    sellable: bool
