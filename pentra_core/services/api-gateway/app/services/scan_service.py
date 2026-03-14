"""Scan service — scan lifecycle management, quota enforcement, event publishing.

Framework-agnostic: accepts plain arguments, returns ORM objects.
No FastAPI Request dependency.

**MOD-04 compatibility**: This service creates only the ``Scan`` record
and publishes ``scan.created`` to Redis Streams.  All DAG planning and
``ScanJob`` creation is delegated to the orchestrator service.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from pentra_common.events.stream_publisher import StreamPublisher
from pentra_common.storage.artifacts import read_json_artifact
from pentra_common.schemas import SCAN_TERMINAL_STATES

from app.models.attack_graph import ScanArtifact
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.tenant import TenantQuota

logger = logging.getLogger(__name__)


# ── Public service functions ─────────────────────────────────────────


async def create_scan(
    *,
    tenant_id: uuid.UUID,
    created_by: uuid.UUID,
    asset_id: uuid.UUID,
    scan_type: str,
    priority: str,
    config: dict | None,
    stream_publisher: StreamPublisher,
    session: AsyncSession,
) -> Scan:
    """Create a scan with quota validation and event publishing.

    1. Validate asset exists and belongs to tenant
    2. Check tenant quota (concurrent + daily limits)
    3. Create Scan record
    4. Increment quota counters
    5. Publish ``scan.created`` event to Redis Stream (XADD)

    All DAG planning and ScanJob creation is handled by the orchestrator
    after it consumes the ``scan.created`` event.
    """
    # 1 — validate asset
    asset = await session.get(Asset, asset_id)
    if asset is None or not asset.is_active:
        raise ValueError("Asset not found or inactive")

    if str(asset.tenant_id) != str(tenant_id):
        raise ValueError("Asset does not belong to this tenant")

    # 2 — check quota
    quota_stmt = select(TenantQuota).where(TenantQuota.tenant_id == tenant_id)
    quota = (await session.execute(quota_stmt)).scalar_one_or_none()

    if quota:
        if quota.active_scans >= quota.max_concurrent_scans:
            raise ValueError(
                f"Concurrent scan limit reached ({quota.max_concurrent_scans})"
            )
        if quota.scans_today >= quota.max_daily_scans:
            raise ValueError(
                f"Daily scan limit reached ({quota.max_daily_scans})"
            )

    # 3 — create scan record
    scan = Scan(
        tenant_id=tenant_id,
        asset_id=asset_id,
        created_by=created_by,
        scan_type=scan_type,
        priority=priority,
        config=config or {},
        status="queued",
        progress=0,
    )
    session.add(scan)
    await session.flush()

    # 4 — increment quota counters
    if quota:
        quota.active_scans += 1
        quota.scans_today += 1
        await session.flush()

    # 5 — publish scan.created event to Redis Stream
    await stream_publisher.publish_scan_created(
        scan_id=scan.id,
        tenant_id=tenant_id,
        asset_id=asset_id,
        project_id=asset.project_id,
        scan_type=scan_type,
        priority=priority,
        target=asset.target,
        asset_type=asset.asset_type,
        config=config or {},
        created_by=created_by,
    )

    logger.info(
        "Scan created: scan_id=%s tenant=%s type=%s priority=%s",
        scan.id, tenant_id, scan_type, priority,
    )

    return scan


async def list_scans(
    *,
    session: AsyncSession,
    status_filter: str | None = None,
    asset_id: uuid.UUID | None = None,
    page: int = 1,
    page_size: int = 20,
) -> tuple[list[Scan], int]:
    """List scans for the current tenant (paginated, filterable).

    RLS enforces tenant scope automatically.
    """
    conditions = []
    if status_filter:
        conditions.append(Scan.status == status_filter)
    if asset_id:
        conditions.append(Scan.asset_id == asset_id)

    # Count
    count_q = select(func.count()).select_from(Scan)
    for cond in conditions:
        count_q = count_q.where(cond)
    total = (await session.execute(count_q)).scalar_one()

    # Fetch
    offset = (page - 1) * page_size
    stmt = select(Scan).order_by(Scan.created_at.desc()).offset(offset).limit(page_size)
    for cond in conditions:
        stmt = stmt.where(cond)
    result = await session.execute(stmt)
    return list(result.scalars().all()), total


async def get_scan(
    *, scan_id: uuid.UUID, session: AsyncSession
) -> Scan | None:
    """Fetch a scan by ID."""
    return await session.get(Scan, scan_id)


async def cancel_scan(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    stream_publisher: StreamPublisher,
    session: AsyncSession,
) -> Scan:
    """Cancel a running scan — publish cancellation to Redis Stream.

    Sets status to ``cancelled`` and publishes ``scan.status_changed``
    so the orchestrator can gracefully stop dispatching jobs.
    """
    scan = await session.get(Scan, scan_id)
    if scan is None:
        raise ValueError("Scan not found")

    # Verify it's not already in a terminal state
    if scan.status in {s.value for s in SCAN_TERMINAL_STATES}:
        raise ValueError(f"Scan is already in terminal state: {scan.status}")

    old_status = scan.status
    scan.status = "cancelled"
    scan.error_message = "Cancelled by user"
    scan.completed_at = datetime.now(timezone.utc)
    await session.flush()

    # Decrement active scans quota
    quota_stmt = select(TenantQuota).where(TenantQuota.tenant_id == tenant_id)
    quota = (await session.execute(quota_stmt)).scalar_one_or_none()
    if quota and quota.active_scans > 0:
        quota.active_scans -= 1
        await session.flush()

    # Publish status change event to Redis Stream
    await stream_publisher.publish_scan_status_changed(
        scan_id=scan.id,
        tenant_id=tenant_id,
        old_status=old_status,
        new_status="cancelled",
    )

    return scan


async def list_findings(
    *,
    scan_id: uuid.UUID,
    session: AsyncSession,
    page: int = 1,
    page_size: int = 20,
) -> tuple[list[Finding], int]:
    """List findings for a scan (paginated)."""
    base_filter = Finding.scan_id == scan_id

    count_stmt = select(func.count()).select_from(Finding).where(base_filter)
    total = (await session.execute(count_stmt)).scalar_one()

    offset = (page - 1) * page_size
    stmt = (
        select(Finding)
        .where(base_filter)
        .order_by(Finding.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    result = await session.execute(stmt)
    return list(result.scalars().all()), total


async def list_artifact_summaries(
    *,
    scan_id: uuid.UUID,
    session: AsyncSession,
) -> list[dict]:
    """Return artifact summary rows for a scan."""
    stmt = (
        select(ScanArtifact)
        .where(ScanArtifact.scan_id == scan_id)
        .order_by(ScanArtifact.created_at.asc())
    )
    result = await session.execute(stmt)
    artifacts = list(result.scalars().all())

    summaries: list[dict] = []
    for artifact in artifacts:
        metadata = artifact.metadata_ or {}
        summary = metadata.get("summary", {}) if isinstance(metadata, dict) else {}
        severity_counts = {}
        if isinstance(summary, dict):
            severity_counts = summary.get("severity_counts", {}) or metadata.get("severity_counts", {})

        summaries.append(
            {
                "id": artifact.id,
                "scan_id": artifact.scan_id,
                "node_id": artifact.node_id,
                "artifact_type": artifact.artifact_type,
                "tool": metadata.get("tool") if isinstance(metadata, dict) else None,
                "storage_ref": artifact.storage_ref,
                "content_type": artifact.content_type,
                "size_bytes": artifact.size_bytes,
                "checksum": artifact.checksum,
                "item_count": int(metadata.get("item_count", 0)) if isinstance(metadata, dict) else 0,
                "finding_count": int(metadata.get("finding_count", 0)) if isinstance(metadata, dict) else 0,
                "evidence_count": int(metadata.get("evidence_count", 0)) if isinstance(metadata, dict) else 0,
                "severity_counts": severity_counts,
                "summary": summary if isinstance(summary, dict) else {},
                "created_at": artifact.created_at,
            }
        )

    return summaries


async def get_attack_graph(
    *,
    scan_id: uuid.UUID,
    session: AsyncSession,
) -> dict | None:
    """Return the stored attack graph payload for a scan."""
    stmt = (
        select(ScanArtifact)
        .where(
            ScanArtifact.scan_id == scan_id,
            ScanArtifact.artifact_type == "attack_graph",
        )
        .order_by(ScanArtifact.created_at.desc())
        .limit(1)
    )
    artifact = (await session.execute(stmt)).scalar_one_or_none()
    if artifact is None:
        return None

    payload = read_json_artifact(artifact.storage_ref)
    if isinstance(payload, dict):
        nodes = payload.get("nodes", {})
        payload["nodes"] = list(nodes.values()) if isinstance(nodes, dict) else nodes
        return payload

    metadata = artifact.metadata_ or {}
    return {
        "scan_id": scan_id,
        "tenant_id": artifact.tenant_id,
        "built_at": metadata.get("built_at"),
        "node_count": metadata.get("node_count", 0),
        "edge_count": metadata.get("edge_count", 0),
        "path_summary": metadata.get("path_summary", {}),
        "scoring_summary": metadata.get("scoring_summary", {}),
        "nodes": [],
        "edges": [],
    }


async def get_scan_timeline(
    *,
    scan_id: uuid.UUID,
    session: AsyncSession,
) -> list[dict]:
    """Build a timeline from scan, job, and artifact state."""
    stmt = (
        select(Scan)
        .where(Scan.id == scan_id)
        .options(selectinload(Scan.jobs), selectinload(Scan.artifacts))
    )
    scan = (await session.execute(stmt)).scalar_one_or_none()
    if scan is None:
        return []

    events: list[dict] = [
        {
            "id": f"scan:{scan.id}:created",
            "timestamp": scan.created_at,
            "event_type": "system",
            "title": "Scan created",
            "details": f"Scan type: {scan.scan_type}",
            "status": scan.status,
            "phase": None,
            "tool": None,
            "job_id": None,
            "node_id": None,
            "artifact_ref": None,
        }
    ]

    if scan.started_at:
        events.append(
            {
                "id": f"scan:{scan.id}:started",
                "timestamp": scan.started_at,
                "event_type": "system",
                "title": "Scan started",
                "details": "Pipeline entered execution.",
                "status": scan.status,
                "phase": None,
                "tool": None,
                "job_id": None,
                "node_id": None,
                "artifact_ref": None,
            }
        )

    for job in sorted(scan.jobs, key=lambda value: (value.phase, value.created_at)):
        events.append(
            {
                "id": f"job:{job.id}",
                "timestamp": job.completed_at or job.started_at or job.created_at,
                "event_type": _timeline_event_type(job.phase),
                "title": f"{job.tool} {job.status}",
                "details": f"Phase {job.phase} · retries {job.retry_count}",
                "status": job.status,
                "phase": job.phase,
                "tool": job.tool,
                "job_id": job.id,
                "node_id": None,
                "artifact_ref": job.output_ref,
            }
        )

    for artifact in sorted(scan.artifacts, key=lambda value: value.created_at):
        metadata = artifact.metadata_ or {}
        events.append(
            {
                "id": f"artifact:{artifact.id}",
                "timestamp": artifact.created_at,
                "event_type": "artifact",
                "title": f"{artifact.artifact_type} stored",
                "details": _artifact_timeline_details(artifact.artifact_type, metadata),
                "status": None,
                "phase": None,
                "tool": metadata.get("tool") if isinstance(metadata, dict) else None,
                "job_id": None,
                "node_id": artifact.node_id,
                "artifact_ref": artifact.storage_ref,
            }
        )

    if scan.completed_at:
        events.append(
            {
                "id": f"scan:{scan.id}:completed",
                "timestamp": scan.completed_at,
                "event_type": "system",
                "title": f"Scan {scan.status}",
                "details": f"Progress reached {scan.progress}%.",
                "status": scan.status,
                "phase": None,
                "tool": None,
                "job_id": None,
                "node_id": None,
                "artifact_ref": None,
            }
        )

    return sorted(events, key=lambda event: event["timestamp"])


async def list_evidence_references(
    *,
    scan_id: uuid.UUID,
    session: AsyncSession,
) -> list[dict]:
    """Extract evidence references from persisted findings."""
    stmt = (
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .order_by(Finding.created_at.desc())
    )
    findings = list((await session.execute(stmt)).scalars().all())

    evidence_refs: list[dict] = []
    for finding in findings:
        evidence = finding.evidence or {}
        target = str(
            evidence.get("endpoint")
            or evidence.get("target")
            or "unknown"
        )
        references = evidence.get("references", [])
        if isinstance(references, list) and references:
            for reference in references:
                evidence_refs.append(
                    {
                        "id": reference.get("id") or f"{finding.id}:reference",
                        "finding_id": finding.id,
                        "finding_title": finding.title,
                        "severity": finding.severity,
                        "tool_source": finding.tool_source,
                        "evidence_type": reference.get("evidence_type", "reference"),
                        "label": reference.get("label", finding.title),
                        "target": target,
                        "content_preview": reference.get("content_preview", ""),
                        "content": None,
                        "storage_ref": reference.get("storage_ref") or evidence.get("storage_ref"),
                        "metadata": {},
                    }
                )

        for evidence_type in ("request", "response", "payload", "exploit_result"):
            content = evidence.get(evidence_type)
            if not content:
                continue
            evidence_refs.append(
                {
                    "id": f"{finding.id}:{evidence_type}",
                    "finding_id": finding.id,
                    "finding_title": finding.title,
                    "severity": finding.severity,
                    "tool_source": finding.tool_source,
                    "evidence_type": evidence_type,
                    "label": f"{finding.title} · {evidence_type.replace('_', ' ')}",
                    "target": target,
                    "content_preview": str(content)[:240],
                    "content": str(content),
                    "storage_ref": evidence.get("storage_ref"),
                    "metadata": {},
                }
            )

    return evidence_refs


async def get_scan_report(
    *,
    scan_id: uuid.UUID,
    session: AsyncSession,
) -> dict | None:
    """Build a lightweight report response from persisted findings and scan summary."""
    stmt = (
        select(Scan)
        .where(Scan.id == scan_id)
        .options(selectinload(Scan.findings), selectinload(Scan.asset))
    )
    scan = (await session.execute(stmt)).scalar_one_or_none()
    if scan is None:
        return None

    findings = sorted(scan.findings, key=lambda finding: (finding.severity, finding.created_at))
    severity_counts = {key: 0 for key in ("critical", "high", "medium", "low", "info")}
    for finding in findings:
        severity_counts[finding.severity] += 1

    top_findings = [
        {
            "id": str(finding.id),
            "title": finding.title,
            "severity": finding.severity,
            "cvss_score": float(finding.cvss_score) if finding.cvss_score is not None else None,
            "description": finding.description,
            "remediation": finding.remediation,
        }
        for finding in findings[:5]
    ]
    evidence_count = 0
    for finding in findings:
        evidence = finding.evidence or {}
        references = evidence.get("references", [])
        evidence_count += len(references) if isinstance(references, list) else 0
        for key in ("request", "response", "payload", "exploit_result"):
            if evidence.get(key):
                evidence_count += 1

    asset_target = scan.asset.target if scan.asset is not None else str(scan.asset_id)
    executive_summary = _build_executive_summary(asset_target, severity_counts)
    markdown = _build_report_markdown(
        asset_target=asset_target,
        executive_summary=executive_summary,
        severity_counts=severity_counts,
        top_findings=top_findings,
    )

    return {
        "scan_id": scan.id,
        "report_id": f"scan-report:{scan.id}",
        "generated_at": datetime.now(timezone.utc),
        "executive_summary": executive_summary,
        "severity_counts": severity_counts,
        "vulnerability_count": len(findings),
        "evidence_count": evidence_count,
        "narrative": None,
        "compliance": [],
        "top_findings": top_findings,
        "markdown": markdown,
    }


def _timeline_event_type(phase: int) -> str:
    if phase <= 1:
        return "recon"
    if phase <= 3:
        return "vuln"
    if phase == 4:
        return "exploit"
    if phase == 5:
        return "analysis"
    return "report"


def _artifact_timeline_details(artifact_type: str, metadata: dict | None) -> str:
    metadata = metadata or {}
    item_count = int(metadata.get("item_count", 0) or 0)
    finding_count = int(metadata.get("finding_count", 0) or 0)
    evidence_count = int(metadata.get("evidence_count", 0) or 0)
    return (
        f"{artifact_type} · items {item_count} · findings {finding_count} · evidence {evidence_count}"
    )


def _build_executive_summary(asset_target: str, severity_counts: dict[str, int]) -> str:
    total = sum(severity_counts.values())
    if total == 0:
        return f"Autonomous assessment of {asset_target} completed with no persisted findings."

    parts = [f"Autonomous assessment of {asset_target} identified {total} persisted findings"]
    if severity_counts["critical"]:
        parts.append(f"{severity_counts['critical']} critical")
    if severity_counts["high"]:
        parts.append(f"{severity_counts['high']} high")
    if severity_counts["medium"]:
        parts.append(f"{severity_counts['medium']} medium")
    return ", ".join(parts) + "."


def _build_report_markdown(
    *,
    asset_target: str,
    executive_summary: str,
    severity_counts: dict[str, int],
    top_findings: list[dict],
) -> str:
    lines = [
        f"# Pentra Report - {asset_target}",
        "",
        "## Executive Summary",
        "",
        executive_summary,
        "",
        "## Severity Summary",
        "",
        f"- Critical: {severity_counts['critical']}",
        f"- High: {severity_counts['high']}",
        f"- Medium: {severity_counts['medium']}",
        f"- Low: {severity_counts['low']}",
        f"- Info: {severity_counts['info']}",
        "",
        "## Top Findings",
        "",
    ]

    if not top_findings:
        lines.append("No persisted findings were available.")
    else:
        for finding in top_findings:
            lines.extend(
                [
                    f"### {finding['title']}",
                    f"Severity: {finding['severity']}",
                    finding.get("description") or "No description provided.",
                    "",
                ]
            )

    return "\n".join(lines)
