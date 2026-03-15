"""Scan service — scan lifecycle management, quota enforcement, event publishing.

Framework-agnostic: accepts plain arguments, returns ORM objects.
No FastAPI Request dependency.

**MOD-04 compatibility**: This service creates only the ``Scan`` record
and publishes ``scan.created`` to Redis Streams.  All DAG planning and
``ScanJob`` creation is delegated to the orchestrator service.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import uuid
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from pentra_common.events.stream_publisher import StreamPublisher
from pentra_common.profiles import enforce_safe_scan_config, prepare_scan_config
from pentra_common.storage.artifacts import read_json_artifact
from pentra_common.schemas import SCAN_TERMINAL_STATES
from pentra_common.config.settings import get_settings

from app.models.attack_graph import ScanArtifact
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.tenant import TenantQuota

logger = logging.getLogger(__name__)


_DEFAULT_EXPORT_FORMATS = ["markdown", "json", "csv"]
_FIX_GUIDANCE_LIBRARY: dict[str, dict[str, Any]] = {
    "sql_injection": {
        "title": "Eliminate injectable database queries",
        "owner_hint": "Backend Engineering",
        "actions": [
            "Replace dynamic SQL construction with parameterized queries.",
            "Add regression tests for injectable parameters on authenticated and unauthenticated routes.",
            "Review database permissions to reduce blast radius for compromised queries.",
        ],
    },
    "idor": {
        "title": "Enforce object-level authorization consistently",
        "owner_hint": "Application Engineering",
        "actions": [
            "Authorize access on every object lookup, not only on list endpoints.",
            "Add tenant and ownership checks to direct object reference handlers.",
            "Add replay tests that exercise cross-user and cross-tenant requests.",
        ],
    },
    "auth_bypass": {
        "title": "Close authorization bypass paths in authenticated workflows",
        "owner_hint": "Identity Engineering",
        "actions": [
            "Enforce session validation before serving privileged workflow steps.",
            "Bind privileged actions to the authenticated principal and current session state.",
            "Add workflow replay regression tests for cross-session and skipped-step access.",
        ],
    },
    "workflow_bypass": {
        "title": "Protect stateful workflows against step and order bypass",
        "owner_hint": "Product Engineering",
        "actions": [
            "Validate server-side workflow state before completing high-impact actions.",
            "Reject replayed, duplicated, or out-of-order requests for stateful actions.",
            "Add end-to-end tests for checkout, onboarding, and approval workflows.",
        ],
    },
    "unsafe_deserialization": {
        "title": "Remove unsafe deserialization attack paths",
        "owner_hint": "Platform Engineering",
        "actions": [
            "Disable unsafe object deserialization for untrusted input.",
            "Use allow-listed serializers and signed payloads where serialization is required.",
            "Review internal endpoints and background jobs for gadget-friendly libraries.",
        ],
    },
    "graphql_introspection": {
        "title": "Reduce GraphQL schema exposure and tighten resolver auth",
        "owner_hint": "API Platform",
        "actions": [
            "Disable introspection for production users where possible.",
            "Review resolver authorization and rate limiting for sensitive schema paths.",
            "Gate developer-only schema features behind authenticated admin roles.",
        ],
    },
}

_COMPLIANCE_LIBRARY: dict[str, dict[str, list[str]]] = {
    "sql_injection": {"owasp": ["A03:2021-Injection"], "cwe": ["CWE-89"]},
    "idor": {"owasp": ["A01:2021-Broken Access Control"], "cwe": ["CWE-639"]},
    "auth_bypass": {"owasp": ["A01:2021-Broken Access Control", "A07:2021-Authentication Failures"], "cwe": ["CWE-287"]},
    "workflow_bypass": {"owasp": ["A01:2021-Broken Access Control"], "cwe": ["CWE-285"]},
    "unsafe_deserialization": {"owasp": ["A08:2021-Software and Data Integrity Failures"], "cwe": ["CWE-502"]},
    "graphql_introspection": {"owasp": ["A05:2021-Security Misconfiguration"], "cwe": ["CWE-200"]},
}


def _with_request_metadata(
    config: dict[str, Any] | None,
    *,
    idempotency_key: str | None,
) -> dict[str, Any]:
    normalized = deepcopy(config or {})
    if not isinstance(normalized, dict):
        normalized = {}

    request_metadata = (
        deepcopy(normalized.get("request_metadata"))
        if isinstance(normalized.get("request_metadata"), dict)
        else {}
    )
    request_metadata["submitted_at"] = datetime.now(timezone.utc).isoformat()
    if idempotency_key:
        request_metadata["idempotency_key"] = idempotency_key

    normalized["request_metadata"] = request_metadata
    return normalized


async def _find_existing_idempotent_scan(
    *,
    tenant_id: uuid.UUID,
    created_by: uuid.UUID,
    asset_id: uuid.UUID,
    scan_type: str,
    idempotency_key: str,
    session: AsyncSession,
) -> Scan | None:
    window_hours = max(int(get_settings().scan_idempotency_window_hours), 1)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)
    stmt = (
        select(Scan)
        .where(
            Scan.tenant_id == tenant_id,
            Scan.created_by == created_by,
            Scan.asset_id == asset_id,
            Scan.scan_type == scan_type,
            Scan.created_at >= cutoff,
        )
        .order_by(Scan.created_at.desc())
        .limit(10)
    )
    scans = list((await session.execute(stmt)).scalars().all())
    for scan in scans:
        config = scan.config or {}
        request_metadata = (
            config.get("request_metadata") if isinstance(config, dict) else {}
        )
        if not isinstance(request_metadata, dict):
            continue
        if str(request_metadata.get("idempotency_key") or "") == idempotency_key:
            return scan
    return None


async def _get_scan_for_tenant(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
) -> Scan | None:
    stmt = select(Scan).where(Scan.id == scan_id, Scan.tenant_id == tenant_id)
    return (await session.execute(stmt)).scalar_one_or_none()


# ── Public service functions ─────────────────────────────────────────


async def create_scan(
    *,
    tenant_id: uuid.UUID,
    created_by: uuid.UUID,
    asset_id: uuid.UUID,
    scan_type: str,
    priority: str,
    config: dict | None,
    idempotency_key: str | None,
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

    request_config = _with_request_metadata(config, idempotency_key=idempotency_key)

    if idempotency_key:
        existing = await _find_existing_idempotent_scan(
            tenant_id=tenant_id,
            created_by=created_by,
            asset_id=asset_id,
            scan_type=scan_type,
            idempotency_key=idempotency_key,
            session=session,
        )
        if existing is not None:
            logger.info(
                "Returning existing scan for idempotency key: scan_id=%s key=%s",
                existing.id,
                idempotency_key,
            )
            return existing

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

    normalized_config = prepare_scan_config(
        scan_type=scan_type,
        asset_type=asset.asset_type,
        asset_target=asset.target,
        config=request_config,
    )
    normalized_config = enforce_safe_scan_config(
        scan_type=scan_type,
        asset_type=asset.asset_type,
        asset_target=asset.target,
        config=normalized_config,
    )

    # 3 — create scan record
    scan = Scan(
        tenant_id=tenant_id,
        asset_id=asset_id,
        created_by=created_by,
        scan_type=scan_type,
        priority=priority,
        config=normalized_config,
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
        config=normalized_config,
        created_by=created_by,
    )

    logger.info(
        "Scan created: scan_id=%s tenant=%s type=%s priority=%s profile=%s",
        scan.id,
        tenant_id,
        scan_type,
        priority,
        normalized_config.get("profile_id"),
    )

    return scan


async def list_scans(
    *,
    tenant_id: uuid.UUID,
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
    conditions.append(Scan.tenant_id == tenant_id)

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
    *, scan_id: uuid.UUID, tenant_id: uuid.UUID, session: AsyncSession
) -> Scan | None:
    """Fetch a scan by ID."""
    return await _get_scan_for_tenant(
        scan_id=scan_id,
        tenant_id=tenant_id,
        session=session,
    )


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
    scan = await _get_scan_for_tenant(
        scan_id=scan_id,
        tenant_id=tenant_id,
        session=session,
    )
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


async def create_retest_scan(
    *,
    source_scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    created_by: uuid.UUID,
    priority: str | None,
    config_overrides: dict | None,
    idempotency_key: str | None,
    stream_publisher: StreamPublisher,
    session: AsyncSession,
) -> Scan:
    """Create a retest scan using a completed scan as the baseline."""
    stmt = (
        select(Scan)
        .where(Scan.id == source_scan_id, Scan.tenant_id == tenant_id)
        .options(selectinload(Scan.findings), selectinload(Scan.asset))
    )
    source_scan = (await session.execute(stmt)).scalar_one_or_none()
    if source_scan is None:
        raise ValueError("Source scan not found")

    if source_scan.status != "completed":
        raise ValueError("Only completed scans can be used as a retest baseline")

    merged_config = _build_retest_config(
        source_scan=source_scan,
        config_overrides=config_overrides or {},
    )

    recommended_priority = priority or _recommended_retest_priority(source_scan)
    return await create_scan(
        tenant_id=tenant_id,
        created_by=created_by,
        asset_id=source_scan.asset_id,
        scan_type=source_scan.scan_type,
        priority=recommended_priority,
        config=merged_config,
        idempotency_key=idempotency_key,
        stream_publisher=stream_publisher,
        session=session,
    )


async def list_scan_jobs(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
) -> list[Any] | None:
    """List jobs for a tenant-scoped scan."""
    scan = await _get_scan_for_tenant(scan_id=scan_id, tenant_id=tenant_id, session=session)
    if scan is None:
        return None
    result = await session.execute(
        text(
            """
            SELECT j.id,
                   j.scan_id,
                   j.phase,
                   j.tool,
                   j.status,
                   j.priority,
                   j.worker_id,
                   j.output_ref,
                   j.started_at,
                   j.completed_at,
                   j.error_message,
                   j.retry_count,
                   j.created_at,
                   n.output_summary
            FROM scan_jobs j
            LEFT JOIN scan_nodes n ON n.job_id = j.id
            WHERE j.scan_id = :scan_id AND j.tenant_id = :tenant_id
            ORDER BY j.phase ASC, j.created_at ASC
            """
        ),
        {"scan_id": str(scan_id), "tenant_id": str(tenant_id)},
    )
    jobs: list[dict[str, Any]] = []
    for row in result.mappings().all():
        output_summary = row.get("output_summary") or {}
        if not isinstance(output_summary, dict):
            output_summary = {}
        provenance = str(output_summary.get("execution_provenance") or "").strip().lower() or None
        status = "blocked" if provenance == "blocked" else str(row["status"])
        jobs.append(
            {
                "id": row["id"],
                "scan_id": row["scan_id"],
                "phase": int(row["phase"]),
                "tool": row["tool"],
                "status": status,
                "priority": row["priority"],
                "worker_id": row["worker_id"],
                "output_ref": row["output_ref"],
                "started_at": row["started_at"],
                "completed_at": row["completed_at"],
                "error_message": row["error_message"],
                "retry_count": int(row["retry_count"] or 0),
                "execution_mode": output_summary.get("execution_mode"),
                "execution_provenance": provenance,
                "execution_reason": output_summary.get("execution_reason"),
                "created_at": row["created_at"],
            }
        )
    return jobs


async def list_findings(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
    page: int = 1,
    page_size: int = 20,
) -> tuple[list[Finding], int]:
    """List findings for a scan (paginated)."""
    scan = await _get_scan_for_tenant(scan_id=scan_id, tenant_id=tenant_id, session=session)
    if scan is None:
        return [], 0

    base_filter = Finding.scan_id == scan.id

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
    tenant_id: uuid.UUID,
    session: AsyncSession,
) -> list[dict]:
    """Return artifact summary rows for a scan."""
    scan = await _get_scan_for_tenant(scan_id=scan_id, tenant_id=tenant_id, session=session)
    if scan is None:
        return []

    stmt = (
        select(ScanArtifact)
        .where(ScanArtifact.scan_id == scan.id, ScanArtifact.tenant_id == tenant_id)
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
                "execution_mode": _artifact_execution_mode(artifact.artifact_type, metadata),
                "execution_provenance": _artifact_execution_provenance(artifact.artifact_type, metadata),
                "execution_reason": _artifact_execution_reason(metadata),
                "created_at": artifact.created_at,
            }
        )

    return summaries


async def get_attack_graph(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
) -> dict | None:
    """Return the stored attack graph payload for a scan."""
    scan = await _get_scan_for_tenant(scan_id=scan_id, tenant_id=tenant_id, session=session)
    if scan is None:
        return None

    stmt = (
        select(ScanArtifact)
        .where(
            ScanArtifact.scan_id == scan_id,
            ScanArtifact.tenant_id == tenant_id,
            ScanArtifact.artifact_type == "attack_graph",
        )
        .order_by(ScanArtifact.created_at.desc())
        .limit(1)
    )
    artifact = (await session.execute(stmt)).scalar_one_or_none()
    if artifact is None:
        return _empty_attack_graph_payload(scan)

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
    tenant_id: uuid.UUID,
    session: AsyncSession,
) -> list[dict]:
    """Build a timeline from scan, job, and artifact state."""
    stmt = (
        select(Scan)
        .where(Scan.id == scan_id, Scan.tenant_id == tenant_id)
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

    jobs = await list_scan_jobs(scan_id=scan_id, tenant_id=tenant_id, session=session) or []
    for job in jobs:
        job_reason = _artifact_execution_reason(job)
        detail_parts = [f"Phase {job['phase']} · retries {job['retry_count']}"]
        if job_reason:
            detail_parts.append(str(job_reason).replace("_", " "))
        events.append(
            {
                "id": f"job:{job['id']}",
                "timestamp": job["completed_at"] or job["started_at"] or job["created_at"],
                "event_type": _timeline_event_type(int(job["phase"])),
                "title": f"{job['tool']} {job['status']}",
                "details": " · ".join(detail_parts),
                "status": job["status"],
                "phase": int(job["phase"]),
                "tool": job["tool"],
                "job_id": job["id"],
                "node_id": None,
                "artifact_ref": job.get("output_ref"),
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
    tenant_id: uuid.UUID,
    session: AsyncSession,
) -> list[dict]:
    """Extract evidence references from persisted findings."""
    scan = await _get_scan_for_tenant(scan_id=scan_id, tenant_id=tenant_id, session=session)
    if scan is None:
        return []

    stmt = (
        select(Finding)
        .where(Finding.scan_id == scan.id)
        .order_by(Finding.created_at.desc())
    )
    findings = list((await session.execute(stmt)).scalars().all())
    return _build_evidence_references(findings)


async def get_scan_report(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
) -> dict | None:
    """Build a buyer-ready report response from persisted findings and graph data."""
    context = await _load_report_context(
        scan_id=scan_id,
        tenant_id=tenant_id,
        session=session,
    )
    if context is None:
        return None

    scan = context["scan"]
    findings = context["findings"]
    severity_counts = context["severity_counts"]
    verification_counts = context["verification_counts"]
    asset_summary = _build_asset_summary(scan)
    evidence = _build_evidence_references(findings)
    top_findings = [_finding_snapshot(finding) for finding in findings[:5]]
    finding_groups = _build_finding_groups(findings)
    remediation_plan = _build_remediation_plan(findings)
    compliance = _build_compliance_mappings(findings)
    narrative = _build_attack_narrative(
        scan=scan,
        graph=context["attack_graph"],
        findings=findings,
        remediation_plan=remediation_plan,
    )
    comparison = context["comparison"]
    executive_summary = _build_executive_summary(
        asset_summary["target"],
        severity_counts,
        verification_counts,
    )

    report = {
        "scan_id": scan.id,
        "report_id": f"scan-report:{scan.id}",
        "generated_at": datetime.now(timezone.utc),
        "executive_summary": executive_summary,
        "severity_counts": severity_counts,
        "verification_counts": verification_counts,
        "execution_summary": context["execution_summary"],
        "vulnerability_count": len(findings),
        "evidence_count": len(evidence),
        "asset": asset_summary,
        "narrative": narrative,
        "compliance": compliance,
        "finding_groups": finding_groups,
        "remediation_plan": remediation_plan,
        "comparison": comparison,
        "retest": _build_retest_summary(scan, comparison),
        "export_formats": list(_DEFAULT_EXPORT_FORMATS),
        "top_findings": top_findings,
    }
    report["markdown"] = _build_report_markdown(report)
    return report


async def get_scan_comparison(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
    baseline_scan_id: uuid.UUID | None = None,
) -> dict | None:
    """Compare a scan against an explicit or inferred completed baseline."""
    context = await _load_report_context(
        scan_id=scan_id,
        tenant_id=tenant_id,
        session=session,
        baseline_scan_id=baseline_scan_id,
    )
    if context is None:
        return None
    return context["comparison"]


async def export_scan_report(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    export_format: str,
    session: AsyncSession,
) -> tuple[str, str, str] | None:
    """Export a scan report in markdown, json, or csv form."""
    report = await get_scan_report(
        scan_id=scan_id,
        tenant_id=tenant_id,
        session=session,
    )
    if report is None:
        return None

    target_slug = _slugify(str(report.get("asset", {}).get("target") or scan_id))
    scan_slug = str(scan_id)

    if export_format == "json":
        return (
            json.dumps(report, indent=2, default=_json_default),
            "application/json",
            f"pentra-report-{target_slug}-{scan_slug}.json",
        )

    if export_format == "csv":
        return (
            _build_report_csv(report),
            "text/csv; charset=utf-8",
            f"pentra-report-{target_slug}-{scan_slug}.csv",
        )

    return (
        str(report["markdown"]),
        "text/markdown; charset=utf-8",
        f"pentra-report-{target_slug}-{scan_slug}.md",
    )


async def _load_report_context(
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
    baseline_scan_id: uuid.UUID | None = None,
) -> dict[str, Any] | None:
    stmt = (
        select(Scan)
        .where(Scan.id == scan_id, Scan.tenant_id == tenant_id)
        .options(
            selectinload(Scan.findings),
            selectinload(Scan.asset).selectinload(Asset.project),
        )
    )
    scan = (await session.execute(stmt)).scalar_one_or_none()
    if scan is None:
        return None

    findings = _sort_findings_for_report(scan.findings)
    severity_counts = _count_severity(findings)
    verification_counts = _count_verification(findings)
    attack_graph = await get_attack_graph(
        scan_id=scan_id,
        tenant_id=tenant_id,
        session=session,
    )
    baseline_scan = await _select_baseline_scan(
        scan=scan,
        tenant_id=tenant_id,
        session=session,
        baseline_scan_id=baseline_scan_id,
    )
    comparison = _build_scan_comparison(
        current_scan=scan,
        current_findings=findings,
        baseline_scan=baseline_scan,
    )

    return {
        "scan": scan,
        "findings": findings,
        "severity_counts": severity_counts,
        "verification_counts": verification_counts,
        "execution_summary": _execution_summary_from_scan(scan),
        "attack_graph": attack_graph,
        "baseline_scan": baseline_scan,
        "comparison": comparison,
    }


def _sort_findings_for_report(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda finding: (
            -_verification_rank(_verification_state_for_finding(finding)),
            -_severity_rank(str(finding.severity)),
            -int(finding.confidence or 0),
            finding.created_at,
        ),
    )


def _count_severity(findings: list[Finding]) -> dict[str, int]:
    counts = {key: 0 for key in ("critical", "high", "medium", "low", "info")}
    for finding in findings:
        counts[str(finding.severity)] = counts.get(str(finding.severity), 0) + 1
    return counts


def _count_verification(findings: list[Finding]) -> dict[str, int]:
    counts = {"verified": 0, "suspected": 0, "detected": 0}
    for finding in findings:
        state = _verification_state_for_finding(finding)
        counts[state] = counts.get(state, 0) + 1
    return counts


def _execution_summary_from_scan(scan: Scan) -> dict[str, int]:
    summary = scan.result_summary or {}
    if not isinstance(summary, dict):
        return {"live": 0, "simulated": 0, "blocked": 0, "inferred": 0}
    execution_summary = summary.get("execution_summary") or {}
    if not isinstance(execution_summary, dict):
        return {"live": 0, "simulated": 0, "blocked": 0, "inferred": 0}
    return {
        "live": int(execution_summary.get("live", 0) or 0),
        "simulated": int(execution_summary.get("simulated", 0) or 0),
        "blocked": int(execution_summary.get("blocked", 0) or 0),
        "inferred": int(execution_summary.get("inferred", 0) or 0),
    }


def _artifact_execution_provenance(artifact_type: str, metadata: dict[str, Any] | None) -> str | None:
    if artifact_type in {"attack_graph", "report", "ai_reasoning"}:
        return "inferred"
    if not isinstance(metadata, dict):
        return None
    value = metadata.get("execution_provenance")
    return str(value) if value else None


def _artifact_execution_mode(artifact_type: str, metadata: dict[str, Any] | None) -> str | None:
    if artifact_type in {"attack_graph", "report", "ai_reasoning"}:
        return "derived"
    if not isinstance(metadata, dict):
        return None
    value = metadata.get("execution_mode")
    return str(value) if value else None


def _artifact_execution_reason(metadata: dict[str, Any] | None) -> str | None:
    if not isinstance(metadata, dict):
        return None
    value = metadata.get("execution_reason")
    return str(value) if value else None


def _build_asset_summary(scan: Scan) -> dict[str, Any]:
    asset = scan.asset
    if asset is None:
        return {
            "id": str(scan.asset_id),
            "name": f"Asset {str(scan.asset_id)[:8]}",
            "target": str(scan.asset_id),
            "asset_type": "unknown",
            "project_name": None,
        }

    project = getattr(asset, "project", None)
    return {
        "id": str(asset.id),
        "name": asset.name,
        "target": asset.target,
        "asset_type": asset.asset_type,
        "project_id": str(asset.project_id),
        "project_name": getattr(project, "name", None),
        "description": asset.description,
    }


def _finding_target(finding: Finding) -> str:
    evidence = finding.evidence or {}
    if isinstance(evidence, dict):
        endpoint = evidence.get("endpoint")
        if endpoint:
            return str(endpoint)
        target = evidence.get("target")
        if target:
            return str(target)
    return finding.title


def _finding_route_group(finding: Finding) -> str | None:
    evidence = finding.evidence or {}
    if not isinstance(evidence, dict):
        return None
    classification = evidence.get("classification") or {}
    if not isinstance(classification, dict):
        return None
    route_group = classification.get("route_group")
    return str(route_group) if route_group else None


def _finding_vulnerability_type(finding: Finding) -> str | None:
    value = getattr(finding, "vulnerability_type", None)
    return str(value) if value else None


def _finding_snapshot(finding: Finding) -> dict[str, Any]:
    return {
        "id": str(finding.id),
        "title": finding.title,
        "severity": str(finding.severity),
        "confidence": int(finding.confidence or 0),
        "vulnerability_type": _finding_vulnerability_type(finding),
        "target": _finding_target(finding),
        "route_group": _finding_route_group(finding),
        "verification_state": _verification_state_for_finding(finding),
        "verification_confidence": getattr(finding, "verification_confidence", None),
        "exploitability": getattr(finding, "exploitability", None),
        "surface": getattr(finding, "surface", None),
        "cvss_score": float(finding.cvss_score) if finding.cvss_score is not None else None,
        "description": finding.description,
        "remediation": finding.remediation,
        "tool_source": finding.tool_source,
        "created_at": finding.created_at,
    }


def _build_finding_groups(findings: list[Finding]) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}

    for finding in findings:
        surface = getattr(finding, "surface", None) or "web"
        route_group = _finding_route_group(finding)
        target = _finding_target(finding)
        label = route_group or target
        group_key = f"{surface}:{label}"
        snapshot = _finding_snapshot(finding)
        group = groups.setdefault(
            group_key,
            {
                "group_id": group_key,
                "title": label,
                "surface": surface,
                "target": target,
                "route_group": route_group,
                "severity_counts": {key: 0 for key in ("critical", "high", "medium", "low", "info")},
                "verification_counts": {"verified": 0, "suspected": 0, "detected": 0},
                "findings": [],
            },
        )
        group["severity_counts"][snapshot["severity"]] += 1
        group["verification_counts"][snapshot["verification_state"]] += 1
        group["findings"].append(snapshot)

    grouped = list(groups.values())
    for group in grouped:
        group["findings"].sort(
            key=lambda item: (
                -_verification_rank(str(item.get("verification_state") or "detected")),
                -_severity_rank(str(item.get("severity") or "info")),
                -int(item.get("confidence") or 0),
            )
        )

    return sorted(
        grouped,
        key=lambda group: (
            -_severity_rank(_highest_severity(group["severity_counts"])),
            group["title"],
        ),
    )


def _build_remediation_plan(findings: list[Finding]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}

    for finding in findings:
        vulnerability_type = _finding_vulnerability_type(finding) or "general"
        guidance = _FIX_GUIDANCE_LIBRARY.get(vulnerability_type, {})
        entry = grouped.setdefault(
            vulnerability_type,
            {
                "plan_id": vulnerability_type,
                "title": guidance.get("title") or f"Address {vulnerability_type.replace('_', ' ')} findings",
                "priority": "low",
                "owner_hint": guidance.get("owner_hint") or "Engineering",
                "rationale": "",
                "actions": list(guidance.get("actions") or []),
                "related_finding_ids": [],
                "related_vulnerability_types": [vulnerability_type],
                "related_targets": [],
            },
        )
        snapshot = _finding_snapshot(finding)
        entry["related_finding_ids"].append(snapshot["id"])
        if snapshot["target"] not in entry["related_targets"]:
            entry["related_targets"].append(snapshot["target"])
        entry["priority"] = _higher_priority(
            entry["priority"],
            _priority_from_finding(finding),
        )
        entry["rationale"] = _merge_rationale(
            entry["rationale"],
            _finding_rationale(finding),
        )
        remediation = snapshot.get("remediation")
        if remediation and remediation not in entry["actions"]:
            entry["actions"].append(remediation)

    return sorted(grouped.values(), key=lambda item: _priority_rank(item["priority"]), reverse=True)


def _build_compliance_mappings(findings: list[Finding]) -> list[dict[str, Any]]:
    mappings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for finding in findings:
        vulnerability_type = _finding_vulnerability_type(finding)
        if not vulnerability_type or vulnerability_type in seen:
            continue
        seen.add(vulnerability_type)
        mapping = _COMPLIANCE_LIBRARY.get(vulnerability_type, {})
        mappings.append(
            {
                "vulnerability_type": vulnerability_type,
                "owasp": list(mapping.get("owasp") or []),
                "cwe": list(mapping.get("cwe") or []),
            }
        )
    return mappings


def _build_attack_narrative(
    *,
    scan: Scan,
    graph: dict[str, Any] | None,
    findings: list[Finding],
    remediation_plan: list[dict[str, Any]],
) -> dict[str, Any] | None:
    asset_target = scan.asset.target if scan.asset is not None else str(scan.asset_id)
    graph = graph or {}
    nodes = graph.get("nodes")
    if not isinstance(nodes, list):
        nodes = []
    path_summary = graph.get("path_summary") if isinstance(graph, dict) else {}
    if not isinstance(path_summary, dict):
        path_summary = {}
    targets_reached = [str(item) for item in path_summary.get("targets_reached", []) if item]

    relevant_nodes = [
        node
        for node in nodes
        if isinstance(node, dict)
        and str(node.get("node_type") or "") in {"entrypoint", "service", "endpoint", "vulnerability", "privilege"}
    ]
    relevant_nodes.sort(key=lambda node: _narrative_node_rank(str(node.get("node_type") or "")))
    steps = []
    for index, node in enumerate(relevant_nodes[:5], start=1):
        node_type = str(node.get("node_type") or "unknown")
        label = str(node.get("label") or "Unnamed node")
        steps.append(
            {
                "step": index,
                "action": _narrative_action(node_type),
                "description": _narrative_description(node_type, label),
                "target": label,
                "risk": _narrative_risk(node_type),
                "artifact_ref": node.get("artifact_ref"),
            }
        )

    if not steps and not findings:
        return None

    if not steps:
        for index, finding in enumerate(findings[:3], start=1):
            snapshot = _finding_snapshot(finding)
            steps.append(
                {
                    "step": index,
                    "action": "exploitation",
                    "description": f"Pentra confirmed {snapshot['title']} on {snapshot['target']}.",
                    "target": snapshot["target"],
                    "risk": snapshot["severity"],
                    "artifact_ref": None,
                }
            )

    total_paths = int(path_summary.get("total_paths", 0) or 0)
    summary = (
        f"Pentra identified {total_paths} attack path(s) across {asset_target}."
        if total_paths
        else f"Pentra assembled a focused attack narrative from persisted findings for {asset_target}."
    )
    impact = _impact_summary_from_targets(targets_reached, findings)
    recommendations = [item["title"] for item in remediation_plan[:3]]
    return {
        "title": f"Attack Path Narrative - {asset_target}",
        "summary": summary,
        "impact": impact,
        "steps": steps,
        "recommendations": recommendations,
        "targets_reached": targets_reached,
    }


async def _select_baseline_scan(
    *,
    scan: Scan,
    tenant_id: uuid.UUID,
    session: AsyncSession,
    baseline_scan_id: uuid.UUID | None = None,
) -> Scan | None:
    explicit_baseline = baseline_scan_id
    config = scan.config or {}
    if explicit_baseline is None and isinstance(config, dict):
        retest_config = config.get("retest") or {}
        if isinstance(retest_config, dict):
            raw_baseline = retest_config.get("baseline_scan_id") or retest_config.get("source_scan_id")
            if raw_baseline:
                try:
                    explicit_baseline = uuid.UUID(str(raw_baseline))
                except (TypeError, ValueError):
                    explicit_baseline = None

    stmt = (
        select(Scan)
        .where(Scan.tenant_id == tenant_id)
        .options(selectinload(Scan.findings), selectinload(Scan.asset).selectinload(Asset.project))
    )
    if explicit_baseline is not None:
        return (
            await session.execute(stmt.where(Scan.id == explicit_baseline))
        ).scalar_one_or_none()

    comparison_stmt = (
        stmt.where(
            Scan.asset_id == scan.asset_id,
            Scan.id != scan.id,
            Scan.status == "completed",
            Scan.created_at < scan.created_at,
        )
        .order_by(Scan.created_at.desc())
        .limit(1)
    )
    return (await session.execute(comparison_stmt)).scalar_one_or_none()


def _build_scan_comparison(
    *,
    current_scan: Scan,
    current_findings: list[Finding],
    baseline_scan: Scan | None,
) -> dict[str, Any]:
    generated_at = datetime.now(timezone.utc)
    if baseline_scan is None:
        return {
            "current_scan_id": current_scan.id,
            "baseline_scan_id": None,
            "generated_at": generated_at,
            "baseline_generated_at": None,
            "summary": "No previous completed scan is available for historical comparison yet.",
            "counts": {"new": len(current_findings), "resolved": 0, "persistent": 0, "escalated": 0},
            "severity_delta": _count_severity(current_findings),
            "verification_delta": _count_verification(current_findings),
            "new_findings": [_finding_snapshot(finding) for finding in current_findings[:5]],
            "resolved_findings": [],
            "escalated_findings": [],
        }

    baseline_findings = _sort_findings_for_report(baseline_scan.findings)
    current_by_key = {_finding_comparison_key(item): item for item in current_findings}
    baseline_by_key = {_finding_comparison_key(item): item for item in baseline_findings}

    new_keys = [key for key in current_by_key if key not in baseline_by_key]
    resolved_keys = [key for key in baseline_by_key if key not in current_by_key]
    persistent_keys = [key for key in current_by_key if key in baseline_by_key]
    escalated_keys = [
        key
        for key in persistent_keys
        if _finding_has_escalated(current_by_key[key], baseline_by_key[key])
    ]

    severity_delta = {
        level: _count_severity(current_findings).get(level, 0) - _count_severity(baseline_findings).get(level, 0)
        for level in ("critical", "high", "medium", "low", "info")
    }
    verification_delta = {
        level: _count_verification(current_findings).get(level, 0) - _count_verification(baseline_findings).get(level, 0)
        for level in ("verified", "suspected", "detected")
    }
    summary = (
        f"Compared with the baseline from {baseline_scan.completed_at or baseline_scan.created_at:%b %d, %Y}, "
        f"Pentra found {len(new_keys)} new, {len(resolved_keys)} resolved, and {len(persistent_keys)} persistent findings."
    )

    return {
        "current_scan_id": current_scan.id,
        "baseline_scan_id": baseline_scan.id,
        "generated_at": generated_at,
        "baseline_generated_at": baseline_scan.completed_at or baseline_scan.created_at,
        "summary": summary,
        "counts": {
            "new": len(new_keys),
            "resolved": len(resolved_keys),
            "persistent": len(persistent_keys),
            "escalated": len(escalated_keys),
        },
        "severity_delta": severity_delta,
        "verification_delta": verification_delta,
        "new_findings": [_finding_snapshot(current_by_key[key]) for key in new_keys[:5]],
        "resolved_findings": [_finding_snapshot(baseline_by_key[key]) for key in resolved_keys[:5]],
        "escalated_findings": [_finding_snapshot(current_by_key[key]) for key in escalated_keys[:5]],
    }


def _build_retest_summary(scan: Scan, comparison: dict[str, Any]) -> dict[str, Any]:
    return {
        "eligible": scan.status == "completed",
        "recommended_scan_type": scan.scan_type,
        "recommended_priority": _recommended_retest_priority(scan),
        "baseline_scan_id": str(scan.id),
        "compare_against_scan_id": str(comparison.get("baseline_scan_id")) if comparison.get("baseline_scan_id") else None,
        "launch_endpoint": f"/api/v1/scans/{scan.id}/retest",
    }


def _build_retest_config(
    *,
    source_scan: Scan,
    config_overrides: dict[str, Any],
) -> dict[str, Any]:
    base_config = deepcopy(source_scan.config or {})
    if not isinstance(base_config, dict):
        base_config = {}
    overrides = deepcopy(config_overrides or {})
    if not isinstance(overrides, dict):
        overrides = {}

    base_retest = base_config.get("retest") if isinstance(base_config.get("retest"), dict) else {}
    override_retest = overrides.get("retest") if isinstance(overrides.get("retest"), dict) else {}
    merged = {
        **base_config,
        **{key: value for key, value in overrides.items() if key != "retest"},
    }
    merged["retest"] = {
        **base_retest,
        **override_retest,
        "mode": "buyer_ready_retest",
        "baseline_scan_id": str(source_scan.id),
        "requested_at": datetime.now(timezone.utc).isoformat(),
        "targets": _build_retest_targets(source_scan.findings),
    }
    return merged


def _build_retest_targets(findings: list[Finding]) -> list[dict[str, Any]]:
    targets = []
    for finding in _sort_findings_for_report(findings)[:10]:
        snapshot = _finding_snapshot(finding)
        targets.append(
            {
                "finding_id": snapshot["id"],
                "title": snapshot["title"],
                "vulnerability_type": snapshot["vulnerability_type"],
                "target": snapshot["target"],
                "route_group": snapshot["route_group"],
                "verification_state": snapshot["verification_state"],
            }
        )
    return targets


def _recommended_retest_priority(scan: Scan) -> str:
    summary = scan.result_summary or {}
    severity_counts = summary.get("severity_counts") if isinstance(summary, dict) else {}
    if isinstance(severity_counts, dict):
        if int(severity_counts.get("critical", 0) or 0) > 0:
            return "high"
        if int(severity_counts.get("high", 0) or 0) > 0:
            return "high"
    return str(scan.priority)


def _build_report_csv(report: dict[str, Any]) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "finding_id",
            "title",
            "severity",
            "verification_state",
            "vulnerability_type",
            "target",
            "route_group",
            "exploitability",
            "confidence",
            "remediation",
        ],
    )
    writer.writeheader()

    for group in report.get("finding_groups", []):
        if not isinstance(group, dict):
            continue
        for finding in group.get("findings", []):
            if not isinstance(finding, dict):
                continue
            writer.writerow(
                {
                    "finding_id": finding.get("id"),
                    "title": finding.get("title"),
                    "severity": finding.get("severity"),
                    "verification_state": finding.get("verification_state"),
                    "vulnerability_type": finding.get("vulnerability_type"),
                    "target": finding.get("target"),
                    "route_group": finding.get("route_group"),
                    "exploitability": finding.get("exploitability"),
                    "confidence": finding.get("confidence"),
                    "remediation": finding.get("remediation"),
                }
            )

    return output.getvalue()


def _json_default(value: Any) -> Any:
    if isinstance(value, (datetime, uuid.UUID)):
        return str(value)
    return value


def _slugify(value: str) -> str:
    cleaned = "".join(char.lower() if char.isalnum() else "-" for char in value)
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    return cleaned.strip("-") or "scan"


def _finding_comparison_key(finding: Finding) -> str:
    vulnerability_type = _finding_vulnerability_type(finding) or finding.title.lower()
    route_group = _finding_route_group(finding) or _finding_target(finding)
    return f"{vulnerability_type}:{route_group}".lower()


def _finding_has_escalated(current: Finding, baseline: Finding) -> bool:
    if _severity_rank(str(current.severity)) > _severity_rank(str(baseline.severity)):
        return True
    return _verification_rank(_verification_state_for_finding(current)) > _verification_rank(
        _verification_state_for_finding(baseline)
    )


def _priority_from_finding(finding: Finding) -> str:
    if _verification_state_for_finding(finding) == "verified" and str(finding.severity) in {"critical", "high"}:
        return "immediate"
    if str(finding.severity) in {"critical", "high"}:
        return "high"
    if str(finding.severity) == "medium":
        return "medium"
    return "low"


def _priority_rank(priority: str) -> int:
    return {"immediate": 4, "high": 3, "medium": 2, "low": 1}.get(priority, 0)


def _higher_priority(left: str, right: str) -> str:
    return left if _priority_rank(left) >= _priority_rank(right) else right


def _finding_rationale(finding: Finding) -> str:
    vulnerability_type = (_finding_vulnerability_type(finding) or "finding").replace("_", " ")
    target = _finding_target(finding)
    verification = _verification_state_for_finding(finding)
    return f"{str(finding.severity).capitalize()} {verification} {vulnerability_type} affecting {target}."


def _merge_rationale(existing: str, candidate: str) -> str:
    if not existing:
        return candidate
    if candidate and candidate not in existing:
        return f"{existing} {candidate}"
    return existing


def _highest_severity(severity_counts: dict[str, int]) -> str:
    for level in ("critical", "high", "medium", "low", "info"):
        if int(severity_counts.get(level, 0) or 0) > 0:
            return level
    return "info"


def _narrative_node_rank(node_type: str) -> int:
    return {
        "entrypoint": 0,
        "service": 1,
        "endpoint": 2,
        "vulnerability": 3,
        "privilege": 4,
    }.get(node_type, 5)


def _narrative_action(node_type: str) -> str:
    return {
        "entrypoint": "discovery",
        "service": "enumeration",
        "endpoint": "enumeration",
        "vulnerability": "exploitation",
        "privilege": "impact",
    }.get(node_type, "analysis")


def _narrative_description(node_type: str, label: str) -> str:
    return {
        "entrypoint": f"The attack path begins from {label}.",
        "service": f"Pentra identified an exposed service surface at {label}.",
        "endpoint": f"Pentra traversed the reachable application endpoint {label}.",
        "vulnerability": f"Pentra connected offensive evidence to the vulnerability node {label}.",
        "privilege": f"The path can terminate in the privileged state {label}.",
    }.get(node_type, f"Pentra analyzed {label}.")


def _narrative_risk(node_type: str) -> str:
    return {
        "entrypoint": "medium",
        "service": "medium",
        "endpoint": "medium",
        "vulnerability": "high",
        "privilege": "critical",
    }.get(node_type, "low")


def _impact_summary_from_targets(targets_reached: list[str], findings: list[Finding]) -> str:
    if "shell_access" in targets_reached:
        return "Attack paths show a route to shell-level access if the identified weaknesses remain exploitable."
    if "database_access" in targets_reached:
        return "Attack paths show reachable database access and sensitive data exposure risk."
    if any(_finding_vulnerability_type(finding) == "auth_bypass" for finding in findings):
        return "Broken access control creates a credible path to privileged workflow abuse."
    if any(_finding_vulnerability_type(finding) == "idor" for finding in findings):
        return "Object-level authorization gaps allow sensitive records to be reached without the correct principal."
    return "The offensive graph shows exploitable web and API weaknesses that engineering should remediate in priority order."


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
    provenance = _artifact_execution_provenance(artifact_type, metadata)
    parts = [artifact_type, f"items {item_count}", f"findings {finding_count}", f"evidence {evidence_count}"]
    if provenance:
        parts.append(f"truth {provenance}")
    return " · ".join(parts)


def _empty_attack_graph_payload(scan: Scan) -> dict[str, Any]:
    return {
        "scan_id": scan.id,
        "tenant_id": scan.tenant_id,
        "built_at": None,
        "node_count": 0,
        "edge_count": 0,
        "path_summary": {
            "total_paths": 0,
            "targets_reached": [],
            "shortest_path": 0,
        },
        "scoring_summary": {},
        "nodes": [],
        "edges": [],
    }


def _build_evidence_references(findings: list[Finding]) -> list[dict[str, Any]]:
    deduped: dict[str, dict[str, Any]] = {}

    for finding in findings:
        evidence = finding.evidence or {}
        if not isinstance(evidence, dict):
            continue

        target = str(
            evidence.get("endpoint")
            or evidence.get("target")
            or "unknown"
        )
        storage_ref = evidence.get("storage_ref")
        raw_signatures: set[str] = set()

        for evidence_type in ("request", "response", "payload", "exploit_result"):
            content = evidence.get(evidence_type)
            if not content:
                continue

            candidate = {
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
                "storage_ref": storage_ref,
                "metadata": {},
            }
            signature = _evidence_signature(candidate)
            raw_signatures.add(signature)
            _upsert_evidence_reference(deduped, signature, candidate)

        references = evidence.get("references", [])
        if not isinstance(references, list):
            continue

        for index, reference in enumerate(references):
            if isinstance(reference, dict):
                evidence_type = str(reference.get("evidence_type", "reference"))
                preview = str(reference.get("content_preview", ""))
                reference_id = reference.get("id") or f"{finding.id}:reference:{index}"
                reference_storage_ref = reference.get("storage_ref") or storage_ref
                label = reference.get("label", finding.title)
            else:
                evidence_type = "reference"
                preview = str(reference)
                reference_id = f"{finding.id}:reference:{index}"
                reference_storage_ref = storage_ref
                label = f"{finding.title} · reference"

            candidate = {
                "id": reference_id,
                "finding_id": finding.id,
                "finding_title": finding.title,
                "severity": finding.severity,
                "tool_source": finding.tool_source,
                "evidence_type": evidence_type,
                "label": label,
                "target": target,
                "content_preview": preview,
                "content": None,
                "storage_ref": reference_storage_ref,
                "metadata": {},
            }
            signature = _evidence_signature(candidate)
            if evidence_type != "reference" and signature in raw_signatures:
                continue
            _upsert_evidence_reference(deduped, signature, candidate)

    return sorted(
        deduped.values(),
        key=lambda item: (
            -_severity_rank(str(item.get("severity", "info"))),
            -_evidence_rank(str(item.get("evidence_type", "reference"))),
            str(item.get("finding_title", "")),
            str(item.get("label", "")),
        ),
    )


def _evidence_signature(item: dict[str, Any]) -> str:
    storage_ref = str(item.get("storage_ref") or "")
    base_storage_ref = storage_ref.split("#", 1)[0]
    content = str(item.get("content") or item.get("content_preview") or "").strip()
    return "|".join(
        [
            str(item.get("evidence_type", "reference")),
            str(item.get("target", "")),
            base_storage_ref,
            content[:240],
        ]
    )


def _upsert_evidence_reference(
    deduped: dict[str, dict[str, Any]],
    signature: str,
    candidate: dict[str, Any],
) -> None:
    existing = deduped.get(signature)
    candidate = {
        **candidate,
        "metadata": {
            **candidate.get("metadata", {}),
            "related_findings": [candidate.get("finding_title")] if candidate.get("finding_title") else [],
            "duplicate_count": 1,
        },
    }

    if existing is None:
        deduped[signature] = candidate
        return

    _merge_related_finding(existing, candidate.get("finding_title"))
    existing["metadata"]["duplicate_count"] = int(existing["metadata"].get("duplicate_count", 1)) + 1

    if _evidence_preference(candidate) > _evidence_preference(existing):
        candidate["metadata"] = existing["metadata"]
        deduped[signature] = candidate


def _merge_related_finding(item: dict[str, Any], finding_title: str | None) -> None:
    if not finding_title:
        return
    metadata = item.setdefault("metadata", {})
    related = metadata.setdefault("related_findings", [])
    if finding_title not in related:
        related.append(finding_title)


def _evidence_preference(item: dict[str, Any]) -> tuple[int, int, int]:
    return (
        1 if item.get("content") else 0,
        _severity_rank(str(item.get("severity", "info"))),
        _evidence_rank(str(item.get("evidence_type", "reference"))),
    )


def _severity_rank(severity: str) -> int:
    return {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
    }.get(severity, 0)


def _evidence_rank(evidence_type: str) -> int:
    return {
        "exploit_result": 5,
        "response": 4,
        "request": 3,
        "payload": 2,
        "reference": 1,
    }.get(evidence_type, 0)


def _verification_state_for_finding(finding: Finding) -> str:
    state = getattr(finding, "verification_state", None)
    if state in {"verified", "suspected", "detected"}:
        return str(state)
    if finding.source_type == "exploit_verify":
        return "verified"
    if finding.source_type == "ai_analysis":
        return "suspected"
    return "detected"


def _verification_rank(state: str) -> int:
    return {
        "verified": 3,
        "suspected": 2,
        "detected": 1,
    }.get(state, 0)


def _build_executive_summary(
    asset_target: str,
    severity_counts: dict[str, int],
    verification_counts: dict[str, int],
) -> str:
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
    if verification_counts.get("verified"):
        parts.append(f"{verification_counts['verified']} verified")
    if verification_counts.get("suspected"):
        parts.append(f"{verification_counts['suspected']} suspected")
    return ", ".join(parts) + "."


def _build_report_markdown(report: dict[str, Any]) -> str:
    asset = report.get("asset", {}) if isinstance(report, dict) else {}
    asset_target = str(asset.get("target") or report.get("scan_id") or "unknown")
    executive_summary = str(report.get("executive_summary") or "")
    severity_counts = report.get("severity_counts") or {}
    verification_counts = report.get("verification_counts") or {}
    execution_summary = report.get("execution_summary") or {}
    top_findings = report.get("top_findings") or []
    comparison = report.get("comparison") or {}
    narrative = report.get("narrative") or {}
    remediation_plan = report.get("remediation_plan") or []
    finding_groups = report.get("finding_groups") or []

    lines = [
        f"# Pentra Report - {asset_target}",
        "",
        "## Asset Summary",
        "",
        f"- Asset: {asset.get('name') or 'Unknown Asset'}",
        f"- Project: {asset.get('project_name') or 'Unassigned'}",
        f"- Asset Type: {asset.get('asset_type') or 'unknown'}",
        "",
        "## Executive Summary",
        "",
        executive_summary,
        "",
        "## Severity Summary",
        "",
        f"- Critical: {severity_counts.get('critical', 0)}",
        f"- High: {severity_counts.get('high', 0)}",
        f"- Medium: {severity_counts.get('medium', 0)}",
        f"- Low: {severity_counts.get('low', 0)}",
        f"- Info: {severity_counts.get('info', 0)}",
        "",
        "## Verification Summary",
        "",
        f"- Verified: {verification_counts.get('verified', 0)}",
        f"- Suspected: {verification_counts.get('suspected', 0)}",
        f"- Detected: {verification_counts.get('detected', 0)}",
        "",
        "## Execution Truth",
        "",
        f"- Live Artifacts: {execution_summary.get('live', 0)}",
        f"- Simulated Artifacts: {execution_summary.get('simulated', 0)}",
        f"- Blocked Artifacts: {execution_summary.get('blocked', 0)}",
        f"- Inferred Artifacts: {execution_summary.get('inferred', 0)}",
        "",
        "## Historical Comparison",
        "",
        str(comparison.get("summary") or "No historical comparison available."),
        "",
    ]

    if comparison:
        counts = comparison.get("counts") or {}
        lines.extend(
            [
                f"- New Findings: {counts.get('new', 0)}",
                f"- Resolved Findings: {counts.get('resolved', 0)}",
                f"- Persistent Findings: {counts.get('persistent', 0)}",
                f"- Escalated Findings: {counts.get('escalated', 0)}",
                "",
            ]
        )

    if narrative:
        lines.extend(
            [
                "## Attack Path Narrative",
                "",
                str(narrative.get("summary") or ""),
                "",
            ]
        )
        if narrative.get("impact"):
            lines.extend(["### Impact", "", str(narrative.get("impact")), ""])
        steps = narrative.get("steps") or []
        if isinstance(steps, list) and steps:
            lines.extend(["### Attack Steps", ""])
            for step in steps:
                if not isinstance(step, dict):
                    continue
                lines.append(
                    f"- Step {step.get('step')}: {step.get('description')} [{step.get('risk', 'low')}]"
                )
            lines.append("")

    lines.extend(["## Remediation Plan", ""])
    if not remediation_plan:
        lines.append("No remediation plan items were generated.")
    else:
        for item in remediation_plan:
            if not isinstance(item, dict):
                continue
            lines.extend(
                [
                    f"### {item.get('title')}",
                    f"Priority: {item.get('priority')}",
                    f"Owner Hint: {item.get('owner_hint')}",
                    item.get("rationale") or "",
                    "",
                ]
            )
            for action in item.get("actions") or []:
                lines.append(f"- {action}")
            lines.append("")

    lines.extend(["## Grouped Findings", ""])
    if not finding_groups:
        lines.append("No grouped findings were available.")
    else:
        for group in finding_groups:
            if not isinstance(group, dict):
                continue
            lines.extend(
                [
                    f"### {group.get('title')}",
                    f"Surface: {group.get('surface') or 'web'}",
                    "",
                ]
            )
            for finding in group.get("findings") or []:
                if not isinstance(finding, dict):
                    continue
                verification_state = str(finding.get("verification_state") or "detected").capitalize()
                lines.extend(
                    [
                        f"- {finding.get('title')} ({finding.get('severity')}, {verification_state})",
                        f"  Target: {finding.get('target')}",
                    ]
                )
            lines.append("")

    lines.extend(["## Top Findings", ""])
    if not top_findings:
        lines.append("No persisted findings were available.")
    else:
        for finding in top_findings:
            verification_state = str(finding.get("verification_state") or "detected").capitalize()
            verification_confidence = finding.get("verification_confidence")
            verification_line = f"Verification: {verification_state}"
            if verification_confidence is not None:
                verification_line += f" ({verification_confidence}%)"
            lines.extend(
                [
                    f"### {finding['title']}",
                    f"Severity: {finding['severity']}",
                    verification_line,
                    finding.get("description") or "No description provided.",
                    "",
                ]
            )

    return "\n".join(lines)
