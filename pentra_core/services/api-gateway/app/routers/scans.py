"""Scan router — scan lifecycle endpoints.

Mounted at ``/api/v1/scans``.

Events are published to Redis Streams (XADD) for durable delivery
to the MOD-04 orchestrator service.
"""

from __future__ import annotations

import logging
import json
import uuid

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from pentra_common.events.stream_publisher import StreamPublisher
from pentra_common.schemas import (
    ScanAIReasoningResponse,
    ArtifactSummaryResponse,
    AttackGraphResponse,
    EvidenceReferenceResponse,
    FindingResponse,
    PaginatedResponse,
    ScanCreate,
    ScanComparisonResponse,
    ScanRetestCreate,
    ScanReportResponse,
    ScanResponse,
    ScanJobResponse,
    ScanTimelineEventResponse,
)

from app.deps import CurrentUser, get_current_user, get_db_session, get_stream_publisher, require_roles
from app.observability.audit import log_audit_event
from app.security.redaction import redact_secrets
from app.services import ai_reasoning_service, scan_service

logger = logging.getLogger(__name__)

router = APIRouter(tags=["scans"])


def _scan_response(scan) -> ScanResponse:
    payload = ScanResponse.model_validate(scan)
    return payload.model_copy(update={"config": redact_secrets(payload.config or {})})


@router.post(
    "",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a scan",
)
async def create_scan(
    request: Request,
    body: ScanCreate,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    user: CurrentUser = Depends(require_roles("owner", "admin", "member")),
    session: AsyncSession = Depends(get_db_session),
    publisher: StreamPublisher = Depends(get_stream_publisher),
) -> ScanResponse:
    """Create a new scan for an asset.

    Validates tenant quota, creates the Scan record, and publishes a
    ``scan.created`` event to Redis Streams for the orchestrator.

    All DAG planning and ScanJob creation is handled by the orchestrator.
    """
    try:
        scan = await scan_service.create_scan(
            tenant_id=user.tenant_id,
            created_by=user.user_id,
            asset_id=body.asset_id,
            scan_type=body.scan_type.value,
            priority=body.priority.value,
            config=body.config,
            idempotency_key=idempotency_key,
            stream_publisher=publisher,
            session=session,
        )
    except ValueError as exc:
        log_audit_event(
            request=request,
            user=user,
            action="scan.create",
            outcome="denied",
            resource_type="scan",
            details={
                "asset_id": str(body.asset_id),
                "scan_type": body.scan_type.value,
                "reason": str(exc),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        )
    except (ConnectionError, RuntimeError, OSError) as exc:
        log_audit_event(
            request=request,
            user=user,
            action="scan.create",
            outcome="error",
            resource_type="scan",
            details={
                "asset_id": str(body.asset_id),
                "scan_type": body.scan_type.value,
                "reason": str(exc),
            },
        )
        logger.error("Infrastructure error during scan creation: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Backend service unavailable — check that Redis and the orchestrator are running",
        )
    log_audit_event(
        request=request,
        user=user,
        action="scan.create",
        outcome="success",
        resource_type="scan",
        resource_id=str(scan.id),
        details={
            "asset_id": str(body.asset_id),
            "scan_type": body.scan_type.value,
            "priority": body.priority.value,
            "idempotency_key": idempotency_key,
            "profile_id": (scan.config or {}).get("profile_id"),
        },
    )
    return _scan_response(scan)


@router.get(
    "",
    response_model=PaginatedResponse[ScanResponse],
    summary="List scans",
)
async def list_scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status_filter: str | None = Query(None, alias="status"),
    asset_id: uuid.UUID | None = Query(None),
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> PaginatedResponse[ScanResponse]:
    """List scans for the authenticated tenant (paginated, filterable)."""
    items, total = await scan_service.list_scans(
        tenant_id=user.tenant_id,
        session=session,
        status_filter=status_filter,
        asset_id=asset_id,
        page=page,
        page_size=page_size,
    )
    return PaginatedResponse(
        items=[_scan_response(s) for s in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/{scan_id}",
    response_model=ScanResponse,
    summary="Get scan detail",
)
async def get_scan(
    scan_id: uuid.UUID,
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> ScanResponse:
    """Get a single scan by ID."""
    scan = await scan_service.get_scan(
        scan_id=scan_id,
        tenant_id=user.tenant_id,
        session=session,
    )
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found"
        )
    return _scan_response(scan)


@router.get(
    "/{scan_id}/jobs",
    response_model=list[ScanJobResponse],
    summary="List scan jobs",
)
async def list_scan_jobs(
    scan_id: uuid.UUID,
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> list[ScanJobResponse]:
    """List all execution jobs for a scan (created by orchestrator)."""
    jobs = await scan_service.list_scan_jobs(
        scan_id=scan_id,
        tenant_id=user.tenant_id,
        session=session,
    )
    if jobs is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found"
        )
    return [ScanJobResponse.model_validate(job) for job in jobs]


@router.post(
    "/{scan_id}/cancel",
    response_model=ScanResponse,
    summary="Cancel a scan",
)
async def cancel_scan(
    request: Request,
    scan_id: uuid.UUID,
    user: CurrentUser = Depends(require_roles("owner", "admin", "member")),
    session: AsyncSession = Depends(get_db_session),
    publisher: StreamPublisher = Depends(get_stream_publisher),
) -> ScanResponse:
    """Cancel a running scan.

    Publishes ``scan.status_changed`` (cancelled) to Redis Streams so
    the orchestrator can gracefully stop dispatching jobs.
    """
    try:
        scan = await scan_service.cancel_scan(
            scan_id=scan_id,
            tenant_id=user.tenant_id,
            stream_publisher=publisher,
            session=session,
        )
    except ValueError as exc:
        log_audit_event(
            request=request,
            user=user,
            action="scan.cancel",
            outcome="denied",
            resource_type="scan",
            resource_id=str(scan_id),
            details={"reason": str(exc)},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        )
    log_audit_event(
        request=request,
        user=user,
        action="scan.cancel",
        outcome="success",
        resource_type="scan",
        resource_id=str(scan.id),
    )
    return _scan_response(scan)


@router.post(
    "/{scan_id}/retest",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Launch a retest scan from a completed scan",
)
async def create_retest_scan(
    request: Request,
    scan_id: uuid.UUID,
    body: ScanRetestCreate | None = None,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    user: CurrentUser = Depends(require_roles("owner", "admin", "member")),
    session: AsyncSession = Depends(get_db_session),
    publisher: StreamPublisher = Depends(get_stream_publisher),
) -> ScanResponse:
    try:
        scan = await scan_service.create_retest_scan(
            source_scan_id=scan_id,
            tenant_id=user.tenant_id,
            created_by=user.user_id,
            priority=body.priority.value if body and body.priority else None,
            config_overrides=body.config_overrides if body else None,
            idempotency_key=idempotency_key,
            stream_publisher=publisher,
            session=session,
        )
    except ValueError as exc:
        log_audit_event(
            request=request,
            user=user,
            action="scan.retest",
            outcome="denied",
            resource_type="scan",
            resource_id=str(scan_id),
            details={"reason": str(exc)},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )
    log_audit_event(
        request=request,
        user=user,
        action="scan.retest",
        outcome="success",
        resource_type="scan",
        resource_id=str(scan.id),
        details={
            "source_scan_id": str(scan_id),
            "idempotency_key": idempotency_key,
        },
    )
    return _scan_response(scan)


@router.get(
    "/{scan_id}/findings",
    response_model=PaginatedResponse[FindingResponse],
    summary="List findings for a scan",
)
async def list_findings(
    scan_id: uuid.UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> PaginatedResponse[FindingResponse]:
    """List vulnerability findings for a scan (paginated)."""
    items, total = await scan_service.list_findings(
        scan_id=scan_id,
        tenant_id=user.tenant_id,
        session=session,
        page=page,
        page_size=page_size,
    )
    return PaginatedResponse(
        items=[FindingResponse.model_validate(f) for f in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/{scan_id}/artifacts/summary",
    response_model=list[ArtifactSummaryResponse],
    summary="List normalized artifact summaries for a scan",
)
async def list_artifact_summaries(
    scan_id: uuid.UUID,
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> list[ArtifactSummaryResponse]:
    summaries = await scan_service.list_artifact_summaries(
        scan_id=scan_id,
        tenant_id=user.tenant_id,
        session=session,
    )
    return [ArtifactSummaryResponse.model_validate(item) for item in summaries]


@router.get(
    "/{scan_id}/attack-graph",
    response_model=AttackGraphResponse,
    summary="Get the persisted attack graph for a scan",
)
async def get_attack_graph(
    scan_id: uuid.UUID,
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> AttackGraphResponse:
    graph = await scan_service.get_attack_graph(
        scan_id=scan_id,
        tenant_id=user.tenant_id,
        session=session,
    )
    if graph is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Attack graph not found",
        )
    return AttackGraphResponse.model_validate(graph)


@router.get(
    "/{scan_id}/timeline",
    response_model=list[ScanTimelineEventResponse],
    summary="Get scan timeline events",
)
async def get_scan_timeline(
    scan_id: uuid.UUID,
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> list[ScanTimelineEventResponse]:
    timeline = await scan_service.get_scan_timeline(
        scan_id=scan_id,
        tenant_id=user.tenant_id,
        session=session,
    )
    return [ScanTimelineEventResponse.model_validate(item) for item in timeline]


@router.get(
    "/{scan_id}/evidence",
    response_model=list[EvidenceReferenceResponse],
    summary="List evidence references for a scan",
)
async def list_evidence(
    scan_id: uuid.UUID,
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> list[EvidenceReferenceResponse]:
    evidence = await scan_service.list_evidence_references(
        scan_id=scan_id,
        tenant_id=user.tenant_id,
        session=session,
    )
    return [EvidenceReferenceResponse.model_validate(item) for item in evidence]


@router.get(
    "/{scan_id}/comparison",
    response_model=ScanComparisonResponse,
    summary="Compare a scan with its previous completed baseline",
)
async def get_scan_comparison(
    scan_id: uuid.UUID,
    baseline_scan_id: uuid.UUID | None = Query(
        default=None,
        description="Optional explicit baseline scan id. Defaults to the previous completed scan on the same asset.",
    ),
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> ScanComparisonResponse:
    comparison = await scan_service.get_scan_comparison(
        scan_id=scan_id,
        tenant_id=user.tenant_id,
        baseline_scan_id=baseline_scan_id,
        session=session,
    )
    if comparison is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )
    return ScanComparisonResponse.model_validate(comparison)


@router.get(
    "/{scan_id}/ai-reasoning",
    response_model=ScanAIReasoningResponse,
    summary="Get advisory AI reasoning for a scan",
)
async def get_scan_ai_reasoning(
    scan_id: uuid.UUID,
    refresh: bool = Query(False),
    mode: str = Query(
        "advisory_only",
        pattern="^(advisory_only|deep_advisory)$",
        description="AI advisory mode. Deep Advisory uses the premium reasoning route.",
    ),
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> ScanAIReasoningResponse:
    reasoning = await ai_reasoning_service.get_scan_ai_reasoning(
        scan_id=scan_id,
        tenant_id=user.tenant_id,
        user_id=user.user_id,
        session=session,
        refresh=refresh,
        advisory_mode=mode,
    )
    if reasoning is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )
    return ScanAIReasoningResponse.model_validate(reasoning)


@router.get(
    "/{scan_id}/report",
    response_model=ScanReportResponse,
    summary="Build a scan report from persisted findings",
)
async def get_scan_report(
    scan_id: uuid.UUID,
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> ScanReportResponse:
    report = await scan_service.get_scan_report(
        scan_id=scan_id,
        tenant_id=user.tenant_id,
        session=session,
    )
    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )
    return ScanReportResponse.model_validate(report)


@router.get(
    "/{scan_id}/report/export",
    summary="Export a scan report as markdown, json, or csv",
)
async def export_scan_report(
    request: Request,
    scan_id: uuid.UUID,
    format: str = Query(
        "markdown",
        pattern="^(markdown|json|csv)$",
        description="Export format for the scan report.",
    ),
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> Response:
    exported = await scan_service.export_scan_report(
        scan_id=scan_id,
        tenant_id=user.tenant_id,
        export_format=format,
        session=session,
    )
    if exported is None:
        log_audit_event(
            request=request,
            user=user,
            action="scan.report.export",
            outcome="denied",
            resource_type="scan",
            resource_id=str(scan_id),
            details={"format": format, "reason": "scan not found"},
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    content, media_type, filename = exported
    if format == "json":
        parsed = json.loads(content)
        response = Response(
            content=json.dumps(parsed, indent=2),
            media_type=media_type,
        )
    else:
        response = Response(content=content, media_type=media_type)
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    log_audit_event(
        request=request,
        user=user,
        action="scan.report.export",
        outcome="success",
        resource_type="scan",
        resource_id=str(scan_id),
        details={"format": format, "filename": filename},
    )
    return response
