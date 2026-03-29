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
    AgentTranscriptResponse,
    ScanAIReasoningResponse,
    ArtifactSummaryResponse,
    AttackGraphResponse,
    EvidenceReferenceResponse,
    FieldValidationAssessmentResponse,
    FieldValidationSummaryResponse,
    FindingResponse,
    JobSessionResponse,
    MultiAssetScanCreate,
    MultiAssetScanResponse,
    PaginatedResponse,
    ScanIssueExportRequest,
    ScanIssueExportResponse,
    ScanCreate,
    ScanComparisonResponse,
    ScanReportNotificationRequest,
    ScanReportNotificationResponse,
    ScanRetestCreate,
    ScanReportResponse,
    ScanResponse,
    ScanJobResponse,
    ScanPlannerContextResponse,
    ScanTargetModelResponse,
    ScanTimelineEventResponse,
    ToolApprovalRequest,
    ToolApprovalResponse,
    ToolExecutionLogContentResponse,
    ToolExecutionLogResponse,
)

from app.deps import CurrentUser, get_current_user, get_db_session, get_stream_publisher, require_roles
from app.observability.audit import log_audit_event
from app.security.redaction import redact_secrets
from app.services import ai_reasoning_service, scan_service, target_model_service

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
            scheduled_at=body.scheduled_at,
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


@router.post(
    "/batch",
    response_model=MultiAssetScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create scans for multiple assets",
)
async def create_multi_asset_scans(
    request: Request,
    body: MultiAssetScanCreate,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    user: CurrentUser = Depends(require_roles("owner", "admin", "member")),
    session: AsyncSession = Depends(get_db_session),
    publisher: StreamPublisher = Depends(get_stream_publisher),
) -> MultiAssetScanResponse:
    try:
        payload = await scan_service.create_multi_asset_scan_batch(
            tenant_id=user.tenant_id,
            created_by=user.user_id,
            scan_type=body.scan_type.value,
            priority=body.priority.value,
            config=body.config,
            asset_ids=body.asset_ids,
            asset_group_id=body.asset_group_id,
            scheduled_at=body.scheduled_at,
            idempotency_key=idempotency_key,
            stream_publisher=publisher,
            session=session,
        )
    except ValueError as exc:
        log_audit_event(
            request=request,
            user=user,
            action="scan.batch_create",
            outcome="denied",
            resource_type="scan_batch",
            details={
                "asset_group_id": str(body.asset_group_id) if body.asset_group_id else None,
                "asset_count": len(body.asset_ids or []),
                "reason": str(exc),
            },
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except (ConnectionError, RuntimeError, OSError) as exc:
        log_audit_event(
            request=request,
            user=user,
            action="scan.batch_create",
            outcome="error",
            resource_type="scan_batch",
            details={"reason": str(exc)},
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Backend service unavailable — check that Redis and the orchestrator are running",
        )

    log_audit_event(
        request=request,
        user=user,
        action="scan.batch_create",
        outcome="success",
        resource_type="scan_batch",
        details={
            "asset_group_id": str(payload["asset_group_id"]) if payload["asset_group_id"] else None,
            "requested_asset_count": int(payload["requested_asset_count"]),
            "created_count": int(payload["created_count"]),
            "failed_count": int(payload["failed_count"]),
        },
    )
    return MultiAssetScanResponse(
        batch_request_id=str(payload["batch_request_id"]),
        asset_group_id=payload.get("asset_group_id"),
        requested_asset_count=int(payload["requested_asset_count"]),
        created_count=int(payload["created_count"]),
        failed_count=int(payload["failed_count"]),
        scans=[_scan_response(scan) for scan in payload["scans"]],
        failures=payload["failures"],
    )


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
    "/ai/providers/diagnostics",
    summary="Inspect AI provider routing and live diagnostics",
)
async def get_ai_provider_diagnostics(
    live: bool = Query(False, description="Run live provider probes"),
    user: CurrentUser = Depends(require_roles("owner", "admin", "member")),
) -> dict[str, object]:
    _ = user
    return await ai_reasoning_service.get_ai_provider_diagnostics(live=live)


@router.get(
    "/field-validation/summary",
    response_model=FieldValidationSummaryResponse,
    summary="Get aggregated field-validation readiness separate from benchmark matrices",
)
async def get_field_validation_summary(
    limit: int = Query(10, ge=1, le=50),
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> FieldValidationSummaryResponse:
    summary = await scan_service.get_field_validation_summary(
        tenant_id=user.tenant_id,
        session=session,
        limit=limit,
    )
    return FieldValidationSummaryResponse.model_validate(summary)


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
    "/{scan_id}/jobs/{job_id}/session",
    response_model=JobSessionResponse,
    summary="Get the replayable command session for one scan job",
)
async def get_scan_job_session(
    scan_id: uuid.UUID,
    job_id: uuid.UUID,
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> JobSessionResponse:
    payload = await scan_service.get_scan_job_session(
        scan_id=scan_id,
        job_id=job_id,
        tenant_id=user.tenant_id,
        session=session,
    )
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Job session not found",
        )
    return JobSessionResponse.model_validate(payload)


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

    Persists the status change and emits durable cancellation events so
    the orchestrator and workers stop dispatching or executing scan work.
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
    "/{scan_id}/pause",
    response_model=ScanResponse,
    summary="Pause a running scan",
)
async def pause_scan(
    request: Request,
    scan_id: uuid.UUID,
    user: CurrentUser = Depends(require_roles("owner", "admin", "member")),
    session: AsyncSession = Depends(get_db_session),
    publisher: StreamPublisher = Depends(get_stream_publisher),
) -> ScanResponse:
    try:
        scan = await scan_service.pause_scan(
            scan_id=scan_id,
            tenant_id=user.tenant_id,
            stream_publisher=publisher,
            session=session,
        )
    except ValueError as exc:
        log_audit_event(
            request=request,
            user=user,
            action="scan.pause",
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
        action="scan.pause",
        outcome="success",
        resource_type="scan",
        resource_id=str(scan.id),
    )
    return _scan_response(scan)


@router.post(
    "/{scan_id}/resume",
    response_model=ScanResponse,
    summary="Resume a paused scan",
)
async def resume_scan(
    request: Request,
    scan_id: uuid.UUID,
    user: CurrentUser = Depends(require_roles("owner", "admin", "member")),
    session: AsyncSession = Depends(get_db_session),
    publisher: StreamPublisher = Depends(get_stream_publisher),
) -> ScanResponse:
    try:
        scan = await scan_service.resume_scan(
            scan_id=scan_id,
            tenant_id=user.tenant_id,
            resumed_by=user.user_id,
            stream_publisher=publisher,
            session=session,
        )
    except ValueError as exc:
        log_audit_event(
            request=request,
            user=user,
            action="scan.resume",
            outcome="denied",
            resource_type="scan",
            resource_id=str(scan_id),
            details={"reason": str(exc)},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )
    except RuntimeError as exc:
        log_audit_event(
            request=request,
            user=user,
            action="scan.resume",
            outcome="error",
            resource_type="scan",
            resource_id=str(scan_id),
            details={"reason": str(exc)},
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        )
    log_audit_event(
        request=request,
        user=user,
        action="scan.resume",
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
    "/{scan_id}/target-model",
    response_model=ScanTargetModelResponse,
    summary="Get the normalized target model for a scan",
)
async def get_scan_target_model(
    scan_id: uuid.UUID,
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> ScanTargetModelResponse:
    target_model = await target_model_service.get_scan_target_model(
        scan_id=scan_id,
        tenant_id=user.tenant_id,
        session=session,
    )
    if target_model is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target model not found",
    )
    return ScanTargetModelResponse.model_validate(target_model)


@router.get(
    "/{scan_id}/field-validation",
    response_model=FieldValidationAssessmentResponse,
    summary="Get field-validation assessment for a scan",
)
async def get_scan_field_validation_assessment(
    scan_id: uuid.UUID,
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> FieldValidationAssessmentResponse:
    assessment = await scan_service.get_scan_field_validation_assessment(
        scan_id=scan_id,
        tenant_id=user.tenant_id,
        session=session,
    )
    if assessment is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Field-validation assessment not found",
    )
    return FieldValidationAssessmentResponse.model_validate(assessment)


@router.post(
    "/{scan_id}/tool-approvals",
    response_model=ToolApprovalResponse,
    summary="Approve one or more approval-gated tools for an in-flight scan",
)
async def approve_scan_tools(
    request: Request,
    scan_id: uuid.UUID,
    body: ToolApprovalRequest,
    user: CurrentUser = Depends(require_roles("owner", "admin", "member")),
    session: AsyncSession = Depends(get_db_session),
    publisher: StreamPublisher = Depends(get_stream_publisher),
) -> ToolApprovalResponse:
    try:
        payload = await scan_service.approve_scan_tools(
            scan_id=scan_id,
            tenant_id=user.tenant_id,
            tools=body.tools,
            session=session,
            stream_publisher=publisher,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    log_audit_event(
        request=request,
        user=user,
        action="scan.tool_approve",
        outcome="success",
        resource_type="scan",
        resource_id=str(scan_id),
        details={"tools": body.tools},
    )
    return ToolApprovalResponse.model_validate(payload)


@router.get(
    "/{scan_id}/planner-context",
    response_model=ScanPlannerContextResponse,
    summary="Get persisted planner context for a scan",
)
async def get_scan_planner_context(
    scan_id: uuid.UUID,
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> ScanPlannerContextResponse:
    planner_context = await scan_service.get_scan_planner_context(
        scan_id=scan_id,
        tenant_id=user.tenant_id,
        session=session,
    )
    if planner_context is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Planner context not found",
        )
    return ScanPlannerContextResponse.model_validate(planner_context)


@router.get(
    "/{scan_id}/agent-transcript",
    response_model=AgentTranscriptResponse,
    summary="Get the persisted Pentra Agent transcript for a scan",
)
async def get_scan_agent_transcript(
    scan_id: uuid.UUID,
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> AgentTranscriptResponse:
    transcript = await scan_service.get_scan_agent_transcript(
        scan_id=scan_id,
        tenant_id=user.tenant_id,
        session=session,
    )
    if transcript is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent transcript not found",
        )
    return AgentTranscriptResponse.model_validate(transcript)


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
    summary="Export a scan report as markdown, json, csv, or html",
)
async def export_scan_report(
    request: Request,
    scan_id: uuid.UUID,
    format: str = Query(
        "markdown",
        pattern="^(markdown|json|csv|html)$",
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


@router.post(
    "/{scan_id}/report/notify",
    response_model=ScanReportNotificationResponse,
    summary="Deliver a scan report summary to a webhook destination",
)
async def notify_scan_report(
    request: Request,
    scan_id: uuid.UUID,
    body: ScanReportNotificationRequest,
    user: CurrentUser = Depends(require_roles("owner", "admin", "member")),
    session: AsyncSession = Depends(get_db_session),
) -> ScanReportNotificationResponse:
    try:
        delivered = await scan_service.deliver_scan_report_notification(
            scan_id=scan_id,
            tenant_id=user.tenant_id,
            channel=body.channel,
            destination_url=str(body.destination_url),
            top_findings_limit=body.top_findings_limit,
            include_markdown=body.include_markdown,
            include_html=body.include_html,
            custom_headers=body.custom_headers,
            authorization_header=body.authorization_header,
            session=session,
        )
    except RuntimeError as exc:
        log_audit_event(
            request=request,
            user=user,
            action="scan.report.notify",
            outcome="error",
            resource_type="scan",
            resource_id=str(scan_id),
            details={
                "channel": body.channel,
                "destination_host": body.destination_url.host,
                "reason": str(exc),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(exc),
        )

    if delivered is None:
        log_audit_event(
            request=request,
            user=user,
            action="scan.report.notify",
            outcome="denied",
            resource_type="scan",
            resource_id=str(scan_id),
            details={
                "channel": body.channel,
                "destination_host": body.destination_url.host,
                "reason": "scan not found",
            },
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    log_audit_event(
        request=request,
        user=user,
        action="scan.report.notify",
        outcome="success",
        resource_type="scan",
        resource_id=str(scan_id),
        details={
            "channel": body.channel,
            "destination_host": delivered["destination_host"],
            "status_code": delivered["status_code"],
        },
    )
    return ScanReportNotificationResponse.model_validate(delivered)


@router.post(
    "/{scan_id}/issues/export",
    response_model=ScanIssueExportResponse,
    summary="Preview or deliver provider-shaped issue payloads for a scan",
)
async def export_scan_issues(
    request: Request,
    scan_id: uuid.UUID,
    body: ScanIssueExportRequest,
    user: CurrentUser = Depends(require_roles("owner", "admin", "member")),
    session: AsyncSession = Depends(get_db_session),
) -> ScanIssueExportResponse:
    try:
        exported = await scan_service.export_scan_issues(
            scan_id=scan_id,
            tenant_id=user.tenant_id,
            provider=body.provider,
            mode=body.mode,
            minimum_severity=body.minimum_severity,
            verified_only=body.verified_only,
            max_issues=body.max_issues,
            destination_url=str(body.destination_url) if body.destination_url else None,
            base_url=str(body.base_url) if body.base_url else None,
            repository=body.repository,
            project_key=body.project_key,
            custom_headers=body.custom_headers,
            authorization_header=body.authorization_header,
            session=session,
        )
    except RuntimeError as exc:
        log_audit_event(
            request=request,
            user=user,
            action="scan.issues.export",
            outcome="error",
            resource_type="scan",
            resource_id=str(scan_id),
            details={
                "provider": body.provider,
                "mode": body.mode,
                "reason": str(exc),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(exc),
        )

    if exported is None:
        log_audit_event(
            request=request,
            user=user,
            action="scan.issues.export",
            outcome="denied",
            resource_type="scan",
            resource_id=str(scan_id),
            details={
                "provider": body.provider,
                "mode": body.mode,
                "reason": "scan not found",
            },
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    log_audit_event(
        request=request,
        user=user,
        action="scan.issues.export",
        outcome="success",
        resource_type="scan",
        resource_id=str(scan_id),
        details={
            "provider": body.provider,
            "mode": body.mode,
            "selected_count": exported["selected_count"],
            "delivered_count": exported["delivered_count"],
            "destination_host": exported.get("destination_host"),
        },
    )
    return ScanIssueExportResponse.model_validate(exported)


@router.post(
    "/{scan_id}/rerun-tool",
    summary="Re-run a tool command with optional modifications",
    status_code=status.HTTP_200_OK,
)
async def rerun_tool(
    request: Request,
    scan_id: uuid.UUID,
    body: dict,
    user: CurrentUser = Depends(require_roles("owner", "admin", "member")),
    session: AsyncSession = Depends(get_db_session),
) -> dict:
    """Re-run a tool command against the scan target.

    This endpoint currently validates ownership and input shape only.
    The actual orchestration path for ad-hoc tool re-execution is not
    wired yet, so the API must fail closed instead of claiming work was
    queued when nothing will run.
    """
    command = body.get("command", [])
    tool_id = body.get("tool_id", "unknown")

    if not command or not isinstance(command, list):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="command must be a non-empty list of strings",
        )

    # Verify the scan exists and belongs to tenant
    scan = await scan_service.get_scan(
        scan_id=scan_id,
        tenant_id=user.tenant_id,
        session=session,
    )
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    log_audit_event(
        request=request,
        user=user,
        action="scan.rerun_tool",
        outcome="denied",
        resource_type="scan",
        resource_id=str(scan_id),
        details={
            "tool_id": tool_id,
            "argument_count": len(command),
            "reason": "not_implemented",
        },
    )
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=(
            "Tool re-execution is not wired to orchestration yet. "
            "Use the Terminal tab for manual commands until this endpoint is implemented."
        ),
    )


# ── Phase 5: AI Intelligence Endpoints ──────────────────────────────

@router.get(
    "/{scan_id}/exploitation-paths",
    summary="AI-suggested exploitation chains",
    status_code=status.HTTP_200_OK,
)
async def get_exploitation_paths(
    request: Request,
    scan_id: uuid.UUID,
    user: CurrentUser = Depends(require_roles("owner", "admin", "member")),
    session: AsyncSession = Depends(get_db_session),
) -> dict:
    """Analyze findings and suggest multi-step exploitation chains.

    Returns attack chains with MITRE ATT&CK mapping, lateral movement
    opportunities, and cross-finding patterns.
    """
    result = await ai_reasoning_service.suggest_exploitation_paths(
        scan_id=scan_id,
        tenant_id=user.tenant_id,
        user_id=user.user_id,
        session=session,
    )
    if result.get("error"):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=result["error"],
        )
    return result


@router.get(
    "/{scan_id}/vector-priorities",
    summary="AI-prioritized attack vectors",
    status_code=status.HTTP_200_OK,
)
async def get_vector_priorities(
    request: Request,
    scan_id: uuid.UUID,
    vectors: str | None = Query(default=None, description="Comma-separated vector IDs to consider"),
    user: CurrentUser = Depends(require_roles("owner", "admin", "member")),
    session: AsyncSession = Depends(get_db_session),
) -> dict:
    """Rank attack vectors by likelihood and impact for this target.

    Optionally filter to a subset of vectors via the ``vectors`` query param.
    """
    available_vectors = [v.strip() for v in vectors.split(",")] if vectors else None
    result = await ai_reasoning_service.prioritize_attack_vectors(
        scan_id=scan_id,
        tenant_id=user.tenant_id,
        user_id=user.user_id,
        session=session,
        available_vectors=available_vectors,
    )
    if result.get("error"):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=result["error"],
        )
    return result


@router.get(
    "/{scan_id}/remediation-report",
    summary="AI-generated remediation recommendations",
    status_code=status.HTTP_200_OK,
)
async def get_remediation_report(
    request: Request,
    scan_id: uuid.UUID,
    user: CurrentUser = Depends(require_roles("owner", "admin", "member")),
    session: AsyncSession = Depends(get_db_session),
) -> dict:
    """Generate actionable remediation recommendations for scan findings.

    Returns grouped fix instructions with effort estimates, compliance
    mapping, and priority ordering.
    """
    result = await ai_reasoning_service.generate_remediation_report(
        scan_id=scan_id,
        tenant_id=user.tenant_id,
        user_id=user.user_id,
        session=session,
    )
    if result.get("error"):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=result["error"],
        )
    return result


# ── Tool Execution Logs ──────────────────────────────────────────────

@router.get(
    "/{scan_id}/tool-logs",
    response_model=ToolExecutionLogResponse,
    summary="Get tool execution logs for a scan",
)
async def get_tool_logs(
    scan_id: uuid.UUID,
    user: CurrentUser = Depends(require_roles("owner", "admin", "member")),
    session: AsyncSession = Depends(get_db_session),
) -> ToolExecutionLogResponse:
    """Return tool execution logs for a scan.

    Shows the exact commands executed, their stdout/stderr output,
    duration, exit codes, and execution provenance (live/simulated/blocked).
    """
    logs = await scan_service.get_scan_tool_logs(
        scan_id=scan_id,
        tenant_id=user.tenant_id,
        session=session,
    )
    if logs is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tool logs not found",
        )
    return ToolExecutionLogResponse.model_validate(logs)


@router.get(
    "/{scan_id}/tool-logs/content",
    response_model=ToolExecutionLogContentResponse,
    summary="Read full tool execution log content for one stored command artifact",
)
async def get_tool_log_content(
    scan_id: uuid.UUID,
    storage_ref: str = Query(..., description="Stored stdout/stderr/command artifact reference"),
    user: CurrentUser = Depends(require_roles("owner", "admin", "member")),
    session: AsyncSession = Depends(get_db_session),
) -> ToolExecutionLogContentResponse:
    payload = await scan_service.get_scan_tool_log_content(
        scan_id=scan_id,
        tenant_id=user.tenant_id,
        storage_ref=storage_ref,
        session=session,
    )
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tool log content not found",
        )
    return ToolExecutionLogContentResponse.model_validate(payload)


@router.get(
    "/{scan_id}/strategy-log",
    summary="Get AI strategy recommendations for a scan",
)
async def get_strategy_log(
    scan_id: uuid.UUID,
    user: CurrentUser = Depends(require_roles("owner", "admin", "member")),
    session: AsyncSession = Depends(get_db_session),
) -> dict:
    """Return AI strategy advisor decisions made during the scan.

    Shows what the AI recommended at each phase transition, including
    recommended tools, attack vectors, and phase-skip decisions.
    """
    from sqlalchemy import text as sa_text

    await session.execute(
        sa_text(f"SET LOCAL app.tenant_id = '{user.tenant_id}'")
    )

    # Check for strategy artifacts stored during execution
    result = await session.execute(
        sa_text("""
            SELECT
                a.id,
                a.artifact_type,
                a.storage_ref,
                a.metadata,
                a.created_at
            FROM scan_artifacts a
            WHERE a.scan_id = :scan_id
              AND a.artifact_type IN ('ai_strategy', 'ai_reasoning', 'findings_scored', 'planner_effect')
            ORDER BY a.created_at ASC
        """),
        {"scan_id": str(scan_id)},
    )

    strategy_entries = []
    for row in result.mappings().all():
        metadata = row.get("metadata") or {}
        if not isinstance(metadata, dict):
            metadata = {}

        strategy_entries.append({
            "id": str(row["id"]),
            "type": row["artifact_type"],
            "storage_ref": row.get("storage_ref"),
            "created_at": str(row.get("created_at") or ""),
            "summary": metadata.get("summary", {}),
        })

    return {
        "scan_id": str(scan_id),
        "total": len(strategy_entries),
        "entries": strategy_entries,
    }
