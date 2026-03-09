"""Scan router — scan lifecycle endpoints.

Mounted at ``/api/v1/scans``.

Events are published to Redis Streams (XADD) for durable delivery
to the MOD-04 orchestrator service.
"""

from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from pentra_common.events.stream_publisher import StreamPublisher
from pentra_common.schemas import (
    FindingResponse,
    PaginatedResponse,
    ScanCreate,
    ScanResponse,
    ScanJobResponse,
)

from app.deps import CurrentUser, get_current_user, get_db_session, get_stream_publisher
from app.services import scan_service

logger = logging.getLogger(__name__)

router = APIRouter(tags=["scans"])


@router.post(
    "",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a scan",
)
async def create_scan(
    body: ScanCreate,
    user: CurrentUser = Depends(get_current_user),
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
            stream_publisher=publisher,
            session=session,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        )
    return ScanResponse.model_validate(scan)


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
        session=session,
        status_filter=status_filter,
        asset_id=asset_id,
        page=page,
        page_size=page_size,
    )
    return PaginatedResponse(
        items=[ScanResponse.model_validate(s) for s in items],
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
    scan = await scan_service.get_scan(scan_id=scan_id, session=session)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found"
        )
    return ScanResponse.model_validate(scan)


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
    from sqlalchemy import select as sa_select
    from sqlalchemy.orm import selectinload
    from app.models.scan import Scan as ScanModel

    stmt = (
        sa_select(ScanModel)
        .where(ScanModel.id == scan_id)
        .options(selectinload(ScanModel.jobs))
    )
    result = await session.execute(stmt)
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found"
        )
    return [ScanJobResponse.model_validate(j) for j in scan.jobs]


@router.post(
    "/{scan_id}/cancel",
    response_model=ScanResponse,
    summary="Cancel a scan",
)
async def cancel_scan(
    scan_id: uuid.UUID,
    user: CurrentUser = Depends(get_current_user),
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
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        )
    return ScanResponse.model_validate(scan)


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
        scan_id=scan_id, session=session, page=page, page_size=page_size
    )
    return PaginatedResponse(
        items=[FindingResponse.model_validate(f) for f in items],
        total=total,
        page=page,
        page_size=page_size,
    )
