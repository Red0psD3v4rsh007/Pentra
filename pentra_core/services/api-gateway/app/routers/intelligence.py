"""Intelligence router — tenant-wide and per-asset intelligence views."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from pentra_common.schemas import AssetHistoryResponse, IntelligenceSummaryResponse

from app.deps import CurrentUser, get_current_user, get_db_session
from app.services import intelligence_service

router = APIRouter(tags=["intelligence"])


@router.get(
    "/summary",
    response_model=IntelligenceSummaryResponse,
    summary="Get the tenant intelligence summary",
)
async def get_intelligence_summary(
    scan_limit: int = Query(default=100, ge=1, le=250),
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> IntelligenceSummaryResponse:
    payload = await intelligence_service.get_intelligence_summary(
        tenant_id=user.tenant_id,
        session=session,
        scan_limit=scan_limit,
    )
    return IntelligenceSummaryResponse.model_validate(payload)


@router.get(
    "/assets/{asset_id}/history",
    response_model=AssetHistoryResponse,
    summary="Get cross-scan history and trend data for one asset",
)
async def get_asset_history(
    asset_id: UUID,
    limit: int = Query(default=20, ge=1, le=100),
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> AssetHistoryResponse:
    payload = await intelligence_service.get_asset_history(
        asset_id=asset_id,
        tenant_id=user.tenant_id,
        session=session,
        limit=limit,
    )
    if payload is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return AssetHistoryResponse.model_validate(payload)
