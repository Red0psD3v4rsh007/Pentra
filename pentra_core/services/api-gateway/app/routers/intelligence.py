"""Intelligence router — tenant-wide cross-scan intelligence summaries."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from pentra_common.schemas import IntelligenceSummaryResponse

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
