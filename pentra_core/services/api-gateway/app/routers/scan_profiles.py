"""Scan profile router — truthful launch contracts for supported scan profiles."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from pentra_common.profiles import list_scan_profile_contracts
from pentra_common.schemas import ScanProfileContractResponse

from app.deps import CurrentUser, get_current_user

router = APIRouter(tags=["scan_profiles"])


@router.get(
    "",
    response_model=list[ScanProfileContractResponse],
    summary="List truthful scan profile contracts for an asset target",
)
async def list_scan_profiles(
    asset_type: str = Query(..., description="Asset type such as web_app or api"),
    target: str = Query(..., description="Target URL or hostname"),
    _: CurrentUser = Depends(get_current_user),
) -> list[ScanProfileContractResponse]:
    contracts = list_scan_profile_contracts(asset_type=asset_type, target=target)
    return [ScanProfileContractResponse.model_validate(item) for item in contracts]
