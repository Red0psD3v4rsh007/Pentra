"""Scan profile router — truthful launch contracts for supported scan profiles."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from pentra_common.profiles import list_scan_profile_contracts, preflight_scan_profile_contract
from pentra_common.schemas import (
    ScanProfileContractResponse,
    ScanProfilePreflightRequest,
    ScanProfilePreflightResponse,
)

from app.deps import CurrentUser, get_current_user
from app.services import ai_reasoning_service

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


@router.post(
    "/preflight",
    response_model=ScanProfilePreflightResponse,
    summary="Run frontend-visible launch preflight for a scan profile contract",
)
async def preflight_scan_profile(
    body: ScanProfilePreflightRequest,
    _: CurrentUser = Depends(get_current_user),
) -> ScanProfilePreflightResponse:
    diagnostics = await ai_reasoning_service.get_ai_provider_diagnostics(live=False)
    readiness = ai_reasoning_service.summarize_ai_provider_diagnostics(diagnostics)
    try:
        payload = preflight_scan_profile_contract(
            asset_type=body.asset_type,
            target=body.target,
            contract_id=body.contract_id,
            scan_mode=body.scan_mode,
            methodology=body.methodology,
            authorization_acknowledged=body.authorization_acknowledged,
            approved_live_tools=body.approved_live_tools,
            credentials=body.credentials,
            repository=body.repository,
            scope=body.scope,
            ai_provider_readiness={
                **readiness,
                "provider_priority": diagnostics.get("provider_priority", []),
                "enabled": diagnostics.get("enabled", False),
            },
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return ScanProfilePreflightResponse.model_validate(payload)
