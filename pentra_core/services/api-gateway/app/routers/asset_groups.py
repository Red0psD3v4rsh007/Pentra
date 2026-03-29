"""Asset-group router — reusable multi-target scan scopes."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from pentra_common.schemas import (
    AssetGroupCreate,
    AssetGroupUpdate,
    AssetGroupResponse,
    PaginatedResponse,
    ScanBatchCreate,
    MultiAssetScanResponse,
)
from pentra_common.events.stream_publisher import StreamPublisher

from app.deps import CurrentUser, get_current_user, get_db_session, get_stream_publisher, require_roles
from app.observability.audit import log_audit_event
from app.routers.scans import _scan_response
from app.services import asset_group_service, scan_service

router = APIRouter(tags=["asset-groups"])


def _asset_group_response(group) -> AssetGroupResponse:
    return AssetGroupResponse(
        id=group.id,
        tenant_id=group.tenant_id,
        project_id=group.project_id,
        name=group.name,
        description=group.description,
        is_active=group.is_active,
        asset_count=int(getattr(group, "asset_count", 0)),
        asset_ids=list(getattr(group, "asset_ids", [])),
        created_at=group.created_at,
        updated_at=group.updated_at,
    )


def _batch_scan_response(payload: dict[str, object]) -> MultiAssetScanResponse:
    return MultiAssetScanResponse(
        batch_request_id=str(payload["batch_request_id"]),
        asset_group_id=payload.get("asset_group_id"),
        requested_asset_count=int(payload["requested_asset_count"]),
        created_count=int(payload["created_count"]),
        failed_count=int(payload["failed_count"]),
        scans=[_scan_response(scan) for scan in payload["scans"]],  # type: ignore[index]
        failures=payload["failures"],  # type: ignore[arg-type]
    )


@router.post(
    "/projects/{project_id}/asset-groups",
    response_model=AssetGroupResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create an asset group",
)
async def create_asset_group(
    request: Request,
    project_id: uuid.UUID,
    body: AssetGroupCreate,
    user: CurrentUser = Depends(require_roles("owner", "admin", "member")),
    session: AsyncSession = Depends(get_db_session),
) -> AssetGroupResponse:
    try:
        group = await asset_group_service.create_asset_group(
            tenant_id=user.tenant_id,
            project_id=project_id,
            created_by=user.user_id,
            name=body.name,
            description=body.description,
            asset_ids=body.asset_ids,
            session=session,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    log_audit_event(
        request=request,
        user=user,
        action="asset_group.create",
        outcome="success",
        resource_type="asset_group",
        resource_id=str(group.id),
        details={"project_id": str(project_id), "asset_count": int(group.asset_count)},
    )
    return _asset_group_response(group)


@router.get(
    "/projects/{project_id}/asset-groups",
    response_model=PaginatedResponse[AssetGroupResponse],
    summary="List asset groups in a project",
)
async def list_asset_groups(
    project_id: uuid.UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> PaginatedResponse[AssetGroupResponse]:
    groups, total = await asset_group_service.list_asset_groups(
        project_id=project_id,
        tenant_id=user.tenant_id,
        session=session,
        page=page,
        page_size=page_size,
    )
    return PaginatedResponse(
        items=[_asset_group_response(group) for group in groups],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/asset-groups/{asset_group_id}",
    response_model=AssetGroupResponse,
    summary="Get an asset group",
)
async def get_asset_group(
    asset_group_id: uuid.UUID,
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> AssetGroupResponse:
    group = await asset_group_service.get_asset_group(
        asset_group_id=asset_group_id,
        tenant_id=user.tenant_id,
        session=session,
    )
    if group is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset group not found")
    return _asset_group_response(group)


@router.patch(
    "/asset-groups/{asset_group_id}",
    response_model=AssetGroupResponse,
    summary="Update an asset group",
)
async def update_asset_group(
    request: Request,
    asset_group_id: uuid.UUID,
    body: AssetGroupUpdate,
    user: CurrentUser = Depends(require_roles("owner", "admin", "member")),
    session: AsyncSession = Depends(get_db_session),
) -> AssetGroupResponse:
    try:
        group = await asset_group_service.update_asset_group(
            asset_group_id=asset_group_id,
            tenant_id=user.tenant_id,
            name=body.name,
            description=body.description,
            asset_ids=body.asset_ids,
            session=session,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    log_audit_event(
        request=request,
        user=user,
        action="asset_group.update",
        outcome="success",
        resource_type="asset_group",
        resource_id=str(group.id),
        details={"asset_count": int(group.asset_count)},
    )
    return _asset_group_response(group)


@router.delete(
    "/asset-groups/{asset_group_id}",
    response_model=None,
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    summary="Delete an asset group",
)
async def delete_asset_group(
    request: Request,
    asset_group_id: uuid.UUID,
    user: CurrentUser = Depends(require_roles("owner", "admin")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    try:
        await asset_group_service.delete_asset_group(
            asset_group_id=asset_group_id,
            tenant_id=user.tenant_id,
            session=session,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))

    log_audit_event(
        request=request,
        user=user,
        action="asset_group.delete",
        outcome="success",
        resource_type="asset_group",
        resource_id=str(asset_group_id),
    )


@router.post(
    "/asset-groups/{asset_group_id}/scans",
    response_model=MultiAssetScanResponse,
    summary="Create scans for every asset in a group",
)
async def create_asset_group_scans(
    request: Request,
    asset_group_id: uuid.UUID,
    body: ScanBatchCreate,
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
            asset_ids=None,
            asset_group_id=asset_group_id,
            scheduled_at=body.scheduled_at,
            idempotency_key=idempotency_key,
            stream_publisher=publisher,
            session=session,
        )
    except ValueError as exc:
        log_audit_event(
            request=request,
            user=user,
            action="asset_group.scan_batch",
            outcome="denied",
            resource_type="asset_group",
            resource_id=str(asset_group_id),
            details={"reason": str(exc)},
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    log_audit_event(
        request=request,
        user=user,
        action="asset_group.scan_batch",
        outcome="success",
        resource_type="asset_group",
        resource_id=str(asset_group_id),
        details={
            "requested_asset_count": int(payload["requested_asset_count"]),
            "created_count": int(payload["created_count"]),
            "failed_count": int(payload["failed_count"]),
        },
    )
    return _batch_scan_response(payload)
