"""Asset router — CRUD endpoints for project-scoped assets.

Creation is nested under ``/api/v1/projects/{project_id}/assets``.
Direct access is at ``/api/v1/assets/{asset_id}``.
"""

from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from pentra_common.schemas import AssetCreate, AssetResponse, AssetUpdate, PaginatedResponse

from app.deps import CurrentUser, get_current_user, get_db_session, require_roles
from app.observability.audit import log_audit_event
from app.services import asset_service, project_service

logger = logging.getLogger(__name__)

router = APIRouter(tags=["assets"])


# ── Nested under project ────────────────────────────────────────────


@router.post(
    "/projects/{project_id}/assets",
    response_model=AssetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create an asset under a project",
)
async def create_asset(
    request: Request,
    project_id: uuid.UUID,
    body: AssetCreate,
    user: CurrentUser = Depends(require_roles("owner", "admin", "member")),
    session: AsyncSession = Depends(get_db_session),
) -> AssetResponse:
    """Create a new scan target (asset) under the given project."""
    # Verify project exists and belongs to the tenant
    project = await project_service.get_project(
        project_id=project_id,
        tenant_id=user.tenant_id,
        session=session,
    )
    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Project not found"
        )

    asset = await asset_service.create_asset(
        tenant_id=user.tenant_id,
        project_id=project_id,
        created_by=user.user_id,
        name=body.name,
        asset_type=body.asset_type.value,
        target=body.target,
        description=body.description,
        tags=body.tags,
        session=session,
    )
    log_audit_event(
        request=request,
        user=user,
        action="asset.create",
        outcome="success",
        resource_type="asset",
        resource_id=str(asset.id),
        details={"project_id": str(project_id), "target": asset.target},
    )
    return _to_response(asset)


@router.get(
    "/projects/{project_id}/assets",
    response_model=PaginatedResponse[AssetResponse],
    summary="List assets in a project",
)
async def list_assets(
    project_id: uuid.UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> PaginatedResponse[AssetResponse]:
    """List assets for a project (paginated)."""
    items, total = await asset_service.list_assets(
        project_id=project_id,
        tenant_id=user.tenant_id,
        session=session,
        page=page,
        page_size=page_size,
    )
    return PaginatedResponse(
        items=[_to_response(a) for a in items],
        total=total,
        page=page,
        page_size=page_size,
    )


# ── Direct access ───────────────────────────────────────────────────


@router.get(
    "/assets/{asset_id}",
    response_model=AssetResponse,
    summary="Get an asset",
)
async def get_asset(
    asset_id: uuid.UUID,
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> AssetResponse:
    """Get a single asset by ID."""
    asset = await asset_service.get_asset(
        asset_id=asset_id,
        tenant_id=user.tenant_id,
        session=session,
    )
    if asset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found"
        )
    return _to_response(asset)


@router.patch(
    "/assets/{asset_id}",
    response_model=AssetResponse,
    summary="Update an asset",
)
async def update_asset(
    request: Request,
    asset_id: uuid.UUID,
    body: AssetUpdate,
    user: CurrentUser = Depends(require_roles("owner", "admin", "member")),
    session: AsyncSession = Depends(get_db_session),
) -> AssetResponse:
    """Update mutable fields of an asset (name, description, tags)."""
    try:
        asset = await asset_service.update_asset(
            asset_id=asset_id,
            tenant_id=user.tenant_id,
            name=body.name,
            description=body.description,
            tags=body.tags,
            session=session,
        )
    except ValueError as exc:
        log_audit_event(
            request=request,
            user=user,
            action="asset.update",
            outcome="denied",
            resource_type="asset",
            resource_id=str(asset_id),
            details={"reason": str(exc)},
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        )
    log_audit_event(
        request=request,
        user=user,
        action="asset.update",
        outcome="success",
        resource_type="asset",
        resource_id=str(asset.id),
        details={"target": asset.target},
    )
    return _to_response(asset)


@router.delete(
    "/assets/{asset_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete an asset",
)
async def delete_asset(
    request: Request,
    asset_id: uuid.UUID,
    user: CurrentUser = Depends(require_roles("owner", "admin")),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    """Soft-delete an asset."""
    try:
        await asset_service.delete_asset(
            asset_id=asset_id,
            tenant_id=user.tenant_id,
            session=session,
        )
    except ValueError as exc:
        log_audit_event(
            request=request,
            user=user,
            action="asset.delete",
            outcome="denied",
            resource_type="asset",
            resource_id=str(asset_id),
            details={"reason": str(exc)},
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        )
    log_audit_event(
        request=request,
        user=user,
        action="asset.delete",
        outcome="success",
        resource_type="asset",
        resource_id=str(asset_id),
    )


# ── Response helpers ─────────────────────────────────────────────────


def _to_response(asset) -> AssetResponse:
    """Convert an Asset ORM object to an AssetResponse.

    Flattens ``AssetTag`` relationships into a ``{key: value}`` dict.
    """
    tags = {tag.key: tag.value for tag in (asset.tags or [])}
    return AssetResponse(
        id=asset.id,
        tenant_id=asset.tenant_id,
        project_id=asset.project_id,
        name=asset.name,
        asset_type=asset.asset_type,
        target=asset.target,
        description=asset.description,
        is_verified=asset.is_verified,
        is_active=asset.is_active,
        tags=tags,
        created_at=asset.created_at,
        updated_at=asset.updated_at,
    )
