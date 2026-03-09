"""Tenant router — current-tenant introspection and member management.

All endpoints are scoped to the caller's tenant (extracted from JWT).
Mounted at ``/api/v1/tenants``.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from pentra_common.schemas import (
    TenantQuotaResponse,
    TenantResponse,
    TenantUpdate,
    UserInvite,
    UserResponse,
)

from app.deps import CurrentUser, get_current_user, get_db_session, require_roles
from app.services import tenant_service

logger = logging.getLogger(__name__)

router = APIRouter(tags=["tenants"])


@router.get(
    "/me",
    response_model=TenantResponse,
    summary="Get current tenant",
)
async def get_my_tenant(
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> TenantResponse:
    """Return details of the authenticated user's tenant."""
    tenant = await tenant_service.get_tenant(
        tenant_id=user.tenant_id, session=session
    )
    if tenant is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found",
        )
    return TenantResponse.model_validate(tenant)


@router.get(
    "/me/quota",
    response_model=TenantQuotaResponse,
    summary="Get tenant quota and usage",
)
async def get_my_quota(
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> TenantQuotaResponse:
    """Return quota limits and current usage for the authenticated tenant."""
    quota = await tenant_service.get_quota(
        tenant_id=user.tenant_id, session=session
    )
    if quota is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Quota record not found for tenant",
        )
    return TenantQuotaResponse.model_validate(quota)


@router.patch(
    "/me",
    response_model=TenantResponse,
    summary="Update tenant name",
)
async def update_my_tenant(
    body: TenantUpdate,
    user: CurrentUser = Depends(require_roles("owner", "admin")),
    session: AsyncSession = Depends(get_db_session),
) -> TenantResponse:
    """Update mutable fields of the caller's tenant (owner/admin only)."""
    try:
        tenant = await tenant_service.update_tenant(
            tenant_id=user.tenant_id, name=body.name, session=session
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        )
    return TenantResponse.model_validate(tenant)


@router.get(
    "/me/members",
    response_model=list[UserResponse],
    summary="List tenant members",
)
async def list_members(
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> list[UserResponse]:
    """List all users belonging to the current tenant."""
    members = await tenant_service.list_members(
        tenant_id=user.tenant_id, session=session
    )
    return [UserResponse.model_validate(m) for m in members]


@router.post(
    "/me/members/invite",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Invite a member to the tenant",
)
async def invite_member(
    body: UserInvite,
    user: CurrentUser = Depends(require_roles("owner", "admin")),
    session: AsyncSession = Depends(get_db_session),
) -> UserResponse:
    """Invite a new member to the tenant (owner/admin only).

    Creates a user record with the specified role.  Email invitation
    delivery is deferred to the ``notify-svc`` (MOD-04+).
    """
    try:
        new_user = await tenant_service.invite_member(
            tenant_id=user.tenant_id,
            email=body.email,
            role_name=body.role,
            session=session,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(exc)
        )
    return UserResponse.model_validate(new_user)
