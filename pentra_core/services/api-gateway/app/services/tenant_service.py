"""Tenant service — tenant CRUD, member management, quota queries.

Framework-agnostic: accepts plain arguments, returns ORM/dataclass
objects.  No FastAPI Request dependency.
"""

from __future__ import annotations

import logging
import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.tenant import Tenant, TenantQuota
from app.models.user import Role, User, UserRole

logger = logging.getLogger(__name__)


async def get_tenant(
    *, tenant_id: uuid.UUID, session: AsyncSession
) -> Tenant | None:
    """Fetch a tenant by ID (includes joined quota via relationship)."""
    return await session.get(Tenant, tenant_id)


async def update_tenant(
    *, tenant_id: uuid.UUID, name: str | None, session: AsyncSession
) -> Tenant:
    """Update mutable tenant fields."""
    tenant = await session.get(Tenant, tenant_id)
    if tenant is None:
        raise ValueError("Tenant not found")

    if name is not None:
        tenant.name = name

    await session.flush()
    return tenant


async def get_quota(
    *, tenant_id: uuid.UUID, session: AsyncSession
) -> TenantQuota | None:
    """Fetch the quota record for a tenant."""
    stmt = select(TenantQuota).where(TenantQuota.tenant_id == tenant_id)
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def list_members(
    *, tenant_id: uuid.UUID, session: AsyncSession
) -> list[User]:
    """List all users belonging to a tenant."""
    stmt = select(User).where(User.tenant_id == tenant_id).order_by(User.created_at)
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def invite_member(
    *,
    tenant_id: uuid.UUID,
    email: str,
    role_name: str,
    session: AsyncSession,
) -> User:
    """Create a new user record with the given role under the tenant.

    In production, this would also send an invitation email.
    For now, it creates the User + UserRole association.
    """
    # Check the user doesn't already exist in this tenant
    existing = (
        await session.execute(
            select(User).where(User.email == email, User.tenant_id == tenant_id)
        )
    ).scalar_one_or_none()
    if existing:
        raise ValueError(f"User {email} is already a member of this tenant")

    # Resolve role
    role = (
        await session.execute(select(Role).where(Role.name == role_name))
    ).scalar_one_or_none()
    if role is None:
        raise ValueError(f"Unknown role: {role_name}")

    user = User(
        tenant_id=tenant_id,
        email=email,
        full_name=None,
        is_active=True,
    )
    session.add(user)
    await session.flush()

    user_role = UserRole(
        user_id=user.id,
        role_id=role.id,
        tenant_id=tenant_id,
    )
    session.add(user_role)
    await session.flush()

    return user
