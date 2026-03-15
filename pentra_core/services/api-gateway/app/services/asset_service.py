"""Asset service — CRUD operations for tenant-scoped assets.

Framework-agnostic: accepts plain arguments, returns ORM objects.
No FastAPI Request dependency.
"""

from __future__ import annotations

import logging
import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset, AssetTag

logger = logging.getLogger(__name__)


async def create_asset(
    *,
    tenant_id: uuid.UUID,
    project_id: uuid.UUID,
    created_by: uuid.UUID,
    name: str,
    asset_type: str,
    target: str,
    description: str | None,
    tags: dict[str, str] | None,
    session: AsyncSession,
) -> Asset:
    """Create a new asset under the given project."""
    asset = Asset(
        tenant_id=tenant_id,
        project_id=project_id,
        created_by=created_by,
        name=name,
        asset_type=asset_type,
        target=target,
        description=description,
    )
    session.add(asset)
    await session.flush()

    # Create tags if provided
    if tags:
        for key, value in tags.items():
            tag = AssetTag(asset_id=asset.id, key=key, value=value)
            session.add(tag)
        await session.flush()

    await session.refresh(asset, attribute_names=["tags"])
    return asset


async def list_assets(
    *,
    project_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
    page: int = 1,
    page_size: int = 20,
) -> tuple[list[Asset], int]:
    """List assets for a project (tenant-scoped via RLS).

    Returns ``(items, total_count)``.
    """
    base_filter = (
        (Asset.project_id == project_id)
        & (Asset.tenant_id == tenant_id)
        & (Asset.is_active == True)  # noqa: E712
    )

    count_stmt = select(func.count()).select_from(Asset).where(base_filter)
    total = (await session.execute(count_stmt)).scalar_one()

    offset = (page - 1) * page_size
    stmt = (
        select(Asset)
        .where(base_filter)
        .order_by(Asset.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    result = await session.execute(stmt)
    return list(result.unique().scalars().all()), total


async def get_asset(
    *, asset_id: uuid.UUID, tenant_id: uuid.UUID, session: AsyncSession
) -> Asset | None:
    """Fetch a single asset by ID (RLS enforces tenant scope)."""
    stmt = select(Asset).where(
        Asset.id == asset_id,
        Asset.tenant_id == tenant_id,
        Asset.is_active == True,  # noqa: E712
    )
    result = await session.execute(stmt)
    return result.unique().scalar_one_or_none()


async def update_asset(
    *,
    asset_id: uuid.UUID,
    tenant_id: uuid.UUID,
    name: str | None,
    description: str | None,
    tags: dict[str, str] | None,
    session: AsyncSession,
) -> Asset:
    """Update mutable asset fields and optionally replace tags."""
    asset = await get_asset(
        asset_id=asset_id,
        tenant_id=tenant_id,
        session=session,
    )
    if asset is None:
        raise ValueError("Asset not found")

    if name is not None:
        asset.name = name
    if description is not None:
        asset.description = description

    # Replace tags if provided
    if tags is not None:
        # Remove existing tags
        for existing_tag in list(asset.tags):
            await session.delete(existing_tag)
        await session.flush()

        # Add new tags
        for key, value in tags.items():
            tag = AssetTag(asset_id=asset.id, key=key, value=value)
            session.add(tag)

    await session.flush()
    await session.refresh(asset, attribute_names=["tags"])
    return asset


async def delete_asset(
    *, asset_id: uuid.UUID, tenant_id: uuid.UUID, session: AsyncSession
) -> None:
    """Soft-delete an asset by setting ``is_active = False``."""
    asset = await get_asset(
        asset_id=asset_id,
        tenant_id=tenant_id,
        session=session,
    )
    if asset is None:
        raise ValueError("Asset not found")

    asset.is_active = False
    await session.flush()
