"""Asset-group service for reusable multi-target scan scopes."""

from __future__ import annotations

import uuid

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.asset_group import AssetGroup, AssetGroupMember
from app.models.project import Project


def _unique_asset_ids(asset_ids: list[uuid.UUID]) -> list[uuid.UUID]:
    return list(dict.fromkeys(asset_ids))


def _attach_asset_state(
    groups: list[AssetGroup],
    members: dict[uuid.UUID, list[uuid.UUID]],
) -> list[AssetGroup]:
    for group in groups:
        asset_ids = list(members.get(group.id, []))
        setattr(group, "asset_ids", asset_ids)
        setattr(group, "asset_count", len(asset_ids))
    return groups


async def _load_project(
    *,
    project_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
) -> Project | None:
    stmt = select(Project).where(
        Project.id == project_id,
        Project.tenant_id == tenant_id,
        Project.is_active == True,  # noqa: E712
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def _load_group_member_map(
    *,
    group_ids: list[uuid.UUID],
    tenant_id: uuid.UUID,
    session: AsyncSession,
) -> dict[uuid.UUID, list[uuid.UUID]]:
    if not group_ids:
        return {}

    stmt = (
        select(AssetGroupMember.asset_group_id, AssetGroupMember.asset_id)
        .join(Asset, Asset.id == AssetGroupMember.asset_id)
        .where(
            AssetGroupMember.tenant_id == tenant_id,
            AssetGroupMember.asset_group_id.in_(group_ids),
            Asset.tenant_id == tenant_id,
            Asset.is_active == True,  # noqa: E712
        )
        .order_by(AssetGroupMember.created_at.asc())
    )
    rows = (await session.execute(stmt)).all()
    members: dict[uuid.UUID, list[uuid.UUID]] = {}
    for group_id, asset_id in rows:
        members.setdefault(group_id, []).append(asset_id)
    return members


async def _load_assets_for_group(
    *,
    asset_ids: list[uuid.UUID],
    project_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
) -> list[Asset]:
    unique_ids = _unique_asset_ids(asset_ids)
    if not unique_ids:
        raise ValueError("Asset groups require at least one asset")

    stmt = (
        select(Asset)
        .where(
            Asset.tenant_id == tenant_id,
            Asset.project_id == project_id,
            Asset.is_active == True,  # noqa: E712
            Asset.id.in_(unique_ids),
        )
    )
    assets = list((await session.execute(stmt)).unique().scalars().all())
    if len(assets) != len(unique_ids):
        raise ValueError("One or more assets were not found in the project")

    asset_map = {asset.id: asset for asset in assets}
    return [asset_map[asset_id] for asset_id in unique_ids]


async def create_asset_group(
    *,
    tenant_id: uuid.UUID,
    project_id: uuid.UUID,
    created_by: uuid.UUID,
    name: str,
    description: str | None,
    asset_ids: list[uuid.UUID],
    session: AsyncSession,
) -> AssetGroup:
    project = await _load_project(
        project_id=project_id,
        tenant_id=tenant_id,
        session=session,
    )
    if project is None:
        raise ValueError("Project not found")

    assets = await _load_assets_for_group(
        asset_ids=asset_ids,
        project_id=project_id,
        tenant_id=tenant_id,
        session=session,
    )

    group = AssetGroup(
        tenant_id=tenant_id,
        project_id=project_id,
        created_by=created_by,
        name=name,
        description=description,
    )
    session.add(group)
    await session.flush()

    for asset in assets:
        session.add(
            AssetGroupMember(
                tenant_id=tenant_id,
                asset_group_id=group.id,
                asset_id=asset.id,
                created_by=created_by,
            )
        )
    await session.flush()
    setattr(group, "asset_ids", [asset.id for asset in assets])
    setattr(group, "asset_count", len(assets))
    return group


async def list_asset_groups(
    *,
    project_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
    page: int = 1,
    page_size: int = 20,
) -> tuple[list[AssetGroup], int]:
    project = await _load_project(
        project_id=project_id,
        tenant_id=tenant_id,
        session=session,
    )
    if project is None:
        return [], 0

    count_stmt = select(func.count()).select_from(AssetGroup).where(
        AssetGroup.project_id == project_id,
        AssetGroup.tenant_id == tenant_id,
        AssetGroup.is_active == True,  # noqa: E712
    )
    total = (await session.execute(count_stmt)).scalar_one()

    offset = (page - 1) * page_size
    stmt = (
        select(AssetGroup)
        .where(
            AssetGroup.project_id == project_id,
            AssetGroup.tenant_id == tenant_id,
            AssetGroup.is_active == True,  # noqa: E712
        )
        .order_by(AssetGroup.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    groups = list((await session.execute(stmt)).scalars().all())
    members = await _load_group_member_map(
        group_ids=[group.id for group in groups],
        tenant_id=tenant_id,
        session=session,
    )
    return _attach_asset_state(groups, members), total


async def get_asset_group(
    *,
    asset_group_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
) -> AssetGroup | None:
    stmt = select(AssetGroup).where(
        AssetGroup.id == asset_group_id,
        AssetGroup.tenant_id == tenant_id,
        AssetGroup.is_active == True,  # noqa: E712
    )
    group = (await session.execute(stmt)).scalar_one_or_none()
    if group is None:
        return None
    members = await _load_group_member_map(
        group_ids=[group.id],
        tenant_id=tenant_id,
        session=session,
    )
    return _attach_asset_state([group], members)[0]


async def update_asset_group(
    *,
    asset_group_id: uuid.UUID,
    tenant_id: uuid.UUID,
    name: str | None,
    description: str | None,
    asset_ids: list[uuid.UUID] | None,
    session: AsyncSession,
) -> AssetGroup:
    group = await get_asset_group(
        asset_group_id=asset_group_id,
        tenant_id=tenant_id,
        session=session,
    )
    if group is None:
        raise ValueError("Asset group not found")

    if name is not None:
        group.name = name
    if description is not None:
        group.description = description

    if asset_ids is not None:
        assets = await _load_assets_for_group(
            asset_ids=asset_ids,
            project_id=group.project_id,
            tenant_id=tenant_id,
            session=session,
        )
        await session.execute(
            delete(AssetGroupMember).where(AssetGroupMember.asset_group_id == asset_group_id)
        )
        for asset in assets:
            session.add(
                AssetGroupMember(
                    tenant_id=tenant_id,
                    asset_group_id=asset_group_id,
                    asset_id=asset.id,
                    created_by=group.created_by,
                )
            )
        setattr(group, "asset_ids", [asset.id for asset in assets])
        setattr(group, "asset_count", len(assets))

    await session.flush()

    if not hasattr(group, "asset_ids"):
        members = await _load_group_member_map(
            group_ids=[group.id],
            tenant_id=tenant_id,
            session=session,
        )
        _attach_asset_state([group], members)
    return group


async def delete_asset_group(
    *,
    asset_group_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
) -> None:
    group = await get_asset_group(
        asset_group_id=asset_group_id,
        tenant_id=tenant_id,
        session=session,
    )
    if group is None:
        raise ValueError("Asset group not found")

    group.is_active = False
    await session.flush()


async def list_asset_group_assets(
    *,
    asset_group_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
) -> list[Asset]:
    group = await get_asset_group(
        asset_group_id=asset_group_id,
        tenant_id=tenant_id,
        session=session,
    )
    if group is None:
        raise ValueError("Asset group not found")

    asset_ids = list(getattr(group, "asset_ids", []))
    if not asset_ids:
        return []

    stmt = select(Asset).where(
        Asset.tenant_id == tenant_id,
        Asset.is_active == True,  # noqa: E712
        Asset.id.in_(asset_ids),
    )
    assets = list((await session.execute(stmt)).unique().scalars().all())
    asset_map = {asset.id: asset for asset in assets}
    return [asset_map[asset_id] for asset_id in asset_ids if asset_id in asset_map]
