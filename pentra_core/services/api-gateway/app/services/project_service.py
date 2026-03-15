"""Project service — CRUD operations for tenant-scoped projects.

Framework-agnostic: accepts plain arguments, returns ORM objects.
No FastAPI Request dependency.
"""

from __future__ import annotations

import logging
import re
import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.project import Project

logger = logging.getLogger(__name__)


def _slugify(name: str) -> str:
    """Convert a project name to a URL-safe slug."""
    slug = name.lower().strip()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    return slug.strip("-") or "project"


def _attach_asset_counts(
    projects: list[Project],
    counts: dict[uuid.UUID, int],
) -> list[Project]:
    for project in projects:
        setattr(project, "asset_count", int(counts.get(project.id, 0)))
    return projects


async def _load_asset_counts(
    *,
    tenant_id: uuid.UUID,
    project_ids: list[uuid.UUID],
    session: AsyncSession,
) -> dict[uuid.UUID, int]:
    if not project_ids:
        return {}

    stmt = (
        select(Asset.project_id, func.count())
        .where(
            Asset.tenant_id == tenant_id,
            Asset.is_active == True,  # noqa: E712
            Asset.project_id.in_(project_ids),
        )
        .group_by(Asset.project_id)
    )
    rows = (await session.execute(stmt)).all()
    return {project_id: int(count) for project_id, count in rows}


async def create_project(
    *,
    tenant_id: uuid.UUID,
    created_by: uuid.UUID,
    name: str,
    slug: str | None,
    description: str | None,
    session: AsyncSession,
) -> Project:
    """Create a new project under the given tenant."""
    project = Project(
        tenant_id=tenant_id,
        created_by=created_by,
        name=name,
        slug=slug or _slugify(name),
        description=description,
    )
    session.add(project)
    await session.flush()
    return project


async def list_projects(
    *,
    tenant_id: uuid.UUID,
    session: AsyncSession,
    page: int = 1,
    page_size: int = 20,
) -> tuple[list[Project], int]:
    """List projects (tenant-scoped via RLS).

    Returns ``(items, total_count)``.
    """
    count_stmt = select(func.count()).select_from(Project).where(  # noqa: E712
        Project.tenant_id == tenant_id,
        Project.is_active == True,
    )
    total = (await session.execute(count_stmt)).scalar_one()

    offset = (page - 1) * page_size
    stmt = (
        select(Project)
        .where(Project.tenant_id == tenant_id, Project.is_active == True)  # noqa: E712
        .order_by(Project.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    result = await session.execute(stmt)
    projects = list(result.scalars().all())
    counts = await _load_asset_counts(
        tenant_id=tenant_id,
        project_ids=[project.id for project in projects],
        session=session,
    )
    return _attach_asset_counts(projects, counts), total


async def get_project(
    *, project_id: uuid.UUID, tenant_id: uuid.UUID, session: AsyncSession
) -> Project | None:
    """Fetch a single project by ID (RLS enforces tenant scope)."""
    stmt = select(Project).where(
        Project.id == project_id,
        Project.tenant_id == tenant_id,
        Project.is_active == True,  # noqa: E712
    )
    result = await session.execute(stmt)
    project = result.scalar_one_or_none()
    if project is None:
        return None

    counts = await _load_asset_counts(
        tenant_id=tenant_id,
        project_ids=[project.id],
        session=session,
    )
    return _attach_asset_counts([project], counts)[0]


async def update_project(
    *,
    project_id: uuid.UUID,
    tenant_id: uuid.UUID,
    name: str | None,
    description: str | None,
    session: AsyncSession,
) -> Project:
    """Update mutable project fields."""
    project = await get_project(
        project_id=project_id,
        tenant_id=tenant_id,
        session=session,
    )
    if project is None:
        raise ValueError("Project not found")

    if name is not None:
        project.name = name
    if description is not None:
        project.description = description

    await session.flush()
    return project


async def delete_project(
    *, project_id: uuid.UUID, tenant_id: uuid.UUID, session: AsyncSession
) -> None:
    """Soft-delete a project by setting ``is_active = False``."""
    project = await get_project(
        project_id=project_id,
        tenant_id=tenant_id,
        session=session,
    )
    if project is None:
        raise ValueError("Project not found")

    project.is_active = False
    await session.flush()
