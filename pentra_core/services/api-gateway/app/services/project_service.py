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

from app.models.project import Project

logger = logging.getLogger(__name__)


def _slugify(name: str) -> str:
    """Convert a project name to a URL-safe slug."""
    slug = name.lower().strip()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    return slug.strip("-") or "project"


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
    session: AsyncSession,
    page: int = 1,
    page_size: int = 20,
) -> tuple[list[Project], int]:
    """List projects (tenant-scoped via RLS).

    Returns ``(items, total_count)``.
    """
    count_stmt = select(func.count()).select_from(Project).where(Project.is_active == True)  # noqa: E712
    total = (await session.execute(count_stmt)).scalar_one()

    offset = (page - 1) * page_size
    stmt = (
        select(Project)
        .where(Project.is_active == True)  # noqa: E712
        .order_by(Project.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    result = await session.execute(stmt)
    return list(result.scalars().all()), total


async def get_project(
    *, project_id: uuid.UUID, session: AsyncSession
) -> Project | None:
    """Fetch a single project by ID (RLS enforces tenant scope)."""
    stmt = select(Project).where(
        Project.id == project_id, Project.is_active == True  # noqa: E712
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def update_project(
    *,
    project_id: uuid.UUID,
    name: str | None,
    description: str | None,
    session: AsyncSession,
) -> Project:
    """Update mutable project fields."""
    project = await get_project(project_id=project_id, session=session)
    if project is None:
        raise ValueError("Project not found")

    if name is not None:
        project.name = name
    if description is not None:
        project.description = description

    await session.flush()
    return project


async def delete_project(
    *, project_id: uuid.UUID, session: AsyncSession
) -> None:
    """Soft-delete a project by setting ``is_active = False``."""
    project = await get_project(project_id=project_id, session=session)
    if project is None:
        raise ValueError("Project not found")

    project.is_active = False
    await session.flush()
