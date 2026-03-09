"""Project router — CRUD endpoints for tenant-scoped projects.

Mounted at ``/api/v1/projects``.
"""

from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from pentra_common.schemas import PaginatedResponse, ProjectCreate, ProjectResponse, ProjectUpdate

from app.deps import CurrentUser, get_current_user, get_db_session
from app.services import project_service

logger = logging.getLogger(__name__)

router = APIRouter(tags=["projects"])


@router.post(
    "",
    response_model=ProjectResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a project",
)
async def create_project(
    body: ProjectCreate,
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> ProjectResponse:
    """Create a new project under the authenticated user's tenant."""
    project = await project_service.create_project(
        tenant_id=user.tenant_id,
        created_by=user.user_id,
        name=body.name,
        slug=body.slug,
        description=body.description,
        session=session,
    )
    return ProjectResponse.model_validate(project)


@router.get(
    "",
    response_model=PaginatedResponse[ProjectResponse],
    summary="List projects",
)
async def list_projects(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> PaginatedResponse[ProjectResponse]:
    """List projects for the authenticated tenant (paginated)."""
    items, total = await project_service.list_projects(
        session=session, page=page, page_size=page_size
    )
    return PaginatedResponse(
        items=[ProjectResponse.model_validate(p) for p in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/{project_id}",
    response_model=ProjectResponse,
    summary="Get a project",
)
async def get_project(
    project_id: uuid.UUID,
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> ProjectResponse:
    """Get a single project by ID."""
    project = await project_service.get_project(
        project_id=project_id, session=session
    )
    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Project not found"
        )
    return ProjectResponse.model_validate(project)


@router.patch(
    "/{project_id}",
    response_model=ProjectResponse,
    summary="Update a project",
)
async def update_project(
    project_id: uuid.UUID,
    body: ProjectUpdate,
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> ProjectResponse:
    """Update mutable fields of a project."""
    try:
        project = await project_service.update_project(
            project_id=project_id,
            name=body.name,
            description=body.description,
            session=session,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        )
    return ProjectResponse.model_validate(project)


@router.delete(
    "/{project_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a project",
)
async def delete_project(
    project_id: uuid.UUID,
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> None:
    """Soft-delete a project (sets ``is_active = False``)."""
    try:
        await project_service.delete_project(
            project_id=project_id, session=session
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        )
