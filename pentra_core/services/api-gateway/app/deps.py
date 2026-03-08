"""FastAPI dependency injection layer.

Provides injectable dependencies for the router → service → repository
pipeline.  Each dependency is a thin wrapper that composes primitives
from ``pentra_common``.

Dependency graph::

    Router
      ├── get_current_user       (JWT → CurrentUser)
      ├── get_db_session          (async session + RLS tenant context)
      ├── get_event_publisher     (Redis publisher from app.state)
      └── require_roles("admin")  (role gate → CurrentUser)
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import AsyncGenerator

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from pentra_common.auth.tenant_context import CurrentUser, get_current_user, require_roles
from pentra_common.db.rls import set_tenant_context
from pentra_common.db.session import async_session_factory
from pentra_common.events.publisher import EventPublisher

logger = logging.getLogger(__name__)


# ── Database session with RLS ────────────────────────────────────────


async def get_db_session(
    request: Request,
) -> AsyncGenerator[AsyncSession, None]:
    """Yield an async DB session with the tenant context set for RLS.

    If the request has an authenticated user (``request.state.user``),
    the PostgreSQL session variable ``app.tenant_id`` is set before
    yielding.  This enables row-level security policies.

    Non-authenticated routes (health, auth) get a session without RLS.
    """
    async with async_session_factory() as session:
        try:
            # Set RLS context if user is authenticated
            user: CurrentUser | None = getattr(request.state, "user", None)
            if user is not None:
                await set_tenant_context(session, user.tenant_id)

            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ── Event publisher ──────────────────────────────────────────────────


async def get_event_publisher(request: Request) -> EventPublisher:
    """Retrieve the Redis event publisher from application state.

    Initialised during lifespan startup in ``main.py``.
    """
    publisher: EventPublisher | None = getattr(request.app.state, "event_publisher", None)
    if publisher is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Event publisher not available",
        )
    return publisher


# ── Re-exports for convenience ───────────────────────────────────────
# Routers import everything from deps.py:
#   from app.deps import get_current_user, get_db_session, require_roles, ...

__all__ = [
    "get_current_user",
    "get_db_session",
    "get_event_publisher",
    "require_roles",
    "CurrentUser",
]
