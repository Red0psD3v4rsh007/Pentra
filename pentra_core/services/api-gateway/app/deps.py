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
from collections.abc import AsyncGenerator

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from pentra_common.auth.tenant_context import CurrentUser
from pentra_common.db.rls import set_tenant_context
from pentra_common.db.session import async_session_factory
from pentra_common.events.publisher import EventPublisher
from pentra_common.events.stream_publisher import StreamPublisher

from app.security.runtime_auth import build_dev_bypass_user, is_dev_auth_bypass_enabled

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
            if user is None and is_dev_auth_bypass_enabled():
                user = build_dev_bypass_user()
                request.state.user = user
                request.state.tenant_id = user.tenant_id
            if user is not None:
                await set_tenant_context(session, user.tenant_id)

            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ── Event publisher (Pub/Sub — backward compat) ─────────────────────


async def get_event_publisher(request: Request) -> EventPublisher:
    """Retrieve the Redis Pub/Sub event publisher from application state.

    Initialised during lifespan startup in ``main.py``.
    """
    publisher: EventPublisher | None = getattr(request.app.state, "event_publisher", None)
    if publisher is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Event publisher not available",
        )
    return publisher


# ── Stream publisher (Redis Streams — durable events for MOD-04) ─────


async def get_stream_publisher(request: Request) -> StreamPublisher:
    """Retrieve the Redis Streams publisher from application state.

    Used for durable event publishing (scan.created, scan.cancelled)
    that requires acknowledgement and replay guarantees.
    Initialised during lifespan startup in ``main.py``.
    """
    publisher: StreamPublisher | None = getattr(request.app.state, "stream_publisher", None)
    if publisher is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Stream publisher not available",
        )
    return publisher


async def get_current_user(request: Request) -> CurrentUser:
    """Return the authenticated request user or the configured dev bypass user."""
    user: CurrentUser | None = getattr(request.state, "user", None)
    if user is None and is_dev_auth_bypass_enabled():
        user = build_dev_bypass_user()
        request.state.user = user
        request.state.tenant_id = user.tenant_id

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def require_roles(*allowed_roles: str):
    """App-scoped role gate that respects middleware-authenticated users."""

    async def _check(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if not any(role in allowed_roles for role in user.roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {', '.join(allowed_roles)}",
            )
        return user

    return _check

# ── Re-exports for convenience ───────────────────────────────────────
# Routers import everything from deps.py:
#   from app.deps import get_current_user, get_db_session, require_roles, ...

__all__ = [
    "get_current_user",
    "get_db_session",
    "get_event_publisher",
    "get_stream_publisher",
    "require_roles",
    "CurrentUser",
]
