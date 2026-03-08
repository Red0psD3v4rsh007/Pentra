"""FastAPI dependency that extracts the current user from the JWT.

This is the primary auth dependency used by all protected endpoints.
It validates the access token, extracts claims, and provides a typed
``CurrentUser`` dataclass for downstream use.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from pentra_common.auth.jwt import TokenError, decode_token

_bearer_scheme = HTTPBearer(auto_error=False)


@dataclass(frozen=True, slots=True)
class CurrentUser:
    """Typed representation of the authenticated user from JWT claims."""

    user_id: uuid.UUID
    tenant_id: uuid.UUID
    email: str
    roles: list[str] = field(default_factory=list)
    tier: str = "free"


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> CurrentUser:
    """FastAPI dependency — extract and validate the Bearer JWT.

    Returns a :class:`CurrentUser` instance on success, or raises
    ``401 Unauthorized``.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_token(credentials.credentials)
    except TokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type — access token required",
        )

    return CurrentUser(
        user_id=uuid.UUID(payload["sub"]),
        tenant_id=uuid.UUID(payload["tid"]),
        email=payload.get("email", ""),
        roles=payload.get("roles", []),
        tier=payload.get("tier", "free"),
    )


def require_roles(*allowed_roles: str):
    """Factory returning a dependency that checks the user has one of the
    given roles.

    Usage::

        @router.post("/admin-action")
        async def admin_action(
            user: CurrentUser = Depends(require_roles("owner", "admin")),
        ):
            ...
    """

    async def _check(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if not any(role in allowed_roles for role in user.roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {', '.join(allowed_roles)}",
            )
        return user

    return _check
