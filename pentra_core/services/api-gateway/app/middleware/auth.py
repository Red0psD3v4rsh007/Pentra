"""JWT authentication middleware.

Intercepts every request, extracts the Bearer token (if present),
validates it via ``pentra_common.auth.jwt``, and populates
``request.state.user`` with a :class:`CurrentUser` instance.

Public routes (health, auth callbacks) are skipped — they don't
carry a Bearer token, so ``request.state.user`` remains ``None``.
Protected endpoints enforce auth via the ``get_current_user``
FastAPI dependency (which raises 401 if ``request.state.user`` is
absent).

This middleware also sets ``request.state.tenant_id`` for use by
the rate-limit middleware and logging context.
"""

from __future__ import annotations

import logging
import uuid

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from pentra_common.auth.jwt import TokenError, decode_token
from pentra_common.auth.tenant_context import CurrentUser

from app.security.runtime_auth import build_dev_bypass_user, is_dev_auth_bypass_enabled

logger = logging.getLogger(__name__)

# Routes that never require authentication
_PUBLIC_PREFIXES = (
    "/health",
    "/ready",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/auth/google",
)


class AuthMiddleware(BaseHTTPMiddleware):
    """Extract and validate JWT from the Authorization header.

    Populates ``request.state.user`` (CurrentUser | None) and
    ``request.state.tenant_id`` (UUID | None) for downstream use.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Default: unauthenticated
        request.state.user = None
        request.state.tenant_id = None

        # Skip public routes entirely
        path = request.url.path
        if any(path.startswith(prefix) for prefix in _PUBLIC_PREFIXES):
            return await call_next(request)

        # Extract Bearer token
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            try:
                payload = decode_token(token)
                if payload.get("type") == "access":
                    user = CurrentUser(
                        user_id=uuid.UUID(payload["sub"]),
                        tenant_id=uuid.UUID(payload["tid"]),
                        email=payload.get("email", ""),
                        roles=payload.get("roles", []),
                        tier=payload.get("tier", "free"),
                    )
                    request.state.user = user
                    request.state.tenant_id = user.tenant_id

                    # Enrich log context
                    logger.debug(
                        "Authenticated: user=%s tenant=%s roles=%s",
                        user.user_id,
                        user.tenant_id,
                        user.roles,
                    )
            except TokenError:
                # Invalid token — don't block; let the route-level dependency
                # raise 401 if authentication is required.
                logger.debug("Invalid token on %s — proceeding unauthenticated", path)
        elif is_dev_auth_bypass_enabled():
            user = build_dev_bypass_user()
            request.state.user = user
            request.state.tenant_id = user.tenant_id
            logger.debug(
                "Development auth bypass active: user=%s tenant=%s",
                user.user_id,
                user.tenant_id,
            )

        return await call_next(request)
