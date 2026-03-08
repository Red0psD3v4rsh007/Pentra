"""JWT token creation and verification.

Tokens carry tenant_id, user_id, roles, and tier so that downstream
services can enforce authorization and RLS without hitting the DB.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt

from pentra_common.config.settings import get_settings


class TokenError(Exception):
    """Raised when a token cannot be created or decoded."""


# ── Token creation ──────────────────────────────────────────────────


def create_access_token(
    *,
    user_id: uuid.UUID,
    tenant_id: uuid.UUID,
    email: str,
    roles: list[str],
    tier: str,
) -> str:
    """Create a short-lived access token (15 min default)."""
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "tid": str(tenant_id),
        "email": email,
        "roles": roles,
        "tier": tier,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=settings.jwt_access_token_expire_minutes),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def create_refresh_token(
    *,
    user_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> str:
    """Create a long-lived refresh token (7 day default, single-use)."""
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "tid": str(tenant_id),
        "type": "refresh",
        "iat": now,
        "exp": now + timedelta(days=settings.jwt_refresh_token_expire_days),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


# ── Token verification ──────────────────────────────────────────────


def decode_token(token: str) -> dict:
    """Decode and validate a JWT, returning the claims dict.

    Raises :class:`TokenError` on invalid/expired tokens.
    """
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
        )
        return payload
    except JWTError as exc:
        raise TokenError(f"Invalid token: {exc}") from exc
