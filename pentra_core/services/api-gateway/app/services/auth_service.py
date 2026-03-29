"""Authentication service — Google OAuth flow, user upsert, token management.

This module is framework-agnostic: it accepts plain arguments and returns
plain values.  It has **no dependency** on FastAPI request objects.
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlencode

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pentra_common.auth.jwt import (
    TokenError,
    create_access_token,
    create_refresh_token,
    decode_token,
)
from pentra_common.config.settings import get_settings

from app.models.tenant import Tenant, TenantQuota
from app.models.user import Role, User, UserRole

logger = logging.getLogger(__name__)
settings = get_settings()

# ── Tier defaults ────────────────────────────────────────────────────

_TIER_DEFAULTS = {
    "free": {"max_concurrent_scans": 2, "max_daily_scans": 100, "max_assets": 20, "max_projects": 5},
    "pro": {"max_concurrent_scans": 20, "max_daily_scans": 1000, "max_assets": 200, "max_projects": 50},
    "enterprise": {"max_concurrent_scans": 200, "max_daily_scans": 100_000, "max_assets": 10_000, "max_projects": 500},
}

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"


@dataclass(frozen=True)
class TokenPair:
    """Access + refresh token pair returned after authentication."""

    access_token: str
    refresh_token: str
    expires_in: int


# ── Public service functions ─────────────────────────────────────────


def get_google_auth_url(*, state: str | None = None) -> str:
    """Build the Google OAuth 2.0 consent screen redirect URL."""
    params = {
        "client_id": settings.google_client_id,
        "redirect_uri": settings.google_redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "consent",
    }
    if state:
        params["state"] = state
    return f"{GOOGLE_AUTH_URL}?{urlencode(params)}"


async def handle_google_callback(
    *, code: str, session: AsyncSession
) -> TokenPair:
    """Exchange the OAuth authorisation code for a token pair.

    1. Exchange code → Google tokens
    2. Fetch Google user profile
    3. Upsert User (+ Tenant if first sign-up)
    4. Issue Pentra JWT pair
    """
    # Step 1 — exchange code for Google tokens
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            GOOGLE_TOKEN_URL,
            data={
                "code": code,
                "client_id": settings.google_client_id,
                "client_secret": settings.google_client_secret,
                "redirect_uri": settings.google_redirect_uri,
                "grant_type": "authorization_code",
            },
        )
        token_resp.raise_for_status()
        google_tokens = token_resp.json()

        # Step 2 — fetch user profile
        userinfo_resp = await client.get(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {google_tokens['access_token']}"},
        )
        userinfo_resp.raise_for_status()
        profile = userinfo_resp.json()

    google_id: str = profile["sub"]
    email: str = profile["email"]
    full_name: str = profile.get("name", "")
    avatar_url: str | None = profile.get("picture")

    # Step 3 — upsert user
    user = await _get_or_create_user(
        session=session,
        google_id=google_id,
        email=email,
        full_name=full_name,
        avatar_url=avatar_url,
    )

    # Update last login
    user.last_login_at = datetime.now(timezone.utc)
    await session.flush()

    # Step 4 — issue token pair
    roles = [ur.role.name for ur in user.user_roles if ur.role]
    tenant = await session.get(Tenant, user.tenant_id)
    tier = tenant.tier if tenant else "free"

    return _issue_tokens(
        user_id=user.id,
        tenant_id=user.tenant_id,
        email=user.email,
        roles=roles,
        tier=tier,
    )


async def refresh_tokens(
    *, refresh_token_str: str, session: AsyncSession
) -> TokenPair:
    """Validate a refresh token and issue a new access + refresh pair."""
    try:
        payload = decode_token(refresh_token_str)
    except TokenError:
        raise ValueError("Invalid or expired refresh token")

    if payload.get("type") != "refresh":
        raise ValueError("Token is not a refresh token")

    user_id = uuid.UUID(payload["sub"])
    tenant_id = uuid.UUID(payload["tid"])

    # Verify user still exists and is active
    user = await session.get(User, user_id)
    if user is None or not user.is_active:
        raise ValueError("User not found or inactive")

    roles = [ur.role.name for ur in user.user_roles if ur.role]
    tenant = await session.get(Tenant, tenant_id)
    tier = tenant.tier if tenant else "free"

    return _issue_tokens(
        user_id=user_id,
        tenant_id=tenant_id,
        email=user.email,
        roles=roles,
        tier=tier,
    )


async def get_user_by_id(
    *, user_id: uuid.UUID, session: AsyncSession
) -> User | None:
    """Fetch a user by primary key (used by /auth/me)."""
    return await session.get(User, user_id)


# ── Internal helpers ─────────────────────────────────────────────────


def _issue_tokens(
    *,
    user_id: uuid.UUID,
    tenant_id: uuid.UUID,
    email: str,
    roles: list[str],
    tier: str,
) -> TokenPair:
    """Create and return a JWT access + refresh token pair."""
    access = create_access_token(
        user_id=user_id,
        tenant_id=tenant_id,
        email=email,
        roles=roles,
        tier=tier,
    )
    refresh = create_refresh_token(user_id=user_id, tenant_id=tenant_id)
    return TokenPair(
        access_token=access,
        refresh_token=refresh,
        expires_in=settings.jwt_access_token_expire_minutes * 60,
    )


def _slugify(name: str) -> str:
    """Convert a name to a URL-safe slug."""
    slug = name.lower().strip()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    slug = slug.strip("-")
    return slug or "org"


async def _get_or_create_user(
    *,
    session: AsyncSession,
    google_id: str,
    email: str,
    full_name: str,
    avatar_url: str | None,
) -> User:
    """Look up user by google_id or email; create if new (with tenant)."""
    # Try google_id first
    stmt = select(User).where(User.google_id == google_id)
    result = await session.execute(stmt)
    user = result.scalar_one_or_none()
    if user:
        user.full_name = full_name
        user.avatar_url = avatar_url
        return user

    # Try email
    stmt = select(User).where(User.email == email)
    result = await session.execute(stmt)
    user = result.scalar_one_or_none()
    if user:
        user.google_id = google_id
        user.full_name = full_name
        user.avatar_url = avatar_url
        return user

    # New user — create tenant first
    tenant = Tenant(
        name=f"{full_name or email.split('@')[0]}'s Organisation",
        slug=_slugify(full_name or email.split("@")[0]) + f"-{uuid.uuid4().hex[:6]}",
        tier="free",
    )
    session.add(tenant)
    await session.flush()  # get tenant.id

    # Create quota
    defaults = _TIER_DEFAULTS["free"]
    quota = TenantQuota(
        tenant_id=tenant.id,
        **defaults,
    )
    session.add(quota)

    # Create user
    user = User(
        tenant_id=tenant.id,
        email=email,
        full_name=full_name,
        google_id=google_id,
        avatar_url=avatar_url,
    )
    session.add(user)
    await session.flush()

    # Assign "owner" role
    owner_role = (
        await session.execute(select(Role).where(Role.name == "owner"))
    ).scalar_one_or_none()

    if owner_role:
        user_role = UserRole(
            user_id=user.id,
            role_id=owner_role.id,
            tenant_id=tenant.id,
        )
        session.add(user_role)
        await session.flush()

    return user
