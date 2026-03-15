"""Runtime auth helpers for dev bypass and request-scoped user handling."""

from __future__ import annotations

import uuid

from pentra_common.auth.tenant_context import CurrentUser
from pentra_common.config.settings import get_settings


def is_dev_auth_bypass_enabled() -> bool:
    settings = get_settings()
    return settings.app_env == "development" and settings.dev_auth_bypass_enabled


def build_dev_bypass_user() -> CurrentUser:
    settings = get_settings()
    roles = [role.strip() for role in settings.dev_auth_roles.split(",") if role.strip()]

    return CurrentUser(
        user_id=uuid.UUID(settings.dev_auth_user_id),
        tenant_id=uuid.UUID(settings.dev_auth_tenant_id),
        email=settings.dev_auth_email,
        roles=roles or ["owner"],
        tier=settings.dev_auth_tier,
    )
