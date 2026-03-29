"""Authentication router — Google OAuth 2.0 flow and token management.

All auth routes are mounted at ``/auth``.  The Google callback and
token refresh endpoints interact with :mod:`app.services.auth_service`
for business logic.
"""

from __future__ import annotations

import logging
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from pentra_common.config.settings import get_settings
from pentra_common.schemas import TokenResponse, UserResponse

from app.deps import CurrentUser, get_current_user, get_db_session
from app.services import auth_service

logger = logging.getLogger(__name__)

router = APIRouter(tags=["auth"])
_FRONTEND_LOGIN_STATE = "frontend"


# ── Request schemas (local to this router) ───────────────────────────


class RefreshRequest(BaseModel):
    refresh_token: str


class AuthRuntimeResponse(BaseModel):
    dev_auth_bypass_enabled: bool
    google_oauth_configured: bool
    auth_methods: list[str]


# ── Endpoints ────────────────────────────────────────────────────────


def _build_frontend_google_redirect_url(tokens: TokenResponse) -> str:
    settings = get_settings()
    base_url = settings.frontend_base_url.rstrip("/")
    fragment = urlencode(
        {
            "access_token": tokens.access_token,
            "refresh_token": tokens.refresh_token,
            "token_type": tokens.token_type,
            "expires_in": str(tokens.expires_in),
        }
    )
    return f"{base_url}/auth/google/callback#{fragment}"


@router.get(
    "/runtime",
    response_model=AuthRuntimeResponse,
    summary="Get browser authentication runtime capabilities",
)
async def auth_runtime() -> AuthRuntimeResponse:
    settings = get_settings()
    google_oauth_configured = bool(
        settings.google_client_id.strip() and settings.google_client_secret.strip()
    )
    auth_methods: list[str] = []
    if settings.app_env == "development" and settings.dev_auth_bypass_enabled:
        auth_methods.append("dev_bypass")
    if google_oauth_configured:
        auth_methods.append("google_oauth")

    return AuthRuntimeResponse(
        dev_auth_bypass_enabled=settings.app_env == "development"
        and settings.dev_auth_bypass_enabled,
        google_oauth_configured=google_oauth_configured,
        auth_methods=auth_methods,
    )


@router.get(
    "/google",
    summary="Redirect to Google OAuth consent screen",
    status_code=status.HTTP_307_TEMPORARY_REDIRECT,
)
async def google_login(
    mode: str | None = Query(
        default=None,
        description="Optional browser flow mode. Use 'frontend' to finish auth in the UI.",
    ),
):
    """Initiate the Google OAuth 2.0 authorisation-code flow."""
    state = _FRONTEND_LOGIN_STATE if mode == _FRONTEND_LOGIN_STATE else None
    url = auth_service.get_google_auth_url(state=state)
    return RedirectResponse(url=url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)


@router.get(
    "/google/callback",
    response_model=TokenResponse,
    summary="Handle Google OAuth callback",
)
async def google_callback(
    code: str = Query(..., description="OAuth authorisation code from Google"),
    state: str | None = Query(default=None, description="Optional browser flow state"),
    session: AsyncSession = Depends(get_db_session),
) -> TokenResponse:
    """Exchange the Google authorisation code for Pentra JWT tokens.

    Creates the user and tenant if this is the first login.
    """
    try:
        tokens = await auth_service.handle_google_callback(
            code=code, session=session
        )
    except Exception as exc:
        logger.exception("Google OAuth callback failed")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"OAuth authentication failed: {exc}",
        )

    token_response = TokenResponse(
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        token_type="bearer",
        expires_in=tokens.expires_in,
    )
    if state == _FRONTEND_LOGIN_STATE:
        return RedirectResponse(
            url=_build_frontend_google_redirect_url(token_response),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    return token_response


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh access token",
)
async def refresh_token(
    body: RefreshRequest,
    session: AsyncSession = Depends(get_db_session),
) -> TokenResponse:
    """Exchange a valid refresh token for a new access + refresh pair."""
    try:
        tokens = await auth_service.refresh_tokens(
            refresh_token_str=body.refresh_token, session=session
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        )

    return TokenResponse(
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        token_type="bearer",
        expires_in=tokens.expires_in,
    )


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user profile",
)
async def me(
    user: CurrentUser = Depends(get_current_user),
    session: AsyncSession = Depends(get_db_session),
) -> UserResponse:
    """Return the profile of the currently authenticated user."""
    db_user = await auth_service.get_user_by_id(
        user_id=user.user_id, session=session
    )
    if db_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return UserResponse.model_validate(db_user)
