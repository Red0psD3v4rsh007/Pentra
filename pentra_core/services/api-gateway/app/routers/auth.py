"""Authentication router — Google OAuth 2.0 flow and token management.

All auth routes are mounted at ``/auth``.  The Google callback and
token refresh endpoints interact with :mod:`app.services.auth_service`
for business logic.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from pentra_common.schemas import TokenResponse, UserResponse

from app.deps import CurrentUser, get_current_user, get_db_session
from app.services import auth_service

logger = logging.getLogger(__name__)

router = APIRouter(tags=["auth"])


# ── Request schemas (local to this router) ───────────────────────────


class RefreshRequest(BaseModel):
    refresh_token: str


# ── Endpoints ────────────────────────────────────────────────────────


@router.get(
    "/google",
    summary="Redirect to Google OAuth consent screen",
    status_code=status.HTTP_307_TEMPORARY_REDIRECT,
)
async def google_login():
    """Initiate the Google OAuth 2.0 authorisation-code flow."""
    url = auth_service.get_google_auth_url()
    return RedirectResponse(url=url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)


@router.get(
    "/google/callback",
    response_model=TokenResponse,
    summary="Handle Google OAuth callback",
)
async def google_callback(
    code: str = Query(..., description="OAuth authorisation code from Google"),
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

    return TokenResponse(
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        token_type="bearer",
        expires_in=tokens.expires_in,
    )


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
