from __future__ import annotations

import asyncio
import os
import sys
import types
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def _install_fake_jose() -> None:
    if "jose" in sys.modules:
        return

    jwt_module = types.SimpleNamespace(
        encode=lambda *args, **kwargs: "token",
        decode=lambda *args, **kwargs: {},
    )
    sys.modules["jose"] = types.SimpleNamespace(JWTError=Exception, jwt=jwt_module)


def test_google_login_frontend_mode_sets_frontend_state(monkeypatch) -> None:
    _install_fake_jose()
    from app.routers import auth

    captured: dict[str, str | None] = {"state": None}

    def fake_get_google_auth_url(*, state: str | None = None) -> str:
        captured["state"] = state
        return "https://accounts.example.test/oauth"

    monkeypatch.setattr(auth.auth_service, "get_google_auth_url", fake_get_google_auth_url)

    response = asyncio.run(auth.google_login(mode="frontend"))

    assert response.headers["location"] == "https://accounts.example.test/oauth"
    assert captured["state"] == "frontend"


def test_google_callback_frontend_mode_redirects_back_to_frontend(monkeypatch) -> None:
    _install_fake_jose()
    from app.routers import auth

    async def fake_handle_google_callback(**_: object) -> SimpleNamespace:
        return SimpleNamespace(
            access_token="access-token",
            refresh_token="refresh-token",
            expires_in=900,
        )

    monkeypatch.setattr(auth.auth_service, "handle_google_callback", fake_handle_google_callback)
    monkeypatch.setattr(
        auth,
        "get_settings",
        lambda: SimpleNamespace(frontend_base_url="http://localhost:3006"),
    )

    response = asyncio.run(
        auth.google_callback(code="oauth-code", state="frontend", session=object())
    )

    parsed = urlparse(response.headers["location"])
    fragment = parse_qs(parsed.fragment)

    assert response.status_code == 303
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == "http://localhost:3006/auth/google/callback"
    assert fragment["access_token"] == ["access-token"]
    assert fragment["refresh_token"] == ["refresh-token"]
    assert fragment["expires_in"] == ["900"]


def test_auth_runtime_reports_dev_bypass_and_google_oauth(monkeypatch) -> None:
    _install_fake_jose()
    from app.routers import auth

    monkeypatch.setattr(
        auth,
        "get_settings",
        lambda: SimpleNamespace(
            app_env="development",
            dev_auth_bypass_enabled=True,
            google_client_id="google-client-id",
            google_client_secret="google-client-secret",
        ),
    )

    payload = asyncio.run(auth.auth_runtime())

    assert payload.dev_auth_bypass_enabled is True
    assert payload.google_oauth_configured is True
    assert payload.auth_methods == ["dev_bypass", "google_oauth"]
