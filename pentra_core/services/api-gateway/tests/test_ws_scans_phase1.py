from __future__ import annotations

import asyncio
import os
import sys
import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def test_authenticate_scan_websocket_accepts_valid_query_token(monkeypatch) -> None:
    from app.routers import ws_scans

    expected_user_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    expected_tenant_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

    def fake_decode_token(token: str) -> dict[str, object]:
        assert token == "scan-token"
        return {
            "type": "access",
            "sub": expected_user_id,
            "tid": expected_tenant_id,
            "email": "viewer@pentra.local",
            "roles": ["viewer"],
            "tier": "enterprise",
        }

    monkeypatch.setattr(ws_scans, "decode_token", fake_decode_token)
    websocket = SimpleNamespace(headers={}, query_params={"token": "scan-token"})

    user = ws_scans._authenticate_scan_websocket(websocket)

    assert str(user.user_id) == expected_user_id
    assert str(user.tenant_id) == expected_tenant_id
    assert user.roles == ["viewer"]


def test_authenticate_scan_websocket_uses_dev_bypass(monkeypatch) -> None:
    from app.routers import ws_scans

    bypass_user = SimpleNamespace(
        user_id=uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        tenant_id=uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
        email="dev@pentra.local",
        roles=["owner"],
        tier="enterprise",
    )

    monkeypatch.setattr(ws_scans, "is_dev_auth_bypass_enabled", lambda: True)
    monkeypatch.setattr(ws_scans, "build_dev_bypass_user", lambda: bypass_user)

    websocket = SimpleNamespace(headers={}, query_params={})
    user = ws_scans._authenticate_scan_websocket(websocket)

    assert user is bypass_user


def test_authenticate_scan_websocket_rejects_missing_token(monkeypatch) -> None:
    from app.routers import ws_scans

    monkeypatch.setattr(ws_scans, "is_dev_auth_bypass_enabled", lambda: False)
    websocket = SimpleNamespace(headers={}, query_params={})

    with pytest.raises(ws_scans._WebSocketAuthError) as exc_info:
        ws_scans._authenticate_scan_websocket(websocket, token="")

    assert exc_info.value.code == 4401
    assert "Missing authentication token" in exc_info.value.reason


def test_require_scan_access_rejects_cross_tenant_scan(monkeypatch) -> None:
    from app.routers import ws_scans
    from pentra_common.auth.tenant_context import CurrentUser

    user = CurrentUser(
        user_id=uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        tenant_id=uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
        email="viewer@pentra.local",
        roles=["viewer"],
        tier="enterprise",
    )

    async def fake_get_scan(*, scan_id: uuid.UUID, tenant_id: uuid.UUID, session: object) -> None:
        return None

    monkeypatch.setattr(ws_scans.scan_service, "get_scan", fake_get_scan)

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(
            ws_scans._require_scan_access(
                scan_id=uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc"),
                user=user,
                session=object(),
            )
        )

    assert exc_info.value.status_code == 404
    assert "Scan not found" in str(exc_info.value.detail)
