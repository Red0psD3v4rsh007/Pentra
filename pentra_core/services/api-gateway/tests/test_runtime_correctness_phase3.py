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


def _build_user(*, tenant_id: str, user_id: str, roles: list[str]) -> object:
    from pentra_common.auth.tenant_context import CurrentUser

    return CurrentUser(
        user_id=uuid.UUID(user_id),
        tenant_id=uuid.UUID(tenant_id),
        email="phase3@pentra.local",
        roles=roles,
        tier="enterprise",
    )


def _build_request(path: str) -> object:
    return SimpleNamespace(
        url=SimpleNamespace(path=path),
        method="POST",
        state=SimpleNamespace(request_id="req-phase3"),
    )


def test_create_app_builds_runtime_middleware_in_correct_order() -> None:
    from app.main import create_app

    app = create_app()
    middleware_names = [middleware.cls.__name__ for middleware in app.user_middleware]

    assert middleware_names[:4] == [
        "CORSMiddleware",
        "RequestContextMiddleware",
        "AuthMiddleware",
        "RateLimitMiddleware",
    ]


def test_cors_normalizes_loopback_origin_variants() -> None:
    from app.middleware.cors import _normalize_allowed_origins

    origins = _normalize_allowed_origins(
        ["http://localhost:3006"],
        frontend_base_url="http://localhost:3006",
    )

    assert "http://localhost:3006" in origins
    assert "http://127.0.0.1:3006" in origins


def test_ai_routes_forward_current_user_user_id(monkeypatch) -> None:
    from app.routers import scans

    user = _build_user(
        tenant_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        user_id="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        roles=["member"],
    )
    captured: list[tuple[str, uuid.UUID]] = []

    async def fake_exploitation_paths(**kwargs: object) -> dict[str, object]:
        captured.append(("paths", kwargs["user_id"]))  # type: ignore[index]
        return {"ok": True}

    async def fake_vector_priorities(**kwargs: object) -> dict[str, object]:
        captured.append(("vectors", kwargs["user_id"]))  # type: ignore[index]
        return {"ok": True}

    async def fake_remediation_report(**kwargs: object) -> dict[str, object]:
        captured.append(("remediation", kwargs["user_id"]))  # type: ignore[index]
        return {"ok": True}

    monkeypatch.setattr(
        scans.ai_reasoning_service,
        "suggest_exploitation_paths",
        fake_exploitation_paths,
    )
    monkeypatch.setattr(
        scans.ai_reasoning_service,
        "prioritize_attack_vectors",
        fake_vector_priorities,
    )
    monkeypatch.setattr(
        scans.ai_reasoning_service,
        "generate_remediation_report",
        fake_remediation_report,
    )

    asyncio.run(
        scans.get_exploitation_paths(
            request=_build_request("/api/v1/scans/scan-1/exploitation-paths"),
            scan_id=uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc"),
            user=user,
            session=object(),
        )
    )
    asyncio.run(
        scans.get_vector_priorities(
            request=_build_request("/api/v1/scans/scan-1/vector-priorities"),
            scan_id=uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc"),
            vectors="jwt,idor",
            user=user,
            session=object(),
        )
    )
    asyncio.run(
        scans.get_remediation_report(
            request=_build_request("/api/v1/scans/scan-1/remediation-report"),
            scan_id=uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc"),
            user=user,
            session=object(),
        )
    )

    assert captured == [
        ("paths", user.user_id),
        ("vectors", user.user_id),
        ("remediation", user.user_id),
    ]


def test_rerun_tool_fails_closed_until_orchestrated(monkeypatch) -> None:
    from app.routers import scans

    user = _build_user(
        tenant_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        user_id="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        roles=["member"],
    )
    audit_events: list[dict[str, object]] = []

    async def fake_get_scan(*, scan_id: uuid.UUID, tenant_id: uuid.UUID, session: object) -> object:
        return object()

    def fake_audit_event(**kwargs: object) -> None:
        audit_events.append(kwargs)

    monkeypatch.setattr(scans.scan_service, "get_scan", fake_get_scan)
    monkeypatch.setattr(scans, "log_audit_event", fake_audit_event)

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(
            scans.rerun_tool(
                request=_build_request("/api/v1/scans/scan-1/rerun-tool"),
                scan_id=uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc"),
                body={"tool_id": "nuclei", "command": ["nuclei", "-u", "https://example.com"]},
                user=user,
                session=object(),
            )
        )

    assert exc_info.value.status_code == 501
    assert "not wired to orchestration yet" in str(exc_info.value.detail)
    assert audit_events[0]["outcome"] == "denied"
    assert audit_events[0]["details"] == {
        "tool_id": "nuclei",
        "argument_count": 3,
        "reason": "not_implemented",
    }
