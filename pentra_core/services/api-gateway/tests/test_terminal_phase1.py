from __future__ import annotations

import asyncio
import os
import sys
from types import SimpleNamespace
import uuid

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
        email="terminal@pentra.local",
        roles=roles,
        tier="enterprise",
    )


def test_user_can_manage_terminal_session_for_same_owner() -> None:
    from app.routers import terminal

    tenant_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    user_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    user = _build_user(tenant_id=tenant_id, user_id=user_id, roles=["member"])

    session_data = {
        "tenant_id": tenant_id,
        "user_id": user_id,
    }

    assert terminal._user_can_manage_session(user, session_data) is True


def test_user_can_manage_terminal_session_denies_other_member_but_allows_admin() -> None:
    from app.routers import terminal

    tenant_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    owner_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    other_member = _build_user(
        tenant_id=tenant_id,
        user_id="cccccccc-cccc-cccc-cccc-cccccccccccc",
        roles=["member"],
    )
    admin = _build_user(
        tenant_id=tenant_id,
        user_id="dddddddd-dddd-dddd-dddd-dddddddddddd",
        roles=["admin"],
    )
    session_data = {
        "tenant_id": tenant_id,
        "user_id": owner_id,
    }

    assert terminal._user_can_manage_session(other_member, session_data) is False
    assert terminal._user_can_manage_session(admin, session_data) is True


def test_validate_terminal_image_rejects_unregistered_image() -> None:
    from app.routers import terminal

    assert "instrumentisto/nmap:latest" in terminal._allowed_terminal_images()

    with pytest.raises(HTTPException) as exc_info:
        terminal._validate_terminal_image("evilcorp/escape-shell:latest")

    assert exc_info.value.status_code == 400
    assert "registered Pentra tool image" in str(exc_info.value.detail)


def test_create_terminal_session_passes_tenant_and_user_metadata(monkeypatch) -> None:
    from app.routers import terminal

    user = _build_user(
        tenant_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        user_id="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        roles=["member"],
    )
    scan_id = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
    captured: dict[str, str] = {}

    async def fake_get_scan(*, scan_id: uuid.UUID, tenant_id: uuid.UUID, session: object) -> object:
        return object()

    async def fake_start_tool_container(
        tool_image: str,
        scan_id: str,
        *,
        tenant_id: str,
        user_id: str,
        work_dir: str = "/work",
    ) -> dict[str, str]:
        captured["tool_image"] = tool_image
        captured["scan_id"] = scan_id
        captured["tenant_id"] = tenant_id
        captured["user_id"] = user_id
        return {
            "session_id": "sess-1",
            "container_id": "container-1",
            "container_name": "pentra-terminal-test",
            "status": "running",
        }

    monkeypatch.setattr(terminal.scan_service, "get_scan", fake_get_scan)
    monkeypatch.setattr(terminal, "_validate_terminal_image", lambda tool_image: None)
    monkeypatch.setattr(terminal._shell_manager, "start_tool_container", fake_start_tool_container)

    result = asyncio.run(
        terminal.create_terminal_session(
            {"tool_image": "instrumentisto/nmap:latest", "scan_id": scan_id},
            user=user,
            session=object(),
        )
    )

    assert result["session_id"] == "sess-1"
    assert captured["tool_image"] == "instrumentisto/nmap:latest"
    assert captured["scan_id"] == scan_id
    assert captured["tenant_id"] == str(user.tenant_id)
    assert captured["user_id"] == str(user.user_id)


def test_start_tool_container_overrides_entrypoint_with_shell(monkeypatch) -> None:
    from app.routers import terminal

    manager = terminal.ContainerShellManager()
    run_calls: list[dict[str, object]] = []

    class _FakeContainers:
        def run(self, image: str, **kwargs: object) -> object:
            run_calls.append({"image": image, **kwargs})
            return SimpleNamespace(id="container-1")

    fake_client = SimpleNamespace(containers=_FakeContainers())

    monkeypatch.setattr(manager, "_get_docker", lambda: fake_client)
    monkeypatch.setattr(terminal.os, "makedirs", lambda *args, **kwargs: None)

    result = asyncio.run(
        manager.start_tool_container(
            "instrumentisto/nmap:latest",
            "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
            tenant_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            user_id="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        )
    )

    assert result["container_id"] == "container-1"
    assert run_calls[0]["image"] == "instrumentisto/nmap:latest"
    assert run_calls[0]["entrypoint"] == "/bin/sh"
    assert run_calls[0]["command"] == ["-lc", "while true; do sleep 3600; done"]
    session = manager.get_session(result["session_id"])
    assert session is not None
    assert session["shell_path"] == "/bin/sh"


def test_start_tool_container_falls_back_to_secondary_shell(monkeypatch) -> None:
    from app.routers import terminal

    manager = terminal.ContainerShellManager()
    attempted_shells: list[str] = []

    class _FakeContainers:
        def run(self, image: str, **kwargs: object) -> object:
            shell = str(kwargs.get("entrypoint"))
            attempted_shells.append(shell)
            if shell == "/bin/sh":
                raise RuntimeError('exec: "/bin/sh": stat /bin/sh: no such file or directory')
            return SimpleNamespace(id="container-2")

    fake_client = SimpleNamespace(containers=_FakeContainers())

    monkeypatch.setattr(manager, "_get_docker", lambda: fake_client)
    monkeypatch.setattr(terminal.os, "makedirs", lambda *args, **kwargs: None)

    result = asyncio.run(
        manager.start_tool_container(
            "example/tool:latest",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
            tenant_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            user_id="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        )
    )

    assert attempted_shells[:2] == ["/bin/sh", "sh"]
    session = manager.get_session(result["session_id"])
    assert session is not None
    assert session["shell_path"] == "sh"
