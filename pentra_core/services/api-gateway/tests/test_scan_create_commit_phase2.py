from __future__ import annotations

import asyncio
import os
import sys
import uuid
from types import SimpleNamespace

import pytest


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


class _FakeResult:
    def __init__(self, value: object) -> None:
        self._value = value

    def scalar_one_or_none(self) -> object:
        return self._value

    def scalar(self) -> object:
        return self._value


class _FakeSession:
    def __init__(self, *, asset: object, quota: object | None) -> None:
        self.asset = asset
        self.quota = quota
        self.execute_calls = 0
        self.executed_statements: list[object] = []
        self.commit_calls = 0
        self.rollback_calls = 0
        self.deleted: list[object] = []

    async def get(self, _model: object, _asset_id: uuid.UUID) -> object:
        return self.asset

    async def execute(self, _stmt: object) -> _FakeResult:
        self.executed_statements.append(_stmt)
        self.execute_calls += 1
        if self.execute_calls == 1:
            return _FakeResult(self.quota)
        return _FakeResult(0)

    def add(self, obj: object) -> None:
        if getattr(obj, "id", None) is None:
            setattr(obj, "id", uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"))

    async def flush(self) -> None:
        return None

    async def commit(self) -> None:
        self.commit_calls += 1

    async def rollback(self) -> None:
        self.rollback_calls += 1

    async def delete(self, obj: object) -> None:
        self.deleted.append(obj)


class _CommitAwarePublisher:
    def __init__(self, session: _FakeSession) -> None:
        self.session = session
        self.commit_counts_at_publish: list[int] = []

    async def publish_scan_created(self, **_payload: object) -> str:
        self.commit_counts_at_publish.append(self.session.commit_calls)
        return "stream-id-1"


class _FailingPublisher(_CommitAwarePublisher):
    async def publish_scan_created(self, **_payload: object) -> str:
        self.commit_counts_at_publish.append(self.session.commit_calls)
        raise ConnectionError("redis unavailable")


def _identity_config(
    *,
    scan_type: str,
    asset_type: str,
    asset_target: str,
    config: dict | None,
) -> dict:
    return dict(config or {})


def test_create_scan_commits_before_publish(monkeypatch) -> None:
    from app.services import scan_service

    tenant_id = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
    created_by = uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc")
    asset_id = uuid.UUID("dddddddd-dddd-dddd-dddd-dddddddddddd")
    asset = SimpleNamespace(
        id=asset_id,
        tenant_id=tenant_id,
        is_active=True,
        asset_type="web_app",
        target="https://example.com",
        project_id=uuid.UUID("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"),
    )
    quota = SimpleNamespace(
        tenant_id=tenant_id,
        active_scans=0,
        scans_today=0,
        max_concurrent_scans=5,
        max_daily_scans=50,
    )
    session = _FakeSession(asset=asset, quota=quota)
    publisher = _CommitAwarePublisher(session)

    monkeypatch.setattr(scan_service, "prepare_scan_config", _identity_config)
    monkeypatch.setattr(scan_service, "enforce_safe_scan_config", _identity_config)

    scan = asyncio.run(
        scan_service.create_scan(
            tenant_id=tenant_id,
            created_by=created_by,
            asset_id=asset_id,
            scan_type="full",
            priority="normal",
            config={"profile_id": "external_web_api_v1"},
            idempotency_key=None,
            stream_publisher=publisher,
            session=session,
        )
    )

    assert scan.id == uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    assert session.commit_calls == 1
    assert publisher.commit_counts_at_publish == [1]
    assert quota.active_scans == 1
    assert quota.scans_today == 1


def test_create_scan_reverts_committed_row_when_publish_fails(monkeypatch) -> None:
    from app.services import scan_service

    tenant_id = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
    created_by = uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc")
    asset_id = uuid.UUID("dddddddd-dddd-dddd-dddd-dddddddddddd")
    asset = SimpleNamespace(
        id=asset_id,
        tenant_id=tenant_id,
        is_active=True,
        asset_type="web_app",
        target="https://example.com",
        project_id=uuid.UUID("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"),
    )
    quota = SimpleNamespace(
        tenant_id=tenant_id,
        active_scans=0,
        scans_today=0,
        max_concurrent_scans=5,
        max_daily_scans=50,
    )
    session = _FakeSession(asset=asset, quota=quota)
    publisher = _FailingPublisher(session)

    monkeypatch.setattr(scan_service, "prepare_scan_config", _identity_config)
    monkeypatch.setattr(scan_service, "enforce_safe_scan_config", _identity_config)

    with pytest.raises(RuntimeError, match="Failed to enqueue scan after commit"):
        asyncio.run(
            scan_service.create_scan(
                tenant_id=tenant_id,
                created_by=created_by,
                asset_id=asset_id,
                scan_type="full",
                priority="normal",
                config={"profile_id": "external_web_api_v1"},
                idempotency_key=None,
                stream_publisher=publisher,
                session=session,
            )
        )

    assert publisher.commit_counts_at_publish == [1]
    assert session.commit_calls == 2
    assert session.rollback_calls == 0
    assert len(session.deleted) == 1
    assert quota.active_scans == 0
    assert quota.scans_today == 0


def test_create_scan_locks_quota_row_for_update(monkeypatch) -> None:
    from app.services import scan_service

    tenant_id = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
    created_by = uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc")
    asset_id = uuid.UUID("dddddddd-dddd-dddd-dddd-dddddddddddd")
    asset = SimpleNamespace(
        id=asset_id,
        tenant_id=tenant_id,
        is_active=True,
        asset_type="web_app",
        target="https://example.com",
        project_id=uuid.UUID("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"),
    )
    quota = SimpleNamespace(
        tenant_id=tenant_id,
        active_scans=0,
        scans_today=0,
        max_concurrent_scans=5,
        max_daily_scans=50,
    )
    session = _FakeSession(asset=asset, quota=quota)
    publisher = _CommitAwarePublisher(session)

    monkeypatch.setattr(scan_service, "prepare_scan_config", _identity_config)
    monkeypatch.setattr(scan_service, "enforce_safe_scan_config", _identity_config)

    asyncio.run(
        scan_service.create_scan(
            tenant_id=tenant_id,
            created_by=created_by,
            asset_id=asset_id,
            scan_type="full",
            priority="normal",
            config={"profile_id": "external_web_api_v1"},
            idempotency_key=None,
            stream_publisher=publisher,
            session=session,
        )
    )

    quota_stmt = session.executed_statements[0]
    assert getattr(quota_stmt, "_for_update_arg", None) is not None
