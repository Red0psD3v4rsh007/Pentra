from __future__ import annotations

import asyncio
import os
import sys
import uuid
from types import SimpleNamespace


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
    def __init__(
        self,
        *,
        asset: object,
        quota: object | None,
        existing_scan: object | None = None,
    ) -> None:
        self.asset = asset
        self.quota = quota
        self.existing_scan = existing_scan
        self.execute_calls = 0
        self.commit_calls = 0
        self.rollback_calls = 0
        self.added: list[object] = []

    async def get(self, _model: object, _asset_id: uuid.UUID) -> object:
        return self.asset

    async def execute(self, _stmt: object) -> _FakeResult:
        self.execute_calls += 1
        if self.execute_calls == 1:
            return _FakeResult(self.quota)
        if self.execute_calls == 2:
            return _FakeResult(self.existing_scan)
        return _FakeResult(0)

    def add(self, obj: object) -> None:
        self.added.append(obj)
        if getattr(obj, "id", None) is None:
            setattr(obj, "id", uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"))

    async def flush(self) -> None:
        return None

    async def commit(self) -> None:
        self.commit_calls += 1

    async def rollback(self) -> None:
        self.rollback_calls += 1


class _Publisher:
    def __init__(self) -> None:
        self.publish_calls = 0

    async def publish_scan_created(self, **_payload: object) -> str:
        self.publish_calls += 1
        return "stream-id-1"


def _identity_config(
    *,
    scan_type: str,
    asset_type: str,
    asset_target: str,
    config: dict | None,
) -> dict:
    return dict(config or {})


def test_scan_model_exposes_db_backed_idempotency_key() -> None:
    from app.models.scan import Scan

    assert "idempotency_key" in Scan.__table__.c
    unique_index = next(
        index for index in Scan.__table__.indexes if index.name == "uq_scans_idempotency_key"
    )
    assert unique_index.unique is True
    assert [column.name for column in unique_index.columns] == [
        "tenant_id",
        "created_by",
        "asset_id",
        "scan_type",
        "idempotency_key",
    ]


def test_create_scan_returns_existing_idempotent_scan_before_quota_rejection(
    monkeypatch,
) -> None:
    from app.services import scan_service

    tenant_id = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
    created_by = uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc")
    asset_id = uuid.UUID("dddddddd-dddd-dddd-dddd-dddddddddddd")
    existing_scan = SimpleNamespace(
        id=uuid.UUID("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"),
        tenant_id=tenant_id,
        asset_id=asset_id,
        created_by=created_by,
        scan_type="full",
        idempotency_key="req-123",
    )
    asset = SimpleNamespace(
        id=asset_id,
        tenant_id=tenant_id,
        is_active=True,
        asset_type="web_app",
        target="https://example.com",
        project_id=uuid.UUID("ffffffff-ffff-ffff-ffff-ffffffffffff"),
    )
    quota = SimpleNamespace(
        tenant_id=tenant_id,
        active_scans=5,
        scans_today=0,
        max_concurrent_scans=5,
        max_daily_scans=50,
    )
    session = _FakeSession(asset=asset, quota=quota, existing_scan=existing_scan)
    publisher = _Publisher()

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
            idempotency_key="req-123",
            stream_publisher=publisher,
            session=session,
        )
    )

    assert scan is existing_scan
    assert publisher.publish_calls == 0
    assert session.commit_calls == 0
    assert session.added == []


def test_create_scan_persists_idempotency_key_on_new_scan(monkeypatch) -> None:
    from app.services import scan_service

    tenant_id = uuid.UUID("11111111-1111-1111-1111-111111111111")
    created_by = uuid.UUID("22222222-2222-2222-2222-222222222222")
    asset_id = uuid.UUID("33333333-3333-3333-3333-333333333333")
    asset = SimpleNamespace(
        id=asset_id,
        tenant_id=tenant_id,
        is_active=True,
        asset_type="web_app",
        target="https://example.com",
        project_id=uuid.UUID("44444444-4444-4444-4444-444444444444"),
    )
    quota = SimpleNamespace(
        tenant_id=tenant_id,
        active_scans=0,
        scans_today=0,
        max_concurrent_scans=5,
        max_daily_scans=50,
    )
    session = _FakeSession(asset=asset, quota=quota)
    publisher = _Publisher()

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
            idempotency_key="req-456",
            stream_publisher=publisher,
            session=session,
        )
    )

    assert scan.idempotency_key == "req-456"
    assert session.added[0].idempotency_key == "req-456"
    assert publisher.publish_calls == 1
