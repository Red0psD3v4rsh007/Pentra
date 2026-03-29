from __future__ import annotations

import asyncio
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
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

    def mappings(self) -> "_FakeResult":
        return self

    def all(self) -> list[object]:
        if isinstance(self._value, list):
            return list(self._value)
        return []

    def first(self) -> object:
        if isinstance(self._value, list):
            return self._value[0] if self._value else None
        return self._value


class _FakeSession:
    def __init__(
        self,
        *,
        asset: object | None = None,
        execute_values: list[object] | None = None,
    ) -> None:
        self.asset = asset
        self.execute_values = list(execute_values or [])
        self.flush_calls = 0
        self.commit_calls = 0
        self.rollback_calls = 0
        self.added: list[object] = []

    async def get(self, _model: object, _asset_id: uuid.UUID) -> object:
        return self.asset

    async def execute(self, _stmt: object, _params: object | None = None) -> _FakeResult:
        value = self.execute_values.pop(0) if self.execute_values else 0
        return _FakeResult(value)

    def add(self, obj: object) -> None:
        self.added.append(obj)
        if getattr(obj, "id", None) is None:
            setattr(obj, "id", uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"))

    async def flush(self) -> None:
        self.flush_calls += 1

    async def commit(self) -> None:
        self.commit_calls += 1

    async def rollback(self) -> None:
        self.rollback_calls += 1


class _FakeStreamPublisher:
    def __init__(self) -> None:
        self.created_calls: list[dict[str, object]] = []
        self.resumed_calls: list[dict[str, object]] = []
        self.status_calls: list[dict[str, object]] = []

    async def publish_scan_created(self, **payload: object) -> str:
        self.created_calls.append(payload)
        return "scan-created-1"

    async def publish_scan_resumed(self, **payload: object) -> str:
        self.resumed_calls.append(payload)
        return "scan-resumed-1"

    async def publish_scan_status_changed(self, **payload: object) -> str:
        self.status_calls.append(payload)
        return "scan-status-1"


def _identity_config(
    *,
    scan_type: str,
    asset_type: str,
    asset_target: str,
    config: dict | None,
) -> dict:
    return dict(config or {})


def test_scan_model_exposes_scheduled_at_column() -> None:
    from app.models.scan import Scan

    assert "scheduled_at" in Scan.__table__.c


def test_create_scan_future_schedule_does_not_publish_or_consume_quota(monkeypatch) -> None:
    from app.services import scan_service

    tenant_id = uuid.UUID("11111111-1111-1111-1111-111111111111")
    created_by = uuid.UUID("22222222-2222-2222-2222-222222222222")
    asset_id = uuid.UUID("33333333-3333-3333-3333-333333333333")
    scheduled_at = datetime.now(timezone.utc) + timedelta(hours=2)
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
    session = _FakeSession(asset=asset, execute_values=[quota, 0])
    publisher = _FakeStreamPublisher()

    monkeypatch.setattr(scan_service, "prepare_scan_config", _identity_config)
    monkeypatch.setattr(scan_service, "enforce_safe_scan_config", _identity_config)

    scan = asyncio.run(
        scan_service.create_scan(
            tenant_id=tenant_id,
            created_by=created_by,
            asset_id=asset_id,
            scan_type="full",
            priority="high",
            config={"profile_id": "external_web_api_v1"},
            idempotency_key=None,
            scheduled_at=scheduled_at,
            stream_publisher=publisher,
            session=session,
        )
    )

    assert scan.status == "paused"
    assert scan.scheduled_at == scheduled_at
    assert quota.active_scans == 0
    assert quota.scans_today == 0
    assert publisher.created_calls == []
    assert session.commit_calls == 1


def test_pause_scan_marks_running_scan_paused(monkeypatch) -> None:
    from app.services import scan_service

    scan_id = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    tenant_id = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
    scan = SimpleNamespace(id=scan_id, status="running", progress=58)
    session = _FakeSession()
    publisher = _FakeStreamPublisher()

    async def fake_get_scan_for_tenant_for_update(
        *,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        session: object,
    ) -> object:
        assert scan_id
        assert tenant_id
        assert session is not None
        return scan

    monkeypatch.setattr(
        scan_service,
        "_get_scan_for_tenant_for_update",
        fake_get_scan_for_tenant_for_update,
    )

    result = asyncio.run(
        scan_service.pause_scan(
            scan_id=scan_id,
            tenant_id=tenant_id,
            stream_publisher=publisher,
            session=session,
        )
    )

    assert result is scan
    assert scan.status == "paused"
    assert session.flush_calls == 1
    assert publisher.status_calls == [
        {
            "scan_id": scan_id,
            "tenant_id": tenant_id,
            "old_status": "running",
            "new_status": "paused",
            "progress": 58,
        }
    ]


def test_resume_scheduled_scan_claims_quota_and_publishes_created(monkeypatch) -> None:
    from app.services import scan_service

    scan_id = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
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
    scan = SimpleNamespace(
        id=scan_id,
        tenant_id=tenant_id,
        asset_id=asset_id,
        created_by=created_by,
        scan_type="full",
        priority="high",
        config={"profile_id": "external_web_api_v1"},
        status="paused",
        progress=0,
        started_at=None,
        scheduled_at=datetime.now(timezone.utc) - timedelta(minutes=1),
    )
    quota = SimpleNamespace(
        tenant_id=tenant_id,
        active_scans=0,
        scans_today=0,
        max_concurrent_scans=3,
        max_daily_scans=20,
    )
    session = _FakeSession(asset=asset, execute_values=[quota, 0])
    publisher = _FakeStreamPublisher()

    async def fake_get_scan_for_tenant_for_update(
        *,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        session: object,
    ) -> object:
        return scan

    monkeypatch.setattr(
        scan_service,
        "_get_scan_for_tenant_for_update",
        fake_get_scan_for_tenant_for_update,
    )

    result = asyncio.run(
        scan_service.resume_scan(
            scan_id=scan_id,
            tenant_id=tenant_id,
            resumed_by=created_by,
            stream_publisher=publisher,
            session=session,
        )
    )

    assert result is scan
    assert scan.status == "queued"
    assert quota.active_scans == 1
    assert quota.scans_today == 1
    assert publisher.created_calls[0]["scan_id"] == scan_id
    assert publisher.status_calls == [
        {
            "scan_id": scan_id,
            "tenant_id": tenant_id,
            "old_status": "paused",
            "new_status": "queued",
            "progress": 0,
        }
    ]


def test_resume_running_scan_publishes_resume_event(monkeypatch) -> None:
    from app.services import scan_service

    scan_id = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    tenant_id = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
    resumed_by = uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc")
    asset_id = uuid.UUID("dddddddd-dddd-dddd-dddd-dddddddddddd")
    asset = SimpleNamespace(
        id=asset_id,
        tenant_id=tenant_id,
        is_active=True,
        asset_type="web_app",
        target="https://example.com",
        project_id=uuid.UUID("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"),
    )
    scan = SimpleNamespace(
        id=scan_id,
        tenant_id=tenant_id,
        asset_id=asset_id,
        created_by=resumed_by,
        scan_type="full",
        priority="high",
        config={"profile_id": "external_web_api_v1"},
        status="paused",
        progress=37,
        started_at=datetime.now(timezone.utc) - timedelta(minutes=5),
        scheduled_at=None,
    )
    session = _FakeSession(asset=asset)
    publisher = _FakeStreamPublisher()

    async def fake_get_scan_for_tenant_for_update(
        *,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        session: object,
    ) -> object:
        return scan

    monkeypatch.setattr(
        scan_service,
        "_get_scan_for_tenant_for_update",
        fake_get_scan_for_tenant_for_update,
    )

    result = asyncio.run(
        scan_service.resume_scan(
            scan_id=scan_id,
            tenant_id=tenant_id,
            resumed_by=resumed_by,
            stream_publisher=publisher,
            session=session,
        )
    )

    assert result is scan
    assert scan.status == "running"
    assert publisher.created_calls == []
    assert publisher.resumed_calls == [
        {
            "scan_id": scan_id,
            "tenant_id": tenant_id,
            "old_status": "paused",
            "new_status": "running",
            "resume_mode": "continue",
            "resumed_by": resumed_by,
        }
    ]


def test_activate_due_scheduled_scans_only_returns_due_scan_ids() -> None:
    from app.services import scan_service
    from app.services.scheduled_scan_launcher import ScheduledScanLauncher

    due_scan_id = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

    class _LauncherSessionFactory:
        def __call__(self):
            class _Ctx:
                async def __aenter__(self_nonlocal) -> _FakeSession:
                    return _FakeSession()

                async def __aexit__(self_nonlocal, exc_type, exc, tb) -> None:
                    return None

            return _Ctx()

    async def fake_activate_due_scheduled_scans(
        *,
        stream_publisher: object,
        session: object,
        limit: int = 10,
    ) -> list[uuid.UUID]:
        assert stream_publisher is not None
        assert session is not None
        assert limit > 0
        return [due_scan_id]

    original = scan_service.activate_due_scheduled_scans
    scan_service.activate_due_scheduled_scans = fake_activate_due_scheduled_scans
    try:
        launcher = ScheduledScanLauncher(_LauncherSessionFactory(), _FakeStreamPublisher())
        activated = asyncio.run(launcher._tick())
    finally:
        scan_service.activate_due_scheduled_scans = original

    assert activated == [str(due_scan_id)]
