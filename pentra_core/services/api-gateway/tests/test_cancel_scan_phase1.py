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


class _FakeSession:
    def __init__(self, quota: object | None) -> None:
        self._quota = quota
        self.flush_calls = 0

    async def flush(self) -> None:
        self.flush_calls += 1

    async def execute(self, _stmt: object) -> _FakeResult:
        return _FakeResult(self._quota)


class _FakeStreamPublisher:
    def __init__(self) -> None:
        self.cancelled_calls: list[dict[str, object]] = []
        self.status_calls: list[dict[str, object]] = []

    async def publish_scan_cancelled(self, **payload: object) -> str:
        self.cancelled_calls.append(payload)
        return "scan-cancelled-1"

    async def publish_scan_status_changed(self, **payload: object) -> str:
        self.status_calls.append(payload)
        return "scan-status-1"


def test_cancel_scan_publishes_durable_cancel_event(monkeypatch) -> None:
    from app.services import scan_service

    scan_id = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    tenant_id = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
    scan = SimpleNamespace(
        id=scan_id,
        status="running",
        error_message=None,
        completed_at=None,
    )
    quota = SimpleNamespace(active_scans=2)
    session = _FakeSession(quota=quota)
    publisher = _FakeStreamPublisher()

    async def fake_get_scan_for_tenant(
        *,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        session: object,
    ) -> object:
        assert session is not None
        assert scan_id == uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        assert tenant_id == uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
        return scan

    monkeypatch.setattr(scan_service, "_get_scan_for_tenant", fake_get_scan_for_tenant)

    result = asyncio.run(
        scan_service.cancel_scan(
            scan_id=scan_id,
            tenant_id=tenant_id,
            stream_publisher=publisher,
            session=session,
        )
    )

    assert result is scan
    assert scan.status == "cancelled"
    assert scan.error_message == "Cancelled by user"
    assert quota.active_scans == 1
    assert session.flush_calls == 2
    assert publisher.cancelled_calls == [
        {
            "scan_id": scan_id,
            "tenant_id": tenant_id,
            "old_status": "running",
        }
    ]
    assert publisher.status_calls == [
        {
            "scan_id": scan_id,
            "tenant_id": tenant_id,
            "old_status": "running",
            "new_status": "cancelled",
        }
    ]
