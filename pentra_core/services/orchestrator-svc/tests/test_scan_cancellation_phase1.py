from __future__ import annotations

import asyncio
import os
import sys
import uuid


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


class _FakeRedis:
    def __init__(self) -> None:
        self.set_calls: list[tuple[str, str, int | None]] = []

    async def set(self, key: str, value: str, ex: int | None = None) -> bool:
        self.set_calls.append((key, value, ex))
        return True


class _FakeConcurrency:
    def __init__(self) -> None:
        self.processed: list[str] = []

    async def is_event_processed(self, _event_id: str) -> bool:
        return False

    async def mark_event_processed(self, event_id: str) -> None:
        self.processed.append(event_id)


class _FakeEventPublisher:
    def __init__(self) -> None:
        self.status_changes: list[tuple[uuid.UUID, str, str]] = []

    async def publish_status_change(
        self,
        scan_id: uuid.UUID,
        old_status: str,
        new_status: str,
    ) -> None:
        self.status_changes.append((scan_id, old_status, new_status))


def test_handle_scan_event_routes_cancelled_events() -> None:
    from app.services.orchestrator_service import OrchestratorService

    service = OrchestratorService(session_factory=None, redis=None)  # type: ignore[arg-type]
    calls: list[tuple[str, str]] = []

    async def fake_handle_scan_cancelled(event: dict[str, str]) -> None:
        calls.append((event["event_type"], event["scan_id"]))

    service.handle_scan_cancelled = fake_handle_scan_cancelled  # type: ignore[method-assign]

    asyncio.run(
        service.handle_scan_event(
            {
                "event_type": "scan.cancelled",
                "scan_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "tenant_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            }
        )
    )

    assert calls == [("scan.cancelled", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")]


def test_handle_scan_cancelled_sets_cancel_flag_and_marks_event_processed() -> None:
    from app.services.orchestrator_service import OrchestratorService

    scan_id = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    redis = _FakeRedis()
    concurrency = _FakeConcurrency()
    events = _FakeEventPublisher()
    service = OrchestratorService(session_factory=None, redis=redis)  # type: ignore[arg-type]
    service._concurrency = concurrency  # type: ignore[assignment]
    service._events = events  # type: ignore[assignment]

    asyncio.run(
        service.handle_scan_cancelled(
            {
                "event_type": "scan.cancelled",
                "event_id": "evt-1",
                "scan_id": str(scan_id),
                "tenant_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                "old_status": "validating",
            }
        )
    )

    assert concurrency.processed == ["evt-1"]
    assert redis.set_calls == [
        (f"pentra:scan:cancelled:{scan_id}", "1", 86400)
    ]
    assert events.status_changes == [
        (scan_id, "validating", "cancelled")
    ]
