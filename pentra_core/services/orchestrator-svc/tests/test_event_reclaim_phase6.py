from __future__ import annotations

import asyncio
import os
import sys


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


class _FakeRedis:
    def __init__(self, result: object) -> None:
        self.result = result
        self.calls: list[tuple[str, str, str, int, str, int]] = []

    async def xautoclaim(
        self,
        stream: str,
        group: str,
        consumer: str,
        min_idle_ms: int,
        start_id: str,
        *,
        count: int,
    ) -> object:
        self.calls.append((stream, group, consumer, min_idle_ms, start_id, count))
        return self.result


def test_scan_consumer_reclaims_idle_messages(monkeypatch) -> None:
    from app.events.scan_consumer import (
        BATCH_SIZE,
        CG_ORCHESTRATOR,
        RECLAIM_BATCH_SIZE,
        RECLAIM_IDLE_MS,
        STREAM_SCAN_EVENTS,
        ScanConsumer,
    )

    del BATCH_SIZE  # imported to keep the test aligned with the module surface

    claimed_entries = [
        ("1-0", {"data": '{"event_type":"scan.created","scan_id":"scan-1"}'}),
        ("2-0", {"data": '{"event_type":"scan.resumed","scan_id":"scan-2"}'}),
    ]
    redis = _FakeRedis(("0-0", claimed_entries, []))
    processed: list[str] = []

    async def noop_handler(payload: dict[str, object]) -> None:
        return None

    consumer = ScanConsumer(redis=redis, consumer_name="orch-test", handler=noop_handler)

    async def fake_process_message(msg_id: str, fields: dict[str, str]) -> None:
        processed.append(msg_id)

    monkeypatch.setattr(consumer, "_process_message", fake_process_message)

    reclaimed = asyncio.run(consumer._reclaim_idle_messages())

    assert reclaimed == 2
    assert processed == ["1-0", "2-0"]
    assert redis.calls == [
        (
            STREAM_SCAN_EVENTS,
            CG_ORCHESTRATOR,
            "orch-test",
            RECLAIM_IDLE_MS,
            "0-0",
            RECLAIM_BATCH_SIZE,
        )
    ]


def test_job_event_handler_reclaims_idle_messages(monkeypatch) -> None:
    from app.events.job_event_handler import (
        CG_ORCHESTRATOR,
        RECLAIM_BATCH_SIZE,
        RECLAIM_IDLE_MS,
        STREAM_JOB_EVENTS,
        JobEventHandler,
    )

    claimed_entries = [
        ("1-0", {"data": '{"event_type":"job.completed","node_id":"node-1"}'}),
        ("2-0", {"data": '{"event_type":"job.failed","node_id":"node-2"}'}),
    ]
    redis = _FakeRedis(("0-0", claimed_entries, []))
    processed: list[str] = []

    async def noop_handler(event: dict[str, object]) -> None:
        return None

    handler = JobEventHandler(
        redis=redis,
        consumer_name="orch-test",
        on_completed=noop_handler,
        on_failed=noop_handler,
    )

    async def fake_process_message(msg_id: str, fields: dict[str, str]) -> None:
        processed.append(msg_id)

    monkeypatch.setattr(handler, "_process_message", fake_process_message)

    reclaimed = asyncio.run(handler._reclaim_idle_messages())

    assert reclaimed == 2
    assert processed == ["1-0", "2-0"]
    assert redis.calls == [
        (
            STREAM_JOB_EVENTS,
            CG_ORCHESTRATOR,
            "orch-test",
            RECLAIM_IDLE_MS,
            "0-0",
            RECLAIM_BATCH_SIZE,
        )
    ]


def test_scan_consumer_reclaim_returns_zero_when_empty() -> None:
    from app.events.scan_consumer import ScanConsumer

    redis = _FakeRedis(("0-0", [], []))

    async def noop_handler(payload: dict[str, object]) -> None:
        return None

    consumer = ScanConsumer(redis=redis, consumer_name="orch-test", handler=noop_handler)

    reclaimed = asyncio.run(consumer._reclaim_idle_messages())

    assert reclaimed == 0


def test_job_event_handler_reclaim_returns_zero_when_empty() -> None:
    from app.events.job_event_handler import JobEventHandler

    redis = _FakeRedis(("0-0", [], []))

    async def noop_handler(event: dict[str, object]) -> None:
        return None

    handler = JobEventHandler(
        redis=redis,
        consumer_name="orch-test",
        on_completed=noop_handler,
        on_failed=noop_handler,
    )

    reclaimed = asyncio.run(handler._reclaim_idle_messages())

    assert reclaimed == 0
