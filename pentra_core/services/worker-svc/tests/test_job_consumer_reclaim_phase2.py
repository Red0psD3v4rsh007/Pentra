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
        self.heartbeat_calls: list[tuple[str, str, str, int, tuple[str, ...], int | None, bool]] = []
        self.acks: list[tuple[str, str, str]] = []
        self.deleted: list[str] = []

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

    async def xclaim(
        self,
        stream: str,
        group: str,
        consumer: str,
        min_idle_ms: int,
        message_ids: list[str],
        *,
        idle: int | None = None,
        justid: bool = False,
        **_: object,
    ) -> object:
        self.heartbeat_calls.append(
            (stream, group, consumer, min_idle_ms, tuple(message_ids), idle, justid)
        )
        return list(message_ids)

    async def xack(self, stream: str, group: str, msg_id: str) -> int:
        self.acks.append((stream, group, msg_id))
        return 1

    async def delete(self, key: str) -> int:
        self.deleted.append(key)
        return 1

    async def get(self, key: str) -> None:
        del key
        return None

    async def incr(self, key: str) -> int:
        del key
        return 1

    async def expire(self, key: str, seconds: int) -> bool:
        del key, seconds
        return True


def test_reclaim_idle_messages_processes_claimed_entries(monkeypatch) -> None:
    from app.events.job_consumer import JobConsumer, CG_WORKERS, RECLAIM_BATCH_SIZE, RECLAIM_IDLE_MS

    claimed_entries = [
        ("1-0", {"data": '{"job_id":"job-1"}'}),
        ("2-0", {"data": '{"job_id":"job-2"}'}),
    ]
    redis = _FakeRedis(("0-0", claimed_entries, []))
    processed: list[str] = []

    async def noop_handler(payload: dict[str, object]) -> None:
        return None

    consumer = JobConsumer(redis=redis, family="web", handler=noop_handler)

    async def fake_process_message(msg_id: str, fields: dict[str, str]) -> None:
        processed.append(msg_id)

    monkeypatch.setattr(consumer, "_process_message", fake_process_message)

    reclaimed = asyncio.run(consumer._reclaim_idle_messages())

    assert reclaimed == 2
    assert processed == ["1-0", "2-0"]
    assert redis.calls == [
        (
            "pentra:stream:worker:web",
            CG_WORKERS,
            consumer._consumer_name,
            RECLAIM_IDLE_MS,
            "0-0",
            RECLAIM_BATCH_SIZE,
        )
    ]


def test_reclaim_idle_messages_returns_zero_when_nothing_claimed() -> None:
    from app.events.job_consumer import JobConsumer

    redis = _FakeRedis(("0-0", [], []))

    async def noop_handler(payload: dict[str, object]) -> None:
        return None

    consumer = JobConsumer(redis=redis, family="recon", handler=noop_handler)

    reclaimed = asyncio.run(consumer._reclaim_idle_messages())

    assert reclaimed == 0


def test_process_message_heartbeats_in_flight_jobs(monkeypatch) -> None:
    import app.events.job_consumer as job_consumer
    from app.events.job_consumer import CG_WORKERS, JobConsumer

    redis = _FakeRedis(("0-0", [], []))
    processed: list[str] = []

    async def handler(payload: dict[str, object]) -> None:
        processed.append(str(payload["job_id"]))
        await asyncio.sleep(0.03)

    consumer = JobConsumer(redis=redis, family="web", handler=handler)
    consumer._running = True
    monkeypatch.setattr(job_consumer, "HEARTBEAT_INTERVAL_MS", 10)

    asyncio.run(
        consumer._process_message(
            "1-0",
            {"data": '{"job_id":"job-1","scan_id":"scan-1","tool":"httpx_probe"}'},
        )
    )

    assert processed == ["job-1"]
    assert redis.acks == [("pentra:stream:worker:web", CG_WORKERS, "1-0")]
    assert redis.deleted == ["pentra:redelivery:1-0"]
    assert redis.heartbeat_calls
    stream, group, consumer_name, min_idle_ms, message_ids, idle, justid = redis.heartbeat_calls[0]
    assert stream == "pentra:stream:worker:web"
    assert group == CG_WORKERS
    assert consumer_name == consumer.consumer_name
    assert min_idle_ms == 0
    assert message_ids == ("1-0",)
    assert idle == 0
    assert justid is True
