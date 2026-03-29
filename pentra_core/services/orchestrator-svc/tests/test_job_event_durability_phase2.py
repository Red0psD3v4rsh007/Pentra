from __future__ import annotations

import asyncio
import json
import os
import sys
import uuid


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


class _FakeRedis:
    def __init__(self, trace: list[str] | None = None) -> None:
        self.trace = trace
        self.acks: list[tuple[str, str, str]] = []
        self.set_calls: list[tuple[str, str, int | None]] = []

    async def xack(self, stream: str, group: str, msg_id: str) -> int:
        self.acks.append((stream, group, msg_id))
        return 1

    async def get(self, _key: str) -> str | None:
        return None

    async def set(self, key: str, value: str, ex: int | None = None) -> bool:
        if self.trace is not None:
            self.trace.append(f"redis.set:{key}")
        self.set_calls.append((key, value, ex))
        return True


class _FakeSession:
    def __init__(self, trace: list[str]) -> None:
        self.trace = trace

    async def execute(self, _stmt: object) -> None:
        self.trace.append("session.execute")

    async def commit(self) -> None:
        self.trace.append("session.commit")


class _FakeSessionFactory:
    def __init__(self, trace: list[str]) -> None:
        self._trace = trace

    def __call__(self) -> "_FakeSessionFactory":
        return self

    async def __aenter__(self) -> _FakeSession:
        return _FakeSession(self._trace)

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False


class _FakeConcurrency:
    def __init__(self, trace: list[str]) -> None:
        self.trace = trace

    async def is_event_processed(self, _event_id: str) -> bool:
        return False

    async def acquire_scan_lock(
        self,
        scan_id: uuid.UUID,
        holder: str = "orchestrator",
    ) -> bool:
        self.trace.append(f"lock.acquire:{scan_id}")
        return True

    async def release_scan_lock(
        self,
        scan_id: uuid.UUID,
        holder: str = "orchestrator",
    ) -> bool:
        self.trace.append(f"lock.release:{scan_id}")
        return True

    async def mark_event_processed(self, event_id: str) -> None:
        self.trace.append(f"event.processed:{event_id}")


class _FakeStateManager:
    def __init__(self, session: _FakeSession) -> None:
        self.trace = session.trace

    async def transition_scan(self, scan_id: uuid.UUID, status: str) -> None:
        self.trace.append(f"transition_scan:{scan_id}:{status}")

    async def mark_node_completed(
        self,
        node_id: uuid.UUID,
        output_ref: str,
        output_summary: dict[str, object],
    ) -> dict[str, object]:
        self.trace.append(f"mark_node_completed:{node_id}")
        return {
            "dag_id": uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc"),
            "phase_number": 2,
        }


class _FakePipelineExecutor:
    def __init__(self, session: _FakeSession, redis: _FakeRedis) -> None:
        self._resolver = None
        self._dispatcher = None

    async def execute_after_completion(self, **_kwargs: object) -> dict[str, object]:
        return {
            "dag_status": "running",
            "progress": 55,
        }


class _FakeArtifactBus:
    def __init__(self, session: _FakeSession) -> None:
        self._session = session

    async def process_completed_node(self, **_kwargs: object) -> dict[str, int]:
        return {
            "dynamic_nodes_created": 0,
            "strategy_nodes_created": 0,
            "exploration_nodes_created": 0,
        }


class _FakeEvents:
    async def publish_node_update(self, *args: object, **kwargs: object) -> None:
        return None

    async def publish_progress(self, *args: object, **kwargs: object) -> None:
        return None

    async def publish_status_change(self, *args: object, **kwargs: object) -> None:
        return None


def test_job_event_handler_does_not_ack_handler_failure() -> None:
    from app.events.job_event_handler import JobEventHandler

    redis = _FakeRedis()

    async def fail_completed(_event: dict[str, object]) -> None:
        raise RuntimeError("db unavailable")

    async def noop_failed(_event: dict[str, object]) -> None:
        return None

    handler = JobEventHandler(
        redis=redis,
        consumer_name="orch-test",
        on_completed=fail_completed,
        on_failed=noop_failed,
    )

    asyncio.run(
        handler._process_message(
            "1-0",
            {
                "data": json.dumps(
                    {
                        "event_type": "job.completed",
                        "node_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                    }
                )
            },
        )
    )

    assert redis.acks == []


def test_handle_job_completed_sets_node_cache_after_commit(monkeypatch) -> None:
    from app.services import orchestrator_service

    trace: list[str] = []
    redis = _FakeRedis(trace)
    service = orchestrator_service.OrchestratorService(
        session_factory=_FakeSessionFactory(trace),
        redis=redis,
    )
    service._concurrency = _FakeConcurrency(trace)  # type: ignore[assignment]
    service._events = _FakeEvents()  # type: ignore[assignment]

    monkeypatch.setattr(
        orchestrator_service,
        "StateManager",
        _FakeStateManager,
    )
    monkeypatch.setattr(
        orchestrator_service,
        "PipelineExecutor",
        _FakePipelineExecutor,
    )
    monkeypatch.setattr(
        orchestrator_service,
        "ArtifactBus",
        _FakeArtifactBus,
    )
    async def fake_is_scan_cancelled(_scan_id: uuid.UUID) -> bool:
        return False

    monkeypatch.setattr(service, "_is_scan_cancelled", fake_is_scan_cancelled)

    event = {
        "event_id": "evt-1",
        "scan_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "tenant_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "node_id": "dddddddd-dddd-dddd-dddd-dddddddddddd",
        "output_ref": "artifact://node/output.json",
        "output_summary": {"artifact_type": "nuclei"},
        "tool": "nuclei",
    }

    asyncio.run(service.handle_job_completed(event))

    assert "session.commit" in trace
    commit_index = trace.index("session.commit")
    assert redis.set_calls == [
        (
            "pentra:node_completed:dddddddd-dddd-dddd-dddd-dddddddddddd",
            "1",
            86400,
        )
    ]
    redis_set_index = trace.index(
        "redis.set:pentra:node_completed:dddddddd-dddd-dddd-dddd-dddddddddddd"
    )
    processed_index = trace.index("event.processed:evt-1")
    assert commit_index < redis_set_index
    assert redis_set_index < processed_index
    assert commit_index < processed_index
