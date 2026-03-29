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


class _ScalarResult:
    def __init__(self, value: object) -> None:
        self._value = value

    def scalar(self) -> object:
        return self._value

    def scalar_one_or_none(self) -> object:
        return self._value


class _MappingsResult:
    def __init__(self, rows: list[dict[str, object]]) -> None:
        self._rows = rows

    def mappings(self) -> "_MappingsResult":
        return self

    def all(self) -> list[dict[str, object]]:
        return self._rows

    def first(self) -> dict[str, object] | None:
        return self._rows[0] if self._rows else None


class _RecordingRedis:
    def __init__(self, trace: list[str] | None = None) -> None:
        self.trace = trace
        self.xadd_calls: list[tuple[str, str]] = []
        self.xadd_payloads: list[dict[str, object]] = []
        self.lock_holder: str | None = None

    async def xadd(
        self,
        stream: str,
        fields: dict[str, str],
        *,
        id: str = "*",
        maxlen: int | None = None,
        approximate: bool = True,
    ) -> str:
        if self.trace is not None:
            self.trace.append(f"redis.xadd:{stream}:{id}")
        self.xadd_calls.append((stream, id))
        self.xadd_payloads.append(
            {
                "stream": stream,
                "id": id,
                "fields": dict(fields),
            }
        )
        return id

    async def set(
        self,
        key: str,
        value: str,
        *,
        nx: bool | None = None,
        ex: int | None = None,
    ) -> bool:
        if key == "pentra:lock:job_dispatch_relay":
            if nx and self.lock_holder is not None:
                return False
            self.lock_holder = value
            return True
        return True

    async def eval(self, _script: str, _numkeys: int, key: str, holder: str) -> int:
        if key == "pentra:lock:job_dispatch_relay" and self.lock_holder == holder:
            self.lock_holder = None
            return 1
        return 0

    async def get(self, _key: str) -> str | None:
        return None

    async def exists(self, _key: str) -> int:
        return 0


class _DispatchSession:
    def __init__(self, trace: list[str] | None = None) -> None:
        self.trace = trace
        self.sql: list[str] = []
        self.flushes = 0
        self.pending_rows: list[dict[str, object]] = []

    async def execute(self, stmt: object, params: dict[str, object] | None = None) -> object:
        sql_text = str(stmt)
        self.sql.append(sql_text)
        if "SELECT id FROM scans WHERE id = :sid" in sql_text:
            return _ScalarResult("scan-present")
        if "SELECT phase_number FROM scan_phases" in sql_text:
            return _MappingsResult([{"phase_number": 2}])
        if "SELECT id, job_id, worker_stream, payload, created_at" in sql_text:
            return _MappingsResult(self.pending_rows)
        return _MappingsResult([])

    async def flush(self) -> None:
        self.flushes += 1

    async def commit(self) -> None:
        self.sql.append("session.commit")
        if self.trace is not None:
            self.trace.append("session.commit")


class _SessionFactory:
    def __init__(self, session: _DispatchSession) -> None:
        self._session = session

    def __call__(self) -> "_SessionFactory":
        return self

    async def __aenter__(self) -> _DispatchSession:
        return self._session

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False


class _FakeConcurrency:
    def __init__(self, trace: list[str]) -> None:
        self.trace = trace

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

    async def is_event_processed(self, _event_id: str) -> bool:
        return False

    async def mark_event_processed(self, event_id: str) -> None:
        self.trace.append(f"event.processed:{event_id}")


class _FakeStateManagerCreate:
    def __init__(self, session: _DispatchSession) -> None:
        self._session = session

    async def transition_scan(self, scan_id: uuid.UUID, status: str) -> None:
        self._session.sql.append(f"transition_scan:{scan_id}:{status}")


class _FakeStateManagerComplete:
    def __init__(self, session: _DispatchSession) -> None:
        self._session = session

    async def transition_scan(self, scan_id: uuid.UUID, status: str) -> None:
        self._session.sql.append(f"transition_scan:{scan_id}:{status}")

    async def mark_node_completed(
        self,
        node_id: uuid.UUID,
        output_ref: str,
        output_summary: dict[str, object],
    ) -> dict[str, object]:
        return {
            "dag_id": uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc"),
            "phase_number": 2,
        }


class _FakeBuilder:
    def __init__(self, session: _DispatchSession) -> None:
        self._session = session

    async def build_dag(
        self,
        *,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        scan_type: str,
        asset_type: str,
        config: dict[str, object],
    ) -> uuid.UUID:
        return uuid.UUID("dddddddd-dddd-dddd-dddd-dddddddddddd")


class _FakeCreateExecutor:
    def __init__(self, session: _DispatchSession, redis: object) -> None:
        self._session = session

    async def start_pipeline(
        self,
        *,
        dag_id: uuid.UUID,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        target: str,
        priority: str,
    ) -> dict[str, object]:
        return {
            "dispatched_count": 2,
            "dispatched_job_ids": [
                uuid.UUID("11111111-1111-1111-1111-111111111111"),
                uuid.UUID("22222222-2222-2222-2222-222222222222"),
            ],
        }


class _FakeCompleteExecutor:
    def __init__(self, session: _DispatchSession, redis: object) -> None:
        self._resolver = None
        self._dispatcher = None

    async def execute_after_completion(self, **_kwargs: object) -> dict[str, object]:
        return {
            "dag_status": "running",
            "progress": 55,
            "dispatched_job_ids": [
                uuid.UUID("33333333-3333-3333-3333-333333333333"),
            ],
        }


class _FakeArtifactBus:
    def __init__(self, session: _DispatchSession) -> None:
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


def test_job_dispatcher_stages_outbox_without_redis_publish() -> None:
    from app.engine.dependency_resolver import ReadyNode
    from app.engine.job_dispatcher import JobDispatcher

    session = _DispatchSession()
    redis = _RecordingRedis()
    dispatcher = JobDispatcher(session, redis)

    node = ReadyNode(
        node_id=uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        dag_id=uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
        phase_id=uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc"),
        tool="nuclei",
        worker_family="web",
        config={"timeout_seconds": 600, "max_retries": 2},
        input_refs={"targets": "artifact://targets.txt"},
    )

    job_ids = asyncio.run(
        dispatcher.dispatch_nodes(
            [node],
            scan_id=uuid.UUID("dddddddd-dddd-dddd-dddd-dddddddddddd"),
            tenant_id=uuid.UUID("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"),
            target="https://example.com",
            priority="normal",
            config={"rate_limits": {"nuclei_requests_per_minute": 20}},
        )
    )

    assert len(job_ids) == 1
    assert any("INSERT INTO job_dispatch_outbox" in sql for sql in session.sql)
    assert any("UPDATE scan_nodes SET status = 'scheduled'" in sql for sql in session.sql)
    assert redis.xadd_calls == []


def test_publish_pending_jobs_marks_outbox_and_job_as_scheduled() -> None:
    from datetime import datetime, timezone

    from app.engine.job_dispatcher import JobDispatcher

    session = _DispatchSession()
    session.pending_rows = [
        {
            "id": 42,
            "job_id": uuid.UUID("11111111-1111-1111-1111-111111111111"),
            "worker_stream": "pentra:stream:worker:web",
            "payload": {"job_id": "11111111-1111-1111-1111-111111111111"},
            "created_at": datetime(2026, 3, 21, 12, 0, tzinfo=timezone.utc),
        }
    ]
    redis = _RecordingRedis()
    dispatcher = JobDispatcher(session, redis)

    published = asyncio.run(
        dispatcher.publish_pending_jobs_for_tenant(
            limit=10,
            tenant_id=uuid.UUID("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"),
        )
    )

    assert published == 1
    assert redis.xadd_calls == [
        ("pentra:stream:worker:web", "1774094400000-42")
    ]
    payload = json.loads(str(redis.xadd_payloads[0]["fields"]["data"]))
    assert payload["scheduled_at"]
    assert any("UPDATE job_dispatch_outbox" in sql for sql in session.sql)
    assert any("UPDATE scan_jobs" in sql for sql in session.sql)


def test_handle_scan_created_flushes_dispatches_after_commit(monkeypatch) -> None:
    from app.services import orchestrator_service

    trace: list[str] = []
    session = _DispatchSession(trace)
    service = orchestrator_service.OrchestratorService(
        session_factory=_SessionFactory(session),
        redis=_RecordingRedis(trace),
    )
    service._concurrency = _FakeConcurrency(trace)  # type: ignore[assignment]

    monkeypatch.setattr(orchestrator_service, "DAGBuilder", _FakeBuilder)
    monkeypatch.setattr(orchestrator_service, "PipelineExecutor", _FakeCreateExecutor)
    monkeypatch.setattr(orchestrator_service, "StateManager", _FakeStateManagerCreate)

    async def fake_publish_pending_dispatches_best_effort(
        *,
        tenant_id: uuid.UUID | None = None,
        limit: int = 100,
    ) -> int:
        trace.append(f"publish_pending:{tenant_id}:{limit}")
        return limit

    monkeypatch.setattr(
        service,
        "_publish_pending_dispatches_best_effort",
        fake_publish_pending_dispatches_best_effort,
    )

    asyncio.run(
        service.handle_scan_created(
            {
                "event_id": "evt-create-outbox",
                "scan_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "tenant_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                "scan_type": "full",
                "priority": "normal",
                "asset_type": "web_app",
                "target": "https://example.com",
                "config": {},
            }
        )
    )

    commit_index = trace.index("session.commit")
    publish_index = trace.index(
        "publish_pending:bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb:2"
    )
    processed_index = trace.index("event.processed:evt-create-outbox")
    assert commit_index < publish_index
    assert publish_index < processed_index


def test_handle_job_completed_flushes_dispatches_after_commit(monkeypatch) -> None:
    from app.services import orchestrator_service

    trace: list[str] = []
    session = _DispatchSession(trace)
    service = orchestrator_service.OrchestratorService(
        session_factory=_SessionFactory(session),
        redis=_RecordingRedis(trace),
    )
    service._concurrency = _FakeConcurrency(trace)  # type: ignore[assignment]
    service._events = _FakeEvents()  # type: ignore[assignment]

    monkeypatch.setattr(orchestrator_service, "StateManager", _FakeStateManagerComplete)
    monkeypatch.setattr(orchestrator_service, "PipelineExecutor", _FakeCompleteExecutor)
    monkeypatch.setattr(orchestrator_service, "ArtifactBus", _FakeArtifactBus)

    async def fake_is_scan_cancelled(_scan_id: uuid.UUID) -> bool:
        return False

    async def fake_publish_pending_dispatches_best_effort(
        *,
        tenant_id: uuid.UUID | None = None,
        limit: int = 100,
    ) -> int:
        trace.append(f"publish_pending:{tenant_id}:{limit}")
        return limit

    monkeypatch.setattr(service, "_is_scan_cancelled", fake_is_scan_cancelled)
    monkeypatch.setattr(
        service,
        "_publish_pending_dispatches_best_effort",
        fake_publish_pending_dispatches_best_effort,
    )

    asyncio.run(
        service.handle_job_completed(
            {
                "event_id": "evt-complete-outbox",
                "scan_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "tenant_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                "node_id": "dddddddd-dddd-dddd-dddd-dddddddddddd",
                "output_ref": "artifact://node/output.json",
                "output_summary": {"artifact_type": "nuclei"},
                "tool": "nuclei",
            }
        )
    )

    commit_index = trace.index("session.commit")
    publish_index = trace.index(
        "publish_pending:bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb:1"
    )
    processed_index = trace.index("event.processed:evt-complete-outbox")
    assert commit_index < publish_index
    assert publish_index < processed_index
