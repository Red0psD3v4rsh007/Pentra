from __future__ import annotations

import asyncio
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


class _MappingsResult:
    def __init__(self, rows: list[dict[str, object]]) -> None:
        self._rows = rows

    def mappings(self) -> "_MappingsResult":
        return self

    def all(self) -> list[dict[str, object]]:
        return self._rows


class _RecordingSession:
    def __init__(self) -> None:
        self.sql: list[str] = []
        self.commits = 0
        self.select_rows: list[dict[str, object]] = []

    async def execute(self, stmt: object, params: dict[str, object] | None = None) -> object:
        sql_text = str(stmt)
        self.sql.append(sql_text)
        if "SELECT id FROM scans" in sql_text:
            return _ScalarResult("scan-present")
        if "SELECT s.id AS scan_id" in sql_text:
            return _MappingsResult(self.select_rows)
        return _MappingsResult([])

    async def commit(self) -> None:
        self.commits += 1


class _SessionFactory:
    def __init__(self, session: _RecordingSession) -> None:
        self._session = session

    def __call__(self) -> "_SessionFactory":
        return self

    async def __aenter__(self) -> _RecordingSession:
        return self._session

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False


class _ConcurrencyNoTenantCounters:
    def __init__(self) -> None:
        self.processed: list[str] = []

    async def acquire_scan_lock(
        self,
        scan_id: uuid.UUID,
        holder: str = "orchestrator",
    ) -> bool:
        return True

    async def release_scan_lock(
        self,
        scan_id: uuid.UUID,
        holder: str = "orchestrator",
    ) -> bool:
        return True

    async def is_event_processed(self, _event_id: str) -> bool:
        return False

    async def mark_event_processed(self, event_id: str) -> None:
        self.processed.append(event_id)


class _FakeStateManagerCreate:
    def __init__(self, session: _RecordingSession) -> None:
        self._session = session

    async def transition_scan(self, scan_id: uuid.UUID, status: str) -> None:
        self._session.sql.append(f"transition_scan:{scan_id}:{status}")


class _FakeStateManagerComplete:
    def __init__(self, session: _RecordingSession) -> None:
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
    def __init__(self, session: _RecordingSession) -> None:
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
    def __init__(self, session: _RecordingSession, redis: object) -> None:
        self._session = session

    async def start_pipeline(
        self,
        *,
        dag_id: uuid.UUID,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        target: str,
        priority: str,
    ) -> dict[str, int]:
        return {"dispatched_count": 2}


class _FakeCompleteExecutor:
    def __init__(self, session: _RecordingSession, redis: object) -> None:
        self._resolver = None
        self._dispatcher = None

    async def execute_after_completion(self, **_kwargs: object) -> dict[str, object]:
        return {"dag_status": "completed", "progress": 100}


class _FakeArtifactBus:
    def __init__(self, session: _RecordingSession) -> None:
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


class _FakeRedis:
    async def set(self, key: str, value: str, ex: int | None = None) -> bool:
        return True

    async def get(self, key: str) -> str | None:
        return None


def test_handle_scan_created_no_longer_requires_redis_tenant_counter_methods(monkeypatch) -> None:
    from app.services import orchestrator_service

    session = _RecordingSession()
    service = orchestrator_service.OrchestratorService(
        session_factory=_SessionFactory(session),
        redis=_FakeRedis(),
    )
    service._concurrency = _ConcurrencyNoTenantCounters()  # type: ignore[assignment]

    monkeypatch.setattr(orchestrator_service, "DAGBuilder", _FakeBuilder)
    monkeypatch.setattr(orchestrator_service, "PipelineExecutor", _FakeCreateExecutor)
    monkeypatch.setattr(orchestrator_service, "StateManager", _FakeStateManagerCreate)

    asyncio.run(
        service.handle_scan_created(
            {
                "event_id": "evt-create-1",
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

    assert service._concurrency.processed == ["evt-create-1"]  # type: ignore[attr-defined]
    assert any("transition_scan:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa:validating" in item for item in session.sql)


def test_handle_job_completed_decrements_db_quota_without_redis_counter(monkeypatch) -> None:
    from app.services import orchestrator_service

    session = _RecordingSession()
    service = orchestrator_service.OrchestratorService(
        session_factory=_SessionFactory(session),
        redis=_FakeRedis(),
    )
    service._concurrency = _ConcurrencyNoTenantCounters()  # type: ignore[assignment]
    service._events = _FakeEvents()  # type: ignore[assignment]

    monkeypatch.setattr(orchestrator_service, "StateManager", _FakeStateManagerComplete)
    monkeypatch.setattr(orchestrator_service, "PipelineExecutor", _FakeCompleteExecutor)
    monkeypatch.setattr(orchestrator_service, "ArtifactBus", _FakeArtifactBus)

    async def fake_is_scan_cancelled(_scan_id: uuid.UUID) -> bool:
        return False

    monkeypatch.setattr(service, "_is_scan_cancelled", fake_is_scan_cancelled)

    asyncio.run(
        service.handle_job_completed(
            {
                "event_id": "evt-complete-1",
                "scan_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "tenant_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                "node_id": "dddddddd-dddd-dddd-dddd-dddddddddddd",
                "output_ref": "artifact://node/output.json",
                "output_summary": {"artifact_type": "nuclei"},
                "tool": "nuclei",
            }
        )
    )

    assert service._concurrency.processed == ["evt-complete-1"]  # type: ignore[attr-defined]
    assert any("UPDATE tenant_quotas" in sql for sql in session.sql)


def test_watchdog_decrements_db_quota_when_force_finalizing_stale_scan() -> None:
    from app.engine.scan_watchdog import ScanWatchdog

    session = _RecordingSession()
    session.select_rows = [
        {
            "scan_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "tenant_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "status": "running",
            "total_nodes": 3,
            "active_nodes": 0,
            "completed_nodes": 2,
            "failed_nodes": 1,
            "skipped_nodes": 0,
        }
    ]
    watchdog = ScanWatchdog(_SessionFactory(session), object())  # type: ignore[arg-type]

    recovered = asyncio.run(watchdog._recover_stale_scans())

    assert recovered == 1
    assert any("UPDATE tenant_quotas" in sql for sql in session.sql)
