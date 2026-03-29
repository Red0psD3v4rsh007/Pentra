from __future__ import annotations

import asyncio
import importlib
import os
import sys
import uuid


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def _import_orchestrator_module(module_name: str) -> object:
    for key in list(sys.modules):
        if key == "app" or key.startswith("app."):
            sys.modules.pop(key, None)
    return importlib.import_module(module_name)


class _Result:
    def __init__(self, rows: list[dict[str, object]] | None = None) -> None:
        self._rows = rows or []

    def mappings(self) -> "_Result":
        return self

    def first(self) -> dict[str, object] | None:
        return self._rows[0] if self._rows else None


class _RecordingSession:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object] | None]] = []

    async def execute(self, stmt: object, params: dict[str, object] | None = None) -> _Result:
        sql = str(stmt)
        self.calls.append((sql, params))
        if "SELECT status FROM scans" in sql:
            return _Result([{"status": "running"}])
        return _Result()

    async def flush(self) -> None:
        return None


def test_transition_scan_completed_persists_progress_100() -> None:
    StateManager = _import_orchestrator_module("app.engine.state_manager").StateManager

    session = _RecordingSession()
    state = StateManager(session)  # type: ignore[arg-type]

    asyncio.run(
        state.transition_scan(
            uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            "completed",
        )
    )

    update_calls = [sql for sql, _params in session.calls if "UPDATE scans" in sql]
    assert any("progress = 100" in sql for sql in update_calls)


class _FakeRedis:
    async def get(self, _key: str) -> None:
        return None

    async def set(self, _key: str, _value: str, ex: int | None = None) -> bool:
        return True


class _FakeSessionFactory:
    def __call__(self) -> "_FakeSessionFactory":
        return self

    async def __aenter__(self) -> "_FakeSessionFactory":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False

    async def execute(self, _stmt: object, _params: dict[str, object] | None = None) -> _Result:
        return _Result()

    async def commit(self) -> None:
        return None


class _FakeConcurrency:
    async def is_event_processed(self, _event_id: str) -> bool:
        return False

    async def acquire_scan_lock(
        self,
        _scan_id: uuid.UUID,
        holder: str = "orchestrator",
    ) -> bool:
        return True

    async def release_scan_lock(
        self,
        _scan_id: uuid.UUID,
        holder: str = "orchestrator",
    ) -> bool:
        return True

    async def mark_event_processed(self, _event_id: str) -> None:
        return None


class _FakeStateManager:
    def __init__(self, _session: object) -> None:
        self.transitions: list[tuple[uuid.UUID, str]] = []

    async def transition_scan(self, scan_id: uuid.UUID, status: str) -> None:
        self.transitions.append((scan_id, status))

    async def mark_node_completed(
        self,
        node_id: uuid.UUID,
        output_ref: str,
        output_summary: dict[str, object],
    ) -> dict[str, object]:
        return {
            "dag_id": uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc"),
            "phase_number": 2,
            "state_changed": True,
            "current_status": "completed",
        }


class _FakePipelineExecutor:
    def __init__(self, session: object, redis: object) -> None:
        self._resolver = None
        self._dispatcher = None

    async def execute_after_completion(self, **_kwargs: object) -> dict[str, object]:
        return {
            "dag_status": "completed",
            "progress": 92,
            "dispatched_job_ids": [],
        }


class _FakeArtifactBus:
    def __init__(self, _session: object) -> None:
        return None

    async def process_completed_node(self, **_kwargs: object) -> dict[str, int]:
        return {
            "dynamic_nodes_created": 0,
            "strategy_nodes_created": 0,
            "exploration_nodes_created": 0,
        }


class _FakeEvents:
    def __init__(self) -> None:
        self.progress_calls: list[int] = []

    async def publish_node_update(self, *args: object, **kwargs: object) -> None:
        return None

    async def publish_progress(self, _scan_id: uuid.UUID, progress: int, *args: object, **kwargs: object) -> None:
        self.progress_calls.append(progress)

    async def publish_status_change(self, *args: object, **kwargs: object) -> None:
        return None


def test_handle_job_completed_publishes_terminal_progress_100(monkeypatch) -> None:
    orchestrator_service = _import_orchestrator_module("app.services.orchestrator_service")

    service = orchestrator_service.OrchestratorService(
        session_factory=_FakeSessionFactory(),  # type: ignore[arg-type]
        redis=_FakeRedis(),  # type: ignore[arg-type]
    )
    events = _FakeEvents()
    service._events = events  # type: ignore[assignment]
    service._concurrency = _FakeConcurrency()  # type: ignore[assignment]

    monkeypatch.setattr(orchestrator_service, "StateManager", _FakeStateManager)
    monkeypatch.setattr(orchestrator_service, "PipelineExecutor", _FakePipelineExecutor)
    monkeypatch.setattr(orchestrator_service, "ArtifactBus", _FakeArtifactBus)

    async def _not_cancelled(_scan_id: uuid.UUID) -> bool:
        return False

    async def _noop(*args: object, **kwargs: object) -> None:
        return None

    async def _zero(*args: object, **kwargs: object) -> int:
        return 0

    monkeypatch.setattr(service, "_is_scan_cancelled", _not_cancelled)
    monkeypatch.setattr(service, "_publish_pending_dispatches_best_effort", _zero)
    monkeypatch.setattr(service, "_sync_historical_findings_best_effort", _noop)
    monkeypatch.setattr(service, "_decrement_active_scan_quota", _noop)

    event = {
        "event_id": "evt-phase7",
        "scan_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "tenant_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "node_id": "dddddddd-dddd-dddd-dddd-dddddddddddd",
        "output_ref": "artifacts/test.json",
        "output_summary": {"artifact_type": "nuclei"},
        "tool": "nuclei",
    }

    asyncio.run(service.handle_job_completed(event))

    assert events.progress_calls == [92, 100]
