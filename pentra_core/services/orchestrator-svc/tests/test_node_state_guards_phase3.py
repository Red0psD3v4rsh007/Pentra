from __future__ import annotations

import asyncio
import inspect
import os
import sys
import uuid


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


class _FakeRedis:
    async def get(self, key: str) -> str | None:
        return None

    async def set(self, key: str, value: str, ex: int | None = None) -> bool:
        return True


class _FakeSession:
    def __init__(self) -> None:
        self.commits = 0
        self.executes = 0

    async def execute(self, stmt: object, params: object | None = None) -> None:
        del stmt, params
        self.executes += 1

    async def commit(self) -> None:
        self.commits += 1


class _SessionFactory:
    def __init__(self, session: _FakeSession) -> None:
        self._session = session

    def __call__(self) -> "_SessionFactory":
        return self

    async def __aenter__(self) -> _FakeSession:
        return self._session

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False


class _FakeConcurrency:
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

    async def is_event_processed(self, event_id: str) -> bool:
        return False

    async def mark_event_processed(self, event_id: str) -> None:
        self.processed.append(event_id)


class _DuplicateCompletedStateManager:
    def __init__(self, session: _FakeSession) -> None:
        self._session = session

    async def transition_scan(self, scan_id: uuid.UUID, status: str) -> None:
        return None

    async def mark_node_completed(
        self,
        node_id: uuid.UUID,
        output_ref: str,
        output_summary: dict[str, object],
    ) -> dict[str, object]:
        return {
            "dag_id": uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc"),
            "phase_number": 2,
            "state_changed": False,
            "current_status": "completed",
        }


class _DuplicateFailedStateManager:
    def __init__(self, session: _FakeSession) -> None:
        self._session = session

    async def transition_scan(self, scan_id: uuid.UUID, status: str) -> None:
        return None

    async def mark_node_failed(
        self,
        node_id: uuid.UUID,
        error: str,
        *,
        output_ref: str | None = None,
        output_summary: dict | None = None,
    ) -> dict[str, object]:
        del node_id, error, output_ref, output_summary
        return {
            "dag_id": uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc"),
            "phase_number": 2,
            "retry_count": 0,
            "max_retries": 0,
            "state_changed": False,
            "current_status": "failed",
        }


class _PipelineShouldNotRun:
    def __init__(self, *args: object, **kwargs: object) -> None:
        raise AssertionError("Pipeline executor should not run for stale terminal events")


class _FakeEvents:
    def __init__(self) -> None:
        self.job_updates: list[dict[str, object]] = []
        self.command_updates: list[dict[str, object]] = []
        self.node_updates: list[dict[str, object]] = []

    async def publish_node_update(self, *args: object, **kwargs: object) -> None:
        self.node_updates.append({"args": args, "kwargs": kwargs})

    async def publish_progress(self, *args: object, **kwargs: object) -> None:
        return None

    async def publish_status_change(self, *args: object, **kwargs: object) -> None:
        return None

    async def publish_job_update(self, *args: object, **kwargs: object) -> None:
        self.job_updates.append({"args": args, "kwargs": kwargs})

    async def publish_command_update(self, *args: object, **kwargs: object) -> None:
        self.command_updates.append({"args": args, "kwargs": kwargs})


def test_state_manager_sql_guards_terminal_overwrite_paths() -> None:
    from app.engine.state_manager import StateManager

    completed_source = inspect.getsource(StateManager.mark_node_completed)
    failed_source = inspect.getsource(StateManager.mark_node_failed)

    assert "status IN ('scheduled', 'running')" in completed_source
    assert "status IN ('scheduled', 'running')" in failed_source
    assert "state_changed" in completed_source
    assert "state_changed" in failed_source


def test_handle_job_completed_short_circuits_duplicate_terminal_event(monkeypatch) -> None:
    from app.services import orchestrator_service

    session = _FakeSession()
    service = orchestrator_service.OrchestratorService(
        session_factory=_SessionFactory(session),
        redis=_FakeRedis(),
    )
    service._concurrency = _FakeConcurrency()  # type: ignore[assignment]
    service._events = _FakeEvents()  # type: ignore[assignment]

    monkeypatch.setattr(orchestrator_service, "StateManager", _DuplicateCompletedStateManager)
    monkeypatch.setattr(orchestrator_service, "PipelineExecutor", _PipelineShouldNotRun)

    async def fake_is_scan_cancelled(_scan_id: uuid.UUID) -> bool:
        return False

    monkeypatch.setattr(service, "_is_scan_cancelled", fake_is_scan_cancelled)

    asyncio.run(
        service.handle_job_completed(
            {
                "event_id": "evt-dup-completed",
                "scan_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "tenant_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                "node_id": "dddddddd-dddd-dddd-dddd-dddddddddddd",
                "output_ref": "artifact://node/output.json",
                "output_summary": {"artifact_type": "nuclei"},
                "tool": "nuclei",
            }
        )
    )

    assert service._concurrency.processed == ["evt-dup-completed"]  # type: ignore[attr-defined]
    assert session.commits == 1


def test_handle_job_failed_short_circuits_duplicate_terminal_event(monkeypatch) -> None:
    from app.services import orchestrator_service

    session = _FakeSession()
    service = orchestrator_service.OrchestratorService(
        session_factory=_SessionFactory(session),
        redis=_FakeRedis(),
    )
    service._concurrency = _FakeConcurrency()  # type: ignore[assignment]

    monkeypatch.setattr(orchestrator_service, "StateManager", _DuplicateFailedStateManager)
    monkeypatch.setattr(orchestrator_service, "PipelineExecutor", _PipelineShouldNotRun)

    async def fake_is_scan_cancelled(_scan_id: uuid.UUID) -> bool:
        return False

    monkeypatch.setattr(service, "_is_scan_cancelled", fake_is_scan_cancelled)

    asyncio.run(
        service.handle_job_failed(
            {
                "event_id": "evt-dup-failed",
                "scan_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "tenant_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                "node_id": "dddddddd-dddd-dddd-dddd-dddddddddddd",
                "error_code": "TIMEOUT",
                "error_message": "timed out",
            }
        )
    )

    assert service._concurrency.processed == ["evt-dup-failed"]  # type: ignore[attr-defined]
    assert session.commits == 1


def test_handle_job_failed_persists_and_publishes_failed_execution_log(monkeypatch) -> None:
    from app.services import orchestrator_service

    session = _FakeSession()
    service = orchestrator_service.OrchestratorService(
        session_factory=_SessionFactory(session),
        redis=_FakeRedis(),
    )
    service._concurrency = _FakeConcurrency()  # type: ignore[assignment]
    service._events = _FakeEvents()  # type: ignore[assignment]

    captured: dict[str, object] = {}

    class _RecordingStateManager:
        def __init__(self, _session: _FakeSession) -> None:
            self._session = _session

        async def transition_scan(self, scan_id: uuid.UUID, status: str) -> None:
            del scan_id, status
            return None

        async def mark_node_failed(
            self,
            node_id: uuid.UUID,
            error: str,
            *,
            output_ref: str | None = None,
            output_summary: dict | None = None,
        ) -> dict[str, object]:
            captured["node_id"] = node_id
            captured["error"] = error
            captured["output_ref"] = output_ref
            captured["output_summary"] = output_summary
            return {
                "dag_id": uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc"),
                "phase_number": 3,
                "retry_count": 0,
                "max_retries": 0,
                "state_changed": True,
                "current_status": "failed",
            }

        async def update_scan_progress(self, scan_id: uuid.UUID) -> None:
            del scan_id
            return None

    class _FailurePipelineExecutor:
        def __init__(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

        async def execute_after_failure(self, **kwargs: object) -> dict[str, object]:
            del kwargs
            return {"dag_status": "failed", "dispatched_job_ids": []}

    async def fake_is_scan_cancelled(_scan_id: uuid.UUID) -> bool:
        return False

    monkeypatch.setattr(orchestrator_service, "StateManager", _RecordingStateManager)
    monkeypatch.setattr(orchestrator_service, "PipelineExecutor", _FailurePipelineExecutor)
    monkeypatch.setattr(service, "_is_scan_cancelled", fake_is_scan_cancelled)

    output_summary = {
        "artifact_type": "http_observation",
        "duration_ms": 1450,
        "execution_mode": "controlled_live_external",
        "execution_provenance": "live",
        "execution_reason": None,
        "execution_class": "external_tool",
        "execution_log": {
            "execution_class": "external_tool",
            "command": ["nuclei", "-u", "https://example.com"],
            "stdout_preview": "partial stdout",
            "stderr_preview": "fatal stderr",
            "exit_code": 2,
            "command_artifact_ref": "artifacts/t/cmd.json",
            "full_stdout_artifact_ref": "artifacts/t/stdout.txt",
            "full_stderr_artifact_ref": "artifacts/t/stderr.txt",
        },
    }

    asyncio.run(
        service.handle_job_failed(
            {
                "event_id": "evt-failed-log",
                "job_id": "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
                "scan_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "tenant_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                "node_id": "dddddddd-dddd-dddd-dddd-dddddddddddd",
                "tool": "nuclei",
                "error_code": "EXIT_2",
                "error_message": "fatal stderr",
                "output_ref": "",
                "output_summary": output_summary,
            }
        )
    )

    assert captured["error"] == "fatal stderr"
    assert captured["output_ref"] is None
    assert captured["output_summary"] == output_summary
    assert len(service._events.job_updates) == 1  # type: ignore[attr-defined]
    assert len(service._events.command_updates) == 1  # type: ignore[attr-defined]
    command_kwargs = service._events.command_updates[0]["kwargs"]  # type: ignore[index,attr-defined]
    assert command_kwargs["status"] == "failed"
    assert command_kwargs["execution_class"] == "external_tool"
    assert command_kwargs["command"] == ["nuclei", "-u", "https://example.com"]
    assert command_kwargs["stderr_preview"] == "fatal stderr"
    assert command_kwargs["artifact_ref"] == "artifacts/t/cmd.json"
    assert command_kwargs["command_artifact_ref"] == "artifacts/t/cmd.json"
