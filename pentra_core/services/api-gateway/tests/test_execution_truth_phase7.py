from __future__ import annotations

import asyncio
import os
import sys
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

from pentra_common.storage.artifacts import write_json_artifact, write_text_artifact


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


class _Result:
    def __init__(self, rows: list[dict[str, object]] | None = None) -> None:
        self._rows = rows or []

    def mappings(self) -> "_Result":
        return self

    def all(self) -> list[dict[str, object]]:
        return self._rows


class _FakeSession:
    def __init__(self, rows: list[dict[str, object]]) -> None:
        self._rows = rows

    async def execute(self, _stmt: object, _params: dict[str, object] | None = None) -> _Result:
        return _Result(self._rows)


def test_list_scan_jobs_normalizes_derived_phase_truth(monkeypatch) -> None:
    from app.services import scan_service

    async def fake_get_scan_for_tenant(**_kwargs: object) -> object:
        return object()

    monkeypatch.setattr(scan_service, "_get_scan_for_tenant", fake_get_scan_for_tenant)

    rows = [
        {
            "id": uuid.UUID("11111111-1111-1111-1111-111111111111"),
            "scan_id": uuid.UUID("22222222-2222-2222-2222-222222222222"),
            "node_id": uuid.UUID("99999999-9999-9999-9999-999999999999"),
            "phase": 5,
            "tool": "ai_triage",
            "status": "completed",
            "priority": "normal",
            "worker_id": None,
            "output_ref": "artifacts/test.json",
            "scheduled_at": None,
            "claimed_at": None,
            "started_at": None,
            "completed_at": None,
            "error_message": None,
            "retry_count": 0,
            "created_at": None,
            "output_summary": {
                "execution_mode": "controlled_live_local",
                "execution_provenance": "blocked",
                "execution_reason": "not_supported",
            },
        }
    ]

    jobs = asyncio.run(
        scan_service.list_scan_jobs(
            scan_id=uuid.UUID("22222222-2222-2222-2222-222222222222"),
            tenant_id=uuid.UUID("33333333-3333-3333-3333-333333333333"),
            session=_FakeSession(rows),  # type: ignore[arg-type]
        )
    )

    assert jobs == [
        {
            "id": uuid.UUID("11111111-1111-1111-1111-111111111111"),
            "scan_id": uuid.UUID("22222222-2222-2222-2222-222222222222"),
            "node_id": uuid.UUID("99999999-9999-9999-9999-999999999999"),
            "phase": 5,
            "tool": "ai_triage",
            "status": "completed",
            "priority": "normal",
            "worker_id": None,
            "output_ref": "artifacts/test.json",
            "scheduled_at": None,
            "claimed_at": None,
            "started_at": None,
            "completed_at": None,
            "error_message": None,
            "retry_count": 0,
            "queue_delay_seconds": None,
            "claim_to_start_seconds": None,
            "execution_duration_seconds": None,
            "end_to_end_seconds": None,
            "execution_mode": "derived",
            "execution_provenance": "derived",
            "execution_reason": "derived_phase",
            "execution_class": "external_tool",
            "policy_state": "derived",
            "created_at": None,
        }
    ]


def test_list_scan_jobs_exposes_timing_boundaries(monkeypatch) -> None:
    from app.services import scan_service

    async def fake_get_scan_for_tenant(**_kwargs: object) -> object:
        return object()

    monkeypatch.setattr(scan_service, "_get_scan_for_tenant", fake_get_scan_for_tenant)

    scheduled_at = datetime(2026, 3, 22, 10, 0, 0, tzinfo=timezone.utc)
    claimed_at = datetime(2026, 3, 22, 10, 0, 2, tzinfo=timezone.utc)
    started_at = datetime(2026, 3, 22, 10, 0, 5, tzinfo=timezone.utc)
    completed_at = datetime(2026, 3, 22, 10, 0, 12, tzinfo=timezone.utc)

    rows = [
        {
            "id": uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            "scan_id": uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            "node_id": uuid.UUID("dddddddd-dddd-dddd-dddd-dddddddddddd"),
            "phase": 2,
            "tool": "nuclei",
            "status": "completed",
            "priority": "normal",
            "worker_id": "worker-web-123",
            "output_ref": "artifacts/nuclei.json",
            "scheduled_at": scheduled_at,
            "claimed_at": claimed_at,
            "started_at": started_at,
            "completed_at": completed_at,
            "error_message": None,
            "retry_count": 0,
            "created_at": scheduled_at,
            "output_summary": {},
        }
    ]

    jobs = asyncio.run(
        scan_service.list_scan_jobs(
            scan_id=uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            tenant_id=uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc"),
            session=_FakeSession(rows),  # type: ignore[arg-type]
        )
    )

    assert jobs == [
        {
            "id": uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            "scan_id": uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            "node_id": uuid.UUID("dddddddd-dddd-dddd-dddd-dddddddddddd"),
            "phase": 2,
            "tool": "nuclei",
            "status": "completed",
            "priority": "normal",
            "worker_id": "worker-web-123",
            "output_ref": "artifacts/nuclei.json",
            "scheduled_at": scheduled_at,
            "claimed_at": claimed_at,
            "started_at": started_at,
            "completed_at": completed_at,
            "error_message": None,
            "retry_count": 0,
            "queue_delay_seconds": 2.0,
            "claim_to_start_seconds": 3.0,
            "execution_duration_seconds": 7.0,
            "end_to_end_seconds": 12.0,
            "execution_mode": None,
            "execution_provenance": None,
            "execution_reason": None,
            "execution_class": "external_tool",
            "policy_state": "auto_live",
            "created_at": scheduled_at,
        }
    ]


def test_artifact_execution_helpers_normalize_derived_tools() -> None:
    from app.services.scan_service import (
        _artifact_execution_mode,
        _artifact_execution_provenance,
        _artifact_execution_reason,
    )

    metadata = {
        "tool": "report_gen",
        "execution_mode": "controlled_live_local",
        "execution_provenance": "blocked",
        "execution_reason": "not_supported",
    }

    assert _artifact_execution_mode("report_gen", metadata) == "derived"
    assert _artifact_execution_provenance("report_gen", metadata) == "derived"
    assert _artifact_execution_reason(metadata) == "derived_phase"


def test_get_scan_tool_logs_surfaces_failed_execution_log(monkeypatch) -> None:
    from app.services import scan_service

    async def fake_get_scan_for_tenant(**_kwargs: object) -> object:
        return object()

    monkeypatch.setattr(scan_service, "_get_scan_for_tenant", fake_get_scan_for_tenant)

    rows = [
        {
            "node_id": uuid.UUID("11111111-1111-1111-1111-111111111111"),
            "tool": "nuclei",
            "worker_family": "web",
            "status": "failed",
            "output_summary": {
                "duration_ms": 820,
                "execution_mode": "controlled_live_external",
                "execution_provenance": "live",
                "execution_reason": "exit_2",
                "execution_class": "external_tool",
                "execution_log": {
                    "execution_class": "external_tool",
                    "command": ["nuclei", "-u", "https://example.com"],
                    "stdout_preview": "stdout preview",
                    "stderr_preview": "stderr preview",
                    "exit_code": 2,
                    "full_stdout_artifact_ref": "artifacts/t/stdout.txt",
                    "full_stderr_artifact_ref": "artifacts/t/stderr.txt",
                    "command_artifact_ref": "artifacts/t/command.json",
                },
            },
            "phase_number": 4,
            "phase_name": "verification",
            "job_id": uuid.UUID("22222222-2222-2222-2222-222222222222"),
            "job_status": "failed",
            "output_ref": None,
            "started_at": None,
            "completed_at": None,
            "error_message": "stderr preview",
        }
    ]

    logs = asyncio.run(
        scan_service.get_scan_tool_logs(
            scan_id=uuid.UUID("33333333-3333-3333-3333-333333333333"),
            tenant_id=uuid.UUID("44444444-4444-4444-4444-444444444444"),
            session=_FakeSession(rows),  # type: ignore[arg-type]
        )
    )

    assert logs is not None
    assert logs["total"] == 1
    entry = logs["logs"][0]
    assert entry["status"] == "failed"
    assert entry["execution_class"] == "external_tool"
    assert entry["command"] == ["nuclei", "-u", "https://example.com"]
    assert entry["stderr_preview"] == "stderr preview"
    assert entry["full_stdout_artifact_ref"] == "artifacts/t/stdout.txt"
    assert entry["full_stderr_artifact_ref"] == "artifacts/t/stderr.txt"
    assert entry["command_artifact_ref"] == "artifacts/t/command.json"
    assert entry["runtime_stage"] == "failed"
    assert entry["stream_complete"] is True


def test_get_scan_tool_logs_defaults_missing_execution_truth(monkeypatch) -> None:
    from app.services import scan_service

    async def fake_get_scan_for_tenant(**_kwargs: object) -> object:
        return object()

    monkeypatch.setattr(scan_service, "_get_scan_for_tenant", fake_get_scan_for_tenant)

    rows = [
        {
            "node_id": uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            "tool": "web_interact",
            "worker_family": "web",
            "status": "completed",
            "output_summary": {},
            "phase_number": 2,
            "phase_name": "discovery",
            "job_id": uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            "job_status": "completed",
            "output_ref": None,
            "started_at": None,
            "completed_at": None,
            "error_message": None,
        }
    ]

    logs = asyncio.run(
        scan_service.get_scan_tool_logs(
            scan_id=uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc"),
            tenant_id=uuid.UUID("dddddddd-dddd-dddd-dddd-dddddddddddd"),
            session=_FakeSession(rows),  # type: ignore[arg-type]
        )
    )

    assert logs is not None
    entry = logs["logs"][0]
    assert entry["execution_mode"] == "unknown"
    assert entry["execution_provenance"] == "unknown"
    assert entry["execution_class"] == "pentra_native"


def test_get_scan_tool_logs_reads_live_execution_artifacts_for_running_jobs(monkeypatch) -> None:
    from app.services import scan_service

    scan_id = uuid.UUID("11111111-1111-1111-1111-111111111111")
    tenant_id = uuid.UUID("22222222-2222-2222-2222-222222222222")
    node_id = uuid.UUID("33333333-3333-3333-3333-333333333333")
    job_id = uuid.UUID("44444444-4444-4444-4444-444444444444")

    async def fake_get_scan_for_tenant(**_kwargs: object) -> object:
        return SimpleNamespace(config={"execution": {"mode": "controlled_live_external"}})

    monkeypatch.setattr(scan_service, "_get_scan_for_tenant", fake_get_scan_for_tenant)

    command_ref = f"artifacts/{tenant_id}/{scan_id}/{node_id}/execution_logs/httpx_probe_command.json"
    stdout_ref = f"artifacts/{tenant_id}/{scan_id}/{node_id}/execution_logs/httpx_probe_stdout.txt"
    session_ref = f"artifacts/{tenant_id}/{scan_id}/{node_id}/execution_logs/httpx_probe_session.json"
    write_json_artifact(
        command_ref,
        {
            "command": ["httpx", "-l", "/work/input/httpx_targets.txt", "-json"],
            "display_command": "httpx -l /work/input/httpx_targets.txt -json",
            "canonical_command": {
                "argv": ["httpx", "-l", "/work/input/httpx_targets.txt", "-json"],
                "display_command": "httpx -l /work/input/httpx_targets.txt -json",
                "tool_binary": "httpx",
                "container_image": "projectdiscovery/httpx:latest",
                "entrypoint": [],
                "working_dir": "/work/output",
                "channel": "container",
                "execution_class": "external_tool",
                "policy_state": "auto_live",
            },
        },
    )
    write_text_artifact(stdout_ref, "http://example.com [200] [Example Domain]\n")
    write_json_artifact(
        session_ref,
        {
            "status": "running",
            "runtime_stage": "command_resolved",
            "last_chunk_at": datetime.now(timezone.utc).isoformat(),
            "stream_complete": False,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "frames": [
                {
                    "channel": "command",
                    "chunk_seq": 0,
                    "chunk_text": "httpx -l /work/input/httpx_targets.txt -json",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "artifact_ref": command_ref,
                }
            ],
            "exit_code": None,
        },
    )

    rows = [
        {
            "node_id": node_id,
            "tool": "httpx_probe",
            "worker_family": "web",
            "status": "scheduled",
            "output_summary": {},
            "phase_number": 1,
            "phase_name": "recon",
            "job_id": job_id,
            "job_status": "running",
            "output_ref": None,
            "started_at": None,
            "completed_at": None,
            "error_message": None,
        }
    ]

    logs = asyncio.run(
        scan_service.get_scan_tool_logs(
            scan_id=scan_id,
            tenant_id=tenant_id,
            session=_FakeSession(rows),  # type: ignore[arg-type]
        )
    )

    assert logs is not None
    entry = logs["logs"][0]
    assert entry["status"] == "running"
    assert entry["execution_mode"] == "controlled_live_external"
    assert entry["execution_provenance"] == "live"
    assert entry["display_command"] == "httpx -l /work/input/httpx_targets.txt -json"
    assert entry["stdout_preview"] == "http://example.com [200] [Example Domain]\n"
    assert entry["command_artifact_ref"] == command_ref
    assert entry["session_artifact_ref"] == session_ref
    assert entry["runtime_stage"] == "command_resolved"
    assert entry["stream_complete"] is False
    assert entry["last_chunk_at"] is not None


def test_execution_summary_from_scan_exposes_derived_count() -> None:
    from app.services.scan_service import _execution_summary_from_scan

    scan = SimpleNamespace(
        result_summary={
            "execution_summary": {
                "live": 7,
                "simulated": 0,
                "blocked": 1,
                "inferred": 2,
                "derived": 2,
            }
        }
    )

    assert _execution_summary_from_scan(scan) == {
        "live": 7,
        "simulated": 0,
        "blocked": 1,
        "inferred": 2,
        "derived": 2,
    }
