from __future__ import annotations

import asyncio
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

from pentra_common.storage.artifacts import write_json_artifact


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def _build_scan(*, scan_id: uuid.UUID, profile_id: str) -> SimpleNamespace:
    profile_variant = "field_validation" if profile_id == "external_web_api_field_validation_v1" else "standard"
    asset = SimpleNamespace(
        id=uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        project_id=uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
        name="Authorized Portal",
        target="https://portal.example.com",
        asset_type="web_app",
        description=None,
        project=SimpleNamespace(name="Authorized Targets"),
    )
    return SimpleNamespace(
        id=scan_id,
        asset_id=asset.id,
        asset=asset,
        status="completed",
        scan_type="full",
        config={
            "profile_id": profile_id,
            "profile": {
                "id": profile_id,
                "variant": profile_variant,
            },
            "execution": {
                "allowed_live_tools": ["scope_check", "httpx_probe", "web_interact", "ffuf"],
                "approval_required_tools": ["ffuf", "sqlmap"],
            },
            "execution_contract": {
                "benchmark_inputs_enabled": False,
                "approval_required_tools": ["ffuf", "sqlmap"],
                "live_tools": ["scope_check", "httpx_probe", "web_interact"],
            },
        },
        result_summary={},
        created_at=datetime.now(timezone.utc),
    )


def test_get_scan_field_validation_assessment_reports_real_target_readiness(monkeypatch) -> None:
    from app.services import scan_service

    scan_id = uuid.UUID("11111111-1111-1111-1111-111111111111")
    tenant_id = uuid.UUID("22222222-2222-2222-2222-222222222222")
    scan = _build_scan(
        scan_id=scan_id,
        profile_id="external_web_api_field_validation_v1",
    )

    async def fake_load_report_context(**_: object) -> dict[str, object]:
        return {
            "scan": scan,
            "verification_summary": {
                "overall": {
                    "verified": 0,
                    "suspected": 1,
                    "detected": 2,
                }
            },
            "verification_pipeline": {
                "overall": {
                    "total_findings": 2,
                    "verified": 0,
                    "reproduced": 0,
                    "queued": 0,
                    "needs_evidence": 2,
                    "rejected": 0,
                    "expired": 0,
                },
                "queue": [
                    {
                        "queue_state": "needs_evidence",
                        "readiness_reason": "Replayable request context missing for privileged mutation.",
                    }
                ],
            },
        }

    async def fake_planner_context(**_: object) -> dict[str, object]:
        return {
            "target_profile_hypotheses": [
                {"key": "auth_heavy_admin_portal", "confidence": 0.91, "evidence": ["privileged route indicators"]},
            ],
            "capability_pressures": [
                {"pack_key": "p3a_multi_role_stateful_auth", "pressure_score": 88},
                {"pack_key": "p3a_access_control_workflow_abuse", "pressure_score": 74},
            ],
            "capability_advisories": [
                {
                    "provider": "heuristic",
                    "model": "rule-engine-v1",
                    "fallback_used": True,
                    "error": "openai: quota exceeded",
                    "evidence_gap_priorities": ["verification_context"],
                }
            ],
        }

    monkeypatch.setattr(scan_service, "_load_report_context", fake_load_report_context)
    monkeypatch.setattr(scan_service, "get_scan_planner_context", fake_planner_context)

    payload = asyncio.run(
        scan_service.get_scan_field_validation_assessment(
            scan_id=scan_id,
            tenant_id=tenant_id,
            session=object(),
        )
    )

    assert payload is not None
    assert payload["operating_mode"] == "field_validation"
    assert payload["assessment_state"] == "needs_evidence"
    assert payload["benchmark_inputs_disabled_confirmed"] is True
    assert payload["target_profile_guess"] == "auth_heavy_admin_portal"
    assert payload["selected_capability_packs"] == [
        "p3a_multi_role_stateful_auth",
        "p3a_access_control_workflow_abuse",
    ]
    assert payload["approved_live_tools"] == ["ffuf"]
    assert payload["approval_required_tools"] == ["ffuf", "sqlmap"]
    assert payload["approval_pending_tools"] == ["sqlmap"]
    assert payload["tool_policy_states"] == [
        {"tool": "scope_check", "policy_state": "auto_live"},
        {"tool": "httpx_probe", "policy_state": "auto_live"},
        {"tool": "web_interact", "policy_state": "auto_live"},
        {"tool": "ffuf", "policy_state": "approved"},
        {"tool": "sqlmap", "policy_state": "approval_required"},
    ]
    assert payload["ai_fallback_active"] is True
    assert "verification_context" in payload["evidence_gaps"]


def test_get_field_validation_summary_filters_to_field_validation_scans(monkeypatch) -> None:
    from app.services import scan_service

    tenant_id = uuid.UUID("22222222-2222-2222-2222-222222222222")
    field_scan_id = uuid.UUID("11111111-1111-1111-1111-111111111111")
    standard_scan_id = uuid.UUID("33333333-3333-3333-3333-333333333333")
    field_scan = _build_scan(
        scan_id=field_scan_id,
        profile_id="external_web_api_field_validation_v1",
    )
    standard_scan = _build_scan(
        scan_id=standard_scan_id,
        profile_id="external_web_api_v1",
    )

    class _ExecuteResult:
        def __init__(self, scans: list[SimpleNamespace]) -> None:
            self._scans = scans

        def scalars(self) -> "_ExecuteResult":
            return self

        def all(self) -> list[SimpleNamespace]:
            return self._scans

    class _Session:
        async def execute(self, stmt) -> _ExecuteResult:  # noqa: ANN001
            return _ExecuteResult([field_scan, standard_scan])

    async def fake_load_report_context(**kwargs: object) -> dict[str, object]:
        return {
            "scan": field_scan if kwargs["scan_id"] == field_scan_id else standard_scan,
            "verification_summary": {"overall": {"verified": 1, "suspected": 0, "detected": 1}},
            "verification_pipeline": {
                "overall": {
                    "total_findings": 1,
                    "verified": 1,
                    "reproduced": 0,
                    "queued": 0,
                    "needs_evidence": 0,
                    "rejected": 0,
                    "expired": 0,
                },
                "queue": [],
            },
        }

    async def fake_planner_context(**_: object) -> dict[str, object]:
        return {
            "target_profile_hypotheses": [{"key": "spa_rest_api", "confidence": 0.8, "evidence": ["api and browser surfaces"]}],
            "capability_pressures": [{"pack_key": "p3a_browser_xss", "pressure_score": 61}],
            "capability_advisories": [{"provider": "openai", "model": "gpt-4o-mini", "fallback_used": False}],
        }

    monkeypatch.setattr(scan_service, "_load_report_context", fake_load_report_context)
    monkeypatch.setattr(scan_service, "get_scan_planner_context", fake_planner_context)

    payload = asyncio.run(
        scan_service.get_field_validation_summary(
            tenant_id=tenant_id,
            session=_Session(),
            limit=10,
        )
    )

    assert payload["total_scans"] == 1
    assert payload["by_state"]["verified"] == 1
    assert payload["items"][0]["scan_id"] == field_scan_id
    assert payload["items"][0]["benchmark_inputs_disabled_confirmed"] is True


def test_get_scan_job_session_reads_persisted_session_artifact(monkeypatch) -> None:
    from app.services import scan_service

    scan_id = uuid.uuid4()
    tenant_id = uuid.uuid4()
    job_id = uuid.uuid4()
    session_ref = f"artifacts/test/job_sessions/{uuid.uuid4()}.json"
    write_json_artifact(
        session_ref,
        {
            "runtime_stage": "completed",
            "last_chunk_at": "2026-03-28T00:00:02+00:00",
            "stream_complete": True,
            "frames": [
                {
                    "channel": "command",
                    "chunk_seq": 0,
                    "chunk_text": "$ graphql-cop -t http://127.0.0.1:8088/graphql -o json",
                    "artifact_ref": "artifacts/test/command.json",
                },
                {
                    "channel": "stdout",
                    "chunk_seq": 1,
                    "chunk_text": '[{"name":"GraphQL introspection enabled"}]',
                    "artifact_ref": "artifacts/test/stdout.txt",
                },
            ]
        },
    )

    async def fake_logs(**_: object) -> dict[str, object]:
        return {
            "logs": [
                {
                    "job_id": str(job_id),
                    "node_id": "node-1",
                    "tool": "graphql_cop",
                    "status": "completed",
                    "policy_state": "auto_live",
                    "execution_provenance": "live",
                    "execution_reason": None,
                    "execution_class": "external_tool",
                    "runtime_stage": "completed",
                    "last_chunk_at": "2026-03-28T00:00:02+00:00",
                    "stream_complete": True,
                    "started_at": "2026-03-28T00:00:00+00:00",
                    "completed_at": "2026-03-28T00:00:02+00:00",
                    "exit_code": 0,
                    "command": ["graphql-cop", "-t", "http://127.0.0.1:8088/graphql", "-o", "json"],
                    "command_artifact_ref": "artifacts/test/command.json",
                    "full_stdout_artifact_ref": "artifacts/test/stdout.txt",
                    "full_stderr_artifact_ref": None,
                    "session_artifact_ref": session_ref,
                }
            ]
        }

    monkeypatch.setattr(scan_service, "get_scan_tool_logs", fake_logs)

    payload = asyncio.run(
        scan_service.get_scan_job_session(
            scan_id=scan_id,
            job_id=job_id,
            tenant_id=tenant_id,
            session=object(),
        )
    )

    assert payload is not None
    assert payload["policy_state"] == "auto_live"
    assert payload["execution_class"] == "external_tool"
    assert payload["runtime_stage"] == "completed"
    assert payload["stream_complete"] is True
    assert payload["last_chunk_at"] == "2026-03-28T00:00:02+00:00"
    assert payload["frames"][0]["channel"] == "command"
    assert "graphql" in payload["frames"][0]["chunk_text"]
    assert "introspection" in json.dumps(payload["frames"]).lower()
