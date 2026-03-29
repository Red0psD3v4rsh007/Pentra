from __future__ import annotations

import asyncio
import os
import sys
import uuid
from types import SimpleNamespace


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def test_get_scan_planner_context_returns_persisted_planner_and_advisory_state(monkeypatch) -> None:
    from app.services import scan_service

    scan_id = uuid.UUID("11111111-1111-1111-1111-111111111111")
    tenant_id = uuid.UUID("22222222-2222-2222-2222-222222222222")

    planner_effect_artifact = SimpleNamespace(
        storage_ref="artifacts/test/planner_effect.json",
        metadata_={"planner_decision": "focus_auth"},
    )
    advisory_artifact = SimpleNamespace(
        storage_ref="artifacts/test/capability_advisory.json",
        metadata_={"pack_key": "p3a_multi_role_stateful_auth"},
    )

    planner_effect_payload = {
        "target_model_summary": {
            "target_profile_hypotheses": [
                {
                    "key": "auth_heavy_admin_portal",
                    "confidence": 0.88,
                    "evidence": ["privileged route indicators observed"],
                }
            ],
            "capability_pressures": [
                {
                    "pack_key": "p3a_multi_role_stateful_auth",
                    "pressure_score": 74,
                    "planner_action_keys": ["compare_role_access"],
                }
            ],
            "advisory_artifact_refs": [
                {
                    "pack_key": "p3a_multi_role_stateful_auth",
                    "storage_ref": "artifacts/test/capability_advisory.json",
                }
            ],
        },
        "strategic_plan": {
            "decision": "focus_auth",
            "objective": "Compare role access on privileged routes",
            "actions": [
                {
                    "action_type": "compare_role_access",
                    "preferred_tool_ids": ["web_interact"],
                }
            ],
        },
        "tactical_plan": {"mutation_kind": "prefer_role_diff"},
    }
    capability_advisory_payload = {
        "response": {
            "pack_key": "p3a_multi_role_stateful_auth",
            "provider": "openai",
            "model": "gpt-5-mini",
            "focus_items": [{"route_group": "/admin/users"}],
            "evidence_gap_priorities": ["verification"],
        },
        "target_model_summary": {
            "target_profile_hypotheses": [
                {"key": "auth_heavy_admin_portal", "confidence": 0.88}
            ]
        },
    }

    async def fake_get_scan_for_tenant(**_: object) -> SimpleNamespace:
        return SimpleNamespace(id=scan_id)

    async def fake_latest_artifact_by_type(**_: object) -> SimpleNamespace:
        return planner_effect_artifact

    async def fake_latest_capability_advisories(**_: object) -> list[SimpleNamespace]:
        return [advisory_artifact]

    def fake_read_artifact_payload(artifact: SimpleNamespace) -> dict:
        if artifact.storage_ref == planner_effect_artifact.storage_ref:
            return planner_effect_payload
        return capability_advisory_payload

    monkeypatch.setattr(scan_service, "_get_scan_for_tenant", fake_get_scan_for_tenant)
    monkeypatch.setattr(scan_service, "_latest_artifact_by_type", fake_latest_artifact_by_type)
    monkeypatch.setattr(scan_service, "_latest_capability_advisories", fake_latest_capability_advisories)
    monkeypatch.setattr(scan_service, "_read_artifact_payload", fake_read_artifact_payload)

    payload = asyncio.run(
        scan_service.get_scan_planner_context(
            scan_id=scan_id,
            tenant_id=tenant_id,
            session=object(),
        )
    )

    assert payload is not None
    assert payload["scan_id"] == scan_id
    assert payload["planner_decision"] == "focus_auth"
    assert payload["target_profile_hypotheses"][0]["key"] == "auth_heavy_admin_portal"
    assert payload["capability_pressures"][0]["pack_key"] == "p3a_multi_role_stateful_auth"
    assert payload["advisory_artifact_refs"][0]["storage_ref"] == advisory_artifact.storage_ref
    assert payload["strategic_plan"]["actions"][0]["action_type"] == "compare_role_access"
    assert payload["capability_advisories"][0]["provider"] == "openai"
