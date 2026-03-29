"""Regression tests for live validation findings in the AI strategy artifact path."""

from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path

from app.engine.dependency_resolver import ReadyNode
from app.engine.ai_strategy_advisor import StrategyRecommendation
from app.engine.pipeline_executor import PipelineExecutor
from pentra_common.storage.artifacts import resolve_storage_ref


class _FakeSession:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []
        self.flush_count = 0

    async def execute(self, statement, params=None):  # type: ignore[no-untyped-def]
        self.calls.append(
            {
                "statement": str(statement),
                "params": dict(params or {}),
            }
        )
        return None

    async def flush(self) -> None:
        self.flush_count += 1


def test_store_strategy_artifact_persists_storage_ref(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("ARTIFACT_STORE_PATH", str(tmp_path))

    session = _FakeSession()
    executor = PipelineExecutor(session=session, redis=None)  # type: ignore[arg-type]
    recommendation = StrategyRecommendation(
        recommended_tools=[{"tool_id": "nuclei", "reason": "scan endpoints"}],
        attack_vectors=["sqli"],
        endpoint_focus=["/orders"],
        phase_decision="proceed",
        strategy_notes="Continue with vulnerability scanning.",
        confidence=0.8,
        provider="heuristic",
        model="rule-engine-v1",
        duration_ms=7,
    )

    scan_id = uuid.uuid4()
    tenant_id = uuid.uuid4()

    asyncio.run(
        executor._store_strategy_artifact(
            scan_id=scan_id,
            tenant_id=tenant_id,
            phase_completed=2,
            recommendation=recommendation,
        )
    )

    assert session.flush_count == 1
    assert len(session.calls) == 1

    params = session.calls[0]["params"]
    storage_ref = str(params["ref"])
    assert storage_ref.startswith(f"artifacts/{tenant_id}/{scan_id}/strategy/")
    assert int(params["size_bytes"]) > 0
    assert str(params["checksum"])

    stored_path = resolve_storage_ref(storage_ref, root=tmp_path)
    assert stored_path.exists()

    payload = json.loads(stored_path.read_text())
    assert payload["artifact_type"] == "ai_strategy"
    assert payload["scan_id"] == str(scan_id)
    assert payload["metadata"]["phase_completed"] == 2
    assert payload["recommendation"]["phase_decision"] == "proceed"


def test_store_planner_effect_artifact_persists_storage_ref(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("ARTIFACT_STORE_PATH", str(tmp_path))

    session = _FakeSession()
    executor = PipelineExecutor(session=session, redis=None)  # type: ignore[arg-type]

    scan_id = uuid.uuid4()
    tenant_id = uuid.uuid4()
    dag_id = uuid.uuid4()
    phase_id = uuid.uuid4()

    recommendation = StrategyRecommendation(
        recommended_tools=[{"tool_id": "sqlmap", "reason": "verify login parameter handling"}],
        attack_vectors=["sqli", "auth"],
        endpoint_focus=["https://demo.test/login"],
        phase_decision="proceed",
        strategy_notes="Target the authenticated login flow.",
        confidence=0.84,
        provider="heuristic",
        model="rule-engine-v1",
        duration_ms=12,
    )

    ready_before = [
        ReadyNode(
            node_id=uuid.uuid4(),
            dag_id=dag_id,
            phase_id=phase_id,
            tool="nuclei",
            worker_family="vuln",
            config={},
            input_refs={},
        ),
        ReadyNode(
            node_id=uuid.uuid4(),
            dag_id=dag_id,
            phase_id=phase_id,
            tool="sqlmap",
            worker_family="vuln",
            config={},
            input_refs={},
        ),
        ReadyNode(
            node_id=uuid.uuid4(),
            dag_id=dag_id,
            phase_id=phase_id,
            tool="nikto",
            worker_family="vuln",
            config={},
            input_refs={},
        ),
    ]
    ready_after = [ready_before[1]]
    static_dispatched = [ready_before[1]]

    planner_result = {
        "status": "dispatched",
        "planner_decision": "rebalance_phase",
        "mutation_kind": "rebalance_phase",
        "expected_path_change": "rebalance_phase",
        "planner_actions": [
            {
                "action_type": "deepen_auth_context_probe",
                "route_group": "/login",
                "objective": "Deepen authenticated understanding of /login.",
                "hypothesis": "The login route likely needs stateful follow-up.",
                "rationale": "Target-model pressure is highest on /login.",
                "target_urls": ["https://demo.test/login"],
                "preferred_tool_ids": ["web_interact", "sqlmap"],
                "suppressed_tool_ids": [],
                "prerequisite_evidence": ["target_model_focus"],
                "expected_value": "surface stateful auth pressure more effectively than generic scanning",
                "stop_condition": "stop after bounded route-specific evidence expansion completes",
            },
            {
                "action_type": "pause_noisy_tool_family",
                "route_group": "/login",
                "objective": "Reduce low-value tool noise around /login.",
                "hypothesis": "Generic scanners are too noisy for this phase.",
                "rationale": "Suppress broad scanner work until stronger auth pressure is resolved.",
                "target_urls": ["https://demo.test/login"],
                "preferred_tool_ids": [],
                "suppressed_tool_ids": ["nuclei", "nikto"],
                "prerequisite_evidence": ["low_signal_generic_scanning"],
                "expected_value": "reduce false-positive-heavy work",
                "stop_condition": "resume once stronger target-model pressure exists",
            },
        ],
        "created_node_ids": [str(uuid.uuid4())],
        "job_ids": [str(uuid.uuid4())],
        "dispatched_tools": ["web_interact", "sqlmap"],
        "suppressed_tool_ids": ["nuclei", "nikto"],
        "suppressed_node_ids": [str(ready_before[0].node_id), str(ready_before[2].node_id)],
        "target_model_summary": {
            "route_group_count": 2,
            "auth_surface_count": 3,
            "parameter_count": 4,
            "workflow_edge_count": 6,
            "source_artifact_types": ["endpoints"],
            "has_meaningful_pressure": True,
            "top_focus": {
                "route_group": "/login",
                "focus_score": 13,
                "requires_auth": True,
                "auth_variants": ["admin", "john", "unauthenticated"],
                "parameter_names": ["csrf_token", "password", "username"],
                "endpoint_urls": ["https://demo.test/login"],
                "workflow_edge_count": 6,
                "interaction_kinds": ["form"],
                "safe_replay": True,
                "vulnerability_types": [],
                "truth_counts": {
                    "observed": 0,
                    "suspected": 0,
                    "reproduced": 0,
                    "verified": 0,
                    "rejected": 0,
                    "expired": 0,
                },
                "severity_counts": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                },
                "evidence_gaps": ["parameter_mapping"],
            },
            "route_groups": [],
        },
        "strategic_plan": {
            "decision": "rebalance_phase",
            "objective": "Deepen authenticated understanding and privilege pressure on /login.",
            "rationale": "Target-model pressure is highest on /login.",
            "expected_path_change": "rebalance_phase",
            "recommended_tool_ids": ["web_interact", "sqlmap"],
            "suppressed_tool_ids": ["nuclei", "nikto"],
            "endpoint_focus": ["https://demo.test/login"],
            "attack_vectors": ["sqli", "auth"],
            "actions": [],
            "measurable_effect_expected": True,
        },
        "tactical_plan": {
            "decision": "rebalance_phase",
            "mutation_kind": "rebalance_phase",
            "rationale": "Target-model pressure is highest on /login.",
            "actions": [],
            "planned_followups": [],
            "suppressed_tool_ids": ["nuclei", "nikto"],
            "expected_path_change": "rebalance_phase",
        },
    }

    asyncio.run(
        executor._store_planner_effect_artifact(
            scan_id=scan_id,
            tenant_id=tenant_id,
            phase_completed=2,
            recommendation=recommendation,
            planner_result=planner_result,
            ready_nodes_before_planner=ready_before,
            ready_nodes_after_planner=ready_after,
            static_dispatched_nodes=static_dispatched,
        )
    )

    assert session.flush_count == 1
    assert len(session.calls) == 1

    params = session.calls[0]["params"]
    storage_ref = str(params["ref"])
    assert storage_ref.startswith(f"artifacts/{tenant_id}/{scan_id}/planner_effect/")
    assert int(params["size_bytes"]) > 0
    assert str(params["checksum"])

    stored_path = resolve_storage_ref(storage_ref, root=tmp_path)
    assert stored_path.exists()

    payload = json.loads(stored_path.read_text())
    assert payload["artifact_type"] == "planner_effect"
    assert payload["scan_id"] == str(scan_id)
    assert payload["phase_completed"] == 2
    assert payload["metadata"]["phase_completed"] == 2
    assert payload["target_model_summary"]["top_focus"]["route_group"] == "/login"
    assert payload["strategic_plan"]["decision"] == "rebalance_phase"
    assert payload["mutation_result"]["suppressed_tool_ids"] == ["nuclei", "nikto"]
    assert payload["runtime_effect"]["static_ready_tools_before_planner"] == [
        "nuclei",
        "sqlmap",
        "nikto",
    ]
    assert payload["runtime_effect"]["static_ready_tools_after_planner"] == ["sqlmap"]
    assert payload["runtime_effect"]["static_dispatched_tools"] == ["sqlmap"]
