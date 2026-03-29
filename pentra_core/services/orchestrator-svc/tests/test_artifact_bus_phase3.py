from __future__ import annotations

import asyncio
import os
import sys
import uuid
from unittest.mock import AsyncMock, MagicMock


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def test_merge_finding_record_prefers_stronger_source_and_dedupes_references():
    from app.engine.artifact_bus import _merge_finding_record

    existing = {
        "source_type": "scanner",
        "severity": "high",
        "confidence": 82,
        "title": "SQL Injection in Login Endpoint",
        "cve_id": None,
        "cvss_score": 8.5,
        "description": "Initial detection",
        "remediation": "Use prepared statements.",
        "tool_source": "nuclei",
        "evidence": {
            "storage_ref": "artifacts/scan/nuclei.json",
            "references": [
                {
                    "id": "req-1",
                    "evidence_type": "request",
                    "content_preview": "POST /api/v1/auth/login",
                    "storage_ref": "artifacts/scan/nuclei.json#req-1",
                }
            ],
            "classification": {"exploitability": "medium"},
        },
    }
    candidate = {
        "source_type": "ai_analysis",
        "severity": "critical",
        "confidence": 96,
        "title": "SQL Injection in Login Endpoint",
        "cve_id": None,
        "cvss_score": 9.8,
        "description": "Merged exploit path confirms auth bypass and likely data exposure.",
        "remediation": "Replace string interpolation with parameterized queries.",
        "tool_source": "ai_triage",
        "evidence": {
            "storage_ref": "artifacts/scan/ai_triage.json",
            "references": [
                {
                    "id": "req-1",
                    "evidence_type": "request",
                    "content_preview": "POST /api/v1/auth/login",
                    "storage_ref": "artifacts/scan/nuclei.json#req-1",
                }
            ],
            "classification": {"exploitability": "high"},
        },
    }

    merged = _merge_finding_record(existing=existing, candidate=candidate)

    assert merged["source_type"] == "ai_analysis"
    assert merged["severity"] == "critical"
    assert merged["confidence"] == 96
    assert len(merged["evidence"]["references"]) == 1
    assert merged["evidence"]["classification"]["exploitability"] == "high"
    assert merged["evidence"]["metadata"]["tool_sources"] == ["ai_triage", "nuclei"]


def test_build_verification_queue_candidates_accepts_ai_analysis_with_proof_material():
    from app.engine.artifact_bus import _build_verification_queue_candidates

    candidates = _build_verification_queue_candidates(
        findings=[
            {
                "fingerprint": "finding-fp-1",
                "source_type": "ai_analysis",
                "title": "Possible IDOR in user profile API",
                "severity": "high",
                "confidence": 88,
                "target": "http://127.0.0.1:8088/api/v1/users/7",
                "endpoint": "http://127.0.0.1:8088/api/v1/users/7",
                "tool_source": "ai_triage",
                "vulnerability_type": "idor",
                "evidence": {
                    "target": "http://127.0.0.1:8088/api/v1/users/7",
                    "endpoint": "http://127.0.0.1:8088/api/v1/users/7",
                    "request": "GET /api/v1/users/7",
                    "response": "HTTP/1.1 200\n\n{\"email\":\"demo@example.com\"}",
                    "references": [
                        {
                            "id": "finding-fp-1:response",
                            "evidence_type": "response",
                            "label": "profile response",
                            "storage_ref": "artifacts/scan/ai_triage.json#finding-fp-1:response",
                        }
                    ],
                    "classification": {
                        "vulnerability_type": "idor",
                        "route_group": "/api/v1/users/{id}",
                        "surface": "api",
                        "verification_state": "suspected",
                    },
                },
            }
        ],
        output_ref="artifacts/scan/ai_triage.json",
    )

    assert len(candidates) == 1
    assert candidates[0]["fingerprint"] == "finding-fp-1"
    assert candidates[0]["verification_state"] == "suspected"
    assert candidates[0]["storage_ref"] == "artifacts/scan/ai_triage.json"


def test_build_verification_queue_candidates_skips_terminal_or_evidence_free_findings():
    from app.engine.artifact_bus import _build_verification_queue_candidates

    candidates = _build_verification_queue_candidates(
        findings=[
            {
                "fingerprint": "verified-fp",
                "source_type": "scanner",
                "title": "Already verified SQLi",
                "target": "http://127.0.0.1:8088/api/v1/auth/login",
                "evidence": {
                    "request": "POST /api/v1/auth/login",
                    "classification": {"truth_state": "verified"},
                },
            },
            {
                "fingerprint": "empty-fp",
                "source_type": "scanner",
                "title": "Weak signal",
                "target": "http://127.0.0.1:8088/api/v1/auth/login",
                "evidence": {"classification": {"verification_state": "detected"}},
            },
        ],
        output_ref="artifacts/scan/nuclei.json",
    )

    assert candidates == []


def test_merge_verification_outcome_evidence_rejects_failed_live_verification():
    from app.engine.artifact_bus import _merge_verification_outcome_evidence

    merged = _merge_verification_outcome_evidence(
        existing={
            "target": "http://127.0.0.1:8088/api/v1/users/7",
            "endpoint": "http://127.0.0.1:8088/api/v1/users/7",
            "request": "GET /api/v1/users/7",
            "classification": {"vulnerability_type": "idor", "verification_state": "detected"},
            "metadata": {},
            "references": [],
        },
        source_type="scanner",
        verification_context={
            "vulnerability_type": "idor",
            "request_url": "http://127.0.0.1:8088/api/v1/users/7",
            "finding_fingerprint": "finding-fp-1",
        },
        artifact={
            "summary": {"highlights": ["No sensitive fields were returned."]},
            "metadata": {"execution_provenance": "live"},
            "findings": [],
        },
        output_ref="artifacts/tenant/scan/node/custom_poc.json",
        tool="custom_poc",
        occurred_at="2026-03-23T10:00:00+00:00",
        proof_observed=False,
    )

    assert merged["classification"]["truth_state"] == "rejected"
    assert merged["classification"]["verification_state"] == "detected"
    assert merged["metadata"]["last_verification_outcome"] == "failed"
    assert merged["metadata"]["negative_verification_count"] == 1
    assert merged["references"][0]["evidence_type"] == "negative_verification"


def test_merge_verification_outcome_evidence_promotes_successful_live_verification():
    from app.engine.artifact_bus import _merge_verification_outcome_evidence

    merged = _merge_verification_outcome_evidence(
        existing={
            "target": "http://127.0.0.1:8088/api/v1/auth/login",
            "endpoint": "http://127.0.0.1:8088/api/v1/auth/login",
            "classification": {"vulnerability_type": "sql_injection", "verification_state": "detected"},
            "metadata": {},
            "references": [],
        },
        source_type="scanner",
        verification_context={
            "vulnerability_type": "sql_injection",
            "request_url": "http://127.0.0.1:8088/api/v1/auth/login?id=1",
            "finding_fingerprint": "finding-fp-2",
        },
        artifact={
            "summary": {"highlights": ["Injectable parameter id confirmed."]},
            "metadata": {"execution_provenance": "live"},
            "findings": [
                {
                    "title": "Verified SQL injection",
                    "evidence": {
                        "request": "GET /api/v1/auth/login?id=1",
                        "response": "HTTP/1.1 200\n\nrows: 3",
                        "exploit_result": "Injectable parameter: id | DBMS: PostgreSQL",
                    },
                }
            ],
        },
        output_ref="artifacts/tenant/scan/node/sqlmap_verify.json",
        tool="sqlmap_verify",
        occurred_at="2026-03-23T10:00:00+00:00",
        proof_observed=True,
    )

    assert merged["classification"]["verification_state"] == "verified"
    assert merged["classification"]["verified"] is True
    assert merged["metadata"]["last_verification_outcome"] == "verified"
    assert merged["metadata"]["verified_at"] == "2026-03-23T10:00:00+00:00"
    assert any(ref["evidence_type"] == "verification_artifact" for ref in merged["references"])


def test_process_completed_node_syncs_verified_impact_artifacts_to_source_findings():
    from app.engine.artifact_bus import ArtifactBus

    bus = ArtifactBus.__new__(ArtifactBus)
    bus._session = MagicMock()
    bus._planner = MagicMock()
    bus._planner.plan_exploits = AsyncMock(return_value=[])
    bus._verifier = MagicMock()
    bus._verifier.verify_impact = AsyncMock(return_value=0)
    bus._graph_builder = MagicMock()
    bus._graph_builder.update_incremental = AsyncMock(
        return_value=MagicMock(nodes=[], edges=[])
    )
    bus._load_artifact = AsyncMock(
        return_value={
            "findings": [
                {
                    "title": "Verified stack trace exposure",
                    "vulnerability_type": "stack_trace_exposure",
                    "evidence": {
                        "classification": {
                            "verification_state": "verified",
                            "vulnerability_type": "stack_trace_exposure",
                        }
                    },
                }
            ],
            "items": [],
            "evidence": [],
            "summary": {"highlights": ["Stack trace markers confirmed."]},
            "metadata": {"execution_provenance": "live"},
        }
    )
    bus._load_scan_config = AsyncMock(return_value={})
    bus._persist_findings = AsyncMock(return_value=1)
    bus._refresh_scan_result_summary = AsyncMock()
    bus._sync_verification_outcome_to_findings = AsyncMock(return_value=1)

    result = asyncio.run(
        bus.process_completed_node(
            dag_id=uuid.uuid4(),
            scan_id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
            node_id=uuid.uuid4(),
            tool="custom_poc",
            artifact_type="verified_impact",
            output_ref="artifacts/tenant/scan/node/custom_poc.json",
            output_summary={},
        )
    )

    assert result["verification_outcomes_applied"] == 1
    bus._sync_verification_outcome_to_findings.assert_awaited_once()
