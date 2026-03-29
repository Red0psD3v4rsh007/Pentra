from __future__ import annotations

import os
import sys
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def test_build_evidence_references_deduplicates_raw_and_reference_entries():
    from app.services.scan_service import _build_evidence_references

    finding = SimpleNamespace(
        id="finding-1",
        title="SQL Injection in Login Endpoint",
        severity="critical",
        tool_source="ai_triage",
        evidence={
            "target": "example.com",
            "endpoint": "https://example.com/api/v1/auth/login",
            "storage_ref": "artifacts/tenant/scan/node/ai_triage.json",
            "request": "POST /api/v1/auth/login",
            "references": [
                {
                    "id": "fingerprint:request",
                    "evidence_type": "request",
                    "label": "SQL Injection in Login Endpoint · request",
                    "content_preview": "POST /api/v1/auth/login",
                    "storage_ref": "artifacts/tenant/scan/node/ai_triage.json#fingerprint:request",
                }
            ],
        },
    )

    evidence = _build_evidence_references([finding])

    assert len(evidence) == 1
    assert evidence[0]["evidence_type"] == "request"
    assert evidence[0]["content"] == "POST /api/v1/auth/login"


def test_build_evidence_references_collapses_duplicate_findings():
    from app.services.scan_service import _build_evidence_references

    shared_evidence = {
        "target": "example.com",
        "endpoint": "https://example.com/api/v1/auth/login",
        "storage_ref": "artifacts/tenant/scan/node/shared.json",
        "payload": "admin' OR '1'='1",
    }
    findings = [
        SimpleNamespace(
            id="finding-1",
            title="SQL Injection in Login Endpoint",
            severity="critical",
            tool_source="nuclei",
            evidence=shared_evidence,
        ),
        SimpleNamespace(
            id="finding-2",
            title="SQL Injection confirmed via sqlmap",
            severity="critical",
            tool_source="sqlmap",
            evidence=shared_evidence,
        ),
    ]

    evidence = _build_evidence_references(findings)

    assert len(evidence) == 1
    assert set(evidence[0]["metadata"]["related_findings"]) == {
        "SQL Injection in Login Endpoint",
        "SQL Injection confirmed via sqlmap",
    }


def test_empty_attack_graph_payload_for_active_scan():
    from app.services.scan_service import _empty_attack_graph_payload

    scan = SimpleNamespace(
        id="scan-1",
        tenant_id="tenant-1",
    )

    payload = _empty_attack_graph_payload(scan)

    assert payload["scan_id"] == "scan-1"
    assert payload["tenant_id"] == "tenant-1"
    assert payload["node_count"] == 0
    assert payload["edge_count"] == 0
    assert payload["path_summary"]["total_paths"] == 0


def test_verification_state_prefers_explicit_classification():
    from app.services.scan_service import _verification_state_for_finding

    finding = SimpleNamespace(
        source_type="scanner",
        verification_state="verified",
    )

    assert _verification_state_for_finding(finding) == "verified"


def test_finding_truth_summary_promotes_only_verified_replayable_proof():
    from app.models.finding import Finding

    finding = Finding(
        scan_job_id="33333333-3333-3333-3333-333333333333",
        source_type="exploit_verify",
        tool_source="sqlmap_verify",
        evidence={
            "target": "example.com",
            "endpoint": "https://example.com/api/v1/login",
            "storage_ref": "artifacts/tenant/scan/node/sqlmap_verify.json",
            "request": "POST /api/v1/login",
            "response": "500 stack trace",
            "references": [
                {
                    "id": "proof:response",
                    "evidence_type": "response",
                    "storage_ref": "artifacts/tenant/scan/node/sqlmap_verify.json#response",
                }
            ],
            "classification": {
                "verification_state": "verified",
            },
            "metadata": {
                "verification_context": {
                    "request_url": "https://example.com/api/v1/login",
                    "http_method": "POST",
                }
            },
        },
    )

    assert finding.truth_state == "verified"
    assert finding.truth_summary["promoted"] is True
    assert finding.truth_summary["provenance_complete"] is True
    assert finding.truth_summary["replayable"] is True


def test_finding_truth_state_reproduced_when_replayability_is_missing():
    from app.models.finding import Finding

    finding = Finding(
        scan_job_id="33333333-3333-3333-3333-333333333333",
        source_type="exploit_verify",
        tool_source="custom_poc",
        evidence={
            "target": "example.com",
            "endpoint": "https://example.com/admin",
            "request": "GET /admin",
            "classification": {
                "verification_state": "verified",
            },
        },
    )

    assert finding.truth_state == "reproduced"
    assert finding.truth_summary["promoted"] is False
    assert finding.truth_summary["replayable"] is False


def test_finding_truth_state_rejects_false_positive_records():
    from app.models.finding import Finding

    finding = Finding(
        source_type="scanner",
        tool_source="nuclei",
        is_false_positive=True,
        evidence={
            "target": "example.com",
            "request": "GET /",
            "classification": {
                "verification_state": "verified",
            },
        },
    )

    assert finding.truth_state == "rejected"
    assert finding.truth_summary["promoted"] is False
    assert any("false positive" in note.lower() for note in finding.truth_summary["notes"])


def test_build_executive_summary_includes_verified_and_suspected_counts():
    from app.services.scan_service import _build_executive_summary

    summary = _build_executive_summary(
        "example.com",
        {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0},
        {"verified": 1, "suspected": 1, "detected": 0},
    )

    assert "1 verified" in summary
    assert "1 suspected" in summary


def test_finding_model_exposes_normalized_vulnerability_type():
    from app.models.finding import Finding
    from pentra_common.schemas.finding import FindingResponse

    finding = Finding(
        title="Authorization bypass confirmed via stateful replay",
        description="Cross-session replay reached privileged content.",
        evidence={
            "classification": {
                "vulnerability_type": "authorization_bypass_confirmed_via_stateful_replay",
            }
        },
    )

    assert finding.vulnerability_type == "auth_bypass"
    payload = FindingResponse.model_validate(
        {
            "id": "11111111-1111-1111-1111-111111111111",
            "scan_id": "22222222-2222-2222-2222-222222222222",
            "source_type": "scanner",
            "title": "Authorization bypass confirmed via stateful replay",
            "severity": "high",
            "confidence": 85,
            "tool_source": "custom_poc",
            "vulnerability_type": finding.vulnerability_type,
            "truth_state": "suspected",
            "truth_summary": {
                "state": "suspected",
                "promoted": False,
                "provenance_complete": False,
                "replayable": False,
                "evidence_reference_count": 0,
                "raw_evidence_present": False,
                "scan_job_bound": False,
                "notes": [],
            },
            "is_false_positive": False,
            "created_at": "2026-03-15T12:00:00+00:00",
        }
    )

    assert payload.vulnerability_type == "auth_bypass"


def test_build_user_facing_findings_merges_verified_proof_into_original_context():
    from app.services.scan_service import _build_user_facing_findings, _finding_target
    from app.models.finding import Finding

    scan_id = uuid.uuid4()
    detected = Finding(
        id=uuid.uuid4(),
        scan_id=scan_id,
        source_type="scanner",
        title="Error: Unexpected path: /api",
        severity="high",
        confidence=84,
        tool_source="web_interact",
        fingerprint="fp-detected",
        created_at=datetime(2026, 3, 24, 7, 55, tzinfo=timezone.utc),
        evidence={
            "endpoint": "http://127.0.0.1:3001/api",
            "request": "GET /api",
            "response": "HTTP/1.1 500",
            "classification": {
                "route_group": "/api",
                "vulnerability_type": "stack_trace_exposure",
                "verification_state": "detected",
            },
            "metadata": {
                "replayable": True,
                "verification_context": {
                    "endpoint": "http://127.0.0.1:3001/api",
                    "route_group": "/api",
                }
            },
        },
    )
    verified = Finding(
        id=uuid.uuid4(),
        scan_id=scan_id,
        source_type="exploit_verify",
        title="Verified stack trace exposure",
        severity="high",
        confidence=94,
        tool_source="custom_poc",
        fingerprint="fp-verified",
        created_at=datetime(2026, 3, 24, 7, 56, tzinfo=timezone.utc),
        evidence={
            "classification": {
                "route_group": "/api",
                "vulnerability_type": "stack_trace_exposure",
                "verification_state": "verified",
            },
            "metadata": {
                "verified_at": "2026-03-24T07:56:06+00:00",
            },
        },
    )

    findings = _build_user_facing_findings([detected, verified], include_rejected=True)

    assert len(findings) == 1
    merged = findings[0]
    assert merged.title == "Verified stack trace exposure"
    assert merged.tool_source == "custom_poc"
    assert merged.verification_state == "verified"
    assert merged.truth_state == "verified"
    assert _finding_target(merged) == "http://127.0.0.1:3001/api"
    assert merged.evidence["metadata"]["duplicate_count"] == 2


def test_build_user_facing_findings_excludes_rejected_false_data_by_default():
    from app.services.scan_service import _build_user_facing_findings
    from app.models.finding import Finding

    finding = Finding(
        id=uuid.uuid4(),
        scan_id=uuid.uuid4(),
        source_type="scanner",
        title="Sensitive API data exposure",
        severity="critical",
        confidence=90,
        tool_source="web_interact",
        fingerprint="fp-rejected",
        created_at=datetime(2026, 3, 24, 7, 56, tzinfo=timezone.utc),
        evidence={
            "endpoint": "http://127.0.0.1:3001/api/Users",
            "classification": {
                "route_group": "/api/users",
                "vulnerability_type": "sensitive_data_exposure",
                "verification_state": "detected",
                "truth_state": "rejected",
            },
            "metadata": {
                "last_verification_outcome": "failed",
            },
        },
    )

    visible = _build_user_facing_findings([finding])
    assert visible == []

    suppressed = _build_user_facing_findings([finding], include_rejected=True)
    assert len(suppressed) == 1
    assert suppressed[0].truth_state == "rejected"
