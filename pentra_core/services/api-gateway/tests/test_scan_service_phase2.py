from __future__ import annotations

import os
import sys
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
            "is_false_positive": False,
            "created_at": "2026-03-15T12:00:00+00:00",
        }
    )

    assert payload.vulnerability_type == "auth_bypass"
