from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from types import SimpleNamespace


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def _finding(
    *,
    finding_id: str,
    title: str,
    severity: str,
    vulnerability_type: str,
    target: str,
    route_group: str,
    verification_state: str = "detected",
    truth_state: str | None = None,
    truth_summary: dict | None = None,
    confidence: int = 80,
    remediation: str | None = None,
):
    return SimpleNamespace(
        id=finding_id,
        title=title,
        severity=severity,
        confidence=confidence,
        description=f"{title} description",
        remediation=remediation,
        tool_source="custom_poc",
        source_type="scanner" if verification_state == "detected" else "exploit_verify",
        cvss_score=None,
        created_at=datetime(2026, 3, 15, 12, 0, tzinfo=timezone.utc),
        evidence={
            "endpoint": target,
            "target": target,
            "classification": {
                "vulnerability_type": vulnerability_type,
                "route_group": route_group,
                "surface": "web",
                "exploitability": "high",
                "verification_state": verification_state,
                "verification_confidence": confidence,
            },
        },
        vulnerability_type=vulnerability_type,
        verification_state=verification_state,
        verification_confidence=confidence,
        truth_state=truth_state,
        truth_summary=truth_summary,
        exploitability="high",
        surface="web",
    )


def test_build_scan_comparison_tracks_new_resolved_and_escalated():
    from app.services.scan_service import _build_scan_comparison

    baseline_scan = SimpleNamespace(
        id="baseline-scan",
        created_at=datetime(2026, 3, 14, 12, 0, tzinfo=timezone.utc),
        completed_at=datetime(2026, 3, 14, 12, 30, tzinfo=timezone.utc),
        findings=[
            _finding(
                finding_id="f-1",
                title="SQLi on login",
                severity="high",
                vulnerability_type="sql_injection",
                target="https://example.com/api/login",
                route_group="/api/login",
                verification_state="detected",
            ),
            _finding(
                finding_id="f-2",
                title="Legacy IDOR",
                severity="medium",
                vulnerability_type="idor",
                target="https://example.com/api/users/2",
                route_group="/api/users/{id}",
                verification_state="detected",
            ),
        ],
    )
    current_scan = SimpleNamespace(
        id="current-scan",
        created_at=datetime(2026, 3, 15, 12, 0, tzinfo=timezone.utc),
    )
    current_findings = [
        _finding(
            finding_id="f-3",
            title="SQLi on login",
            severity="critical",
            vulnerability_type="sql_injection",
            target="https://example.com/api/login",
            route_group="/api/login",
            verification_state="verified",
            confidence=96,
        ),
        _finding(
            finding_id="f-4",
            title="New workflow bypass",
            severity="high",
            vulnerability_type="workflow_bypass",
            target="https://example.com/checkout/review",
            route_group="/checkout/review",
            verification_state="detected",
        ),
    ]

    comparison = _build_scan_comparison(
        current_scan=current_scan,
        current_findings=current_findings,
        baseline_scan=baseline_scan,
    )

    assert comparison["counts"]["new"] == 1
    assert comparison["counts"]["resolved"] == 1
    assert comparison["counts"]["persistent"] == 1
    assert comparison["counts"]["escalated"] == 1
    assert comparison["new_findings"][0]["vulnerability_type"] == "workflow_bypass"
    assert comparison["resolved_findings"][0]["vulnerability_type"] == "idor"
    assert comparison["escalated_findings"][0]["verification_state"] == "verified"


def test_build_retest_config_carries_targets_and_baseline_id():
    from app.services.scan_service import _build_retest_config

    source_scan = SimpleNamespace(
        id="scan-1",
        config={"profile_id": "external_web_api_v1"},
        findings=[
            _finding(
                finding_id="f-1",
                title="Verified IDOR",
                severity="high",
                vulnerability_type="idor",
                target="https://example.com/api/users/2",
                route_group="/api/users/{id}",
                verification_state="verified",
            )
        ],
    )

    config = _build_retest_config(
        source_scan=source_scan,
        config_overrides={"stateful_testing": {"enabled": True}},
    )

    assert config["profile_id"] == "external_web_api_v1"
    assert config["stateful_testing"]["enabled"] is True
    assert config["retest"]["baseline_scan_id"] == "scan-1"
    assert config["retest"]["targets"][0]["vulnerability_type"] == "idor"


def test_build_report_markdown_includes_phase7_sections():
    from app.services.scan_service import _build_report_markdown

    markdown = _build_report_markdown(
        {
            "scan_id": "scan-1",
            "asset": {
                "name": "Demo API",
                "project_name": "Pentra Demo",
                "asset_type": "api",
                "target": "https://example.com",
            },
            "executive_summary": "Autonomous assessment identified 2 high-risk findings.",
            "severity_counts": {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0},
            "verification_counts": {"verified": 1, "suspected": 0, "detected": 1},
            "verification_summary": {
                "profile_id": "external_web_api_v1",
                "overall": {
                    "total_findings": 2,
                    "verified": 1,
                    "suspected": 0,
                    "detected": 1,
                    "verified_share": 0.5,
                },
                "by_type": [
                    {
                        "vulnerability_type": "sql_injection",
                        "total_findings": 1,
                        "verified": 1,
                        "suspected": 0,
                        "detected": 0,
                        "verified_share": 1.0,
                    },
                    {
                        "vulnerability_type": "workflow_bypass",
                        "total_findings": 1,
                        "verified": 0,
                        "suspected": 0,
                        "detected": 1,
                        "verified_share": 0.0,
                    },
                ],
            },
            "verification_pipeline": {
                "profile_id": "external_web_api_v1",
                "scan_type": "full",
                "overall": {
                    "total_findings": 2,
                    "verified": 1,
                    "reproduced": 0,
                    "queued": 0,
                    "needs_evidence": 1,
                    "rejected": 0,
                    "expired": 0,
                    "verified_share": 0.5,
                    "proof_ready_share": 0.5,
                },
                "by_type": [],
                "queue": [
                    {
                        "finding_id": "finding-2",
                        "title": "Workflow bypass",
                        "queue_state": "needs_evidence",
                        "readiness_reason": "Additional provenance or proof material is required before verification.",
                        "required_actions": [
                            "Attach source, target, and persisted evidence provenance."
                        ],
                    }
                ],
            },
            "comparison": {
                "summary": "Compared with the previous scan, Pentra found 1 new and 1 resolved finding.",
                "counts": {"new": 1, "resolved": 1, "persistent": 1, "escalated": 0},
            },
            "narrative": {
                "summary": "Pentra reached a database access outcome through the login API.",
                "impact": "Database exposure risk remains high.",
                "steps": [{"step": 1, "description": "Reach the login API", "risk": "high"}],
            },
            "remediation_plan": [
                {
                    "title": "Eliminate injectable database queries",
                    "priority": "immediate",
                    "owner_hint": "Backend Engineering",
                    "rationale": "Critical verified sql injection affecting /api/login.",
                    "actions": ["Use parameterized queries."],
                }
            ],
            "finding_groups": [
                {
                    "title": "/api/login",
                    "surface": "api",
                    "findings": [
                        {
                            "title": "SQLi on login",
                            "severity": "critical",
                            "verification_state": "verified",
                            "target": "https://example.com/api/login",
                        }
                    ],
                }
            ],
            "top_findings": [
                {
                    "title": "SQLi on login",
                    "severity": "critical",
                    "verification_state": "verified",
                    "verification_confidence": 96,
                    "description": "Parameter injection confirmed.",
                }
            ],
        }
    )

    assert "## Historical Comparison" in markdown
    assert "## Attack Path Narrative" in markdown
    assert "## Verification Coverage" in markdown
    assert "## Verification Pipeline" in markdown
    assert "## Verification Queue" in markdown
    assert "sql_injection: 1/1 verified (100%)" in markdown
    assert "## Remediation Plan" in markdown
    assert "## Grouped Findings" in markdown


def test_build_verification_summary_groups_by_type_and_profile():
    from app.services.scan_service import _build_verification_summary

    scan = SimpleNamespace(
        scan_type="full",
        config={"profile_id": "external_web_api_v1"},
    )
    findings = [
        _finding(
            finding_id="f-1",
            title="Verified SQLi",
            severity="critical",
            vulnerability_type="sql_injection",
            target="https://example.com/api/login",
            route_group="/api/login",
            verification_state="verified",
            confidence=96,
        ),
        _finding(
            finding_id="f-2",
            title="Workflow bypass",
            severity="high",
            vulnerability_type="workflow_bypass",
            target="https://example.com/checkout/review",
            route_group="/checkout/review",
            verification_state="verified",
            confidence=92,
        ),
        _finding(
            finding_id="f-3",
            title="GraphQL introspection",
            severity="medium",
            vulnerability_type="graphql_introspection",
            target="https://example.com/graphql",
            route_group="/graphql",
            verification_state="detected",
            confidence=80,
        ),
    ]

    summary = _build_verification_summary(scan=scan, findings=findings)

    assert summary["profile_id"] == "external_web_api_v1"
    assert summary["scan_type"] == "full"
    assert summary["overall"]["total_findings"] == 3
    assert summary["overall"]["verified"] == 2
    assert summary["overall"]["verified_share"] == 0.667
    assert summary["by_type"][0]["vulnerability_type"] == "sql_injection"
    workflow_group = next(
        item for item in summary["by_type"] if item["vulnerability_type"] == "workflow_bypass"
    )
    assert workflow_group["verified_share"] == 1.0


def test_build_verification_pipeline_summary_distinguishes_queue_and_reproduced() -> None:
    from app.services.scan_service import _build_verification_pipeline_summary

    scan = SimpleNamespace(
        scan_type="full",
        config={"profile_id": "external_web_api_v1"},
    )
    findings = [
        _finding(
            finding_id="f-1",
            title="Verified SQLi",
            severity="critical",
            vulnerability_type="sql_injection",
            target="https://example.com/api/login",
            route_group="/api/login",
            verification_state="verified",
            truth_state="verified",
            truth_summary={
                "state": "verified",
                "promoted": True,
                "provenance_complete": True,
                "replayable": True,
                "evidence_reference_count": 1,
                "raw_evidence_present": True,
                "scan_job_bound": True,
                "notes": [],
            },
            confidence=96,
        ),
        _finding(
            finding_id="f-2",
            title="Queued workflow bypass",
            severity="high",
            vulnerability_type="workflow_bypass",
            target="https://example.com/checkout/review",
            route_group="/checkout/review",
            verification_state="suspected",
            truth_state="suspected",
            truth_summary={
                "state": "suspected",
                "promoted": False,
                "provenance_complete": True,
                "replayable": False,
                "evidence_reference_count": 1,
                "raw_evidence_present": True,
                "scan_job_bound": True,
                "notes": [],
            },
            confidence=88,
        ),
        _finding(
            finding_id="f-3",
            title="Reproduced auth bypass",
            severity="high",
            vulnerability_type="auth_bypass",
            target="https://example.com/admin",
            route_group="/admin",
            verification_state="verified",
            truth_state="reproduced",
            truth_summary={
                "state": "reproduced",
                "promoted": False,
                "provenance_complete": True,
                "replayable": False,
                "evidence_reference_count": 1,
                "raw_evidence_present": True,
                "scan_job_bound": True,
                "notes": [],
            },
            confidence=90,
        ),
        _finding(
            finding_id="f-4",
            title="Weak detection",
            severity="medium",
            vulnerability_type="idor",
            target="https://example.com/api/users/7",
            route_group="/api/users/{id}",
            verification_state="detected",
            truth_state="observed",
            truth_summary={
                "state": "observed",
                "promoted": False,
                "provenance_complete": False,
                "replayable": False,
                "evidence_reference_count": 0,
                "raw_evidence_present": False,
                "scan_job_bound": False,
                "notes": [],
            },
            confidence=70,
        ),
    ]

    summary = _build_verification_pipeline_summary(scan=scan, findings=findings)

    assert summary["overall"]["verified"] == 1
    assert summary["overall"]["reproduced"] == 1
    assert summary["overall"]["queued"] == 1
    assert summary["overall"]["needs_evidence"] == 1
    assert summary["overall"]["proof_ready_share"] == 0.5
    assert summary["queue"][0]["queue_state"] == "reproduced"
    assert any(item["queue_state"] == "queued" for item in summary["queue"])
    assert any(item["queue_state"] == "needs_evidence" for item in summary["queue"])
