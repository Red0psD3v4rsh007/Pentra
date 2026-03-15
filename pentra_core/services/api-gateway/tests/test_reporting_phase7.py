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
    assert "## Remediation Plan" in markdown
    assert "## Grouped Findings" in markdown
