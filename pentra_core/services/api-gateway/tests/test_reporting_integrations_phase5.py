from __future__ import annotations

import asyncio
import os
import sys
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from pydantic import ValidationError


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def _sample_report() -> dict[str, object]:
    return {
        "scan_id": uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        "report_id": "scan-report:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "generated_at": datetime(2026, 3, 21, 8, 0, tzinfo=timezone.utc),
        "executive_summary": "Pentra confirmed exploitable issues on the target application.",
        "severity_counts": {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0},
        "verification_counts": {"verified": 1, "suspected": 1, "detected": 0},
        "execution_summary": {"live": 3, "simulated": 0, "blocked": 1, "inferred": 2},
        "vulnerability_count": 2,
        "evidence_count": 4,
        "asset": {
            "id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "name": "Demo API",
            "target": "https://demo.example.com",
            "asset_type": "api",
            "project_name": "Customer Zero",
        },
        "narrative": {
            "summary": "Pentra chained authenticated access into a sensitive workflow action.",
            "impact": "An operator could bypass authorization controls on order state transitions.",
            "steps": [
                {
                    "step": 1,
                    "action": "enumeration",
                    "description": "Discovered the privileged order transition endpoint.",
                    "target": "POST /api/orders/approve",
                    "risk": "medium",
                }
            ],
        },
        "comparison": {
            "summary": "Compared with the previous baseline, Pentra found 1 new finding.",
            "counts": {"new": 1, "resolved": 0, "persistent": 1, "escalated": 0},
        },
        "retest": {"eligible": True, "recommended_priority": "high"},
        "remediation_plan": [
            {
                "title": "Fix authorization gaps",
                "priority": "immediate",
                "owner_hint": "Backend Engineering",
                "rationale": "Verified access-control bypass on privileged order approval flow.",
                "actions": ["Enforce server-side ownership checks on approval endpoints."],
            }
        ],
        "top_findings": [
            {
                "id": "cccccccc-cccc-cccc-cccc-cccccccccccc",
                "title": "Privilege escalation via order approval",
                "severity": "critical",
                "verification_state": "verified",
                "target": "POST /api/orders/approve",
                "description": "Privileged workflow action can be triggered by a low-privilege user.",
                "tool_source": "custom_poc",
                "remediation": "Re-check ownership and approval state on the server.",
            },
            {
                "id": "dddddddd-dddd-dddd-dddd-dddddddddddd",
                "title": "IDOR on invoice lookup",
                "severity": "high",
                "verification_state": "suspected",
                "target": "GET /api/invoices/{id}",
                "description": "Invoice identifiers appear enumerable across tenant boundaries.",
                "tool_source": "nuclei",
                "remediation": "Bind invoice reads to the authenticated tenant.",
            },
        ],
        "finding_groups": [],
        "markdown": "# Pentra Report - https://demo.example.com\n\nExecutive summary",
    }


def _fake_finding(
    *,
    finding_id: str,
    fingerprint: str,
    title: str,
    severity: str,
    verification_state: str,
    vulnerability_type: str,
    target: str,
) -> object:
    return SimpleNamespace(
        id=uuid.UUID(finding_id),
        fingerprint=fingerprint,
        title=title,
        severity=severity,
        confidence=92,
        description=f"{title} description",
        remediation=f"Fix {title}",
        tool_source="custom_poc",
        source_type="scanner",
        verification_state=verification_state,
        verification_confidence=95,
        vulnerability_type=vulnerability_type,
        evidence={
            "target": target,
            "classification": {
                "route_group": target,
                "surface": "web",
                "exploitability": "high",
            },
        },
        cvss_score=9.1,
        created_at=datetime(2026, 3, 21, 8, 0, tzinfo=timezone.utc),
        is_false_positive=False,
    )


def test_scan_issue_export_schema_requires_delivery_coordinates() -> None:
    from pentra_common.schemas import ScanIssueExportRequest

    with pytest.raises(ValidationError):
        ScanIssueExportRequest(provider="github", mode="deliver")

    with pytest.raises(ValidationError):
        ScanIssueExportRequest(
            provider="jira",
            mode="deliver",
            base_url="https://jira.example.com",
        )


def test_export_scan_report_supports_html(monkeypatch) -> None:
    from app.services import scan_service

    async def fake_get_scan_report(**_: object) -> dict[str, object]:
        return _sample_report()

    monkeypatch.setattr(scan_service, "get_scan_report", fake_get_scan_report)

    content, media_type, filename = asyncio.run(
        scan_service.export_scan_report(
            scan_id=uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            tenant_id=uuid.UUID("ffffffff-ffff-ffff-ffff-ffffffffffff"),
            export_format="html",
            session=object(),
        )
    )

    assert media_type == "text/html; charset=utf-8"
    assert filename.endswith(".html")
    assert "<!DOCTYPE html>" in content
    assert "Pentra Offensive Validation Report" in content


def test_deliver_scan_report_notification_posts_webhook_payload(monkeypatch) -> None:
    from app.services import scan_service

    captured: dict[str, object] = {}

    async def fake_get_scan_report(**_: object) -> dict[str, object]:
        return _sample_report()

    async def fake_post_json_payload(**kwargs: object) -> int:
        captured.update(kwargs)
        return 202

    monkeypatch.setattr(scan_service, "get_scan_report", fake_get_scan_report)
    monkeypatch.setattr(scan_service, "_post_json_payload", fake_post_json_payload)

    response = asyncio.run(
        scan_service.deliver_scan_report_notification(
            scan_id=uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            tenant_id=uuid.UUID("ffffffff-ffff-ffff-ffff-ffffffffffff"),
            channel="webhook",
            destination_url="https://hooks.example.com/pentra",
            top_findings_limit=1,
            include_markdown=True,
            include_html=True,
            custom_headers={"X-Pentra-Test": "true"},
            authorization_header="Bearer secret",
            session=object(),
        )
    )

    assert response is not None
    assert response["status_code"] == 202
    assert response["destination_host"] == "hooks.example.com"
    payload = captured["payload"]
    assert isinstance(payload, dict)
    assert payload["event"] == "scan.report.generated"
    assert payload["top_findings"][0]["title"] == "Privilege escalation via order approval"
    assert "report_markdown" in payload
    assert "report_html" in payload


def test_deliver_scan_report_notification_builds_slack_blocks(monkeypatch) -> None:
    from app.services import scan_service

    captured: dict[str, object] = {}

    async def fake_get_scan_report(**_: object) -> dict[str, object]:
        return _sample_report()

    async def fake_post_json_payload(**kwargs: object) -> int:
        captured.update(kwargs)
        return 200

    monkeypatch.setattr(scan_service, "get_scan_report", fake_get_scan_report)
    monkeypatch.setattr(scan_service, "_post_json_payload", fake_post_json_payload)

    asyncio.run(
        scan_service.deliver_scan_report_notification(
            scan_id=uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            tenant_id=uuid.UUID("ffffffff-ffff-ffff-ffff-ffffffffffff"),
            channel="slack",
            destination_url="https://hooks.slack.com/services/demo",
            top_findings_limit=2,
            include_markdown=False,
            include_html=False,
            custom_headers={},
            authorization_header=None,
            session=object(),
        )
    )

    payload = captured["payload"]
    assert isinstance(payload, dict)
    assert payload["text"].startswith("Pentra report ready")
    assert payload["blocks"][0]["type"] == "header"


def test_export_scan_issues_preview_filters_and_shapes_github_payloads(monkeypatch) -> None:
    from app.services import scan_service

    report = _sample_report()
    selected_findings = [
        _fake_finding(
            finding_id="11111111-1111-1111-1111-111111111111",
            fingerprint="fp-critical",
            title="Critical auth bypass",
            severity="critical",
            verification_state="verified",
            vulnerability_type="auth_bypass",
            target="POST /api/admin/approve",
        ),
        _fake_finding(
            finding_id="22222222-2222-2222-2222-222222222222",
            fingerprint="fp-high",
            title="High IDOR",
            severity="high",
            verification_state="suspected",
            vulnerability_type="idor",
            target="GET /api/invoices/{id}",
        ),
        _fake_finding(
            finding_id="33333333-3333-3333-3333-333333333333",
            fingerprint="fp-low",
            title="Low info leak",
            severity="low",
            verification_state="verified",
            vulnerability_type="general",
            target="GET /status",
        ),
    ]

    async def fake_load_report_context(**_: object) -> dict[str, object]:
        return {"findings": selected_findings}

    async def fake_get_scan_report(**_: object) -> dict[str, object]:
        return report

    monkeypatch.setattr(scan_service, "_load_report_context", fake_load_report_context)
    monkeypatch.setattr(scan_service, "get_scan_report", fake_get_scan_report)

    exported = asyncio.run(
        scan_service.export_scan_issues(
            scan_id=uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            tenant_id=uuid.UUID("ffffffff-ffff-ffff-ffff-ffffffffffff"),
            provider="github",
            mode="preview",
            minimum_severity="high",
            verified_only=True,
            max_issues=10,
            destination_url=None,
            base_url=None,
            repository=None,
            project_key=None,
            custom_headers={},
            authorization_header=None,
            session=object(),
        )
    )

    assert exported is not None
    assert exported["selected_count"] == 1
    assert exported["delivered_count"] == 0
    ticket = exported["tickets"][0]
    assert ticket["delivery_status"] == "preview"
    assert ticket["payload"]["title"].startswith("[CRITICAL]")
    assert ticket["payload"]["labels"][0] == "pentra"


def test_export_scan_issues_delivers_jira_payload(monkeypatch) -> None:
    from app.services import scan_service

    finding = _fake_finding(
        finding_id="44444444-4444-4444-4444-444444444444",
        fingerprint="fp-jira",
        title="Workflow bypass",
        severity="high",
        verification_state="verified",
        vulnerability_type="workflow_bypass",
        target="POST /api/orders/approve",
    )
    captured: dict[str, object] = {}

    async def fake_load_report_context(**_: object) -> dict[str, object]:
        return {"findings": [finding]}

    async def fake_get_scan_report(**_: object) -> dict[str, object]:
        return _sample_report()

    async def fake_post_json_payload(**kwargs: object) -> int:
        captured.update(kwargs)
        return 201

    monkeypatch.setattr(scan_service, "_load_report_context", fake_load_report_context)
    monkeypatch.setattr(scan_service, "get_scan_report", fake_get_scan_report)
    monkeypatch.setattr(scan_service, "_post_json_payload", fake_post_json_payload)

    exported = asyncio.run(
        scan_service.export_scan_issues(
            scan_id=uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            tenant_id=uuid.UUID("ffffffff-ffff-ffff-ffff-ffffffffffff"),
            provider="jira",
            mode="deliver",
            minimum_severity="medium",
            verified_only=True,
            max_issues=5,
            destination_url=None,
            base_url="https://jira.example.com",
            repository=None,
            project_key="PENTRA",
            custom_headers={"X-Test": "jira"},
            authorization_header="Basic token",
            session=object(),
        )
    )

    assert exported is not None
    assert exported["delivered_count"] == 1
    assert exported["destination_host"] == "jira.example.com"
    assert captured["destination_url"] == "https://jira.example.com/rest/api/3/issue"
    payload = captured["payload"]
    assert isinstance(payload, dict)
    assert payload["fields"]["project"]["key"] == "PENTRA"
    assert payload["fields"]["description"]["type"] == "doc"
