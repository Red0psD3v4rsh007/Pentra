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
    route_group: str,
    technology: str | None = None,
    source_type: str = "scanner",
    verification_state: str | None = None,
    tool_source: str = "nuclei",
) -> SimpleNamespace:
    classification = {
        "route_group": route_group,
    }
    if technology:
        classification["primary_technology"] = technology
    if verification_state:
        classification["verification_state"] = verification_state

    return SimpleNamespace(
        id=finding_id,
        title=title,
        severity=severity,
        confidence=90,
        vulnerability_type=vulnerability_type,
        source_type=source_type,
        tool_source=tool_source,
        cvss_score=None,
        description="demo",
        remediation="fix it",
        evidence={
            "endpoint": f"https://example.test{route_group}",
            "classification": classification,
        },
        verification_state=verification_state,
        verification_confidence=92 if verification_state else None,
        exploitability="high",
        surface="api",
        created_at=datetime(2026, 3, 16, 12, 0, tzinfo=timezone.utc),
    )


def _artifact(*, artifact_type: str, technology_counts: dict[str, int], item_count: int = 0) -> SimpleNamespace:
    return SimpleNamespace(
        artifact_type=artifact_type,
        created_at=datetime(2026, 3, 16, 12, 5, tzinfo=timezone.utc),
        metadata_={
            "summary": {
                "technology_counts": technology_counts,
                "item_count": item_count,
                "targets": ["https://example.test/api/v1/users"],
            }
        },
    )


def _scan(scan_id: str, findings: list[SimpleNamespace], artifacts: list[SimpleNamespace]) -> SimpleNamespace:
    return SimpleNamespace(
        id=scan_id,
        asset_id=f"asset-{scan_id}",
        status="completed",
        created_at=datetime(2026, 3, 16, 12, 0, tzinfo=timezone.utc),
        updated_at=datetime(2026, 3, 16, 12, 10, tzinfo=timezone.utc),
        completed_at=datetime(2026, 3, 16, 12, 10, tzinfo=timezone.utc),
        result_summary={"verification_counts": {"verified": 1, "suspected": 0, "detected": 1}},
        config={},
        asset=SimpleNamespace(
            id=f"asset-{scan_id}",
            name=f"Asset {scan_id}",
            target=f"https://example.test/{scan_id}",
        ),
        findings=findings,
        artifacts=artifacts,
    )


def test_build_pattern_matches_groups_repeated_findings():
    from app.services.intelligence_service import _build_pattern_matches

    scans = [
        _scan(
            "scan-1",
            [
                _finding(
                    finding_id="finding-1",
                    title="Broken object level authorization",
                    severity="high",
                    vulnerability_type="idor",
                    route_group="/api/v1/users/{id}",
                    verification_state="verified",
                ),
                _finding(
                    finding_id="finding-2",
                    title="Broken object level authorization",
                    severity="medium",
                    vulnerability_type="idor",
                    route_group="/api/v1/users/{id}",
                ),
            ],
            [],
        )
    ]

    patterns = _build_pattern_matches(scans)

    assert len(patterns) == 1
    assert patterns[0]["vulnerability_type"] == "idor"
    assert patterns[0]["finding_count"] == 2
    assert patterns[0]["verification_counts"]["verified"] == 1
    assert patterns[0]["highest_severity"] == "high"


def test_build_technology_clusters_combines_artifacts_and_finding_context():
    from app.services.intelligence_service import _build_technology_clusters

    scans = [
        _scan(
            "scan-1",
            [
                _finding(
                    finding_id="finding-1",
                    title="SQL injection",
                    severity="critical",
                    vulnerability_type="sql_injection",
                    route_group="/api/v1/auth/login",
                    technology="SQLite",
                    verification_state="verified",
                    tool_source="sqlmap",
                )
            ],
            [
                _artifact(
                    artifact_type="http_probe",
                    technology_counts={"Next.js": 3, "OpenAPI": 1},
                    item_count=4,
                )
            ],
        )
    ]

    clusters = _build_technology_clusters(scans)
    by_name = {item["technology"]: item for item in clusters}

    assert by_name["Next.js"]["endpoint_count"] == 3
    assert by_name["Next.js"]["asset_count"] == 1
    assert by_name["SQLite"]["finding_count"] == 1
    assert by_name["SQLite"]["severity_counts"]["critical"] == 1


def test_build_route_groups_preserves_verified_counts():
    from app.services.intelligence_service import _build_route_groups

    scans = [
        _scan(
            "scan-1",
            [
                _finding(
                    finding_id="finding-1",
                    title="IDOR",
                    severity="high",
                    vulnerability_type="idor",
                    route_group="/api/v1/users/{id}",
                    verification_state="verified",
                ),
                _finding(
                    finding_id="finding-2",
                    title="Authorization bypass",
                    severity="medium",
                    vulnerability_type="auth_bypass",
                    route_group="/api/v1/users/{id}",
                ),
            ],
            [],
        )
    ]

    route_groups = _build_route_groups(scans)

    assert len(route_groups) == 1
    assert route_groups[0]["route_group"] == "/api/v1/users/{id}"
    assert route_groups[0]["finding_count"] == 2
    assert route_groups[0]["verification_counts"]["verified"] == 1
    assert "idor" in route_groups[0]["vulnerability_types"]
