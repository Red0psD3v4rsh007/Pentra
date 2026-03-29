from __future__ import annotations

import asyncio
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def _asset(asset_id: uuid.UUID) -> SimpleNamespace:
    return SimpleNamespace(
        id=asset_id,
        tenant_id=uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        is_active=True,
        name="Primary API",
        target="https://api.example.test",
    )


def _finding(
    *,
    finding_id: str,
    vulnerability_type: str,
    route_group: str,
    severity: str = "high",
    verification_state: str | None = None,
    include_classification_vtype: bool = False,
) -> SimpleNamespace:
    classification = {
        "route_group": route_group,
        "surface": "web",
        "primary_technology": "Next.js",
    }
    if include_classification_vtype:
        classification["vulnerability_type"] = vulnerability_type
    if verification_state:
        classification["verification_state"] = verification_state

    return SimpleNamespace(
        id=uuid.UUID(finding_id),
        title=f"{vulnerability_type} finding",
        severity=severity,
        vulnerability_type=vulnerability_type,
        verification_state=verification_state,
        evidence={
            "target": f"https://api.example.test{route_group}",
            "classification": classification,
        },
        created_at=datetime(2026, 3, 21, 9, 0, tzinfo=timezone.utc),
    )


def _artifact(*, technology: str, pages: int, forms: int) -> SimpleNamespace:
    return SimpleNamespace(
        artifact_type="http_probe",
        metadata_={
            "summary": {
                "technology_counts": {technology: 1},
                "stateful_context": {
                    "page_count": pages,
                    "form_count": forms,
                },
            }
        },
    )


def _scan(
    *,
    scan_id: str,
    asset: SimpleNamespace,
    created_at: datetime,
    status: str = "completed",
    findings: list[SimpleNamespace] | None = None,
    artifacts: list[SimpleNamespace] | None = None,
) -> SimpleNamespace:
    completed_at = created_at + timedelta(minutes=15) if status == "completed" else None
    return SimpleNamespace(
        id=uuid.UUID(scan_id),
        asset_id=asset.id,
        asset=asset,
        scan_type="full",
        status=status,
        priority="high",
        created_at=created_at,
        updated_at=created_at + timedelta(minutes=5),
        started_at=created_at + timedelta(minutes=1),
        completed_at=completed_at,
        result_summary={
            "severity_counts": {
                "critical": 0,
                "high": len(findings or []),
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "verification_counts": {
                "verified": sum(
                    1
                    for finding in (findings or [])
                    if getattr(finding, "verification_state", None) == "verified"
                ),
                "suspected": 0,
                "detected": sum(
                    1
                    for finding in (findings or [])
                    if getattr(finding, "verification_state", None) != "verified"
                ),
            },
        },
        findings=findings or [],
        artifacts=artifacts or [],
    )


class _ScalarResult:
    def __init__(self, value: object) -> None:
        self._value = value

    def scalar_one_or_none(self) -> object:
        return self._value

    def scalar_one(self) -> object:
        return self._value

    def scalar(self) -> object:
        return self._value


class _SequenceScalarResult:
    def __init__(self, values: list[object]) -> None:
        self._values = values

    def all(self) -> list[object]:
        return self._values


class _SequenceResult:
    def __init__(self, values: list[object]) -> None:
        self._values = values

    def scalars(self) -> _SequenceScalarResult:
        return _SequenceScalarResult(self._values)


class _FakeSession:
    def __init__(self, responses: list[object]) -> None:
        self._responses = list(responses)
        self.execute_calls = 0

    async def execute(self, _statement: object) -> object:
        response = self._responses[self.execute_calls]
        self.execute_calls += 1
        return response


def test_build_trending_patterns_reads_direct_finding_vulnerability_type() -> None:
    from app.services.intelligence_store import build_trending_patterns

    asset = _asset(uuid.UUID("11111111-1111-1111-1111-111111111111"))
    older_scan = _scan(
        scan_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        asset=asset,
        created_at=datetime(2026, 3, 19, 8, 0, tzinfo=timezone.utc),
        findings=[
            _finding(
                finding_id="aaaaaaaa-0000-0000-0000-000000000001",
                vulnerability_type="idor",
                route_group="/api/v1/orders/{id}",
                include_classification_vtype=True,
            )
        ],
    )
    newer_scan = _scan(
        scan_id="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        asset=asset,
        created_at=datetime(2026, 3, 20, 8, 0, tzinfo=timezone.utc),
        findings=[
            _finding(
                finding_id="bbbbbbbb-0000-0000-0000-000000000001",
                vulnerability_type="sql_injection",
                route_group="/api/v1/search",
                include_classification_vtype=False,
            )
        ],
    )

    trends = build_trending_patterns([older_scan, newer_scan], window=1)
    by_type = {item["vulnerability_type"]: item for item in trends}

    assert by_type["sql_injection"]["direction"] == "new"
    assert by_type["sql_injection"]["recent_count"] == 1
    assert by_type["idor"]["direction"] == "decreasing"


def test_get_asset_history_returns_cross_scan_comparison_and_knowledge(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.services import intelligence_service, scan_service

    tenant_id = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    asset_id = uuid.UUID("11111111-1111-1111-1111-111111111111")
    asset = _asset(asset_id)

    latest_scan = _scan(
        scan_id="22222222-2222-2222-2222-222222222222",
        asset=asset,
        created_at=datetime(2026, 3, 21, 8, 0, tzinfo=timezone.utc),
        findings=[
            _finding(
                finding_id="11111111-0000-0000-0000-000000000001",
                vulnerability_type="auth_bypass",
                route_group="/api/login",
                verification_state="verified",
            )
        ],
        artifacts=[_artifact(technology="Next.js", pages=4, forms=2)],
    )
    previous_scan = _scan(
        scan_id="33333333-3333-3333-3333-333333333333",
        asset=asset,
        created_at=datetime(2026, 3, 20, 8, 0, tzinfo=timezone.utc),
        findings=[
            _finding(
                finding_id="22222222-0000-0000-0000-000000000001",
                vulnerability_type="rate_limit_bypass",
                route_group="/api/token",
            )
        ],
        artifacts=[_artifact(technology="OpenAPI", pages=2, forms=1)],
    )
    oldest_scan = _scan(
        scan_id="44444444-4444-4444-4444-444444444444",
        asset=asset,
        created_at=datetime(2026, 3, 19, 8, 0, tzinfo=timezone.utc),
        findings=[
            _finding(
                finding_id="33333333-0000-0000-0000-000000000001",
                vulnerability_type="idor",
                route_group="/api/v1/users/{id}",
            )
        ],
        artifacts=[],
    )

    async def fake_get_scan_comparison(**kwargs: object) -> dict[str, object] | None:
        if kwargs["scan_id"] == latest_scan.id:
            return {
                "summary": "1 new and 1 persistent finding compared with the baseline.",
                "counts": {
                    "new": 1,
                    "resolved": 0,
                    "persistent": 1,
                    "escalated": 0,
                },
                "baseline_scan_id": previous_scan.id,
            }
        if kwargs["scan_id"] == previous_scan.id:
            return {
                "summary": "No previous completed scan is available for historical comparison yet.",
                "counts": {
                    "new": 0,
                    "resolved": 0,
                    "persistent": 0,
                    "escalated": 0,
                },
                "baseline_scan_id": None,
            }
        return None

    monkeypatch.setattr(scan_service, "get_scan_comparison", fake_get_scan_comparison)

    session = _FakeSession(
        [
            _ScalarResult(asset),
            _ScalarResult(3),
            _SequenceResult([latest_scan, previous_scan]),
            _SequenceResult([latest_scan, previous_scan, oldest_scan]),
        ]
    )

    payload = asyncio.run(
        intelligence_service.get_asset_history(
            asset_id=asset_id,
            tenant_id=tenant_id,
            session=session,
            limit=2,
        )
    )

    assert payload is not None
    assert payload["total_scans"] == 3
    assert payload["known_technologies"] == ["Next.js", "OpenAPI"]
    assert payload["tracked_vulnerability_types"] == [
        "auth_bypass",
        "idor",
        "rate_limit_bypass",
    ]
    assert len(payload["entries"]) == 2
    assert payload["entries"][0]["comparison_counts"]["new"] == 1
    assert payload["entries"][0]["baseline_scan_id"] == previous_scan.id
    assert session.execute_calls == 4


def test_asset_history_route_raises_not_found_when_service_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.routers import intelligence

    async def fake_get_asset_history(**_: object) -> None:
        return None

    monkeypatch.setattr(intelligence.intelligence_service, "get_asset_history", fake_get_asset_history)

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(
            intelligence.get_asset_history(
                asset_id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
                limit=20,
                user=SimpleNamespace(tenant_id=uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")),
                session=object(),
            )
        )

    assert exc_info.value.status_code == 404
