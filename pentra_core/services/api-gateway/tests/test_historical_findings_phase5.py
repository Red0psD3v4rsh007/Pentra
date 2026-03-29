from __future__ import annotations

import asyncio
import os
import sys
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


class _ScalarResult:
    def __init__(self, value: object) -> None:
        self._value = value

    def scalar_one(self) -> object:
        return self._value

    def scalar_one_or_none(self) -> object:
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


def _historical_finding(
    *,
    finding_id: str,
    asset_id: str,
    last_seen_scan_id: str,
    last_seen_at: datetime,
    severity: str,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.UUID(finding_id),
        asset_id=uuid.UUID(asset_id),
        lineage_key=f"lineage-{finding_id[:8]}",
        fingerprint=f"fp-{finding_id[:8]}",
        title="Historical auth bypass",
        vulnerability_type="auth_bypass",
        route_group="/api/admin/approve",
        target="api.example.test",
        latest_severity=severity,
        latest_verification_state="verified",
        latest_source_type="scanner",
        first_seen_scan_id=uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        first_seen_at=datetime(2026, 3, 1, 9, 0, tzinfo=timezone.utc),
        last_seen_scan_id=uuid.UUID(last_seen_scan_id),
        last_seen_at=last_seen_at,
        latest_finding_id=uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
        occurrence_count=3,
    )


def _occurrence(
    *,
    occurrence_id: str,
    historical_finding_id: str,
    scan_id: str,
    severity: str,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.UUID(occurrence_id),
        historical_finding_id=uuid.UUID(historical_finding_id),
        scan_id=uuid.UUID(scan_id),
        finding_id=uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc"),
        severity=severity,
        verification_state="verified",
        source_type="scanner",
        observed_at=datetime(2026, 3, 21, 8, 0, tzinfo=timezone.utc),
    )


def test_list_historical_findings_derives_active_and_resolved_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services import historical_finding_service

    asset_id = uuid.UUID("11111111-1111-1111-1111-111111111111")
    tenant_id = uuid.UUID("22222222-2222-2222-2222-222222222222")
    latest_completed_scan_id = uuid.UUID("33333333-3333-3333-3333-333333333333")

    async def fake_get_asset(**_: object) -> object:
        return SimpleNamespace(id=asset_id)

    monkeypatch.setattr(historical_finding_service.asset_service, "get_asset", fake_get_asset)

    active_finding = _historical_finding(
        finding_id="44444444-4444-4444-4444-444444444444",
        asset_id=str(asset_id),
        last_seen_scan_id=str(latest_completed_scan_id),
        last_seen_at=datetime(2026, 3, 21, 8, 0, tzinfo=timezone.utc),
        severity="critical",
    )
    resolved_finding = _historical_finding(
        finding_id="55555555-5555-5555-5555-555555555555",
        asset_id=str(asset_id),
        last_seen_scan_id="66666666-6666-6666-6666-666666666666",
        last_seen_at=datetime(2026, 3, 20, 8, 0, tzinfo=timezone.utc),
        severity="medium",
    )
    occurrences = [
        _occurrence(
            occurrence_id="77777777-7777-7777-7777-777777777777",
            historical_finding_id=str(active_finding.id),
            scan_id=str(latest_completed_scan_id),
            severity="critical",
        ),
        _occurrence(
            occurrence_id="88888888-8888-8888-8888-888888888888",
            historical_finding_id=str(resolved_finding.id),
            scan_id="66666666-6666-6666-6666-666666666666",
            severity="medium",
        ),
    ]
    session = _FakeSession(
        [
            _ScalarResult(latest_completed_scan_id),
            _ScalarResult(2),
            _SequenceResult([active_finding, resolved_finding]),
            _SequenceResult(occurrences),
        ]
    )

    items, total = asyncio.run(
        historical_finding_service.list_historical_findings(
            asset_id=asset_id,
            tenant_id=tenant_id,
            session=session,
            page=1,
            page_size=10,
            status="all",
            occurrence_limit=2,
        )
    ) or ([], 0)

    assert total == 2
    assert items[0]["status"] == "active"
    assert items[0]["recent_occurrences"][0]["scan_id"] == latest_completed_scan_id
    assert items[1]["status"] == "resolved"
    assert session.execute_calls == 4


def test_historical_finding_route_raises_404_when_asset_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.routers import assets

    async def fake_list_historical_findings(**_: object) -> None:
        return None

    monkeypatch.setattr(
        assets.historical_finding_service,
        "list_historical_findings",
        fake_list_historical_findings,
    )

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(
            assets.list_historical_findings(
                asset_id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
                page=1,
                page_size=20,
                status_filter="all",
                occurrence_limit=3,
                user=SimpleNamespace(tenant_id=uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")),
                session=object(),
            )
        )

    assert exc_info.value.status_code == 404
