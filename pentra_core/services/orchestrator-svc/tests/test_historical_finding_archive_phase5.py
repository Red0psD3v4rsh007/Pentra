from __future__ import annotations

import asyncio
import os
import sys
import uuid
from datetime import datetime, timezone


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


class _MappingResult:
    def __init__(self, rows: list[dict[str, object]]) -> None:
        self._rows = rows

    def first(self) -> dict[str, object] | None:
        return self._rows[0] if self._rows else None

    def all(self) -> list[dict[str, object]]:
        return self._rows


class _Result:
    def __init__(self, rows: list[dict[str, object]] | None = None) -> None:
        self._rows = rows or []

    def mappings(self) -> _MappingResult:
        return _MappingResult(self._rows)


class _FakeSession:
    def __init__(self, responses: list[_Result]) -> None:
        self._responses = list(responses)
        self.calls: list[tuple[str, dict[str, object] | None]] = []

    async def execute(self, statement: object, params: dict[str, object] | None = None) -> _Result:
        self.calls.append((str(statement), params))
        response = self._responses[len(self.calls) - 1]
        return response


def test_sync_completed_scan_historical_findings_inserts_lineage_and_occurrence() -> None:
    from app.engine.historical_finding_archive import sync_completed_scan_historical_findings

    tenant_id = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    scan_id = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
    asset_id = uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc")
    historical_id = uuid.UUID("dddddddd-dddd-dddd-dddd-dddddddddddd")
    observed_at = datetime(2026, 3, 21, 10, 0, tzinfo=timezone.utc)

    session = _FakeSession(
        [
            _Result([{"asset_id": asset_id, "observed_at": observed_at}]),
            _Result(
                [
                    {
                        "id": uuid.UUID("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"),
                        "fingerprint": "fp-auth-bypass",
                        "title": "Auth bypass",
                        "severity": "critical",
                        "source_type": "scanner",
                        "evidence": {
                            "target": "api.example.test",
                            "endpoint": "/api/admin/approve",
                            "classification": {
                                "vulnerability_type": "auth_bypass",
                                "route_group": "/api/admin/approve",
                                "verification_state": "verified",
                            },
                        },
                    }
                ]
            ),
            _Result([]),
            _Result(
                [
                    {
                        "id": historical_id,
                        "lineage_key": "fp-auth-bypass",
                        "first_seen_scan_id": scan_id,
                        "first_seen_at": observed_at,
                        "last_seen_scan_id": scan_id,
                        "last_seen_at": observed_at,
                        "occurrence_count": 0,
                    }
                ]
            ),
            _Result(),
            _Result(),
        ]
    )

    archived = asyncio.run(
        sync_completed_scan_historical_findings(
            session,
            scan_id=scan_id,
            tenant_id=tenant_id,
        )
    )

    assert archived == 1
    assert any("INSERT INTO historical_findings" in call[0] for call in session.calls)
    assert any("INSERT INTO historical_finding_occurrences" in call[0] for call in session.calls)
    update_params = next(params for sql, params in session.calls if "UPDATE historical_findings" in sql)
    assert update_params is not None
    assert update_params["occurrence_count"] == 1


def test_sync_completed_scan_historical_findings_does_not_double_count_same_scan() -> None:
    from app.engine.historical_finding_archive import sync_completed_scan_historical_findings

    tenant_id = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    scan_id = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
    asset_id = uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc")
    historical_id = uuid.UUID("dddddddd-dddd-dddd-dddd-dddddddddddd")
    occurrence_id = uuid.UUID("ffffffff-ffff-ffff-ffff-ffffffffffff")
    observed_at = datetime(2026, 3, 21, 10, 0, tzinfo=timezone.utc)

    session = _FakeSession(
        [
            _Result([{"asset_id": asset_id, "observed_at": observed_at}]),
            _Result(
                [
                    {
                        "id": uuid.UUID("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"),
                        "fingerprint": "fp-auth-bypass",
                        "title": "Auth bypass",
                        "severity": "critical",
                        "source_type": "scanner",
                        "evidence": {
                            "target": "api.example.test",
                            "classification": {
                                "vulnerability_type": "auth_bypass",
                                "route_group": "/api/admin/approve",
                                "verification_state": "verified",
                            },
                        },
                    }
                ]
            ),
            _Result(
                [
                    {
                        "id": historical_id,
                        "lineage_key": "fp-auth-bypass",
                        "first_seen_scan_id": scan_id,
                        "first_seen_at": observed_at,
                        "last_seen_scan_id": scan_id,
                        "last_seen_at": observed_at,
                        "occurrence_count": 2,
                    }
                ]
            ),
            _Result(
                [
                    {
                        "id": occurrence_id,
                        "historical_finding_id": historical_id,
                    }
                ]
            ),
            _Result(),
            _Result(),
        ]
    )

    archived = asyncio.run(
        sync_completed_scan_historical_findings(
            session,
            scan_id=scan_id,
            tenant_id=tenant_id,
        )
    )

    assert archived == 1
    update_params = next(params for sql, params in session.calls if "UPDATE historical_findings" in sql)
    assert update_params is not None
    assert update_params["occurrence_count"] == 2
    assert any("UPDATE historical_finding_occurrences" in call[0] for call in session.calls)
