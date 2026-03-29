"""Historical finding service — asset-scoped cross-scan lineage queries."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.historical_finding import HistoricalFinding, HistoricalFindingOccurrence
from app.models.scan import Scan
from app.services import asset_service

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _severity_sort_expression() -> Any:
    return case(
        *[(HistoricalFinding.latest_severity == severity, index) for index, severity in enumerate(_SEVERITY_ORDER, start=1)],
        else_=len(_SEVERITY_ORDER) + 1,
    )


async def list_historical_findings(
    *,
    asset_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
    page: int = 1,
    page_size: int = 20,
    status: str = "all",
    occurrence_limit: int = 3,
) -> tuple[list[dict[str, Any]], int] | None:
    asset = await asset_service.get_asset(
        asset_id=asset_id,
        tenant_id=tenant_id,
        session=session,
    )
    if asset is None:
        return None

    latest_completed_scan_id = (
        await session.execute(
            select(Scan.id)
            .where(
                Scan.tenant_id == tenant_id,
                Scan.asset_id == asset_id,
                Scan.status == "completed",
            )
            .order_by(Scan.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    base_filter = (
        (HistoricalFinding.tenant_id == tenant_id)
        & (HistoricalFinding.asset_id == asset_id)
    )
    if status == "active" and latest_completed_scan_id is not None:
        base_filter = base_filter & (HistoricalFinding.last_seen_scan_id == latest_completed_scan_id)
    elif status == "resolved" and latest_completed_scan_id is not None:
        base_filter = base_filter & (HistoricalFinding.last_seen_scan_id != latest_completed_scan_id)
    elif status == "resolved" and latest_completed_scan_id is None:
        return [], 0

    total = (
        await session.execute(
            select(func.count()).select_from(HistoricalFinding).where(base_filter)
        )
    ).scalar_one()

    offset = (page - 1) * page_size
    findings = list(
        (
            await session.execute(
                select(HistoricalFinding)
                .where(base_filter)
                .order_by(
                    _severity_sort_expression(),
                    HistoricalFinding.last_seen_at.desc(),
                    HistoricalFinding.occurrence_count.desc(),
                )
                .offset(offset)
                .limit(page_size)
            )
        )
        .scalars()
        .all()
    )

    if not findings:
        return [], int(total)

    historical_ids = [item.id for item in findings]
    occurrence_rows = list(
        (
            await session.execute(
                select(HistoricalFindingOccurrence)
                .where(HistoricalFindingOccurrence.historical_finding_id.in_(historical_ids))
                .order_by(
                    HistoricalFindingOccurrence.historical_finding_id.asc(),
                    HistoricalFindingOccurrence.observed_at.desc(),
                )
            )
        )
        .scalars()
        .all()
    )

    grouped_occurrences: dict[uuid.UUID, list[HistoricalFindingOccurrence]] = {}
    for occurrence in occurrence_rows:
        bucket = grouped_occurrences.setdefault(occurrence.historical_finding_id, [])
        if len(bucket) < occurrence_limit:
            bucket.append(occurrence)

    items: list[dict[str, Any]] = []
    for finding in findings:
        derived_status = (
            "active"
            if latest_completed_scan_id is not None and finding.last_seen_scan_id == latest_completed_scan_id
            else "resolved"
        )
        items.append(
            {
                "id": finding.id,
                "asset_id": finding.asset_id,
                "lineage_key": finding.lineage_key,
                "fingerprint": finding.fingerprint,
                "title": finding.title,
                "vulnerability_type": finding.vulnerability_type,
                "route_group": finding.route_group,
                "target": finding.target,
                "latest_severity": finding.latest_severity,
                "latest_verification_state": finding.latest_verification_state,
                "latest_source_type": finding.latest_source_type,
                "first_seen_scan_id": finding.first_seen_scan_id,
                "first_seen_at": finding.first_seen_at,
                "last_seen_scan_id": finding.last_seen_scan_id,
                "last_seen_at": finding.last_seen_at,
                "latest_finding_id": finding.latest_finding_id,
                "occurrence_count": int(finding.occurrence_count or 0),
                "status": derived_status,
                "recent_occurrences": [
                    {
                        "id": occurrence.id,
                        "scan_id": occurrence.scan_id,
                        "finding_id": occurrence.finding_id,
                        "severity": occurrence.severity,
                        "verification_state": occurrence.verification_state,
                        "source_type": occurrence.source_type,
                        "observed_at": occurrence.observed_at,
                    }
                    for occurrence in grouped_occurrences.get(finding.id, [])
                ],
            }
        )
    return items, int(total)
