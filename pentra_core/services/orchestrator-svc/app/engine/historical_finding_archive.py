"""Historical finding archive — snapshots completed scan findings into cross-scan lineage tables."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import bindparam, text
from sqlalchemy.ext.asyncio import AsyncSession


def _finding_classification(evidence: dict[str, Any]) -> dict[str, Any]:
    classification = evidence.get("classification") or {}
    return classification if isinstance(classification, dict) else {}


def _historical_snapshot_from_row(row: dict[str, Any]) -> dict[str, Any]:
    evidence = row.get("evidence") or {}
    if not isinstance(evidence, dict):
        evidence = {}
    classification = _finding_classification(evidence)
    return {
        "finding_id": uuid.UUID(str(row["id"])),
        "lineage_key": str(row["fingerprint"]),
        "fingerprint": str(row["fingerprint"]),
        "title": str(row["title"]),
        "vulnerability_type": (
            str(classification.get("vulnerability_type")).strip()
            if classification.get("vulnerability_type")
            else None
        ),
        "route_group": (
            str(classification.get("route_group")).strip()
            if classification.get("route_group")
            else None
        ),
        "target": str(evidence.get("target") or evidence.get("endpoint") or "unknown-target"),
        "latest_severity": str(row["severity"]),
        "latest_verification_state": (
            str(classification.get("verification_state")).strip()
            if classification.get("verification_state")
            else None
        ),
        "latest_source_type": str(row["source_type"]),
    }


async def sync_completed_scan_historical_findings(
    session: AsyncSession,
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> int:
    """Archive the final completed-scan finding snapshot into lineage tables.

    The archive is intentionally asset-scoped. A lineage is deduplicated by
    ``(asset_id, lineage_key)`` where ``lineage_key`` is currently the stable
    finding fingerprint emitted by the worker normalization layer.
    """

    scan_result = await session.execute(
        text(
            """
            SELECT asset_id,
                   COALESCE(completed_at, updated_at, created_at, NOW()) AS observed_at
            FROM scans
            WHERE id = :scan_id
              AND tenant_id = :tenant_id
              AND status = 'completed'
            """
        ),
        {"scan_id": str(scan_id), "tenant_id": str(tenant_id)},
    )
    scan_row = scan_result.mappings().first()
    if scan_row is None:
        return 0

    asset_id = uuid.UUID(str(scan_row["asset_id"]))
    observed_at = scan_row["observed_at"]
    if not isinstance(observed_at, datetime):
        observed_at = datetime.now(timezone.utc)

    finding_result = await session.execute(
        text(
            """
            SELECT id, fingerprint, title, severity, source_type, evidence
            FROM findings
            WHERE scan_id = :scan_id
              AND tenant_id = :tenant_id
            """
        ),
        {"scan_id": str(scan_id), "tenant_id": str(tenant_id)},
    )
    finding_rows = [dict(row) for row in finding_result.mappings().all() if row.get("fingerprint")]
    if not finding_rows:
        return 0

    lineage_keys = sorted({str(row["fingerprint"]) for row in finding_rows})
    existing_stmt = text(
        """
        SELECT id, lineage_key, first_seen_scan_id, first_seen_at,
               last_seen_scan_id, last_seen_at, occurrence_count
        FROM historical_findings
        WHERE tenant_id = :tenant_id
          AND asset_id = :asset_id
          AND lineage_key IN :lineage_keys
        """
    ).bindparams(bindparam("lineage_keys", expanding=True))
    existing_result = await session.execute(
        existing_stmt,
        {
            "tenant_id": str(tenant_id),
            "asset_id": str(asset_id),
            "lineage_keys": lineage_keys,
        },
    )
    existing_by_key = {
        str(row["lineage_key"]): dict(row)
        for row in existing_result.mappings().all()
    }

    existing_ids = [str(row["id"]) for row in existing_by_key.values()]
    occurrences_by_historical_id: dict[str, dict[str, Any]] = {}
    if existing_ids:
        occurrence_stmt = text(
            """
            SELECT id, historical_finding_id
            FROM historical_finding_occurrences
            WHERE scan_id = :scan_id
              AND historical_finding_id IN :historical_ids
            """
        ).bindparams(bindparam("historical_ids", expanding=True))
        occurrence_result = await session.execute(
            occurrence_stmt,
            {
                "scan_id": str(scan_id),
                "historical_ids": existing_ids,
            },
        )
        occurrences_by_historical_id = {
            str(row["historical_finding_id"]): dict(row)
            for row in occurrence_result.mappings().all()
        }

    archived_count = 0
    for row in finding_rows:
        snapshot = _historical_snapshot_from_row(row)
        historical = existing_by_key.get(snapshot["lineage_key"])
        if historical is None:
            insert_result = await session.execute(
                text(
                    """
                    INSERT INTO historical_findings (
                        id, tenant_id, asset_id, lineage_key, fingerprint,
                        title, vulnerability_type, route_group, target,
                        latest_severity, latest_verification_state, latest_source_type,
                        first_seen_scan_id, last_seen_scan_id, latest_finding_id,
                        first_seen_at, last_seen_at, occurrence_count
                    ) VALUES (
                        :id, :tenant_id, :asset_id, :lineage_key, :fingerprint,
                        :title, :vulnerability_type, :route_group, :target,
                        :latest_severity, :latest_verification_state, :latest_source_type,
                        :first_seen_scan_id, :last_seen_scan_id, :latest_finding_id,
                        :first_seen_at, :last_seen_at, 0
                    )
                    RETURNING id, lineage_key, first_seen_scan_id, first_seen_at,
                              last_seen_scan_id, last_seen_at, occurrence_count
                    """
                ),
                {
                    "id": str(uuid.uuid4()),
                    "tenant_id": str(tenant_id),
                    "asset_id": str(asset_id),
                    "lineage_key": snapshot["lineage_key"],
                    "fingerprint": snapshot["fingerprint"],
                    "title": snapshot["title"],
                    "vulnerability_type": snapshot["vulnerability_type"],
                    "route_group": snapshot["route_group"],
                    "target": snapshot["target"],
                    "latest_severity": snapshot["latest_severity"],
                    "latest_verification_state": snapshot["latest_verification_state"],
                    "latest_source_type": snapshot["latest_source_type"],
                    "first_seen_scan_id": str(scan_id),
                    "last_seen_scan_id": str(scan_id),
                    "latest_finding_id": str(snapshot["finding_id"]),
                    "first_seen_at": observed_at,
                    "last_seen_at": observed_at,
                },
            )
            inserted = insert_result.mappings().first()
            if inserted is None:
                continue
            historical = dict(inserted)
            existing_by_key[snapshot["lineage_key"]] = historical

        historical_id = str(historical["id"])
        occurrence = occurrences_by_historical_id.get(historical_id)
        occurrence_inserted = occurrence is None

        if occurrence_inserted:
            await session.execute(
                text(
                    """
                    INSERT INTO historical_finding_occurrences (
                        id, tenant_id, historical_finding_id, asset_id, scan_id,
                        finding_id, severity, verification_state, source_type, observed_at
                    ) VALUES (
                        :id, :tenant_id, :historical_finding_id, :asset_id, :scan_id,
                        :finding_id, :severity, :verification_state, :source_type, :observed_at
                    )
                    """
                ),
                {
                    "id": str(uuid.uuid4()),
                    "tenant_id": str(tenant_id),
                    "historical_finding_id": historical_id,
                    "asset_id": str(asset_id),
                    "scan_id": str(scan_id),
                    "finding_id": str(snapshot["finding_id"]),
                    "severity": snapshot["latest_severity"],
                    "verification_state": snapshot["latest_verification_state"],
                    "source_type": snapshot["latest_source_type"],
                    "observed_at": observed_at,
                },
            )
            occurrences_by_historical_id[historical_id] = {
                "historical_finding_id": historical_id,
            }
        else:
            await session.execute(
                text(
                    """
                    UPDATE historical_finding_occurrences
                    SET finding_id = :finding_id,
                        severity = :severity,
                        verification_state = :verification_state,
                        source_type = :source_type,
                        observed_at = :observed_at
                    WHERE id = :id
                    """
                ),
                {
                    "id": str(occurrence["id"]),
                    "finding_id": str(snapshot["finding_id"]),
                    "severity": snapshot["latest_severity"],
                    "verification_state": snapshot["latest_verification_state"],
                    "source_type": snapshot["latest_source_type"],
                    "observed_at": observed_at,
                },
            )

        first_seen_at = historical["first_seen_at"]
        last_seen_at = historical["last_seen_at"]
        first_seen_scan_id = historical["first_seen_scan_id"]
        last_seen_scan_id = historical["last_seen_scan_id"]
        if not isinstance(first_seen_at, datetime) or observed_at <= first_seen_at:
            first_seen_at = observed_at
            first_seen_scan_id = scan_id
        if not isinstance(last_seen_at, datetime) or observed_at >= last_seen_at:
            last_seen_at = observed_at
            last_seen_scan_id = scan_id

        occurrence_count = int(historical.get("occurrence_count") or 0)
        if occurrence_inserted:
            occurrence_count += 1

        await session.execute(
            text(
                """
                UPDATE historical_findings
                SET title = :title,
                    vulnerability_type = :vulnerability_type,
                    route_group = :route_group,
                    target = :target,
                    latest_severity = :latest_severity,
                    latest_verification_state = :latest_verification_state,
                    latest_source_type = :latest_source_type,
                    first_seen_scan_id = :first_seen_scan_id,
                    last_seen_scan_id = :last_seen_scan_id,
                    latest_finding_id = :latest_finding_id,
                    first_seen_at = :first_seen_at,
                    last_seen_at = :last_seen_at,
                    occurrence_count = :occurrence_count
                WHERE id = :id
                """
            ),
            {
                "id": historical_id,
                "title": snapshot["title"],
                "vulnerability_type": snapshot["vulnerability_type"],
                "route_group": snapshot["route_group"],
                "target": snapshot["target"],
                "latest_severity": snapshot["latest_severity"],
                "latest_verification_state": snapshot["latest_verification_state"],
                "latest_source_type": snapshot["latest_source_type"],
                "first_seen_scan_id": str(first_seen_scan_id) if first_seen_scan_id else None,
                "last_seen_scan_id": str(last_seen_scan_id) if last_seen_scan_id else None,
                "latest_finding_id": str(snapshot["finding_id"]),
                "first_seen_at": first_seen_at,
                "last_seen_at": last_seen_at,
                "occurrence_count": occurrence_count,
            },
        )
        historical["first_seen_at"] = first_seen_at
        historical["last_seen_at"] = last_seen_at
        historical["first_seen_scan_id"] = first_seen_scan_id
        historical["last_seen_scan_id"] = last_seen_scan_id
        historical["occurrence_count"] = occurrence_count
        archived_count += 1

    return archived_count
