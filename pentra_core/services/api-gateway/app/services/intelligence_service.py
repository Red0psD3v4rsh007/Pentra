"""Cross-scan intelligence aggregation for the product UI."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import uuid
from typing import Any

from sqlalchemy import distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from pentra_common.storage.artifacts import read_json_artifact

from app.models.asset import Asset
from app.models.attack_graph import ScanArtifact
from app.models.finding import Finding
from app.models.scan import Scan
from app.services import scan_service
from app.services.intelligence_store import (
    build_trending_patterns,
    build_target_knowledge,
    fingerprint_finding,
)

_SEVERITIES = ("critical", "high", "medium", "low", "info")
_VERIFICATION_STATES = ("verified", "suspected", "detected")
_TERMINAL_SCAN_STATES = {"completed", "failed", "rejected"}


def _zero_severity_counts() -> dict[str, int]:
    return {severity: 0 for severity in _SEVERITIES}


def _zero_verification_counts() -> dict[str, int]:
    return {state: 0 for state in _VERIFICATION_STATES}


def _summary_for_artifact(artifact: ScanArtifact) -> dict[str, Any]:
    metadata = artifact.metadata_ or {}
    if not isinstance(metadata, dict):
        return {}
    summary = metadata.get("summary")
    return summary if isinstance(summary, dict) else {}


def _scan_asset_name(scan: Scan) -> str:
    if getattr(scan, "asset", None) is not None and getattr(scan.asset, "name", None):
        return str(scan.asset.name)
    return f"Asset {str(scan.asset_id)[:8]}"


def _scan_target(scan: Scan) -> str:
    if getattr(scan, "asset", None) is not None and getattr(scan.asset, "target", None):
        return str(scan.asset.target)
    return "unknown-target"


def _scan_severity_counts(scan: Scan) -> dict[str, int]:
    summary = getattr(scan, "result_summary", None) or {}
    if isinstance(summary, dict):
        counts = summary.get("severity_counts")
        if isinstance(counts, dict):
            return {severity: int(counts.get(severity, 0) or 0) for severity in _SEVERITIES}

    counts = _zero_severity_counts()
    for finding in getattr(scan, "findings", []) or []:
        counts[_severity_from_finding(finding)] += 1
    return counts


def _scan_verification_counts(scan: Scan) -> dict[str, int]:
    summary = getattr(scan, "result_summary", None) or {}
    if isinstance(summary, dict):
        counts = summary.get("verification_counts")
        if isinstance(counts, dict):
            return {
                state: int(counts.get(state, 0) or 0)
                for state in _VERIFICATION_STATES
            }

    counts = _zero_verification_counts()
    for finding in getattr(scan, "findings", []) or []:
        counts[_verification_from_finding(finding)] += 1
    return counts


def _tracked_vulnerability_types(scans: list[Scan]) -> list[str]:
    items = {
        vulnerability_type
        for scan in scans
        for finding in (getattr(scan, "findings", []) or [])
        for vulnerability_type in [scan_service._finding_vulnerability_type(finding)]
        if vulnerability_type
    }
    return sorted(items)


def _severity_from_finding(finding: Finding) -> str:
    severity = str(getattr(finding, "severity", "info") or "info").lower()
    return severity if severity in _SEVERITIES else "info"


def _verification_from_finding(finding: Finding) -> str:
    state = scan_service._verification_state_for_finding(finding) or "detected"
    return state if state in _VERIFICATION_STATES else "detected"


def _finding_primary_technology(finding: Finding) -> str | None:
    evidence = getattr(finding, "evidence", None) or {}
    if not isinstance(evidence, dict):
        return None
    classification = evidence.get("classification") or {}
    if not isinstance(classification, dict):
        return None
    value = classification.get("primary_technology")
    if not value:
        return None
    normalized = str(value).strip()
    return normalized or None


def _path_targets(graph_payload: dict[str, Any] | None) -> list[str]:
    if not isinstance(graph_payload, dict):
        return []
    path_summary = graph_payload.get("path_summary")
    if not isinstance(path_summary, dict):
        return []
    targets = path_summary.get("targets_reached")
    if not isinstance(targets, list):
        return []
    return [str(item) for item in targets if item]


def _pattern_title(vulnerability_type: str | None, route_group: str | None, target: str) -> str:
    name = (vulnerability_type or "unclassified_pattern").replace("_", " ").strip().title()
    return f"{name} on {route_group or target}"


def _build_pattern_matches(scans: list[Scan]) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}

    for scan in scans:
        for finding in getattr(scan, "findings", []) or []:
            snapshot = scan_service._finding_snapshot(finding)
            vulnerability_type = snapshot.get("vulnerability_type")
            route_group = snapshot.get("route_group")
            target = str(snapshot.get("target") or _scan_target(scan))
            key = f"{vulnerability_type or 'unclassified'}:{route_group or target}".lower()
            group = groups.setdefault(
                key,
                {
                    "key": key,
                    "title": _pattern_title(vulnerability_type, route_group, target),
                    "vulnerability_type": vulnerability_type,
                    "route_group": route_group,
                    "tool_sources": set(),
                    "scan_ids": set(),
                    "finding_count": 0,
                    "highest_severity": "info",
                    "severity_counts": _zero_severity_counts(),
                    "verification_counts": _zero_verification_counts(),
                    "last_seen": None,
                    "first_seen": None,
                },
            )

            severity = _severity_from_finding(finding)
            verification_state = _verification_from_finding(finding)
            group["tool_sources"].add(str(snapshot.get("tool_source") or "unknown"))
            group["scan_ids"].add(str(scan.id))
            group["finding_count"] += 1
            group["severity_counts"][severity] += 1
            group["verification_counts"][verification_state] += 1
            if scan_service._severity_rank(severity) > scan_service._severity_rank(group["highest_severity"]):
                group["highest_severity"] = severity
            created_at = getattr(finding, "created_at", None)
            if group["last_seen"] is None or (created_at and created_at > group["last_seen"]):
                group["last_seen"] = created_at
            if group["first_seen"] is None or (created_at and created_at < group["first_seen"]):
                group["first_seen"] = created_at

    pattern_matches = []
    for group in groups.values():
        pattern_matches.append(
            {
                **group,
                "tool_sources": sorted(group["tool_sources"]),
                "scan_count": len(group["scan_ids"]),
                "fingerprint": fingerprint_finding({
                    "vulnerability_type": group.get("vulnerability_type"),
                    "route_group": group.get("route_group"),
                }),
            }
        )

    pattern_matches.sort(
        key=lambda item: (
            -scan_service._severity_rank(str(item["highest_severity"])),
            -int(item["verification_counts"]["verified"]),
            -int(item["finding_count"]),
            item["last_seen"] or datetime.min.replace(tzinfo=timezone.utc),
        )
    )
    return pattern_matches[:12]


def _build_technology_clusters(scans: list[Scan]) -> list[dict[str, Any]]:
    clusters: dict[str, dict[str, Any]] = {}

    for scan in scans:
        asset_name = _scan_asset_name(scan)
        asset_target = _scan_target(scan)

        for artifact in getattr(scan, "artifacts", []) or []:
            summary = _summary_for_artifact(artifact)
            technology_counts = summary.get("technology_counts") or {}
            if not isinstance(technology_counts, dict):
                continue
            for technology, count in technology_counts.items():
                normalized = str(technology).strip()
                if not normalized:
                    continue
                cluster = clusters.setdefault(
                    normalized,
                    {
                        "technology": normalized,
                        "asset_ids": set(),
                        "scan_ids": set(),
                        "endpoint_count": 0,
                        "finding_count": 0,
                        "severity_counts": _zero_severity_counts(),
                        "related_assets": set(),
                        "related_targets": set(),
                    },
                )
                cluster["asset_ids"].add(str(scan.asset_id))
                cluster["scan_ids"].add(str(scan.id))
                cluster["endpoint_count"] += int(count or 0)
                cluster["related_assets"].add(asset_name)
                cluster["related_targets"].add(asset_target)

        for finding in getattr(scan, "findings", []) or []:
            technology = _finding_primary_technology(finding)
            if not technology:
                continue
            cluster = clusters.setdefault(
                technology,
                {
                    "technology": technology,
                    "asset_ids": set(),
                    "scan_ids": set(),
                    "endpoint_count": 0,
                    "finding_count": 0,
                    "severity_counts": _zero_severity_counts(),
                    "related_assets": set(),
                    "related_targets": set(),
                },
            )
            cluster["asset_ids"].add(str(scan.asset_id))
            cluster["scan_ids"].add(str(scan.id))
            cluster["finding_count"] += 1
            cluster["severity_counts"][_severity_from_finding(finding)] += 1
            cluster["related_assets"].add(asset_name)
            cluster["related_targets"].add(asset_target)

    technology_clusters = []
    for cluster in clusters.values():
        technology_clusters.append(
            {
                "technology": cluster["technology"],
                "asset_count": len(cluster["asset_ids"]),
                "scan_count": len(cluster["scan_ids"]),
                "endpoint_count": int(cluster["endpoint_count"]),
                "finding_count": int(cluster["finding_count"]),
                "severity_counts": cluster["severity_counts"],
                "related_assets": sorted(cluster["related_assets"]),
                "related_targets": sorted(cluster["related_targets"]),
            }
        )

    technology_clusters.sort(
        key=lambda item: (
            -item["finding_count"],
            -item["endpoint_count"],
            item["technology"].lower(),
        )
    )
    return technology_clusters[:12]


def _build_route_groups(scans: list[Scan]) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}

    for scan in scans:
        for finding in getattr(scan, "findings", []) or []:
            route_group = scan_service._finding_route_group(finding) or scan_service._finding_target(finding)
            if not route_group:
                continue
            group = groups.setdefault(
                route_group,
                {
                    "route_group": route_group,
                    "asset_targets": set(),
                    "scan_ids": set(),
                    "finding_count": 0,
                    "highest_severity": "info",
                    "severity_counts": _zero_severity_counts(),
                    "verification_counts": _zero_verification_counts(),
                    "vulnerability_types": set(),
                },
            )
            severity = _severity_from_finding(finding)
            verification_state = _verification_from_finding(finding)
            vulnerability_type = scan_service._finding_vulnerability_type(finding)
            group["asset_targets"].add(_scan_target(scan))
            group["scan_ids"].add(str(scan.id))
            group["finding_count"] += 1
            group["severity_counts"][severity] += 1
            group["verification_counts"][verification_state] += 1
            if vulnerability_type:
                group["vulnerability_types"].add(vulnerability_type)
            if scan_service._severity_rank(severity) > scan_service._severity_rank(group["highest_severity"]):
                group["highest_severity"] = severity

    route_groups = []
    for group in groups.values():
        route_groups.append(
            {
                "route_group": group["route_group"],
                "asset_targets": sorted(group["asset_targets"]),
                "scan_count": len(group["scan_ids"]),
                "finding_count": group["finding_count"],
                "highest_severity": group["highest_severity"],
                "severity_counts": group["severity_counts"],
                "verification_counts": group["verification_counts"],
                "vulnerability_types": sorted(group["vulnerability_types"]),
            }
        )

    route_groups.sort(
        key=lambda item: (
            -scan_service._severity_rank(str(item["highest_severity"])),
            -int(item["verification_counts"]["verified"]),
            -int(item["finding_count"]),
            str(item["route_group"]).lower(),
        )
    )
    return route_groups[:12]


def _build_surface_expansions(scans: list[Scan]) -> list[dict[str, Any]]:
    expansions: list[dict[str, Any]] = []

    for scan in scans:
        discovered_targets: set[str] = set()
        technologies: set[str] = set()
        artifact_types: set[str] = set()
        discovered_forms = 0

        for artifact in getattr(scan, "artifacts", []) or []:
            summary = _summary_for_artifact(artifact)
            targets = summary.get("targets")
            if isinstance(targets, list):
                discovered_targets.update(str(item) for item in targets if item)

            technology_counts = summary.get("technology_counts") or {}
            if isinstance(technology_counts, dict):
                technologies.update(str(item) for item in technology_counts.keys() if item)

            stateful_context = summary.get("stateful_context") or {}
            if isinstance(stateful_context, dict):
                discovered_forms += int(stateful_context.get("form_count", 0) or 0)

            if summary:
                artifact_types.add(str(artifact.artifact_type))

        if not discovered_targets and not technologies and not discovered_forms:
            continue

        expansions.append(
            {
                "scan_id": scan.id,
                "asset_id": scan.asset_id,
                "asset_name": _scan_asset_name(scan),
                "target": _scan_target(scan),
                "generated_at": scan.completed_at or scan.updated_at or scan.created_at,
                "discovered_targets": len(discovered_targets),
                "discovered_forms": discovered_forms,
                "technologies": sorted(technologies),
                "artifact_types": sorted(artifact_types),
            }
        )

    expansions.sort(
        key=lambda item: item.get("generated_at") or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    return expansions[:12]


def _build_exploit_trends(scans: list[Scan]) -> list[dict[str, Any]]:
    completed_scans = [scan for scan in scans if str(scan.status) == "completed"]
    completed_scans.sort(key=lambda scan: scan.completed_at or scan.created_at)

    trends = []
    for scan in completed_scans[-12:]:
        summary = scan.result_summary or {}
        verification_counts = summary.get("verification_counts") if isinstance(summary, dict) else {}
        if not isinstance(verification_counts, dict):
            verification_counts = {}
        trends.append(
            {
                "scan_id": scan.id,
                "asset_name": _scan_asset_name(scan),
                "generated_at": scan.completed_at or scan.created_at,
                "verified": int(verification_counts.get("verified", 0) or 0),
                "suspected": int(verification_counts.get("suspected", 0) or 0),
                "detected": int(verification_counts.get("detected", 0) or 0),
            }
        )
    return trends


async def _build_retest_deltas(
    scans: list[Scan],
    *,
    tenant_id: uuid.UUID,
    session: AsyncSession,
) -> list[dict[str, Any]]:
    deltas: list[dict[str, Any]] = []

    for scan in scans:
        if str(scan.status) != "completed":
            continue
        config = scan.config or {}
        if not isinstance(config, dict):
            continue
        retest = config.get("retest")
        if not isinstance(retest, dict):
            continue
        raw_baseline = retest.get("baseline_scan_id") or retest.get("source_scan_id")
        if not raw_baseline:
            continue
        try:
            baseline_scan_id = uuid.UUID(str(raw_baseline))
        except ValueError:
            continue
        comparison = await scan_service.get_scan_comparison(
            scan_id=scan.id,
            tenant_id=tenant_id,
            baseline_scan_id=baseline_scan_id,
            session=session,
        )
        deltas.append(
            {
                "scan_id": scan.id,
                "baseline_scan_id": comparison.get("baseline_scan_id"),
                "asset_name": _scan_asset_name(scan),
                "target": _scan_target(scan),
                "generated_at": scan.completed_at or scan.created_at,
                "summary": comparison.get("summary") or "Retest comparison available.",
                "counts": comparison.get("counts") or {},
            }
        )
        if len(deltas) >= 8:
            break

    return deltas


def _build_advisory_summaries(scans: list[Scan]) -> list[dict[str, Any]]:
    advisories: list[dict[str, Any]] = []

    for scan in scans:
        advisory_artifacts = [
            artifact
            for artifact in getattr(scan, "artifacts", []) or []
            if str(getattr(artifact, "artifact_type", "")) == "ai_reasoning"
        ]
        if not advisory_artifacts:
            continue
        artifact = sorted(advisory_artifacts, key=lambda item: item.created_at, reverse=True)[0]
        payload = read_json_artifact(artifact.storage_ref)
        if not isinstance(payload, dict):
            continue
        response = payload.get("response") or {}
        parsed = response.get("parsed") if isinstance(response, dict) else {}
        report = parsed.get("report") if isinstance(parsed, dict) else {}
        if not isinstance(report, dict):
            continue
        draft_summary = str(report.get("draft_summary") or "").strip()
        if not draft_summary:
            continue
        advisories.append(
            {
                "scan_id": scan.id,
                "asset_name": _scan_asset_name(scan),
                "generated_at": payload.get("generated_at") or artifact.created_at,
                "advisory_mode": payload.get("advisory_mode"),
                "provider": payload.get("provider"),
                "model": payload.get("model"),
                "draft_summary": draft_summary,
                "prioritization_notes": report.get("prioritization_notes"),
                "remediation_focus": [
                    str(item) for item in (report.get("remediation_focus") or []) if item
                ],
            }
        )

    advisories.sort(
        key=lambda item: item.get("generated_at") or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    return advisories[:8]


async def get_intelligence_summary(
    *,
    tenant_id: uuid.UUID,
    session: AsyncSession,
    scan_limit: int = 100,
) -> dict[str, Any]:
    scans_stmt = (
        select(Scan)
        .where(Scan.tenant_id == tenant_id)
        .options(
            selectinload(Scan.asset),
            selectinload(Scan.findings),
            selectinload(Scan.artifacts),
        )
        .order_by(Scan.created_at.desc())
        .limit(scan_limit)
    )
    scans = list((await session.execute(scans_stmt)).scalars().all())

    total_scans = (
        await session.execute(select(func.count()).select_from(Scan).where(Scan.tenant_id == tenant_id))
    ).scalar_one()
    completed_scans = (
        await session.execute(
            select(func.count()).select_from(Scan).where(
                Scan.tenant_id == tenant_id,
                Scan.status == "completed",
            )
        )
    ).scalar_one()
    active_scans = (
        await session.execute(
            select(func.count()).select_from(Scan).where(
                Scan.tenant_id == tenant_id,
                ~Scan.status.in_(tuple(_TERMINAL_SCAN_STATES)),
            )
        )
    ).scalar_one()
    assets_with_history = (
        await session.execute(
            select(func.count(distinct(Scan.asset_id))).where(Scan.tenant_id == tenant_id)
        )
    ).scalar_one()

    pattern_matches = _build_pattern_matches(scans)
    technology_clusters = _build_technology_clusters(scans)
    route_groups = _build_route_groups(scans)
    surface_expansions = _build_surface_expansions(scans)
    exploit_trends = _build_exploit_trends(scans)
    retest_deltas = await _build_retest_deltas(scans, tenant_id=tenant_id, session=session)
    advisory_summaries = _build_advisory_summaries(scans)

    trending_patterns = build_trending_patterns(scans)
    target_knowledge = build_target_knowledge(scans)

    verified_findings = sum(
        1
        for scan in scans
        for finding in (getattr(scan, "findings", []) or [])
        if _verification_from_finding(finding) == "verified"
    )

    return {
        "generated_at": datetime.now(timezone.utc),
        "definition": (
            "Intelligence in Pentra means cross-scan offensive insight derived from persisted "
            "scan findings, artifact summaries, retest deltas, attack-graph outcomes, and advisory artifacts."
        ),
        "overview": {
            "total_scans": int(total_scans),
            "completed_scans": int(completed_scans),
            "active_scans": int(active_scans),
            "assets_with_history": int(assets_with_history),
            "verified_findings": int(verified_findings),
            "recurring_patterns": len(pattern_matches),
            "technology_clusters": len(technology_clusters),
            "route_groups": len(route_groups),
            "trending_patterns": len(trending_patterns),
            "tracked_assets": len(target_knowledge),
        },
        "pattern_matches": pattern_matches,
        "technology_clusters": technology_clusters,
        "route_groups": route_groups,
        "surface_expansions": surface_expansions,
        "exploit_trends": exploit_trends,
        "retest_deltas": retest_deltas,
        "advisory_summaries": advisory_summaries,
        "trending_patterns": trending_patterns,
        "target_knowledge": target_knowledge,
    }


async def get_asset_history(
    *,
    asset_id: uuid.UUID,
    tenant_id: uuid.UUID,
    session: AsyncSession,
    limit: int = 20,
) -> dict[str, Any] | None:
    asset_stmt = select(Asset).where(
        Asset.id == asset_id,
        Asset.tenant_id == tenant_id,
        Asset.is_active == True,  # noqa: E712
    )
    asset = (await session.execute(asset_stmt)).scalar_one_or_none()
    if asset is None:
        return None

    total_scans = (
        await session.execute(
            select(func.count()).select_from(Scan).where(
                Scan.tenant_id == tenant_id,
                Scan.asset_id == asset_id,
            )
        )
    ).scalar_one()

    recent_scans_stmt = (
        select(Scan)
        .where(Scan.tenant_id == tenant_id, Scan.asset_id == asset_id)
        .options(
            selectinload(Scan.asset),
            selectinload(Scan.findings),
            selectinload(Scan.artifacts),
        )
        .order_by(Scan.created_at.desc())
        .limit(limit)
    )
    scans = list((await session.execute(recent_scans_stmt)).scalars().all())

    knowledge_scans_stmt = (
        select(Scan)
        .where(Scan.tenant_id == tenant_id, Scan.asset_id == asset_id)
        .options(
            selectinload(Scan.asset),
            selectinload(Scan.findings),
            selectinload(Scan.artifacts),
        )
        .order_by(Scan.created_at.desc())
    )
    knowledge_scans = list((await session.execute(knowledge_scans_stmt)).scalars().all())

    target_knowledge = build_target_knowledge(knowledge_scans)
    asset_knowledge = next(
        (
            item
            for item in target_knowledge
            if str(item.get("asset_id")) == str(asset_id)
        ),
        None,
    )

    entries: list[dict[str, Any]] = []
    for scan in scans:
        comparison_summary: str | None = None
        comparison_counts: dict[str, int] = {}
        baseline_scan_id: uuid.UUID | None = None

        if str(scan.status) == "completed":
            comparison = await scan_service.get_scan_comparison(
                scan_id=scan.id,
                tenant_id=tenant_id,
                session=session,
            )
            if comparison is not None:
                comparison_summary = comparison.get("summary")
                raw_counts = comparison.get("counts") or {}
                if isinstance(raw_counts, dict):
                    comparison_counts = {
                        key: int(raw_counts.get(key, 0) or 0)
                        for key in ("new", "resolved", "persistent", "escalated")
                    }
                raw_baseline = comparison.get("baseline_scan_id")
                if raw_baseline:
                    try:
                        baseline_scan_id = uuid.UUID(str(raw_baseline))
                    except (TypeError, ValueError):
                        baseline_scan_id = None

        severity_counts = _scan_severity_counts(scan)
        verification_counts = _scan_verification_counts(scan)

        entries.append(
            {
                "scan_id": scan.id,
                "scan_type": str(scan.scan_type),
                "status": str(scan.status),
                "priority": str(scan.priority),
                "generated_at": scan.completed_at or scan.updated_at or scan.created_at,
                "started_at": scan.started_at,
                "completed_at": scan.completed_at,
                "severity_counts": severity_counts,
                "verification_counts": verification_counts,
                "total_findings": sum(severity_counts.values()),
                "comparison_summary": comparison_summary,
                "comparison_counts": comparison_counts,
                "baseline_scan_id": baseline_scan_id,
            }
        )

    return {
        "asset_id": asset.id,
        "asset_name": asset.name,
        "target": asset.target,
        "generated_at": datetime.now(timezone.utc),
        "total_scans": int(total_scans),
        "known_technologies": (
            list(asset_knowledge.get("known_technologies", []))
            if isinstance(asset_knowledge, dict)
            else []
        ),
        "tracked_vulnerability_types": _tracked_vulnerability_types(knowledge_scans),
        "entries": entries,
    }
