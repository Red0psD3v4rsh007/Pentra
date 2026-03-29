"""Persistent intelligence store — accumulates knowledge across scans.

Provides three capabilities:
  1. Pattern fingerprints: hash-based dedup of recurring findings
  2. Trending tracker: track which vulnerability types are increasing/decreasing
  3. Target knowledge: remember discovered endpoints, auth surfaces, technologies per asset
"""

from __future__ import annotations

import hashlib
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


def fingerprint_finding(finding: dict[str, Any]) -> str:
    """Create a stable hash fingerprint for a finding to enable cross-scan dedup."""
    components = [
        str(finding.get("vulnerability_type") or "").lower(),
        str(finding.get("route_group") or finding.get("endpoint") or "").lower(),
        str(finding.get("tool_source") or "").lower(),
    ]
    raw = "|".join(components)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def build_trending_patterns(
    scans: list[Any],
    *,
    window: int = 6,
) -> list[dict[str, Any]]:
    """Track vulnerability types that are increasing or decreasing across scans.

    Compares the most recent `window` scans to the previous `window` scans.
    Returns patterns with direction: 'increasing', 'decreasing', 'stable', or 'new'.
    """
    completed = [s for s in scans if str(getattr(s, "status", "")) == "completed"]
    completed.sort(key=lambda s: getattr(s, "completed_at", None) or getattr(s, "created_at", datetime.min.replace(tzinfo=timezone.utc)))

    if len(completed) < 2:
        return []

    recent = completed[-window:]
    previous = completed[max(0, len(completed) - window * 2):-window] if len(completed) > window else []

    recent_types: dict[str, int] = defaultdict(int)
    previous_types: dict[str, int] = defaultdict(int)

    for scan in recent:
        for finding in getattr(scan, "findings", []) or []:
            vtype = _finding_vuln_type(finding)
            if vtype:
                recent_types[vtype] += 1

    for scan in previous:
        for finding in getattr(scan, "findings", []) or []:
            vtype = _finding_vuln_type(finding)
            if vtype:
                previous_types[vtype] += 1

    all_types = set(recent_types.keys()) | set(previous_types.keys())
    trends: list[dict[str, Any]] = []
    for vtype in all_types:
        recent_count = recent_types.get(vtype, 0)
        previous_count = previous_types.get(vtype, 0)

        if previous_count == 0 and recent_count > 0:
            direction = "new"
        elif recent_count > previous_count:
            direction = "increasing"
        elif recent_count < previous_count:
            direction = "decreasing"
        else:
            direction = "stable"

        trends.append({
            "vulnerability_type": vtype,
            "recent_count": recent_count,
            "previous_count": previous_count,
            "direction": direction,
            "delta": recent_count - previous_count,
        })

    trends.sort(key=lambda t: (-abs(t["delta"]), t["vulnerability_type"]))
    return trends[:15]


def build_target_knowledge(scans: list[Any]) -> list[dict[str, Any]]:
    """Accumulate discovered endpoints, forms, technologies per asset across scans.

    Persists knowledge about what Pentra has learned about each target over time.
    """
    from pentra_common.storage.artifacts import read_json_artifact

    assets: dict[str, dict[str, Any]] = {}
    for scan in scans:
        asset_id = str(getattr(scan, "asset_id", ""))
        if not asset_id:
            continue

        asset = assets.setdefault(asset_id, {
            "asset_id": asset_id,
            "asset_name": _scan_asset_name(scan),
            "target": _scan_target(scan),
            "scan_count": 0,
            "endpoints": set(),
            "forms": set(),
            "technologies": set(),
            "auth_surfaces": set(),
            "vulnerability_types": set(),
            "first_seen": None,
            "last_seen": None,
        })

        asset["scan_count"] += 1
        scan_time = getattr(scan, "completed_at", None) or getattr(scan, "created_at", None)
        if scan_time:
            if asset["first_seen"] is None or scan_time < asset["first_seen"]:
                asset["first_seen"] = scan_time
            if asset["last_seen"] is None or scan_time > asset["last_seen"]:
                asset["last_seen"] = scan_time

        # Extract knowledge from artifacts
        for artifact in getattr(scan, "artifacts", []) or []:
            metadata = getattr(artifact, "metadata_", None) or {}
            if not isinstance(metadata, dict):
                continue
            summary = metadata.get("summary") or {}
            if not isinstance(summary, dict):
                continue

            # Endpoints from stateful context
            stateful = summary.get("stateful_context") or {}
            if isinstance(stateful, dict):
                page_count = int(stateful.get("page_count", 0) or 0)
                form_count = int(stateful.get("form_count", 0) or 0)
                if page_count:
                    asset["endpoints"].add(f"pages:{page_count}")
                if form_count:
                    asset["forms"].add(f"forms:{form_count}")

            # Technologies
            tech_counts = summary.get("technology_counts") or {}
            if isinstance(tech_counts, dict):
                for tech in tech_counts:
                    asset["technologies"].add(str(tech))

        # Extract knowledge from findings
        for finding in getattr(scan, "findings", []) or []:
            vtype = _finding_vuln_type(finding)
            if vtype:
                asset["vulnerability_types"].add(vtype)

            endpoint = _finding_endpoint(finding)
            if endpoint:
                asset["endpoints"].add(endpoint)

            # Track auth surfaces
            evidence = getattr(finding, "evidence", None) or {}
            if isinstance(evidence, dict):
                classification = evidence.get("classification") or {}
                if not isinstance(classification, dict):
                    classification = {}
                surface = classification.get("surface") or evidence.get("surface")
                route = classification.get("route_group") or evidence.get("route_group") or _finding_endpoint(finding)
                if surface == "web" and any(
                    kw in str(route).lower()
                    for kw in ("login", "auth", "oauth", "token")
                ):
                    asset["auth_surfaces"].add(str(route))

    result = []
    for asset in assets.values():
        result.append({
            "asset_id": asset["asset_id"],
            "asset_name": asset["asset_name"],
            "target": asset["target"],
            "scan_count": asset["scan_count"],
            "known_endpoints": len(asset["endpoints"]),
            "known_forms": len(asset["forms"]),
            "known_technologies": sorted(asset["technologies"]),
            "known_auth_surfaces": sorted(asset["auth_surfaces"]),
            "known_vulnerability_types": sorted(asset["vulnerability_types"]),
            "first_seen": asset["first_seen"],
            "last_seen": asset["last_seen"],
        })

    result.sort(key=lambda a: -(a["scan_count"]))
    return result[:12]


def _finding_vuln_type(finding: Any) -> str:
    """Extract vulnerability type from a Finding model."""
    direct = getattr(finding, "vulnerability_type", None)
    if direct:
        return str(direct).strip()

    evidence = getattr(finding, "evidence", None) or {}
    if isinstance(evidence, dict):
        classification = evidence.get("classification") or {}
        if isinstance(classification, dict):
            vtype = classification.get("vulnerability_type")
            if vtype:
                return str(vtype).strip()
        vtype = evidence.get("vulnerability_type")
        if vtype:
            return str(vtype).strip()
    return ""


def _finding_endpoint(finding: Any) -> str:
    """Extract endpoint from a Finding model."""
    evidence = getattr(finding, "evidence", None) or {}
    if isinstance(evidence, dict):
        classification = evidence.get("classification") or {}
        if isinstance(classification, dict):
            route_group = classification.get("route_group")
            if route_group:
                return str(route_group).strip()
        endpoint = evidence.get("endpoint") or evidence.get("target")
        if endpoint:
            return str(endpoint).strip()
    return ""


def _scan_asset_name(scan: Any) -> str:
    if getattr(scan, "asset", None) is not None and getattr(scan.asset, "name", None):
        return str(scan.asset.name)
    return f"Asset {str(getattr(scan, 'asset_id', 'unknown'))[:8]}"


def _scan_target(scan: Any) -> str:
    if getattr(scan, "asset", None) is not None and getattr(scan.asset, "target", None):
        return str(scan.asset.target)
    return "unknown-target"
