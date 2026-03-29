"""Phase 7 competitive benchmark harness.

Runs repeatable live benchmarks against the local Pentra stack and persists a
baseline metrics artifact into the repo workspace.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
import json
import os
from pathlib import Path
from statistics import mean
import subprocess
import sys
import time
from typing import Any

import httpx
import redis.asyncio as aioredis

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from pentra_core.scripts.local.proof_contract import new_run_id, stamp_proof_payload
from run_phase6_chaos_matrix import (
    API_BASE_URL,
    ASSET_ID,
    DEMO_TARGET_URL,
    LOG_DIR,
    ORCH_BASE_URL,
    REDIS_URL,
    ROOT_DIR,
    STATEFUL_FULL_CONFIG,
    WORKER_HEALTH_PORTS,
    WORKER_LIVE_TOOLS,
    _assert_http_ok,
    _cleanup_active_scans,
    _parse_datetime,
    _start_service,
    _terminate_service,
    _wait_for_json,
    _worker_health_url,
)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(line_buffering=True)
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(line_buffering=True)

OUTPUT_DIR = ROOT_DIR / ".local" / "pentra" / "phase6"
OUTPUT_PATH = OUTPUT_DIR / "benchmark_matrix_latest.json"
POLL_INTERVAL_SECONDS = float(os.getenv("PENTRA_PHASE6_POLL_INTERVAL_SECONDS", "1"))
BENCHMARK_PROJECT_ID = os.getenv(
    "PENTRA_BENCHMARK_PROJECT_ID",
    "33333333-3333-3333-3333-333333333333",
)
BENCHMARK_ASSET_GROUP_NAME = os.getenv(
    "PENTRA_BENCHMARK_ASSET_GROUP_NAME",
    "Phase 7 Local Benchmark Group",
)
TRUE_COLD_START_PROBE = os.getenv(
    "PENTRA_TRUE_COLD_START_PROBE",
    "true",
).lower() not in {"0", "false", "no", "off"}
TRUE_COLD_START_FAMILY = os.getenv("PENTRA_TRUE_COLD_START_FAMILY", "web")
TRUE_COLD_START_IMAGES = tuple(
    image.strip()
    for image in os.getenv(
        "PENTRA_TRUE_COLD_START_IMAGES",
        "projectdiscovery/httpx:latest,secsi/ffuf:latest",
    ).split(",")
    if image.strip()
)
BENCHMARK_TENANT_ID = os.getenv(
    "PENTRA_BENCHMARK_TENANT_ID",
    "22222222-2222-2222-2222-222222222222",
)
BENCHMARK_DAILY_SCAN_QUOTA = int(os.getenv("PENTRA_BENCHMARK_DAILY_SCAN_QUOTA", "1000"))
SQL_DATABASE_URL = os.getenv(
    "PENTRA_BENCHMARK_SQL_DATABASE_URL",
    os.getenv("DATABASE_URL", "postgresql+asyncpg://pentra:pentra@localhost:5433/pentra_dev").replace(
        "+asyncpg",
        "",
    ),
)
PROOF_RUN_ID = new_run_id()


@dataclass(frozen=True)
class BenchmarkAssetSpec:
    name: str
    asset_type: str
    target: str
    description: str


BENCHMARK_LOCAL_ASSETS: tuple[BenchmarkAssetSpec, ...] = (
    BenchmarkAssetSpec(
        name="Phase 7 Demo API Mirror",
        asset_type="api",
        target=DEMO_TARGET_URL,
        description="Local-safe benchmark mirror for concurrent API load.",
    ),
    BenchmarkAssetSpec(
        name="Phase 7 Demo Web Mirror",
        asset_type="web_app",
        target=DEMO_TARGET_URL,
        description="Local-safe benchmark mirror for web-app batch load.",
    ),
    *tuple(
        BenchmarkAssetSpec(
            name=f"Phase 7 Demo Benchmark Mirror {index:02d}",
            asset_type="web_app" if index % 2 == 0 else "api",
            target=DEMO_TARGET_URL,
            description="Additional local-safe benchmark mirror for concurrent load.",
        )
        for index in range(3, 11)
    ),
)


@dataclass(frozen=True)
class BenchmarkScenario:
    key: str
    label: str
    mode: str
    scan_type: str
    config: dict[str, Any]
    iterations: int
    timeout_seconds: int
    asset_role: str = "primary"
    concurrency: int = 1
    batch_size: int = 1


@dataclass(frozen=True)
class BenchmarkContext:
    project_id: str
    primary_asset_id: str
    local_asset_ids: tuple[str, ...]
    web_asset_id: str
    asset_group_id: str


SCENARIOS: tuple[BenchmarkScenario, ...] = (
    BenchmarkScenario(
        key="recon_web_api_v1",
        label="Recon / external_web_api_v1",
        mode="single",
        scan_type="recon",
        config={"profile_id": "external_web_api_v1"},
        iterations=1,
        timeout_seconds=120,
    ),
    BenchmarkScenario(
        key="vuln_web_api_v1",
        label="Vuln / external_web_api_v1",
        mode="single",
        scan_type="vuln",
        config={"profile_id": "external_web_api_v1"},
        iterations=1,
        timeout_seconds=180,
    ),
    BenchmarkScenario(
        key="full_web_api_v1",
        label="Full / external_web_api_v1",
        mode="single",
        scan_type="full",
        config={"profile_id": "external_web_api_v1"},
        iterations=1,
        timeout_seconds=180,
    ),
    BenchmarkScenario(
        key="full_stateful_web_api_v1",
        label="Full Stateful / external_web_api_v1",
        mode="single",
        scan_type="full",
        config=STATEFUL_FULL_CONFIG,
        iterations=1,
        timeout_seconds=240,
    ),
    BenchmarkScenario(
        key="full_web_local_web_app",
        label="Full / local web-app asset",
        mode="single",
        scan_type="full",
        config={"profile_id": "external_web_api_v1"},
        iterations=1,
        timeout_seconds=180,
        asset_role="web_local",
    ),
    BenchmarkScenario(
        key="full_multi_asset_batch_direct",
        label="Full / direct multi-asset batch",
        mode="batch_direct",
        scan_type="full",
        config={"profile_id": "external_web_api_v1"},
        iterations=1,
        timeout_seconds=240,
        batch_size=3,
    ),
    BenchmarkScenario(
        key="full_multi_asset_batch_group",
        label="Full / asset-group batch",
        mode="batch_group",
        scan_type="full",
        config={"profile_id": "external_web_api_v1"},
        iterations=1,
        timeout_seconds=240,
        batch_size=3,
    ),
    BenchmarkScenario(
        key="recon_concurrent_1",
        label="Recon / concurrent load x1",
        mode="concurrent",
        scan_type="recon",
        config={"profile_id": "external_web_api_v1"},
        iterations=1,
        timeout_seconds=120,
        concurrency=1,
    ),
    BenchmarkScenario(
        key="recon_concurrent_5",
        label="Recon / concurrent load x5",
        mode="concurrent",
        scan_type="recon",
        config={"profile_id": "external_web_api_v1"},
        iterations=1,
        timeout_seconds=180,
        concurrency=5,
    ),
    BenchmarkScenario(
        key="recon_concurrent_10",
        label="Recon / concurrent load x10",
        mode="concurrent",
        scan_type="recon",
        config={"profile_id": "external_web_api_v1"},
        iterations=1,
        timeout_seconds=240,
        concurrency=10,
    ),
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _seconds_between(start: str | None, end: str | None) -> float | None:
    start_dt = _parse_datetime(start)
    end_dt = _parse_datetime(end)
    if start_dt is None or end_dt is None:
        return None
    return round((end_dt - start_dt).total_seconds(), 3)


def _avg(values: list[float | None]) -> float | None:
    filtered = [value for value in values if value is not None]
    if not filtered:
        return None
    return round(mean(filtered), 3)


def _profile_id_for_scenario(scenario: BenchmarkScenario) -> str | None:
    profile_id = scenario.config.get("profile_id")
    return str(profile_id) if profile_id else None


def _verified_share(verified: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return round(verified / total, 3)


def _build_verification_summary(
    *,
    findings: list[dict[str, Any]],
    profile_id: str | None,
    scan_type: str,
) -> dict[str, Any]:
    by_type: dict[str, dict[str, Any]] = {}
    overall = {
        "total_findings": len(findings),
        "verified": 0,
        "suspected": 0,
        "detected": 0,
        "verified_share": 0.0,
    }

    for finding in findings:
        vulnerability_type = str(finding.get("vulnerability_type") or "unclassified")
        verification_state = str(finding.get("verification_state") or "detected")
        if verification_state not in {"verified", "suspected", "detected"}:
            verification_state = "detected"

        group = by_type.setdefault(
            vulnerability_type,
            {
                "vulnerability_type": vulnerability_type,
                "total_findings": 0,
                "verified": 0,
                "suspected": 0,
                "detected": 0,
                "verified_share": 0.0,
            },
        )
        group["total_findings"] += 1
        group[verification_state] += 1
        overall[verification_state] += 1

    for group in by_type.values():
        group["verified_share"] = _verified_share(
            int(group["verified"]),
            int(group["total_findings"]),
        )

    overall["verified_share"] = _verified_share(
        int(overall["verified"]),
        int(overall["total_findings"]),
    )

    ordered = sorted(
        by_type.values(),
        key=lambda item: (-int(item["verified"]), str(item["vulnerability_type"])),
    )
    return {
        "profile_id": profile_id,
        "scan_type": scan_type,
        "overall": overall,
        "by_type": ordered,
    }


def _merge_verification_summaries(
    summaries: list[dict[str, Any]],
    *,
    profile_id: str | None,
    scan_type: str,
) -> dict[str, Any]:
    by_type: dict[str, dict[str, Any]] = {}
    overall = {
        "total_findings": 0,
        "verified": 0,
        "suspected": 0,
        "detected": 0,
        "verified_share": 0.0,
    }

    for summary in summaries:
        if not isinstance(summary, dict):
            continue
        overall_payload = summary.get("overall") or {}
        if isinstance(overall_payload, dict):
            overall["total_findings"] += int(overall_payload.get("total_findings", 0) or 0)
            overall["verified"] += int(overall_payload.get("verified", 0) or 0)
            overall["suspected"] += int(overall_payload.get("suspected", 0) or 0)
            overall["detected"] += int(overall_payload.get("detected", 0) or 0)

        for entry in summary.get("by_type") or []:
            if not isinstance(entry, dict):
                continue
            vulnerability_type = str(entry.get("vulnerability_type") or "unclassified")
            group = by_type.setdefault(
                vulnerability_type,
                {
                    "vulnerability_type": vulnerability_type,
                    "total_findings": 0,
                    "verified": 0,
                    "suspected": 0,
                    "detected": 0,
                    "verified_share": 0.0,
                },
            )
            group["total_findings"] += int(entry.get("total_findings", 0) or 0)
            group["verified"] += int(entry.get("verified", 0) or 0)
            group["suspected"] += int(entry.get("suspected", 0) or 0)
            group["detected"] += int(entry.get("detected", 0) or 0)

    for group in by_type.values():
        group["verified_share"] = _verified_share(
            int(group["verified"]),
            int(group["total_findings"]),
        )

    overall["verified_share"] = _verified_share(
        int(overall["verified"]),
        int(overall["total_findings"]),
    )

    ordered = sorted(
        by_type.values(),
        key=lambda item: (-int(item["verified"]), str(item["vulnerability_type"])),
    )
    return {
        "profile_id": profile_id,
        "scan_type": scan_type,
        "overall": overall,
        "by_type": ordered,
    }


def _worker_family_from_job(job: dict[str, Any]) -> str:
    worker_id = str(job.get("worker_id") or "").strip()
    if worker_id.startswith("worker-"):
        parts = worker_id.split("-")
        if len(parts) >= 3 and parts[1]:
            return parts[1]
    return "unknown"


def _worker_health_url_map() -> dict[str, str]:
    return {family: _worker_health_url(family) for family in WORKER_HEALTH_PORTS}


async def _fetch_json(client: httpx.AsyncClient, url: str) -> Any:
    response = await client.get(url)
    response.raise_for_status()
    return response.json()


async def _list_project_assets(client: httpx.AsyncClient, project_id: str) -> list[dict[str, Any]]:
    payload = await _fetch_json(
        client,
        f"{API_BASE_URL}/api/v1/projects/{project_id}/assets?page=1&page_size=100",
    )
    if not isinstance(payload, dict):
        return []
    items = payload.get("items")
    return [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []


async def _create_asset(
    client: httpx.AsyncClient,
    *,
    project_id: str,
    spec: BenchmarkAssetSpec,
) -> dict[str, Any]:
    response = await client.post(
        f"{API_BASE_URL}/api/v1/projects/{project_id}/assets",
        json={
            "name": spec.name,
            "asset_type": spec.asset_type,
            "target": spec.target,
            "description": spec.description,
            "tags": {"benchmark": "phase7"},
        },
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise RuntimeError(f"Unexpected asset create response for {spec.name}")
    return payload


async def _list_asset_groups(client: httpx.AsyncClient, project_id: str) -> list[dict[str, Any]]:
    payload = await _fetch_json(
        client,
        f"{API_BASE_URL}/api/v1/projects/{project_id}/asset-groups?page=1&page_size=100",
    )
    if not isinstance(payload, dict):
        return []
    items = payload.get("items")
    return [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []


async def _create_asset_group(
    client: httpx.AsyncClient,
    *,
    project_id: str,
    name: str,
    asset_ids: list[str],
) -> dict[str, Any]:
    response = await client.post(
        f"{API_BASE_URL}/api/v1/projects/{project_id}/asset-groups",
        json={
            "name": name,
            "description": "Phase 7 benchmark multi-target group",
            "asset_ids": asset_ids,
        },
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise RuntimeError(f"Unexpected asset-group create response for {name}")
    return payload


async def _update_asset_group(
    client: httpx.AsyncClient,
    *,
    asset_group_id: str,
    name: str,
    asset_ids: list[str],
) -> dict[str, Any]:
    response = await client.patch(
        f"{API_BASE_URL}/api/v1/asset-groups/{asset_group_id}",
        json={
            "name": name,
            "description": "Phase 7 benchmark multi-target group",
            "asset_ids": asset_ids,
        },
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise RuntimeError(f"Unexpected asset-group update response for {asset_group_id}")
    return payload


async def _ensure_named_asset_group(
    client: httpx.AsyncClient,
    *,
    project_id: str,
    name: str,
    asset_ids: list[str],
) -> dict[str, Any]:
    groups = await _list_asset_groups(client, project_id)
    group = next(
        (item for item in groups if str(item.get("name")) == name),
        None,
    )
    if group is None:
        return await _create_asset_group(
            client,
            project_id=project_id,
            name=name,
            asset_ids=asset_ids,
        )
    existing_ids = [str(item) for item in group.get("asset_ids", [])]
    if existing_ids != asset_ids:
        return await _update_asset_group(
            client,
            asset_group_id=str(group["id"]),
            name=name,
            asset_ids=asset_ids,
        )
    return group


async def _ensure_benchmark_context(client: httpx.AsyncClient) -> BenchmarkContext:
    assets = await _list_project_assets(client, BENCHMARK_PROJECT_ID)
    by_name = {str(asset.get("name")): asset for asset in assets}

    primary = next(
        (
            asset
            for asset in assets
            if str(asset.get("id")) == ASSET_ID
        ),
        None,
    )
    if primary is None:
        raise RuntimeError(f"Primary benchmark asset {ASSET_ID} not found in project {BENCHMARK_PROJECT_ID}")

    ensured_assets: list[dict[str, Any]] = [primary]
    for spec in BENCHMARK_LOCAL_ASSETS:
        asset = by_name.get(spec.name)
        if asset is None:
            asset = await _create_asset(client, project_id=BENCHMARK_PROJECT_ID, spec=spec)
        ensured_assets.append(asset)

    asset_ids = [str(asset["id"]) for asset in ensured_assets]
    web_asset_id = next(
        (
            str(asset["id"])
            for asset in ensured_assets
            if str(asset.get("asset_type")) == "web_app"
            and str(asset.get("target")) == DEMO_TARGET_URL
        ),
        asset_ids[-1],
    )

    group = await _ensure_named_asset_group(
        client,
        project_id=BENCHMARK_PROJECT_ID,
        name=BENCHMARK_ASSET_GROUP_NAME,
        asset_ids=asset_ids,
    )

    return BenchmarkContext(
        project_id=BENCHMARK_PROJECT_ID,
        primary_asset_id=str(primary["id"]),
        local_asset_ids=tuple(asset_ids),
        web_asset_id=web_asset_id,
        asset_group_id=str(group["id"]),
    )


def _true_cold_start_requested() -> bool:
    return TRUE_COLD_START_PROBE and bool(TRUE_COLD_START_IMAGES)


def _docker_image_present(image: str) -> bool:
    result = subprocess.run(
        ["docker", "image", "inspect", image],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def _clear_docker_images(images: tuple[str, ...]) -> dict[str, dict[str, str]]:
    results: dict[str, dict[str, str]] = {}
    for image in images:
        if not _docker_image_present(image):
            results[image] = {"status": "missing", "detail": "not_present"}
            continue
        result = subprocess.run(
            ["docker", "image", "rm", "-f", image],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            results[image] = {"status": "removed", "detail": "removed_for_true_cold_probe"}
        else:
            detail = (result.stderr or result.stdout or "docker image rm failed").strip()
            results[image] = {"status": "failed", "detail": detail[:500]}
    return results


def _psql_scalar(query: str) -> str | None:
    result = subprocess.run(
        [
            "psql",
            SQL_DATABASE_URL,
            "-At",
            "-c",
            query,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "psql query failed").strip()
        raise RuntimeError(detail[:500])
    value = result.stdout.strip()
    return value or None


def _get_daily_scan_quota() -> int:
    value = _psql_scalar(
        "select max_daily_scans from tenant_quotas "
        f"where tenant_id = '{BENCHMARK_TENANT_ID}' limit 1;"
    )
    if value is None:
        raise RuntimeError(f"Missing tenant quota row for {BENCHMARK_TENANT_ID}")
    return int(value)


def _set_daily_scan_quota(value: int) -> None:
    _psql_scalar(
        "update tenant_quotas "
        f"set max_daily_scans = {int(value)} "
        f"where tenant_id = '{BENCHMARK_TENANT_ID}' "
        "returning max_daily_scans;"
    )


async def _create_scan(
    client: httpx.AsyncClient,
    *,
    asset_id: str,
    scan_type: str,
    config: dict[str, Any],
) -> dict[str, Any]:
    response = await client.post(
        f"{API_BASE_URL}/api/v1/scans",
        json={
            "asset_id": asset_id,
            "scan_type": scan_type,
            "priority": "normal",
            "config": config,
        },
    )
    if response.is_error:
        detail = response.text.strip()[:500]
        raise RuntimeError(
            f"scan create failed for asset {asset_id}: "
            f"status={response.status_code} detail={detail}"
        )
    payload = response.json()
    print(f"[scan] created {scan_type} scan {payload['id']}")
    return payload


async def _create_multi_asset_batch(
    client: httpx.AsyncClient,
    *,
    scan_type: str,
    config: dict[str, Any],
    asset_ids: list[str],
) -> dict[str, Any]:
    response = await client.post(
        f"{API_BASE_URL}/api/v1/scans/batch",
        json={
            "scan_type": scan_type,
            "priority": "normal",
            "config": config,
            "asset_ids": asset_ids,
        },
    )
    if response.is_error:
        detail = response.text.strip()[:500]
        raise RuntimeError(
            f"direct batch create failed: status={response.status_code} detail={detail}"
        )
    payload = response.json()
    if not isinstance(payload, dict):
        raise RuntimeError("Unexpected direct batch response")
    return payload


async def _create_asset_group_batch(
    client: httpx.AsyncClient,
    *,
    scan_type: str,
    config: dict[str, Any],
    asset_group_id: str,
) -> dict[str, Any]:
    response = await client.post(
        f"{API_BASE_URL}/api/v1/asset-groups/{asset_group_id}/scans",
        json={
            "scan_type": scan_type,
            "priority": "normal",
            "config": config,
        },
    )
    if response.is_error:
        detail = response.text.strip()[:500]
        raise RuntimeError(
            f"asset-group batch create failed: status={response.status_code} detail={detail}"
        )
    payload = response.json()
    if not isinstance(payload, dict):
        raise RuntimeError("Unexpected asset-group batch response")
    return payload


async def _get_scan(client: httpx.AsyncClient, scan_id: str) -> dict[str, Any]:
    payload = await _fetch_json(client, f"{API_BASE_URL}/api/v1/scans/{scan_id}")
    if not isinstance(payload, dict):
        raise RuntimeError(f"Unexpected scan payload for {scan_id}")
    return payload


async def _get_scan_jobs(client: httpx.AsyncClient, scan_id: str) -> list[dict[str, Any]]:
    payload = await _fetch_json(client, f"{API_BASE_URL}/api/v1/scans/{scan_id}/jobs")
    return [item for item in payload if isinstance(item, dict)] if isinstance(payload, list) else []


async def _get_findings(client: httpx.AsyncClient, scan_id: str) -> list[dict[str, Any]]:
    payload = await _fetch_json(
        client,
        f"{API_BASE_URL}/api/v1/scans/{scan_id}/findings?page=1&page_size=100",
    )
    if not isinstance(payload, dict):
        return []
    items = payload.get("items")
    return [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []


async def _get_artifacts(client: httpx.AsyncClient, scan_id: str) -> list[dict[str, Any]]:
    payload = await _fetch_json(client, f"{API_BASE_URL}/api/v1/scans/{scan_id}/artifacts/summary")
    return [item for item in payload if isinstance(item, dict)] if isinstance(payload, list) else []


async def _get_attack_graph(client: httpx.AsyncClient, scan_id: str) -> dict[str, Any] | None:
    response = await client.get(f"{API_BASE_URL}/api/v1/scans/{scan_id}/attack-graph")
    if response.status_code == 404:
        return None
    response.raise_for_status()
    payload = response.json()
    return payload if isinstance(payload, dict) else None


async def _get_tool_logs(client: httpx.AsyncClient, scan_id: str) -> list[dict[str, Any]]:
    payload = await _fetch_json(client, f"{API_BASE_URL}/api/v1/scans/{scan_id}/tool-logs")
    if not isinstance(payload, dict):
        return []
    logs = payload.get("logs")
    return [item for item in logs if isinstance(item, dict)] if isinstance(logs, list) else []


async def _fetch_worker_health_snapshot(client: httpx.AsyncClient) -> dict[str, dict[str, Any]]:
    snapshot: dict[str, dict[str, Any]] = {}
    for family, url in _worker_health_url_map().items():
        payload = await _fetch_json(client, url)
        if isinstance(payload, dict):
            snapshot[family] = payload
    return snapshot


async def _wait_for_scan_terminal(
    client: httpx.AsyncClient,
    *,
    scan_id: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        payload = await _get_scan(client, scan_id)
        print(f"[wait] scan={scan_id} status={payload['status']} progress={payload['progress']}%")
        if str(payload.get("status")) in {"completed", "failed", "rejected", "cancelled"}:
            return payload
        await asyncio.sleep(POLL_INTERVAL_SECONDS)
    raise RuntimeError(f"Scan {scan_id} did not reach a terminal state in time")


async def _collect_scan_bundle(
    client: httpx.AsyncClient,
    *,
    scenario: BenchmarkScenario,
    scan_id: str,
) -> dict[str, Any]:
    terminal = await _wait_for_scan_terminal(
        client,
        scan_id=scan_id,
        timeout_seconds=scenario.timeout_seconds,
    )
    jobs = await _get_scan_jobs(client, scan_id)
    findings = await _get_findings(client, scan_id)
    artifacts = await _get_artifacts(client, scan_id)
    attack_graph = await _get_attack_graph(client, scan_id)
    return {
        "scan": terminal,
        "jobs": jobs,
        "findings": findings,
        "artifacts": artifacts,
        "attack_graph": attack_graph,
    }


def _job_timing_metrics(
    jobs: list[dict[str, Any]],
    *,
    scan_created_at: str | None,
) -> dict[str, Any]:
    queue_delays: list[float] = []
    claim_to_start_latencies: list[float] = []
    first_job_start_seconds: float | None = None
    scan_created_dt = _parse_datetime(scan_created_at)
    per_family_claim_to_start: dict[str, list[float]] = {}

    for job in jobs:
        scheduled_at = _parse_datetime(str(job.get("scheduled_at") or ""))
        claimed_at = _parse_datetime(str(job.get("claimed_at") or ""))
        started_at = _parse_datetime(str(job.get("started_at") or ""))

        if scheduled_at is not None and claimed_at is not None:
            queue_delays.append(round((claimed_at - scheduled_at).total_seconds(), 3))

        if claimed_at is not None and started_at is not None:
            claim_to_start = round((started_at - claimed_at).total_seconds(), 3)
            claim_to_start_latencies.append(claim_to_start)
            family = _worker_family_from_job(job)
            per_family_claim_to_start.setdefault(family, []).append(claim_to_start)

        if scan_created_dt is not None and started_at is not None:
            delay = round((started_at - scan_created_dt).total_seconds(), 3)
            if first_job_start_seconds is None or delay < first_job_start_seconds:
                first_job_start_seconds = delay

    per_family = {
        family: {
            "avg_claim_to_start_seconds": round(mean(values), 3),
            "max_claim_to_start_seconds": max(values),
        }
        for family, values in per_family_claim_to_start.items()
        if values
    }

    return {
        "first_queue_delay_seconds": min(queue_delays) if queue_delays else None,
        "avg_queue_delay_seconds": round(mean(queue_delays), 3) if queue_delays else None,
        "max_queue_delay_seconds": max(queue_delays) if queue_delays else None,
        "time_to_first_job_start_seconds": first_job_start_seconds,
        "avg_claim_to_start_seconds": round(mean(claim_to_start_latencies), 3) if claim_to_start_latencies else None,
        "max_claim_to_start_seconds": max(claim_to_start_latencies) if claim_to_start_latencies else None,
        "per_family_claim_to_start_seconds": per_family,
    }


def _first_finding_latency(
    *,
    scan_created_at: str | None,
    findings: list[dict[str, Any]],
) -> float | None:
    created_dt = _parse_datetime(scan_created_at)
    if created_dt is None or not findings:
        return None
    finding_times = [
        _parse_datetime(str(item.get("created_at") or ""))
        for item in findings
    ]
    valid_times = [item for item in finding_times if item is not None]
    if not valid_times:
        return None
    return round((min(valid_times) - created_dt).total_seconds(), 3)


def _first_artifact_latency(
    *,
    scan_created_at: str | None,
    artifacts: list[dict[str, Any]],
) -> float | None:
    created_dt = _parse_datetime(scan_created_at)
    if created_dt is None or not artifacts:
        return None
    artifact_times = [
        _parse_datetime(str(item.get("created_at") or ""))
        for item in artifacts
    ]
    valid_times = [item for item in artifact_times if item is not None]
    if not valid_times:
        return None
    return round((min(valid_times) - created_dt).total_seconds(), 3)


def _worker_delta_metrics(
    *,
    before: dict[str, dict[str, Any]],
    after: dict[str, dict[str, Any]],
    duration_seconds: float | None,
) -> dict[str, Any]:
    per_family: dict[str, dict[str, float | int | None]] = {}
    aggregate_processed = 0
    aggregate_failed = 0

    for family in WORKER_HEALTH_PORTS:
        before_state = before.get(family, {})
        after_state = after.get(family, {})
        processed_delta = int(after_state.get("jobs_processed") or 0) - int(before_state.get("jobs_processed") or 0)
        failed_delta = int(after_state.get("jobs_failed") or 0) - int(before_state.get("jobs_failed") or 0)
        aggregate_processed += processed_delta
        aggregate_failed += failed_delta
        throughput = None
        if duration_seconds and duration_seconds > 0:
            throughput = round(processed_delta / duration_seconds, 3)
        per_family[family] = {
            "jobs_processed_delta": processed_delta,
            "jobs_failed_delta": failed_delta,
            "jobs_per_second": throughput,
        }

    aggregate_throughput = None
    if duration_seconds and duration_seconds > 0:
        aggregate_throughput = round(aggregate_processed / duration_seconds, 3)

    return {
        "per_family": per_family,
        "aggregate_jobs_processed_delta": aggregate_processed,
        "aggregate_jobs_failed_delta": aggregate_failed,
        "aggregate_jobs_per_second": aggregate_throughput,
    }


def _summarize_run(
    *,
    scenario: BenchmarkScenario,
    scan: dict[str, Any],
    jobs: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    artifacts: list[dict[str, Any]],
    attack_graph: dict[str, Any] | None,
    worker_before: dict[str, dict[str, Any]],
    worker_after: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    total_runtime_seconds = _seconds_between(scan.get("created_at"), scan.get("completed_at"))
    execution_runtime_seconds = _seconds_between(scan.get("started_at"), scan.get("completed_at"))
    job_metrics = _job_timing_metrics(
        jobs,
        scan_created_at=scan.get("created_at"),
    )
    verified_findings = [
        finding
        for finding in findings
        if str(finding.get("verification_state") or "") == "verified"
    ]
    artifact_bytes_total = sum(int(item.get("size_bytes") or 0) for item in artifacts)
    evidence_count_total = sum(int(item.get("evidence_count") or 0) for item in artifacts)
    worker_delta = _worker_delta_metrics(
        before=worker_before,
        after=worker_after,
        duration_seconds=execution_runtime_seconds or total_runtime_seconds,
    )
    verification_summary = _build_verification_summary(
        findings=findings,
        profile_id=_profile_id_for_scenario(scenario),
        scan_type=scenario.scan_type,
    )

    return {
        "scenario_key": scenario.key,
        "label": scenario.label,
        "scan_id": scan["id"],
        "scan_type": scenario.scan_type,
        "status": scan["status"],
        "progress": scan["progress"],
        "created_at": scan.get("created_at"),
        "started_at": scan.get("started_at"),
        "completed_at": scan.get("completed_at"),
        "total_runtime_seconds": total_runtime_seconds,
        "execution_runtime_seconds": execution_runtime_seconds,
        "time_to_first_finding_seconds": _first_finding_latency(
            scan_created_at=scan.get("created_at"),
            findings=findings,
        ),
        "time_to_first_artifact_seconds": _first_artifact_latency(
            scan_created_at=scan.get("created_at"),
            artifacts=artifacts,
        ),
        "job_metrics": job_metrics,
        "job_counts": {
            "total": len(jobs),
            "completed": sum(1 for item in jobs if str(item.get("status")) == "completed"),
            "failed": sum(1 for item in jobs if str(item.get("status")) == "failed"),
            "blocked": sum(1 for item in jobs if str(item.get("status")) == "blocked"),
        },
        "output_volume": {
            "findings": len(findings),
            "verified_findings": len(verified_findings),
            "artifacts": len(artifacts),
            "evidence": evidence_count_total,
            "artifact_bytes_total": artifact_bytes_total,
            "attack_graph_nodes": int((attack_graph or {}).get("node_count") or len((attack_graph or {}).get("nodes", []))),
            "attack_graph_edges": int((attack_graph or {}).get("edge_count") or len((attack_graph or {}).get("edges", []))),
        },
        "worker_delta": worker_delta,
        "verification_summary": verification_summary,
    }


def _aggregate_runs(
    scenario: BenchmarkScenario,
    runs: list[dict[str, Any]],
) -> dict[str, Any]:
    benchmark_context = dict(runs[0].get("benchmark_context") or {}) if runs else {}
    verification_summary = _merge_verification_summaries(
        [
            run.get("verification_summary") or {}
            for run in runs
        ],
        profile_id=_profile_id_for_scenario(scenario),
        scan_type=scenario.scan_type,
    )
    return {
        "scenario_key": scenario.key,
        "label": scenario.label,
        "mode": scenario.mode,
        "benchmark_context": benchmark_context,
        "iterations": len(runs),
        "avg_scan_count": _avg(
            [
                float((run.get("benchmark_context") or {}).get("scan_count", 1))
                for run in runs
            ]
        ),
        "avg_total_runtime_seconds": _avg([run.get("total_runtime_seconds") for run in runs]),
        "avg_execution_runtime_seconds": _avg([run.get("execution_runtime_seconds") for run in runs]),
        "avg_time_to_first_artifact_seconds": _avg([run.get("time_to_first_artifact_seconds") for run in runs]),
        "avg_time_to_first_finding_seconds": _avg([run.get("time_to_first_finding_seconds") for run in runs]),
        "avg_first_queue_delay_seconds": _avg(
            [run.get("job_metrics", {}).get("first_queue_delay_seconds") for run in runs]
        ),
        "avg_queue_delay_seconds": _avg(
            [run.get("job_metrics", {}).get("avg_queue_delay_seconds") for run in runs]
        ),
        "avg_max_queue_delay_seconds": _avg(
            [run.get("job_metrics", {}).get("max_queue_delay_seconds") for run in runs]
        ),
        "avg_time_to_first_job_start_seconds": _avg(
            [run.get("job_metrics", {}).get("time_to_first_job_start_seconds") for run in runs]
        ),
        "avg_claim_to_start_seconds": _avg(
            [run.get("job_metrics", {}).get("avg_claim_to_start_seconds") for run in runs]
        ),
        "avg_max_claim_to_start_seconds": _avg(
            [run.get("job_metrics", {}).get("max_claim_to_start_seconds") for run in runs]
        ),
        "avg_artifact_count": _avg([run.get("output_volume", {}).get("artifacts") for run in runs]),
        "avg_artifact_bytes_total": _avg(
            [run.get("output_volume", {}).get("artifact_bytes_total") for run in runs]
        ),
        "avg_finding_count": _avg([run.get("output_volume", {}).get("findings") for run in runs]),
        "avg_verified_finding_count": _avg(
            [run.get("output_volume", {}).get("verified_findings") for run in runs]
        ),
        "avg_verified_share": _avg(
            [
                (run.get("verification_summary") or {}).get("overall", {}).get("verified_share")
                for run in runs
            ]
        ),
        "avg_evidence_count": _avg([run.get("output_volume", {}).get("evidence") for run in runs]),
        "avg_worker_jobs_per_second": _avg(
            [run.get("worker_delta", {}).get("aggregate_jobs_per_second") for run in runs]
        ),
        "verification_summary": verification_summary,
        "runs": runs,
    }


def _select_asset_id(context: BenchmarkContext, *, role: str) -> str:
    if role == "primary":
        return context.primary_asset_id
    if role == "web_local":
        return context.web_asset_id
    raise ValueError(f"Unsupported benchmark asset role: {role}")


def _select_asset_ids(context: BenchmarkContext, *, count: int) -> list[str]:
    if count <= 0:
        return []
    pool = list(context.local_asset_ids)
    if not pool:
        raise RuntimeError("No benchmark-local assets available")
    selected: list[str] = []
    index = 0
    while len(selected) < count:
        selected.append(pool[index % len(pool)])
        index += 1
    return selected


def _latest_timestamp(values: list[str | None]) -> str | None:
    parsed = [_parse_datetime(value) for value in values if value]
    valid = [item for item in parsed if item is not None]
    if not valid:
        return None
    return max(valid).isoformat()


def _summarize_group_run(
    *,
    scenario: BenchmarkScenario,
    group_created_at: str,
    wall_clock_seconds: float,
    bundles: list[dict[str, Any]],
    worker_before: dict[str, dict[str, Any]],
    worker_after: dict[str, dict[str, Any]],
    benchmark_context: dict[str, Any],
) -> dict[str, Any]:
    scans = [bundle["scan"] for bundle in bundles]
    jobs = [job for bundle in bundles for job in bundle["jobs"]]
    findings = [item for bundle in bundles for item in bundle["findings"]]
    artifacts = [item for bundle in bundles for item in bundle["artifacts"]]
    attack_graphs = [bundle.get("attack_graph") or {} for bundle in bundles]

    verified_findings = [
        finding
        for finding in findings
        if str(finding.get("verification_state") or "") == "verified"
    ]
    artifact_bytes_total = sum(int(item.get("size_bytes") or 0) for item in artifacts)
    evidence_count_total = sum(int(item.get("evidence_count") or 0) for item in artifacts)
    attack_graph_nodes = sum(
        int(graph.get("node_count") or len(graph.get("nodes", [])))
        for graph in attack_graphs
    )
    attack_graph_edges = sum(
        int(graph.get("edge_count") or len(graph.get("edges", [])))
        for graph in attack_graphs
    )
    verification_summary = _build_verification_summary(
        findings=findings,
        profile_id=_profile_id_for_scenario(scenario),
        scan_type=scenario.scan_type,
    )

    terminal_statuses = {str(scan.get("status")) for scan in scans}
    status = "completed" if terminal_statuses == {"completed"} else "mixed"
    progress_values = [
        int(scan.get("progress") or 0)
        for scan in scans
    ]
    job_metrics = _job_timing_metrics(jobs, scan_created_at=group_created_at)
    execution_runtimes = [
        _seconds_between(scan.get("started_at"), scan.get("completed_at"))
        for scan in scans
    ]

    return {
        "scenario_key": scenario.key,
        "label": scenario.label,
        "scan_id": None,
        "scan_type": scenario.scan_type,
        "status": status,
        "progress": min(progress_values) if progress_values else 0,
        "created_at": group_created_at,
        "started_at": group_created_at,
        "completed_at": _latest_timestamp([scan.get("completed_at") for scan in scans]),
        "total_runtime_seconds": round(wall_clock_seconds, 3),
        "execution_runtime_seconds": _avg(execution_runtimes) or round(wall_clock_seconds, 3),
        "time_to_first_finding_seconds": _first_finding_latency(
            scan_created_at=group_created_at,
            findings=findings,
        ),
        "time_to_first_artifact_seconds": _first_artifact_latency(
            scan_created_at=group_created_at,
            artifacts=artifacts,
        ),
        "job_metrics": job_metrics,
        "job_counts": {
            "total": len(jobs),
            "completed": sum(1 for item in jobs if str(item.get("status")) == "completed"),
            "failed": sum(1 for item in jobs if str(item.get("status")) == "failed"),
            "blocked": sum(1 for item in jobs if str(item.get("status")) == "blocked"),
        },
        "output_volume": {
            "findings": len(findings),
            "verified_findings": len(verified_findings),
            "artifacts": len(artifacts),
            "evidence": evidence_count_total,
            "artifact_bytes_total": artifact_bytes_total,
            "attack_graph_nodes": attack_graph_nodes,
            "attack_graph_edges": attack_graph_edges,
        },
        "worker_delta": _worker_delta_metrics(
            before=worker_before,
            after=worker_after,
            duration_seconds=wall_clock_seconds,
        ),
        "verification_summary": verification_summary,
        "benchmark_context": {
            **benchmark_context,
            "scan_count": len(scans),
        },
        "child_scans": [
            {
                "scan_id": str(scan.get("id")),
                "status": str(scan.get("status")),
                "asset_id": str(scan.get("asset_id") or ""),
                "created_at": scan.get("created_at"),
                "completed_at": scan.get("completed_at"),
                "total_runtime_seconds": _seconds_between(
                    scan.get("created_at"),
                    scan.get("completed_at"),
                ),
            }
            for scan in scans
        ],
    }


async def _run_single_benchmark(
    client: httpx.AsyncClient,
    *,
    scenario: BenchmarkScenario,
    context: BenchmarkContext,
) -> dict[str, Any]:
    await _cleanup_active_scans(client)
    worker_before = await _fetch_worker_health_snapshot(client)
    scan = await _create_scan(
        client,
        asset_id=_select_asset_id(context, role=scenario.asset_role),
        scan_type=scenario.scan_type,
        config=scenario.config,
    )
    scan_id = str(scan["id"])
    bundle = await _collect_scan_bundle(client, scenario=scenario, scan_id=scan_id)
    terminal = bundle["scan"]
    if str(terminal.get("status")) != "completed":
        raise RuntimeError(f"Benchmark scenario {scenario.key} ended in {terminal.get('status')}")

    worker_after = await _fetch_worker_health_snapshot(client)

    summary = _summarize_run(
        scenario=scenario,
        scan=terminal,
        jobs=bundle["jobs"],
        findings=bundle["findings"],
        artifacts=bundle["artifacts"],
        attack_graph=bundle["attack_graph"],
        worker_before=worker_before,
        worker_after=worker_after,
    )
    summary["benchmark_context"] = {
        "mode": scenario.mode,
        "scan_count": 1,
        "asset_id": _select_asset_id(context, role=scenario.asset_role),
    }
    return summary


async def _run_direct_batch_benchmark(
    client: httpx.AsyncClient,
    *,
    scenario: BenchmarkScenario,
    context: BenchmarkContext,
) -> dict[str, Any]:
    await _cleanup_active_scans(client)
    worker_before = await _fetch_worker_health_snapshot(client)
    asset_ids = _select_asset_ids(context, count=scenario.batch_size)
    started_monotonic = time.monotonic()
    created_at = _utc_now()
    batch = await _create_multi_asset_batch(
        client,
        scan_type=scenario.scan_type,
        config=scenario.config,
        asset_ids=asset_ids,
    )
    scans = [item for item in batch.get("scans", []) if isinstance(item, dict)]
    if len(scans) != len(asset_ids):
        raise RuntimeError(
            f"Direct batch created {len(scans)} scans for {len(asset_ids)} requested assets"
        )
    bundles = await asyncio.gather(
        *[
            _collect_scan_bundle(client, scenario=scenario, scan_id=str(scan["id"]))
            for scan in scans
        ]
    )
    if any(str(bundle["scan"].get("status")) != "completed" for bundle in bundles):
        raise RuntimeError(f"Direct batch benchmark {scenario.key} did not complete cleanly")
    worker_after = await _fetch_worker_health_snapshot(client)
    return _summarize_group_run(
        scenario=scenario,
        group_created_at=created_at,
        wall_clock_seconds=time.monotonic() - started_monotonic,
        bundles=bundles,
        worker_before=worker_before,
        worker_after=worker_after,
        benchmark_context={
            "mode": scenario.mode,
            "asset_ids": asset_ids,
            "batch_request_id": str(batch.get("batch_request_id") or ""),
            "asset_group_id": str(batch.get("asset_group_id") or ""),
        },
    )


async def _run_asset_group_batch_benchmark(
    client: httpx.AsyncClient,
    *,
    scenario: BenchmarkScenario,
    context: BenchmarkContext,
) -> dict[str, Any]:
    await _cleanup_active_scans(client)
    worker_before = await _fetch_worker_health_snapshot(client)
    asset_ids = _select_asset_ids(context, count=scenario.batch_size)
    group = await _ensure_named_asset_group(
        client,
        project_id=context.project_id,
        name=f"{BENCHMARK_ASSET_GROUP_NAME} x{scenario.batch_size}",
        asset_ids=asset_ids,
    )
    started_monotonic = time.monotonic()
    created_at = _utc_now()
    batch = await _create_asset_group_batch(
        client,
        scan_type=scenario.scan_type,
        config=scenario.config,
        asset_group_id=str(group["id"]),
    )
    scans = [item for item in batch.get("scans", []) if isinstance(item, dict)]
    bundles = await asyncio.gather(
        *[
            _collect_scan_bundle(client, scenario=scenario, scan_id=str(scan["id"]))
            for scan in scans
        ]
    )
    if any(str(bundle["scan"].get("status")) != "completed" for bundle in bundles):
        raise RuntimeError(f"Asset-group batch benchmark {scenario.key} did not complete cleanly")
    worker_after = await _fetch_worker_health_snapshot(client)
    return _summarize_group_run(
        scenario=scenario,
        group_created_at=created_at,
        wall_clock_seconds=time.monotonic() - started_monotonic,
        bundles=bundles,
        worker_before=worker_before,
        worker_after=worker_after,
        benchmark_context={
            "mode": scenario.mode,
            "asset_ids": asset_ids,
            "batch_request_id": str(batch.get("batch_request_id") or ""),
            "asset_group_id": str(group["id"]),
        },
    )


async def _run_concurrent_benchmark(
    client: httpx.AsyncClient,
    *,
    scenario: BenchmarkScenario,
    context: BenchmarkContext,
) -> dict[str, Any]:
    await _cleanup_active_scans(client)
    worker_before = await _fetch_worker_health_snapshot(client)
    asset_ids = _select_asset_ids(context, count=scenario.concurrency)
    started_monotonic = time.monotonic()
    created_at = _utc_now()
    batch = await _create_multi_asset_batch(
        client,
        scan_type=scenario.scan_type,
        config=scenario.config,
        asset_ids=asset_ids,
    )
    scans = [item for item in batch.get("scans", []) if isinstance(item, dict)]
    if len(scans) != scenario.concurrency:
        raise RuntimeError(
            f"Concurrent benchmark {scenario.key} created {len(scans)} scans for requested concurrency {scenario.concurrency}"
        )
    bundles = await asyncio.gather(
        *[
            _collect_scan_bundle(client, scenario=scenario, scan_id=str(scan["id"]))
            for scan in scans
        ]
    )
    if any(str(bundle["scan"].get("status")) != "completed" for bundle in bundles):
        raise RuntimeError(f"Concurrent benchmark {scenario.key} did not complete cleanly")
    worker_after = await _fetch_worker_health_snapshot(client)
    return _summarize_group_run(
        scenario=scenario,
        group_created_at=created_at,
        wall_clock_seconds=time.monotonic() - started_monotonic,
        bundles=bundles,
        worker_before=worker_before,
        worker_after=worker_after,
        benchmark_context={
            "mode": scenario.mode,
            "asset_ids": asset_ids,
            "concurrency": scenario.concurrency,
            "batch_request_id": str(batch.get("batch_request_id") or ""),
        },
    )


async def _restart_worker_with_prewarm(
    *,
    family: str,
    prewarm_enabled: bool,
) -> dict[str, Any]:
    health_url = _worker_health_url(family)
    name = f"worker-{family}"
    new_pid = await _start_service(
        name=name,
        command=[str(ROOT_DIR / "pentra_core/scripts/local/run_worker.sh"), family],
        env={
            **os.environ,
            "WORKER_LIVE_TOOLS": WORKER_LIVE_TOOLS,
            "WORKER_EXECUTION_MODE": os.getenv("WORKER_EXECUTION_MODE", "controlled_live_local"),
            "WORKER_LIVE_TARGET_POLICY": os.getenv("WORKER_LIVE_TARGET_POLICY", "local_only"),
            "WORKER_HEALTH_HOST": "127.0.0.1",
            "WORKER_HEALTH_PORT": str(WORKER_HEALTH_PORTS[family]),
            "WORKER_PREWARM_IMAGES": "true" if prewarm_enabled else "false",
        },
        health_url=health_url,
    )
    async with httpx.AsyncClient(timeout=5.0) as client:
        payload = await _wait_for_json(
            client,
            url=health_url,
            expect_up=True,
            timeout_seconds=15,
            label=name,
        )
    if not isinstance(payload, dict):
        raise RuntimeError(f"Unexpected worker health payload for {family}")
    return {"pid": new_pid, "health": payload}


async def _run_cold_start_probe(client: httpx.AsyncClient) -> dict[str, Any]:
    scenario = BenchmarkScenario(
        key="recon_cold_start_probe",
        label="Recon cold-start probe",
        mode="single",
        scan_type="recon",
        config={"profile_id": "external_web_api_v1"},
        iterations=1,
        timeout_seconds=120,
    )
    context = await _ensure_benchmark_context(client)
    family = TRUE_COLD_START_FAMILY
    health_url = _worker_health_url(family)

    await _cleanup_active_scans(client)
    killed_pid = await _terminate_service(name=f"worker-{family}", health_url=health_url)
    no_prewarm_clear = _clear_docker_images(TRUE_COLD_START_IMAGES) if _true_cold_start_requested() else {}
    no_prewarm = await _restart_worker_with_prewarm(family=family, prewarm_enabled=False)
    no_prewarm_run = await _run_single_benchmark(client, scenario=scenario, context=context)

    killed_pid_2 = await _terminate_service(name=f"worker-{family}", health_url=health_url)
    with_prewarm_clear = _clear_docker_images(TRUE_COLD_START_IMAGES) if _true_cold_start_requested() else {}
    with_prewarm = await _restart_worker_with_prewarm(family=family, prewarm_enabled=True)
    with_prewarm_run = await _run_single_benchmark(client, scenario=scenario, context=context)

    no_prewarm_health = no_prewarm["health"]
    with_prewarm_health = with_prewarm["health"]

    return {
        "worker_family": family,
        "probe_mode": "true_cold" if _true_cold_start_requested() else "warm_restart",
        "probe_images": list(TRUE_COLD_START_IMAGES),
        "initial_killed_pid": killed_pid,
        "second_killed_pid": killed_pid_2,
        "no_prewarm": {
            "worker_pid": no_prewarm["pid"],
            "image_reset": no_prewarm_clear,
            "worker_health": no_prewarm_health,
            "run": no_prewarm_run,
        },
        "with_prewarm": {
            "worker_pid": with_prewarm["pid"],
            "image_reset": with_prewarm_clear,
            "worker_health": with_prewarm_health,
            "run": with_prewarm_run,
        },
        "comparison": {
            "total_runtime_delta_seconds": round(
                float(no_prewarm_run.get("total_runtime_seconds") or 0)
                - float(with_prewarm_run.get("total_runtime_seconds") or 0),
                3,
            ),
            "first_artifact_delta_seconds": round(
                float(no_prewarm_run.get("time_to_first_artifact_seconds") or 0)
                - float(with_prewarm_run.get("time_to_first_artifact_seconds") or 0),
                3,
            ),
            "no_prewarm_status": str(no_prewarm_health.get("prewarm", {}).get("status") or "unknown"),
            "with_prewarm_status": str(with_prewarm_health.get("prewarm", {}).get("status") or "unknown"),
        },
    }


def _write_artifact(
    *,
    status: str,
    scenarios: list[dict[str, Any]],
    cold_start: dict[str, Any] | None,
    context: BenchmarkContext | None,
) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": _utc_now(),
        "status": status,
        "phase": "P7.4",
        "environment": {
            "api_base_url": API_BASE_URL,
            "orchestrator_base_url": ORCH_BASE_URL,
            "demo_target_url": DEMO_TARGET_URL,
            "tenant_id": BENCHMARK_TENANT_ID,
            "project_id": context.project_id if context else BENCHMARK_PROJECT_ID,
            "primary_asset_id": context.primary_asset_id if context else ASSET_ID,
            "local_asset_ids": list(context.local_asset_ids) if context else [ASSET_ID],
            "asset_group_id": context.asset_group_id if context else None,
            "true_cold_start_probe": _true_cold_start_requested(),
            "benchmark_daily_scan_quota": BENCHMARK_DAILY_SCAN_QUOTA,
        },
        "scenario_benchmarks": scenarios,
        "cold_start_probe": cold_start,
    }
    stamped = stamp_proof_payload(
        payload,
        artifact_kind="benchmark_matrix",
        phase="P7.4",
        script_path="pentra_core/scripts/local/run_phase6_benchmark_matrix.py",
        root_dir=ROOT_DIR,
        environment_context={
            "api_base_url": API_BASE_URL,
            "orchestrator_base_url": ORCH_BASE_URL,
            "demo_target_url": DEMO_TARGET_URL,
            "tenant_id": BENCHMARK_TENANT_ID,
            "project_id": context.project_id if context else BENCHMARK_PROJECT_ID,
            "primary_asset_id": context.primary_asset_id if context else ASSET_ID,
            "true_cold_start_probe": _true_cold_start_requested(),
            "true_cold_start_images": list(TRUE_COLD_START_IMAGES),
            "benchmark_daily_scan_quota": BENCHMARK_DAILY_SCAN_QUOTA,
        },
        run_id=PROOF_RUN_ID,
    )
    OUTPUT_PATH.write_text(json.dumps(stamped, indent=2, sort_keys=True))


async def _ensure_stack_health(client: httpx.AsyncClient) -> None:
    await _assert_http_ok(client, f"{API_BASE_URL}/health", "api health")
    await _assert_http_ok(client, f"{ORCH_BASE_URL}/health", "orchestrator health")
    await _assert_http_ok(client, f"{DEMO_TARGET_URL}/healthz", "demo target health")
    for family, url in _worker_health_url_map().items():
        await _assert_http_ok(client, url, f"worker {family} health")


async def main() -> None:
    scenario_results: list[dict[str, Any]] = []
    cold_start_probe: dict[str, Any] | None = None
    original_daily_quota: int | None = None

    async with httpx.AsyncClient(timeout=10.0) as client:
        await _ensure_stack_health(client)
        context = await _ensure_benchmark_context(client)
        redis = aioredis.from_url(REDIS_URL, decode_responses=True)
        try:
            await redis.ping()
            await redis.aclose()
            original_daily_quota = _get_daily_scan_quota()
            if original_daily_quota < BENCHMARK_DAILY_SCAN_QUOTA:
                _set_daily_scan_quota(BENCHMARK_DAILY_SCAN_QUOTA)

            for scenario in SCENARIOS:
                print(f"[benchmark] {scenario.label}")
                runs: list[dict[str, Any]] = []
                for iteration in range(1, scenario.iterations + 1):
                    print(f"[benchmark] iteration {iteration}/{scenario.iterations}")
                    if scenario.mode == "single":
                        runner = _run_single_benchmark(client, scenario=scenario, context=context)
                    elif scenario.mode == "batch_direct":
                        runner = _run_direct_batch_benchmark(client, scenario=scenario, context=context)
                    elif scenario.mode == "batch_group":
                        runner = _run_asset_group_batch_benchmark(client, scenario=scenario, context=context)
                    elif scenario.mode == "concurrent":
                        runner = _run_concurrent_benchmark(client, scenario=scenario, context=context)
                    else:
                        raise RuntimeError(f"Unsupported benchmark mode {scenario.mode}")

                    run = await asyncio.wait_for(runner, timeout=scenario.timeout_seconds)
                    run["iteration"] = iteration
                    runs.append(run)
                    _write_artifact(
                        status="in_progress",
                        scenarios=scenario_results + [_aggregate_runs(scenario, runs)],
                        cold_start=cold_start_probe,
                        context=context,
                    )
                scenario_results.append(_aggregate_runs(scenario, runs))

            print("[benchmark] web worker cold-start probe")
            cold_start_probe = await asyncio.wait_for(_run_cold_start_probe(client), timeout=240)
            _write_artifact(
                status="passed",
                scenarios=scenario_results,
                cold_start=cold_start_probe,
                context=context,
            )
            print(f"[ok] Wrote Phase 7 benchmark proof to {OUTPUT_PATH}")
        finally:
            if original_daily_quota is not None and original_daily_quota < BENCHMARK_DAILY_SCAN_QUOTA:
                _set_daily_scan_quota(original_daily_quota)
            await _cleanup_active_scans(client)


if __name__ == "__main__":
    asyncio.run(main())
