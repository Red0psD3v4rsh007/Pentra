"""Phase 6 live chaos matrix runner.

Exercises the local Pentra stack under controlled failure conditions and writes
the resulting proof artifact into the repo workspace.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid
from typing import Any, Awaitable, Callable

import httpx
import redis.asyncio as aioredis

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from pentra_core.scripts.local.proof_contract import new_run_id, stamp_proof_payload
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(line_buffering=True)
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(line_buffering=True)

API_BASE_URL = os.getenv("PENTRA_API_BASE_URL", "http://127.0.0.1:8000")
ORCH_BASE_URL = os.getenv("PENTRA_ORCHESTRATOR_BASE_URL", "http://127.0.0.1:8001")
DEMO_TARGET_URL = os.getenv("PENTRA_PHASE6_DEMO_URL", "http://127.0.0.1:8088")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
ASSET_ID = os.getenv("PENTRA_PHASE6_ASSET_ID", "55555555-5555-5555-5555-555555555555")
ROOT_DIR = Path(__file__).resolve().parents[3]
OUTPUT_DIR = ROOT_DIR / ".local" / "pentra" / "phase6"
OUTPUT_PATH = OUTPUT_DIR / "chaos_matrix_latest.json"
LOG_DIR = ROOT_DIR / ".local" / "pentra"
PID_DIR = LOG_DIR / "pids"
WORKER_LIVE_TOOLS = os.getenv(
    "WORKER_LIVE_TOOLS",
    "scope_check,httpx_probe,ffuf,nuclei,sqlmap,sqlmap_verify,custom_poc,web_interact",
)
POLL_INTERVAL_SECONDS = float(os.getenv("PENTRA_PHASE6_POLL_INTERVAL_SECONDS", "1"))
ORCHESTRATOR_RECLAIM_IDLE_MS = int(os.getenv("ORCHESTRATOR_RECLAIM_IDLE_MS", "5000"))
WORKER_BLOCK_MS = int(os.getenv("WORKER_BLOCK_MS", "1000"))
WORKER_RECLAIM_IDLE_MS = int(os.getenv("WORKER_RECLAIM_IDLE_MS", "5000"))
WORKER_RECLAIM_HEARTBEAT_MS = int(os.getenv("WORKER_RECLAIM_HEARTBEAT_MS", "1500"))
PROOF_RUN_ID = new_run_id()

SCAN_STREAM = "pentra:stream:scan_events"
JOB_STREAM = "pentra:stream:job_events"
ORCHESTRATOR_GROUP = "orchestrator-cg"
ACTIVE_SCAN_STATUSES = {"queued", "validating", "running", "paused"}
TERMINAL_SCAN_STATUSES = {"completed", "failed", "rejected", "cancelled"}
RUNNING_JOB_STATUSES = {"running", "assigned", "scheduled"}
WORKER_HEALTH_PORTS = {
    "recon": 9101,
    "network": 9102,
    "web": 9103,
    "vuln": 9104,
    "exploit": 9105,
}

STATEFUL_FULL_CONFIG: dict[str, Any] = {
    "profile_id": "external_web_api_v1",
    "stateful_testing": {
        "enabled": True,
        "crawl_max_depth": 2,
        "max_pages": 20,
        "max_replays": 4,
        "seed_paths": ["/", "/login", "/portal/dashboard", "/portal/checkout/cart"],
        "default_csrf_token": "demo-csrf",
        "auth": {
            "login_page_path": "/login",
            "username_field": "username",
            "password_field": "password",
            "success_path_contains": "/portal/dashboard",
            "credentials": [
                {"label": "john", "username": "john", "password": "test", "role": "user"},
                {"label": "admin", "username": "admin", "password": "admin123", "role": "admin"},
            ],
        },
    },
}


@dataclass(frozen=True)
class ScenarioDefinition:
    key: str
    label: str
    timeout_seconds: int
    runner: Callable[[httpx.AsyncClient, aioredis.Redis], Awaitable[dict[str, Any]]]


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def _iso_duration_seconds(started_at: str | None, completed_at: str | None) -> float | None:
    start_dt = _parse_datetime(started_at)
    end_dt = _parse_datetime(completed_at)
    if start_dt is None or end_dt is None:
        return None
    return round((end_dt - start_dt).total_seconds(), 2)


def _seconds_after_threshold(timestamp: str | None, *, threshold: datetime) -> float | None:
    value = _parse_datetime(timestamp)
    if value is None or value <= threshold:
        return None
    return round((value - threshold).total_seconds(), 2)


def _worker_health_url(family: str) -> str:
    port = WORKER_HEALTH_PORTS[family]
    return f"http://127.0.0.1:{port}/health"


def _orchestrator_health_url() -> str:
    return f"{ORCH_BASE_URL}/health"


def _pid_file(name: str) -> Path:
    return PID_DIR / f"{name}.pid"


def _read_pid(name: str) -> int:
    pid_path = _pid_file(name)
    if not pid_path.exists():
        raise RuntimeError(f"Missing pid file for {name}: {pid_path}")
    value = pid_path.read_text().strip()
    if not value:
        raise RuntimeError(f"Empty pid file for {name}: {pid_path}")
    return int(value)


async def _assert_http_ok(client: httpx.AsyncClient, url: str, label: str) -> None:
    response = await client.get(url)
    response.raise_for_status()
    print(f"[ok] {label}: {response.status_code}")


async def _fetch_json(client: httpx.AsyncClient, url: str) -> Any:
    response = await client.get(url)
    response.raise_for_status()
    return response.json()


async def _wait_for_json(
    client: httpx.AsyncClient,
    *,
    url: str,
    expect_up: bool,
    timeout_seconds: int,
    label: str,
) -> dict[str, Any] | None:
    deadline = time.monotonic() + timeout_seconds
    last_error: str | None = None
    while time.monotonic() < deadline:
        try:
            response = await client.get(url)
            response.raise_for_status()
            payload = response.json()
            if expect_up:
                return payload if isinstance(payload, dict) else {"value": payload}
            last_error = f"{label} still up"
        except Exception as exc:
            if not expect_up:
                return None
            last_error = str(exc)
        await asyncio.sleep(1)
    if expect_up:
        raise RuntimeError(f"{label} did not become healthy in time: {last_error}")
    raise RuntimeError(f"{label} did not go down in time: {last_error}")


async def _create_scan(
    client: httpx.AsyncClient,
    *,
    scan_type: str,
    config: dict[str, Any],
) -> dict[str, Any]:
    response = await client.post(
        f"{API_BASE_URL}/api/v1/scans",
        json={
            "asset_id": ASSET_ID,
            "scan_type": scan_type,
            "priority": "normal",
            "config": config,
        },
    )
    response.raise_for_status()
    payload = response.json()
    print(f"[scan] created {scan_type} scan {payload['id']}")
    return payload


async def _pause_scan(client: httpx.AsyncClient, scan_id: str) -> dict[str, Any]:
    response = await client.post(f"{API_BASE_URL}/api/v1/scans/{scan_id}/pause")
    response.raise_for_status()
    payload = response.json()
    print(f"[scan] paused {scan_id}")
    return payload


async def _resume_scan(client: httpx.AsyncClient, scan_id: str) -> dict[str, Any]:
    response = await client.post(f"{API_BASE_URL}/api/v1/scans/{scan_id}/resume")
    response.raise_for_status()
    payload = response.json()
    print(f"[scan] resumed {scan_id}")
    return payload


async def _cancel_scan(client: httpx.AsyncClient, scan_id: str) -> dict[str, Any]:
    response = await client.post(f"{API_BASE_URL}/api/v1/scans/{scan_id}/cancel")
    response.raise_for_status()
    payload = response.json()
    print(f"[scan] cancelled {scan_id}")
    return payload


async def _get_scan(client: httpx.AsyncClient, scan_id: str) -> dict[str, Any]:
    payload = await _fetch_json(client, f"{API_BASE_URL}/api/v1/scans/{scan_id}")
    if not isinstance(payload, dict):
        raise RuntimeError(f"Unexpected scan payload for {scan_id}")
    return payload


async def _get_scan_jobs(client: httpx.AsyncClient, scan_id: str) -> list[dict[str, Any]]:
    payload = await _fetch_json(client, f"{API_BASE_URL}/api/v1/scans/{scan_id}/jobs")
    return [item for item in payload if isinstance(item, dict)] if isinstance(payload, list) else []


async def _get_tool_logs(client: httpx.AsyncClient, scan_id: str) -> list[dict[str, Any]]:
    payload = await _fetch_json(client, f"{API_BASE_URL}/api/v1/scans/{scan_id}/tool-logs")
    if not isinstance(payload, dict):
        return []
    logs = payload.get("logs")
    return [item for item in logs if isinstance(item, dict)] if isinstance(logs, list) else []


async def _list_scans(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    payload = await _fetch_json(client, f"{API_BASE_URL}/api/v1/scans?page=1&page_size=100")
    if not isinstance(payload, dict):
        return []
    items = payload.get("items")
    return [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []


async def _wait_for_scan_status(
    client: httpx.AsyncClient,
    *,
    scan_id: str,
    expected_status: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        payload = await _get_scan(client, scan_id)
        print(f"[wait] scan={scan_id} status={payload['status']} progress={payload['progress']}%")
        if str(payload.get("status")) == expected_status:
            return payload
        await asyncio.sleep(POLL_INTERVAL_SECONDS)
    raise RuntimeError(f"Scan {scan_id} did not reach status {expected_status}")


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
        if str(payload.get("status")) in TERMINAL_SCAN_STATUSES:
            return payload
        await asyncio.sleep(POLL_INTERVAL_SECONDS)
    raise RuntimeError(f"Scan {scan_id} did not reach a terminal state in time")


async def _wait_for_running_work(
    client: httpx.AsyncClient,
    *,
    scan_id: str,
    families: set[str] | None,
    timeout_seconds: int,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        logs = await _get_tool_logs(client, scan_id)
        for entry in logs:
            family = str(entry.get("worker_family") or "")
            status = str(entry.get("status") or entry.get("job_status") or "")
            if status in RUNNING_JOB_STATUSES and (families is None or family in families):
                print(f"[wait] running tool={entry.get('tool')} family={family} scan={scan_id}")
                return entry
        await asyncio.sleep(0.5)
    raise RuntimeError(f"No running work observed for scan {scan_id}")


async def _wait_for_recovery_progress(
    client: httpx.AsyncClient,
    *,
    scan_id: str,
    worker_family: str,
    health_url: str,
    restart_threshold: datetime,
    timeout_seconds: int,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            health_payload = await _fetch_json(client, health_url)
        except Exception:
            health_payload = None

        if isinstance(health_payload, dict):
            current_job = health_payload.get("current_job")
            if isinstance(current_job, dict):
                claimed_delta = _seconds_after_threshold(
                    str(current_job.get("claimed_at") or ""),
                    threshold=restart_threshold,
                )
                started_delta = _seconds_after_threshold(
                    str(current_job.get("started_at") or ""),
                    threshold=restart_threshold,
                )
                delta_candidates = [
                    delta for delta in (claimed_delta, started_delta) if delta is not None
                ]
                if delta_candidates:
                    return {
                        "source": "worker_health",
                        "job_id": current_job.get("job_id"),
                        "tool": current_job.get("tool_name"),
                        "resumed_at": current_job.get("claimed_at") or current_job.get("started_at"),
                        "resume_seconds": min(delta_candidates),
                    }

        logs = await _get_tool_logs(client, scan_id)
        resumed_entries = [
            entry
            for entry in _started_after(logs, threshold=restart_threshold)
            if str(entry.get("worker_family") or "") == worker_family
        ]
        if resumed_entries:
            resumed_entries.sort(key=lambda entry: str(entry.get("started_at") or ""))
            entry = resumed_entries[0]
            return {
                "source": "tool_log",
                "job_id": entry.get("job_id"),
                "tool": entry.get("tool"),
                "resumed_at": entry.get("started_at"),
                "resume_seconds": _seconds_after_threshold(
                    str(entry.get("started_at") or ""),
                    threshold=restart_threshold,
                ),
            }

        await asyncio.sleep(0.5)

    raise RuntimeError(
        f"No resumed progress observed for worker family {worker_family} on scan {scan_id}"
    )


def _started_after(
    logs: list[dict[str, Any]],
    *,
    threshold: datetime,
) -> list[dict[str, Any]]:
    offenders: list[dict[str, Any]] = []
    for entry in logs:
        started_at = _parse_datetime(str(entry.get("started_at") or ""))
        if started_at is None or started_at <= threshold:
            continue
        offenders.append(
            {
                "tool": entry.get("tool"),
                "worker_family": entry.get("worker_family"),
                "status": entry.get("status"),
                "job_status": entry.get("job_status"),
                "started_at": entry.get("started_at"),
            }
        )
    return offenders


async def _cleanup_active_scans(client: httpx.AsyncClient) -> list[str]:
    scans = await _list_scans(client)
    active_scan_ids = [
        str(scan["id"])
        for scan in scans
        if str(scan.get("status")) in ACTIVE_SCAN_STATUSES
    ]
    if not active_scan_ids:
        return []

    print(f"[cleanup] cancelling active scans: {', '.join(active_scan_ids)}")
    for scan_id in active_scan_ids:
        try:
            await _cancel_scan(client, scan_id)
        except Exception as exc:
            print(f"[cleanup] cancel failed for {scan_id}: {exc}")

    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        scans = await _list_scans(client)
        remaining = [
            str(scan["id"])
            for scan in scans
            if str(scan.get("status")) in ACTIVE_SCAN_STATUSES
        ]
        if not remaining:
            return active_scan_ids
        await asyncio.sleep(1)

    raise RuntimeError("Timed out waiting for active scans to drain during cleanup")


def _service_env(extra: dict[str, str]) -> dict[str, str]:
    env = os.environ.copy()
    env.update(extra)
    return env


async def _terminate_service(
    *,
    name: str,
    health_url: str,
) -> int:
    pid = _read_pid(name)
    print(f"[service] stopping {name} pid={pid}")
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await _wait_for_json(
                client,
                url=health_url,
                expect_up=False,
                timeout_seconds=20,
                label=name,
            )
    finally:
        _pid_file(name).unlink(missing_ok=True)

    return pid


async def _start_service(
    *,
    name: str,
    command: list[str],
    env: dict[str, str],
    health_url: str,
) -> int:
    if _pid_file(name).exists():
        _pid_file(name).unlink(missing_ok=True)

    log_path = LOG_DIR / f"{name}.log"
    with log_path.open("ab") as log_handle:
        process = subprocess.Popen(
            command,
            cwd=str(ROOT_DIR),
            env=env,
            stdout=log_handle,
            stderr=log_handle,
            start_new_session=True,
        )
    _pid_file(name).write_text(f"{process.pid}\n")
    print(f"[service] started {name} pid={process.pid}")

    async with httpx.AsyncClient(timeout=5.0) as client:
        await _wait_for_json(
            client,
            url=health_url,
            expect_up=True,
            timeout_seconds=30,
            label=name,
        )
    return process.pid


async def _restart_worker(family: str) -> dict[str, Any]:
    health_url = _worker_health_url(family)
    name = f"worker-{family}"
    new_pid = await _start_service(
        name=name,
        command=[str(ROOT_DIR / "pentra_core/scripts/local/run_worker.sh"), family],
        env=_service_env(
            {
                "WORKER_LIVE_TOOLS": WORKER_LIVE_TOOLS,
                "WORKER_EXECUTION_MODE": os.getenv("WORKER_EXECUTION_MODE", "controlled_live_local"),
                "WORKER_LIVE_TARGET_POLICY": os.getenv("WORKER_LIVE_TARGET_POLICY", "local_only"),
                "WORKER_HEALTH_HOST": "127.0.0.1",
                "WORKER_HEALTH_PORT": str(WORKER_HEALTH_PORTS[family]),
                "WORKER_PREWARM_IMAGES": os.getenv("WORKER_PREWARM_IMAGES", "true"),
                "WORKER_BLOCK_MS": str(WORKER_BLOCK_MS),
                "WORKER_RECLAIM_IDLE_MS": str(WORKER_RECLAIM_IDLE_MS),
                "WORKER_RECLAIM_HEARTBEAT_MS": str(WORKER_RECLAIM_HEARTBEAT_MS),
            }
        ),
        health_url=health_url,
    )
    async with httpx.AsyncClient(timeout=5.0) as client:
        payload = await _wait_for_json(
            client,
            url=health_url,
            expect_up=True,
            timeout_seconds=10,
            label=name,
        )
    return {"pid": new_pid, "health": payload}


async def _restart_orchestrator() -> dict[str, Any]:
    new_pid = await _start_service(
        name="orchestrator",
        command=[str(ROOT_DIR / "pentra_core/scripts/local/run_orchestrator.sh")],
        env=_service_env(
            {
                "PENTRA_DISABLE_AUTONOMY": os.getenv("PENTRA_DISABLE_AUTONOMY", "false"),
                "PENTRA_ORCHESTRATOR_PORT": "8001",
            }
        ),
        health_url=_orchestrator_health_url(),
    )
    async with httpx.AsyncClient(timeout=5.0) as client:
        payload = await _wait_for_json(
            client,
            url=_orchestrator_health_url(),
            expect_up=True,
            timeout_seconds=10,
            label="orchestrator",
        )
    return {"pid": new_pid, "health": payload}


async def _orphan_matching_event(
    redis: aioredis.Redis,
    *,
    stream: str,
    matcher: Callable[[dict[str, Any]], bool],
    timeout_seconds: int,
) -> dict[str, Any]:
    consumer_name = f"chaos-orphan-{uuid.uuid4()}"
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        messages = await redis.xreadgroup(
            groupname=ORCHESTRATOR_GROUP,
            consumername=consumer_name,
            streams={stream: ">"},
            count=10,
            block=1000,
        )
        if not messages:
            continue
        for _stream_name, entries in messages:
            for msg_id, fields in entries:
                raw = fields.get("data", "{}")
                try:
                    payload = json.loads(raw)
                except Exception:
                    payload = {}
                if matcher(payload):
                    print(
                        f"[orphan] claimed {payload.get('event_type')} msg={msg_id} consumer={consumer_name}"
                    )
                    return {
                        "consumer_name": consumer_name,
                        "message_id": msg_id,
                        "payload": payload,
                    }
    raise RuntimeError(f"Timed out waiting to orphan a matching event on {stream}")


async def _scenario_worker_death_recovery(
    client: httpx.AsyncClient,
    redis: aioredis.Redis,
) -> dict[str, Any]:
    del redis
    await _cleanup_active_scans(client)
    scan = await _create_scan(client, scan_type="full", config=STATEFUL_FULL_CONFIG)
    scan_id = str(scan["id"])

    running = await _wait_for_running_work(
        client,
        scan_id=scan_id,
        families={"web", "vuln", "exploit"},
        timeout_seconds=45,
    )
    family = str(running["worker_family"])
    health_url = _worker_health_url(family)

    async with httpx.AsyncClient(timeout=5.0) as health_client:
        before_health = await _wait_for_json(
            health_client,
            url=health_url,
            expect_up=True,
            timeout_seconds=5,
            label=f"worker-{family}",
        )

    killed_pid = await _terminate_service(name=f"worker-{family}", health_url=health_url)
    restart_started_at = _utc_now()
    restarted = await _restart_worker(family)
    recovery = await _wait_for_recovery_progress(
        client,
        scan_id=scan_id,
        worker_family=family,
        health_url=health_url,
        restart_threshold=_parse_datetime(restart_started_at) or datetime.now(UTC),
        timeout_seconds=30,
    )

    terminal = await _wait_for_scan_terminal(
        client,
        scan_id=scan_id,
        timeout_seconds=180,
    )
    if str(terminal.get("status")) != "completed":
        raise RuntimeError(f"Worker death scenario ended in {terminal.get('status')}")

    return {
        "scan_id": scan_id,
        "killed_worker_family": family,
        "killed_pid": killed_pid,
        "restart_started_at": restart_started_at,
        "restarted_pid": restarted["pid"],
        "worker_health_before": before_health,
        "worker_health_after": restarted["health"],
        "recovery_resumed_at": recovery["resumed_at"],
        "recovery_resume_seconds": recovery["resume_seconds"],
        "recovery_source": recovery["source"],
        "recovery_job_id": recovery.get("job_id"),
        "recovery_tool": recovery.get("tool"),
        "terminal_status": terminal["status"],
        "scan_duration_seconds": _iso_duration_seconds(
            terminal.get("started_at"),
            terminal.get("completed_at"),
        ),
    }


async def _scenario_cancel_during_execution(
    client: httpx.AsyncClient,
    redis: aioredis.Redis,
) -> dict[str, Any]:
    del redis
    await _cleanup_active_scans(client)
    scan = await _create_scan(client, scan_type="full", config=STATEFUL_FULL_CONFIG)
    scan_id = str(scan["id"])

    await _wait_for_running_work(
        client,
        scan_id=scan_id,
        families={"web", "vuln", "exploit"},
        timeout_seconds=45,
    )

    cancel_requested_at = datetime.now(UTC)
    cancelled = await _cancel_scan(client, scan_id)
    if str(cancelled.get("status")) != "cancelled":
        raise RuntimeError(f"Cancel endpoint returned {cancelled.get('status')}")

    await _wait_for_scan_status(
        client,
        scan_id=scan_id,
        expected_status="cancelled",
        timeout_seconds=20,
    )
    await asyncio.sleep(8)
    final_scan = await _get_scan(client, scan_id)
    logs = await _get_tool_logs(client, scan_id)
    offenders = _started_after(
        logs,
        threshold=cancel_requested_at + timedelta(seconds=2),
    )
    if str(final_scan.get("status")) != "cancelled":
        raise RuntimeError(f"Cancelled scan regressed to {final_scan.get('status')}")
    if offenders:
        raise RuntimeError(f"Observed new job starts after cancel: {offenders}")

    return {
        "scan_id": scan_id,
        "cancel_requested_at": cancel_requested_at.isoformat(),
        "terminal_status": final_scan["status"],
        "jobs_after_cancel_grace": offenders,
    }


async def _scenario_pause_resume_under_load(
    client: httpx.AsyncClient,
    redis: aioredis.Redis,
) -> dict[str, Any]:
    del redis
    await _cleanup_active_scans(client)
    scan = await _create_scan(client, scan_type="full", config=STATEFUL_FULL_CONFIG)
    scan_id = str(scan["id"])

    await _wait_for_running_work(
        client,
        scan_id=scan_id,
        families={"web", "vuln", "exploit"},
        timeout_seconds=45,
    )

    pause_requested_at = datetime.now(UTC)
    paused = await _pause_scan(client, scan_id)
    if str(paused.get("status")) != "paused":
        raise RuntimeError(f"Pause endpoint returned {paused.get('status')}")

    await _wait_for_scan_status(
        client,
        scan_id=scan_id,
        expected_status="paused",
        timeout_seconds=20,
    )
    await asyncio.sleep(8)
    paused_scan = await _get_scan(client, scan_id)
    paused_logs = await _get_tool_logs(client, scan_id)
    offenders = _started_after(
        paused_logs,
        threshold=pause_requested_at + timedelta(seconds=2),
    )
    if str(paused_scan.get("status")) != "paused":
        raise RuntimeError(f"Paused scan regressed to {paused_scan.get('status')}")
    if offenders:
        raise RuntimeError(f"Observed new job starts while paused: {offenders}")

    resume_requested_at = _utc_now()
    resumed = await _resume_scan(client, scan_id)
    if str(resumed.get("status")) != "running":
        raise RuntimeError(f"Resume endpoint returned {resumed.get('status')}")

    terminal = await _wait_for_scan_terminal(
        client,
        scan_id=scan_id,
        timeout_seconds=180,
    )
    if str(terminal.get("status")) != "completed":
        raise RuntimeError(f"Pause/resume scenario ended in {terminal.get('status')}")

    return {
        "scan_id": scan_id,
        "pause_requested_at": pause_requested_at.isoformat(),
        "resume_requested_at": resume_requested_at,
        "terminal_status": terminal["status"],
        "scan_duration_seconds": _iso_duration_seconds(
            terminal.get("started_at"),
            terminal.get("completed_at"),
        ),
    }


async def _scenario_scan_event_reclaim(
    client: httpx.AsyncClient,
    redis: aioredis.Redis,
) -> dict[str, Any]:
    await _cleanup_active_scans(client)

    killed_pid = await _terminate_service(
        name="orchestrator",
        health_url=_orchestrator_health_url(),
    )

    try:
        scan = await _create_scan(
            client,
            scan_type="recon",
            config={"profile_id": "external_web_api_v1"},
        )
        scan_id = str(scan["id"])
        orphaned = await _orphan_matching_event(
            redis,
            stream=SCAN_STREAM,
            matcher=lambda payload: (
                str(payload.get("event_type")) == "scan.created"
                and str(payload.get("scan_id")) == scan_id
            ),
            timeout_seconds=20,
        )
    finally:
        restarted = await _restart_orchestrator()

    await asyncio.sleep((ORCHESTRATOR_RECLAIM_IDLE_MS / 1000) + 2)
    terminal = await _wait_for_scan_terminal(
        client,
        scan_id=scan_id,
        timeout_seconds=120,
    )
    if str(terminal.get("status")) != "completed":
        raise RuntimeError(f"Scan-event reclaim scenario ended in {terminal.get('status')}")

    return {
        "scan_id": scan_id,
        "orphaned_message_id": orphaned["message_id"],
        "orphan_consumer_name": orphaned["consumer_name"],
        "killed_orchestrator_pid": killed_pid,
        "restarted_orchestrator_pid": restarted["pid"],
        "terminal_status": terminal["status"],
    }


async def _scenario_job_event_reclaim(
    client: httpx.AsyncClient,
    redis: aioredis.Redis,
) -> dict[str, Any]:
    await _cleanup_active_scans(client)
    scan = await _create_scan(client, scan_type="full", config=STATEFUL_FULL_CONFIG)
    scan_id = str(scan["id"])

    await _wait_for_running_work(
        client,
        scan_id=scan_id,
        families={"web", "vuln", "exploit"},
        timeout_seconds=45,
    )

    killed_pid = await _terminate_service(
        name="orchestrator",
        health_url=_orchestrator_health_url(),
    )
    try:
        orphaned = await _orphan_matching_event(
            redis,
            stream=JOB_STREAM,
            matcher=lambda payload: (
                str(payload.get("scan_id")) == scan_id
                and str(payload.get("event_type")) in {"job.completed", "job.failed"}
            ),
            timeout_seconds=90,
        )
    finally:
        restarted = await _restart_orchestrator()

    await asyncio.sleep((ORCHESTRATOR_RECLAIM_IDLE_MS / 1000) + 2)
    terminal = await _wait_for_scan_terminal(
        client,
        scan_id=scan_id,
        timeout_seconds=180,
    )
    if str(terminal.get("status")) != "completed":
        raise RuntimeError(f"Job-event reclaim scenario ended in {terminal.get('status')}")

    return {
        "scan_id": scan_id,
        "orphaned_message_id": orphaned["message_id"],
        "orphaned_event_type": orphaned["payload"].get("event_type"),
        "orphan_consumer_name": orphaned["consumer_name"],
        "killed_orchestrator_pid": killed_pid,
        "restarted_orchestrator_pid": restarted["pid"],
        "terminal_status": terminal["status"],
        "scan_duration_seconds": _iso_duration_seconds(
            terminal.get("started_at"),
            terminal.get("completed_at"),
        ),
    }


SCENARIOS: tuple[ScenarioDefinition, ...] = (
    ScenarioDefinition(
        key="worker_death_recovery",
        label="Worker death recovery",
        timeout_seconds=240,
        runner=_scenario_worker_death_recovery,
    ),
    ScenarioDefinition(
        key="cancel_during_execution",
        label="Cancel during active execution",
        timeout_seconds=90,
        runner=_scenario_cancel_during_execution,
    ),
    ScenarioDefinition(
        key="pause_resume_under_load",
        label="Pause/resume under load",
        timeout_seconds=240,
        runner=_scenario_pause_resume_under_load,
    ),
    ScenarioDefinition(
        key="scan_event_reclaim",
        label="Scan-event reclaim after orchestrator interruption",
        timeout_seconds=180,
        runner=_scenario_scan_event_reclaim,
    ),
    ScenarioDefinition(
        key="job_event_reclaim",
        label="Job-event reclaim after orchestrator interruption",
        timeout_seconds=240,
        runner=_scenario_job_event_reclaim,
    ),
)


def _write_artifact(*, results: list[dict[str, Any]], status: str) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": _utc_now(),
        "status": status,
        "phase": "P6.3",
        "api_base_url": API_BASE_URL,
        "orchestrator_base_url": ORCH_BASE_URL,
        "demo_target_url": DEMO_TARGET_URL,
        "asset_id": ASSET_ID,
        "reclaim_idle_ms": ORCHESTRATOR_RECLAIM_IDLE_MS,
        "orchestrator_reclaim_idle_ms": ORCHESTRATOR_RECLAIM_IDLE_MS,
        "worker_reclaim_idle_ms": WORKER_RECLAIM_IDLE_MS,
        "worker_reclaim_heartbeat_ms": WORKER_RECLAIM_HEARTBEAT_MS,
        "worker_block_ms": WORKER_BLOCK_MS,
        "summary": {
            "scenario_count": len(results),
            "passed": sum(1 for result in results if result.get("status") == "passed"),
            "failed": sum(1 for result in results if result.get("status") == "failed"),
        },
        "scenarios": results,
    }
    stamped = stamp_proof_payload(
        payload,
        artifact_kind="chaos_matrix",
        phase="P6.3",
        script_path="pentra_core/scripts/local/run_phase6_chaos_matrix.py",
        root_dir=ROOT_DIR,
        environment_context={
            "api_base_url": API_BASE_URL,
            "orchestrator_base_url": ORCH_BASE_URL,
            "demo_target_url": DEMO_TARGET_URL,
            "asset_id": ASSET_ID,
            "worker_live_tools": WORKER_LIVE_TOOLS,
            "worker_reclaim_idle_ms": WORKER_RECLAIM_IDLE_MS,
            "worker_reclaim_heartbeat_ms": WORKER_RECLAIM_HEARTBEAT_MS,
            "worker_block_ms": WORKER_BLOCK_MS,
            "orchestrator_reclaim_idle_ms": ORCHESTRATOR_RECLAIM_IDLE_MS,
        },
        run_id=PROOF_RUN_ID,
    )
    OUTPUT_PATH.write_text(json.dumps(stamped, indent=2, sort_keys=True))


async def _ensure_stack_health(client: httpx.AsyncClient) -> None:
    await _assert_http_ok(client, f"{API_BASE_URL}/health", "api health")
    await _assert_http_ok(client, _orchestrator_health_url(), "orchestrator health")
    await _assert_http_ok(client, f"{DEMO_TARGET_URL}/healthz", "demo target health")
    for family in WORKER_HEALTH_PORTS:
        await _assert_http_ok(client, _worker_health_url(family), f"worker {family} health")


async def main() -> None:
    results: list[dict[str, Any]] = []

    async with httpx.AsyncClient(timeout=10.0) as client:
        await _ensure_stack_health(client)
        redis = aioredis.from_url(REDIS_URL, decode_responses=True)
        try:
            await redis.ping()

            for scenario in SCENARIOS:
                print(f"[scenario] {scenario.label}")
                started_at = _utc_now()
                started_monotonic = time.monotonic()
                try:
                    detail = await asyncio.wait_for(
                        scenario.runner(client, redis),
                        timeout=scenario.timeout_seconds,
                    )
                    result = {
                        "scenario_key": scenario.key,
                        "label": scenario.label,
                        "status": "passed",
                        "started_at": started_at,
                        "completed_at": _utc_now(),
                        "duration_seconds": round(time.monotonic() - started_monotonic, 2),
                        "detail": detail,
                    }
                    results.append(result)
                    _write_artifact(results=results, status="in_progress")
                except Exception as exc:
                    result = {
                        "scenario_key": scenario.key,
                        "label": scenario.label,
                        "status": "failed",
                        "started_at": started_at,
                        "completed_at": _utc_now(),
                        "duration_seconds": round(time.monotonic() - started_monotonic, 2),
                        "error": str(exc),
                    }
                    results.append(result)
                    _write_artifact(results=results, status="failed")
                    raise
                finally:
                    await _cleanup_active_scans(client)

            _write_artifact(results=results, status="passed")
            print(f"[ok] Wrote Phase 6 chaos proof to {OUTPUT_PATH}")
        finally:
            await redis.aclose()


if __name__ == "__main__":
    asyncio.run(main())
