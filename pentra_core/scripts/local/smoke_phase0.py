"""Phase 0 smoke test for the local Pentra pipeline.

Checks:
  - API and orchestrator health endpoints respond
  - a scan can be created via the API
  - the orchestrator creates DAG/jobs
  - workers complete at least one job
  - artifacts are stored in PostgreSQL

Expected local stack:
  - API on http://localhost:8000
  - orchestrator on http://localhost:8001
  - PostgreSQL on localhost:5433
  - Redis on localhost:6379
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from typing import Any

import asyncpg
import httpx

API_BASE_URL = os.getenv("PENTRA_API_BASE_URL", "http://127.0.0.1:8000")
ORCH_BASE_URL = os.getenv("PENTRA_ORCHESTRATOR_BASE_URL", "http://127.0.0.1:8001")
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://pentra:pentra@localhost:5433/pentra_dev",
)
ASSET_ID = os.getenv("PENTRA_DEV_ASSET_ID", "44444444-4444-4444-4444-444444444444")
TIMEOUT_SECONDS = int(os.getenv("PENTRA_SMOKE_TIMEOUT_SECONDS", "90"))


def _sync_db_url(database_url: str) -> str:
    return database_url.replace("postgresql+asyncpg://", "postgresql://", 1)


async def _assert_http_ok(client: httpx.AsyncClient, url: str, label: str) -> None:
    response = await client.get(url)
    response.raise_for_status()
    print(f"[ok] {label}: {response.status_code}")


async def _create_scan(client: httpx.AsyncClient) -> dict[str, Any]:
    response = await client.post(
        f"{API_BASE_URL}/api/v1/scans",
        json={
            "asset_id": ASSET_ID,
            "scan_type": "recon",
            "priority": "normal",
            "config": {
                "phase0_smoke": True,
            },
        },
    )
    response.raise_for_status()
    payload = response.json()
    print(f"[ok] scan created: {payload['id']}")
    return payload


async def _poll_scan(client: httpx.AsyncClient, scan_id: str) -> dict[str, Any]:
    deadline = time.monotonic() + TIMEOUT_SECONDS

    while time.monotonic() < deadline:
        response = await client.get(f"{API_BASE_URL}/api/v1/scans/{scan_id}")
        response.raise_for_status()
        payload = response.json()
        status = payload["status"]
        progress = payload["progress"]
        print(f"[wait] scan={scan_id} status={status} progress={progress}%")

        if status in {"completed", "failed", "rejected"}:
            return payload

        await asyncio.sleep(2)

    raise RuntimeError(
        f"Scan {scan_id} did not reach a terminal state within {TIMEOUT_SECONDS}s"
    )


async def _fetch_jobs(client: httpx.AsyncClient, scan_id: str) -> list[dict[str, Any]]:
    response = await client.get(f"{API_BASE_URL}/api/v1/scans/{scan_id}/jobs")
    response.raise_for_status()
    jobs = response.json()
    print(f"[ok] jobs visible via API: {len(jobs)}")
    return jobs


async def _check_db(scan_id: str) -> None:
    conn = await asyncpg.connect(_sync_db_url(DATABASE_URL))
    try:
        scan_row = await conn.fetchrow(
            """
            SELECT status, progress
            FROM scans
            WHERE id = $1
            """,
            scan_id,
        )
        dag_count = await conn.fetchval(
            "SELECT COUNT(*) FROM scan_dags WHERE scan_id = $1",
            scan_id,
        )
        job_count = await conn.fetchval(
            "SELECT COUNT(*) FROM scan_jobs WHERE scan_id = $1",
            scan_id,
        )
        artifact_count = await conn.fetchval(
            "SELECT COUNT(*) FROM scan_artifacts WHERE scan_id = $1",
            scan_id,
        )

        print(f"[ok] db scan status: {scan_row['status']} ({scan_row['progress']}%)")
        print(f"[ok] db dag rows: {dag_count}")
        print(f"[ok] db job rows: {job_count}")
        print(f"[ok] db artifact rows: {artifact_count}")

        if dag_count < 1:
            raise RuntimeError("No scan_dags row found for the created scan")
        if job_count < 1:
            raise RuntimeError("No scan_jobs rows found for the created scan")
        if artifact_count < 1:
            raise RuntimeError("No scan_artifacts rows found for the created scan")
    finally:
        await conn.close()


async def main() -> int:
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            await _assert_http_ok(client, f"{API_BASE_URL}/health", "api health")
            await _assert_http_ok(client, f"{API_BASE_URL}/ready", "api readiness")
            await _assert_http_ok(client, f"{ORCH_BASE_URL}/health", "orchestrator health")

            created = await _create_scan(client)
            finished = await _poll_scan(client, created["id"])
            await _fetch_jobs(client, created["id"])
            await _check_db(created["id"])

        print(
            "[done] Phase 0 smoke test passed:",
            f"scan={created['id']}",
            f"final_status={finished['status']}",
        )
        return 0
    except Exception as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
