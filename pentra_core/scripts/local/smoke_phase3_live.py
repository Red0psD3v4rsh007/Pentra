"""Phase 3 smoke test for Pentra's controlled live web/API slice.

Checks:
  - API and orchestrator health endpoints respond
  - the local Phase 3 demo target responds
  - a full scan can be created for the seeded demo asset
  - the controlled-live tools complete: httpx_probe, ffuf, nuclei, sqlmap
  - the scan produces artifacts, findings, evidence, attack graph, and report data

Expected local stack:
  - API on http://localhost:8000
  - orchestrator on http://localhost:8001
  - PostgreSQL on localhost:5433
  - Redis on localhost:6379
  - local demo target on http://127.0.0.1:8088
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
DEMO_TARGET_URL = os.getenv("PENTRA_PHASE3_DEMO_URL", "http://127.0.0.1:8088")
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://pentra:pentra@localhost:5433/pentra_dev",
)
ASSET_ID = os.getenv("PENTRA_PHASE3_ASSET_ID", "55555555-5555-5555-5555-555555555555")
TIMEOUT_SECONDS = int(os.getenv("PENTRA_PHASE3_TIMEOUT_SECONDS", "240"))
POLL_INTERVAL_SECONDS = float(os.getenv("PENTRA_PHASE3_POLL_INTERVAL_SECONDS", "3"))
LIVE_TOOLS = ("httpx_probe", "ffuf", "nuclei", "sqlmap")


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
            "scan_type": "full",
            "priority": "normal",
            "config": {
                "profile_id": "external_web_api_v1",
            },
        },
    )
    response.raise_for_status()
    payload = response.json()
    print(f"[ok] phase3 scan created: {payload['id']}")
    return payload


async def _poll_scan(client: httpx.AsyncClient, scan_id: str) -> dict[str, Any]:
    deadline = time.monotonic() + TIMEOUT_SECONDS

    while time.monotonic() < deadline:
        response = await client.get(f"{API_BASE_URL}/api/v1/scans/{scan_id}")
        response.raise_for_status()
        payload = response.json()
        print(
            f"[wait] scan={scan_id} status={payload['status']} progress={payload['progress']}%"
        )

        if payload["status"] in {"completed", "failed", "rejected"}:
            return payload

        await asyncio.sleep(POLL_INTERVAL_SECONDS)

    raise RuntimeError(
        f"Phase 3 scan {scan_id} did not reach a terminal state within {TIMEOUT_SECONDS}s"
    )


async def _fetch_json(client: httpx.AsyncClient, path: str) -> Any:
    response = await client.get(f"{API_BASE_URL}{path}")
    response.raise_for_status()
    return response.json()


async def _assert_jobs(scan_id: str, jobs: list[dict[str, Any]]) -> None:
    completed_by_tool = {job["tool"]: job["status"] for job in jobs}
    missing = [tool for tool in LIVE_TOOLS if completed_by_tool.get(tool) != "completed"]
    if missing:
        raise RuntimeError(f"Controlled-live tools did not complete: {', '.join(missing)}")
    print("[ok] controlled-live jobs completed:", ", ".join(LIVE_TOOLS))


async def _assert_db(scan_id: str) -> None:
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
        artifact_count = await conn.fetchval(
            "SELECT COUNT(*) FROM scan_artifacts WHERE scan_id = $1",
            scan_id,
        )
        finding_count = await conn.fetchval(
            "SELECT COUNT(*) FROM findings WHERE scan_id = $1",
            scan_id,
        )

        print(f"[ok] db scan status: {scan_row['status']} ({scan_row['progress']}%)")
        print(f"[ok] db artifacts: {artifact_count}")
        print(f"[ok] db findings: {finding_count}")

        if artifact_count < 1:
            raise RuntimeError("No scan_artifacts rows found for the Phase 3 scan")
        if finding_count < 1:
            raise RuntimeError("No findings rows found for the Phase 3 scan")
    finally:
        await conn.close()


async def main() -> int:
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            await _assert_http_ok(client, f"{API_BASE_URL}/health", "api health")
            await _assert_http_ok(client, f"{API_BASE_URL}/ready", "api readiness")
            await _assert_http_ok(client, f"{ORCH_BASE_URL}/health", "orchestrator health")
            await _assert_http_ok(client, f"{DEMO_TARGET_URL}/healthz", "demo target health")

            created = await _create_scan(client)
            finished = await _poll_scan(client, created["id"])
            if finished["status"] != "completed":
                raise RuntimeError(
                    f"Phase 3 scan ended in {finished['status']}: {finished.get('error_message')}"
                )

            scan_id = created["id"]
            jobs = await _fetch_json(client, f"/api/v1/scans/{scan_id}/jobs")
            await _assert_jobs(scan_id, jobs)

            findings = await _fetch_json(client, f"/api/v1/scans/{scan_id}/findings")
            artifacts = await _fetch_json(client, f"/api/v1/scans/{scan_id}/artifacts/summary")
            evidence = await _fetch_json(client, f"/api/v1/scans/{scan_id}/evidence")
            attack_graph = await _fetch_json(client, f"/api/v1/scans/{scan_id}/attack-graph")
            report = await _fetch_json(client, f"/api/v1/scans/{scan_id}/report")

            print(f"[ok] findings via API: {len(findings)}")
            print(f"[ok] artifact summaries via API: {len(artifacts)}")
            print(f"[ok] evidence references via API: {len(evidence)}")
            print(
                "[ok] attack graph:",
                f"{len(attack_graph.get('nodes', []))} nodes,",
                f"{len(attack_graph.get('edges', []))} edges",
            )
            report_label = report.get("title") or report.get("executive_summary", "")[:120] or "n/a"
            print(f"[ok] report summary: {report_label}")

            if len(findings) < 1:
                raise RuntimeError("Phase 3 scan produced no persisted findings")
            if len(artifacts) < 4:
                raise RuntimeError("Phase 3 scan produced too few artifact summaries")
            if len(evidence) < 1:
                raise RuntimeError("Phase 3 scan produced no evidence references")
            if not attack_graph.get("nodes"):
                raise RuntimeError("Phase 3 scan produced no attack graph nodes")
            if not report.get("executive_summary"):
                raise RuntimeError("Phase 3 scan produced no report summary")

            await _assert_db(scan_id)

        print(
            "[done] Phase 3 live smoke test passed:",
            f"scan={created['id']}",
            "live_tools=httpx_probe,ffuf,nuclei,sqlmap",
        )
        return 0
    except Exception as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
