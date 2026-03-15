"""Phase 4 smoke test for safe exploit verification.

Checks:
  - a full scan against the local Phase 3 demo target completes
  - exploit verification jobs execute for selected safe classes
  - verified findings are persisted with verification state and evidence
  - report output separates verified findings from inferred findings
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
DEMO_TARGET_URL = os.getenv("PENTRA_PHASE4_DEMO_URL", "http://127.0.0.1:8088")
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://pentra:pentra@localhost:5433/pentra_dev",
)
ASSET_ID = os.getenv("PENTRA_PHASE4_ASSET_ID", "55555555-5555-5555-5555-555555555555")
TIMEOUT_SECONDS = int(os.getenv("PENTRA_PHASE4_TIMEOUT_SECONDS", "300"))
POLL_INTERVAL_SECONDS = float(os.getenv("PENTRA_PHASE4_POLL_INTERVAL_SECONDS", "3"))


def _sync_db_url(database_url: str) -> str:
    return database_url.replace("postgresql+asyncpg://", "postgresql://", 1)


async def _assert_http_ok(client: httpx.AsyncClient, url: str, label: str) -> None:
    response = await client.get(url)
    response.raise_for_status()
    print(f"[ok] {label}: {response.status_code}")


async def _create_scan(client: httpx.AsyncClient) -> str:
    response = await client.post(
        f"{API_BASE_URL}/api/v1/scans",
        json={
            "asset_id": ASSET_ID,
            "scan_type": "full",
            "priority": "normal",
            "config": {"profile_id": "external_web_api_v1"},
        },
    )
    response.raise_for_status()
    scan_id = response.json()["id"]
    print(f"[ok] phase4 scan created: {scan_id}")
    return scan_id


async def _poll_scan(client: httpx.AsyncClient, scan_id: str) -> dict[str, Any]:
    deadline = time.monotonic() + TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        response = await client.get(f"{API_BASE_URL}/api/v1/scans/{scan_id}")
        response.raise_for_status()
        payload = response.json()
        print(f"[wait] scan={scan_id} status={payload['status']} progress={payload['progress']}%")
        if payload["status"] in {"completed", "failed", "rejected"}:
            return payload
        await asyncio.sleep(POLL_INTERVAL_SECONDS)
    raise RuntimeError(f"Phase 4 scan {scan_id} did not finish within {TIMEOUT_SECONDS}s")


async def _fetch_json(client: httpx.AsyncClient, path: str) -> Any:
    response = await client.get(f"{API_BASE_URL}{path}")
    response.raise_for_status()
    return response.json()


def _unwrap_items(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        items = payload.get("items")
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
    return []


async def _assert_db(scan_id: str) -> None:
    conn = await asyncpg.connect(_sync_db_url(DATABASE_URL))
    try:
        impact_count = await conn.fetchval(
            """
            SELECT COUNT(*)
            FROM scan_artifacts
            WHERE scan_id = $1
              AND artifact_type IN ('database_access', 'verified_impact')
            """,
            scan_id,
        )
        verified_findings = await conn.fetchval(
            """
            SELECT COUNT(*)
            FROM findings
            WHERE scan_id = $1
              AND source_type = 'exploit_verify'
            """,
            scan_id,
        )
        print(f"[ok] db impact artifacts: {impact_count}")
        print(f"[ok] db verified findings: {verified_findings}")
        if impact_count < 1:
            raise RuntimeError("No impact verification artifacts were stored")
        if verified_findings < 1:
            raise RuntimeError("No exploit_verify findings were persisted")
    finally:
        await conn.close()


async def main() -> int:
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            await _assert_http_ok(client, f"{API_BASE_URL}/health", "api health")
            await _assert_http_ok(client, f"{ORCH_BASE_URL}/health", "orchestrator health")
            await _assert_http_ok(client, f"{DEMO_TARGET_URL}/healthz", "demo target health")

            scan_id = await _create_scan(client)
            result = await _poll_scan(client, scan_id)
            if result["status"] != "completed":
                raise RuntimeError(f"Phase 4 scan ended in {result['status']}")

            jobs = await _fetch_json(client, f"/api/v1/scans/{scan_id}/jobs")
            job_status = {job["tool"]: job["status"] for job in jobs}
            for tool in ("sqlmap_verify", "custom_poc"):
                if job_status.get(tool) != "completed":
                    raise RuntimeError(f"{tool} did not complete: {job_status.get(tool)}")
            if "metasploit" in job_status:
                raise RuntimeError("safe_first verification should not dispatch metasploit")
            print("[ok] safe verification jobs completed: sqlmap_verify, custom_poc")

            findings = _unwrap_items(await _fetch_json(client, f"/api/v1/scans/{scan_id}/findings"))
            verified = [finding for finding in findings if finding.get("verification_state") == "verified"]
            if not verified:
                raise RuntimeError("No verified findings returned by the API")
            print(f"[ok] verified findings via API: {len(verified)}")

            report = await _fetch_json(client, f"/api/v1/scans/{scan_id}/report")
            verification_counts = report.get("verification_counts", {})
            if int(verification_counts.get("verified", 0) or 0) < 1:
                raise RuntimeError("Report does not include verified findings")
            print(
                "[ok] report verification counts:",
                f"verified={verification_counts.get('verified', 0)}",
                f"suspected={verification_counts.get('suspected', 0)}",
                f"detected={verification_counts.get('detected', 0)}",
            )

            evidence = await _fetch_json(client, f"/api/v1/scans/{scan_id}/evidence")
            exploit_evidence = [
                item for item in evidence if item.get("evidence_type") in {"exploit_result", "response"}
            ]
            if not exploit_evidence:
                raise RuntimeError("No exploit evidence references returned by the API")
            print(f"[ok] exploit evidence references: {len(exploit_evidence)}")

            await _assert_db(scan_id)

        print(f"[done] Phase 4 safe verification smoke test passed: scan={scan_id}")
        return 0
    except Exception as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
