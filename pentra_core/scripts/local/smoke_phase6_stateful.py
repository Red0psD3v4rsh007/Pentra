"""Phase 6 smoke test for stateful web interaction and workflow replay.

Checks:
  - a full scan against the local demo target completes
  - the web_interact job performs authenticated crawl and safe replay
  - workflow-driven custom_poc nodes execute when autonomy is enabled
  - stateful findings surface through the API
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from typing import Any

import httpx

API_BASE_URL = os.getenv("PENTRA_API_BASE_URL", "http://127.0.0.1:8000")
ORCH_BASE_URL = os.getenv("PENTRA_ORCHESTRATOR_BASE_URL", "http://127.0.0.1:8001")
DEMO_TARGET_URL = os.getenv("PENTRA_PHASE6_DEMO_URL", "http://127.0.0.1:8088")
ASSET_ID = os.getenv("PENTRA_PHASE6_ASSET_ID", "55555555-5555-5555-5555-555555555555")
TIMEOUT_SECONDS = int(os.getenv("PENTRA_PHASE6_TIMEOUT_SECONDS", "300"))
POLL_INTERVAL_SECONDS = float(os.getenv("PENTRA_PHASE6_POLL_INTERVAL_SECONDS", "3"))


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
            "config": {
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
            },
        },
    )
    response.raise_for_status()
    scan_id = response.json()["id"]
    print(f"[ok] phase6 scan created: {scan_id}")
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
    raise RuntimeError(f"Phase 6 scan {scan_id} did not finish within {TIMEOUT_SECONDS}s")


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


async def main() -> int:
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            await _assert_http_ok(client, f"{API_BASE_URL}/health", "api health")
            await _assert_http_ok(client, f"{ORCH_BASE_URL}/health", "orchestrator health")
            await _assert_http_ok(client, f"{DEMO_TARGET_URL}/healthz", "demo target health")

            scan_id = await _create_scan(client)
            result = await _poll_scan(client, scan_id)
            if result["status"] != "completed":
                raise RuntimeError(f"Phase 6 scan ended in {result['status']}")

            jobs = _unwrap_items(await _fetch_json(client, f"/api/v1/scans/{scan_id}/jobs"))
            job_status = {job["tool"]: job["status"] for job in jobs}
            if job_status.get("web_interact") != "completed":
                raise RuntimeError(f"web_interact did not complete: {job_status.get('web_interact')}")
            print("[ok] web_interact job completed")

            artifact_summaries = await _fetch_json(client, f"/api/v1/scans/{scan_id}/artifacts/summary")
            web_interact = next(
                (item for item in artifact_summaries if item.get("tool") == "web_interact"),
                None,
            )
            if web_interact is None:
                raise RuntimeError("No web_interact artifact summary returned by the API")

            stateful = web_interact.get("summary", {}).get("stateful_context", {})
            if int(stateful.get("session_count", 0) or 0) < 1:
                raise RuntimeError("web_interact did not record any authenticated session context")
            if int(stateful.get("form_count", 0) or 0) < 1:
                raise RuntimeError("web_interact did not discover any forms")
            if int(stateful.get("replay_count", 0) or 0) < 1:
                raise RuntimeError("web_interact did not perform any safe replay")
            print(
                "[ok] stateful summary:",
                f"sessions={stateful.get('session_count', 0)}",
                f"forms={stateful.get('form_count', 0)}",
                f"workflows={stateful.get('workflow_count', 0)}",
                f"replays={stateful.get('replay_count', 0)}",
            )

            workflow_jobs = [job for job in jobs if job.get("tool") == "custom_poc"]
            if not workflow_jobs:
                raise RuntimeError(
                    "No workflow-driven custom_poc jobs were dispatched. "
                    "Start the orchestrator with PENTRA_DISABLE_AUTONOMY=false for Phase 6 verification."
                )
            if not any(job.get("status") == "completed" for job in workflow_jobs):
                raise RuntimeError("Workflow custom_poc jobs were created but did not complete")
            print(f"[ok] workflow custom_poc jobs: {len(workflow_jobs)}")

            findings = _unwrap_items(await _fetch_json(client, f"/api/v1/scans/{scan_id}/findings"))
            stateful_findings = [
                finding
                for finding in findings
                if finding.get("vulnerability_type") in {
                    "workflow_bypass",
                    "auth_bypass",
                    "idor",
                    "privilege_escalation",
                }
            ]
            if not stateful_findings:
                raise RuntimeError("No stateful findings were returned by the API")
            print(f"[ok] stateful findings surfaced: {len(stateful_findings)}")

        print(f"[done] Phase 6 stateful smoke test passed: scan={scan_id}")
        return 0
    except Exception as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
