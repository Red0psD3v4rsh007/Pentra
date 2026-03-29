"""Full-stack smoke test for Pentra's local live validation phase.

This script assumes the repo-owned local stack is already running. It verifies
service health for the frontend, API, orchestrator, demo target, and workers,
then runs both the controlled-live Phase 3 smoke and the stateful Phase 6 smoke.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from pathlib import Path

import httpx

ROOT_DIR = Path(__file__).resolve().parents[3]

API_BASE_URL = os.getenv("PENTRA_API_BASE_URL", "http://127.0.0.1:8000")
ORCH_BASE_URL = os.getenv("PENTRA_ORCHESTRATOR_BASE_URL", "http://127.0.0.1:8001")
FRONTEND_BASE_URL = os.getenv("PENTRA_FRONTEND_BASE_URL", "http://127.0.0.1:3006")
DEMO_TARGET_URL = os.getenv("PENTRA_PHASE3_DEMO_URL", "http://127.0.0.1:8088")

WORKER_HEALTH_PORTS = {
    "recon": int(os.getenv("PENTRA_WORKER_RECON_HEALTH_PORT", "9101")),
    "network": int(os.getenv("PENTRA_WORKER_NETWORK_HEALTH_PORT", "9102")),
    "web": int(os.getenv("PENTRA_WORKER_WEB_HEALTH_PORT", "9103")),
    "vuln": int(os.getenv("PENTRA_WORKER_VULN_HEALTH_PORT", "9104")),
    "exploit": int(os.getenv("PENTRA_WORKER_EXPLOIT_HEALTH_PORT", "9105")),
}


async def _assert_http_ok(client: httpx.AsyncClient, url: str, label: str) -> None:
    response = await client.get(url, follow_redirects=True)
    response.raise_for_status()
    print(f"[ok] {label}: {response.status_code}")


def _run_script(path: Path) -> None:
    print(f"[run] {path.relative_to(ROOT_DIR)}")
    env = dict(os.environ)
    subprocess.run(
        [sys.executable, str(path)],
        cwd=str(ROOT_DIR),
        env=env,
        check=True,
    )
    print(f"[ok] {path.name}")


async def main() -> int:
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            await _assert_http_ok(client, f"{FRONTEND_BASE_URL}/", "frontend")
            await _assert_http_ok(client, f"{API_BASE_URL}/health", "api health")
            await _assert_http_ok(client, f"{API_BASE_URL}/ready", "api readiness")
            await _assert_http_ok(client, f"{ORCH_BASE_URL}/health", "orchestrator health")
            await _assert_http_ok(client, f"{DEMO_TARGET_URL}/healthz", "demo target health")

            for family, port in WORKER_HEALTH_PORTS.items():
                await _assert_http_ok(
                    client,
                    f"http://127.0.0.1:{port}/health",
                    f"worker {family} health",
                )

        _run_script(ROOT_DIR / "pentra_core/scripts/local/smoke_phase3_live.py")
        _run_script(ROOT_DIR / "pentra_core/scripts/local/smoke_phase6_stateful.py")

        print("[done] Full-stack smoke passed: frontend, API, orchestrator, workers, Phase 3, Phase 6")
        return 0
    except subprocess.CalledProcessError as exc:
        print(f"[error] Smoke subprocess failed with exit code {exc.returncode}", file=sys.stderr)
        return exc.returncode
    except Exception as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
