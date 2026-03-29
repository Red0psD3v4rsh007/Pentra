"""Shared helpers for Phase 10 local capability benchmark validators."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any

import httpx


REPO_ROOT = Path(__file__).resolve().parents[3]
PACKAGES_DIR = REPO_ROOT / "pentra_core" / "packages" / "pentra-common"
WORKER_APP_ROOT = REPO_ROOT / "pentra_core" / "services" / "worker-svc"
if str(PACKAGES_DIR) not in sys.path:
    sys.path.insert(0, str(PACKAGES_DIR))
if str(WORKER_APP_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKER_APP_ROOT))

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import run_phase8_capability_matrix as phase8
else:
    from . import run_phase8_capability_matrix as phase8


OUTPUT_DIR = REPO_ROOT / ".local" / "pentra" / "phase10"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_benchmark(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text())
    if not isinstance(payload, dict):
        raise RuntimeError(f"Benchmark manifest must be a JSON object: {path}")
    return payload


def selected_paths(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    items: list[str] = []
    seen: set[str] = set()
    for item in value:
        text = str(item).strip()
        key = text.lower()
        if not text or key in seen:
            continue
        seen.add(key)
        items.append(text)
    return items


def resolve_scan_config(target_spec: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    plans = target_spec.get("scan_plans")
    if not isinstance(plans, list) or not plans or not isinstance(plans[0], dict):
        raise RuntimeError(f"Benchmark target '{target_spec.get('key')}' is missing a usable scan plan")
    plan = plans[0]
    scan_config = phase8.resolve_scan_plan_config(
        config_template=str(plan.get("config_template") or "default_external_web_api_v1"),
        config_overrides=plan.get("config_overrides") if isinstance(plan.get("config_overrides"), dict) else None,
    )
    return plan, scan_config


async def probe(url: str) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
        try:
            response = await client.get(url)
        except Exception as exc:  # pragma: no cover - live runtime dependent
            return {"reachable": False, "status_code": None, "detail": str(exc)}
    return {
        "reachable": response.status_code < 500,
        "status_code": response.status_code,
        "detail": response.text[:200],
    }


async def wait_for_http(url: str, timeout_seconds: int) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last: dict[str, Any] = {"reachable": False, "status_code": None, "detail": "timeout"}
    while time.monotonic() < deadline:
        last = await probe(url)
        if last.get("reachable"):
            return last
        await asyncio.sleep(1)
    return last


def run_launch_recipe(target_spec: dict[str, Any]) -> dict[str, Any]:
    recipe = target_spec.get("launch_recipe")
    if not isinstance(recipe, dict):
        return {"status": "skipped", "detail": "no_launch_recipe"}

    script_value = str(recipe.get("script") or "").strip()
    if not script_value:
        return {"status": "skipped", "detail": "missing_script"}

    script_path = (REPO_ROOT / script_value).resolve()
    args = [str(item) for item in recipe.get("args", []) if str(item).strip()]
    completed = subprocess.run(
        ["bash", str(script_path), *args],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    output = (completed.stdout or completed.stderr or "").strip()
    return {
        "status": "ok" if completed.returncode == 0 else "failed",
        "returncode": completed.returncode,
        "detail": output[-1000:],
        "script": script_value,
        "args": args,
    }


def ensure_repo_local_target_process(target_spec: dict[str, Any]) -> dict[str, Any]:
    script_value = str(target_spec.get("repo_local_launch_script") or "").strip()
    if not script_value:
        return {"status": "skipped", "detail": "missing_repo_local_launch_script"}

    script_path = (REPO_ROOT / script_value).resolve()
    key = str(target_spec.get("key") or "repo_local_target").strip() or "repo_local_target"
    safe_key = key.replace("/", "-")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    log_path = OUTPUT_DIR / f"{safe_key}_target.log"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT) + (f":{env['PYTHONPATH']}" if env.get("PYTHONPATH") else "")
    with log_path.open("ab") as stream:
        process = subprocess.Popen(  # noqa: S603,S607
            [str(script_path)],
            cwd=REPO_ROOT,
            stdout=stream,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            env=env,
        )
    return {
        "status": "started",
        "pid": process.pid,
        "detail": f"spawned {script_value}",
        "script": script_value,
        "log_path": str(log_path),
    }


async def ensure_target(target_spec: dict[str, Any]) -> dict[str, Any]:
    target_key = str(target_spec.get("key") or "")
    healthcheck_url = str(target_spec.get("healthcheck_url") or target_spec.get("target") or "").strip()
    launch_mode = str(target_spec.get("launch_mode") or "").strip()

    preflight = await probe(healthcheck_url)
    if preflight.get("reachable"):
        return {"status": "already_running", "health": preflight}

    if launch_mode == "docker_script":
        launch = run_launch_recipe(target_spec)
        if launch.get("status") != "ok":
            return {"status": "launch_failed", "launch": launch, "health": preflight}
        health = await wait_for_http(healthcheck_url, 180)
        return {"status": "ok" if health.get("reachable") else "launch_failed", "launch": launch, "health": health}

    if target_key == "repo_demo_api" or launch_mode == "repo_local":
        launch = ensure_repo_local_target_process(target_spec)
        health = await wait_for_http(healthcheck_url, 45)
        return {"status": "ok" if health.get("reachable") else "launch_failed", "launch": launch, "health": health}

    return {"status": "unavailable", "health": preflight}
