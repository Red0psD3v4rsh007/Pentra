"""Phase 9 capability benchmark harness.

Extends the capability benchmark program beyond the repo demo target by
launching pinned harder benchmark apps from committed per-target manifests and
scoring Pentra against an explicit expectation subset for each target.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any

import httpx

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
    from proof_contract import new_run_id, stamp_proof_payload
    import run_phase8_capability_matrix as phase8
else:
    from .proof_contract import new_run_id, stamp_proof_payload
    from . import run_phase8_capability_matrix as phase8

ROOT_DIR = Path(__file__).resolve().parents[3]
MANIFEST_PATH = (
    Path(os.getenv("PENTRA_PHASE9_TARGET_MATRIX_PATH", "")).resolve()
    if os.getenv("PENTRA_PHASE9_TARGET_MATRIX_PATH", "").strip()
    else (
        ROOT_DIR
        / "pentra_core"
        / "dev_targets"
        / "capability_benchmarks"
        / "phase9_target_matrix.json"
    )
)
OUTPUT_DIR = ROOT_DIR / ".local" / "pentra" / "phase9"
OUTPUT_PATH = OUTPUT_DIR / "capability_matrix_latest.json"
PROOF_RUN_ID = new_run_id()
POLL_INTERVAL_SECONDS = float(os.getenv("PENTRA_PHASE9_POLL_INTERVAL_SECONDS", "1"))
TIMEOUT_GRACE_SECONDS = int(os.getenv("PENTRA_PHASE9_TIMEOUT_GRACE_SECONDS", "180"))

API_BASE_URL = os.getenv("PENTRA_API_BASE_URL", "http://127.0.0.1:8000")
BENCHMARK_PROJECT_ID = os.getenv(
    "PENTRA_BENCHMARK_PROJECT_ID",
    "33333333-3333-3333-3333-333333333333",
)


def _load_json_file(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text())
    if not isinstance(payload, dict):
        raise RuntimeError(f"Manifest must be a JSON object: {path}")
    return payload


def _resolve_manifest_entry(base_path: Path, raw_path: str) -> Path:
    candidate = Path(raw_path)
    if candidate.is_absolute():
        return candidate
    repo_candidate = ROOT_DIR / candidate
    if repo_candidate.exists():
        return repo_candidate
    return (base_path.parent / candidate).resolve()


async def _fetch_json(client: httpx.AsyncClient, url: str) -> Any:
    response = await client.get(url)
    response.raise_for_status()
    return response.json()


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


async def _wait_for_target_available(
    client: httpx.AsyncClient,
    *,
    url: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last = {"reachable": False, "status_code": None, "detail": "timeout"}
    while time.monotonic() < deadline:
        last = await phase8._probe_target(client, url)
        if last["reachable"]:
            return last
        await asyncio.sleep(POLL_INTERVAL_SECONDS)
    return last


def _is_terminal_scan_status(status: str) -> bool:
    return status in {"completed", "failed", "rejected", "cancelled"}


async def _wait_for_scan_terminal_grace(
    client: httpx.AsyncClient,
    *,
    scan_id: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        payload = await _get_scan(client, scan_id)
        print(f"[grace] scan={scan_id} status={payload['status']} progress={payload['progress']}%")
        if _is_terminal_scan_status(str(payload.get("status") or "")):
            return payload
        await asyncio.sleep(POLL_INTERVAL_SECONDS)
    raise RuntimeError(
        f"Scan {scan_id} did not reach a terminal state after {timeout_seconds}s grace"
    )


def load_phase9_manifest(path: Path) -> dict[str, Any]:
    payload = _load_json_file(path)
    targets: list[dict[str, Any]] = []

    direct_targets = payload.get("targets")
    if isinstance(direct_targets, list):
        for item in direct_targets:
            if isinstance(item, dict):
                targets.append(dict(item))

    target_manifest_paths = payload.get("target_manifests")
    if isinstance(target_manifest_paths, list):
        for item in target_manifest_paths:
            target_path = _resolve_manifest_entry(path, str(item))
            target_payload = _load_json_file(target_path)
            if not isinstance(target_payload, dict):
                raise RuntimeError(f"Target manifest must be a JSON object: {target_path}")
            target_record = dict(target_payload)
            target_record.setdefault("ground_truth_source", str(target_path.relative_to(ROOT_DIR)))
            target_record["manifest_path"] = str(target_path)
            targets.append(target_record)

    if not targets:
        raise RuntimeError(f"Phase 9 target manifest did not resolve any targets: {path}")

    normalized = dict(payload)
    normalized["targets"] = targets
    return normalized


def _run_launch_recipe(target_spec: dict[str, Any]) -> dict[str, Any]:
    recipe = target_spec.get("launch_recipe")
    if not isinstance(recipe, dict):
        return {"status": "skipped", "detail": "no_launch_recipe"}

    script_value = str(recipe.get("script") or "").strip()
    if not script_value:
        return {"status": "skipped", "detail": "missing_script"}

    script_path = (ROOT_DIR / script_value).resolve()
    args = [str(item) for item in recipe.get("args", []) if str(item).strip()]
    completed = subprocess.run(
        ["bash", str(script_path), *args],
        cwd=ROOT_DIR,
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


def _ensure_repo_local_target_process(target_spec: dict[str, Any]) -> dict[str, Any]:
    script_value = str(target_spec.get("repo_local_launch_script") or "").strip()
    if not script_value:
        return {"status": "skipped", "detail": "missing_repo_local_launch_script"}

    script_path = (ROOT_DIR / script_value).resolve()
    key = str(target_spec.get("key") or "repo_local_target").strip() or "repo_local_target"
    safe_key = key.replace("/", "-")
    log_dir = ROOT_DIR / ".local" / "pentra" / "phase9"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"{safe_key}_target.log"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT_DIR) + (f":{env['PYTHONPATH']}" if env.get("PYTHONPATH") else "")
    command = [str(script_path)]
    with log_path.open("ab") as stream:
        process = subprocess.Popen(  # noqa: S603,S607
            command,
            cwd=ROOT_DIR,
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


def summarize_phase9_targets(results: list[dict[str, Any]]) -> dict[str, Any]:
    enabled_targets = [item for item in results if item.get("enabled") is True]
    executed_targets = [
        item for item in enabled_targets if item.get("status") in {"passed", "failed"}
    ]
    partial_targets = [item for item in enabled_targets if item.get("status") == "partial"]
    passed_targets = [item for item in executed_targets if item.get("status") == "passed"]
    failed_targets = [item for item in executed_targets if item.get("status") == "failed"]
    planned_targets = [item for item in results if item.get("status") == "planned"]
    unavailable_targets = [item for item in results if item.get("status") == "unavailable"]
    launch_failed_targets = [item for item in results if item.get("status") == "launch_failed"]
    non_demo_executed_targets = [
        item
        for item in executed_targets
        if str(item.get("key") or "") != "repo_demo_api"
    ]

    artifact_passed = (
        len(non_demo_executed_targets) >= 3
        and not unavailable_targets
        and not launch_failed_targets
        and not partial_targets
    )
    artifact_status = "passed" if artifact_passed else "partial" if partial_targets else "failed"
    return {
        "status": artifact_status,
        "summary": {
            "total_targets": len(results),
            "enabled_targets": len(enabled_targets),
            "planned_targets": len(planned_targets),
            "executed_targets": len(executed_targets),
            "non_demo_executed_targets": len(non_demo_executed_targets),
            "partial_targets": len(partial_targets),
            "passed_targets": len(passed_targets),
            "failed_targets": len(failed_targets),
            "unavailable_targets": len(unavailable_targets),
            "launch_failed_targets": len(launch_failed_targets),
        },
    }


def derive_phase9_target_status(scan_runs: list[dict[str, Any]]) -> tuple[str, str]:
    if not scan_runs:
        return ("failed", "No scan runs were executed for the enabled target.")

    first_error = next(
        (
            str(run.get("error"))
            for run in scan_runs
            if str(run.get("error") or "").strip()
        ),
        "",
    )

    if any(
        bool(run.get("partial"))
        or not _is_terminal_scan_status(str(run.get("status") or ""))
        for run in scan_runs
    ):
        detail = first_error or (
            "One or more scan plans did not reach a terminal state, so this benchmark"
            " result is incomplete."
        )
        return ("partial", detail)

    passed = all(
        run.get("status") == "completed"
        and (run.get("capability_assessment") or {}).get("meets_target_bar") is True
        for run in scan_runs
    )
    if passed:
        return ("passed", "")

    detail = first_error or "Completed scan plans did not meet the target capability bar."
    return ("failed", detail)


def _capability_scenario(plan: dict[str, Any], resolved_config: dict[str, Any]) -> Any:
    return type(
        "CapabilityScenario",
        (),
        {
            "key": str(plan["key"]),
            "label": str(plan["label"]),
            "mode": "capability",
            "scan_type": str(plan["scan_type"]),
            "config": resolved_config,
            "iterations": 1,
            "timeout_seconds": int(plan.get("timeout_seconds", 240)),
        },
    )()


async def _run_scan_plan_safe(
    client: httpx.AsyncClient,
    *,
    asset_id: str,
    target_spec: dict[str, Any],
    plan: dict[str, Any],
) -> dict[str, Any]:
    helpers = phase8._runtime_helpers()
    worker_before = await helpers["_fetch_worker_health_snapshot"](client)
    resolved_config = phase8.resolve_scan_plan_config(
        config_template=str(plan["config_template"]),
        config_overrides=plan.get("config_overrides"),
    )
    scenario = _capability_scenario(plan, resolved_config)
    scan = await helpers["_create_scan"](
        client,
        asset_id=asset_id,
        scan_type=str(plan["scan_type"]),
        config=resolved_config,
    )
    scan_id = str(scan["id"])

    error_message: str | None = None
    partial = False
    grace_extended = False
    try:
        bundle = await helpers["_collect_scan_bundle"](
            client,
            scenario=scenario,
            scan_id=scan_id,
        )
        terminal_scan = bundle["scan"]
        jobs = bundle["jobs"]
        findings = bundle["findings"]
        artifacts = bundle["artifacts"]
        attack_graph = bundle["attack_graph"]
    except Exception as exc:
        partial = True
        error_message = str(exc)
        terminal_scan = await _get_scan(client, scan_id)
        if (
            "did not reach a terminal state in time" in error_message
            and TIMEOUT_GRACE_SECONDS > 0
            and not _is_terminal_scan_status(str(terminal_scan.get("status") or ""))
        ):
            print(f"[grace] extending scan {scan_id} by {TIMEOUT_GRACE_SECONDS}s")
            try:
                terminal_scan = await _wait_for_scan_terminal_grace(
                    client,
                    scan_id=scan_id,
                    timeout_seconds=TIMEOUT_GRACE_SECONDS,
                )
                partial = False
                error_message = None
                grace_extended = True
            except Exception as grace_exc:
                error_message = str(grace_exc)
        jobs = await _get_scan_jobs(client, scan_id)
        findings = await _get_findings(client, scan_id)
        artifacts = await _get_artifacts(client, scan_id)
        attack_graph = await _get_attack_graph(client, scan_id)

    worker_after = await helpers["_fetch_worker_health_snapshot"](client)
    run_summary = helpers["_summarize_run"](
        scenario=scenario,
        scan=terminal_scan,
        jobs=jobs,
        findings=findings,
        artifacts=artifacts,
        attack_graph=attack_graph,
        worker_before=worker_before,
        worker_after=worker_after,
    )
    run_summary["capability_assessment"] = phase8.evaluate_capability_assessment(
        findings=findings,
        expectations=target_spec.get("expectations") or {},
    )
    if grace_extended:
        run_summary["grace_extended"] = True
    if partial:
        run_summary["partial"] = True
        run_summary["error"] = error_message
        run_summary["timed_out"] = "did not reach a terminal state in time" in str(
            error_message or ""
        )
    return run_summary


async def run_capability_matrix(
    *,
    manifest_path: Path = MANIFEST_PATH,
) -> dict[str, Any]:
    manifest = load_phase9_manifest(manifest_path)
    project_id = str(manifest.get("project_id") or BENCHMARK_PROJECT_ID)

    results: list[dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=30.0, trust_env=False) as client:
        for target_spec in manifest["targets"]:
            if not isinstance(target_spec, dict):
                continue
            enabled = bool(target_spec.get("enabled"))
            target_record = {
                "key": str(target_spec.get("key") or "unknown"),
                "name": str(target_spec.get("asset_name") or "unknown"),
                "enabled": enabled,
                "launch_mode": str(target_spec.get("launch_mode") or "unknown"),
                "manifest_path": str(target_spec.get("manifest_path") or ""),
                "target": str(target_spec.get("target") or ""),
                "ground_truth_source": str(target_spec.get("ground_truth_source") or ""),
                "notes": str(target_spec.get("notes") or ""),
            }
            if not enabled:
                target_record["status"] = "planned"
                target_record["detail"] = "Target remains disabled until its launch recipe and expectation subset are ready."
                results.append(target_record)
                continue

            launch_mode = str(target_spec.get("launch_mode") or "").strip()
            if launch_mode == "repo_local":
                availability = await phase8._probe_target(client, str(target_spec["healthcheck_url"]))
                if availability["reachable"]:
                    launch_result = {"status": "already_running", "detail": "repo_local target already reachable"}
                else:
                    launch_result = await asyncio.to_thread(_ensure_repo_local_target_process, target_spec)
                target_record["launch_result"] = launch_result
                availability = await _wait_for_target_available(
                    client,
                    url=str(target_spec["healthcheck_url"]),
                    timeout_seconds=45,
                )
                target_record["availability"] = availability
                if not availability["reachable"]:
                    target_record["status"] = "unavailable"
                    target_record["detail"] = "Health check failed for enabled target."
                    results.append(target_record)
                    continue
            else:
                launch_result = await asyncio.to_thread(_run_launch_recipe, target_spec)
                target_record["launch_result"] = launch_result
                if launch_result.get("status") == "failed":
                    target_record["status"] = "launch_failed"
                    target_record["detail"] = "Launch recipe failed before benchmark execution."
                    results.append(target_record)
                    continue

                availability = await phase8._probe_target(client, str(target_spec["healthcheck_url"]))
                target_record["availability"] = availability
                if not availability["reachable"]:
                    target_record["status"] = "unavailable"
                    target_record["detail"] = "Health check failed for enabled target."
                    results.append(target_record)
                    continue

            asset = await phase8._ensure_named_asset(
                client,
                project_id=project_id,
                target_spec=target_spec,
            )
            target_record["asset_id"] = str(asset["id"])

            scan_runs: list[dict[str, Any]] = []
            for plan in target_spec.get("scan_plans", []):
                if not isinstance(plan, dict):
                    continue
                scan_runs.append(
                    await _run_scan_plan_safe(
                        client,
                        asset_id=str(asset["id"]),
                        target_spec=target_spec,
                        plan=plan,
                    )
                )

            target_record["scan_runs"] = scan_runs
            target_status, detail = derive_phase9_target_status(scan_runs)
            target_record["status"] = target_status
            if detail:
                target_record["detail"] = detail
            results.append(target_record)

    summary = summarize_phase9_targets(results)
    payload = {
        "status": summary["status"],
        "phase": "P9.3",
        "manifest_path": str(manifest_path),
        "api_base_url": API_BASE_URL,
        "project_id": project_id,
        "summary": summary["summary"],
        "targets": results,
    }
    stamped = stamp_proof_payload(
        payload,
        artifact_kind="capability_matrix",
        phase="P9.3",
        script_path="pentra_core/scripts/local/run_phase9_capability_matrix.py",
        root_dir=ROOT_DIR,
        environment_context={
            "api_base_url": API_BASE_URL,
            "manifest_path": str(manifest_path),
            "project_id": project_id,
        },
        run_id=PROOF_RUN_ID,
    )
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(stamped, indent=2, sort_keys=True))
    return stamped


def main() -> None:
    payload = asyncio.run(run_capability_matrix())
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
