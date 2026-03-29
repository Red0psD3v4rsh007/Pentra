"""Live local validation harness for Phase 10 P3A.5 against parser/upload benchmarks."""

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

from app.engine.web_interaction_runner import WebInteractionRunner

BENCHMARK_PATHS = [
    REPO_ROOT / "pentra_core" / "dev_targets" / "capability_benchmarks" / "repo_parser_upload_demo.json",
]
OUTPUT_DIR = REPO_ROOT / ".local" / "pentra" / "phase10"
OUTPUT_PATH = OUTPUT_DIR / "parser_file_benchmarks_live_latest.json"

_PARSER_EXPECTATION_TYPES = {
    "xxe",
    "insecure_deserialization",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_benchmark(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text())
    if not isinstance(payload, dict):
        raise RuntimeError(f"Benchmark manifest must be a JSON object: {path}")
    return payload


def _selected_paths(value: Any) -> list[str]:
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


def _resolve_scan_config(target_spec: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    plans = target_spec.get("scan_plans")
    if not isinstance(plans, list) or not plans or not isinstance(plans[0], dict):
        raise RuntimeError(f"Benchmark target '{target_spec.get('key')}' is missing a usable scan plan")
    plan = plans[0]
    scan_config = phase8.resolve_scan_plan_config(
        config_template=str(plan.get("config_template") or "default_external_web_api_v1"),
        config_overrides=plan.get("config_overrides") if isinstance(plan.get("config_overrides"), dict) else None,
    )
    return plan, scan_config


async def _probe(url: str) -> dict[str, Any]:
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


async def _wait_for_http(url: str, timeout_seconds: int) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last: dict[str, Any] = {"reachable": False, "status_code": None, "detail": "timeout"}
    while time.monotonic() < deadline:
        last = await _probe(url)
        if last.get("reachable"):
            return last
        await asyncio.sleep(1)
    return last


def _ensure_repo_local_target_process(target_spec: dict[str, Any]) -> dict[str, Any]:
    script_value = str(target_spec.get("repo_local_launch_script") or "").strip()
    if not script_value:
        return {"status": "skipped", "detail": "missing_repo_local_launch_script"}

    script_path = (REPO_ROOT / script_value).resolve()
    key = str(target_spec.get("key") or "repo_local_target").strip() or "repo_local_target"
    safe_key = key.replace("/", "-")
    log_path = OUTPUT_DIR / f"{safe_key}_target.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    command = [str(script_path)]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT) + (f":{env['PYTHONPATH']}" if env.get("PYTHONPATH") else "")
    with log_path.open("ab") as stream:
        process = subprocess.Popen(  # noqa: S603,S607
            command,
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


async def _ensure_target(target_spec: dict[str, Any]) -> dict[str, Any]:
    healthcheck_url = str(target_spec.get("healthcheck_url") or target_spec.get("target") or "").strip()
    preflight = await _probe(healthcheck_url)
    if preflight.get("reachable"):
        return {"status": "already_running", "health": preflight}

    launch_mode = str(target_spec.get("launch_mode") or "").strip()
    if launch_mode == "repo_local":
        launch = _ensure_repo_local_target_process(target_spec)
        health = await _wait_for_http(healthcheck_url, 45)
        return {"status": "ok" if health.get("reachable") else "launch_failed", "launch": launch, "health": health}

    return {"status": "unavailable", "health": preflight}


def _top_route_assessments(discovery: dict[str, Any], limit: int = 10) -> list[dict[str, Any]]:
    capability = discovery.get("parser_file_abuse_capability") or {}
    route_assessments = capability.get("route_assessments") or []
    if not isinstance(route_assessments, list):
        return []
    return [item for item in route_assessments if isinstance(item, dict)][:limit]


def _top_candidates(discovery: dict[str, Any], limit: int = 10) -> list[dict[str, Any]]:
    candidates = discovery.get("parser_file_candidates") or []
    if not isinstance(candidates, list):
        return []
    ranked = sorted(
        [item for item in candidates if isinstance(item, dict)],
        key=lambda item: (
            -int(str(item.get("vulnerability_type") or "").strip() == "xxe"),
            -int(item.get("confidence") or 0),
            str(item.get("route_group") or ""),
        ),
    )
    return ranked[:limit]


def _filter_parser_expectations(expectations: dict[str, Any]) -> list[str]:
    return [
        item
        for item in _selected_paths(expectations.get("expected_vulnerability_types"))
        if item in _PARSER_EXPECTATION_TYPES
    ]


def _evaluate_parser_file_assessment(
    *,
    target_spec: dict[str, Any],
    discovery: dict[str, Any],
) -> dict[str, Any]:
    expectations = target_spec.get("expectations") if isinstance(target_spec.get("expectations"), dict) else {}
    expected_types = set(_filter_parser_expectations(expectations))
    candidates = discovery.get("parser_file_candidates") or []
    detected_types = {
        str(item.get("vulnerability_type") or "").strip()
        for item in candidates
        if isinstance(item, dict) and str(item.get("vulnerability_type") or "").strip()
    }
    detected_expected = sorted(expected_types & detected_types)
    missed_expected = sorted(expected_types - detected_types)
    unexpected_detected = sorted(detected_types - expected_types)

    detected_recall = round(len(detected_expected) / len(expected_types), 3) if expected_types else None
    minimum_detected_recall = float(expectations.get("minimum_detected_recall", 0.0) or 0.0)
    capability = discovery.get("parser_file_abuse_capability") or {}
    route_counts = capability.get("route_assessment_counts") or {}
    negative_evidence_count = int(route_counts.get("negative_evidence_routes") or capability.get("negative_evidence_count") or 0)
    planner_hook_count = int(capability.get("planner_hook_count") or 0)
    candidate_count = int(capability.get("candidate_count") or len(candidates))

    return {
        "scope": "parser_file_only",
        "expected_vulnerability_types": sorted(expected_types),
        "detected_types": sorted(detected_types),
        "detected_expected_types": detected_expected,
        "missed_expected_types": missed_expected,
        "unexpected_detected_types": unexpected_detected,
        "detected_recall": detected_recall,
        "minimum_detected_recall": minimum_detected_recall,
        "meets_detected_recall": detected_recall is None or detected_recall >= minimum_detected_recall,
        "meets_target_bar": detected_recall is None or detected_recall >= minimum_detected_recall,
        "candidate_count": candidate_count,
        "planner_hook_count": planner_hook_count,
        "negative_evidence_count": negative_evidence_count,
    }


async def _validate_target(path: Path) -> dict[str, Any]:
    target_spec = _load_benchmark(path)
    plan, scan_config = _resolve_scan_config(target_spec)
    ensure_result = await _ensure_target(target_spec)
    health = ensure_result.get("health") if isinstance(ensure_result, dict) else {}
    if not isinstance(health, dict):
        health = {}

    target = str(target_spec.get("target") or "").strip()
    record: dict[str, Any] = {
        "captured_at": _utc_now(),
        "benchmark_key": str(target_spec.get("key") or ""),
        "manifest_path": str(path.relative_to(REPO_ROOT)),
        "target": target,
        "healthcheck_url": str(target_spec.get("healthcheck_url") or ""),
        "launch_mode": str(target_spec.get("launch_mode") or ""),
        "launch_result": ensure_result,
        "scan_plan_key": str(plan.get("key") or ""),
        "scan_plan_label": str(plan.get("label") or ""),
        "config_template": str(plan.get("config_template") or ""),
        "seed_paths": _selected_paths(
            ((scan_config.get("stateful_testing") or {}).get("seed_paths") or [])
        ),
    }

    if not health.get("reachable"):
        record["status"] = "unavailable"
        record["detail"] = "Target health check failed after launch attempt."
        return record

    runner = WebInteractionRunner()
    discovery = await runner.run_discovery(base_url=target, scan_config=scan_config)
    assessment = _evaluate_parser_file_assessment(target_spec=target_spec, discovery=discovery)
    capability = discovery.get("parser_file_abuse_capability") or {}

    record.update(
        {
            "status": "passed" if assessment.get("meets_target_bar") else "failed",
            "detail": "" if assessment.get("meets_target_bar") else "Parser/file capability did not meet the benchmark recall bar.",
            "expectations": target_spec.get("expectations") or {},
            "parser_file_assessment": assessment,
            "summary": discovery.get("summary") or {},
            "parser_file_abuse_capability": capability,
            "top_route_assessments": _top_route_assessments(discovery),
            "top_candidates": _top_candidates(discovery),
            "probe_findings": discovery.get("probe_findings") or [],
        }
    )
    return record


async def main() -> int:
    results = [await _validate_target(path) for path in BENCHMARK_PATHS]
    payload = {
        "captured_at": _utc_now(),
        "target_count": len(results),
        "results": results,
        "summary": {
            "passed_targets": sum(1 for item in results if item.get("status") == "passed"),
            "failed_targets": sum(1 for item in results if item.get("status") == "failed"),
            "unavailable_targets": sum(1 for item in results if item.get("status") == "unavailable"),
        },
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(payload, indent=2))
    for item in results:
        target_key = str(item.get("benchmark_key") or "unknown")
        per_target_path = OUTPUT_DIR / f"{target_key}_parser_file_live_latest.json"
        per_target_path.write_text(json.dumps(item, indent=2))

    print(str(OUTPUT_PATH))
    print(
        json.dumps(
            {
                "summary": payload["summary"],
                "targets": [
                    {
                        "key": item.get("benchmark_key"),
                        "status": item.get("status"),
                        "detail": item.get("detail"),
                        "detected_recall": ((item.get("parser_file_assessment") or {}).get("detected_recall")),
                    }
                    for item in results
                ],
            },
            indent=2,
        )
    )
    return 0 if all(item.get("status") == "passed" for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
