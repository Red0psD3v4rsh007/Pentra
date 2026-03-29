"""Phase 8 capability benchmark harness.

Measures Pentra against explicit benchmark ground truth instead of only timing
and orchestration health.
"""

from __future__ import annotations

import asyncio
from copy import deepcopy
import json
import os
from pathlib import Path
import sys
from typing import Any

import httpx

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
    from proof_contract import new_run_id, stamp_proof_payload
else:
    from .proof_contract import new_run_id, stamp_proof_payload

ROOT_DIR = Path(__file__).resolve().parents[3]
API_BASE_URL = os.getenv("PENTRA_API_BASE_URL", "http://127.0.0.1:8000")
BENCHMARK_PROJECT_ID = os.getenv(
    "PENTRA_BENCHMARK_PROJECT_ID",
    "33333333-3333-3333-3333-333333333333",
)
STATEFUL_FULL_CONFIG: dict[str, Any] = {
    "profile_id": "external_web_api_v1",
    "selected_checks": {
        "authenticated_crawling": True,
        "workflow_replay": True,
        "stateful_testing": True,
    },
    "stateful_testing": {
        "enabled": True,
        "crawl_max_depth": 2,
        "max_pages": 20,
        "max_replays": 4,
        "seed_paths": ["/", "/login"],
        "default_csrf_token": "pentra-safe",
        "auth": {
            "login_page_path": "/login",
            "username_field": "username",
            "password_field": "password",
            "success_path_contains": "/dashboard",
            "credentials": [],
        },
    },
}


MANIFEST_PATH = (
    ROOT_DIR
    / "pentra_core"
    / "dev_targets"
    / "capability_benchmarks"
    / "phase8_target_matrix.json"
)
OUTPUT_DIR = ROOT_DIR / ".local" / "pentra" / "phase8"
OUTPUT_PATH = OUTPUT_DIR / "capability_matrix_latest.json"
PROOF_RUN_ID = new_run_id()


def _runtime_helpers() -> dict[str, Any]:
    scripts_dir = Path(__file__).resolve().parent
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))

    if __package__ in {None, ""}:
        from run_phase6_benchmark_matrix import (
            _collect_scan_bundle,
            _create_asset,
            _create_scan,
            _fetch_worker_health_snapshot,
            _list_project_assets,
            _summarize_run,
        )
    else:
        try:
            from .run_phase6_benchmark_matrix import (
                _collect_scan_bundle,
                _create_asset,
                _create_scan,
                _fetch_worker_health_snapshot,
                _list_project_assets,
                _summarize_run,
            )
        except ModuleNotFoundError:
            from run_phase6_benchmark_matrix import (
                _collect_scan_bundle,
                _create_asset,
                _create_scan,
                _fetch_worker_health_snapshot,
                _list_project_assets,
                _summarize_run,
            )

    return {
        "_collect_scan_bundle": _collect_scan_bundle,
        "_create_asset": _create_asset,
        "_create_scan": _create_scan,
        "_fetch_worker_health_snapshot": _fetch_worker_health_snapshot,
        "_list_project_assets": _list_project_assets,
        "_summarize_run": _summarize_run,
    }


def _load_manifest(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text())
    if not isinstance(payload, dict):
        raise RuntimeError(f"Manifest must be a JSON object: {path}")
    targets = payload.get("targets")
    if not isinstance(targets, list):
        raise RuntimeError(f"Manifest targets must be a list: {path}")
    return payload


def _deep_merge(base: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    merged = deepcopy(base)
    for key, value in overrides.items():
        current = merged.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            merged[key] = _deep_merge(current, value)
        else:
            merged[key] = deepcopy(value)
    return merged


def resolve_scan_plan_config(
    *,
    config_template: str,
    config_overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    templates = {
        "default_external_web_api_v1": {"profile_id": "external_web_api_v1"},
        "stateful_full": deepcopy(STATEFUL_FULL_CONFIG),
    }
    if config_template not in templates:
        raise ValueError(f"Unsupported config template: {config_template}")
    base = deepcopy(templates[config_template])
    if not config_overrides:
        return base
    return _deep_merge(base, config_overrides)


def evaluate_capability_assessment(
    *,
    findings: list[dict[str, Any]],
    expectations: dict[str, Any],
) -> dict[str, Any]:
    expected_types = {
        str(item).strip()
        for item in expectations.get("expected_vulnerability_types", [])
        if str(item).strip()
    }
    expected_verified_types = {
        str(item).strip()
        for item in expectations.get("expected_verified_types", [])
        if str(item).strip()
    }
    detected_types = {
        str(item.get("vulnerability_type") or "unclassified").strip()
        for item in findings
        if str(item.get("vulnerability_type") or "").strip()
    }
    verified_types = {
        str(item.get("vulnerability_type") or "unclassified").strip()
        for item in findings
        if str(item.get("vulnerability_type") or "").strip()
        and str(item.get("verification_state") or "detected").strip() == "verified"
    }

    detected_expected = sorted(expected_types & detected_types)
    missed_expected = sorted(expected_types - detected_types)
    unexpected_detected = sorted(detected_types - expected_types)

    verified_expected = sorted(expected_verified_types & verified_types)
    missed_verified = sorted(expected_verified_types - verified_types)

    detected_recall = (
        round(len(detected_expected) / len(expected_types), 3)
        if expected_types
        else None
    )
    verified_recall = (
        round(len(verified_expected) / len(expected_verified_types), 3)
        if expected_verified_types
        else None
    )

    total_findings = len(findings)
    verified_count = len(
        [
            item
            for item in findings
            if str(item.get("verification_state") or "detected").strip() == "verified"
        ]
    )
    verified_share = round(verified_count / total_findings, 3) if total_findings else 0.0

    minimum_detected_recall = float(expectations.get("minimum_detected_recall", 0.0) or 0.0)
    minimum_verified_recall = float(expectations.get("minimum_verified_recall", 0.0) or 0.0)
    minimum_verified_share = float(expectations.get("minimum_verified_share", 0.0) or 0.0)

    meets_detected_recall = detected_recall is None or detected_recall >= minimum_detected_recall
    meets_verified_recall = verified_recall is None or verified_recall >= minimum_verified_recall
    meets_verified_share = verified_share >= minimum_verified_share

    return {
        "expected_vulnerability_types": sorted(expected_types),
        "expected_verified_types": sorted(expected_verified_types),
        "detected_types": sorted(detected_types),
        "verified_types": sorted(verified_types),
        "detected_expected_types": detected_expected,
        "missed_expected_types": missed_expected,
        "unexpected_detected_types": unexpected_detected,
        "verified_expected_types": verified_expected,
        "missed_verified_types": missed_verified,
        "detected_recall": detected_recall,
        "verified_recall": verified_recall,
        "verified_share": verified_share,
        "minimum_detected_recall": minimum_detected_recall,
        "minimum_verified_recall": minimum_verified_recall,
        "minimum_verified_share": minimum_verified_share,
        "meets_detected_recall": meets_detected_recall,
        "meets_verified_recall": meets_verified_recall,
        "meets_verified_share": meets_verified_share,
        "meets_target_bar": (
            meets_detected_recall
            and meets_verified_recall
            and meets_verified_share
        ),
    }


async def _probe_target(client: httpx.AsyncClient, url: str) -> dict[str, Any]:
    try:
        response = await client.get(url, follow_redirects=True)
    except Exception as exc:  # pragma: no cover - exercised in live runs
        return {
            "reachable": False,
            "status_code": None,
            "detail": str(exc),
        }
    return {
        "reachable": response.status_code < 500,
        "status_code": response.status_code,
        "detail": response.text[:200],
    }


async def _ensure_named_asset(
    client: httpx.AsyncClient,
    *,
    project_id: str,
    target_spec: dict[str, Any],
) -> dict[str, Any]:
    helpers = _runtime_helpers()
    assets = await helpers["_list_project_assets"](client, project_id)
    asset_name = str(target_spec["asset_name"])
    existing = next((asset for asset in assets if str(asset.get("name")) == asset_name), None)
    if existing is not None:
        return existing
    return await helpers["_create_asset"](
        client,
        project_id=project_id,
        spec=type(
            "CapabilityAssetSpec",
            (),
            {
                "name": asset_name,
                "asset_type": str(target_spec["asset_type"]),
                "target": str(target_spec["target"]),
                "description": f"Phase 8 capability benchmark target: {target_spec['key']}",
            },
        )(),
    )


async def _run_scan_plan(
    client: httpx.AsyncClient,
    *,
    asset_id: str,
    target_spec: dict[str, Any],
    plan: dict[str, Any],
) -> dict[str, Any]:
    helpers = _runtime_helpers()
    worker_before = await helpers["_fetch_worker_health_snapshot"](client)
    resolved_config = resolve_scan_plan_config(
        config_template=str(plan["config_template"]),
        config_overrides=plan.get("config_overrides"),
    )
    scan = await helpers["_create_scan"](
        client,
        asset_id=asset_id,
        scan_type=str(plan["scan_type"]),
        config=resolved_config,
    )
    bundle = await helpers["_collect_scan_bundle"](
        client,
        scenario=type(
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
        )(),
        scan_id=str(scan["id"]),
    )
    worker_after = await helpers["_fetch_worker_health_snapshot"](client)
    run_summary = helpers["_summarize_run"](
        scenario=type(
            "CapabilityScenario",
            (),
            {
                "key": str(plan["key"]),
                "label": str(plan["label"]),
                "mode": "capability",
                "scan_type": str(plan["scan_type"]),
                "config": resolved_config,
            },
        )(),
        scan=bundle["scan"],
        jobs=bundle["jobs"],
        findings=bundle["findings"],
        artifacts=bundle["artifacts"],
        attack_graph=bundle["attack_graph"],
        worker_before=worker_before,
        worker_after=worker_after,
    )
    run_summary["capability_assessment"] = evaluate_capability_assessment(
        findings=bundle["findings"],
        expectations=target_spec.get("expectations") or {},
    )
    return run_summary


async def run_capability_matrix(
    *,
    manifest_path: Path = MANIFEST_PATH,
) -> dict[str, Any]:
    manifest = _load_manifest(manifest_path)
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
                "target": str(target_spec.get("target") or ""),
                "ground_truth_source": str(target_spec.get("ground_truth_source") or ""),
                "notes": str(target_spec.get("notes") or ""),
            }
            if not enabled:
                target_record["status"] = "planned"
                target_record["detail"] = "Target remains disabled until launch recipe and ground truth are committed."
                results.append(target_record)
                continue

            availability = await _probe_target(client, str(target_spec["healthcheck_url"]))
            target_record["availability"] = availability
            if not availability["reachable"]:
                target_record["status"] = "unavailable"
                target_record["detail"] = "Health check failed for enabled target."
                results.append(target_record)
                continue

            asset = await _ensure_named_asset(
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
                    await _run_scan_plan(
                        client,
                        asset_id=str(asset["id"]),
                        target_spec=target_spec,
                        plan=plan,
                    )
                )

            target_record["scan_runs"] = scan_runs
            target_record["status"] = (
                "passed"
                if scan_runs
                and all(
                    run.get("status") == "completed"
                    and (run.get("capability_assessment") or {}).get("meets_target_bar") is True
                    for run in scan_runs
                )
                else "failed"
            )
            results.append(target_record)

    enabled_targets = [item for item in results if item.get("enabled") is True]
    executed_targets = [
        item for item in enabled_targets if item.get("status") in {"passed", "failed"}
    ]
    passed_targets = [item for item in executed_targets if item.get("status") == "passed"]
    planned_targets = [item for item in results if item.get("status") == "planned"]
    unavailable_targets = [item for item in results if item.get("status") == "unavailable"]

    payload = {
        "status": (
            "passed"
            if executed_targets
            and len(passed_targets) == len(executed_targets)
            and not unavailable_targets
            else "failed"
        ),
        "phase": "P8.1",
        "manifest_path": str(manifest_path),
        "api_base_url": API_BASE_URL,
        "project_id": project_id,
        "summary": {
            "total_targets": len(results),
            "enabled_targets": len(enabled_targets),
            "planned_targets": len(planned_targets),
            "executed_targets": len(executed_targets),
            "passed_targets": len(passed_targets),
            "unavailable_targets": len(unavailable_targets),
        },
        "targets": results,
    }
    stamped = stamp_proof_payload(
        payload,
        artifact_kind="capability_matrix",
        phase="P8.1",
        script_path="pentra_core/scripts/local/run_phase8_capability_matrix.py",
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
