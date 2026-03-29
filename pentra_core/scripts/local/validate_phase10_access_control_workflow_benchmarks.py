"""Live local validation harness for Phase 10 P3A.3 against benchmark targets."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]
PACKAGES_DIR = REPO_ROOT / "pentra_core" / "packages" / "pentra-common"
WORKER_APP_ROOT = REPO_ROOT / "pentra_core" / "services" / "worker-svc"
if str(PACKAGES_DIR) not in sys.path:
    sys.path.insert(0, str(PACKAGES_DIR))
if str(WORKER_APP_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKER_APP_ROOT))

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import phase10_live_benchmark_helpers as helpers
else:
    from . import phase10_live_benchmark_helpers as helpers

from app.engine.web_interaction_runner import WebInteractionRunner

BENCHMARK_PATHS = [
    REPO_ROOT / "pentra_core" / "dev_targets" / "capability_benchmarks" / "repo_demo_api.json",
]
OUTPUT_DIR = helpers.OUTPUT_DIR
OUTPUT_PATH = OUTPUT_DIR / "access_control_workflow_benchmarks_live_latest.json"

_ACCESS_EXPECTATION_TYPES = {
    "auth_bypass",
    "idor",
    "parameter_tampering",
    "privilege_escalation",
    "workflow_bypass",
}


def _top_route_assessments(discovery: dict[str, Any], limit: int = 10) -> list[dict[str, Any]]:
    capability = discovery.get("access_control_workflow_abuse_capability") or {}
    route_assessments = capability.get("route_assessments") or []
    if not isinstance(route_assessments, list):
        return []
    ranked = sorted(
        [item for item in route_assessments if isinstance(item, dict)],
        key=lambda item: (
            -int(item.get("advisory_priority") or 0),
            -int(item.get("risk_score") or 0),
            str(item.get("route_group") or ""),
        ),
    )
    return ranked[:limit]


def _top_candidates(discovery: dict[str, Any], limit: int = 10) -> list[dict[str, Any]]:
    candidates = discovery.get("access_control_candidates") or []
    if not isinstance(candidates, list):
        return []
    ranked = sorted(
        [item for item in candidates if isinstance(item, dict)],
        key=lambda item: (
            -int(item.get("confidence") or 0),
            -int(str(item.get("vulnerability_type") or "").strip() in {"privilege_escalation", "idor"}),
            str(item.get("route_group") or ""),
        ),
    )
    return ranked[:limit]


def _filter_access_expectations(target_spec: dict[str, Any]) -> list[str]:
    expectations = {}
    coverage = target_spec.get("pack_coverage_expectations")
    if isinstance(coverage, dict):
        expectations = coverage.get("p3a_access_control_workflow_abuse") if isinstance(coverage.get("p3a_access_control_workflow_abuse"), dict) else {}
    return [
        item
        for item in helpers.selected_paths(expectations.get("expected_vulnerability_types"))
        if item in _ACCESS_EXPECTATION_TYPES
    ]


def _evaluate_access_control_workflow_assessment(
    *,
    target_spec: dict[str, Any],
    discovery: dict[str, Any],
) -> dict[str, Any]:
    expected_types = set(_filter_access_expectations(target_spec))
    candidates = discovery.get("access_control_candidates") or []
    detected_types = {
        str(item.get("vulnerability_type") or "").strip()
        for item in candidates
        if isinstance(item, dict) and str(item.get("vulnerability_type") or "").strip()
    }
    detected_expected = sorted(expected_types & detected_types)
    missed_expected = sorted(expected_types - detected_types)
    unexpected_detected = sorted(detected_types - expected_types)

    coverage = target_spec.get("pack_coverage_expectations")
    pack_expectations = (
        coverage.get("p3a_access_control_workflow_abuse")
        if isinstance(coverage, dict) and isinstance(coverage.get("p3a_access_control_workflow_abuse"), dict)
        else {}
    )
    detected_recall = round(len(detected_expected) / len(expected_types), 3) if expected_types else None
    minimum_detected_recall = float(pack_expectations.get("minimum_detected_recall", 1.0) or 0.0)
    capability = discovery.get("access_control_workflow_abuse_capability") or {}

    return {
        "scope": "access_control_workflow_only",
        "expected_vulnerability_types": sorted(expected_types),
        "detected_types": sorted(detected_types),
        "detected_expected_types": detected_expected,
        "missed_expected_types": missed_expected,
        "unexpected_detected_types": unexpected_detected,
        "detected_recall": detected_recall,
        "minimum_detected_recall": minimum_detected_recall,
        "meets_detected_recall": detected_recall is None or detected_recall >= minimum_detected_recall,
        "meets_target_bar": detected_recall is None or detected_recall >= minimum_detected_recall,
        "candidate_count": int(capability.get("candidate_count") or len(candidates) or 0),
        "planner_hook_count": int(capability.get("planner_hook_count") or 0),
        "negative_evidence_count": int(
            ((capability.get("route_assessment_counts") or {}).get("negative_evidence_routes") or 0)
        ),
        "target_profile": str(capability.get("target_profile") or ""),
    }


async def _run_target(target_spec: dict[str, Any]) -> dict[str, Any]:
    launch = await helpers.ensure_target(target_spec)
    if launch.get("status") not in {"ok", "already_running"}:
        return {
            "benchmark_key": str(target_spec.get("key") or ""),
            "captured_at": helpers.utc_now(),
            "status": "unavailable" if launch.get("status") == "unavailable" else "launch_failed",
            "detail": str((launch.get("health") or {}).get("detail") or launch.get("status") or ""),
            "target": str(target_spec.get("target") or ""),
            "healthcheck_url": str(target_spec.get("healthcheck_url") or ""),
            "launch_mode": str(target_spec.get("launch_mode") or ""),
            "launch_result": launch,
            "manifest_path": str(target_spec.get("manifest_path") or target_spec.get("ground_truth_source") or ""),
        }

    plan, scan_config = helpers.resolve_scan_config(target_spec)
    discovery = await WebInteractionRunner().run_discovery(
        base_url=str(target_spec.get("target") or ""),
        scan_config=scan_config,
    )
    assessment = _evaluate_access_control_workflow_assessment(
        target_spec=target_spec,
        discovery=discovery,
    )
    record = {
        "benchmark_key": str(target_spec.get("key") or ""),
        "captured_at": helpers.utc_now(),
        "status": "passed" if bool(assessment.get("meets_target_bar")) else "failed",
        "detail": "",
        "target": str(target_spec.get("target") or ""),
        "healthcheck_url": str(target_spec.get("healthcheck_url") or ""),
        "launch_mode": str(target_spec.get("launch_mode") or ""),
        "launch_result": launch,
        "manifest_path": str(target_spec.get("manifest_path") or target_spec.get("ground_truth_source") or ""),
        "scan_plan_key": str(plan.get("key") or ""),
        "scan_plan_label": str(plan.get("label") or ""),
        "config_template": str(plan.get("config_template") or ""),
        "seed_paths": helpers.selected_paths(((scan_config.get("stateful_testing") or {}).get("seed_paths"))),
        "summary": discovery.get("summary") if isinstance(discovery.get("summary"), dict) else {},
        "access_control_workflow_abuse_capability": discovery.get("access_control_workflow_abuse_capability") or {},
        "access_control_candidates": discovery.get("access_control_candidates") or [],
        "access_control_workflow_assessment": assessment,
        "top_candidates": _top_candidates(discovery),
        "top_route_assessments": _top_route_assessments(discovery),
    }
    per_target_path = OUTPUT_DIR / f"{record['benchmark_key']}_access_control_workflow_live_latest.json"
    per_target_path.write_text(json.dumps(record, indent=2, sort_keys=True))
    return record


def _summarize_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    passed = sum(1 for item in results if item.get("status") == "passed")
    failed = sum(1 for item in results if item.get("status") == "failed")
    unavailable = sum(1 for item in results if item.get("status") in {"unavailable", "launch_failed"})
    return {
        "passed_targets": passed,
        "failed_targets": failed,
        "unavailable_targets": unavailable,
    }


async def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    for path in BENCHMARK_PATHS:
        target_spec = helpers.load_benchmark(path)
        target_spec = dict(target_spec)
        target_spec["manifest_path"] = str(path)
        results.append(await _run_target(target_spec))
    payload = {
        "captured_at": helpers.utc_now(),
        "target_count": len(results),
        "summary": _summarize_results(results),
        "results": results,
    }
    OUTPUT_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True))
    print(json.dumps(payload["summary"], indent=2, sort_keys=True))


if __name__ == "__main__":
    asyncio.run(main())
