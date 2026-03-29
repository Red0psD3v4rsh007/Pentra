"""Aggregate Phase 10 per-pack live benchmark metrics into one matrix artifact."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[3]
OUTPUT_DIR = REPO_ROOT / ".local" / "pentra" / "phase10"
OUTPUT_PATH = OUTPUT_DIR / "pack_matrix_latest.json"

_PACK_SPECS = (
    {
        "pack_key": "p3a_browser_xss",
        "artifact_path": OUTPUT_DIR / "juice_shop_browser_xss_live_latest.json",
        "kind": "browser_xss",
    },
    {
        "pack_key": "p3a_multi_role_stateful_auth",
        "artifact_path": OUTPUT_DIR / "auth_benchmarks_live_latest.json",
        "kind": "benchmark_results",
        "assessment_key": "auth_assessment",
    },
    {
        "pack_key": "p3a_access_control_workflow_abuse",
        "artifact_path": OUTPUT_DIR / "access_control_workflow_benchmarks_live_latest.json",
        "kind": "benchmark_results",
        "assessment_key": "access_control_workflow_assessment",
    },
    {
        "pack_key": "p3a_injection",
        "artifact_path": OUTPUT_DIR / "injection_benchmarks_live_latest.json",
        "kind": "benchmark_results",
        "assessment_key": "injection_assessment",
    },
    {
        "pack_key": "p3a_parser_file_abuse",
        "artifact_path": OUTPUT_DIR / "parser_file_benchmarks_live_latest.json",
        "kind": "benchmark_results",
        "assessment_key": "parser_file_assessment",
    },
    {
        "pack_key": "p3a_disclosure_misconfig_crypto",
        "artifact_path": OUTPUT_DIR / "disclosure_benchmarks_live_latest.json",
        "kind": "benchmark_results",
        "assessment_key": "capability_assessment",
        "results_key": "targets",
    },
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    payload = json.loads(path.read_text())
    return payload if isinstance(payload, dict) else None


def _safe_rate(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return round(numerator / denominator, 3)


def _aggregate_assessment_metrics(
    *,
    results: list[dict[str, Any]],
    assessment_key: str,
) -> dict[str, Any]:
    expected_count = 0
    detected_expected_count = 0
    candidate_count = 0
    negative_evidence_count = 0
    planner_hook_count = 0
    benchmark_keys: list[str] = []
    statuses: list[str] = []
    for result in results:
        benchmark_key = str(result.get("benchmark_key") or "").strip()
        if benchmark_key and benchmark_key not in benchmark_keys:
            benchmark_keys.append(benchmark_key)
        statuses.append(str(result.get("status") or ""))
        assessment = result.get(assessment_key)
        if not isinstance(assessment, dict):
            continue
        expected_count += len(assessment.get("expected_vulnerability_types") or [])
        detected_expected_count += len(assessment.get("detected_expected_types") or [])
        candidate_count += int(assessment.get("candidate_count") or 0)
        negative_evidence_count += int(assessment.get("negative_evidence_count") or 0)
        planner_hook_count += int(assessment.get("planner_hook_count") or 0)
    return {
        "status": "passed" if results and all(status == "passed" for status in statuses) else "partial" if results else "missing",
        "target_count": len(results),
        "benchmark_keys": benchmark_keys,
        "detected_recall": _safe_rate(detected_expected_count, expected_count),
        "verified_recall": None,
        "verified_share": None,
        "candidate_count": candidate_count,
        "negative_evidence_count": negative_evidence_count,
        "planner_hook_count": planner_hook_count,
        "demotion_rate": _safe_rate(negative_evidence_count, candidate_count),
    }


def _browser_xss_metrics(payload: dict[str, Any]) -> dict[str, Any]:
    capability = payload.get("browser_xss_capability")
    capability = capability if isinstance(capability, dict) else {}
    candidate_count = int(capability.get("candidate_count") or len(payload.get("top_candidates") or []) or 0)
    planner_hook_count = int(capability.get("planner_hook_count") or 0)
    negative_evidence_count = int(capability.get("negative_evidence_count") or 0)
    verification_outcomes = payload.get("verification_outcomes") or []
    verified_findings = payload.get("verified_findings") or []
    verification_attempts = len(verification_outcomes)
    no_observation_count = sum(
        1
        for item in verification_outcomes
        if isinstance(item, dict) and str(item.get("verification_state") or "").strip() == "no_observation"
    )
    challenge_count = int(
        (payload.get("live_inventory_summary") or {}).get("xss_challenge_count")
        or (payload.get("benchmark_inventory_summary") or {}).get("xss_challenge_count")
        or 0
    )
    benchmark_key = str(payload.get("benchmark_key") or "juice_shop_local").strip() or "juice_shop_local"
    return {
        "status": "passed" if payload else "missing",
        "target_count": 1,
        "benchmark_keys": [benchmark_key],
        "detected_recall": _safe_rate(candidate_count, challenge_count),
        "verified_recall": _safe_rate(len(verified_findings), challenge_count),
        "verified_share": _safe_rate(len(verified_findings), candidate_count),
        "candidate_count": candidate_count,
        "negative_evidence_count": max(negative_evidence_count, no_observation_count),
        "planner_hook_count": planner_hook_count,
        "demotion_rate": _safe_rate(no_observation_count, verification_attempts),
    }


def build_phase10_pack_rows(base_dir: Path | None = None) -> list[dict[str, Any]]:
    root = base_dir or OUTPUT_DIR
    rows: list[dict[str, Any]] = []
    for spec in _PACK_SPECS:
        artifact_path = root / Path(spec["artifact_path"]).name
        payload = _load_json(artifact_path)
        if payload is None:
            rows.append(
                {
                    "pack_key": spec["pack_key"],
                    "artifact_path": str(artifact_path),
                    "status": "missing",
                    "target_count": 0,
                    "benchmark_keys": [],
                    "detected_recall": None,
                    "verified_recall": None,
                    "verified_share": None,
                    "candidate_count": 0,
                    "negative_evidence_count": 0,
                    "planner_hook_count": 0,
                    "demotion_rate": None,
                }
            )
            continue

        if spec["kind"] == "browser_xss":
            metrics = _browser_xss_metrics(payload)
        else:
            results_key = str(spec.get("results_key") or "results")
            raw_results = payload.get(results_key)
            results = [item for item in raw_results if isinstance(item, dict)] if isinstance(raw_results, list) else []
            metrics = _aggregate_assessment_metrics(
                results=results,
                assessment_key=str(spec["assessment_key"]),
            )

        rows.append(
            {
                "pack_key": spec["pack_key"],
                "artifact_path": str(artifact_path),
                **metrics,
            }
        )
    return rows


def summarize_phase10_pack_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    passed = sum(1 for row in rows if row.get("status") == "passed")
    partial = sum(1 for row in rows if row.get("status") == "partial")
    missing = sum(1 for row in rows if row.get("status") == "missing")
    return {
        "status": "passed" if rows and partial == 0 and missing == 0 else "partial" if rows else "missing",
        "summary": {
            "pack_count": len(rows),
            "passed_packs": passed,
            "partial_packs": partial,
            "missing_packs": missing,
        },
    }


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    rows = build_phase10_pack_rows()
    payload = {
        "captured_at": _utc_now(),
        "rows": rows,
        **summarize_phase10_pack_rows(rows),
    }
    OUTPUT_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True))
    print(json.dumps(payload["summary"], indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
