from __future__ import annotations

import json
from pathlib import Path

from pentra_core.scripts.local.run_phase10_pack_matrix import (
    build_phase10_pack_rows,
    summarize_phase10_pack_rows,
)


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload))


def test_phase10_pack_matrix_aggregates_pack_metrics(tmp_path: Path) -> None:
    _write_json(
        tmp_path / "juice_shop_browser_xss_live_latest.json",
        {
            "benchmark_key": "juice_shop_local",
            "benchmark_inventory_summary": {"xss_challenge_count": 10},
            "browser_xss_capability": {"candidate_count": 8, "planner_hook_count": 4, "negative_evidence_count": 1},
            "verification_outcomes": [
                {"verification_state": "verified"},
                {"verification_state": "no_observation"},
            ],
            "verified_findings": [{}, {}],
        },
    )
    _write_json(
        tmp_path / "auth_benchmarks_live_latest.json",
        {
            "results": [
                {
                    "benchmark_key": "repo_demo_api",
                    "status": "passed",
                    "auth_assessment": {
                        "expected_vulnerability_types": ["idor"],
                        "detected_expected_types": ["idor"],
                        "candidate_count": 3,
                        "negative_evidence_count": 1,
                        "planner_hook_count": 2,
                    },
                }
            ]
        },
    )
    _write_json(
        tmp_path / "access_control_workflow_benchmarks_live_latest.json",
        {
            "results": [
                {
                    "benchmark_key": "repo_demo_api",
                    "status": "passed",
                    "access_control_workflow_assessment": {
                        "expected_vulnerability_types": ["workflow_bypass"],
                        "detected_expected_types": ["workflow_bypass"],
                        "candidate_count": 4,
                        "negative_evidence_count": 1,
                        "planner_hook_count": 3,
                    },
                }
            ]
        },
    )
    _write_json(
        tmp_path / "injection_benchmarks_live_latest.json",
        {
            "results": [
                {
                    "benchmark_key": "repo_demo_api",
                    "status": "passed",
                    "injection_assessment": {
                        "expected_vulnerability_types": ["sql_injection"],
                        "detected_expected_types": ["sql_injection"],
                        "candidate_count": 2,
                        "negative_evidence_count": 0,
                        "planner_hook_count": 1,
                    },
                }
            ]
        },
    )
    _write_json(
        tmp_path / "parser_file_benchmarks_live_latest.json",
        {
            "results": [
                {
                    "benchmark_key": "repo_parser_upload_demo",
                    "status": "passed",
                    "parser_file_assessment": {
                        "expected_vulnerability_types": ["xxe"],
                        "detected_expected_types": ["xxe"],
                        "candidate_count": 2,
                        "negative_evidence_count": 1,
                        "planner_hook_count": 2,
                    },
                }
            ]
        },
    )
    _write_json(
        tmp_path / "disclosure_benchmarks_live_latest.json",
        {
            "targets": [
                {
                    "benchmark_key": "repo_demo_api",
                    "status": "passed",
                    "capability_assessment": {
                        "expected_vulnerability_types": ["openapi_exposure"],
                        "detected_expected_types": ["openapi_exposure"],
                        "candidate_count": 1,
                        "negative_evidence_count": 0,
                        "planner_hook_count": 1,
                    },
                }
            ]
        },
    )

    rows = build_phase10_pack_rows(tmp_path)
    row_map = {row["pack_key"]: row for row in rows}

    assert row_map["p3a_browser_xss"]["detected_recall"] == 0.8
    assert row_map["p3a_browser_xss"]["verified_recall"] == 0.2
    assert row_map["p3a_multi_role_stateful_auth"]["detected_recall"] == 1.0
    assert row_map["p3a_access_control_workflow_abuse"]["candidate_count"] == 4
    assert row_map["p3a_disclosure_misconfig_crypto"]["planner_hook_count"] == 1


def test_phase10_pack_matrix_summary_marks_missing_rows_partial(tmp_path: Path) -> None:
    _write_json(
        tmp_path / "juice_shop_browser_xss_live_latest.json",
        {
            "benchmark_key": "juice_shop_local",
            "benchmark_inventory_summary": {"xss_challenge_count": 2},
            "browser_xss_capability": {"candidate_count": 1, "planner_hook_count": 1},
            "verification_outcomes": [],
            "verified_findings": [],
        },
    )

    rows = build_phase10_pack_rows(tmp_path)
    summary = summarize_phase10_pack_rows(rows)

    assert summary["status"] == "partial"
    assert summary["summary"]["missing_packs"] >= 1
