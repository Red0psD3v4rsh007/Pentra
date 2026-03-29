from __future__ import annotations

import os
import sys


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
_repo_root = os.path.dirname(os.path.dirname(os.path.dirname(_svc_root)))
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)


def test_phase10_parser_file_benchmark_assessment_filters_non_parser_expectations() -> None:
    from pentra_core.scripts.local.validate_phase10_parser_file_benchmarks import _evaluate_parser_file_assessment

    assessment = _evaluate_parser_file_assessment(
        target_spec={
            "expectations": {
                "expected_vulnerability_types": [
                    "xxe",
                    "insecure_deserialization",
                    "sql_injection",
                ],
                "minimum_detected_recall": 0.5,
            }
        },
        discovery={
            "parser_file_candidates": [
                {"vulnerability_type": "xxe"},
                {"vulnerability_type": "insecure_deserialization"},
            ],
            "parser_file_abuse_capability": {
                "candidate_count": 2,
                "planner_hook_count": 2,
                "route_assessment_counts": {"negative_evidence_routes": 1},
            },
        },
    )

    assert assessment["scope"] == "parser_file_only"
    assert assessment["expected_vulnerability_types"] == ["insecure_deserialization", "xxe"]
    assert assessment["detected_expected_types"] == ["insecure_deserialization", "xxe"]
    assert assessment["missed_expected_types"] == []
    assert assessment["detected_recall"] == 1.0
    assert assessment["meets_target_bar"] is True
