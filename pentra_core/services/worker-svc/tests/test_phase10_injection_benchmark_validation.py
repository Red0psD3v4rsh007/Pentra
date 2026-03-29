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


def test_phase10_injection_benchmark_assessment_filters_non_injection_expectations() -> None:
    from pentra_core.scripts.local.validate_phase10_injection_benchmarks import _evaluate_injection_assessment

    assessment = _evaluate_injection_assessment(
        target_spec={
            "expectations": {
                "expected_vulnerability_types": [
                    "auth_bypass",
                    "sql_injection",
                    "graphql_introspection",
                ],
                "minimum_detected_recall": 0.5,
            }
        },
        discovery={
            "injection_candidates": [
                {"vulnerability_type": "sql_injection"},
                {"vulnerability_type": "graphql_injection"},
            ],
            "injection_capability": {
                "candidate_count": 2,
                "planner_hook_count": 1,
                "route_assessment_counts": {"negative_evidence_routes": 1},
            },
        },
    )

    assert assessment["scope"] == "injection_only"
    assert assessment["expected_vulnerability_types"] == ["graphql_introspection", "sql_injection"]
    assert assessment["detected_expected_types"] == ["sql_injection"]
    assert assessment["missed_expected_types"] == ["graphql_introspection"]
    assert assessment["detected_recall"] == 0.5
    assert assessment["meets_target_bar"] is True
