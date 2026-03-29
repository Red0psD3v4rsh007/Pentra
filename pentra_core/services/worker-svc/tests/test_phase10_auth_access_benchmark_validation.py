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


def test_phase10_auth_benchmark_assessment_uses_pack_expectations() -> None:
    from pentra_core.scripts.local.validate_phase10_auth_benchmarks import _evaluate_auth_assessment

    assessment = _evaluate_auth_assessment(
        target_spec={
            "pack_coverage_expectations": {
                "p3a_multi_role_stateful_auth": {
                    "expected_vulnerability_types": [
                        "idor",
                        "workflow_bypass",
                    ],
                    "minimum_detected_recall": 1.0,
                }
            }
        },
        discovery={
            "auth_candidates": [
                {"vulnerability_type": "idor"},
                {"vulnerability_type": "idor"},
            ],
            "multi_role_stateful_auth_capability": {
                "candidate_count": 2,
                "planner_hook_count": 1,
                "route_assessment_counts": {"negative_evidence_routes": 1},
                "target_profile": "auth_heavy_admin_portal",
                "role_count": 3,
            },
        },
    )

    assert assessment["scope"] == "multi_role_stateful_auth_only"
    assert assessment["expected_vulnerability_types"] == ["idor"]
    assert assessment["detected_expected_types"] == ["idor"]
    assert assessment["missed_expected_types"] == []
    assert assessment["detected_recall"] == 1.0
    assert assessment["meets_target_bar"] is True


def test_phase10_access_benchmark_assessment_filters_to_access_workflow_types() -> None:
    from pentra_core.scripts.local.validate_phase10_access_control_workflow_benchmarks import (
        _evaluate_access_control_workflow_assessment,
    )

    assessment = _evaluate_access_control_workflow_assessment(
        target_spec={
            "pack_coverage_expectations": {
                "p3a_access_control_workflow_abuse": {
                    "expected_vulnerability_types": [
                        "workflow_bypass",
                        "sql_injection",
                    ],
                    "minimum_detected_recall": 0.5,
                }
            }
        },
        discovery={
            "access_control_candidates": [
                {"vulnerability_type": "workflow_bypass"},
                {"vulnerability_type": "parameter_tampering"},
            ],
            "access_control_workflow_abuse_capability": {
                "candidate_count": 2,
                "planner_hook_count": 2,
                "route_assessment_counts": {"negative_evidence_routes": 0},
                "target_profile": "workflow_heavy_commerce",
            },
        },
    )

    assert assessment["scope"] == "access_control_workflow_only"
    assert assessment["expected_vulnerability_types"] == ["workflow_bypass"]
    assert assessment["detected_expected_types"] == ["workflow_bypass"]
    assert assessment["missed_expected_types"] == []
    assert assessment["detected_recall"] == 1.0
    assert assessment["meets_target_bar"] is True
