"""MOD-11.8 Offensive System Validation tests — end-to-end pipeline validation
through realistic attack scenarios.

Run:
    cd pentra_core/services/orchestrator-svc
    python -m pytest tests/test_offensive_validation.py -v
"""

from __future__ import annotations

import os
import sys

import pytest

_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


# ═══════════════════════════════════════════════════════════════════
# 1. Scenario Loading
# ═══════════════════════════════════════════════════════════════════


def test_scenarios_loaded():
    from app.engine.scenario_runner import ScenarioRunner
    runner = ScenarioRunner()
    assert runner.scenario_count >= 6


def test_scenario_names():
    from app.engine.scenario_runner import ScenarioRunner
    runner = ScenarioRunner()
    names = runner.scenario_names
    assert "sql_injection_discovery" in names
    assert "idor_workflow" in names
    assert "exploit_refinement_loop" in names


# ═══════════════════════════════════════════════════════════════════
# 2. Individual Scenario Execution
# ═══════════════════════════════════════════════════════════════════


def test_scenario_sql_injection():
    from app.engine.scenario_runner import ScenarioRunner
    runner = ScenarioRunner()
    scenarios = [s for s in runner._scenarios if s["name"] == "sql_injection_discovery"]
    result = runner.run_scenario(scenarios[0])
    assert result.success is True
    assert result.graph_node_count >= 3
    assert result.total_hypotheses > 0
    assert "heuristic_matching" in result.pipeline_steps


def test_scenario_idor_workflow():
    from app.engine.scenario_runner import ScenarioRunner
    runner = ScenarioRunner()
    scenarios = [s for s in runner._scenarios if s["name"] == "idor_workflow"]
    result = runner.run_scenario(scenarios[0])
    assert result.success is True
    assert result.workflow_hypotheses > 0
    assert "workflow_mutation" in result.pipeline_steps


def test_scenario_workflow_bypass():
    from app.engine.scenario_runner import ScenarioRunner
    runner = ScenarioRunner()
    scenarios = [s for s in runner._scenarios if s["name"] == "workflow_bypass"]
    result = runner.run_scenario(scenarios[0])
    assert result.success is True
    assert result.workflow_hypotheses > 0


def test_scenario_credential_reuse():
    from app.engine.scenario_runner import ScenarioRunner
    runner = ScenarioRunner()
    scenarios = [s for s in runner._scenarios if s["name"] == "credential_reuse"]
    result = runner.run_scenario(scenarios[0])
    assert result.success is True
    assert result.total_hypotheses > 0


def test_scenario_endpoint_discovery():
    from app.engine.scenario_runner import ScenarioRunner
    runner = ScenarioRunner()
    scenarios = [s for s in runner._scenarios if s["name"] == "endpoint_discovery_chain"]
    result = runner.run_scenario(scenarios[0])
    assert result.success is True
    assert result.recon_hypotheses > 0
    assert "recon_planning" in result.pipeline_steps


def test_scenario_exploit_refinement():
    from app.engine.scenario_runner import ScenarioRunner
    runner = ScenarioRunner()
    scenarios = [s for s in runner._scenarios if s["name"] == "exploit_refinement_loop"]
    result = runner.run_scenario(scenarios[0])
    assert result.success is True
    assert result.refinement_attempts > 0
    assert "exploit_refinement" in result.pipeline_steps


# ═══════════════════════════════════════════════════════════════════
# 3. Full Sweep
# ═══════════════════════════════════════════════════════════════════


def test_all_scenarios_pass():
    from app.engine.scenario_runner import ScenarioRunner
    runner = ScenarioRunner()
    results = runner.run_all()
    for r in results:
        assert r.success is True, f"Scenario {r.scenario_name} failed: {r.errors}"


def test_all_scenarios_generate_hypotheses():
    from app.engine.scenario_runner import ScenarioRunner
    runner = ScenarioRunner()
    results = runner.run_all()
    for r in results:
        assert r.total_hypotheses > 0, f"Scenario {r.scenario_name}: no hypotheses"


def test_all_scenarios_scored():
    from app.engine.scenario_runner import ScenarioRunner
    runner = ScenarioRunner()
    results = runner.run_all()
    for r in results:
        assert r.scored_hypotheses > 0, f"Scenario {r.scenario_name}: no scored hypotheses"


# ═══════════════════════════════════════════════════════════════════
# 4. Result Validator
# ═══════════════════════════════════════════════════════════════════


def test_validator_reports_pass():
    from app.engine.scenario_runner import ScenarioRunner
    from app.engine.result_validator import ResultValidator
    runner = ScenarioRunner()
    results = runner.run_all()
    validator = ResultValidator()
    reports = validator.validate_all(results, runner._scenarios)
    for rpt in reports:
        assert rpt.passed is True, (
            f"Scenario {rpt.scenario_name} validation failed: "
            + ", ".join(c.check_name for c in rpt.checks if not c.passed)
        )


def test_validator_check_counts():
    from app.engine.scenario_runner import ScenarioRunner
    from app.engine.result_validator import ResultValidator
    runner = ScenarioRunner()
    results = runner.run_all()
    validator = ResultValidator()
    reports = validator.validate_all(results, runner._scenarios)
    for rpt in reports:
        assert rpt.total_checks > 0
        assert rpt.passed_checks == rpt.total_checks


def test_validator_report_to_dict():
    from app.engine.scenario_runner import ScenarioRunner
    from app.engine.result_validator import ResultValidator
    runner = ScenarioRunner()
    result = runner.run_all()[0]
    rpt = ResultValidator().validate(result, runner._scenarios[0])
    d = rpt.to_dict()
    assert "passed" in d
    assert "total" in d


def test_scenario_result_to_dict():
    from app.engine.scenario_runner import ScenarioRunner
    runner = ScenarioRunner()
    result = runner.run_all()[0]
    d = result.to_dict()
    assert "scenario" in d
    assert "total_hypotheses" in d


# ═══════════════════════════════════════════════════════════════════
# 5. Cross-Module Integration Checks
# ═══════════════════════════════════════════════════════════════════


def test_pipeline_artifact_propagation():
    """Verify artifacts flow through all pipeline stages."""
    from app.engine.scenario_runner import ScenarioRunner
    runner = ScenarioRunner()
    results = runner.run_all()
    for r in results:
        assert len(r.pipeline_steps) >= 5, (
            f"Scenario {r.scenario_name}: only {len(r.pipeline_steps)} steps executed"
        )


def test_pipeline_graph_construction():
    """Verify attack graphs built from all scenarios."""
    from app.engine.scenario_runner import ScenarioRunner
    runner = ScenarioRunner()
    results = runner.run_all()
    for r in results:
        assert r.graph_node_count >= 2, f"Scenario {r.scenario_name}: insufficient nodes"


def test_pipeline_hypothesis_diversity():
    """Verify different hypothesis sources contribute."""
    from app.engine.scenario_runner import ScenarioRunner
    runner = ScenarioRunner()
    results = runner.run_all()
    total_recon = sum(r.recon_hypotheses for r in results)
    total_workflow = sum(r.workflow_hypotheses for r in results)
    total_heuristic = sum(r.heuristic_matches for r in results)
    assert total_recon > 0, "No recon hypotheses across all scenarios"
    assert total_workflow > 0, "No workflow hypotheses across all scenarios"
    assert total_heuristic > 0, "No heuristic matches across all scenarios"


# ── Run directly ─────────────────────────────────────────────────

if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
