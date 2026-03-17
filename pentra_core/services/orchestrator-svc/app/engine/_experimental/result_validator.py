"""Result validator — validates scenario results against expected outcomes.

MOD-11.8: Checks that scenario results match expected pipeline behavior,
artifact generation, and graph construction.
"""

from __future__ import annotations

__classification__ = "experimental"

import logging
from dataclasses import dataclass, field
from typing import Any

from app.engine.scenario_runner import ScenarioResult

logger = logging.getLogger(__name__)


@dataclass
class ValidationCheck:
    """A single validation check result."""

    check_name: str
    passed: bool
    expected: str
    actual: str

    def to_dict(self) -> dict:
        return {
            "check": self.check_name,
            "passed": self.passed,
            "expected": self.expected,
            "actual": self.actual,
        }


@dataclass
class ValidationReport:
    """Complete validation report for a scenario."""

    scenario_name: str
    passed: bool
    checks: list[ValidationCheck] = field(default_factory=list)
    total_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0

    def to_dict(self) -> dict:
        return {
            "scenario": self.scenario_name,
            "passed": self.passed,
            "total": self.total_checks,
            "pass": self.passed_checks,
            "fail": self.failed_checks,
        }


class ResultValidator:
    """Validates scenario results against expected outcomes.

    Usage::

        validator = ResultValidator()
        report = validator.validate(result, scenario_def)
    """

    def validate(
        self,
        result: ScenarioResult,
        scenario: dict,
    ) -> ValidationReport:
        """Validate a scenario result against its definition."""
        report = ValidationReport(scenario_name=result.scenario_name, passed=True)

        # 1 — Scenario succeeded without errors
        self._check(report, "execution_success", result.success, True)
        self._check(report, "no_errors", len(result.errors) == 0, True)

        # 2 — Graph was built
        expected_nodes = scenario.get("expected_graph_nodes", [])
        self._check(
            report, "graph_has_nodes",
            result.graph_node_count > 1,  # > 1 because entrypoint always exists
            True,
        )

        # 3 — Pipeline steps executed
        expected_steps = [s.get("step", "") for s in scenario.get("expected_pipeline", [])]
        for step in expected_steps:
            self._check(
                report, f"step:{step}",
                step in result.pipeline_steps,
                True,
            )

        # 4 — Hypotheses generated
        self._check(
            report, "hypotheses_generated",
            result.total_hypotheses > 0,
            True,
        )

        # 5 — Hypotheses scored
        self._check(
            report, "hypotheses_scored",
            result.scored_hypotheses > 0,
            True,
        )

        # 6 — Module-specific checks
        if any(s.get("step") == "heuristic_matching" for s in scenario.get("expected_pipeline", [])):
            self._check(
                report, "heuristic_matches_found",
                result.heuristic_matches > 0,
                True,
            )

        if any(s.get("step") == "recon_planning" for s in scenario.get("expected_pipeline", [])):
            self._check(
                report, "recon_hypotheses_generated",
                result.recon_hypotheses > 0,
                True,
            )

        if any(s.get("step") == "workflow_mutation" for s in scenario.get("expected_pipeline", [])):
            self._check(
                report, "workflow_hypotheses_generated",
                result.workflow_hypotheses > 0,
                True,
            )

        if any(s.get("step") == "exploit_refinement" for s in scenario.get("expected_pipeline", [])):
            self._check(
                report, "refinement_executed",
                result.refinement_attempts > 0,
                True,
            )

        if any(s.get("step") == "payload_generation" for s in scenario.get("expected_pipeline", [])):
            self._check(
                report, "payloads_generated",
                result.payload_variants > 0,
                True,
            )

        # Finalize
        report.total_checks = len(report.checks)
        report.passed_checks = sum(1 for c in report.checks if c.passed)
        report.failed_checks = report.total_checks - report.passed_checks
        report.passed = report.failed_checks == 0

        return report

    def validate_all(
        self,
        results: list[ScenarioResult],
        scenarios: list[dict],
    ) -> list[ValidationReport]:
        """Validate all results against their scenario definitions."""
        reports = []
        scenario_map = {s["name"]: s for s in scenarios}
        for result in results:
            scenario = scenario_map.get(result.scenario_name, {})
            reports.append(self.validate(result, scenario))
        return reports

    def _check(
        self,
        report: ValidationReport,
        name: str,
        actual: Any,
        expected: Any,
    ) -> None:
        passed = actual == expected
        report.checks.append(ValidationCheck(
            check_name=name,
            passed=passed,
            expected=str(expected),
            actual=str(actual),
        ))
        if not passed:
            report.passed = False
