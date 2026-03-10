"""Heuristic result analyzer — analyzes responses from heuristic tests.

MOD-11: Evaluates test results to determine if vulnerability indicators
are present, classifying outcomes as confirmed, likely, or negative.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class HeuristicResult:
    """Result of a heuristic test analysis."""

    heuristic_name: str
    target_node_id: str
    test_type: str
    verdict: str             # confirmed | likely | negative
    confidence: float        # 0.0–1.0
    vulnerability_class: str
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "heuristic_name": self.heuristic_name,
            "target_node_id": self.target_node_id,
            "test_type": self.test_type,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "vulnerability_class": self.vulnerability_class,
            "evidence_count": len(self.evidence),
        }


# ── Indicator definitions ────────────────────────────────────────────

_POSITIVE_INDICATORS: dict[str, list[str]] = {
    "data_exposure": [
        "different_content_length",
        "contains_pii",
        "unauthorized_data_returned",
        "adjacent_record_accessed",
    ],
    "authentication_bypass": [
        "authenticated_without_credentials",
        "token_accepted_after_mutation",
        "session_created_without_auth",
        "default_credential_accepted",
    ],
    "privilege_escalation": [
        "elevated_role_returned",
        "admin_action_succeeded",
        "extra_field_accepted",
        "method_override_succeeded",
    ],
    "information_disclosure": [
        "stack_trace_returned",
        "debug_info_exposed",
        "internal_path_revealed",
        "server_version_exposed",
    ],
    "admin_access": [
        "admin_panel_accessible",
        "admin_credential_accepted",
    ],
    "credential_leak": [
        "credentials_in_response",
        "api_key_exposed",
    ],
}


class HeuristicAnalyzer:
    """Analyzes heuristic test results for vulnerability indicators.

    Usage::

        analyzer = HeuristicAnalyzer()
        result = analyzer.analyze(test_output, heuristic_config)
    """

    def analyze(
        self,
        test_output: dict[str, Any],
        heuristic_config: dict[str, Any],
    ) -> HeuristicResult:
        """Analyze a heuristic test output.

        Args:
            test_output: Raw test result with keys like status_code,
                response_body, headers, etc.
            heuristic_config: The hypothesis config containing heuristic metadata.
        """
        heuristic_name = heuristic_config.get("heuristic_name", "unknown")
        target_node_id = heuristic_config.get("target_node_id", "unknown")
        test_type = heuristic_config.get("test_type", "unknown")
        vuln_class = heuristic_config.get("vulnerability_class", "unknown")
        impact_types = heuristic_config.get("impact", [])
        base_confidence = float(heuristic_config.get("confidence", 0.5))

        evidence: list[str] = []

        # Check response-based indicators
        status_code = test_output.get("status_code", 0)
        response_body = str(test_output.get("response_body", ""))
        headers = test_output.get("headers", {})

        # 1 — Status code analysis
        if status_code == 200 and test_type in ("token_replay_test", "token_mutation_test", "default_credential_test"):
            evidence.append("authenticated_without_credentials")
        if status_code == 200 and test_type == "method_override_test":
            evidence.append("method_override_succeeded")

        # 2 — Response body analysis
        if self._has_stack_trace(response_body):
            evidence.append("stack_trace_returned")
        if self._has_debug_info(response_body):
            evidence.append("debug_info_exposed")
        if self._has_pii(response_body):
            evidence.append("contains_pii")
        if self._has_internal_paths(response_body):
            evidence.append("internal_path_revealed")

        # 3 — Content length anomaly (for IDOR)
        expected_length = test_output.get("expected_content_length")
        actual_length = test_output.get("actual_content_length")
        if expected_length and actual_length and expected_length != actual_length:
            evidence.append("different_content_length")

        # 4 — Check positive indicators from impact types
        for impact in impact_types:
            indicators = _POSITIVE_INDICATORS.get(impact, [])
            for indicator in indicators:
                if indicator in test_output.get("indicators", []):
                    evidence.append(indicator)

        # Determine verdict
        verdict, confidence = self._determine_verdict(evidence, base_confidence)

        return HeuristicResult(
            heuristic_name=heuristic_name,
            target_node_id=target_node_id,
            test_type=test_type,
            verdict=verdict,
            confidence=round(confidence, 2),
            vulnerability_class=vuln_class,
            evidence=evidence,
        )

    def _determine_verdict(
        self, evidence: list[str], base_confidence: float,
    ) -> tuple[str, float]:
        """Determine verdict from evidence."""
        if len(evidence) >= 3:
            return "confirmed", min(1.0, base_confidence + 0.3)
        elif len(evidence) >= 1:
            return "likely", min(1.0, base_confidence + 0.1)
        else:
            return "negative", 0.0

    def _has_stack_trace(self, body: str) -> bool:
        indicators = ["traceback", "stacktrace", "at line", "exception", "error in"]
        return any(ind in body.lower() for ind in indicators)

    def _has_debug_info(self, body: str) -> bool:
        indicators = ["debug", "x-debug", "phpinfo", "server-status", "django debug"]
        return any(ind in body.lower() for ind in indicators)

    def _has_pii(self, body: str) -> bool:
        indicators = ["email", "password", "ssn", "credit_card", "phone_number"]
        return any(ind in body.lower() for ind in indicators)

    def _has_internal_paths(self, body: str) -> bool:
        indicators = ["/usr/", "/var/", "/home/", "c:\\", "\\users\\"]
        return any(ind in body.lower() for ind in indicators)
