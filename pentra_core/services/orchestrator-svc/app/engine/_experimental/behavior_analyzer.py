"""Behavior analyzer — analyzes responses from workflow mutation tests.

MOD-11.6: Evaluates responses from stateful interaction tests to
detect authorization bypass, data exposure, and workflow abuse.
"""

from __future__ import annotations

__classification__ = "experimental"

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class BehaviorResult:
    """Result of a behavior analysis from workflow mutation testing."""

    mutation_type: str
    workflow_type: str
    target_endpoint: str
    verdict: str             # confirmed | likely | negative
    confidence: float
    flaw_type: str           # auth_bypass | idor | workflow_bypass | privilege_escalation | none
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "mutation_type": self.mutation_type,
            "workflow_type": self.workflow_type,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "flaw_type": self.flaw_type,
            "evidence_count": len(self.evidence),
        }


class BehaviorAnalyzer:
    """Analyzes responses from stateful workflow mutation tests.

    Usage::

        analyzer = BehaviorAnalyzer()
        result = analyzer.analyze(response, mutation_config)
    """

    def analyze(
        self,
        response: dict[str, Any],
        mutation_config: dict[str, Any],
    ) -> BehaviorResult:
        """Analyze a response from a workflow mutation test."""
        mutation_type = mutation_config.get("workflow_mutation", "unknown")
        workflow_type = mutation_config.get("workflow_type", "unknown")
        target = mutation_config.get("target_endpoint", "unknown")

        status = response.get("status_code", 0)
        body = str(response.get("body", ""))
        headers = response.get("headers", {})

        evidence: list[str] = []
        flaw_type = "none"

        # ── Skip step analysis ──────────────────────────────────
        if mutation_type == "skip_step":
            if status == 200:
                evidence.append("step_bypass_succeeded")
                flaw_type = "workflow_bypass"
            if self._has_data(body):
                evidence.append("data_returned_after_skip")

        # ── Cross-session analysis ──────────────────────────────
        elif mutation_type == "cross_session":
            if status == 200:
                evidence.append("unauthenticated_access_succeeded")
                flaw_type = "auth_bypass"
            if status in (301, 302) and "login" not in str(headers.get("Location", "")).lower():
                evidence.append("redirect_without_auth_check")

        # ── Modify ID analysis ──────────────────────────────────
        elif mutation_type == "modify_id":
            if status == 200 and self._has_data(body):
                evidence.append("different_user_data_returned")
                flaw_type = "idor"
            if self._has_pii(body):
                evidence.append("pii_exposure")

        # ── Repeat step analysis ────────────────────────────────
        elif mutation_type == "repeat_step":
            if status == 200:
                evidence.append("duplicate_operation_succeeded")
                flaw_type = "workflow_bypass"

        # ── Swap order analysis ─────────────────────────────────
        elif mutation_type == "swap_order":
            if status == 200:
                evidence.append("reversed_workflow_succeeded")
                flaw_type = "workflow_bypass"

        # ── Generic indicators ──────────────────────────────────
        if status == 200 and mutation_type in ("cross_session", "skip_step"):
            if any(kw in body.lower() for kw in ("admin", "role", "privilege")):
                evidence.append("privilege_indicators")
                flaw_type = "privilege_escalation"

        if self._has_error_info(body):
            evidence.append("debug_information_leaked")

        verdict, confidence = self._determine_verdict(evidence, mutation_type)

        return BehaviorResult(
            mutation_type=mutation_type,
            workflow_type=workflow_type,
            target_endpoint=target,
            verdict=verdict,
            confidence=round(confidence, 2),
            flaw_type=flaw_type,
            evidence=evidence,
        )

    def _determine_verdict(
        self, evidence: list[str], mutation_type: str,
    ) -> tuple[str, float]:
        if not evidence:
            return "negative", 0.0

        strong = {
            "unauthenticated_access_succeeded",
            "different_user_data_returned",
            "step_bypass_succeeded",
            "privilege_indicators",
        }
        has_strong = any(e in strong for e in evidence)

        if len(evidence) >= 3 or (has_strong and len(evidence) >= 2):
            return "confirmed", min(0.95, 0.5 + len(evidence) * 0.15)
        elif has_strong:
            return "likely", min(0.8, 0.4 + len(evidence) * 0.15)
        elif len(evidence) >= 1:
            return "likely", 0.3
        return "negative", 0.0

    def _has_data(self, body: str) -> bool:
        return len(body) > 50 and body.lower() not in ("forbidden", "unauthorized", "not found")

    def _has_pii(self, body: str) -> bool:
        indicators = ["email", "password", "ssn", "phone", "address", "credit"]
        return any(ind in body.lower() for ind in indicators)

    def _has_error_info(self, body: str) -> bool:
        indicators = ["traceback", "exception", "stack trace", "debug"]
        return any(ind in body.lower() for ind in indicators)
