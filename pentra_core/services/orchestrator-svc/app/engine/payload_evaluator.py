"""Payload evaluator — analyzes HTTP responses for exploit indicators.

MOD-11.5: Evaluates responses from payload tests to determine if
exploit indicators are present, scoring results by confidence.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class PayloadResult:
    """Result of payload evaluation."""

    payload_class: str
    payload: str
    mutation: str
    verdict: str             # confirmed | likely | negative
    confidence: float
    indicators_found: list[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "payload_class": self.payload_class,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "mutation": self.mutation,
            "indicators_count": len(self.indicators_found),
        }


# ── Indicator patterns per vulnerability class ────────────────────

_SQL_ERROR_PATTERNS: list[str] = [
    r"sql syntax",
    r"mysql_fetch",
    r"pg_query",
    r"ora-\d{5}",
    r"microsoft.+odbc",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"you have an error in your sql",
    r"sqlite3\.operationalerror",
    r"postgresql.*error",
    r"warning.*mysql",
]

_COMMAND_INJECTION_PATTERNS: list[str] = [
    r"uid=\d+",
    r"root:x:0:0",
    r"www-data",
    r"/bin/(ba)?sh",
    r"total \d+",
    r"drwx",
    r"permission denied",
]

_TEMPLATE_INJECTION_PATTERNS: list[str] = [
    r"\b49\b",             # 7*7 = 49
    r"__class__",
    r"__mro__",
    r"__subclasses__",
    r"jinja2",
    r"mako",
    r"freemarker",
]

_PATH_TRAVERSAL_PATTERNS: list[str] = [
    r"root:x:0:0",
    r"\[boot loader\]",
    r"localhost",
    r"/sbin/nologin",
    r"daemon:",
    r"nobody:",
]

_XXE_PATTERNS: list[str] = [
    r"root:x:0:0",
    r"<!DOCTYPE",
    r"<!ENTITY",
    r"SYSTEM\s+[\"']file:",
]

_DESER_PATTERNS: list[str] = [
    r"uid=\d+",
    r"java\.lang\.",
    r"__reduce__",
    r"pickle",
    r"unserialize",
]

_PATTERNS_BY_CLASS: dict[str, list[str]] = {
    "sql_injection": _SQL_ERROR_PATTERNS,
    "command_injection": _COMMAND_INJECTION_PATTERNS,
    "template_injection": _TEMPLATE_INJECTION_PATTERNS,
    "path_traversal": _PATH_TRAVERSAL_PATTERNS,
    "xxe": _XXE_PATTERNS,
    "deserialization": _DESER_PATTERNS,
}


class PayloadEvaluator:
    """Evaluates HTTP responses for exploit indicators.

    Usage::

        evaluator = PayloadEvaluator()
        result = evaluator.evaluate(response, payload_class, payload, mutation)
    """

    def evaluate(
        self,
        response: dict[str, Any],
        payload_class: str,
        payload: str,
        mutation: str = "none",
    ) -> PayloadResult:
        """Evaluate an HTTP response against expected exploit indicators.

        Args:
            response: Dict with status_code, body, headers, response_time_ms.
            payload_class: The vulnerability class being tested.
            payload: The payload that was sent.
            mutation: The mutation/encoding applied.
        """
        body = str(response.get("body", ""))
        status_code = response.get("status_code", 0)
        response_time = response.get("response_time_ms", 0)
        content_length = response.get("content_length", 0)
        baseline_length = response.get("baseline_content_length", 0)

        indicators: list[str] = []
        details: dict[str, Any] = {}

        # 1 — Pattern matching
        patterns = _PATTERNS_BY_CLASS.get(payload_class, [])
        for pattern in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                indicators.append(f"pattern:{pattern}")

        # 2 — Status code analysis
        if status_code == 500 and payload_class == "sql_injection":
            indicators.append("sql_error_500")
        if status_code == 200 and payload_class in ("command_injection", "template_injection"):
            indicators.append("successful_execution")

        # 3 — Timing analysis (blind injection detection)
        if response_time > 4500 and "SLEEP" in payload.upper():
            indicators.append("time_based_delay")
            details["response_time_ms"] = response_time
        if response_time > 4500 and "sleep" in payload.lower():
            indicators.append("time_based_delay")
            details["response_time_ms"] = response_time

        # 4 — Content length anomaly
        if baseline_length and content_length:
            diff_ratio = abs(content_length - baseline_length) / max(baseline_length, 1)
            if diff_ratio > 0.3:
                indicators.append("content_length_anomaly")
                details["length_diff_ratio"] = round(diff_ratio, 2)

        # 5 — Reflection detection
        if payload in body and len(payload) > 5:
            indicators.append("payload_reflected")

        # Determine verdict
        verdict, confidence = self._determine_verdict(indicators, payload_class)

        return PayloadResult(
            payload_class=payload_class,
            payload=payload,
            mutation=mutation,
            verdict=verdict,
            confidence=round(confidence, 2),
            indicators_found=indicators,
            details=details,
        )

    def evaluate_batch(
        self,
        results: list[dict[str, Any]],
        payload_class: str,
    ) -> list[PayloadResult]:
        """Evaluate a batch of responses."""
        return [
            self.evaluate(
                response=r.get("response", {}),
                payload_class=payload_class,
                payload=r.get("payload", ""),
                mutation=r.get("mutation", "none"),
            )
            for r in results
        ]

    def _determine_verdict(
        self, indicators: list[str], payload_class: str,
    ) -> tuple[str, float]:
        """Determine verdict and confidence from indicators."""
        if not indicators:
            return "negative", 0.0

        # Strong indicators
        strong = ["time_based_delay", "sql_error_500", "successful_execution"]
        has_strong = any(i in indicators for i in strong)

        if len(indicators) >= 3 or (has_strong and len(indicators) >= 2):
            return "confirmed", min(0.95, 0.5 + len(indicators) * 0.15)
        elif has_strong or len(indicators) >= 2:
            return "likely", min(0.8, 0.3 + len(indicators) * 0.15)
        else:
            return "likely", 0.3
