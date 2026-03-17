"""Discovery behavior analyzer — detects anomalies for novel attack discovery.

MOD-12.7: Analyzes HTTP responses, parameter relationships, state
transitions, and timing to identify behavioral anomalies that may
indicate undiscovered attack surfaces. Unlike the MOD-11.6 behavior
analyzer (which analyzes workflow mutation results), this module
focuses on discovering novel attack opportunities from raw system
behavior.
"""

from __future__ import annotations

__classification__ = "experimental"

import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class BehaviorSignal:
    """A detected behavioral anomaly."""

    signal_id: str
    signal_type: str       # param_reuse | unexpected_reflection | state_leak | timing_anomaly | error_pattern | file_reference | object_reference
    source: str
    confidence: float
    evidence: dict[str, Any] = field(default_factory=dict)
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.signal_id, "type": self.signal_type,
            "source": self.source, "confidence": round(self.confidence, 2),
            "description": self.description,
        }


# ── Detection patterns ──────────────────────────────────────────

_PARAM_REUSE_PATTERNS = [
    r"(?:id|uid|user_id|account)\s*=\s*\d+",
    r"(?:file|path|url|redirect)\s*=",
    r"(?:token|key|secret)\s*=",
    r"(?:cmd|command|exec|run)\s*=",
]

_REFLECTION_INDICATORS = [
    "input_value", "<script", "javascript:", "onerror=",
    r"\\x[0-9a-f]{2}", "%3c", "%22",
]

_STATE_LEAK_INDICATORS = [
    "session_id", "csrf_token", "jwt", "bearer",
    "set-cookie", "x-auth", "internal_ip",
    "debug", "stack_trace", "traceback",
]

_FILE_REFERENCE_INDICATORS = [
    "/etc/", "/var/", "/tmp/", "C:\\\\", ".env", ".git",
    "wp-config", "database.yml", ".htaccess", "web.config",
]

_OBJECT_REFERENCE_INDICATORS = [
    "__class__", "__proto__", "constructor",
    "getClass", "__dict__", "__init__",
]


class DiscoveryBehaviorAnalyzer:
    """Analyzes application behavior for anomaly indicators.

    Usage::

        analyzer = DiscoveryBehaviorAnalyzer()
        signals = analyzer.analyze_response(endpoint, response_data)
    """

    def __init__(self) -> None:
        self._signal_count = 0

    @property
    def signals_generated(self) -> int:
        return self._signal_count

    def analyze_response(
        self,
        endpoint: str,
        response: dict[str, Any],
    ) -> list[BehaviorSignal]:
        """Analyze a single response for behavioral anomalies."""
        signals: list[BehaviorSignal] = []
        body = str(response.get("body", ""))
        headers = response.get("headers", {})
        status = response.get("status_code", 200)

        signals.extend(self._check_param_reuse(endpoint, body))
        signals.extend(self._check_reflections(endpoint, body))
        signals.extend(self._check_state_leaks(endpoint, body, headers))
        signals.extend(self._check_file_references(endpoint, body))
        signals.extend(self._check_object_references(endpoint, body))
        signals.extend(self._check_timing(endpoint, response))
        signals.extend(self._check_error_patterns(endpoint, body, status))

        return signals

    def analyze_batch(
        self,
        responses: list[dict[str, Any]],
    ) -> list[BehaviorSignal]:
        """Analyze multiple responses."""
        all_signals: list[BehaviorSignal] = []
        for resp in responses:
            endpoint = resp.get("endpoint", "unknown")
            all_signals.extend(self.analyze_response(endpoint, resp))
        return all_signals

    def _sig(self, stype: str, source: str, conf: float, desc: str, **evidence) -> BehaviorSignal:
        self._signal_count += 1
        return BehaviorSignal(
            signal_id=f"sig:{self._signal_count}",
            signal_type=stype, source=source,
            confidence=conf, description=desc,
            evidence=evidence,
        )

    def _check_param_reuse(self, ep: str, body: str) -> list[BehaviorSignal]:
        signals = []
        for pattern in _PARAM_REUSE_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                signals.append(self._sig(
                    "param_reuse", ep, 0.6,
                    f"Parameter pattern in response: {pattern}",
                    pattern=pattern,
                ))
        return signals

    def _check_reflections(self, ep: str, body: str) -> list[BehaviorSignal]:
        for indicator in _REFLECTION_INDICATORS:
            if re.search(indicator, body, re.IGNORECASE):
                return [self._sig(
                    "unexpected_reflection", ep, 0.7,
                    f"Potential reflection: {indicator}",
                    indicator=indicator,
                )]
        return []

    def _check_state_leaks(self, ep: str, body: str, headers: dict) -> list[BehaviorSignal]:
        combined = body + " " + " ".join(f"{k}:{v}" for k, v in headers.items())
        for indicator in _STATE_LEAK_INDICATORS:
            if indicator.lower() in combined.lower():
                return [self._sig(
                    "state_leak", ep, 0.65,
                    f"State leak indicator: {indicator}",
                    indicator=indicator,
                )]
        return []

    def _check_file_references(self, ep: str, body: str) -> list[BehaviorSignal]:
        for indicator in _FILE_REFERENCE_INDICATORS:
            if indicator.lower() in body.lower():
                return [self._sig(
                    "file_reference", ep, 0.75,
                    f"File system reference: {indicator}",
                    indicator=indicator,
                )]
        return []

    def _check_object_references(self, ep: str, body: str) -> list[BehaviorSignal]:
        for indicator in _OBJECT_REFERENCE_INDICATORS:
            if indicator in body:
                return [self._sig(
                    "object_reference", ep, 0.7,
                    f"Object/prototype reference: {indicator}",
                    indicator=indicator,
                )]
        return []

    def _check_timing(self, ep: str, response: dict) -> list[BehaviorSignal]:
        elapsed = response.get("elapsed_ms", 0)
        if elapsed > 3000:
            return [self._sig(
                "timing_anomaly", ep, 0.6,
                f"Slow response ({elapsed}ms) — possible timing side-channel",
                elapsed_ms=elapsed,
            )]
        return []

    def _check_error_patterns(self, ep: str, body: str, status: int) -> list[BehaviorSignal]:
        if status >= 500:
            return [self._sig(
                "error_pattern", ep, 0.7,
                f"Server error (HTTP {status}) — potential fault injection vector",
                status_code=status,
            )]
        return []
