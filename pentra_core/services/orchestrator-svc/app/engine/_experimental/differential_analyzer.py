"""Differential analyzer — compares responses across similar requests.

MOD-13.5: Detects differences in status codes, body sizes, error
patterns, and timing across normalized response sets to identify
behavioral anomalies that may indicate vulnerabilities.
"""

from __future__ import annotations

__classification__ = "experimental"

import logging
from dataclasses import dataclass, field
from typing import Any

from app.engine.response_normalizer import NormalizedResponse

logger = logging.getLogger(__name__)


@dataclass
class Differential:
    """A detected difference between response sets."""

    diff_id: str
    diff_type: str          # status_diff | size_diff | hash_diff | timing_diff | error_diff
    endpoint: str
    baseline_value: Any
    anomaly_value: Any
    severity: float         # 0.0–1.0
    description: str

    def to_dict(self) -> dict:
        return {
            "id": self.diff_id, "type": self.diff_type,
            "endpoint": self.endpoint, "severity": round(self.severity, 2),
        }


@dataclass
class DiffResult:
    """Result of a differential analysis."""

    total_compared: int = 0
    differentials: list[Differential] = field(default_factory=list)

    @property
    def anomaly_count(self) -> int:
        return len(self.differentials)

    def to_dict(self) -> dict:
        return {
            "compared": self.total_compared,
            "anomalies": self.anomaly_count,
            "types": list({d.diff_type for d in self.differentials}),
        }


class DifferentialAnalyzer:
    """Compares responses to detect behavioral anomalies.

    Usage::

        analyzer = DifferentialAnalyzer()
        result = analyzer.analyze(baseline_responses, test_responses)
    """

    def __init__(self) -> None:
        self._diff_count = 0

    def analyze(
        self,
        baseline: list[NormalizedResponse],
        test: list[NormalizedResponse],
    ) -> DiffResult:
        """Compare baseline vs test response sets."""
        result = DiffResult(total_compared=len(test))

        # Build baseline profile
        profile = self._build_profile(baseline)

        for resp in test:
            diffs = self._compare(resp, profile)
            result.differentials.extend(diffs)

        result.differentials.sort(key=lambda d: d.severity, reverse=True)
        logger.info("DifferentialAnalyzer: %d anomalies from %d comparisons",
                     result.anomaly_count, result.total_compared)
        return result

    def analyze_within(self, responses: list[NormalizedResponse]) -> DiffResult:
        """Analyze within a single response set for internal inconsistencies."""
        if len(responses) < 2:
            return DiffResult()
        baseline = responses[:len(responses) // 2]
        test = responses[len(responses) // 2:]
        return self.analyze(baseline, test)

    def _build_profile(self, responses: list[NormalizedResponse]) -> dict[str, Any]:
        """Build a statistical profile from baseline responses."""
        if not responses:
            return {}
        statuses = [r.status_code for r in responses]
        lengths = [r.body_length for r in responses]
        timings = [r.elapsed_ms for r in responses]
        hashes = [r.normalized_hash for r in responses]

        return {
            "common_status": max(set(statuses), key=statuses.count),
            "avg_length": sum(lengths) / len(lengths),
            "length_std": self._std(lengths),
            "avg_timing": sum(timings) / len(timings),
            "timing_std": self._std(timings),
            "common_hashes": set(hashes),
            "count": len(responses),
        }

    def _compare(self, resp: NormalizedResponse, profile: dict) -> list[Differential]:
        diffs: list[Differential] = []
        if not profile:
            return diffs

        # 1 — Status code difference
        if resp.status_code != profile["common_status"]:
            self._diff_count += 1
            diffs.append(Differential(
                diff_id=f"diff:{self._diff_count}", diff_type="status_diff",
                endpoint=resp.endpoint,
                baseline_value=profile["common_status"],
                anomaly_value=resp.status_code,
                severity=0.8, description=f"Status {resp.status_code} vs baseline {profile['common_status']}",
            ))

        # 2 — Body size anomaly (>2 std deviations)
        length_std = max(profile["length_std"], 10)
        if abs(resp.body_length - profile["avg_length"]) > 2 * length_std:
            self._diff_count += 1
            diffs.append(Differential(
                diff_id=f"diff:{self._diff_count}", diff_type="size_diff",
                endpoint=resp.endpoint,
                baseline_value=int(profile["avg_length"]),
                anomaly_value=resp.body_length,
                severity=0.6, description=f"Body size {resp.body_length} vs avg {int(profile['avg_length'])}",
            ))

        # 3 — Body hash mismatch
        if resp.normalized_hash not in profile["common_hashes"]:
            self._diff_count += 1
            diffs.append(Differential(
                diff_id=f"diff:{self._diff_count}", diff_type="hash_diff",
                endpoint=resp.endpoint,
                baseline_value=list(profile["common_hashes"])[:3],
                anomaly_value=resp.normalized_hash,
                severity=0.5, description="Response body differs from all baselines",
            ))

        # 4 — Timing anomaly (>3 std deviations)
        timing_std = max(profile["timing_std"], 50)
        if abs(resp.elapsed_ms - profile["avg_timing"]) > 3 * timing_std:
            self._diff_count += 1
            diffs.append(Differential(
                diff_id=f"diff:{self._diff_count}", diff_type="timing_diff",
                endpoint=resp.endpoint,
                baseline_value=round(profile["avg_timing"], 1),
                anomaly_value=resp.elapsed_ms,
                severity=0.7, description=f"Timing {resp.elapsed_ms}ms vs avg {profile['avg_timing']:.0f}ms",
            ))

        # 5 — Error pattern (5xx in test when baseline is 2xx)
        if resp.status_code >= 500 and profile["common_status"] < 400:
            self._diff_count += 1
            diffs.append(Differential(
                diff_id=f"diff:{self._diff_count}", diff_type="error_diff",
                endpoint=resp.endpoint,
                baseline_value=profile["common_status"],
                anomaly_value=resp.status_code,
                severity=0.9, description=f"Server error {resp.status_code} on normally successful endpoint",
            ))

        return diffs

    @staticmethod
    def _std(vals: list[float]) -> float:
        if len(vals) < 2:
            return 0
        mean = sum(vals) / len(vals)
        return (sum((v - mean) ** 2 for v in vals) / len(vals)) ** 0.5
