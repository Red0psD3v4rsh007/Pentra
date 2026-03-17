"""Anomaly detector — converts differential anomalies into hypotheses.

MOD-13.5: Maps detected response differentials into vulnerability
hypotheses (authorization anomaly, logic inconsistency, response
mutation) and inserts them into the Hypothesis Graph Manager.
"""

from __future__ import annotations

__classification__ = "experimental"

import logging
from dataclasses import dataclass, field
from typing import Any

from app.engine.differential_analyzer import Differential, DiffResult
from app.engine.hypothesis_generator import Hypothesis

logger = logging.getLogger(__name__)


@dataclass
class Anomaly:
    """A behavioral anomaly derived from differential analysis."""

    anomaly_id: str
    anomaly_type: str       # auth_anomaly | logic_inconsistency | response_mutation | timing_side_channel | error_injection
    source_diff: Differential
    confidence: float
    hypothesis_type: str
    description: str

    def to_dict(self) -> dict:
        return {
            "id": self.anomaly_id, "type": self.anomaly_type,
            "confidence": round(self.confidence, 2),
        }


# ── Diff-to-anomaly mapping ────────────────────────────────────

_ANOMALY_MAP: dict[str, dict[str, Any]] = {
    "status_diff": {
        "anomaly_type": "auth_anomaly",
        "hypothesis": "differential_auth_bypass",
        "desc": "Status code difference suggests authorization inconsistency",
    },
    "size_diff": {
        "anomaly_type": "logic_inconsistency",
        "hypothesis": "differential_data_leak",
        "desc": "Body size anomaly suggests unexpected data exposure",
    },
    "hash_diff": {
        "anomaly_type": "response_mutation",
        "hypothesis": "differential_response_mutation",
        "desc": "Response body differs unexpectedly from baseline",
    },
    "timing_diff": {
        "anomaly_type": "timing_side_channel",
        "hypothesis": "differential_timing_attack",
        "desc": "Timing anomaly may enable side-channel exploitation",
    },
    "error_diff": {
        "anomaly_type": "error_injection",
        "hypothesis": "differential_fault_injection",
        "desc": "Server error on stable endpoint suggests fault injection vector",
    },
}


class AnomalyDetector:
    """Converts differentials into anomalies and hypotheses.

    Usage::

        detector = AnomalyDetector()
        anomalies = detector.detect(diff_result)
        hypotheses = detector.to_hypotheses(anomalies)
    """

    def __init__(self) -> None:
        self._anomaly_count = 0

    def detect(self, result: DiffResult) -> list[Anomaly]:
        """Convert differentials into anomalies."""
        anomalies: list[Anomaly] = []

        for diff in result.differentials:
            mapping = _ANOMALY_MAP.get(diff.diff_type)
            if not mapping:
                continue
            self._anomaly_count += 1
            anomalies.append(Anomaly(
                anomaly_id=f"anomaly:{self._anomaly_count}",
                anomaly_type=mapping["anomaly_type"],
                source_diff=diff,
                confidence=diff.severity * 0.9,
                hypothesis_type=mapping["hypothesis"],
                description=mapping["desc"],
            ))

        anomalies.sort(key=lambda a: a.confidence, reverse=True)
        logger.info("AnomalyDetector: %d anomalies from %d differentials",
                     len(anomalies), len(result.differentials))
        return anomalies

    def to_hypotheses(self, anomalies: list[Anomaly]) -> list[Hypothesis]:
        """Convert anomalies into pipeline hypotheses."""
        hypotheses: list[Hypothesis] = []
        for anomaly in anomalies:
            hypotheses.append(Hypothesis(
                hypothesis_id=f"diff_hyp:{anomaly.anomaly_id}",
                hypothesis_type=anomaly.hypothesis_type,
                target_node_id=anomaly.source_diff.endpoint,
                target_label=anomaly.source_diff.endpoint,
                description=anomaly.description,
                tool="custom_differential",
                worker_family="exploit",
                config={
                    "anomaly_type": anomaly.anomaly_type,
                    "diff_type": anomaly.source_diff.diff_type,
                    "baseline_value": str(anomaly.source_diff.baseline_value),
                    "anomaly_value": str(anomaly.source_diff.anomaly_value),
                    "no_persist": True,
                },
                required_artifacts=[],
                estimated_complexity=int(anomaly.confidence * 10),
            ))
        return hypotheses

    def summary(self, anomalies: list[Anomaly]) -> dict[str, Any]:
        by_type: dict[str, int] = {}
        for a in anomalies:
            by_type[a.anomaly_type] = by_type.get(a.anomaly_type, 0) + 1
        return {"total": len(anomalies), "by_type": by_type}
