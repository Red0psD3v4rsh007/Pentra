"""Attack hypothesis generator — generates novel attack ideas from behavioral signals.

MOD-12.7: Converts behavioral anomalies detected by the discovery
behavior analyzer into novel attack hypotheses that can be evaluated
by the hypothesis graph manager and executed by the experiment engine.
"""

from __future__ import annotations

__classification__ = "experimental"

import logging
from dataclasses import dataclass, field
from typing import Any

from app.engine.discovery_behavior_analyzer import BehaviorSignal
from app.engine.hypothesis_generator import Hypothesis

logger = logging.getLogger(__name__)


@dataclass
class AttackIdea:
    """A novel attack idea derived from behavioral analysis."""

    idea_id: str
    idea_type: str          # param_fs_interaction | object_injection | protocol_misuse | state_abuse | reflection_exploit | timing_exploit | error_fault
    source_signal: BehaviorSignal
    description: str
    experiment_type: str     # protocol_mutation | sequence_mutation | state_mutation | param_combination
    confidence: float
    risk_potential: float

    def to_dict(self) -> dict:
        return {
            "id": self.idea_id, "type": self.idea_type,
            "experiment": self.experiment_type,
            "confidence": round(self.confidence, 2),
        }


# ── Signal-to-idea mapping rules ────────────────────────────────

_IDEA_RULES: list[dict[str, Any]] = [
    {
        "signal_type": "param_reuse",
        "idea_type": "param_fs_interaction",
        "experiment": "param_combination",
        "desc": "Parameter reuse detected — test parameter-filesystem interaction",
        "risk": 0.7,
    },
    {
        "signal_type": "unexpected_reflection",
        "idea_type": "reflection_exploit",
        "experiment": "param_combination",
        "desc": "Input reflection detected — test for novel injection vectors",
        "risk": 0.8,
    },
    {
        "signal_type": "state_leak",
        "idea_type": "state_abuse",
        "experiment": "state_mutation",
        "desc": "State leak detected — test session/state manipulation attacks",
        "risk": 0.75,
    },
    {
        "signal_type": "file_reference",
        "idea_type": "param_fs_interaction",
        "experiment": "param_combination",
        "desc": "File reference detected — test path traversal and file inclusion",
        "risk": 0.85,
    },
    {
        "signal_type": "object_reference",
        "idea_type": "object_injection",
        "experiment": "protocol_mutation",
        "desc": "Object reference detected — test prototype pollution / deserialization",
        "risk": 0.8,
    },
    {
        "signal_type": "timing_anomaly",
        "idea_type": "timing_exploit",
        "experiment": "sequence_mutation",
        "desc": "Timing anomaly detected — test time-based blind injection",
        "risk": 0.6,
    },
    {
        "signal_type": "error_pattern",
        "idea_type": "error_fault",
        "experiment": "param_combination",
        "desc": "Error pattern detected — test fault injection and error-based extraction",
        "risk": 0.7,
    },
]


class AttackHypothesisGenerator:
    """Generates novel attack hypotheses from behavioral signals.

    Usage::

        gen = AttackHypothesisGenerator()
        ideas = gen.generate_from_signals(signals)
        hypotheses = gen.to_hypotheses(ideas)
    """

    def __init__(self) -> None:
        self._idea_count = 0

    def generate_from_signals(self, signals: list[BehaviorSignal]) -> list[AttackIdea]:
        """Convert behavioral signals into attack ideas."""
        ideas: list[AttackIdea] = []

        for signal in signals:
            for rule in _IDEA_RULES:
                if rule["signal_type"] == signal.signal_type:
                    self._idea_count += 1
                    ideas.append(AttackIdea(
                        idea_id=f"idea:{self._idea_count}",
                        idea_type=rule["idea_type"],
                        source_signal=signal,
                        description=rule["desc"],
                        experiment_type=rule["experiment"],
                        confidence=signal.confidence * 0.8,
                        risk_potential=rule["risk"],
                    ))

        ideas.sort(key=lambda i: i.risk_potential, reverse=True)
        logger.info("AttackHypothesisGenerator: %d ideas from %d signals",
                     len(ideas), len(signals))
        return ideas

    def to_hypotheses(self, ideas: list[AttackIdea]) -> list[Hypothesis]:
        """Convert attack ideas into pipeline hypotheses."""
        hypotheses: list[Hypothesis] = []
        for idea in ideas:
            hypotheses.append(Hypothesis(
                hypothesis_id=f"discovery:{idea.idea_id}",
                hypothesis_type=f"discovery_{idea.idea_type}",
                target_node_id=idea.source_signal.source,
                target_label=idea.source_signal.source,
                description=idea.description,
                tool="custom_experiment",
                worker_family="exploit",
                config={
                    "experiment_type": idea.experiment_type,
                    "idea_type": idea.idea_type,
                    "source_signal": idea.source_signal.signal_type,
                    "risk_potential": idea.risk_potential,
                    "no_persist": True,
                },
                required_artifacts=[],
                estimated_complexity=int(idea.risk_potential * 10),
            ))
        return hypotheses
