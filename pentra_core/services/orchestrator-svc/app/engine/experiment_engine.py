"""Experiment engine — runs exploratory tests for novel attack discovery.

MOD-12.7: Executes experimental attack tests that do not match known
patterns, using protocol mutation, sequence mutation, state mutation,
and unexpected parameter combinations. Results feed back into the
hypothesis graph for iterative discovery.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from app.engine.attack_hypothesis_generator import AttackIdea
from app.engine.discovery_behavior_analyzer import BehaviorSignal

logger = logging.getLogger(__name__)


@dataclass
class Experiment:
    """A single exploratory test."""

    experiment_id: str
    experiment_type: str     # protocol_mutation | sequence_mutation | state_mutation | param_combination
    target: str
    mutations: list[dict[str, Any]] = field(default_factory=list)
    status: str = "pending"  # pending | running | completed | failed
    results: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.experiment_id, "type": self.experiment_type,
            "target": self.target, "status": self.status,
            "mutations": len(self.mutations),
        }


@dataclass
class ExperimentResult:
    """Aggregate result of experiment execution."""

    total_experiments: int = 0
    completed: int = 0
    signals_discovered: int = 0
    new_ideas: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "total": self.total_experiments,
            "completed": self.completed,
            "signals": self.signals_discovered,
            "new_ideas": len(self.new_ideas),
        }


# ── Mutation generators ─────────────────────────────────────────

_PROTOCOL_MUTATIONS = [
    {"mutation": "method_swap", "desc": "Swap HTTP method (GET↔POST↔PUT↔DELETE)"},
    {"mutation": "content_type_swap", "desc": "Change content type (json↔xml↔form)"},
    {"mutation": "encoding_change", "desc": "Change encoding (utf8↔utf16↔latin1)"},
    {"mutation": "version_downgrade", "desc": "Downgrade protocol version"},
]

_SEQUENCE_MUTATIONS = [
    {"mutation": "request_replay", "desc": "Replay request with modified nonce"},
    {"mutation": "order_reversal", "desc": "Reverse multi-step request order"},
    {"mutation": "parallel_execution", "desc": "Send concurrent duplicate requests"},
    {"mutation": "delayed_retry", "desc": "Retry after deliberate delay"},
]

_STATE_MUTATIONS = [
    {"mutation": "session_swap", "desc": "Swap session tokens between requests"},
    {"mutation": "cookie_removal", "desc": "Remove specific cookies"},
    {"mutation": "header_injection", "desc": "Inject unexpected headers"},
    {"mutation": "csrf_bypass", "desc": "Attempt CSRF token bypass"},
]

_PARAM_COMBINATIONS = [
    {"mutation": "type_confusion", "desc": "Send array where string expected"},
    {"mutation": "boundary_values", "desc": "Send min/max/negative/zero values"},
    {"mutation": "null_injection", "desc": "Inject null bytes in parameters"},
    {"mutation": "unicode_smuggling", "desc": "Use unicode normalization bypass"},
]

_MUTATION_MAP = {
    "protocol_mutation": _PROTOCOL_MUTATIONS,
    "sequence_mutation": _SEQUENCE_MUTATIONS,
    "state_mutation": _STATE_MUTATIONS,
    "param_combination": _PARAM_COMBINATIONS,
}


class ExperimentEngine:
    """Runs exploratory attack experiments.

    Usage::

        engine = ExperimentEngine()
        experiments = engine.create_experiments(ideas)
        result = engine.run(experiments)
    """

    def __init__(self) -> None:
        self._exp_count = 0

    def create_experiments(self, ideas: list[AttackIdea]) -> list[Experiment]:
        """Create experiments from attack ideas."""
        experiments: list[Experiment] = []
        for idea in ideas:
            mutations = _MUTATION_MAP.get(idea.experiment_type, _PARAM_COMBINATIONS)
            self._exp_count += 1
            experiments.append(Experiment(
                experiment_id=f"exp:{self._exp_count}",
                experiment_type=idea.experiment_type,
                target=idea.source_signal.source,
                mutations=list(mutations),
            ))
        logger.info("ExperimentEngine: created %d experiments from %d ideas",
                     len(experiments), len(ideas))
        return experiments

    def run(self, experiments: list[Experiment]) -> ExperimentResult:
        """Execute experiments (simulated in testing mode)."""
        result = ExperimentResult(total_experiments=len(experiments))

        for exp in experiments:
            exp.status = "running"
            signals = self._execute(exp)
            exp.status = "completed"
            exp.results = {
                "signals": len(signals),
                "mutations_tested": len(exp.mutations),
            }
            result.completed += 1
            result.signals_discovered += len(signals)
            for sig in signals:
                result.new_ideas.append(sig.signal_type)

        logger.info("ExperimentEngine: %d/%d completed, %d signals discovered",
                     result.completed, result.total_experiments, result.signals_discovered)
        return result

    def _execute(self, exp: Experiment) -> list[BehaviorSignal]:
        """Execute a single experiment (returns synthetic signals for now)."""
        signals: list[BehaviorSignal] = []

        # In production, this would make real HTTP requests.
        # For now, simulate signal generation based on experiment type.
        if exp.experiment_type == "protocol_mutation":
            signals.append(BehaviorSignal(
                signal_id=f"exp_sig:{exp.experiment_id}",
                signal_type="error_pattern",
                source=exp.target,
                confidence=0.5,
                description="Protocol mutation triggered unexpected response",
            ))
        elif exp.experiment_type == "state_mutation":
            signals.append(BehaviorSignal(
                signal_id=f"exp_sig:{exp.experiment_id}",
                signal_type="state_leak",
                source=exp.target,
                confidence=0.55,
                description="State mutation revealed session information",
            ))
        elif exp.experiment_type == "param_combination":
            signals.append(BehaviorSignal(
                signal_id=f"exp_sig:{exp.experiment_id}",
                signal_type="param_reuse",
                source=exp.target,
                confidence=0.45,
                description="Parameter combination triggered unexpected behavior",
            ))

        return signals
