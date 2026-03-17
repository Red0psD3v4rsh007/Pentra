"""Hypothesis generator — generates attack hypotheses from graph and artifacts.

MOD-09: Inspects attack graph nodes and artifacts to produce hypotheses
about unexplored attack opportunities.

Hypothesis types:
  - endpoint_fuzz     — parameter tampering, IDOR, injection
  - route_guess       — hidden endpoint discovery
  - credential_reuse  — try leaked creds on other services
  - service_pivot     — lateral movement between services
  - api_discovery     — undocumented API endpoint enumeration
  - param_mutation    — query/body parameter manipulation
"""

from __future__ import annotations

__classification__ = "runtime_optional"

import logging
from dataclasses import dataclass, field
from typing import Any

from app.engine.attack_graph_builder import AttackGraph, AttackNode

logger = logging.getLogger(__name__)


@dataclass
class Hypothesis:
    """A single attack hypothesis to explore."""

    hypothesis_id: str
    hypothesis_type: str     # endpoint_fuzz | route_guess | credential_reuse | service_pivot | api_discovery | param_mutation
    target_node_id: str      # graph node to test
    target_label: str
    description: str
    tool: str                # tool to execute
    worker_family: str       # worker family
    config: dict = field(default_factory=dict)
    required_artifacts: list[str] = field(default_factory=list)
    estimated_complexity: int = 1  # 1=simple, 2=moderate, 3=complex
    timeout_seconds: int = 300


# ── Hypothesis rule definitions ──────────────────────────────────────

@dataclass(frozen=True)
class HypothesisRule:
    """Defines when and how to generate a hypothesis."""

    name: str
    trigger_node_type: str     # graph node type that triggers this rule
    trigger_filter: dict       # property filters on trigger node
    hypothesis_type: str
    tool: str
    worker_family: str
    description_template: str
    complexity: int
    timeout: int


HYPOTHESIS_RULES: list[HypothesisRule] = [
    # 1 — Endpoint with parameters → IDOR / parameter tampering
    HypothesisRule(
        name="endpoint_param_fuzz",
        trigger_node_type="endpoint",
        trigger_filter={},
        hypothesis_type="endpoint_fuzz",
        tool="custom_poc",
        worker_family="exploit",
        description_template="Fuzz parameters on {label}",
        complexity=1,
        timeout=300,
    ),

    # 2 — Endpoint → route guessing for hidden paths
    HypothesisRule(
        name="route_discovery",
        trigger_node_type="endpoint",
        trigger_filter={},
        hypothesis_type="route_guess",
        tool="custom_poc",
        worker_family="web",
        description_template="Discover hidden routes near {label}",
        complexity=2,
        timeout=600,
    ),

    # 3 — Credential → reuse across services
    HypothesisRule(
        name="credential_reuse",
        trigger_node_type="credential",
        trigger_filter={},
        hypothesis_type="credential_reuse",
        tool="custom_poc",
        worker_family="exploit",
        description_template="Attempt credential reuse with {label}",
        complexity=1,
        timeout=300,
    ),

    # 4 — Service → pivot to adjacent services
    HypothesisRule(
        name="service_pivot",
        trigger_node_type="service",
        trigger_filter={},
        hypothesis_type="service_pivot",
        tool="custom_poc",
        worker_family="network",
        description_template="Explore pivot opportunities from {label}",
        complexity=2,
        timeout=600,
    ),

    # 5 — Asset → API discovery on discovered hosts
    HypothesisRule(
        name="api_discovery",
        trigger_node_type="asset",
        trigger_filter={},
        hypothesis_type="api_discovery",
        tool="custom_poc",
        worker_family="web",
        description_template="Enumerate API endpoints on {label}",
        complexity=2,
        timeout=600,
    ),

    # 6 — Vulnerability → parameter mutation testing
    HypothesisRule(
        name="param_mutation",
        trigger_node_type="vulnerability",
        trigger_filter={},
        hypothesis_type="param_mutation",
        tool="custom_poc",
        worker_family="exploit",
        description_template="Mutate parameters around {label}",
        complexity=1,
        timeout=300,
    ),
]


class HypothesisGenerator:
    """Generates attack hypotheses from the attack graph.

    Usage::

        gen = HypothesisGenerator(graph)
        hypotheses = gen.generate()
    """

    def __init__(self, graph: AttackGraph, rules: list[HypothesisRule] | None = None) -> None:
        self._graph = graph
        self._rules = rules if rules is not None else HYPOTHESIS_RULES

    def generate(self, *, max_per_rule: int = 10) -> list[Hypothesis]:
        """Generate hypotheses by matching rules against graph nodes."""
        hypotheses: list[Hypothesis] = []

        nodes_by_type: dict[str, list[AttackNode]] = {}
        for node in self._graph.nodes.values():
            if node.node_type != "entrypoint":
                nodes_by_type.setdefault(node.node_type, []).append(node)

        for rule in self._rules:
            candidates = nodes_by_type.get(rule.trigger_node_type, [])
            count = 0

            for node in candidates:
                if count >= max_per_rule:
                    break
                if not self._matches_filter(node, rule.trigger_filter):
                    continue

                h = Hypothesis(
                    hypothesis_id=f"hyp:{rule.name}:{node.id}",
                    hypothesis_type=rule.hypothesis_type,
                    target_node_id=node.id,
                    target_label=node.label,
                    description=rule.description_template.format(label=node.label),
                    tool=rule.tool,
                    worker_family=rule.worker_family,
                    config={
                        "rule": rule.name,
                        "target_type": node.node_type,
                        "artifact_type": node.properties.get("artifact_type", ""),
                        "no_persist": True,
                    },
                    required_artifacts=[node.properties.get("artifact_type", "")],
                    estimated_complexity=rule.complexity,
                    timeout_seconds=rule.timeout,
                )
                hypotheses.append(h)
                count += 1

        logger.info("Generated %d hypotheses from %d rules", len(hypotheses), len(self._rules))
        return hypotheses

    def _matches_filter(self, node: AttackNode, filters: dict) -> bool:
        if not filters:
            return True
        for key, value in filters.items():
            if key == "artifact_type_contains":
                atype = str(node.properties.get("artifact_type", "")).lower()
                if not any(v.lower() in atype for v in value):
                    return False
            else:
                if node.properties.get(key) != value:
                    return False
        return True
