"""Pattern chain generator — converts composed pattern chains into hypotheses.

MOD-09.6: Takes PatternChain objects from the PatternReasoner and
produces ordered Hypothesis sequences that the ExplorationEngine
can score, budget-check, and convert to dynamic scan_nodes.
"""

from __future__ import annotations

__classification__ = "runtime_optional"

import logging
from typing import Any

from app.engine.attack_graph_builder import AttackGraph
from app.engine.hypothesis_generator import Hypothesis
from app.engine.pattern_reasoner import PatternChain

logger = logging.getLogger(__name__)


class PatternChainGenerator:
    """Converts composed pattern chains into exploration hypotheses.

    Usage::

        gen = PatternChainGenerator(graph)
        hypotheses = gen.generate(chains)
    """

    def __init__(self, graph: AttackGraph) -> None:
        self._graph = graph

    def generate(
        self,
        chains: list[PatternChain],
        *,
        max_hypotheses_per_chain: int = 3,
    ) -> list[Hypothesis]:
        """Convert pattern chains into ordered exploration hypotheses."""
        hypotheses: list[Hypothesis] = []

        for chain in chains:
            chain_hyps = self._generate_from_chain(
                chain, max_per_chain=max_hypotheses_per_chain,
            )
            hypotheses.extend(chain_hyps)

        logger.info(
            "PatternChainGenerator: %d hypotheses from %d chains",
            len(hypotheses), len(chains),
        )
        return hypotheses

    def _generate_from_chain(
        self,
        chain: PatternChain,
        *,
        max_per_chain: int,
    ) -> list[Hypothesis]:
        """Generate hypotheses from a single pattern chain."""
        results: list[Hypothesis] = []

        for step_idx, pattern in enumerate(chain.patterns):
            if len(results) >= max_per_chain:
                break

            # Find a target node for this pattern step
            target_node_id, target_label = self._find_target(pattern)
            if target_node_id is None:
                continue

            for action in pattern.actions:
                if len(results) >= max_per_chain:
                    break

                depends_description = ""
                if step_idx > 0:
                    prev = chain.patterns[step_idx - 1]
                    link = chain.links[step_idx - 1] if step_idx - 1 < len(chain.links) else ""
                    depends_description = f" (after {prev.name} via {link})"

                h = Hypothesis(
                    hypothesis_id=f"chain:{chain.chain_id}:step{step_idx}:{action.tool}",
                    hypothesis_type=f"chain_{chain.chain_id}",
                    target_node_id=target_node_id,
                    target_label=target_label,
                    description=(
                        f"{action.description} "
                        f"[chain:{pattern.name}{depends_description}]"
                    ),
                    tool=action.tool,
                    worker_family=action.worker_family,
                    config={
                        "chain_id": chain.chain_id,
                        "chain_step": step_idx,
                        "chain_depth": chain.depth,
                        "pattern_name": pattern.name,
                        "pattern_domain": pattern.domain,
                        "chain_confidence": chain.total_confidence,
                        "impact": pattern.impact,
                        "no_persist": True,
                    },
                    required_artifacts=[p.artifact_type for p in pattern.preconditions],
                    estimated_complexity=min(3, chain.depth),
                    timeout_seconds=action.timeout,
                )
                results.append(h)

        return results

    def _find_target(self, pattern) -> tuple[str | None, str]:
        """Find a suitable target node for a pattern step."""
        # Look for nodes matching any precondition type
        for precond in pattern.preconditions:
            type_map = {
                "endpoint": "endpoint", "service": "service",
                "asset": "asset", "vulnerability": "vulnerability",
                "credential": "credential", "privilege": "privilege",
            }
            node_type = type_map.get(precond.artifact_type)
            if node_type is None:
                continue

            for node in self._graph.nodes.values():
                if node.node_type == node_type and node.node_type != "entrypoint":
                    return node.id, node.label

        return None, ""
