"""Pattern reasoner — composes multi-step attack chains from patterns.

MOD-09.6: Analyzes the artifact graph and pattern graph together to
detect when multiple patterns can be chained into compound attack paths.

Example reasoning:
  artifact: credential + artifact: ssh_service
    → credential_reuse_ssh matched
    → impact: shell_access
      → shell_access enables: privilege_escalation patterns
        → chain: credential_reuse_ssh → priv_esc
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from app.engine.attack_graph_builder import AttackGraph
from app.engine.pattern_graph_builder import PatternGraph, PatternGraphBuilder
from app.engine.pattern_matcher import PatternMatch, PatternMatcher
from app.knowledge.pattern_registry import AttackPattern, PatternRegistry

logger = logging.getLogger(__name__)


@dataclass
class PatternChain:
    """A multi-step attack chain composed from linked patterns."""

    chain_id: str
    patterns: list[AttackPattern]
    links: list[str]           # impact type connecting each step
    total_confidence: float    # product of match confidences
    depth: int

    def to_dict(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "depth": self.depth,
            "confidence": self.total_confidence,
            "steps": [p.name for p in self.patterns],
            "links": self.links,
        }


_MAX_CHAIN_DEPTH = 4
_MAX_CHAINS = 20


class PatternReasoner:
    """Composes multi-step attack chains by reasoning over patterns.

    Usage::

        reasoner = PatternReasoner(registry, artifact_graph)
        chains = reasoner.reason()
    """

    def __init__(
        self,
        registry: PatternRegistry,
        artifact_graph: AttackGraph,
        *,
        max_depth: int = _MAX_CHAIN_DEPTH,
        max_chains: int = _MAX_CHAINS,
    ) -> None:
        self._registry = registry
        self._artifact_graph = artifact_graph
        self._max_depth = max_depth
        self._max_chains = max_chains

        # Build pattern relationship graph
        pg_builder = PatternGraphBuilder(registry)
        self._pattern_graph = pg_builder.build()

        # Match patterns against current artifacts
        matcher = PatternMatcher(registry, artifact_graph)
        self._matches = matcher.match_all()
        self._match_map = {m.pattern.name: m for m in self._matches}

    @property
    def pattern_graph(self) -> PatternGraph:
        return self._pattern_graph

    @property
    def initial_matches(self) -> list[PatternMatch]:
        return self._matches

    def reason(self) -> list[PatternChain]:
        """Discover multi-step attack chains.

        Starts from currently matched patterns and extends chains
        via the pattern graph relationships.
        """
        chains: list[PatternChain] = []
        chain_counter = 0

        for match in self._matches:
            if chain_counter >= self._max_chains:
                break

            # Explore chains starting from this matched pattern
            found = self._explore_chains(
                current=[match.pattern],
                links=[],
                confidence=match.confidence,
                visited={match.pattern.name},
            )

            for chain_patterns, chain_links, confidence in found:
                if chain_counter >= self._max_chains:
                    break
                if len(chain_patterns) < 2:
                    continue  # Single-step chains are just regular matches

                chain_counter += 1
                chains.append(PatternChain(
                    chain_id=f"pchain:{chain_counter}:{chain_patterns[0].name}",
                    patterns=chain_patterns,
                    links=chain_links,
                    total_confidence=round(confidence, 3),
                    depth=len(chain_patterns),
                ))

        # Sort by confidence descending
        chains.sort(key=lambda c: c.total_confidence, reverse=True)

        logger.info(
            "Pattern reasoning: %d chains from %d initial matches",
            len(chains), len(self._matches),
        )
        return chains

    def _explore_chains(
        self,
        current: list[AttackPattern],
        links: list[str],
        confidence: float,
        visited: set[str],
    ) -> list[tuple[list[AttackPattern], list[str], float]]:
        """DFS exploration of pattern chains."""
        results: list[tuple[list[AttackPattern], list[str], float]] = []

        if len(current) >= 2:
            results.append((list(current), list(links), confidence))

        if len(current) >= self._max_depth:
            return results

        last_pattern = current[-1]
        successors = self._pattern_graph.get_successors(last_pattern.name)

        for succ_name in successors:
            if succ_name in visited:
                continue

            succ_pattern = self._registry.get_pattern(succ_name)
            if succ_pattern is None:
                continue

            # Determine confidence for the successor
            succ_match = self._match_map.get(succ_name)
            if succ_match:
                succ_confidence = succ_match.confidence
            else:
                # Pattern not directly matched but reachable via chain
                succ_confidence = 0.5  # speculative

            # Find the link type
            link_type = self._find_link_type(last_pattern.name, succ_name)

            new_visited = visited | {succ_name}
            sub_results = self._explore_chains(
                current=current + [succ_pattern],
                links=links + [link_type],
                confidence=confidence * succ_confidence,
                visited=new_visited,
            )
            results.extend(sub_results)

        return results

    def _find_link_type(self, source: str, target: str) -> str:
        """Find the impact type connecting two patterns."""
        for edge in self._pattern_graph.edges:
            if edge.source_pattern == source and edge.target_pattern == target:
                return edge.link_type
        return "unknown"
