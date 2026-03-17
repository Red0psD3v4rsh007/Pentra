"""Heuristic matcher — matches vulnerability heuristics against graph artifacts.

MOD-11: Analyzes endpoints and services in the attack graph to detect
preconditions that indicate potential vulnerabilities discoverable
through heuristic testing.
"""

from __future__ import annotations

__classification__ = "runtime_optional"

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from app.engine.attack_graph_builder import AttackGraph, AttackNode

logger = logging.getLogger(__name__)

_HEURISTICS_PATH = Path(__file__).parent.parent / "knowledge" / "heuristics.yaml"


@dataclass
class HeuristicDef:
    """A structured heuristic definition loaded from YAML."""

    name: str
    description: str
    category: str
    confidence: float
    priority: str
    node_type: str           # endpoint | service
    indicators: list[str]    # label substrings that trigger this heuristic
    actions: list[dict]
    impact: list[str]
    vulnerability_class: str


@dataclass
class HeuristicMatch:
    """Result of a heuristic matching against a graph node."""

    heuristic: HeuristicDef
    matched_node_id: str
    matched_label: str
    matched_indicators: list[str]  # which indicators matched

    def to_dict(self) -> dict:
        return {
            "heuristic_name": self.heuristic.name,
            "category": self.heuristic.category,
            "node_id": self.matched_node_id,
            "matched_indicators": self.matched_indicators,
        }


class HeuristicMatcher:
    """Matches vulnerability heuristics against graph nodes.

    Usage::

        matcher = HeuristicMatcher(graph)
        matches = matcher.match_all()
    """

    def __init__(
        self,
        graph: AttackGraph,
        *,
        heuristics_path: Path | str | None = None,
    ) -> None:
        self._graph = graph
        self._heuristics_path = Path(heuristics_path) if heuristics_path else _HEURISTICS_PATH
        self._heuristics: list[HeuristicDef] = []
        self._load()

    @property
    def heuristics(self) -> list[HeuristicDef]:
        return list(self._heuristics)

    def _load(self) -> None:
        """Load heuristic definitions from YAML."""
        if not self._heuristics_path.exists():
            logger.warning("Heuristics file not found: %s", self._heuristics_path)
            return

        with open(self._heuristics_path) as f:
            data = yaml.safe_load(f)

        if not data or "heuristics" not in data:
            return

        for raw in data["heuristics"]:
            try:
                h = HeuristicDef(
                    name=raw["name"],
                    description=raw.get("description", ""),
                    category=raw.get("category", "unknown"),
                    confidence=float(raw.get("confidence", 0.5)),
                    priority=raw.get("priority", "medium"),
                    node_type=raw.get("preconditions", {}).get("node_type", "endpoint"),
                    indicators=raw.get("preconditions", {}).get("indicators", []),
                    actions=raw.get("actions", []),
                    impact=raw.get("impact", []),
                    vulnerability_class=raw.get("vulnerability_class", "unknown"),
                )
                self._heuristics.append(h)
            except (KeyError, TypeError) as e:
                logger.warning("Failed to parse heuristic: %s", e)

        logger.info("Loaded %d heuristic definitions", len(self._heuristics))

    def match_all(self) -> list[HeuristicMatch]:
        """Match all heuristics against graph nodes.

        Returns list of matches sorted by confidence descending.
        """
        matches: list[HeuristicMatch] = []

        for heuristic in self._heuristics:
            for node in self._graph.nodes.values():
                if node.node_type == "entrypoint":
                    continue
                if node.node_type != heuristic.node_type:
                    continue

                matched_indicators = self._check_indicators(node, heuristic.indicators)
                if matched_indicators:
                    matches.append(HeuristicMatch(
                        heuristic=heuristic,
                        matched_node_id=node.id,
                        matched_label=node.label,
                        matched_indicators=matched_indicators,
                    ))

        matches.sort(key=lambda m: m.heuristic.confidence, reverse=True)

        logger.info(
            "Heuristic matching: %d matches from %d heuristics",
            len(matches), len(self._heuristics),
        )
        return matches

    def _check_indicators(self, node: AttackNode, indicators: list[str]) -> list[str]:
        """Check which indicators match the node's label."""
        label_lower = node.label.lower()
        return [ind for ind in indicators if ind.lower() in label_lower]
