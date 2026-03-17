"""Recon planner — plans reconnaissance actions based on discovered assets.

MOD-10: Analyzes graph assets, classifies them, matches recon actions
from the knowledge library, and generates exploration hypotheses.

Flow:
  graph nodes → asset analyzer → classify
  → match recon actions from YAML
  → filter through coverage tracker
  → generate Hypothesis objects
"""

from __future__ import annotations

__classification__ = "runtime_optional"

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from app.engine.attack_graph_builder import AttackGraph
from app.engine.hypothesis_generator import Hypothesis
from app.engine.recon_asset_analyzer import ReconAssetAnalyzer, ReconAsset
from app.engine.recon_memory import ReconMemory

logger = logging.getLogger(__name__)

_RECON_ACTIONS_PATH = Path(__file__).parent.parent / "knowledge" / "recon_actions.yaml"


@dataclass
class ReconAction:
    """A structured recon action from the action library."""

    name: str
    description: str
    target_asset_class: str
    priority: str
    actions: list[dict]     # [{tool, worker_family, timeout, description}]
    impact: list[str]
    generated_artifacts: list[str]


class ReconPlanner:
    """Plans reconnaissance actions based on discovered assets.

    Usage::

        planner = ReconPlanner(graph)
        hypotheses = planner.plan()
    """

    def __init__(
        self,
        graph: AttackGraph,
        *,
        memory: ReconMemory | None = None,
        actions_path: Path | str | None = None,
    ) -> None:
        self._graph = graph
        self._analyzer = ReconAssetAnalyzer(graph)
        self._memory = memory or ReconMemory()
        self._actions_path = Path(actions_path) if actions_path else _RECON_ACTIONS_PATH
        self._recon_actions: list[ReconAction] = []
        self._load_actions()

    @property
    def recon_actions(self) -> list[ReconAction]:
        return list(self._recon_actions)

    @property
    def memory(self) -> ReconMemory:
        return self._memory

    def _load_actions(self) -> None:
        """Load recon actions from YAML."""
        if not self._actions_path.exists():
            logger.warning("Recon actions file not found: %s", self._actions_path)
            return

        with open(self._actions_path) as f:
            data = yaml.safe_load(f)

        if not data or "recon_actions" not in data:
            return

        for raw in data["recon_actions"]:
            try:
                action = ReconAction(
                    name=raw["name"],
                    description=raw.get("description", ""),
                    target_asset_class=raw["target_asset_class"],
                    priority=raw.get("priority", "medium"),
                    actions=raw.get("actions", []),
                    impact=raw.get("impact", []),
                    generated_artifacts=raw.get("generated_artifacts", []),
                )
                self._recon_actions.append(action)
            except (KeyError, TypeError) as e:
                logger.warning("Failed to parse recon action: %s", e)

        logger.info("Loaded %d recon actions", len(self._recon_actions))

    def plan(self, *, max_per_asset: int = 3) -> list[Hypothesis]:
        """Plan recon actions for all assets in the graph.

        Returns ordered Hypothesis objects ready for scoring and dispatch.
        """
        assets = self._analyzer.analyze()
        hypotheses: list[Hypothesis] = []

        # Group actions by target class
        actions_by_class: dict[str, list[ReconAction]] = {}
        for action in self._recon_actions:
            actions_by_class.setdefault(action.target_asset_class, []).append(action)

        # Sort by priority for consistent ordering
        priority_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for cls_actions in actions_by_class.values():
            cls_actions.sort(key=lambda a: priority_rank.get(a.priority, 2))

        for asset in assets:
            matching = actions_by_class.get(asset.asset_class, [])
            count = 0

            for recon_action in matching:
                if count >= max_per_asset:
                    break

                # Check coverage
                if self._memory.has_explored(asset.node_id, recon_action.name):
                    continue

                # Generate hypotheses for each tool in the action
                for tool_def in recon_action.actions:
                    if count >= max_per_asset:
                        break

                    h = Hypothesis(
                        hypothesis_id=f"recon:{recon_action.name}:{asset.node_id}:{tool_def['tool']}",
                        hypothesis_type=f"recon_{recon_action.name}",
                        target_node_id=asset.node_id,
                        target_label=asset.label,
                        description=f"{tool_def.get('description', recon_action.description)} [recon:{recon_action.name}]",
                        tool=tool_def["tool"],
                        worker_family=tool_def.get("worker_family", "recon"),
                        config={
                            "recon_action": recon_action.name,
                            "asset_class": asset.asset_class,
                            "priority": recon_action.priority,
                            "impact": recon_action.impact,
                            "generated_artifacts": recon_action.generated_artifacts,
                            "no_persist": True,
                        },
                        required_artifacts=[asset.asset_class],
                        estimated_complexity=1,
                        timeout_seconds=tool_def.get("timeout", 300),
                    )
                    hypotheses.append(h)
                    count += 1

        logger.info(
            "Recon planner: %d hypotheses from %d assets (%d actions loaded)",
            len(hypotheses), len(assets), len(self._recon_actions),
        )
        return hypotheses
