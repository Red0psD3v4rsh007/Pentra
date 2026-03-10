"""Artifact bus — event-driven artifact propagation and exploit triggering.

MOD-06: Called after a node completes.  Inspects the completed artifact:
  - If artifact_type is 'vulnerabilities': triggers ExploitPlanner
  - If artifact_type is exploit output: triggers ImpactVerifier

MOD-07: Every artifact completion triggers incremental attack graph update.

The artifact bus does NOT directly modify node states.
State transitions remain handled by:
  dependency_resolver, pipeline_executor, state_manager

It creates new nodes/edges via ExploitPlanner and impact artifacts
via ImpactVerifier, then signals the pipeline executor to re-resolve.
"""

from __future__ import annotations

import json
import logging
import uuid
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.engine.exploit_planner import ExploitPlanner
from app.engine.impact_verifier import ImpactVerifier
from app.engine.attack_graph_builder import AttackGraphBuilder
from app.engine.path_enumerator import PathEnumerator
from app.engine.path_scorer import PathScorer
from app.engine.graph_correlator import GraphCorrelator
from app.engine.strategy_engine import StrategyEngine
from app.engine.exploit_chain_generator import ExploitChainGenerator
from app.engine.exploration_engine import ExplorationEngine

logger = logging.getLogger(__name__)

# Artifact types that trigger exploit planning
_EXPLOIT_TRIGGER_TYPES = {"vulnerabilities"}

# Artifact types that trigger impact verification
_IMPACT_TRIGGER_TYPES = {"database_access", "shell_access", "credential_leak", "privilege_escalation"}

# Tools that produce exploit results
_EXPLOIT_TOOLS = {"sqlmap", "metasploit", "custom_poc"}


class ArtifactBus:
    """Artifact-driven pipeline propagation.

    Usage::

        bus = ArtifactBus(session)
        result = await bus.process_completed_node(
            dag_id=dag_id, scan_id=scan_id, tenant_id=tenant_id,
            node_id=node_id, tool=tool, artifact_type=artifact_type,
            output_ref=output_ref, output_summary=output_summary,
        )
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._planner = ExploitPlanner(session)
        self._verifier = ImpactVerifier(session)
        self._graph_builder = AttackGraphBuilder(session)

    async def process_completed_node(
        self,
        *,
        dag_id: uuid.UUID,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        node_id: uuid.UUID,
        tool: str,
        artifact_type: str,
        output_ref: str,
        output_summary: dict | None = None,
    ) -> dict[str, Any]:
        """Inspect a completed node's artifact and trigger follow-up actions.

        Returns:
            dict with 'dynamic_nodes_created', 'impact_artifacts_created'
        """
        result = {
            "dynamic_nodes_created": 0,
            "impact_artifacts_created": 0,
            "graph_updated": False,
            "strategy_nodes_created": 0,
            "exploration_nodes_created": 0,
        }

        # 1 — Vulnerability artifact triggers exploit planning
        if artifact_type in _EXPLOIT_TRIGGER_TYPES:
            vuln_items = await self._load_artifact_items(output_ref, output_summary)

            if vuln_items:
                created = await self._planner.plan_exploits(
                    dag_id=dag_id,
                    scan_id=scan_id,
                    tenant_id=tenant_id,
                    source_node_id=node_id,
                    source_output_ref=output_ref,
                    vulnerability_items=vuln_items,
                )
                result["dynamic_nodes_created"] = len(created)

                if created:
                    logger.info(
                        "ArtifactBus: %d exploit nodes created from %s (%s)",
                        len(created), tool, artifact_type,
                    )

        # 2 — Exploit tool output triggers impact verification
        if tool in _EXPLOIT_TOOLS:
            impact_items = await self._load_artifact_items(output_ref, output_summary)

            # Get the node config for vuln_type/impact_type
            node_config = await self._get_node_config(node_id)
            expected_impact = node_config.get("impact_type", "unknown")

            impact_count = await self._verifier.verify_impact(
                scan_id=scan_id,
                node_id=node_id,
                tenant_id=tenant_id,
                tool=tool,
                output_ref=output_ref,
                expected_impact_type=expected_impact,
                exploit_items=impact_items,
            )
            result["impact_artifacts_created"] = impact_count

            if impact_count > 0:
                logger.info(
                    "ArtifactBus: %d impact artifacts verified from %s",
                    impact_count, tool,
                )


        # 3 — MOD-07: Incremental attack graph update
        try:
            graph = await self._graph_builder.update_incremental(
                scan_id=scan_id,
                tenant_id=tenant_id,
                new_artifact_type=artifact_type,
                new_artifact_ref=output_ref,
            )

            if graph.nodes:
                # MOD-08: Run graph correlation to infer additional edges
                correlator = GraphCorrelator()
                correlated_edges = correlator.correlate(graph)

                # Enumerate paths and score
                enumerator = PathEnumerator(graph)
                paths = enumerator.enumerate_paths(max_paths=50)

                if paths:
                    scorer = PathScorer(graph)
                    scored = scorer.score_paths(paths)
                    # Store scoring summary in graph metadata
                    graph_dict = graph.to_dict()
                    graph_dict["path_summary"] = enumerator.get_path_summary(paths)
                    graph_dict["scoring_summary"] = scorer.get_scoring_summary(scored)

                # Store updated graph as artifact
                await self._graph_builder.store_graph(graph)
                result["graph_updated"] = True

                # MOD-08 Phase 2: Strategy engine + exploit chain generation
                if scored:
                    try:
                        strategy_eng = StrategyEngine(graph)
                        strategy = strategy_eng.select_strategy(scored)

                        if strategy and strategy.estimated_steps > 0:
                            chain_gen = ExploitChainGenerator(self._session, graph)
                            chain = chain_gen.generate_chain(strategy)

                            if chain.steps:
                                chain_node_ids = await chain_gen.create_dynamic_nodes(
                                    chain,
                                    dag_id=dag_id,
                                    scan_id=scan_id,
                                    tenant_id=tenant_id,
                                 )
                                result["strategy_nodes_created"] = len(chain_node_ids)

                    except Exception:
                        logger.exception(
                            "Failed strategy/chain generation for scan %s", scan_id,
                        )

                # MOD-09: Autonomous exploration
                try:
                    explorer = ExplorationEngine(self._session, graph)
                    explore_result = await explorer.explore(
                        dag_id=dag_id,
                        scan_id=scan_id,
                        tenant_id=tenant_id,
                    )
                    result["exploration_nodes_created"] = explore_result["exploration_nodes_created"]
                except Exception:
                    logger.exception(
                        "Failed exploration for scan %s", scan_id,
                    )

        except Exception:
            logger.exception("Failed to update attack graph for scan %s", scan_id)

        return result

    async def _load_artifact_items(
        self, output_ref: str, output_summary: dict | None,
    ) -> list[dict]:
        """Load artifact items from storage_ref or summary.

        In production: reads from S3 via output_ref.
        In dev/test: uses output_summary or loads from local artifact store.
        """
        # Try to load from local artifact store first
        import os
        artifact_store = os.getenv("ARTIFACT_STORE_PATH", "/tmp/pentra/artifacts")

        # output_ref = "artifacts/{tenant}/{scan}/{node}/{tool}.json"
        if output_ref.startswith("artifacts/"):
            local_path = Path(artifact_store) / output_ref.removeprefix("artifacts/")
            if local_path.exists():
                try:
                    data = json.loads(local_path.read_text())
                    if isinstance(data, dict) and "items" in data:
                        return data["items"]
                    elif isinstance(data, list):
                        return data
                except Exception:
                    logger.warning("Failed to read artifact: %s", local_path)

        # Fallback: use summary's item_count to infer
        if output_summary and output_summary.get("item_count", 0) > 0:
            # Return a minimal placeholder so the planner knows there are findings
            return [{"type": output_summary.get("artifact_type", "unknown")}]

        return []

    async def _get_node_config(self, node_id: uuid.UUID) -> dict:
        """Read a node's config JSONB."""
        result = await self._session.execute(text("""
            SELECT config FROM scan_nodes WHERE id = :id
        """), {"id": str(node_id)})
        row = result.scalar()
        if row is None:
            return {}
        return row if isinstance(row, dict) else json.loads(str(row))
