"""Exploration engine — orchestrates autonomous attack exploration.

MOD-09.7 + MOD-10 + MOD-11: Fully knowledge-driven with autonomous recon
planning and heuristic vulnerability discovery.
All hypotheses generated from patterns, chains, recon actions, and heuristics.

Flow:
  graph updated → exploration engine
  → pattern-based hypotheses + chain-based hypotheses + recon hypotheses + heuristic hypotheses
  → scored + filtered → budget checked → memory deduplicated
  → dynamic scan_nodes created → pipeline executor dispatches
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.engine.attack_graph_builder import AttackGraph
from app.engine.hypothesis_generator import Hypothesis
from app.engine.exploration_scorer import ExplorationScorer, ScoredHypothesis
from app.engine.exploration_budget import ExplorationBudget, BudgetConfig
from app.engine.exploration_memory import ExplorationMemory
from app.knowledge.pattern_registry import PatternRegistry
from app.engine.pattern_matcher import PatternMatcher
from app.engine.pattern_executor import PatternExecutor
from app.engine.pattern_reasoner import PatternReasoner
from app.engine.pattern_chain_generator import PatternChainGenerator
from app.engine.recon_planner import ReconPlanner
from app.engine.recon_memory import ReconMemory
from app.engine.heuristic_matcher import HeuristicMatcher
from app.engine.heuristic_test_generator import HeuristicTestGenerator
from app.engine.interaction_mapper import InteractionMapper
from app.engine.state_graph_builder import StateGraphBuilder
from app.engine.workflow_mutator import WorkflowMutator
from pentra_common.profiles import DEFAULT_EXTERNAL_WEB_API_PROFILE_ID

logger = logging.getLogger(__name__)

_WORKFLOW_TYPE_PRIORITY = {
    "payment": 0,
    "admin": 1,
    "user_mgmt": 2,
    "auth": 3,
    "crud": 4,
}

_WORKFLOW_MUTATION_PRIORITY = {
    "skip_step": 0,
    "cross_session": 1,
    "modify_id": 2,
    "repeat_step": 3,
    "swap_order": 4,
}


def _select_stateful_workflow_hypotheses(
    hypotheses: list[Hypothesis],
    *,
    max_hypotheses: int,
) -> list[Hypothesis]:
    """Keep a bounded set of high-signal workflow mutation hypotheses."""
    if max_hypotheses <= 0:
        return []

    candidates = [
        hypothesis
        for hypothesis in hypotheses
        if hypothesis.tool == "custom_poc" and hypothesis.config.get("workflow_mutation")
    ]
    if not candidates:
        return []

    ordered = sorted(
        candidates,
        key=lambda hypothesis: (
            _WORKFLOW_TYPE_PRIORITY.get(str(hypothesis.config.get("workflow_type") or "").strip().lower(), 99),
            _WORKFLOW_MUTATION_PRIORITY.get(
                str(hypothesis.config.get("workflow_mutation") or "").strip().lower(),
                99,
            ),
            str(hypothesis.config.get("target_url") or hypothesis.target_label or ""),
        ),
    )

    selected: list[Hypothesis] = []
    seen_signatures: set[tuple[str, str, str]] = set()
    seen_workflow_types: set[str] = set()
    overflow: list[Hypothesis] = []

    for hypothesis in ordered:
        workflow_type = str(hypothesis.config.get("workflow_type") or "").strip().lower()
        workflow_mutation = str(hypothesis.config.get("workflow_mutation") or "").strip().lower()
        target_url = str(
            hypothesis.config.get("target_url")
            or hypothesis.target_label
            or hypothesis.target_node_id
        ).strip()
        signature = (workflow_type, workflow_mutation, target_url)
        if signature in seen_signatures:
            continue
        seen_signatures.add(signature)

        if workflow_type and workflow_type not in seen_workflow_types and len(selected) < max_hypotheses:
            selected.append(hypothesis)
            seen_workflow_types.add(workflow_type)
        else:
            overflow.append(hypothesis)

    for hypothesis in overflow:
        if len(selected) >= max_hypotheses:
            break
        selected.append(hypothesis)

    return selected[:max_hypotheses]


def _filter_exploration_hypotheses(
    hypotheses: list[Hypothesis],
    *,
    scan_config: dict[str, Any],
) -> list[Hypothesis]:
    """Apply bounded, profile-aware filtering to dynamic exploration work."""
    if not hypotheses:
        return hypotheses

    profile_id = str(
        scan_config.get("profile_id")
        or scan_config.get("profile", {}).get("id")
        or ""
    ).strip()
    if profile_id != DEFAULT_EXTERNAL_WEB_API_PROFILE_ID:
        return hypotheses

    stateful_testing = scan_config.get("stateful_testing", {})
    if not isinstance(stateful_testing, dict):
        stateful_testing = {}

    if stateful_testing.get("enabled"):
        max_replays = int(stateful_testing.get("max_replays", 4) or 4)
        selected = _select_stateful_workflow_hypotheses(
            hypotheses,
            max_hypotheses=max_replays,
        )
        if selected:
            logger.info(
                "Stateful exploration filter kept %d workflow mutation hypotheses out of %d generated",
                len(selected),
                len(hypotheses),
            )
            return selected

    execution = scan_config.get("execution", {})
    if not isinstance(execution, dict):
        execution = {}

    supported_tools = {
        str(tool).strip()
        for tool in execution.get("allowed_live_tools", [])
        if str(tool).strip()
    }
    supported_tools.update(
        str(tool.get("tool")).strip()
        for tool in scan_config.get("toolchain", [])
        if isinstance(tool, dict) and str(tool.get("tool")).strip()
    )
    supported_tools.update(
        str(tool).strip()
        for tool in scan_config.get("verification_policy", {}).get("allowed_tools", [])
        if str(tool).strip()
    )

    if not supported_tools:
        return hypotheses

    filtered: list[Hypothesis] = []
    for hypothesis in hypotheses:
        if hypothesis.tool not in supported_tools:
            continue
        if hypothesis.tool == "custom_poc":
            if hypothesis.config.get("workflow_mutation") or hypothesis.config.get("verification_context"):
                filtered.append(hypothesis)
            continue
        filtered.append(hypothesis)

    logger.info(
        "Profile exploration filter kept %d supported hypotheses out of %d generated",
        len(filtered),
        len(hypotheses),
    )
    return filtered


class ExplorationEngine:
    """Orchestrates autonomous attack exploration.

    Usage::

        engine = ExplorationEngine(session, graph)
        result = await engine.explore(dag_id=..., scan_id=..., tenant_id=...)
    """

    # Shared state across calls within a scan (injected externally)
    _budget: ExplorationBudget | None = None
    _memory: ExplorationMemory | None = None
    _scan_memories: dict[str, ExplorationMemory] = {}

    def __init__(
        self,
        session: AsyncSession,
        graph: AttackGraph,
        *,
        budget: ExplorationBudget | None = None,
        memory: ExplorationMemory | None = None,
    ) -> None:
        self._session = session
        self._graph = graph
        self._scorer = ExplorationScorer(graph)
        self._budget = budget or ExplorationBudget()
        self._memory = memory or ExplorationMemory()
        self._memory_provided = memory is not None

        # MOD-09.5 + MOD-09.7: Fully knowledge-driven
        self._registry = PatternRegistry()
        self._registry.load()
        self._pattern_matcher = PatternMatcher(self._registry, graph)
        self._pattern_executor = PatternExecutor(graph)

        # MOD-10: Autonomous recon planner
        self._recon_memory = ReconMemory()
        self._recon_planner = ReconPlanner(graph, memory=self._recon_memory)

        # MOD-11: Heuristic vulnerability engine
        self._heuristic_matcher = HeuristicMatcher(graph)
        self._heuristic_test_gen = HeuristicTestGenerator(graph)

    async def explore(
        self,
        *,
        dag_id: uuid.UUID,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        min_score: float = 4.0,
    ) -> dict[str, Any]:
        """Run one exploration cycle.

        Returns dict with exploration_nodes_created, hypotheses_generated,
        hypotheses_scored, budget_status.
        """
        result = {
            "exploration_nodes_created": 0,
            "hypotheses_generated": 0,
            "hypotheses_scored": 0,
            "hypotheses_filtered": 0,
            "hypotheses_supported": 0,
            "workflow_groups": 0,
            "workflow_graphs": 0,
            "workflow_hypotheses": 0,
        }
        scan_config = await self._load_scan_config(scan_id)
        if not self._memory_provided:
            self._memory = self._shared_memory(scan_id)

        # 1 — Generate hypotheses (knowledge-driven patterns)
        pattern_matches = self._pattern_matcher.match_all()
        hypotheses = self._pattern_executor.generate_hypotheses(pattern_matches)

        # 2 — Pattern reasoning — compose multi-step chains
        reasoner = PatternReasoner(self._registry, self._graph)
        chains = reasoner.reason()
        if chains:
            chain_gen = PatternChainGenerator(self._graph)
            chain_hypotheses = chain_gen.generate(chains)
            hypotheses.extend(chain_hypotheses)

        # 3 — MOD-10: Autonomous recon planning
        recon_hypotheses = self._recon_planner.plan()
        hypotheses.extend(recon_hypotheses)

        # 4 — MOD-11: Heuristic vulnerability discovery
        heuristic_matches = self._heuristic_matcher.match_all()
        heuristic_hypotheses = self._heuristic_test_gen.generate(heuristic_matches)
        hypotheses.extend(heuristic_hypotheses)

        # 5 — MOD-11.6: Stateful workflow mutation generation
        interaction_groups = InteractionMapper(self._graph).map_interactions()
        workflow_graphs = StateGraphBuilder().build(interaction_groups) if interaction_groups else []
        workflow_hypotheses: list[Hypothesis] = []
        if workflow_graphs:
            workflow_hypotheses = WorkflowMutator(self._graph).mutate(workflow_graphs)
            hypotheses.extend(workflow_hypotheses)

        result["hypotheses_generated"] = len(hypotheses)
        result["pattern_matches"] = len(pattern_matches)
        result["pattern_chains"] = len(chains) if chains else 0
        result["recon_hypotheses"] = len(recon_hypotheses)
        result["heuristic_matches"] = len(heuristic_matches)
        result["heuristic_hypotheses"] = len(heuristic_hypotheses)
        result["workflow_groups"] = len(interaction_groups)
        result["workflow_graphs"] = len(workflow_graphs)
        result["workflow_hypotheses"] = len(workflow_hypotheses)

        hypotheses = _filter_exploration_hypotheses(hypotheses, scan_config=scan_config)
        result["hypotheses_supported"] = len(hypotheses)

        if not hypotheses:
            return result

        # 2 — Filter through memory (skip already explored)
        novel = [
            h for h in hypotheses
            if not self._memory.has_explored(
                hypothesis_type=h.hypothesis_type,
                target_node_id=h.target_node_id,
                tool=h.tool,
            )
        ]
        result["hypotheses_filtered"] = len(hypotheses) - len(novel)

        if not novel:
            logger.info("All hypotheses already explored")
            return result

        # 3 — Score and rank
        scored = self._scorer.score(novel, min_score=min_score)
        result["hypotheses_scored"] = len(scored)

        if not scored:
            return result

        # 4 — Budget check
        allowed = self._budget.get_allowed_count(len(scored))
        if allowed == 0:
            logger.warning("Exploration budget exhausted")
            return result

        selected = scored[:allowed]

        # 5 — Create dynamic nodes
        node_ids = await self._create_exploration_nodes(
            selected,
            dag_id=dag_id,
            scan_id=scan_id,
            tenant_id=tenant_id,
        )
        result["exploration_nodes_created"] = len(node_ids)

        # 6 — Record in memory and consume budget
        for sh in selected:
            self._memory.record(
                hypothesis_type=sh.hypothesis.hypothesis_type,
                target_node_id=sh.hypothesis.target_node_id,
                tool=sh.hypothesis.tool,
            )
        self._budget.consume(count=len(node_ids))

        logger.info(
            "Exploration cycle: generated=%d novel=%d scored=%d created=%d budget_remaining=%d",
            len(hypotheses), len(novel), len(scored), len(node_ids), self._budget.remaining,
        )

        return result

    async def _create_exploration_nodes(
        self,
        scored: list[ScoredHypothesis],
        *,
        dag_id: uuid.UUID,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> list[uuid.UUID]:
        """Insert exploration hypotheses as dynamic scan_nodes."""
        phase_id = await self._get_exploration_phase(dag_id, tenant_id)
        if phase_id is None:
            return []

        created: list[uuid.UUID] = []

        for sh in scored:
            h = sh.hypothesis
            node_id = uuid.uuid4()

            config = {
                "hypothesis_id": h.hypothesis_id,
                "hypothesis_type": h.hypothesis_type,
                "target_node_id": h.target_node_id,
                "target_label": h.target_label,
                "exploration_score": sh.total_score,
                "priority": sh.priority,
                "timeout_seconds": h.timeout_seconds,
                "no_persist": True,
                **h.config,
            }

            await self._session.execute(text("""
                INSERT INTO scan_nodes (
                    id, dag_id, phase_id, tenant_id, tool, worker_family,
                    status, is_dynamic, config
                ) VALUES (
                    :id, :did, :pid, :tid, :tool, :family,
                    'pending', true, CAST(:config AS jsonb)
                )
            """), {
                "id": str(node_id),
                "did": str(dag_id),
                "pid": str(phase_id),
                "tid": str(tenant_id),
                "tool": h.tool,
                "family": h.worker_family,
                "config": json.dumps(config),
            })

            created.append(node_id)

        await self._session.flush()
        return created

    async def _load_scan_config(self, scan_id: uuid.UUID) -> dict[str, Any]:
        result = await self._session.execute(
            text("SELECT config FROM scans WHERE id = :id"),
            {"id": str(scan_id)},
        )
        value = result.scalar_one_or_none()
        return value if isinstance(value, dict) else {}

    @classmethod
    def _shared_memory(cls, scan_id: uuid.UUID) -> ExplorationMemory:
        scan_key = str(scan_id)
        memory = cls._scan_memories.get(scan_key)
        if memory is None:
            memory = ExplorationMemory()
            cls._scan_memories[scan_key] = memory
        return memory

    async def _get_exploration_phase(
        self, dag_id: uuid.UUID, tenant_id: uuid.UUID,
    ) -> uuid.UUID | None:
        """Get or create the exploration phase."""
        result = await self._session.execute(text("""
            SELECT id FROM scan_phases
            WHERE dag_id = :did AND name = 'exploration'
        """), {"did": str(dag_id)})

        row = result.scalar()
        if row is not None:
            return uuid.UUID(str(row))

        max_result = await self._session.execute(text("""
            SELECT COALESCE(MAX(phase_number), -1) AS max_pn
            FROM scan_phases WHERE dag_id = :did
        """), {"did": str(dag_id)})
        max_pn = int(max_result.scalar() or -1)

        phase_id = uuid.uuid4()
        await self._session.execute(text("""
            INSERT INTO scan_phases (id, dag_id, tenant_id, phase_number, name, status, min_success_ratio)
            VALUES (:id, :did, :tid, :pn, 'exploration', 'pending', 0.50)
        """), {
            "id": str(phase_id),
            "did": str(dag_id),
            "tid": str(tenant_id),
            "pn": max_pn + 1,
        })

        await self._session.execute(text("""
            UPDATE scan_dags SET total_phases = total_phases + 1 WHERE id = :did
        """), {"did": str(dag_id)})

        await self._session.flush()
        return phase_id
