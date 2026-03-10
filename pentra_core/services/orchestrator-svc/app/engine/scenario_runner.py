"""Scenario runner — simulates full attack lifecycle scenarios.

MOD-11.8: Loads scenario definitions and executes the complete offensive
pipeline from artifact discovery through exploitation, exercising all
modules in the system.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from app.engine.attack_graph_builder import AttackGraph, AttackNode, AttackEdge
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
from app.engine.payload_mutator import PayloadMutator
from app.engine.payload_evaluator import PayloadEvaluator
from app.engine.exploit_feedback_analyzer import ExploitFeedbackAnalyzer
from app.engine.strategy_refiner import StrategyRefiner
from app.engine.retry_planner import RetryPlanner
from app.engine.exploration_scorer import ExplorationScorer

logger = logging.getLogger(__name__)

_SCENARIOS_PATH = Path(__file__).parent.parent.parent / "tests" / "offensive_scenarios.yaml"


@dataclass
class ScenarioResult:
    """Result of running a single attack scenario."""

    scenario_name: str
    success: bool
    graph_node_count: int = 0
    graph_edge_count: int = 0
    pattern_matches: int = 0
    heuristic_matches: int = 0
    recon_hypotheses: int = 0
    workflow_hypotheses: int = 0
    payload_variants: int = 0
    refinement_attempts: int = 0
    total_hypotheses: int = 0
    scored_hypotheses: int = 0
    errors: list[str] = field(default_factory=list)
    pipeline_steps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "scenario": self.scenario_name,
            "success": self.success,
            "nodes": self.graph_node_count,
            "edges": self.graph_edge_count,
            "total_hypotheses": self.total_hypotheses,
            "errors": self.errors,
            "steps_executed": len(self.pipeline_steps),
        }


class ScenarioRunner:
    """Runs full attack lifecycle scenarios.

    Usage::

        runner = ScenarioRunner()
        results = runner.run_all()
    """

    def __init__(self, scenarios_path: Path | str | None = None) -> None:
        self._scenarios_path = Path(scenarios_path) if scenarios_path else _SCENARIOS_PATH
        self._scenarios: list[dict] = []
        self._load()

    @property
    def scenario_count(self) -> int:
        return len(self._scenarios)

    @property
    def scenario_names(self) -> list[str]:
        return [s["name"] for s in self._scenarios]

    def _load(self) -> None:
        if not self._scenarios_path.exists():
            logger.warning("Scenarios file not found: %s", self._scenarios_path)
            return
        with open(self._scenarios_path) as f:
            data = yaml.safe_load(f)
        self._scenarios = data.get("scenarios", [])
        logger.info("Loaded %d offensive scenarios", len(self._scenarios))

    def run_all(self) -> list[ScenarioResult]:
        """Run all scenarios and return results."""
        return [self.run_scenario(s) for s in self._scenarios]

    def run_scenario(self, scenario: dict) -> ScenarioResult:
        """Run a single attack scenario through the full pipeline."""
        name = scenario.get("name", "unnamed")
        result = ScenarioResult(scenario_name=name, success=False)

        try:
            # 1 — Build attack graph from initial artifacts
            graph = self._build_graph(scenario)
            result.graph_node_count = len(graph.nodes)
            result.pipeline_steps.append("graph_built")

            all_hypotheses = []

            # 2 — Pattern matching
            registry = PatternRegistry()
            registry.load()
            matcher = PatternMatcher(registry, graph)
            matches = matcher.match_all()
            result.pattern_matches = len(matches)
            executor = PatternExecutor(graph)
            pattern_hyps = executor.generate_hypotheses(matches)
            all_hypotheses.extend(pattern_hyps)
            result.pipeline_steps.append("pattern_matching")

            # 3 — Pattern reasoning (chains)
            reasoner = PatternReasoner(registry, graph)
            chains = reasoner.reason()
            if chains:
                chain_gen = PatternChainGenerator(graph)
                chain_hyps = chain_gen.generate(chains)
                all_hypotheses.extend(chain_hyps)
            result.pipeline_steps.append("pattern_reasoning")

            # 4 — Recon planning
            recon_mem = ReconMemory()
            planner = ReconPlanner(graph, memory=recon_mem)
            recon_hyps = planner.plan()
            result.recon_hypotheses = len(recon_hyps)
            all_hypotheses.extend(recon_hyps)
            result.pipeline_steps.append("recon_planning")

            # 5 — Heuristic matching
            h_matcher = HeuristicMatcher(graph)
            h_matches = h_matcher.match_all()
            result.heuristic_matches = len(h_matches)
            h_gen = HeuristicTestGenerator(graph)
            h_hyps = h_gen.generate(h_matches)
            all_hypotheses.extend(h_hyps)
            result.pipeline_steps.append("heuristic_matching")

            # 6 — Interaction mapping + workflow mutations
            i_mapper = InteractionMapper(graph)
            groups = i_mapper.map_interactions()
            if groups:
                sg_builder = StateGraphBuilder()
                wf_graphs = sg_builder.build(groups)
                wf_mutator = WorkflowMutator(graph)
                wf_hyps = wf_mutator.mutate(wf_graphs)
                result.workflow_hypotheses = len(wf_hyps)
                all_hypotheses.extend(wf_hyps)
                result.pipeline_steps.append("workflow_mutation")

            # 7 — Payload generation (for heuristic hypotheses)
            mutator = PayloadMutator()
            payload_count = 0
            for h in h_hyps[:3]:
                vuln_class = h.config.get("vulnerability_class", "")
                if vuln_class in mutator.payload_classes:
                    variants = mutator.generate(vuln_class, max_variants=5)
                    payload_count += len(variants)
            result.payload_variants = payload_count
            result.pipeline_steps.append("payload_generation")

            # 8 — Exploit refinement (simulated)
            simulated = scenario.get("simulated_responses", [])
            if simulated:
                fb_analyzer = ExploitFeedbackAnalyzer()
                refiner = StrategyRefiner(mutator=mutator)
                retry_planner = RetryPlanner()
                for sim in simulated:
                    fb = fb_analyzer.analyze(
                        response={"status_code": sim["status_code"], "body": sim["body"], "headers": {}},
                        payload_info={"payload_class": "sql_injection", "payload": "' OR 1=1--",
                                      "attempt_number": sim["attempt"]},
                    )
                    if fb.should_refine:
                        strategies = refiner.refine(fb)
                        retry_hyps, _ = retry_planner.schedule(strategies)
                        all_hypotheses.extend(retry_hyps)
                        result.refinement_attempts += 1
                result.pipeline_steps.append("exploit_refinement")

            # 9 — Score all hypotheses
            scorer = ExplorationScorer(graph)
            scored = scorer.score(all_hypotheses, min_score=0.0)
            result.total_hypotheses = len(all_hypotheses)
            result.scored_hypotheses = len(scored)
            result.pipeline_steps.append("hypothesis_scoring")

            result.success = True

        except Exception as e:
            result.errors.append(str(e))
            logger.error("Scenario %s failed: %s", name, e)

        return result

    def _build_graph(self, scenario: dict) -> AttackGraph:
        """Build an attack graph from scenario initial artifacts."""
        graph = AttackGraph(scan_id="scenario", tenant_id="test")
        graph.add_node(AttackNode(
            id="ep", node_type="entrypoint", label="attacker", artifact_ref="",
        ))

        for artifact in scenario.get("initial_artifacts", []):
            node = AttackNode(
                id=artifact["node_id"],
                node_type=artifact["type"],
                label=artifact["label"],
                artifact_ref=f"ref:{artifact['node_id']}",
                properties=artifact.get("properties", {}),
            )
            graph.add_node(node)
            graph.add_edge(AttackEdge(
                source="ep", target=node.id,
                edge_type="discovery",
            ))

        return graph
