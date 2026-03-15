"""Workflow mutator — generates mutated interaction sequences for testing.

MOD-11.6: Takes workflow graphs and produces test hypotheses by
mutating interaction sequences to detect business logic flaws,
authorization bypass, and workflow abuse.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from app.engine.attack_graph_builder import AttackGraph
from app.engine.hypothesis_generator import Hypothesis
from app.engine.state_graph_builder import WorkflowGraph, StateTransition

logger = logging.getLogger(__name__)


@dataclass
class WorkflowMutation:
    """A single workflow mutation test case."""

    mutation_id: str
    mutation_type: str       # skip_step | repeat_step | swap_order | modify_id | cross_session
    workflow_type: str
    description: str
    original_sequence: list[str]   # original state IDs
    mutated_sequence: list[str]    # mutated state IDs
    target_endpoint_id: str

    def to_dict(self) -> dict:
        return {
            "mutation_id": self.mutation_id,
            "mutation_type": self.mutation_type,
            "workflow_type": self.workflow_type,
            "original_steps": len(self.original_sequence),
            "mutated_steps": len(self.mutated_sequence),
        }


class WorkflowMutator:
    """Generates mutated interaction sequences as test hypotheses.

    Usage::

        mutator = WorkflowMutator(graph)
        hypotheses = mutator.mutate(workflow_graphs)
    """

    def __init__(self, graph: AttackGraph) -> None:
        self._graph = graph

    def mutate(
        self,
        workflows: list[WorkflowGraph],
        *,
        max_per_workflow: int = 5,
    ) -> list[Hypothesis]:
        """Generate mutation hypotheses from workflow graphs."""
        hypotheses: list[Hypothesis] = []

        for wf in workflows:
            if wf.transition_count == 0:
                continue

            mutations = self._generate_mutations(wf)
            for mutation in mutations[:max_per_workflow]:
                h = self._mutation_to_hypothesis(mutation, wf)
                hypotheses.append(h)

        logger.info("Generated %d workflow mutation hypotheses", len(hypotheses))
        return hypotheses

    def _generate_mutations(self, wf: WorkflowGraph) -> list[WorkflowMutation]:
        """Generate all applicable mutations for a workflow."""
        mutations: list[WorkflowMutation] = []
        state_ids = [s.state_id for s in wf.states]

        if len(state_ids) < 2:
            return mutations

        # 1 — Skip step: jump from initial to terminal (bypass intermediate)
        if len(state_ids) >= 3:
            mutations.append(WorkflowMutation(
                mutation_id=f"mut:skip:{wf.graph_id}",
                mutation_type="skip_step",
                workflow_type=wf.workflow_type,
                description=f"Skip intermediate steps in {wf.workflow_type} workflow",
                original_sequence=state_ids,
                mutated_sequence=[state_ids[0], state_ids[-1]],
                target_endpoint_id=wf.transitions[0].endpoint_id if wf.transitions else "",
            ))

        # 2 — Repeat step: duplicate a state transition
        mutations.append(WorkflowMutation(
            mutation_id=f"mut:repeat:{wf.graph_id}",
            mutation_type="repeat_step",
            workflow_type=wf.workflow_type,
            description=f"Repeat operation in {wf.workflow_type} workflow",
            original_sequence=state_ids,
            mutated_sequence=state_ids + [state_ids[-1]],
            target_endpoint_id=wf.transitions[-1].endpoint_id if wf.transitions else "",
        ))

        # 3 — Swap order: reverse the sequence
        if len(state_ids) >= 3:
            mutations.append(WorkflowMutation(
                mutation_id=f"mut:swap:{wf.graph_id}",
                mutation_type="swap_order",
                workflow_type=wf.workflow_type,
                description=f"Reverse step order in {wf.workflow_type} workflow",
                original_sequence=state_ids,
                mutated_sequence=list(reversed(state_ids)),
                target_endpoint_id=wf.transitions[0].endpoint_id if wf.transitions else "",
            ))

        # 4 — Modify identifier: access with different ID
        mutations.append(WorkflowMutation(
            mutation_id=f"mut:modify_id:{wf.graph_id}",
            mutation_type="modify_id",
            workflow_type=wf.workflow_type,
            description=f"Access {wf.workflow_type} resources with modified identifiers",
            original_sequence=state_ids,
            mutated_sequence=state_ids,
            target_endpoint_id=wf.transitions[0].endpoint_id if wf.transitions else "",
        ))

        # 5 — Cross-session: access without auth
        mutations.append(WorkflowMutation(
            mutation_id=f"mut:cross_session:{wf.graph_id}",
            mutation_type="cross_session",
            workflow_type=wf.workflow_type,
            description=f"Access {wf.workflow_type} workflow without authentication",
            original_sequence=state_ids,
            mutated_sequence=[state_ids[-1]],  # Skip straight to last state
            target_endpoint_id=wf.transitions[-1].endpoint_id if wf.transitions else "",
        ))

        return mutations

    def _mutation_to_hypothesis(self, mutation: WorkflowMutation, wf: WorkflowGraph) -> Hypothesis:
        """Convert a workflow mutation into a hypothesis."""
        target_node = self._graph.nodes.get(mutation.target_endpoint_id)
        target_url = ""
        if target_node is not None:
            target_url = str(
                target_node.properties.get("url")
                or target_node.properties.get("endpoint")
                or target_node.properties.get("target")
                or target_node.label
            )

        sequence_urls: list[str] = []
        for transition in wf.transitions:
            node = self._graph.nodes.get(transition.endpoint_id)
            if node is None:
                continue
            url = str(
                node.properties.get("url")
                or node.properties.get("endpoint")
                or node.properties.get("target")
                or node.label
            ).strip()
            if url and url not in sequence_urls:
                sequence_urls.append(url)

        return Hypothesis(
            hypothesis_id=f"workflow:{mutation.mutation_id}",
            hypothesis_type=f"workflow_{mutation.mutation_type}",
            target_node_id=mutation.target_endpoint_id,
            target_label=mutation.description,
            description=f"{mutation.description} [workflow:{mutation.mutation_type}]",
            tool="custom_poc",
            worker_family="exploit",
            config={
                "workflow_mutation": mutation.mutation_type,
                "workflow_type": mutation.workflow_type,
                "original_steps": len(mutation.original_sequence),
                "mutated_steps": len(mutation.mutated_sequence),
                "mutation_id": mutation.mutation_id,
                "target_url": target_url,
                "sequence_urls": sequence_urls,
                "artifact_type_override": "vulnerabilities",
                "vulnerability_class": "workflow_mutation",
                "no_persist": True,
            },
            required_artifacts=["endpoint"],
            estimated_complexity=2,
            timeout_seconds=600,
        )
