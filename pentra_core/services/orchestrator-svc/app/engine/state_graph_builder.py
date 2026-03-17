"""State graph builder — builds workflow state transition graphs.

MOD-11.6: Constructs a state machine representing application state
transitions derived from interaction groups and endpoint relationships.
"""

from __future__ import annotations

__classification__ = "runtime_optional"

import logging
from dataclasses import dataclass, field
from typing import Any

from app.engine.interaction_mapper import InteractionGroup, EndpointInteraction

logger = logging.getLogger(__name__)


@dataclass
class WorkflowState:
    """A single state in the workflow graph."""

    state_id: str
    label: str
    state_type: str   # initial | intermediate | terminal
    endpoints: list[str] = field(default_factory=list)  # endpoint node IDs at this state

    def to_dict(self) -> dict:
        return {
            "state_id": self.state_id,
            "label": self.label,
            "state_type": self.state_type,
            "endpoint_count": len(self.endpoints),
        }


@dataclass
class StateTransition:
    """A transition between two workflow states."""

    from_state: str
    to_state: str
    action: str          # login | create | modify | delete | navigate
    endpoint_id: str     # triggering endpoint
    requires_auth: bool = False

    def to_dict(self) -> dict:
        return {
            "from": self.from_state,
            "to": self.to_state,
            "action": self.action,
            "requires_auth": self.requires_auth,
        }


@dataclass
class WorkflowGraph:
    """A complete workflow state machine."""

    graph_id: str
    workflow_type: str
    states: list[WorkflowState] = field(default_factory=list)
    transitions: list[StateTransition] = field(default_factory=list)

    @property
    def state_count(self) -> int:
        return len(self.states)

    @property
    def transition_count(self) -> int:
        return len(self.transitions)

    def to_dict(self) -> dict:
        return {
            "graph_id": self.graph_id,
            "workflow_type": self.workflow_type,
            "states": [s.to_dict() for s in self.states],
            "transitions": [t.to_dict() for t in self.transitions],
        }


# ── State inference rules ────────────────────────────────────────

_AUTH_STATES = {
    "unauthenticated": {"login", "signin", "register", "signup"},
    "authenticated": {"logout", "profile", "dashboard", "account"},
    "elevated": {"admin", "manage", "settings", "config"},
}

_CRUD_STATES = {
    "resource_listed": {"list", "index", "search", "browse"},
    "resource_created": {"create", "add", "new", "save"},
    "resource_modified": {"update", "edit", "modify", "patch"},
    "resource_deleted": {"delete", "remove", "destroy"},
}


class StateGraphBuilder:
    """Builds workflow state graphs from interaction groups.

    Usage::

        builder = StateGraphBuilder()
        graphs = builder.build(interaction_groups)
    """

    def build(self, groups: list[InteractionGroup]) -> list[WorkflowGraph]:
        """Build workflow graphs from interaction groups."""
        graphs: list[WorkflowGraph] = []

        for group in groups:
            graph = self._build_group_graph(group)
            if graph.state_count > 0:
                graphs.append(graph)

        logger.info("Built %d workflow graphs", len(graphs))
        return graphs

    def _build_group_graph(self, group: InteractionGroup) -> WorkflowGraph:
        """Build a graph for a single interaction group."""
        graph = WorkflowGraph(
            graph_id=f"wf:{group.group_type}",
            workflow_type=group.group_type,
        )

        # Infer states from endpoint labels
        state_map = _AUTH_STATES if group.group_type == "auth" else _CRUD_STATES

        # Add initial state
        initial_label = "unauthenticated" if group.group_type == "auth" else "initial"
        graph.states.append(WorkflowState(
            state_id=f"state:{initial_label}",
            label=initial_label,
            state_type="initial",
        ))

        # Map endpoints to states
        for ep_label in group.labels:
            ep_lower = ep_label.lower()
            for state_label, keywords in state_map.items():
                if any(kw in ep_lower for kw in keywords):
                    # Check state doesn't already exist
                    existing = [s for s in graph.states if s.label == state_label]
                    if not existing:
                        state = WorkflowState(
                            state_id=f"state:{state_label}",
                            label=state_label,
                            state_type="intermediate",
                            endpoints=[ep_label],
                        )
                        graph.states.append(state)
                    else:
                        existing[0].endpoints.append(ep_label)
                    break

        # If no states matched, create a generic one
        if len(graph.states) <= 1:
            graph.states.append(WorkflowState(
                state_id=f"state:{group.group_type}_active",
                label=f"{group.group_type}_active",
                state_type="intermediate",
                endpoints=group.labels,
            ))

        # Mark last state as terminal
        if len(graph.states) > 1:
            graph.states[-1].state_type = "terminal"

        # Build transitions from interactions
        for interaction in group.interactions:
            action = self._infer_action(interaction)
            graph.transitions.append(StateTransition(
                from_state=graph.states[0].state_id,
                to_state=graph.states[-1].state_id if len(graph.states) > 1 else graph.states[0].state_id,
                action=action,
                endpoint_id=interaction.source_id,
                requires_auth=group.group_type != "auth",
            ))

        # Also add sequential transitions between states
        for i in range(len(graph.states) - 1):
            graph.transitions.append(StateTransition(
                from_state=graph.states[i].state_id,
                to_state=graph.states[i + 1].state_id,
                action="navigate",
                endpoint_id=group.endpoints[0] if group.endpoints else "",
                requires_auth=graph.states[i].label != "unauthenticated",
            ))

        return graph

    def _infer_action(self, interaction: EndpointInteraction) -> str:
        """Infer action type from interaction."""
        label = interaction.source_label.lower()
        if any(kw in label for kw in ("login", "signin", "auth")):
            return "login"
        if any(kw in label for kw in ("create", "add", "new")):
            return "create"
        if any(kw in label for kw in ("update", "edit", "modify")):
            return "modify"
        if any(kw in label for kw in ("delete", "remove")):
            return "delete"
        return "navigate"
