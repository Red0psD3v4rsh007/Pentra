"""Interaction mapper — maps endpoint relationships and infers interaction sequences.

MOD-11.6: Observes API endpoints in the attack graph and identifies
request patterns, endpoint groupings, and interaction flows.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from app.engine.attack_graph_builder import AttackGraph, AttackNode

logger = logging.getLogger(__name__)


@dataclass
class EndpointInteraction:
    """A relationship between two endpoints."""

    source_id: str
    source_label: str
    target_id: str
    target_label: str
    relationship: str  # auth_flow | crud_sequence | resource_chain | redirect

    def to_dict(self) -> dict:
        return {
            "source": self.source_label,
            "target": self.target_label,
            "relationship": self.relationship,
        }


@dataclass
class InteractionGroup:
    """A group of related endpoints forming a workflow."""

    group_id: str
    group_type: str  # auth | crud | admin | payment | user_mgmt
    endpoints: list[str]  # node IDs
    labels: list[str]
    interactions: list[EndpointInteraction] = field(default_factory=list)


# ── Pattern definitions ──────────────────────────────────────────

_AUTH_PATTERNS = ["login", "signin", "auth", "token", "oauth", "session", "logout", "register", "signup"]
_CRUD_PATTERNS = ["create", "update", "delete", "edit", "remove", "add", "modify", "save"]
_ADMIN_PATTERNS = ["admin", "dashboard", "manage", "settings", "config", "panel"]
_PAYMENT_PATTERNS = ["pay", "checkout", "cart", "order", "invoice", "billing", "price"]
_USER_PATTERNS = ["user", "profile", "account", "password", "email", "preferences"]


class InteractionMapper:
    """Maps endpoint relationships and infers interaction sequences.

    Usage::

        mapper = InteractionMapper(graph)
        groups = mapper.map_interactions()
    """

    def __init__(self, graph: AttackGraph) -> None:
        self._graph = graph

    def map_interactions(self) -> list[InteractionGroup]:
        """Analyze graph endpoints and build interaction groups."""
        endpoints = [
            n for n in self._graph.nodes.values()
            if n.node_type == "endpoint" and n.node_type != "entrypoint"
        ]

        groups: list[InteractionGroup] = []
        classified: dict[str, list[AttackNode]] = {
            "auth": [], "crud": [], "admin": [], "payment": [], "user_mgmt": [],
        }

        for ep in endpoints:
            label = ep.label.lower()
            if any(p in label for p in _AUTH_PATTERNS):
                classified["auth"].append(ep)
            if any(p in label for p in _CRUD_PATTERNS):
                classified["crud"].append(ep)
            if any(p in label for p in _ADMIN_PATTERNS):
                classified["admin"].append(ep)
            if any(p in label for p in _PAYMENT_PATTERNS):
                classified["payment"].append(ep)
            if any(p in label for p in _USER_PATTERNS):
                classified["user_mgmt"].append(ep)

        for group_type, eps in classified.items():
            if not eps:
                continue
            interactions = self._infer_interactions(eps, group_type)
            groups.append(InteractionGroup(
                group_id=f"grp:{group_type}",
                group_type=group_type,
                endpoints=[e.id for e in eps],
                labels=[e.label for e in eps],
                interactions=interactions,
            ))

        # Also find cross-group interactions (auth → crud, auth → admin)
        if classified["auth"] and classified["crud"]:
            for auth_ep in classified["auth"]:
                for crud_ep in classified["crud"]:
                    groups[0].interactions.append(EndpointInteraction(
                        source_id=auth_ep.id,
                        source_label=auth_ep.label,
                        target_id=crud_ep.id,
                        target_label=crud_ep.label,
                        relationship="auth_flow",
                    ))

        logger.info("Mapped %d interaction groups from %d endpoints",
                     len(groups), len(endpoints))
        return groups

    def _infer_interactions(
        self, endpoints: list[AttackNode], group_type: str,
    ) -> list[EndpointInteraction]:
        """Infer interactions within a group of endpoints."""
        interactions: list[EndpointInteraction] = []

        for i, ep_a in enumerate(endpoints):
            for ep_b in endpoints[i + 1:]:
                rel = self._classify_relationship(ep_a, ep_b, group_type)
                if rel:
                    interactions.append(EndpointInteraction(
                        source_id=ep_a.id,
                        source_label=ep_a.label,
                        target_id=ep_b.id,
                        target_label=ep_b.label,
                        relationship=rel,
                    ))

        return interactions

    def _classify_relationship(
        self, a: AttackNode, b: AttackNode, group_type: str,
    ) -> str | None:
        """Classify the relationship between two endpoints."""
        a_label = a.label.lower()
        b_label = b.label.lower()

        # Same resource path base → CRUD sequence
        a_base = re.sub(r"[?#].*", "", a_label).rstrip("/")
        b_base = re.sub(r"[?#].*", "", b_label).rstrip("/")
        if a_base == b_base:
            return "crud_sequence"

        # Auth-related pair
        if group_type == "auth":
            return "auth_flow"

        # Same resource type
        a_parts = set(a_base.split("/"))
        b_parts = set(b_base.split("/"))
        if len(a_parts & b_parts) >= 2:
            return "resource_chain"

        return "resource_chain" if group_type in ("crud", "payment") else None
