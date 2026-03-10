"""Attack graph builder — constructs directed attack graphs from scan artifacts.

MOD-07: Ingests artifacts from scan_artifacts. Maps them into graph nodes
(asset, service, endpoint, vulnerability, credential, privilege) and
creates edges representing attacker transitions (discovery, exploit,
credential_usage, lateral_movement, privilege_escalation).

The graph is built in-memory for fast traversal but is always
reconstructible from scan_artifacts. The final graph is serialized
as an artifact_type='attack_graph' in scan_artifacts.

Graph Model:
    Nodes: AttackNode(id, node_type, label, artifact_ref, properties)
    Edges: AttackEdge(source, target, edge_type, properties)
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


# ── Graph data model ─────────────────────────────────────────────────


@dataclass
class AttackNode:
    """A node in the attack graph."""

    id: str
    node_type: str     # entrypoint | asset | service | endpoint | vulnerability | credential | privilege
    label: str         # human-readable label
    artifact_ref: str  # reference to scan_artifact storage_ref
    properties: dict = field(default_factory=dict)


@dataclass
class AttackEdge:
    """A directed edge in the attack graph."""

    source: str        # source node id
    target: str        # target node id
    edge_type: str     # discovery | exploit | credential_usage | lateral_movement | privilege_escalation
    properties: dict = field(default_factory=dict)


@dataclass
class AttackGraph:
    """In-memory attack graph."""

    scan_id: str
    tenant_id: str
    nodes: dict[str, AttackNode] = field(default_factory=dict)
    edges: list[AttackEdge] = field(default_factory=list)
    built_at: str = ""

    def add_node(self, node: AttackNode) -> None:
        self.nodes[node.id] = node

    def add_edge(self, edge: AttackEdge) -> None:
        self.edges.append(edge)

    def has_node(self, node_id: str) -> bool:
        return node_id in self.nodes

    def get_neighbors(self, node_id: str) -> list[str]:
        """Get all nodes reachable from the given node."""
        return [e.target for e in self.edges if e.source == node_id]

    def get_predecessors(self, node_id: str) -> list[str]:
        """Get all nodes that lead to the given node."""
        return [e.source for e in self.edges if e.target == node_id]

    def to_dict(self) -> dict:
        """Serialize graph to a JSON-compatible dict."""
        return {
            "scan_id": self.scan_id,
            "tenant_id": self.tenant_id,
            "built_at": self.built_at,
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "nodes": {nid: {
                "id": n.id,
                "node_type": n.node_type,
                "label": n.label,
                "artifact_ref": n.artifact_ref,
                "properties": n.properties,
            } for nid, n in self.nodes.items()},
            "edges": [{
                "source": e.source,
                "target": e.target,
                "edge_type": e.edge_type,
                "properties": e.properties,
            } for e in self.edges],
        }


# ── Entrypoint definitions ───────────────────────────────────────────

_ENTRYPOINTS = {
    "external_attacker": AttackNode(
        id="entrypoint:external_attacker",
        node_type="entrypoint",
        label="External Attacker",
        artifact_ref="",
        properties={"description": "Unauthenticated external adversary"},
    ),
    "internet_exposed_service": AttackNode(
        id="entrypoint:internet_exposed",
        node_type="entrypoint",
        label="Internet-Exposed Service",
        artifact_ref="",
        properties={"description": "Publicly accessible network service"},
    ),
    "unauthenticated_access": AttackNode(
        id="entrypoint:unauthenticated",
        node_type="entrypoint",
        label="Unauthenticated Access",
        artifact_ref="",
        properties={"description": "Access without credentials"},
    ),
}

# ── Artifact → node type mapping ─────────────────────────────────────

_ARTIFACT_NODE_TYPE: dict[str, str] = {
    "subdomains": "asset",
    "hosts": "asset",
    "services": "service",
    "endpoints": "endpoint",
    "vulnerabilities": "vulnerability",
    "scope": "asset",
    "database_access": "privilege",
    "shell_access": "privilege",
    "credential_leak": "credential",
    "privilege_escalation": "privilege",
    "verified_impact": "privilege",
    "access_levels": "privilege",
    "findings_scored": "vulnerability",
}

# ── Edge inference rules ─────────────────────────────────────────────

_EDGE_RULES: list[tuple[str, str, str]] = [
    # (source_type, target_type, edge_type)
    ("entrypoint", "asset", "discovery"),
    ("asset", "service", "discovery"),
    ("service", "endpoint", "discovery"),
    ("endpoint", "vulnerability", "discovery"),
    ("vulnerability", "privilege", "exploit"),
    ("vulnerability", "credential", "exploit"),
    ("credential", "service", "credential_usage"),
    ("credential", "privilege", "lateral_movement"),
    ("privilege", "privilege", "privilege_escalation"),
]


# ── Attack Graph Builder ─────────────────────────────────────────────


class AttackGraphBuilder:
    """Constructs an attack graph from scan artifacts.

    Usage::

        builder = AttackGraphBuilder(session)
        graph = await builder.build(scan_id=..., tenant_id=...)
        await builder.store_graph(graph)
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def build(
        self,
        *,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> AttackGraph:
        """Build a complete attack graph from all artifacts for a scan."""
        graph = AttackGraph(
            scan_id=str(scan_id),
            tenant_id=str(tenant_id),
            built_at=datetime.now(timezone.utc).isoformat(),
        )

        # 1 — Add entrypoints
        for ep in _ENTRYPOINTS.values():
            graph.add_node(ep)

        # 2 — Load all artifacts for this scan
        artifacts = await self._load_artifacts(scan_id)

        if not artifacts:
            logger.info("No artifacts found for scan %s — empty graph", scan_id)
            return graph

        # 3 — Create nodes from artifacts
        for artifact in artifacts:
            nodes = self._artifact_to_nodes(artifact)
            for node in nodes:
                graph.add_node(node)

        # 4 — Infer edges between nodes
        self._infer_edges(graph)

        logger.info(
            "Attack graph built: scan=%s nodes=%d edges=%d",
            scan_id, len(graph.nodes), len(graph.edges),
        )
        return graph

    async def update_incremental(
        self,
        *,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        new_artifact_type: str,
        new_artifact_ref: str,
    ) -> AttackGraph:
        """Incrementally rebuild the graph after a new artifact appears.

        For now, does full rebuild (fast enough for <10K nodes).
        Future optimization: differential update.
        """
        return await self.build(scan_id=scan_id, tenant_id=tenant_id)

    async def store_graph(
        self,
        graph: AttackGraph,
    ) -> uuid.UUID:
        """Serialize and store the attack graph as a scan_artifact."""
        graph_data = json.dumps(graph.to_dict(), default=str)
        artifact_id = uuid.uuid4()
        scan_id = graph.scan_id
        tenant_id = graph.tenant_id

        # Upsert: delete old attack_graph, insert new
        await self._session.execute(text("""
            DELETE FROM scan_artifacts
            WHERE scan_id = :sid AND artifact_type = 'attack_graph'
        """), {"sid": scan_id})

        await self._session.execute(text("""
            INSERT INTO scan_artifacts (
                id, scan_id, tenant_id,
                artifact_type, storage_ref, metadata
            ) VALUES (
                :id, :sid, :tid,
                'attack_graph', :ref,
                CAST(:meta AS jsonb)
            )
        """), {
            "id": str(artifact_id),
            "sid": scan_id,
            "tid": tenant_id,
            "ref": f"graphs/{tenant_id}/{scan_id}/attack_graph.json",
            "meta": graph_data,
        })

        await self._session.flush()
        logger.info("Attack graph stored: artifact=%s nodes=%d edges=%d",
                     artifact_id, len(graph.nodes), len(graph.edges))
        return artifact_id

    # ── Internal helpers ──────────────────────────────────────────

    async def _load_artifacts(self, scan_id: uuid.UUID) -> list[dict]:
        """Load all artifacts for a scan from the database."""
        result = await self._session.execute(text("""
            SELECT id, artifact_type, storage_ref, metadata, node_id
            FROM scan_artifacts
            WHERE scan_id = :sid
              AND artifact_type != 'attack_graph'
            ORDER BY created_at
        """), {"sid": str(scan_id)})

        return [dict(row) for row in result.mappings().all()]

    def _artifact_to_nodes(self, artifact: dict) -> list[AttackNode]:
        """Convert a scan artifact into one or more attack graph nodes."""
        artifact_type = artifact.get("artifact_type", "unknown")
        node_type = _ARTIFACT_NODE_TYPE.get(artifact_type, "asset")
        storage_ref = artifact.get("storage_ref", "")
        artifact_id = str(artifact.get("id", ""))
        metadata = artifact.get("metadata", {})
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except Exception:
                metadata = {}

        nodes = []

        # If metadata has items, create per-item nodes
        items = metadata.get("items", []) if isinstance(metadata, dict) else []

        if items and len(items) <= 50:  # cap to avoid explosion
            for i, item in enumerate(items):
                label = self._item_label(item, artifact_type, i)
                node_id = f"{artifact_type}:{artifact_id}:{i}"
                nodes.append(AttackNode(
                    id=node_id,
                    node_type=node_type,
                    label=label,
                    artifact_ref=storage_ref,
                    properties={
                        "artifact_type": artifact_type,
                        "artifact_id": artifact_id,
                        "item_index": i,
                        **{k: v for k, v in item.items() if isinstance(v, (str, int, float, bool))},
                    },
                ))
        else:
            # Single aggregate node for the artifact
            label = f"{artifact_type} ({artifact_type})"
            node_id = f"{artifact_type}:{artifact_id}"
            nodes.append(AttackNode(
                id=node_id,
                node_type=node_type,
                label=label,
                artifact_ref=storage_ref,
                properties={
                    "artifact_type": artifact_type,
                    "artifact_id": artifact_id,
                    "item_count": len(items) if items else 1,
                },
            ))

        return nodes

    def _item_label(self, item: dict, artifact_type: str, index: int) -> str:
        """Generate a human-readable label for an artifact item."""
        # Try common fields
        for key in ("host", "name", "url", "matched-at", "target", "service", "port"):
            if key in item and item[key]:
                return str(item[key])[:80]

        return f"{artifact_type}[{index}]"

    def _infer_edges(self, graph: AttackGraph) -> None:
        """Infer edges between nodes based on type-based rules."""
        nodes_by_type: dict[str, list[AttackNode]] = {}
        for node in graph.nodes.values():
            nodes_by_type.setdefault(node.node_type, []).append(node)

        for source_type, target_type, edge_type in _EDGE_RULES:
            sources = nodes_by_type.get(source_type, [])
            targets = nodes_by_type.get(target_type, [])

            if not sources or not targets:
                continue

            for src in sources:
                for tgt in targets:
                    if src.id == tgt.id:
                        continue

                    # For privilege_escalation, only connect different privileges
                    if edge_type == "privilege_escalation":
                        if src.properties.get("artifact_type") == tgt.properties.get("artifact_type"):
                            continue

                    graph.add_edge(AttackEdge(
                        source=src.id,
                        target=tgt.id,
                        edge_type=edge_type,
                        properties={
                            "inferred": True,
                            "rule": f"{source_type}→{target_type}",
                        },
                    ))
