"""Attack graph builder — constructs directed attack graphs from scan artifacts."""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from pentra_common.storage.artifacts import read_json_artifact, write_json_artifact
from pentra_common.storage.retention import apply_artifact_retention_metadata

logger = logging.getLogger(__name__)

_IGNORED_ARTIFACT_TYPES = {"report"}


@dataclass
class AttackNode:
    """A node in the attack graph."""

    id: str
    node_type: str
    label: str
    artifact_ref: str
    properties: dict = field(default_factory=dict)


@dataclass
class AttackEdge:
    """A directed edge in the attack graph."""

    source: str
    target: str
    edge_type: str
    properties: dict = field(default_factory=dict)


@dataclass
class AttackGraph:
    """In-memory attack graph."""

    scan_id: str
    tenant_id: str
    nodes: dict[str, AttackNode] = field(default_factory=dict)
    edges: list[AttackEdge] = field(default_factory=list)
    built_at: str = ""
    path_summary: dict[str, Any] = field(default_factory=dict)
    scoring_summary: dict[str, Any] = field(default_factory=dict)

    def add_node(self, node: AttackNode) -> None:
        self.nodes[node.id] = node

    def add_edge(self, edge: AttackEdge) -> None:
        self.edges.append(edge)

    def has_node(self, node_id: str) -> bool:
        return node_id in self.nodes

    def get_neighbors(self, node_id: str) -> list[str]:
        return [edge.target for edge in self.edges if edge.source == node_id]

    def get_predecessors(self, node_id: str) -> list[str]:
        return [edge.source for edge in self.edges if edge.target == node_id]

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "tenant_id": self.tenant_id,
            "built_at": self.built_at,
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "path_summary": self.path_summary,
            "scoring_summary": self.scoring_summary,
            "nodes": {
                node_id: {
                    "id": node.id,
                    "node_type": node.node_type,
                    "label": node.label,
                    "artifact_ref": node.artifact_ref,
                    "properties": node.properties,
                }
                for node_id, node in self.nodes.items()
            },
            "edges": [
                {
                    "source": edge.source,
                    "target": edge.target,
                    "edge_type": edge.edge_type,
                    "properties": edge.properties,
                }
                for edge in self.edges
            ],
        }


_ENTRYPOINTS = {
    "external_attacker": AttackNode(
        id="entrypoint:external_attacker",
        node_type="entrypoint",
        label="External Attacker",
        artifact_ref="",
        properties={
            "description": "Unauthenticated external adversary",
            "entity_key": "entrypoint:external_attacker",
        },
    ),
    "internet_exposed_service": AttackNode(
        id="entrypoint:internet_exposed",
        node_type="entrypoint",
        label="Internet-Exposed Service",
        artifact_ref="",
        properties={
            "description": "Publicly accessible network service",
            "entity_key": "entrypoint:internet_exposed",
        },
    ),
    "unauthenticated_access": AttackNode(
        id="entrypoint:unauthenticated",
        node_type="entrypoint",
        label="Unauthenticated Access",
        artifact_ref="",
        properties={
            "description": "Access without credentials",
            "entity_key": "entrypoint:unauthenticated",
        },
    ),
}

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

_EDGE_RULES: list[tuple[str, str, str]] = [
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


class AttackGraphBuilder:
    """Constructs an attack graph from scan artifacts."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def build(
        self,
        *,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> AttackGraph:
        graph = AttackGraph(
            scan_id=str(scan_id),
            tenant_id=str(tenant_id),
            built_at=datetime.now(timezone.utc).isoformat(),
        )

        for entrypoint in _ENTRYPOINTS.values():
            graph.add_node(entrypoint)

        artifacts = await self._load_artifacts(scan_id)
        if not artifacts:
            logger.info("No artifacts found for scan %s — empty graph", scan_id)
            return graph

        loaded_artifacts: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for artifact in artifacts:
            payload = self._load_artifact_payload(artifact)
            loaded_artifacts.append((artifact, payload))
            for node in self._artifact_to_nodes(artifact, payload):
                graph.add_node(node)

        self._apply_relationships(graph, loaded_artifacts)
        self._infer_edges(graph)

        logger.info(
            "Attack graph built: scan=%s nodes=%d edges=%d",
            scan_id,
            len(graph.nodes),
            len(graph.edges),
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
        return await self.build(scan_id=scan_id, tenant_id=tenant_id)

    async def store_graph(self, graph: AttackGraph) -> uuid.UUID:
        """Serialize and store the attack graph as a scan artifact."""
        artifact_id = uuid.uuid4()
        storage_ref = f"graphs/{graph.tenant_id}/{graph.scan_id}/attack_graph.json"
        size_bytes, checksum = write_json_artifact(storage_ref, graph.to_dict())

        await self._session.execute(
            text(
                """
                DELETE FROM scan_artifacts
                WHERE scan_id = :sid AND artifact_type = 'attack_graph'
                """
            ),
            {"sid": graph.scan_id},
        )

        await self._session.execute(
            text(
                """
                INSERT INTO scan_artifacts (
                    id, scan_id, tenant_id, artifact_type, storage_ref,
                    content_type, size_bytes, checksum, metadata
                ) VALUES (
                    :id, :sid, :tid, 'attack_graph', :ref,
                    'application/json', :size, :checksum, CAST(:meta AS jsonb)
                )
                """
            ),
            {
                "id": str(artifact_id),
                "sid": graph.scan_id,
                "tid": graph.tenant_id,
                "ref": storage_ref,
                "size": size_bytes,
                "checksum": checksum,
                "meta": json.dumps(
                    apply_artifact_retention_metadata(
                        {
                            "node_count": len(graph.nodes),
                            "edge_count": len(graph.edges),
                            "built_at": graph.built_at,
                            "path_summary": graph.path_summary,
                            "scoring_summary": graph.scoring_summary,
                        },
                        policy="graph",
                    )
                ),
            },
        )

        await self._session.flush()
        logger.info(
            "Attack graph stored: artifact=%s nodes=%d edges=%d",
            artifact_id,
            len(graph.nodes),
            len(graph.edges),
        )
        return artifact_id

    async def _load_artifacts(self, scan_id: uuid.UUID) -> list[dict[str, Any]]:
        result = await self._session.execute(
            text(
                """
                SELECT id, artifact_type, storage_ref, metadata, node_id
                FROM scan_artifacts
                WHERE scan_id = :sid
                  AND artifact_type != 'attack_graph'
                ORDER BY created_at
                """
            ),
            {"sid": str(scan_id)},
        )
        return [dict(row) for row in result.mappings().all()]

    def _load_artifact_payload(self, artifact: dict[str, Any]) -> dict[str, Any]:
        storage_ref = str(artifact.get("storage_ref", ""))
        payload = read_json_artifact(storage_ref)
        if isinstance(payload, dict):
            return payload

        metadata = artifact.get("metadata", {})
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except Exception:
                metadata = {}

        return {
            "items": metadata.get("items", []),
            "findings": metadata.get("findings", []),
            "relationships": metadata.get("relationships", []),
            "summary": metadata.get("summary", {}),
        }

    def _artifact_to_nodes(
        self,
        artifact: dict[str, Any],
        payload: dict[str, Any] | None = None,
    ) -> list[AttackNode]:
        """Convert an artifact into one or more graph nodes."""
        payload = payload or self._load_artifact_payload(artifact)
        artifact_type = str(artifact.get("artifact_type", "unknown"))
        if artifact_type in _IGNORED_ARTIFACT_TYPES:
            return []
        node_type = _ARTIFACT_NODE_TYPE.get(artifact_type, "asset")
        storage_ref = str(artifact.get("storage_ref", ""))
        artifact_id = str(artifact.get("id", ""))
        findings = payload.get("findings", []) if isinstance(payload, dict) else []
        items = payload.get("items", []) if isinstance(payload, dict) else []

        nodes: list[AttackNode] = []

        if findings and artifact_type in {"vulnerabilities", "findings_scored"}:
            for finding in findings:
                fingerprint = str(finding.get("fingerprint") or artifact_id)
                nodes.append(
                    AttackNode(
                        id=f"vulnerability:{fingerprint}",
                        node_type="vulnerability",
                        label=str(finding.get("title") or finding.get("target") or artifact_type),
                        artifact_ref=storage_ref,
                        properties={
                            "artifact_type": artifact_type,
                            "artifact_id": artifact_id,
                            "severity": finding.get("severity"),
                            "target": finding.get("target"),
                            "endpoint": finding.get("endpoint"),
                            "entity_key": finding.get("entity_key", f"vulnerability:{fingerprint}"),
                            "fingerprint": fingerprint,
                        },
                    )
                )
            return nodes

        if findings and artifact_type in {
            "access_levels",
            "database_access",
            "shell_access",
            "credential_leak",
            "privilege_escalation",
            "verified_impact",
        }:
            impact_type = "credential" if artifact_type == "credential_leak" else "privilege"
            for finding in findings:
                fingerprint = str(finding.get("fingerprint") or artifact_id)
                target = str(finding.get("target") or artifact_type)
                nodes.append(
                    AttackNode(
                        id=f"{impact_type}:{fingerprint}",
                        node_type=impact_type,
                        label=str(finding.get("title") or target),
                        artifact_ref=storage_ref,
                        properties={
                            "artifact_type": artifact_type,
                            "artifact_id": artifact_id,
                            "severity": finding.get("severity"),
                            "target": target,
                            "entity_key": finding.get(
                                "entity_key",
                                f"{impact_type}:{target.lower()}",
                            ),
                        },
                    )
                )
            return nodes

        if items and len(items) <= 50:
            for index, item in enumerate(items):
                nodes.append(
                    AttackNode(
                        id=f"{artifact_type}:{artifact_id}:{index}",
                        node_type=node_type,
                        label=self._item_label(item, artifact_type, index),
                        artifact_ref=storage_ref,
                        properties={
                            "artifact_type": artifact_type,
                            "artifact_id": artifact_id,
                            "item_index": index,
                            "entity_key": item.get("entity_key"),
                            **{
                                key: value
                                for key, value in item.items()
                                if isinstance(value, (str, int, float, bool))
                            },
                        },
                    )
                )
            return nodes

        nodes.append(
            AttackNode(
                id=f"{artifact_type}:{artifact_id}",
                node_type=node_type,
                label=f"{artifact_type} ({artifact_type})",
                artifact_ref=storage_ref,
                properties={
                    "artifact_type": artifact_type,
                    "artifact_id": artifact_id,
                    "item_count": len(items) if items else 1,
                },
            )
        )
        return nodes

    def _item_label(self, item: dict[str, Any], artifact_type: str, index: int) -> str:
        for key in ("title", "host", "name", "url", "matched-at", "target", "service", "port", "access_level"):
            if key in item and item[key]:
                return str(item[key])[:80]
        return f"{artifact_type}[{index}]"

    def _apply_relationships(
        self,
        graph: AttackGraph,
        loaded_artifacts: list[tuple[dict[str, Any], dict[str, Any]]],
    ) -> None:
        entity_map: dict[str, list[str]] = {}
        for node in graph.nodes.values():
            entity_key = node.properties.get("entity_key")
            if isinstance(entity_key, str) and entity_key:
                entity_map.setdefault(entity_key, []).append(node.id)

        for artifact, payload in loaded_artifacts:
            relationships = payload.get("relationships", []) if isinstance(payload, dict) else []
            for relationship in relationships:
                source_key = str(relationship.get("source_key", ""))
                target_key = str(relationship.get("target_key", ""))
                edge_type = str(relationship.get("edge_type", "related"))
                for source_id in entity_map.get(source_key, []):
                    for target_id in entity_map.get(target_key, []):
                        if source_id == target_id or self._edge_exists(graph, source_id, target_id, edge_type):
                            continue
                        graph.add_edge(
                            AttackEdge(
                                source=source_id,
                                target=target_id,
                                edge_type=edge_type,
                                properties={
                                    "inferred": False,
                                    "artifact_ref": artifact.get("storage_ref"),
                                },
                            )
                        )

    def _infer_edges(self, graph: AttackGraph) -> None:
        nodes_by_type: dict[str, list[AttackNode]] = {}
        for node in graph.nodes.values():
            nodes_by_type.setdefault(node.node_type, []).append(node)

        for source_type, target_type, edge_type in _EDGE_RULES:
            sources = nodes_by_type.get(source_type, [])
            targets = nodes_by_type.get(target_type, [])
            if not sources or not targets:
                continue

            for source in sources:
                for target in targets:
                    if source.id == target.id:
                        continue
                    if self._edge_exists(graph, source.id, target.id, edge_type):
                        continue
                    if not self._should_link(source, target, edge_type):
                        continue
                    graph.add_edge(
                        AttackEdge(
                            source=source.id,
                            target=target.id,
                            edge_type=edge_type,
                            properties={
                                "inferred": True,
                                "rule": f"{source_type}->{target_type}",
                            },
                        )
                    )

    def _edge_exists(self, graph: AttackGraph, source_id: str, target_id: str, edge_type: str) -> bool:
        return any(
            edge.source == source_id and edge.target == target_id and edge.edge_type == edge_type
            for edge in graph.edges
        )

    def _should_link(self, source: AttackNode, target: AttackNode, edge_type: str) -> bool:
        if source.node_type == "entrypoint":
            return target.node_type == "asset"

        source_target = str(
            source.properties.get("target")
            or source.properties.get("host")
            or source.properties.get("url")
            or ""
        ).lower()
        target_target = str(
            target.properties.get("target")
            or target.properties.get("host")
            or target.properties.get("url")
            or target.properties.get("endpoint")
            or ""
        ).lower()
        target_key = str(target.properties.get("entity_key") or "").lower()

        if source.node_type == "asset" and target.node_type == "service":
            if not target_key:
                return True
            return source_target in target_key or source.label.lower() in target_key

        if source.node_type in {"asset", "service"} and target.node_type == "endpoint":
            if not source_target and not target_target:
                return True
            return source_target in target_target or source.label.lower() in target_target

        if source.node_type in {"asset", "endpoint"} and target.node_type == "vulnerability":
            if not source_target or not target_target:
                return True
            return source_target in target_target

        if source.node_type == "vulnerability" and target.node_type in {"credential", "privilege"}:
            return edge_type == "exploit"

        if source.node_type == "credential" and target.node_type in {"service", "privilege"}:
            return not source_target or source_target in target_target

        if source.node_type == "privilege" and target.node_type == "privilege":
            if source.id == target.id:
                return False
            if not self._same_target_context(source, target):
                return False
            return self._privilege_rank(source) < self._privilege_rank(target)

        return True

    def _same_target_context(self, source: AttackNode, target: AttackNode) -> bool:
        source_target = self._node_target_context(source)
        target_target = self._node_target_context(target)

        if source_target and target_target:
            return (
                source_target == target_target
                or source_target in target_target
                or target_target in source_target
            )

        source_key = str(source.properties.get("entity_key") or "")
        target_key = str(target.properties.get("entity_key") or "")
        if source_key and target_key:
            return source_key == target_key

        return False

    def _node_target_context(self, node: AttackNode) -> str:
        return str(
            node.properties.get("target")
            or node.properties.get("host")
            or node.properties.get("endpoint")
            or node.properties.get("url")
            or ""
        ).lower()

    def _privilege_rank(self, node: AttackNode) -> int:
        artifact_type = str(node.properties.get("artifact_type") or "").lower()
        access_text = " ".join(
            str(value).lower()
            for value in (
                node.properties.get("access_level"),
                node.properties.get("target"),
                node.label,
                artifact_type,
            )
            if value
        )

        rank = {
            "access_levels": 1,
            "database_access": 2,
            "shell_access": 3,
            "verified_impact": 4,
            "privilege_escalation": 5,
        }.get(artifact_type, 0)

        if any(token in access_text for token in ("read", "viewer", "user", "basic")):
            rank = max(rank, 1)
        if any(token in access_text for token in ("db", "database", "dba")):
            rank = max(rank, 2)
        if any(token in access_text for token in ("shell", "command", "exec")):
            rank = max(rank, 3)
        if any(token in access_text for token in ("admin", "root", "system", "superuser")):
            rank = max(rank, 4)

        return rank
