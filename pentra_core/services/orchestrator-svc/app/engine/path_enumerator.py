"""Path enumerator — traverses the attack graph to find compromise paths.

MOD-07: Identifies all paths from attacker entrypoints to high-impact
targets (database_access, shell_access, admin_access, privilege_escalation).

Uses depth-first search with cycle detection and path length limits.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from app.engine.attack_graph_builder import AttackGraph

logger = logging.getLogger(__name__)

# High-impact target node types
_TARGET_NODE_TYPES = {"privilege", "credential"}

# Maximum path depth to prevent explosion
_MAX_PATH_DEPTH = 15


@dataclass
class AttackPath:
    """A single compromise path through the attack graph."""

    path_id: str
    nodes: list[str]       # ordered node IDs from entrypoint to target
    edges: list[str]       # edge types along the path
    entrypoint: str        # starting node ID
    target: str            # final target node ID
    target_type: str       # privilege | credential
    depth: int
    properties: dict = field(default_factory=dict)


class PathEnumerator:
    """Enumerates attack paths from entrypoints to targets.

    Usage::

        enumerator = PathEnumerator(graph)
        paths = enumerator.enumerate_paths()
    """

    def __init__(self, graph: AttackGraph) -> None:
        self._graph = graph
        self._adjacency: dict[str, list[tuple[str, str]]] = {}
        self._build_adjacency()

    def _build_adjacency(self) -> None:
        """Build an adjacency list from edges for fast traversal."""
        for edge in self._graph.edges:
            self._adjacency.setdefault(edge.source, []).append(
                (edge.target, edge.edge_type)
            )

    def enumerate_paths(
        self,
        *,
        max_depth: int = _MAX_PATH_DEPTH,
        max_paths: int = 100,
    ) -> list[AttackPath]:
        """Find all paths from entrypoints to high-impact targets.

        Returns a list of AttackPath objects, sorted by depth (shortest first).
        """
        paths: list[AttackPath] = []
        path_count = 0

        # Start DFS from each entrypoint
        entrypoints = [
            nid for nid, node in self._graph.nodes.items()
            if node.node_type == "entrypoint"
        ]

        for ep_id in entrypoints:
            if path_count >= max_paths:
                break

            found = self._dfs(
                start=ep_id,
                visited=set(),
                current_path=[],
                current_edges=[],
                max_depth=max_depth,
                max_paths=max_paths - path_count,
            )
            paths.extend(found)
            path_count += len(found)

        # Sort by depth (shortest compromise paths first)
        paths.sort(key=lambda p: p.depth)

        logger.info(
            "Path enumeration: %d paths found from %d entrypoints",
            len(paths), len(entrypoints),
        )
        return paths

    def _dfs(
        self,
        *,
        start: str,
        visited: set[str],
        current_path: list[str],
        current_edges: list[str],
        max_depth: int,
        max_paths: int,
    ) -> list[AttackPath]:
        """Depth-first search for paths to target nodes."""
        if len(current_path) > max_depth:
            return []

        visited.add(start)
        current_path.append(start)

        paths: list[AttackPath] = []

        # Check if current node is a target
        node = self._graph.nodes.get(start)
        if node and node.node_type in _TARGET_NODE_TYPES and len(current_path) > 1:
            entrypoint = current_path[0]
            paths.append(AttackPath(
                path_id=f"path:{entrypoint}→{start}:{len(current_path)}",
                nodes=list(current_path),
                edges=list(current_edges),
                entrypoint=entrypoint,
                target=start,
                target_type=node.node_type,
                depth=len(current_path),
                properties={
                    "target_artifact_type": node.properties.get("artifact_type", ""),
                },
            ))

        # Continue DFS if we haven't hit path limit
        if len(paths) < max_paths:
            neighbors = self._adjacency.get(start, [])
            for neighbor_id, edge_type in neighbors:
                if neighbor_id not in visited and len(paths) < max_paths:
                    current_edges.append(edge_type)
                    found = self._dfs(
                        start=neighbor_id,
                        visited=visited,
                        current_path=current_path,
                        current_edges=current_edges,
                        max_depth=max_depth,
                        max_paths=max_paths - len(paths),
                    )
                    paths.extend(found)
                    current_edges.pop()

        current_path.pop()
        visited.discard(start)

        return paths

    def get_path_summary(self, paths: list[AttackPath]) -> dict:
        """Summarize enumerated paths for reporting."""
        if not paths:
            return {"total_paths": 0, "targets_reached": [], "shortest_path": 0}

        targets = set()
        for p in paths:
            target_node = self._graph.nodes.get(p.target)
            if target_node:
                targets.add(target_node.properties.get("artifact_type", p.target_type))

        return {
            "total_paths": len(paths),
            "targets_reached": sorted(targets),
            "shortest_path": min(p.depth for p in paths),
            "longest_path": max(p.depth for p in paths),
            "avg_path_length": sum(p.depth for p in paths) / len(paths),
        }
