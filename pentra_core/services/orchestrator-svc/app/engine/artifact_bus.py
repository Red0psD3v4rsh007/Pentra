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
import os
import uuid
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
from pentra_common.storage.artifacts import read_json_artifact

logger = logging.getLogger(__name__)

# Artifact types that trigger exploit planning
_EXPLOIT_TRIGGER_TYPES = {"vulnerabilities"}

# Artifact types that trigger impact verification
_IMPACT_TRIGGER_TYPES = {"database_access", "shell_access", "credential_leak", "privilege_escalation"}

# Tools that produce exploit results
_EXPLOIT_TOOLS = {"sqlmap", "metasploit", "custom_poc"}


def _autonomy_disabled() -> bool:
    value = os.getenv("PENTRA_DISABLE_AUTONOMY", "false").strip().lower()
    return value in {"1", "true", "yes", "on"}


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
            "findings_persisted": 0,
        }
        scored = []
        artifact = await self._load_artifact(output_ref, output_summary)
        artifact_items = artifact.get("items", [])
        artifact_findings = artifact.get("findings", [])
        artifact_evidence = artifact.get("evidence", [])

        if artifact_findings:
            persisted = await self._persist_findings(
                scan_id=scan_id,
                tenant_id=tenant_id,
                node_id=node_id,
                findings=artifact_findings,
                evidence=artifact_evidence,
                output_ref=output_ref,
            )
            result["findings_persisted"] = persisted
            await self._refresh_scan_result_summary(scan_id)

        # 1 — Vulnerability artifact triggers exploit planning
        if artifact_type in _EXPLOIT_TRIGGER_TYPES:
            vuln_items = artifact_items

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
            impact_items = artifact_items

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
                    graph.path_summary = enumerator.get_path_summary(paths)
                    graph.scoring_summary = scorer.get_scoring_summary(scored)

                # Store updated graph as artifact
                await self._graph_builder.store_graph(graph)
                result["graph_updated"] = True
                await self._refresh_scan_result_summary(scan_id)

                if _autonomy_disabled():
                    logger.info(
                        "Autonomy expansion disabled for scan %s; skipping strategy and exploration",
                        scan_id,
                    )
                else:
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

    async def _load_artifact(
        self, output_ref: str, output_summary: dict | None,
    ) -> dict[str, Any]:
        """Load the rich normalized artifact from storage when possible."""
        payload = read_json_artifact(output_ref)
        if isinstance(payload, dict):
            return payload

        summary = output_summary or {}
        return {
            "items": summary.get("preview_items", []),
            "findings": summary.get("preview_findings", []),
            "evidence": [],
            "summary": summary.get("summary", {}),
        }

    async def _get_node_config(self, node_id: uuid.UUID) -> dict:
        """Read a node's config JSONB."""
        result = await self._session.execute(text("""
            SELECT config FROM scan_nodes WHERE id = :id
        """), {"id": str(node_id)})
        row = result.scalar()
        if row is None:
            return {}
        return row if isinstance(row, dict) else json.loads(str(row))

    async def _persist_findings(
        self,
        *,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        node_id: uuid.UUID,
        findings: list[dict[str, Any]],
        evidence: list[dict[str, Any]],
        output_ref: str,
    ) -> int:
        """Persist canonical artifact findings into the findings table."""
        job_result = await self._session.execute(
            text(
                """
                SELECT job_id
                FROM scan_nodes
                WHERE id = :id
                """
            ),
            {"id": str(node_id)},
        )
        job_id = job_result.scalar_one_or_none()

        if job_id is not None:
            await self._session.execute(
                text(
                    """
                    DELETE FROM findings
                    WHERE scan_id = :scan_id AND scan_job_id = :job_id
                    """
                ),
                {"scan_id": str(scan_id), "job_id": str(job_id)},
            )

        evidence_index: dict[str, list[dict[str, Any]]] = {}
        for evidence_item in evidence:
            fingerprint = str(evidence_item.get("finding_fingerprint", ""))
            if fingerprint:
                evidence_index.setdefault(fingerprint, []).append(evidence_item)

        inserted = 0
        for finding in findings:
            title = str(finding.get("title", "")).strip()
            if not title:
                continue

            fingerprint = str(finding.get("fingerprint") or uuid.uuid4().hex)
            evidence_payload = finding.get("evidence") or {}
            if not isinstance(evidence_payload, dict):
                evidence_payload = {}

            evidence_payload = {
                **evidence_payload,
                "storage_ref": output_ref,
                "references": [
                    {
                        "id": evidence_item.get("id"),
                        "evidence_type": evidence_item.get("evidence_type"),
                        "label": evidence_item.get("label"),
                        "content_preview": evidence_item.get("content_preview"),
                        "storage_ref": f"{output_ref}#{evidence_item.get('id')}",
                    }
                    for evidence_item in evidence_index.get(fingerprint, [])
                ],
            }

            await self._session.execute(
                text(
                    """
                    INSERT INTO findings (
                        id, tenant_id, scan_id, scan_job_id, source_type,
                        title, severity, confidence, cve_id, cvss_score,
                        description, evidence, remediation, tool_source,
                        is_false_positive, fp_probability, fingerprint
                    ) VALUES (
                        :id, :tenant_id, :scan_id, :scan_job_id, :source_type,
                        :title, :severity, :confidence, :cve_id, :cvss_score,
                        :description, CAST(:evidence AS jsonb), :remediation, :tool_source,
                        false, :fp_probability, :fingerprint
                    )
                    """
                ),
                {
                    "id": str(uuid.uuid4()),
                    "tenant_id": str(tenant_id),
                    "scan_id": str(scan_id),
                    "scan_job_id": str(job_id) if job_id is not None else None,
                    "source_type": str(finding.get("source_type", "scanner")),
                    "title": title,
                    "severity": str(finding.get("severity", "info")),
                    "confidence": int(finding.get("confidence", 60) or 60),
                    "cve_id": finding.get("cve_id"),
                    "cvss_score": finding.get("cvss_score"),
                    "description": finding.get("description"),
                    "evidence": json.dumps(evidence_payload),
                    "remediation": finding.get("remediation"),
                    "tool_source": str(finding.get("tool_source", "unknown")),
                    "fp_probability": finding.get("fp_probability"),
                    "fingerprint": fingerprint,
                },
            )
            inserted += 1

        return inserted

    async def _refresh_scan_result_summary(self, scan_id: uuid.UUID) -> None:
        """Refresh the scan.result_summary JSON from persisted findings and artifacts."""
        findings_result = await self._session.execute(
            text(
                """
                SELECT severity, COUNT(*) AS total
                FROM findings
                WHERE scan_id = :scan_id
                GROUP BY severity
                """
            ),
            {"scan_id": str(scan_id)},
        )

        severity_counts = {key: 0 for key in ("critical", "high", "medium", "low", "info")}
        for row in findings_result.mappings().all():
            severity_counts[str(row["severity"])] = int(row["total"])

        artifact_result = await self._session.execute(
            text(
                """
                SELECT artifact_type,
                       COALESCE((metadata->>'item_count')::int, 0) AS item_count,
                       COALESCE((metadata->>'finding_count')::int, 0) AS finding_count,
                       COALESCE((metadata->>'evidence_count')::int, 0) AS evidence_count
                FROM scan_artifacts
                WHERE scan_id = :scan_id
                """
            ),
            {"scan_id": str(scan_id)},
        )
        artifact_rows = artifact_result.mappings().all()
        artifact_types = [str(row["artifact_type"]) for row in artifact_rows]
        evidence_count = sum(int(row["evidence_count"]) for row in artifact_rows)

        attack_graph_result = await self._session.execute(
            text(
                """
                SELECT COUNT(*) > 0
                FROM scan_artifacts
                WHERE scan_id = :scan_id AND artifact_type = 'attack_graph'
                """
            ),
            {"scan_id": str(scan_id)},
        )
        attack_graph_ready = bool(attack_graph_result.scalar())

        summary = {
            "severity_counts": severity_counts,
            "total_findings": sum(severity_counts.values()),
            "artifact_count": len(artifact_rows),
            "artifact_types": sorted(set(artifact_types)),
            "evidence_count": evidence_count,
            "attack_graph_ready": attack_graph_ready,
        }

        await self._session.execute(
            text(
                """
                UPDATE scans
                SET result_summary = CAST(:summary AS jsonb)
                WHERE id = :scan_id
                """
            ),
            {"scan_id": str(scan_id), "summary": json.dumps(summary)},
        )
