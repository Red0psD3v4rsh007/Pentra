"""Artifact bus — event-driven artifact propagation and exploit triggering.

MOD-06: Called after a node completes.  Inspects the completed artifact:
  - If artifact_type is 'vulnerabilities' or high-signal 'endpoints': triggers ExploitPlanner
  - If artifact_type is exploit output: triggers ImpactVerifier

MOD-07: Every artifact completion triggers incremental attack graph update.

The artifact bus does NOT directly modify node states.
State transitions remain handled by:
  dependency_resolver, pipeline_executor, state_manager

It creates new nodes/edges via ExploitPlanner and impact artifacts
via ImpactVerifier, then signals the pipeline executor to re-resolve.
"""

from __future__ import annotations

__classification__ = "runtime_hot_path"

import json
import logging
import os
import uuid
from datetime import datetime, timezone
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
_EXPLOIT_TRIGGER_TYPES = {"vulnerabilities", "endpoints"}

# Artifact types that trigger impact verification
_IMPACT_TRIGGER_TYPES = {"database_access", "shell_access", "credential_leak", "privilege_escalation"}

# Tools that produce exploit results
_EXPLOIT_TOOLS = {"sqlmap_verify", "metasploit", "msf_verify", "custom_poc"}


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
        scan_config = await self._load_scan_config(scan_id)

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
                    scan_config=scan_config,
                )
                result["dynamic_nodes_created"] = len(created)

                if created:
                    logger.info(
                        "ArtifactBus: %d exploit nodes created from %s (%s)",
                        len(created), tool, artifact_type,
                    )

        # 2 — Exploit tool output triggers impact verification
        if tool in _EXPLOIT_TOOLS and artifact_type not in (_IMPACT_TRIGGER_TYPES | {"verified_impact"}):
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

    async def _load_scan_config(self, scan_id: uuid.UUID) -> dict[str, Any]:
        result = await self._session.execute(
            text(
                """
                SELECT config
                FROM scans
                WHERE id = :scan_id
                """
            ),
            {"scan_id": str(scan_id)},
        )
        row = result.scalar_one_or_none()
        if isinstance(row, dict):
            return row
        if isinstance(row, str) and row.strip():
            return json.loads(row)
        return {}

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

        existing_result = await self._session.execute(
            text(
                """
                SELECT id, fingerprint, source_type, severity, confidence, title,
                       cve_id, cvss_score, description, remediation, tool_source, evidence
                FROM findings
                WHERE scan_id = :scan_id
                """
            ),
            {"scan_id": str(scan_id)},
        )
        existing_by_fingerprint = {
            str(row["fingerprint"]): dict(row)
            for row in existing_result.mappings().all()
            if row.get("fingerprint")
        }

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

            source_type = str(finding.get("source_type", "scanner"))
            severity = str(finding.get("severity", "info"))
            confidence = int(finding.get("confidence", 60) or 60)
            tool_source = str(finding.get("tool_source", "unknown"))
            if source_type == "exploit_verify":
                metadata = evidence_payload.get("metadata") or {}
                if not isinstance(metadata, dict):
                    metadata = {}
                metadata.setdefault("verified_at", datetime.now(timezone.utc).isoformat())
                evidence_payload["metadata"] = metadata

            existing = existing_by_fingerprint.get(fingerprint)
            if existing is not None:
                merged = _merge_finding_record(
                    existing=existing,
                    candidate={
                        "source_type": source_type,
                        "severity": severity,
                        "confidence": confidence,
                        "title": title,
                        "cve_id": finding.get("cve_id"),
                        "cvss_score": finding.get("cvss_score"),
                        "description": finding.get("description"),
                        "remediation": finding.get("remediation"),
                        "tool_source": tool_source,
                        "evidence": evidence_payload,
                    },
                )

                await self._session.execute(
                    text(
                        """
                        UPDATE findings
                        SET source_type = :source_type,
                            severity = :severity,
                            confidence = :confidence,
                            title = :title,
                            cve_id = :cve_id,
                            cvss_score = :cvss_score,
                            description = :description,
                            evidence = CAST(:evidence AS jsonb),
                            remediation = :remediation,
                            tool_source = :tool_source
                        WHERE id = :id
                        """
                    ),
                    {
                        "id": str(existing["id"]),
                        "source_type": merged["source_type"],
                        "severity": merged["severity"],
                        "confidence": merged["confidence"],
                        "title": merged["title"],
                        "cve_id": merged["cve_id"],
                        "cvss_score": merged["cvss_score"],
                        "description": merged["description"],
                        "evidence": json.dumps(merged["evidence"]),
                        "remediation": merged["remediation"],
                        "tool_source": merged["tool_source"],
                    },
                )
                existing_by_fingerprint[fingerprint] = {**existing, **merged}
                inserted += 1
                continue

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
                    "source_type": source_type,
                    "title": title,
                    "severity": severity,
                    "confidence": confidence,
                    "cve_id": finding.get("cve_id"),
                    "cvss_score": finding.get("cvss_score"),
                    "description": finding.get("description"),
                    "evidence": json.dumps(evidence_payload),
                    "remediation": finding.get("remediation"),
                    "tool_source": tool_source,
                    "fp_probability": finding.get("fp_probability"),
                    "fingerprint": fingerprint,
                },
            )
            existing_by_fingerprint[fingerprint] = {
                "fingerprint": fingerprint,
                "source_type": source_type,
                "severity": severity,
                "confidence": confidence,
                "title": title,
                "cve_id": finding.get("cve_id"),
                "cvss_score": finding.get("cvss_score"),
                "description": finding.get("description"),
                "remediation": finding.get("remediation"),
                "tool_source": tool_source,
                "evidence": evidence_payload,
            }
            inserted += 1

        return inserted

    async def _refresh_scan_result_summary(self, scan_id: uuid.UUID) -> None:
        """Refresh the scan.result_summary JSON from persisted findings and artifacts."""
        findings_result = await self._session.execute(
            text(
                """
                SELECT severity, evidence, COUNT(*) AS total
                FROM findings
                WHERE scan_id = :scan_id
                GROUP BY severity, evidence
                """
            ),
            {"scan_id": str(scan_id)},
        )

        severity_counts = {key: 0 for key in ("critical", "high", "medium", "low", "info")}
        verification_counts = {"verified": 0, "suspected": 0, "detected": 0}
        for row in findings_result.mappings().all():
            severity = str(row["severity"])
            severity_counts[severity] = severity_counts.get(severity, 0) + int(row["total"])
            evidence = row.get("evidence") or {}
            if isinstance(evidence, dict):
                classification = evidence.get("classification") or {}
                if isinstance(classification, dict):
                    state = str(classification.get("verification_state") or "detected")
                    if state in verification_counts:
                        verification_counts[state] += int(row["total"])

        artifact_result = await self._session.execute(
            text(
                """
                SELECT artifact_type,
                       metadata,
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
        execution_summary = {"live": 0, "simulated": 0, "blocked": 0, "inferred": 0}
        for row in artifact_rows:
            artifact_type = str(row["artifact_type"])
            if artifact_type in {"attack_graph", "report", "ai_reasoning"}:
                execution_summary["inferred"] += 1
                continue

            metadata = row.get("metadata") or {}
            if not isinstance(metadata, dict):
                metadata = {}
            provenance = str(metadata.get("execution_provenance") or "").strip().lower()
            if provenance in execution_summary:
                execution_summary[provenance] += 1

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
            "verification_counts": verification_counts,
            "total_findings": sum(severity_counts.values()),
            "artifact_count": len(artifact_rows),
            "artifact_types": sorted(set(artifact_types)),
            "evidence_count": evidence_count,
            "attack_graph_ready": attack_graph_ready,
            "execution_summary": execution_summary,
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


def _merge_finding_record(
    *,
    existing: dict[str, Any],
    candidate: dict[str, Any],
) -> dict[str, Any]:
    existing_evidence = existing.get("evidence") or {}
    candidate_evidence = candidate.get("evidence") or {}
    if not isinstance(existing_evidence, dict):
        existing_evidence = {}
    if not isinstance(candidate_evidence, dict):
        candidate_evidence = {}

    merged_evidence = _merge_evidence_payload(
        existing_evidence,
        candidate_evidence,
        existing_tool_source=existing.get("tool_source"),
        candidate_tool_source=candidate.get("tool_source"),
    )
    use_candidate = _source_rank(str(candidate.get("source_type", "scanner"))) >= _source_rank(
        str(existing.get("source_type", "scanner"))
    )

    merged = {
        "source_type": candidate["source_type"] if use_candidate else existing.get("source_type"),
        "severity": _better_severity(existing.get("severity"), candidate.get("severity")),
        "confidence": max(int(existing.get("confidence", 0) or 0), int(candidate.get("confidence", 0) or 0)),
        "title": candidate.get("title") if use_candidate else existing.get("title"),
        "cve_id": candidate.get("cve_id") or existing.get("cve_id"),
        "cvss_score": candidate.get("cvss_score") or existing.get("cvss_score"),
        "description": _prefer_text(existing.get("description"), candidate.get("description")),
        "remediation": _prefer_text(existing.get("remediation"), candidate.get("remediation")),
        "tool_source": candidate.get("tool_source") if use_candidate else existing.get("tool_source"),
        "evidence": merged_evidence,
    }
    return merged


def _merge_evidence_payload(
    existing: dict[str, Any],
    candidate: dict[str, Any],
    *,
    existing_tool_source: str | None = None,
    candidate_tool_source: str | None = None,
) -> dict[str, Any]:
    merged = dict(existing)

    for key in ("target", "endpoint", "request", "response", "payload", "exploit_result", "storage_ref", "account"):
        current = merged.get(key)
        candidate_value = candidate.get(key)
        if not current and candidate_value:
            merged[key] = candidate_value

    existing_references = existing.get("references") or []
    candidate_references = candidate.get("references") or []
    if not isinstance(existing_references, list):
        existing_references = []
    if not isinstance(candidate_references, list):
        candidate_references = []

    seen: set[str] = set()
    merged_refs: list[dict[str, Any]] = []
    for reference in existing_references + candidate_references:
        if not isinstance(reference, dict):
            continue
        signature = json.dumps(
            {
                "id": reference.get("id"),
                "type": reference.get("evidence_type"),
                "preview": reference.get("content_preview"),
                "ref": reference.get("storage_ref"),
            },
            sort_keys=True,
        )
        if signature in seen:
            continue
        seen.add(signature)
        merged_refs.append(reference)
    merged["references"] = merged_refs

    existing_classification = existing.get("classification") or {}
    candidate_classification = candidate.get("classification") or {}
    if not isinstance(existing_classification, dict):
        existing_classification = {}
    if not isinstance(candidate_classification, dict):
        candidate_classification = {}
    merged["classification"] = {
        **existing_classification,
        **{key: value for key, value in candidate_classification.items() if value not in (None, "", [], {})},
    }

    metadata = existing.get("metadata") or {}
    if not isinstance(metadata, dict):
        metadata = {}
    tool_sources = set(metadata.get("tool_sources", []))
    tool_sources.update(
        source
        for source in (existing_tool_source, candidate_tool_source)
        if source
    )
    metadata["tool_sources"] = sorted(tool_sources)
    merged["metadata"] = metadata
    return merged


def _source_rank(source_type: str) -> int:
    return {"scanner": 1, "ai_analysis": 2, "exploit_verify": 3}.get(source_type, 0)


def _better_severity(existing: str | None, candidate: str | None) -> str:
    return candidate if _severity_rank(candidate) > _severity_rank(existing) else str(existing or candidate or "info")


def _severity_rank(severity: str | None) -> int:
    return {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
    }.get(str(severity or "info"), 0)


def _prefer_text(existing: Any, candidate: Any) -> Any:
    if not existing:
        return candidate
    if candidate and len(str(candidate)) > len(str(existing)):
        return candidate
    return existing
