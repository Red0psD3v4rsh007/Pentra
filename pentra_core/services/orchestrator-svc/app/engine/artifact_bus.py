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

_DERIVED_EXECUTION_TOOLS = frozenset({"ai_triage", "report_gen"})

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
            "verification_outcomes_applied": 0,
        }
        scored = []
        artifact = await self._load_artifact(output_ref, output_summary)
        artifact_items = artifact.get("items", [])
        artifact_findings = artifact.get("findings", [])
        artifact_evidence = artifact.get("evidence", [])
        scan_config = await self._load_scan_config(scan_id)
        verification_queue_candidates: list[dict[str, Any]] = []

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
            verification_queue_candidates = _build_verification_queue_candidates(
                findings=artifact_findings,
                output_ref=output_ref,
            )

        # 1 — Vulnerability artifact triggers exploit planning
        if artifact_type in _EXPLOIT_TRIGGER_TYPES:
            vuln_items = verification_queue_candidates or artifact_items

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
        elif verification_queue_candidates:
            created = await self._planner.plan_exploits(
                dag_id=dag_id,
                scan_id=scan_id,
                tenant_id=tenant_id,
                source_node_id=node_id,
                source_output_ref=output_ref,
                vulnerability_items=verification_queue_candidates,
                scan_config=scan_config,
            )
            result["dynamic_nodes_created"] = len(created)

            if created:
                logger.info(
                    "ArtifactBus: %d queued verification nodes created from %s (%s)",
                    len(created), tool, artifact_type,
                )

        # 2 — Exploit tool output triggers impact verification
        if tool in _EXPLOIT_TOOLS:
            impact_count = 0
            if artifact_type not in (_IMPACT_TRIGGER_TYPES | {"verified_impact"}):
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

            proof_observed = bool(artifact_findings) or impact_count > 0
            reconciled = await self._sync_verification_outcome_to_findings(
                scan_id=scan_id,
                node_id=node_id,
                tool=tool,
                output_ref=output_ref,
                artifact=artifact,
                proof_observed=proof_observed,
            )
            result["verification_outcomes_applied"] = reconciled
            if reconciled > 0:
                await self._refresh_scan_result_summary(scan_id)


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

    async def _sync_verification_outcome_to_findings(
        self,
        *,
        scan_id: uuid.UUID,
        node_id: uuid.UUID,
        tool: str,
        output_ref: str,
        artifact: dict[str, Any],
        proof_observed: bool,
    ) -> int:
        metadata = artifact.get("metadata") or {}
        if not isinstance(metadata, dict):
            metadata = {}
        execution_provenance = str(metadata.get("execution_provenance") or "").strip().lower()
        if execution_provenance != "live":
            return 0

        node_config = await self._get_node_config(node_id)
        verification_context = node_config.get("verification_context") or {}
        if not isinstance(verification_context, dict) or not verification_context:
            return 0

        candidate_rows = await self._load_verification_target_findings(
            scan_id=scan_id,
            verification_context=verification_context,
        )
        if not candidate_rows:
            return 0

        occurred_at = datetime.now(timezone.utc).isoformat()
        applied = 0
        for row in candidate_rows:
            existing_evidence = row.get("evidence") or {}
            if not isinstance(existing_evidence, dict):
                existing_evidence = {}
            source_type = str(row.get("source_type") or "scanner")
            merged_evidence = _merge_verification_outcome_evidence(
                existing=existing_evidence,
                source_type=source_type,
                verification_context=verification_context,
                artifact=artifact,
                output_ref=output_ref,
                tool=tool,
                occurred_at=occurred_at,
                proof_observed=proof_observed,
            )
            if merged_evidence == existing_evidence:
                continue

            await self._session.execute(
                text(
                    """
                    UPDATE findings
                    SET evidence = CAST(:evidence AS jsonb)
                    WHERE id = :id
                    """
                ),
                {
                    "id": str(row["id"]),
                    "evidence": json.dumps(merged_evidence),
                },
            )
            applied += 1
        return applied

    async def _load_verification_target_findings(
        self,
        *,
        scan_id: uuid.UUID,
        verification_context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        fingerprint = str(verification_context.get("finding_fingerprint") or "").strip()
        if fingerprint:
            result = await self._session.execute(
                text(
                    """
                    SELECT id, fingerprint, source_type, title, evidence, is_false_positive
                    FROM findings
                    WHERE scan_id = :scan_id
                      AND fingerprint = :fingerprint
                      AND source_type <> 'exploit_verify'
                    """
                ),
                {
                    "scan_id": str(scan_id),
                    "fingerprint": fingerprint,
                },
            )
            return [dict(row) for row in result.mappings().all()]

        result = await self._session.execute(
            text(
                """
                SELECT id, fingerprint, source_type, title, evidence, is_false_positive
                FROM findings
                WHERE scan_id = :scan_id
                  AND source_type <> 'exploit_verify'
                """
            ),
            {"scan_id": str(scan_id)},
        )
        rows = [dict(row) for row in result.mappings().all()]
        return [
            row
            for row in rows
            if _finding_matches_verification_context(row, verification_context)
        ]

    async def _refresh_scan_result_summary(self, scan_id: uuid.UUID) -> None:
        """Refresh the scan.result_summary JSON from persisted findings and artifacts."""
        # Severity aggregate — GROUP BY severity only (not evidence!)
        severity_result = await self._session.execute(
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
        for row in severity_result.mappings().all():
            severity = str(row["severity"])
            severity_counts[severity] = severity_counts.get(severity, 0) + int(row["total"])

        # Verification state aggregate — extract from evidence JSONB
        verification_result = await self._session.execute(
            text(
                """
                SELECT COALESCE(
                    evidence->'classification'->>'verification_state',
                    'detected'
                ) AS vstate,
                COUNT(*) AS total
                FROM findings
                WHERE scan_id = :scan_id
                GROUP BY vstate
                """
            ),
            {"scan_id": str(scan_id)},
        )

        verification_counts = {"verified": 0, "suspected": 0, "detected": 0}
        for row in verification_result.mappings().all():
            state = str(row["vstate"])
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
        execution_summary = {"live": 0, "simulated": 0, "blocked": 0, "inferred": 0, "derived": 0}
        for row in artifact_rows:
            artifact_type = str(row["artifact_type"])
            metadata = row.get("metadata") or {}
            if not isinstance(metadata, dict):
                metadata = {}
            tool_name = str(metadata.get("tool") or "").strip().lower()
            provenance = str(metadata.get("execution_provenance") or "").strip().lower()
            reason = str(metadata.get("execution_reason") or "").strip().lower()
            if (
                tool_name in _DERIVED_EXECUTION_TOOLS
                and provenance == "blocked"
                and reason == "not_supported"
            ):
                execution_summary["derived"] += 1
                continue

            if artifact_type in {"attack_graph", "report", "ai_reasoning"}:
                execution_summary["inferred"] += 1
                continue

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


_QUEUEABLE_SOURCE_TYPES = frozenset({"scanner", "ai_analysis"})
_TERMINAL_TRUTH_STATES = frozenset({"verified", "reproduced", "rejected", "expired"})
_RAW_EVIDENCE_KEYS = ("request", "response", "payload", "exploit_result", "proof", "content", "excerpt", "transcript")


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _default_verification_state_for_source(source_type: str) -> str:
    return "suspected" if source_type == "ai_analysis" else "detected"


def _finding_truth_state_from_payload(finding: dict[str, Any]) -> str:
    evidence = _as_dict(finding.get("evidence"))
    classification = _as_dict(evidence.get("classification"))
    metadata = _as_dict(evidence.get("metadata"))

    for container in (classification, metadata):
        state = str(container.get("truth_state") or "").strip().lower()
        if state in _TERMINAL_TRUTH_STATES | {"observed", "suspected"}:
            return state

    if bool(finding.get("is_false_positive")):
        return "rejected"

    for container in (classification, metadata):
        if bool(container.get("expired")) or container.get("expired_at"):
            return "expired"

    verification_state = str(
        classification.get("verification_state")
        or finding.get("verification_state")
        or ""
    ).strip().lower()
    if verification_state == "verified":
        return "verified"
    if verification_state == "suspected" or str(finding.get("source_type") or "").strip().lower() == "ai_analysis":
        return "suspected"
    return "observed"


def _has_raw_finding_evidence(evidence: dict[str, Any]) -> bool:
    return any(str(evidence.get(key) or "").strip() for key in _RAW_EVIDENCE_KEYS)


def _build_verification_queue_candidates(
    *,
    findings: list[dict[str, Any]],
    output_ref: str,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for finding in findings:
        candidate = _build_verification_queue_candidate(
            finding=finding,
            output_ref=output_ref,
        )
        if candidate is not None:
            candidates.append(candidate)
    return candidates


def _build_verification_queue_candidate(
    *,
    finding: dict[str, Any],
    output_ref: str,
) -> dict[str, Any] | None:
    source_type = str(finding.get("source_type") or "scanner").strip().lower()
    if source_type not in _QUEUEABLE_SOURCE_TYPES:
        return None

    truth_state = _finding_truth_state_from_payload(finding)
    if truth_state in _TERMINAL_TRUTH_STATES:
        return None

    title = str(finding.get("title") or "").strip()
    evidence = _as_dict(finding.get("evidence"))
    classification = _as_dict(evidence.get("classification"))
    metadata = _as_dict(evidence.get("metadata"))
    references = _as_list(evidence.get("references"))
    raw_evidence_present = _has_raw_finding_evidence(evidence)
    has_material = raw_evidence_present or any(
        isinstance(item, dict) and any(
            item.get(key) for key in ("id", "evidence_type", "label", "storage_ref")
        )
        for item in references
    )
    if not title or not has_material:
        return None

    endpoint = str(
        finding.get("endpoint")
        or evidence.get("endpoint")
        or finding.get("target")
        or evidence.get("target")
        or ""
    ).strip()
    if not endpoint:
        return None

    return {
        **finding,
        "target": finding.get("target") or evidence.get("target") or endpoint,
        "endpoint": finding.get("endpoint") or evidence.get("endpoint") or endpoint,
        "request": finding.get("request") or evidence.get("request"),
        "response": finding.get("response") or evidence.get("response"),
        "payload": finding.get("payload") or evidence.get("payload"),
        "exploit_result": finding.get("exploit_result") or evidence.get("exploit_result"),
        "surface": finding.get("surface") or classification.get("surface"),
        "route_group": finding.get("route_group") or classification.get("route_group"),
        "vulnerability_type": finding.get("vulnerability_type") or classification.get("vulnerability_type"),
        "references": references,
        "verification_context": _as_dict(metadata.get("verification_context")),
        "storage_ref": str(evidence.get("storage_ref") or output_ref).strip() or output_ref,
        "verification_state": str(
            classification.get("verification_state")
            or finding.get("verification_state")
            or _default_verification_state_for_source(source_type)
        ).strip().lower(),
    }


def _merge_verification_outcome_evidence(
    *,
    existing: dict[str, Any],
    source_type: str,
    verification_context: dict[str, Any],
    artifact: dict[str, Any],
    output_ref: str,
    tool: str,
    occurred_at: str,
    proof_observed: bool,
) -> dict[str, Any]:
    merged = dict(existing)
    classification = _as_dict(merged.get("classification"))
    metadata = _as_dict(merged.get("metadata"))
    references = _as_list(merged.get("references"))
    artifact_summary = _as_dict(artifact.get("summary"))
    artifact_findings = artifact.get("findings") or []

    metadata["verification_context"] = _merge_verification_context(
        metadata.get("verification_context"),
        verification_context,
    )
    metadata["last_verification_outcome"] = "verified" if proof_observed else "failed"
    metadata["last_verification_ref"] = output_ref
    metadata["last_verification_tool"] = tool
    metadata["verification_attempted_at"] = occurred_at
    metadata["replayable"] = True

    if proof_observed:
        classification["verification_state"] = "verified"
        classification["verified"] = True
        classification["verification_outcome"] = "verified"
        classification.pop("truth_state", None)
        metadata.pop("truth_state", None)
        metadata["verified_at"] = occurred_at
        metadata.pop("verification_failed_at", None)

        proof_finding = artifact_findings[0] if artifact_findings else {}
        proof_evidence = _as_dict(_as_dict(proof_finding).get("evidence"))
        for key in ("request", "response", "payload", "exploit_result"):
            if not merged.get(key):
                candidate_value = proof_evidence.get(key)
                if candidate_value:
                    merged[key] = candidate_value

        references = _append_reference(
            references,
            {
                "id": f"{tool}:verification",
                "evidence_type": "verification_artifact",
                "label": f"{tool} verification proof",
                "content_preview": _verification_artifact_preview(
                    artifact=artifact,
                    proof_observed=True,
                ),
                "storage_ref": output_ref,
            },
        )
    else:
        classification["verification_state"] = _default_verification_state_for_source(source_type)
        classification["verified"] = False
        classification["truth_state"] = "rejected"
        classification["verification_outcome"] = "failed"
        metadata["verification_failed_at"] = occurred_at
        metadata["negative_verification_count"] = int(
            metadata.get("negative_verification_count") or 0
        ) + 1
        metadata["negative_verifications"] = _append_negative_verification(
            metadata.get("negative_verifications"),
            {
                "at": occurred_at,
                "tool": tool,
                "storage_ref": output_ref,
                "outcome": "failed",
                "summary": _verification_artifact_preview(
                    artifact=artifact,
                    proof_observed=False,
                ),
            },
        )
        metadata.pop("verified_at", None)
        references = _append_reference(
            references,
            {
                "id": f"{tool}:negative-verification",
                "evidence_type": "negative_verification",
                "label": f"{tool} negative verification",
                "content_preview": _verification_artifact_preview(
                    artifact=artifact,
                    proof_observed=False,
                ),
                "storage_ref": output_ref,
            },
        )

    if not merged.get("storage_ref"):
        merged["storage_ref"] = output_ref
    if not classification.get("vulnerability_type"):
        vuln_type = str(verification_context.get("vulnerability_type") or "").strip().lower()
        if vuln_type:
            classification["vulnerability_type"] = vuln_type
    if not classification.get("route_group") and verification_context.get("route_group"):
        classification["route_group"] = verification_context.get("route_group")
    if not classification.get("surface") and verification_context.get("surface"):
        classification["surface"] = verification_context.get("surface")
    if artifact_summary.get("execution"):
        classification["execution_mode"] = _as_dict(artifact_summary.get("execution")).get("mode")
        classification["execution_provenance"] = _as_dict(artifact_summary.get("execution")).get("provenance")

    merged["classification"] = classification
    merged["metadata"] = metadata
    merged["references"] = references
    return merged


def _merge_verification_context(existing: Any, candidate: dict[str, Any]) -> dict[str, Any]:
    merged = _as_dict(existing)
    for key, value in candidate.items():
        if value not in (None, "", [], {}):
            merged[key] = value
    return merged


def _append_negative_verification(existing: Any, entry: dict[str, Any]) -> list[dict[str, Any]]:
    items = [item for item in _as_list(existing) if isinstance(item, dict)]
    signature = json.dumps(entry, sort_keys=True)
    seen = {json.dumps(item, sort_keys=True) for item in items}
    if signature not in seen:
        items.append(entry)
    return items


def _append_reference(existing: list[Any], candidate: dict[str, Any]) -> list[dict[str, Any]]:
    items = [item for item in existing if isinstance(item, dict)]
    signature = json.dumps(
        {
            "id": candidate.get("id"),
            "type": candidate.get("evidence_type"),
            "preview": candidate.get("content_preview"),
            "ref": candidate.get("storage_ref"),
        },
        sort_keys=True,
    )
    seen = {
        json.dumps(
            {
                "id": item.get("id"),
                "type": item.get("evidence_type"),
                "preview": item.get("content_preview"),
                "ref": item.get("storage_ref"),
            },
            sort_keys=True,
        )
        for item in items
    }
    if signature not in seen:
        items.append(candidate)
    return items


def _verification_artifact_preview(*, artifact: dict[str, Any], proof_observed: bool) -> str:
    if proof_observed:
        finding = _as_dict((artifact.get("findings") or [{}])[0])
        title = str(finding.get("title") or "").strip()
        exploit_result = str(_as_dict(finding.get("evidence")).get("exploit_result") or "").strip()
        if title and exploit_result:
            return f"{title}: {exploit_result[:180]}"
        if title:
            return title
    summary = _as_dict(artifact.get("summary"))
    highlights = summary.get("highlights")
    if isinstance(highlights, list) and highlights:
        return str(highlights[0])
    return (
        "Bounded verification produced replayable negative evidence and did not reproduce the issue."
        if not proof_observed
        else "Verification completed."
    )


def _finding_matches_verification_context(
    finding: dict[str, Any],
    verification_context: dict[str, Any],
) -> bool:
    evidence = _as_dict(finding.get("evidence"))
    classification = _as_dict(evidence.get("classification"))

    context_vuln = str(verification_context.get("vulnerability_type") or "").strip().lower()
    finding_vuln = str(classification.get("vulnerability_type") or "").strip().lower()
    if context_vuln and finding_vuln and context_vuln != finding_vuln:
        return False

    context_locators = _normalized_context_locators(verification_context)
    finding_locators = _normalized_finding_locators(finding)
    if context_locators and finding_locators and context_locators.isdisjoint(finding_locators):
        return False

    context_title = str(
        verification_context.get("finding_title")
        or verification_context.get("title")
        or ""
    ).strip().lower()
    finding_title = str(finding.get("title") or "").strip().lower()
    if context_title and finding_title and context_title == finding_title:
        return True

    return bool(context_locators & finding_locators) or (not context_locators and not context_title)


def _normalized_context_locators(verification_context: dict[str, Any]) -> set[str]:
    values = [
        verification_context.get("request_url"),
        verification_context.get("endpoint"),
        verification_context.get("target"),
        verification_context.get("route_group"),
    ]
    result: set[str] = set()
    for value in values:
        result.update(_normalize_locator_values(value))
    return result


def _normalized_finding_locators(finding: dict[str, Any]) -> set[str]:
    evidence = _as_dict(finding.get("evidence"))
    classification = _as_dict(evidence.get("classification"))
    values = [
        finding.get("target"),
        finding.get("endpoint"),
        evidence.get("target"),
        evidence.get("endpoint"),
        classification.get("route_group"),
    ]
    result: set[str] = set()
    for value in values:
        result.update(_normalize_locator_values(value))
    return result


def _normalize_locator_values(value: Any) -> set[str]:
    raw = str(value or "").strip().lower()
    if not raw:
        return set()
    normalized = raw.rstrip("/")
    if "://" in normalized:
        try:
            from urllib.parse import urlsplit

            parsed = urlsplit(normalized)
            path = (parsed.path or "/").rstrip("/") or "/"
            host = parsed.netloc.lower()
            return {normalized, f"{host}{path}", path}
        except ValueError:
            return {normalized}
    return {normalized}
