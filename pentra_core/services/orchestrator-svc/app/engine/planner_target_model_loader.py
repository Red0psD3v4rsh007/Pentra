"""Planner target-model loader.

Builds a compact, planner-facing target summary directly inside the
orchestrator from persisted findings and scan artifacts. This avoids making
the planner depend on raw scanner logs or on cross-service API calls.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
import uuid
from typing import Any
from urllib.parse import parse_qsl, urlparse

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from pentra_common.storage.artifacts import read_json_artifact

from app.knowledge.ontology_registry import align_capability_graphs
from app.knowledge.target_profile_registry import classify_target_profiles

_TRUTH_STATES = ("observed", "suspected", "reproduced", "verified", "rejected", "expired")
_SEVERITIES = ("critical", "high", "medium", "low", "info")
_RAW_EVIDENCE_KEYS = ("request", "response", "payload", "proof", "transcript", "excerpt", "content")
_UUIDISH_SEGMENT = re.compile(r"^[0-9a-f]{8,}$", re.IGNORECASE)
_SENSITIVE_PARAMETER_HINTS = (
    "password",
    "passwd",
    "token",
    "secret",
    "csrf",
    "session",
    "cookie",
    "auth",
    "otp",
    "code",
    "id",
)


@dataclass(frozen=True)
class PlannerRouteGroupSummary:
    route_group: str
    focus_score: int
    requires_auth: bool
    auth_variants: list[str]
    parameter_names: list[str]
    endpoint_urls: list[str]
    workflow_edge_count: int
    interaction_kinds: list[str]
    safe_replay: bool
    vulnerability_types: list[str]
    truth_counts: dict[str, int]
    severity_counts: dict[str, int]
    evidence_gaps: list[str]

    @property
    def top_target_url(self) -> str:
        return self.endpoint_urls[0] if self.endpoint_urls else ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "route_group": self.route_group,
            "focus_score": self.focus_score,
            "requires_auth": self.requires_auth,
            "auth_variants": list(self.auth_variants),
            "parameter_names": list(self.parameter_names),
            "endpoint_urls": list(self.endpoint_urls),
            "workflow_edge_count": self.workflow_edge_count,
            "interaction_kinds": list(self.interaction_kinds),
            "safe_replay": self.safe_replay,
            "vulnerability_types": list(self.vulnerability_types),
            "truth_counts": dict(self.truth_counts),
            "severity_counts": dict(self.severity_counts),
            "evidence_gaps": list(self.evidence_gaps),
        }


@dataclass(frozen=True)
class PlannerTargetProfileHypothesisSummary:
    key: str
    confidence: float
    evidence: list[str]
    preferred_capability_pack_keys: list[str]
    planner_bias_rules: list[str]
    benchmark_target_keys: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
            "preferred_capability_pack_keys": list(self.preferred_capability_pack_keys),
            "planner_bias_rules": list(self.planner_bias_rules),
            "benchmark_target_keys": list(self.benchmark_target_keys),
        }


@dataclass(frozen=True)
class PlannerCapabilityPressureSummary:
    pack_key: str
    pressure_score: int
    target_profile: str
    target_profile_keys: list[str]
    challenge_family_keys: list[str]
    planner_action_keys: list[str]
    proof_contract_keys: list[str]
    top_route_groups: list[str]
    advisory_ready: bool
    advisory_mode: str
    negative_evidence_count: int
    advisory_artifact_ref: str | None = None
    graph_keys: list[str] = field(default_factory=list)
    graph_target_profile_keys: list[str] = field(default_factory=list)
    graph_planner_action_keys: list[str] = field(default_factory=list)
    graph_proof_contract_keys: list[str] = field(default_factory=list)
    graph_rationale: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pack_key": self.pack_key,
            "pressure_score": self.pressure_score,
            "target_profile": self.target_profile,
            "target_profile_keys": list(self.target_profile_keys),
            "challenge_family_keys": list(self.challenge_family_keys),
            "planner_action_keys": list(self.planner_action_keys),
            "proof_contract_keys": list(self.proof_contract_keys),
            "top_route_groups": list(self.top_route_groups),
            "advisory_ready": self.advisory_ready,
            "advisory_mode": self.advisory_mode,
            "negative_evidence_count": self.negative_evidence_count,
            "advisory_artifact_ref": self.advisory_artifact_ref,
            "graph_keys": list(self.graph_keys),
            "graph_target_profile_keys": list(self.graph_target_profile_keys),
            "graph_planner_action_keys": list(self.graph_planner_action_keys),
            "graph_proof_contract_keys": list(self.graph_proof_contract_keys),
            "graph_rationale": list(self.graph_rationale),
        }


@dataclass(frozen=True)
class PlannerTargetModelSummary:
    route_group_count: int
    auth_surface_count: int
    parameter_count: int
    workflow_edge_count: int
    source_artifact_types: list[str]
    route_groups: list[PlannerRouteGroupSummary]
    target_profile_hypotheses: list[PlannerTargetProfileHypothesisSummary] = field(default_factory=list)
    capability_pressures: list[PlannerCapabilityPressureSummary] = field(default_factory=list)
    advisory_artifact_refs: list[dict[str, str]] = field(default_factory=list)

    @property
    def top_focus(self) -> PlannerRouteGroupSummary | None:
        return self.route_groups[0] if self.route_groups else None

    @property
    def has_meaningful_pressure(self) -> bool:
        top = self.top_focus
        return bool(top and top.focus_score > 0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "route_group_count": self.route_group_count,
            "auth_surface_count": self.auth_surface_count,
            "parameter_count": self.parameter_count,
            "workflow_edge_count": self.workflow_edge_count,
            "source_artifact_types": list(self.source_artifact_types),
            "has_meaningful_pressure": self.has_meaningful_pressure,
            "top_focus": self.top_focus.to_dict() if self.top_focus else None,
            "target_profile_hypotheses": [item.to_dict() for item in self.target_profile_hypotheses],
            "capability_pressures": [item.to_dict() for item in self.capability_pressures],
            "advisory_artifact_refs": [dict(item) for item in self.advisory_artifact_refs],
            "route_groups": [group.to_dict() for group in self.route_groups],
        }


class PlannerTargetModelLoader:
    """Load a planner-facing target summary from DB state and persisted artifacts."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def load(
        self,
        *,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> PlannerTargetModelSummary:
        findings = await self._load_findings(scan_id=scan_id, tenant_id=tenant_id)
        artifacts = await self._load_artifacts(scan_id=scan_id, tenant_id=tenant_id)
        return _build_planner_target_model(findings=findings, artifact_entries=artifacts)

    async def _load_findings(
        self,
        *,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> list[dict[str, Any]]:
        result = await self._session.execute(
            text(
                """
                SELECT
                    id,
                    scan_job_id,
                    source_type,
                    title,
                    severity,
                    tool_source,
                    description,
                    is_false_positive,
                    evidence
                FROM findings
                WHERE scan_id = :scan_id AND tenant_id = :tenant_id
                ORDER BY created_at ASC
                """
            ),
            {"scan_id": str(scan_id), "tenant_id": str(tenant_id)},
        )
        return [dict(row) for row in result.mappings().all()]

    async def _load_artifacts(
        self,
        *,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> list[dict[str, Any]]:
        result = await self._session.execute(
            text(
                """
                SELECT artifact_type, storage_ref, created_at
                FROM scan_artifacts
                WHERE scan_id = :scan_id AND tenant_id = :tenant_id
                ORDER BY created_at ASC
                """
            ),
            {"scan_id": str(scan_id), "tenant_id": str(tenant_id)},
        )
        entries: list[dict[str, Any]] = []
        for row in result.mappings().all():
            payload = read_json_artifact(str(row["storage_ref"]))
            if isinstance(payload, dict):
                entries.append(
                    {
                        "artifact_type": row["artifact_type"],
                        "storage_ref": row["storage_ref"],
                        "created_at": row["created_at"],
                        "payload": payload,
                    }
                )
        return entries


def _build_planner_target_model(
    *,
    findings: list[dict[str, Any]],
    artifact_entries: list[dict[str, Any]],
) -> PlannerTargetModelSummary:
    route_groups: dict[str, dict[str, Any]] = {}
    endpoint_to_group: dict[str, str] = {}
    entity_key_to_group: dict[str, str] = {}
    auth_surfaces: set[str] = set()
    parameters: set[str] = set()
    workflow_edge_count = 0
    capability_summaries: list[dict[str, Any]] = []
    advisory_artifact_refs: list[dict[str, str]] = []
    benchmark_target_keys: set[str] = set()
    source_artifact_types = sorted(
        {
            str(entry.get("artifact_type") or "").strip()
            for entry in artifact_entries
            if str(entry.get("artifact_type") or "").strip()
        }
    )

    for entry in artifact_entries:
        payload = entry.get("payload")
        if not isinstance(payload, dict):
            continue
        if str(entry.get("artifact_type") or payload.get("artifact_type") or "") != "endpoints":
            continue

        for item in _as_list(payload.get("items")):
            if not isinstance(item, dict):
                continue
            url = str(item.get("url") or item.get("endpoint") or item.get("target") or "").strip()
            if not url:
                continue
            route_group = str(item.get("route_group") or _route_group(url)).strip() or _route_group(url)
            group = route_groups.setdefault(route_group, _new_group(route_group))
            group["endpoint_urls"].add(url)
            endpoint_to_group[url] = route_group
            entity_key = str(item.get("entity_key") or "").strip()
            if entity_key:
                entity_key_to_group[entity_key] = route_group
            if item.get("requires_auth"):
                group["requires_auth"] = True
            for value in _string_list(item.get("auth_variants")):
                group["auth_variants"].add(value)
                auth_surfaces.add(value)
            session_label = str(item.get("session_label") or "").strip()
            if session_label:
                group["auth_variants"].add(session_label)
                auth_surfaces.add(session_label)
            for value in _string_list(item.get("form_field_names")):
                group["parameter_names"].add(value)
                parameters.add(value)
            for value in _string_list(item.get("hidden_field_names")):
                group["parameter_names"].add(value)
                parameters.add(value)
            for name, _value in parse_qsl(urlparse(url).query, keep_blank_values=True):
                if name:
                    group["parameter_names"].add(name)
                    parameters.add(name)
            interaction_kind = str(item.get("interaction_kind") or "").strip().lower()
            if interaction_kind:
                group["interaction_kinds"].add(interaction_kind)
            if bool(item.get("safe_replay")):
                group["safe_replay"] = True

        capability = _as_dict(payload.get("browser_xss_capability"))
        if capability:
            _ingest_browser_xss_route_assessments(
                capability=capability,
                route_groups=route_groups,
                endpoint_to_group=endpoint_to_group,
                auth_surfaces=auth_surfaces,
                parameters=parameters,
            )
            capability_summaries.append(
                {
                    "summary": capability,
                    "storage_ref": str(entry.get("storage_ref") or ""),
                }
            )
            benchmark_target_keys.update(_string_list(capability.get("benchmark_target_keys")))
            ref = _capability_advisory_ref(capability=capability, storage_ref=str(entry.get("storage_ref") or ""))
            if ref is not None:
                advisory_artifact_refs.append(ref)

        auth_capability = _as_dict(payload.get("multi_role_stateful_auth_capability"))
        if auth_capability:
            _ingest_multi_role_auth_route_assessments(
                capability=auth_capability,
                route_groups=route_groups,
                endpoint_to_group=endpoint_to_group,
                auth_surfaces=auth_surfaces,
                parameters=parameters,
            )
            capability_summaries.append(
                {
                    "summary": auth_capability,
                    "storage_ref": str(entry.get("storage_ref") or ""),
                }
            )
            benchmark_target_keys.update(_string_list(auth_capability.get("benchmark_target_keys")))
            ref = _capability_advisory_ref(capability=auth_capability, storage_ref=str(entry.get("storage_ref") or ""))
            if ref is not None:
                advisory_artifact_refs.append(ref)

        access_capability = _as_dict(payload.get("access_control_workflow_abuse_capability"))
        if access_capability:
            _ingest_access_control_workflow_route_assessments(
                capability=access_capability,
                route_groups=route_groups,
                endpoint_to_group=endpoint_to_group,
                auth_surfaces=auth_surfaces,
                parameters=parameters,
            )
            capability_summaries.append(
                {
                    "summary": access_capability,
                    "storage_ref": str(entry.get("storage_ref") or ""),
                }
            )
            benchmark_target_keys.update(_string_list(access_capability.get("benchmark_target_keys")))
            ref = _capability_advisory_ref(capability=access_capability, storage_ref=str(entry.get("storage_ref") or ""))
            if ref is not None:
                advisory_artifact_refs.append(ref)

        injection_capability = _as_dict(payload.get("injection_capability"))
        if injection_capability:
            _ingest_injection_route_assessments(
                capability=injection_capability,
                route_groups=route_groups,
                endpoint_to_group=endpoint_to_group,
                auth_surfaces=auth_surfaces,
                parameters=parameters,
            )
            capability_summaries.append(
                {
                    "summary": injection_capability,
                    "storage_ref": str(entry.get("storage_ref") or ""),
                }
            )
            benchmark_target_keys.update(_string_list(injection_capability.get("benchmark_target_keys")))
            ref = _capability_advisory_ref(capability=injection_capability, storage_ref=str(entry.get("storage_ref") or ""))
            if ref is not None:
                advisory_artifact_refs.append(ref)

        parser_capability = _as_dict(payload.get("parser_file_abuse_capability"))
        if parser_capability:
            _ingest_parser_file_route_assessments(
                capability=parser_capability,
                route_groups=route_groups,
                endpoint_to_group=endpoint_to_group,
                auth_surfaces=auth_surfaces,
                parameters=parameters,
            )
            capability_summaries.append(
                {
                    "summary": parser_capability,
                    "storage_ref": str(entry.get("storage_ref") or ""),
                }
            )
            benchmark_target_keys.update(_string_list(parser_capability.get("benchmark_target_keys")))
            ref = _capability_advisory_ref(capability=parser_capability, storage_ref=str(entry.get("storage_ref") or ""))
            if ref is not None:
                advisory_artifact_refs.append(ref)

        disclosure_capability = _as_dict(payload.get("disclosure_misconfig_crypto_capability"))
        if disclosure_capability:
            _ingest_disclosure_route_assessments(
                capability=disclosure_capability,
                route_groups=route_groups,
                endpoint_to_group=endpoint_to_group,
                auth_surfaces=auth_surfaces,
                parameters=parameters,
            )
            capability_summaries.append(
                {
                    "summary": disclosure_capability,
                    "storage_ref": str(entry.get("storage_ref") or ""),
                }
            )
            benchmark_target_keys.update(_string_list(disclosure_capability.get("benchmark_target_keys")))
            ref = _capability_advisory_ref(
                capability=disclosure_capability,
                storage_ref=str(entry.get("storage_ref") or ""),
            )
            if ref is not None:
                advisory_artifact_refs.append(ref)

        for relationship in _as_list(payload.get("relationships")):
            if not isinstance(relationship, dict):
                continue
            edge_type = str(relationship.get("edge_type") or "workflow").strip().lower()
            if edge_type in {"discovery", "exploit"}:
                continue
            workflow_edge_count += 1
            related_groups = {
                entity_key_to_group.get(str(relationship.get("source_key") or "").strip()),
                entity_key_to_group.get(str(relationship.get("target_key") or "").strip()),
                endpoint_to_group.get(str(relationship.get("source_url") or "").strip()),
                endpoint_to_group.get(str(relationship.get("target_url") or "").strip()),
            }
            for group_key in related_groups:
                if group_key:
                    route_groups.setdefault(group_key, _new_group(group_key))["workflow_edge_count"] += 1

    for finding in findings:
        evidence = _as_dict(finding.get("evidence"))
        classification = _as_dict(evidence.get("classification"))
        endpoint = str(evidence.get("endpoint") or evidence.get("target") or "").strip()
        route_group = (
            str(classification.get("route_group") or "").strip()
            or endpoint_to_group.get(endpoint)
            or (_route_group(endpoint) if endpoint else "")
        )
        if not route_group:
            continue

        group = route_groups.setdefault(route_group, _new_group(route_group))
        if endpoint:
            group["endpoint_urls"].add(endpoint)

        vulnerability_type = _normalize_vulnerability_type(
            str(classification.get("vulnerability_type") or "").strip(),
            title=str(finding.get("title") or ""),
            description=str(finding.get("description") or ""),
        )
        if vulnerability_type:
            group["vulnerability_types"].add(vulnerability_type)

        truth_state = _finding_truth_state(finding)
        group["truth_counts"][truth_state] += 1

        severity = str(finding.get("severity") or "info").strip().lower()
        if severity not in group["severity_counts"]:
            severity = "info"
        group["severity_counts"][severity] += 1

        parameter_name = str(
            classification.get("parameter") or evidence.get("parameter") or ""
        ).strip()
        if parameter_name:
            group["parameter_names"].add(parameter_name)
            parameters.add(parameter_name)

        if bool(classification.get("requires_auth")):
            group["requires_auth"] = True

        for label in _string_list(classification.get("auth_variants")):
            group["auth_variants"].add(label)
            auth_surfaces.add(label)

    finalized_groups = [
        PlannerRouteGroupSummary(
            route_group=group["route_group"],
            focus_score=_route_focus_score(group),
            requires_auth=bool(group["requires_auth"]),
            auth_variants=sorted(group["auth_variants"]),
            parameter_names=sorted(group["parameter_names"]),
            endpoint_urls=sorted(group["endpoint_urls"]),
            workflow_edge_count=int(group["workflow_edge_count"]),
            interaction_kinds=sorted(group["interaction_kinds"]),
            safe_replay=bool(group["safe_replay"]),
            vulnerability_types=sorted(group["vulnerability_types"]),
            truth_counts=dict(group["truth_counts"]),
            severity_counts=dict(group["severity_counts"]),
            evidence_gaps=_evidence_gaps(group),
        )
        for group in route_groups.values()
    ]
    finalized_groups.sort(
        key=lambda item: (
            -item.focus_score,
            -item.truth_counts.get("verified", 0),
            -item.truth_counts.get("suspected", 0),
            item.route_group,
        )
    )
    capability_pressures = _build_capability_pressures(capability_summaries)
    target_profile_hypotheses = _build_target_profile_hypotheses(
        route_groups=finalized_groups,
        source_artifact_types=source_artifact_types,
        auth_surface_count=len(auth_surfaces),
        workflow_edge_count=workflow_edge_count,
        capability_pressures=capability_pressures,
        benchmark_target_keys=sorted(benchmark_target_keys),
    )

    return PlannerTargetModelSummary(
        route_group_count=len(finalized_groups),
        auth_surface_count=len(auth_surfaces),
        parameter_count=len(parameters),
        workflow_edge_count=workflow_edge_count,
        source_artifact_types=source_artifact_types,
        route_groups=finalized_groups,
        target_profile_hypotheses=target_profile_hypotheses,
        capability_pressures=capability_pressures,
        advisory_artifact_refs=advisory_artifact_refs,
    )


def _new_group(route_group: str) -> dict[str, Any]:
    return {
        "route_group": route_group,
        "requires_auth": False,
        "auth_variants": set(),
        "parameter_names": set(),
        "endpoint_urls": set(),
        "workflow_edge_count": 0,
        "interaction_kinds": set(),
        "safe_replay": False,
        "vulnerability_types": set(),
        "truth_counts": {key: 0 for key in _TRUTH_STATES},
        "severity_counts": {key: 0 for key in _SEVERITIES},
        "capability_evidence_gaps": set(),
    }


def _ingest_browser_xss_route_assessments(
    *,
    capability: dict[str, Any],
    route_groups: dict[str, dict[str, Any]],
    endpoint_to_group: dict[str, str],
    auth_surfaces: set[str],
    parameters: set[str],
) -> None:
    route_assessments = _as_list(capability.get("route_assessments"))
    for assessment in route_assessments:
        if not isinstance(assessment, dict):
            continue
        route_group = str(assessment.get("route_group") or "").strip()
        if not route_group:
            continue
        group = route_groups.setdefault(route_group, _new_group(route_group))
        page_url = str(assessment.get("page_url") or "").strip()
        if page_url:
            group["endpoint_urls"].add(page_url)
            endpoint_to_group[page_url] = route_group

        if bool(assessment.get("requires_auth")):
            group["requires_auth"] = True
        for label in _string_list(assessment.get("session_labels")):
            group["auth_variants"].add(label)
            auth_surfaces.add(label)
        for label in _string_list(assessment.get("auth_states")):
            group["auth_variants"].add(label)
            auth_surfaces.add(label)
        for name in _string_list(assessment.get("candidate_field_names")) + _string_list(assessment.get("parameter_hypotheses")):
            group["parameter_names"].add(name)
            parameters.add(name)
        for gap in _string_list(assessment.get("evidence_gaps")):
            group["capability_evidence_gaps"].add(gap)

        group["interaction_kinds"].add("xss_route_assessment")
        state = str(assessment.get("assessment_state") or "").strip().lower()
        if state == "candidate_ready":
            group["interaction_kinds"].add("xss_candidate")
            group["vulnerability_types"].add("xss")
            group["severity_counts"]["medium"] += 1
        elif state == "sink_and_source_unbound":
            group["interaction_kinds"].add("xss_route_pressure")
        elif state == "source_only":
            group["interaction_kinds"].add("xss_source_pressure")

        if "stored_execution_xss" in _string_list(assessment.get("proof_contracts")):
            group["safe_replay"] = True


def _ingest_multi_role_auth_route_assessments(
    *,
    capability: dict[str, Any],
    route_groups: dict[str, dict[str, Any]],
    endpoint_to_group: dict[str, str],
    auth_surfaces: set[str],
    parameters: set[str],
) -> None:
    route_assessments = _as_list(capability.get("route_assessments"))
    for assessment in route_assessments:
        if not isinstance(assessment, dict):
            continue
        route_group = str(assessment.get("route_group") or "").strip()
        if not route_group:
            continue
        group = route_groups.setdefault(route_group, _new_group(route_group))
        page_url = str(assessment.get("page_url") or "").strip()
        if page_url:
            group["endpoint_urls"].add(page_url)
            endpoint_to_group[page_url] = route_group

        if bool(assessment.get("requires_auth")):
            group["requires_auth"] = True
        for label in _string_list(assessment.get("session_labels")):
            group["auth_variants"].add(label)
            auth_surfaces.add(label)
        for label in _string_list(assessment.get("auth_states")):
            group["auth_variants"].add(label)
            auth_surfaces.add(label)
        for name in _string_list(assessment.get("parameter_hypotheses")):
            group["parameter_names"].add(name)
            parameters.add(name)
        for gap in _string_list(assessment.get("evidence_gaps")):
            group["capability_evidence_gaps"].add(gap)

        group["interaction_kinds"].add("auth_route_assessment")
        state = str(assessment.get("assessment_state") or "").strip().lower()
        if state == "role_differential_candidate":
            group["interaction_kinds"].update({"auth_candidate", "auth_role_pressure"})
            group["severity_counts"]["medium"] += 1
        elif state == "auth_transition_pressure":
            group["interaction_kinds"].update({"auth_candidate", "auth_transition_pressure"})
            group["severity_counts"]["medium"] += 1
        elif state == "converged_behavior":
            group["interaction_kinds"].add("auth_converged")

        if bool(assessment.get("privileged_surface")):
            group["interaction_kinds"].add("auth_privileged_surface")

        if "role_differential_access_contract" in _string_list(assessment.get("proof_contracts")):
            group["safe_replay"] = True


def _ingest_access_control_workflow_route_assessments(
    *,
    capability: dict[str, Any],
    route_groups: dict[str, dict[str, Any]],
    endpoint_to_group: dict[str, str],
    auth_surfaces: set[str],
    parameters: set[str],
) -> None:
    route_assessments = _as_list(capability.get("route_assessments"))
    for assessment in route_assessments:
        if not isinstance(assessment, dict):
            continue
        route_group = str(assessment.get("route_group") or "").strip()
        if not route_group:
            continue
        group = route_groups.setdefault(route_group, _new_group(route_group))
        page_url = str(assessment.get("page_url") or "").strip()
        if page_url:
            group["endpoint_urls"].add(page_url)
            endpoint_to_group[page_url] = route_group

        if bool(assessment.get("requires_auth")):
            group["requires_auth"] = True
        for label in _string_list(assessment.get("session_labels")):
            group["auth_variants"].add(label)
            auth_surfaces.add(label)
        for label in _string_list(assessment.get("auth_states")):
            group["auth_variants"].add(label)
            auth_surfaces.add(label)
        for name in _string_list(assessment.get("parameter_hypotheses")):
            group["parameter_names"].add(name)
            parameters.add(name)
        for gap in _string_list(assessment.get("evidence_gaps")):
            group["capability_evidence_gaps"].add(gap)
        for vuln in _string_list(assessment.get("candidate_vulnerability_types")):
            group["vulnerability_types"].add(vuln)

        group["interaction_kinds"].add("access_control_route_assessment")
        state = str(assessment.get("assessment_state") or "").strip().lower()
        if state == "access_control_candidate":
            group["interaction_kinds"].add("access_control_candidate")
            group["severity_counts"]["high"] += 1 if bool(assessment.get("privileged_surface")) else 0
            group["severity_counts"]["medium"] += 0 if bool(assessment.get("privileged_surface")) else 1
        elif state == "workflow_abuse_candidate":
            group["interaction_kinds"].add("workflow_abuse_candidate")
            group["severity_counts"]["medium"] += 1
        elif state == "contradictory_evidence":
            group["interaction_kinds"].add("access_control_contradiction")

        if bool(assessment.get("workflow_signal")):
            group["interaction_kinds"].add("workflow_signal")
        if bool(assessment.get("privileged_surface")):
            group["interaction_kinds"].add("access_control_privileged_surface")

        proof_contracts = _string_list(assessment.get("proof_contracts"))
        if {"role_differential_access_contract", "sensitive_data_exposure_replay"} & set(proof_contracts):
            group["safe_replay"] = True


def _ingest_injection_route_assessments(
    *,
    capability: dict[str, Any],
    route_groups: dict[str, dict[str, Any]],
    endpoint_to_group: dict[str, str],
    auth_surfaces: set[str],
    parameters: set[str],
) -> None:
    route_assessments = _as_list(capability.get("route_assessments"))
    for assessment in route_assessments:
        if not isinstance(assessment, dict):
            continue
        route_group = str(assessment.get("route_group") or "").strip()
        if not route_group:
            continue
        group = route_groups.setdefault(route_group, _new_group(route_group))
        page_url = str(assessment.get("page_url") or "").strip()
        if page_url:
            group["endpoint_urls"].add(page_url)
            endpoint_to_group[page_url] = route_group

        if bool(assessment.get("requires_auth")):
            group["requires_auth"] = True
        for label in _string_list(assessment.get("session_labels")):
            group["auth_variants"].add(label)
            auth_surfaces.add(label)
        for label in _string_list(assessment.get("auth_states")):
            group["auth_variants"].add(label)
            auth_surfaces.add(label)
        for name in _string_list(assessment.get("parameter_hypotheses")):
            group["parameter_names"].add(name)
            parameters.add(name)
        for gap in _string_list(assessment.get("evidence_gaps")):
            group["capability_evidence_gaps"].add(gap)
        for vuln in _string_list(assessment.get("candidate_vulnerability_types")):
            group["vulnerability_types"].add(vuln)

        group["interaction_kinds"].add("injection_route_assessment")
        state = str(assessment.get("assessment_state") or "").strip().lower()
        if state == "injection_candidate":
            group["interaction_kinds"].add("injection_candidate")
            group["severity_counts"]["medium"] += 1
        elif state == "graphql_candidate":
            group["interaction_kinds"].update({"injection_candidate", "graphql_candidate"})
            group["severity_counts"]["medium"] += 1
        elif state == "heuristic_only":
            group["interaction_kinds"].add("injection_heuristic_pressure")

        if bool(assessment.get("graphql_surface")):
            group["interaction_kinds"].add("graphql_surface")

        if "injection_replay_contract" in _string_list(assessment.get("proof_contracts")):
            group["safe_replay"] = True


def _ingest_parser_file_route_assessments(
    *,
    capability: dict[str, Any],
    route_groups: dict[str, dict[str, Any]],
    endpoint_to_group: dict[str, str],
    auth_surfaces: set[str],
    parameters: set[str],
) -> None:
    route_assessments = _as_list(capability.get("route_assessments"))
    for assessment in route_assessments:
        if not isinstance(assessment, dict):
            continue
        route_group = str(assessment.get("route_group") or "").strip()
        if not route_group:
            continue
        group = route_groups.setdefault(route_group, _new_group(route_group))
        page_url = str(assessment.get("page_url") or "").strip()
        if page_url:
            group["endpoint_urls"].add(page_url)
            endpoint_to_group[page_url] = route_group

        if bool(assessment.get("requires_auth")):
            group["requires_auth"] = True
        for label in _string_list(assessment.get("session_labels")):
            group["auth_variants"].add(label)
            auth_surfaces.add(label)
        for label in _string_list(assessment.get("auth_states")):
            group["auth_variants"].add(label)
            auth_surfaces.add(label)
        for name in _string_list(assessment.get("parameter_hypotheses")):
            group["parameter_names"].add(name)
            parameters.add(name)
        for name in _string_list(assessment.get("file_field_names")):
            group["parameter_names"].add(name)
            parameters.add(name)
        for gap in _string_list(assessment.get("evidence_gaps")):
            group["capability_evidence_gaps"].add(gap)
        for vuln in _string_list(assessment.get("candidate_vulnerability_types")):
            group["vulnerability_types"].add(vuln)

        group["interaction_kinds"].add("parser_route_assessment")
        state = str(assessment.get("assessment_state") or "").strip().lower()
        if state == "xxe_candidate":
            group["interaction_kinds"].update({"parser_candidate", "xxe_candidate"})
            group["severity_counts"]["medium"] += 1
        elif state == "deserialization_candidate":
            group["interaction_kinds"].update({"parser_candidate", "deserialization_candidate"})
            group["severity_counts"]["medium"] += 1
        elif state == "heuristic_only":
            group["interaction_kinds"].add("parser_heuristic_pressure")

        if bool(assessment.get("upload_surface")):
            group["interaction_kinds"].add("upload_surface")
        if bool(assessment.get("multipart_surface")):
            group["interaction_kinds"].add("multipart_surface")
        if bool(assessment.get("xml_surface")):
            group["interaction_kinds"].add("xml_parser_surface")
        if bool(assessment.get("serialized_surface")):
            group["interaction_kinds"].add("serialized_object_surface")

        proof_contracts = _string_list(assessment.get("proof_contracts"))
        if {"xxe_parser_contract", "deserialization_replay_contract"} & set(proof_contracts):
            group["safe_replay"] = True


def _ingest_disclosure_route_assessments(
    *,
    capability: dict[str, Any],
    route_groups: dict[str, dict[str, Any]],
    endpoint_to_group: dict[str, str],
    auth_surfaces: set[str],
    parameters: set[str],
) -> None:
    route_assessments = _as_list(capability.get("route_assessments"))
    for assessment in route_assessments:
        if not isinstance(assessment, dict):
            continue
        route_group = str(assessment.get("route_group") or "").strip()
        if not route_group:
            continue
        group = route_groups.setdefault(route_group, _new_group(route_group))
        page_url = str(assessment.get("page_url") or "").strip()
        if page_url:
            group["endpoint_urls"].add(page_url)
            endpoint_to_group[page_url] = route_group

        if bool(assessment.get("requires_auth")):
            group["requires_auth"] = True
        for label in _string_list(assessment.get("session_labels")):
            group["auth_variants"].add(label)
            auth_surfaces.add(label)
        for label in _string_list(assessment.get("auth_states")):
            group["auth_variants"].add(label)
            auth_surfaces.add(label)
        for name in _string_list(assessment.get("parameter_hypotheses")):
            group["parameter_names"].add(name)
            parameters.add(name)
        for gap in _string_list(assessment.get("evidence_gaps")):
            group["capability_evidence_gaps"].add(gap)
        for vuln in _string_list(assessment.get("candidate_vulnerability_types")):
            group["vulnerability_types"].add(vuln)

        group["interaction_kinds"].add("disclosure_route_assessment")
        state = str(assessment.get("assessment_state") or "").strip().lower()
        if state == "stack_trace_candidate":
            group["interaction_kinds"].update({"disclosure_candidate", "stack_trace_candidate"})
            group["severity_counts"]["high"] += 1
        elif state == "component_truth_candidate":
            group["interaction_kinds"].update({"disclosure_candidate", "component_truth_candidate"})
            group["severity_counts"]["medium"] += 1
        elif state == "disclosure_candidate":
            group["interaction_kinds"].add("disclosure_candidate")
            group["severity_counts"]["high"] += 1
        elif state == "misconfiguration_candidate":
            group["interaction_kinds"].update({"disclosure_candidate", "misconfiguration_candidate"})
            group["severity_counts"]["medium"] += 1
        elif state == "weak_crypto_candidate":
            group["interaction_kinds"].update({"disclosure_candidate", "weak_crypto_candidate"})
            group["severity_counts"]["high"] += 1
        elif state == "heuristic_only":
            group["interaction_kinds"].add("disclosure_heuristic_pressure")

        if bool(assessment.get("debug_surface")):
            group["interaction_kinds"].add("debug_surface")
        if bool(assessment.get("component_surface")):
            group["interaction_kinds"].add("component_surface")
        if bool(assessment.get("config_surface")):
            group["interaction_kinds"].add("config_surface")
        if bool(assessment.get("secret_surface")):
            group["interaction_kinds"].add("secret_surface")
        if bool(assessment.get("crypto_surface")):
            group["interaction_kinds"].add("crypto_surface")

        proof_contracts = _string_list(assessment.get("proof_contracts"))
        if {
            "sensitive_data_exposure_replay",
            "stack_trace_disclosure_contract",
            "weak_crypto_material_contract",
            "component_truth_contract",
            "misconfiguration_surface_contract",
        } & set(proof_contracts):
            group["safe_replay"] = True


def _route_focus_score(group: dict[str, Any]) -> int:
    truth = group["truth_counts"]
    severity = group["severity_counts"]
    truth_pressure = (
        int(truth.get("verified", 0)) * 8
        + int(truth.get("reproduced", 0)) * 6
        + int(truth.get("suspected", 0)) * 4
        + int(truth.get("observed", 0)) * 2
    )
    artifact_pressure = _artifact_pressure(group)
    if truth_pressure <= 0:
        return artifact_pressure if artifact_pressure >= 5 else 0
    return (
        truth_pressure
        + int(severity.get("critical", 0)) * 5
        + int(severity.get("high", 0)) * 3
        + int(severity.get("medium", 0)) * 2
        + artifact_pressure
    )


def _artifact_pressure(group: dict[str, Any]) -> int:
    interaction_kinds = {
        str(item).strip().lower()
        for item in group.get("interaction_kinds", set())
        if str(item).strip()
    }
    return (
        min(len(group["parameter_names"]), 3)
        + (2 if group["requires_auth"] else 0)
        + min(len(group["auth_variants"]), 2)
        + min(int(group.get("workflow_edge_count", 0)), 3)
        + (2 if "form" in interaction_kinds else 0)
        + (1 if bool(group.get("safe_replay")) else 0)
        + (1 if len(group["endpoint_urls"]) > 1 else 0)
        + (3 if "xss_candidate" in interaction_kinds else 0)
        + (2 if "xss_route_pressure" in interaction_kinds else 0)
        + (1 if "xss_source_pressure" in interaction_kinds else 0)
        + (1 if "xss_route_assessment" in interaction_kinds else 0)
        + (3 if "auth_candidate" in interaction_kinds else 0)
        + (2 if "auth_role_pressure" in interaction_kinds else 0)
        + (2 if "auth_transition_pressure" in interaction_kinds else 0)
        + (1 if "auth_privileged_surface" in interaction_kinds else 0)
        + (3 if "access_control_candidate" in interaction_kinds else 0)
        + (3 if "workflow_abuse_candidate" in interaction_kinds else 0)
        + (1 if "access_control_privileged_surface" in interaction_kinds else 0)
        + (1 if "workflow_signal" in interaction_kinds else 0)
        + (3 if "injection_candidate" in interaction_kinds else 0)
        + (2 if "graphql_candidate" in interaction_kinds else 0)
        + (1 if "injection_heuristic_pressure" in interaction_kinds else 0)
        + (1 if "graphql_surface" in interaction_kinds else 0)
        + (3 if "parser_candidate" in interaction_kinds else 0)
        + (2 if "xxe_candidate" in interaction_kinds else 0)
        + (2 if "deserialization_candidate" in interaction_kinds else 0)
        + (1 if "parser_heuristic_pressure" in interaction_kinds else 0)
        + (1 if "upload_surface" in interaction_kinds else 0)
        + (1 if "xml_parser_surface" in interaction_kinds else 0)
        + (1 if "serialized_object_surface" in interaction_kinds else 0)
        + (2 if "disclosure_candidate" in interaction_kinds else 0)
        + (2 if "stack_trace_candidate" in interaction_kinds else 0)
        + (2 if "component_truth_candidate" in interaction_kinds else 0)
        + (2 if "weak_crypto_candidate" in interaction_kinds else 0)
        + (1 if "misconfiguration_candidate" in interaction_kinds else 0)
        + (1 if "disclosure_heuristic_pressure" in interaction_kinds else 0)
        + (1 if "debug_surface" in interaction_kinds else 0)
        + (1 if "component_surface" in interaction_kinds else 0)
        + (1 if "secret_surface" in interaction_kinds else 0)
        + (1 if "crypto_surface" in interaction_kinds else 0)
    )


def _evidence_gaps(group: dict[str, Any]) -> list[str]:
    truth = group["truth_counts"]
    gaps: list[str] = []
    if truth.get("observed", 0) and not truth.get("suspected", 0) and not truth.get("reproduced", 0):
        gaps.append("triage")
    if (truth.get("suspected", 0) or truth.get("observed", 0)) and not truth.get("verified", 0):
        gaps.append("verification")
    if group["requires_auth"] and not group["auth_variants"]:
        gaps.append("auth_context")
    if group["parameter_names"] and not group["vulnerability_types"]:
        gaps.append("parameter_mapping")
    gaps.extend(_string_list(list(group.get("capability_evidence_gaps") or [])))
    return _string_list(gaps)


def _capability_advisory_ref(
    *,
    capability: dict[str, Any],
    storage_ref: str,
) -> dict[str, str] | None:
    if not storage_ref or not bool(capability.get("ai_advisory_ready")):
        return None
    advisory_bundle = _as_dict(capability.get("advisory_context") or capability.get("ai_advisory_bundle"))
    advisory_mode = str(
        advisory_bundle.get("advisory_mode")
        or ((capability.get("ai_advisory_bundle") or {}).get("advisory_mode") if isinstance(capability.get("ai_advisory_bundle"), dict) else "")
        or ""
    ).strip()
    return {
        "pack_key": str(capability.get("pack_key") or ""),
        "storage_ref": storage_ref,
        "advisory_mode": advisory_mode,
    }


def _build_capability_pressures(
    capability_summaries: list[dict[str, Any]],
) -> list[PlannerCapabilityPressureSummary]:
    pressures: list[PlannerCapabilityPressureSummary] = []
    for item in capability_summaries:
        summary = _as_dict(item.get("summary"))
        pack_key = str(summary.get("pack_key") or "").strip()
        if not pack_key:
            continue
        challenge_family_keys = _string_list(summary.get("challenge_family_keys"))
        attack_primitive_keys = _string_list(summary.get("attack_primitive_keys"))
        planner_action_keys = _string_list(summary.get("planner_action_keys"))
        proof_contract_keys = _string_list(summary.get("proof_contract_keys"))
        route_assessment_counts = _as_dict(summary.get("route_assessment_counts"))
        negative_evidence_count = int(
            summary.get("negative_evidence_count")
            or route_assessment_counts.get("negative_evidence_routes")
            or len(summary.get("negative_evidence") or [])
            or 0
        )
        pressure_score = (
            int(summary.get("candidate_count") or 0) * 8
            + int(summary.get("planner_hook_count") or 0) * 5
            + int(route_assessment_counts.get("candidate_ready") or 0) * 6
            + int(route_assessment_counts.get("role_differential_candidate") or 0) * 7
            + int(route_assessment_counts.get("auth_transition_pressure") or 0) * 4
            + int(route_assessment_counts.get("access_control_candidate") or 0) * 7
            + int(route_assessment_counts.get("workflow_abuse_candidate") or 0) * 6
            + int(route_assessment_counts.get("injection_candidate") or 0) * 7
            + int(route_assessment_counts.get("graphql_candidate") or 0) * 7
            + int(route_assessment_counts.get("xxe_candidate") or 0) * 7
            + int(route_assessment_counts.get("deserialization_candidate") or 0) * 7
            + int(route_assessment_counts.get("disclosure_candidate") or 0) * 7
            + int(route_assessment_counts.get("stack_trace_candidate") or 0) * 8
            + int(route_assessment_counts.get("component_truth_candidate") or 0) * 6
            + int(route_assessment_counts.get("misconfiguration_candidate") or 0) * 6
            + int(route_assessment_counts.get("weak_crypto_candidate") or 0) * 7
            + int(route_assessment_counts.get("heuristic_only") or 0) * 2
            + int(route_assessment_counts.get("parser_heuristic_pressure") or 0) * 2
            + int(route_assessment_counts.get("sink_and_source_unbound") or 0) * 3
            - negative_evidence_count * 2
        )
        top_route_groups = [
            str(route.get("route_group") or "")
            for route in sorted(
                _as_list(summary.get("route_assessments")),
                key=lambda route: (
                    -int(_as_dict(route).get("advisory_priority") or 0),
                    -int(_as_dict(route).get("risk_score") or 0),
                    str(_as_dict(route).get("route_group") or ""),
                ),
            )[:4]
            if str(_as_dict(route).get("route_group") or "").strip()
        ]
        advisory_bundle = _as_dict(summary.get("advisory_context") or summary.get("ai_advisory_bundle"))
        graph_alignments = align_capability_graphs(
            target_profile_keys=(
                [str(summary.get("target_profile") or "").strip()]
                if str(summary.get("target_profile") or "").strip()
                else _string_list(summary.get("target_profile_keys"))
            ),
            challenge_family_keys=challenge_family_keys,
            attack_primitive_keys=attack_primitive_keys,
            proof_contract_keys=proof_contract_keys,
            planner_action_keys=planner_action_keys,
            benchmark_target_keys=_string_list(summary.get("benchmark_target_keys")),
        )
        graph_keys = [alignment.graph_key for alignment in graph_alignments[:3]]
        graph_target_profile_keys = _string_list(
            [
                target_profile_key
                for alignment in graph_alignments[:3]
                for target_profile_key in alignment.matched_target_profile_keys
            ]
        )
        graph_planner_action_keys = _string_list(
            [
                planner_action_key
                for alignment in graph_alignments[:3]
                for planner_action_key in alignment.matched_planner_action_keys
            ]
        )
        graph_proof_contract_keys = _string_list(
            [
                proof_contract_key
                for alignment in graph_alignments[:3]
                for proof_contract_key in alignment.matched_proof_contract_keys
            ]
        )
        graph_rationale = [
            line
            for alignment in graph_alignments[:2]
            for line in alignment.rationale
        ][:6]
        pressures.append(
            PlannerCapabilityPressureSummary(
                pack_key=pack_key,
                pressure_score=max(min(pressure_score, 100), 0),
                target_profile=str(summary.get("target_profile") or ""),
                target_profile_keys=_string_list(summary.get("target_profile_keys")),
                challenge_family_keys=challenge_family_keys,
                planner_action_keys=planner_action_keys,
                proof_contract_keys=proof_contract_keys,
                top_route_groups=top_route_groups,
                advisory_ready=bool(summary.get("ai_advisory_ready")),
                advisory_mode=str(advisory_bundle.get("advisory_mode") or ""),
                negative_evidence_count=negative_evidence_count,
                advisory_artifact_ref=str(item.get("storage_ref") or "") or None,
                graph_keys=graph_keys,
                graph_target_profile_keys=graph_target_profile_keys,
                graph_planner_action_keys=graph_planner_action_keys,
                graph_proof_contract_keys=graph_proof_contract_keys,
                graph_rationale=graph_rationale,
            )
        )
    pressures.sort(key=lambda pressure: (-pressure.pressure_score, pressure.pack_key))
    return pressures


def _build_target_profile_hypotheses(
    *,
    route_groups: list[PlannerRouteGroupSummary],
    source_artifact_types: list[str],
    auth_surface_count: int,
    workflow_edge_count: int,
    capability_pressures: list[PlannerCapabilityPressureSummary],
    benchmark_target_keys: list[str],
) -> list[PlannerTargetProfileHypothesisSummary]:
    hypotheses = classify_target_profiles(
        route_groups=[group.route_group for group in route_groups],
        source_artifact_types=source_artifact_types,
        auth_surface_count=auth_surface_count,
        workflow_edge_count=workflow_edge_count,
        capability_pack_keys=[item.pack_key for item in capability_pressures],
        benchmark_target_keys=benchmark_target_keys,
    )
    return [
        PlannerTargetProfileHypothesisSummary(
            key=item.key,
            confidence=item.confidence,
            evidence=list(item.evidence),
            preferred_capability_pack_keys=list(item.preferred_capability_pack_keys),
            planner_bias_rules=list(item.planner_bias_rules),
            benchmark_target_keys=list(item.benchmark_target_keys),
        )
        for item in hypotheses
    ]


def _finding_truth_state(finding: dict[str, Any]) -> str:
    evidence = _as_dict(finding.get("evidence"))
    classification = _as_dict(evidence.get("classification"))
    metadata = _as_dict(evidence.get("metadata"))

    for container in (classification, metadata):
        value = str(container.get("truth_state") or "").strip().lower()
        if value in _TRUTH_STATES:
            return value

    if bool(finding.get("is_false_positive")):
        return "rejected"

    for container in (classification, metadata):
        if bool(container.get("expired")) or container.get("expired_at"):
            return "expired"

    verification_state = str(classification.get("verification_state") or "").strip().lower()
    if verification_state == "verified":
        return "verified" if _provenance_complete(finding) and _replayable(finding) else "reproduced"
    if verification_state == "suspected":
        return "suspected"
    if str(finding.get("source_type") or "").strip() == "ai_analysis":
        return "suspected"
    return "observed"


def _provenance_complete(finding: dict[str, Any]) -> bool:
    evidence = _as_dict(finding.get("evidence"))
    classification = _as_dict(evidence.get("classification"))
    metadata = _as_dict(evidence.get("metadata"))

    for container in (classification, metadata):
        value = container.get("provenance_complete")
        if isinstance(value, bool):
            return value

    has_source = bool(str(finding.get("source_type") or "").strip()) and bool(str(finding.get("tool_source") or "").strip())
    has_locator = bool(
        evidence.get("endpoint")
        or evidence.get("target")
        or evidence.get("storage_ref")
        or any(_as_dict(item).get("storage_ref") for item in _as_list(evidence.get("references")))
    )
    has_material = _evidence_reference_count(evidence) > 0 or _raw_evidence_present(evidence)
    return has_source and has_locator and has_material


def _replayable(finding: dict[str, Any]) -> bool:
    evidence = _as_dict(finding.get("evidence"))
    classification = _as_dict(evidence.get("classification"))
    metadata = _as_dict(evidence.get("metadata"))

    for container in (classification, metadata):
        value = container.get("replayable")
        if isinstance(value, bool):
            return value

    verification_context = _as_dict(metadata.get("verification_context"))
    if any(
        verification_context.get(key)
        for key in ("request_url", "endpoint", "command", "curl", "http_method")
    ):
        return True

    if (
        (evidence.get("endpoint") or evidence.get("target"))
        and _raw_evidence_present(evidence)
        and (
            evidence.get("storage_ref")
            or any(_as_dict(item).get("storage_ref") for item in _as_list(evidence.get("references")))
        )
    ):
        return True

    return False


def _evidence_reference_count(evidence: dict[str, Any]) -> int:
    references = _as_list(evidence.get("references"))
    return sum(
        1
        for item in references
        if isinstance(item, dict) and any(item.get(key) for key in ("id", "evidence_type", "label"))
    )


def _raw_evidence_present(evidence: dict[str, Any]) -> bool:
    return any(str(evidence.get(key) or "").strip() for key in _RAW_EVIDENCE_KEYS)


def _normalize_vulnerability_type(value: str | None, *, title: str = "", description: str = "") -> str | None:
    raw = str(value or "").strip().lower()
    text = " ".join(part for part in (raw, title, description) if part).lower()
    aliases = (
        ("auth_bypass", ("auth_bypass", "authorization bypass", "auth bypass", "cross_session")),
        ("workflow_bypass", ("workflow_bypass", "workflow bypass", "step_bypass", "skip_step", "swap_order", "repeat_step")),
        ("idor", ("idor", "insecure direct object reference", "object level authorization")),
        ("privilege_escalation", ("privilege_escalation", "privilege escalation")),
        ("sql_injection", ("sql_injection", "sql injection", "sqli")),
    )
    for normalized, patterns in aliases:
        if raw == normalized:
            return normalized
        if any(pattern in text for pattern in patterns):
            return normalized
    return raw or None


def _route_group(url: str) -> str:
    path = urlparse(url).path or "/"
    path = path if path.startswith("/") else f"/{path}"
    segments: list[str] = []
    for segment in path.split("/"):
        if not segment:
            continue
        if segment.isdigit() or _UUIDISH_SEGMENT.match(segment):
            segments.append("{id}")
        else:
            segments.append(segment)
    return "/" + "/".join(segments) if segments else "/"


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    items: list[str] = []
    seen: set[str] = set()
    for item in value:
        text = str(item).strip()
        key = text.lower()
        if not text or key in seen:
            continue
        seen.add(key)
        items.append(text)
    return items


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []
