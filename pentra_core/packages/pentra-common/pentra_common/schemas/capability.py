"""Shared capability-pack schemas for Phase 3 runtime contracts."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, model_validator

from pentra_common.schemas.target_profile import TargetProfileKey


class CapabilityKnowledgeDependencies(BaseModel):
    ontology_index_path: str
    source_profile: str
    cheatsheet_category_keys: list[str] = Field(default_factory=list)
    source_registry_keys: list[str] = Field(default_factory=list)
    corpus_dependency_notes: list[str] = Field(default_factory=list)


class CapabilitySubphase(BaseModel):
    key: str
    name: str


class CapabilityPayloadRegistry(BaseModel):
    file: str
    selection_mode: str


class CapabilityAIAdvisory(BaseModel):
    enabled: bool = False
    advisory_mode: str = ""
    prompt_contract_id: str = ""
    trust_boundary: str = "advisor_only"


class CapabilityManifest(BaseModel):
    pack_key: str
    name: str
    phase: int = 3
    description: str
    ontology_family_keys: list[str] = Field(default_factory=list)
    attack_primitive_keys: list[str] = Field(default_factory=list)
    proof_contract_keys: list[str] = Field(default_factory=list)
    planner_action_keys: list[str] = Field(default_factory=list)
    target_profile_keys: list[TargetProfileKey] = Field(default_factory=list)
    pack_dependency_keys: list[str] = Field(default_factory=list)
    knowledge_dependencies: CapabilityKnowledgeDependencies
    subphases: list[CapabilitySubphase] = Field(default_factory=list)
    runtime_dependencies: list[str] = Field(default_factory=list)
    candidate_generators: list[str] = Field(default_factory=list)
    verifier_entrypoints: list[str] = Field(default_factory=list)
    payload_registry: CapabilityPayloadRegistry | None = None
    ai_advisory: CapabilityAIAdvisory | None = None
    negative_evidence_behavior: list[str] = Field(default_factory=list)
    benchmark_target_keys: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_manifest(self) -> "CapabilityManifest":
        if self.phase < 3:
            raise ValueError(f"Capability manifest '{self.pack_key}' must be Phase 3 or later")
        if not self.ontology_family_keys:
            raise ValueError(f"Capability manifest '{self.pack_key}' must define ontology_family_keys")
        if not self.attack_primitive_keys:
            raise ValueError(f"Capability manifest '{self.pack_key}' must define attack_primitive_keys")
        if not self.proof_contract_keys:
            raise ValueError(f"Capability manifest '{self.pack_key}' must define proof_contract_keys")
        if not self.planner_action_keys:
            raise ValueError(f"Capability manifest '{self.pack_key}' must define planner_action_keys")
        if not self.target_profile_keys:
            raise ValueError(f"Capability manifest '{self.pack_key}' must define target_profile_keys")
        if not self.runtime_dependencies:
            raise ValueError(f"Capability manifest '{self.pack_key}' must define runtime_dependencies")
        if not self.verifier_entrypoints:
            raise ValueError(f"Capability manifest '{self.pack_key}' must define verifier_entrypoints")
        if not self.benchmark_target_keys:
            raise ValueError(f"Capability manifest '{self.pack_key}' must define benchmark_target_keys")
        return self


class CapabilityAdvisoryRequest(BaseModel):
    pack_key: str
    advisory_mode: str
    prompt_contract_id: str
    user_prompt: str
    context: dict[str, Any] = Field(default_factory=dict)
    target_profile_keys: list[TargetProfileKey] = Field(default_factory=list)
    benchmark_target_keys: list[str] = Field(default_factory=list)


class CapabilityAdvisoryResponse(BaseModel):
    pack_key: str
    advisory_mode: str
    focus_items: list[dict[str, Any]] = Field(default_factory=list)
    evidence_gap_priorities: list[str] = Field(default_factory=list)
    parameter_hypotheses: list[str] = Field(default_factory=list)
    workflow_segments: list[dict[str, Any]] = Field(default_factory=list)
    target_profile_hints: list[dict[str, Any]] = Field(default_factory=list)
    provider: str = ""
    model: str = ""
    transport: str = ""
    fallback_used: bool = False
    prompt_version: str = ""
    raw_response: str = ""
    duration_ms: int = 0
    error: str | None = None


class CapabilityResult(BaseModel):
    pack_key: str
    capability_summary: dict[str, Any] = Field(default_factory=dict)
    candidates: list[dict[str, Any]] = Field(default_factory=list)
    negative_evidence: list[dict[str, Any]] = Field(default_factory=list)
    advisory_context: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_result(self) -> "CapabilityResult":
        summary_pack_key = str(self.capability_summary.get("pack_key") or "").strip()
        if summary_pack_key and summary_pack_key != self.pack_key:
            raise ValueError(
                f"Capability result pack_key '{self.pack_key}' does not match summary pack_key '{summary_pack_key}'"
            )
        return self
