"""Knowledge ontology schemas for Phase 2 public-source-first modeling."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from pentra_common.schemas.knowledge_source import KnowledgeFactCitation
from pentra_common.schemas.target_profile import TargetProfileKey


OntologyNodeType = Literal[
    "challenge_family",
    "attack_primitive",
    "workflow_state",
    "role_model",
    "proof_contract",
    "planner_action",
]
WorkflowStateType = Literal[
    "anonymous_surface",
    "authenticated_surface",
    "privileged_surface",
    "role_transition",
    "business_workflow",
    "client_side_route",
]
ProofStrength = Literal["candidate_only", "replayable", "browser_verified", "high_trust"]
CapabilityEdgeRelation = Literal[
    "family_has_primitive",
    "family_uses_workflow_state",
    "family_uses_role_model",
    "family_requires_proof_contract",
    "family_recommends_action",
    "action_targets_primitive",
    "primitive_requires_proof_contract",
    "role_model_enables_action",
]


class ChallengeFamilyDefinition(BaseModel):
    key: str
    name: str
    description: str
    aliases: list[str] = Field(default_factory=list)
    category_labels: list[str] = Field(default_factory=list)
    source_summary_keys: list[str] = Field(default_factory=list)
    attack_primitive_keys: list[str] = Field(default_factory=list)
    workflow_state_keys: list[str] = Field(default_factory=list)
    role_model_keys: list[str] = Field(default_factory=list)
    proof_contract_keys: list[str] = Field(default_factory=list)
    planner_action_keys: list[str] = Field(default_factory=list)
    benchmark_target_keys: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    citations: list[KnowledgeFactCitation] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_family(self) -> "ChallengeFamilyDefinition":
        if not self.source_summary_keys:
            raise ValueError(f"Challenge family '{self.key}' must define source_summary_keys")
        if not self.citations:
            raise ValueError(f"Challenge family '{self.key}' must define citations")
        return self


class AttackPrimitiveDefinition(BaseModel):
    key: str
    name: str
    description: str
    challenge_family_keys: list[str] = Field(default_factory=list)
    source_summary_keys: list[str] = Field(default_factory=list)
    surfaces: list[str] = Field(default_factory=list)
    prerequisite_evidence: list[str] = Field(default_factory=list)
    discovery_signals: list[str] = Field(default_factory=list)
    preferred_tool_ids: list[str] = Field(default_factory=list)
    proof_contract_keys: list[str] = Field(default_factory=list)
    planner_action_keys: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    citations: list[KnowledgeFactCitation] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_primitive(self) -> "AttackPrimitiveDefinition":
        if not self.challenge_family_keys:
            raise ValueError(f"Attack primitive '{self.key}' must define challenge_family_keys")
        if not self.source_summary_keys:
            raise ValueError(f"Attack primitive '{self.key}' must define source_summary_keys")
        if not self.citations:
            raise ValueError(f"Attack primitive '{self.key}' must define citations")
        return self


class WorkflowStateDefinition(BaseModel):
    key: str
    name: str
    description: str
    state_type: WorkflowStateType
    source_summary_keys: list[str] = Field(default_factory=list)
    auth_state: str
    role_hints: list[str] = Field(default_factory=list)
    entry_signals: list[str] = Field(default_factory=list)
    transition_targets: list[str] = Field(default_factory=list)
    benchmark_target_keys: list[str] = Field(default_factory=list)
    citations: list[KnowledgeFactCitation] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_workflow_state(self) -> "WorkflowStateDefinition":
        if not self.source_summary_keys:
            raise ValueError(f"Workflow state '{self.key}' must define source_summary_keys")
        if not self.citations:
            raise ValueError(f"Workflow state '{self.key}' must define citations")
        return self


class RoleVariantDefinition(BaseModel):
    key: str
    label: str
    description: str
    privilege_level: int = 0
    acquisition_modes: list[str] = Field(default_factory=list)
    observable_markers: list[str] = Field(default_factory=list)


class RoleModelDefinition(BaseModel):
    key: str
    name: str
    description: str
    target_keys: list[str] = Field(default_factory=list)
    source_summary_keys: list[str] = Field(default_factory=list)
    roles: list[RoleVariantDefinition] = Field(default_factory=list)
    transition_pairs: list[str] = Field(default_factory=list)
    citations: list[KnowledgeFactCitation] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_role_model(self) -> "RoleModelDefinition":
        if not self.roles:
            raise ValueError(f"Role model '{self.key}' must define roles")
        if not self.source_summary_keys:
            raise ValueError(f"Role model '{self.key}' must define source_summary_keys")
        if not self.citations:
            raise ValueError(f"Role model '{self.key}' must define citations")
        return self


class ProofContractDefinition(BaseModel):
    key: str
    name: str
    description: str
    proof_strength: ProofStrength
    source_summary_keys: list[str] = Field(default_factory=list)
    required_evidence: list[str] = Field(default_factory=list)
    positive_requirements: list[str] = Field(default_factory=list)
    negative_requirements: list[str] = Field(default_factory=list)
    replay_requirements: list[str] = Field(default_factory=list)
    prohibited_shortcuts: list[str] = Field(default_factory=list)
    candidate_tool_ids: list[str] = Field(default_factory=list)
    citations: list[KnowledgeFactCitation] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_proof_contract(self) -> "ProofContractDefinition":
        if not self.source_summary_keys:
            raise ValueError(f"Proof contract '{self.key}' must define source_summary_keys")
        if not self.required_evidence:
            raise ValueError(f"Proof contract '{self.key}' must define required_evidence")
        if not self.citations:
            raise ValueError(f"Proof contract '{self.key}' must define citations")
        return self


class PlannerActionDefinition(BaseModel):
    key: str
    action_type: str
    name: str
    description: str
    source_summary_keys: list[str] = Field(default_factory=list)
    required_inputs: list[str] = Field(default_factory=list)
    evidence_goals: list[str] = Field(default_factory=list)
    candidate_tool_ids: list[str] = Field(default_factory=list)
    stop_conditions: list[str] = Field(default_factory=list)
    benchmark_target_keys: list[str] = Field(default_factory=list)
    citations: list[KnowledgeFactCitation] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_planner_action(self) -> "PlannerActionDefinition":
        if not self.source_summary_keys:
            raise ValueError(f"Planner action '{self.key}' must define source_summary_keys")
        if not self.required_inputs:
            raise ValueError(f"Planner action '{self.key}' must define required_inputs")
        if not self.stop_conditions:
            raise ValueError(f"Planner action '{self.key}' must define stop_conditions")
        if not self.citations:
            raise ValueError(f"Planner action '{self.key}' must define citations")
        return self


class CapabilityGraphEdge(BaseModel):
    source_key: str
    source_type: OntologyNodeType
    relation: CapabilityEdgeRelation
    target_key: str
    target_type: OntologyNodeType
    description: str = ""


class CapabilityGraphDefinition(BaseModel):
    key: str
    name: str
    description: str
    benchmark_target_keys: list[str] = Field(default_factory=list)
    target_profile_keys: list[TargetProfileKey] = Field(default_factory=list)
    source_summary_keys: list[str] = Field(default_factory=list)
    challenge_family_keys: list[str] = Field(default_factory=list)
    attack_primitive_keys: list[str] = Field(default_factory=list)
    workflow_state_keys: list[str] = Field(default_factory=list)
    role_model_keys: list[str] = Field(default_factory=list)
    proof_contract_keys: list[str] = Field(default_factory=list)
    planner_action_keys: list[str] = Field(default_factory=list)
    edges: list[CapabilityGraphEdge] = Field(default_factory=list)
    citations: list[KnowledgeFactCitation] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_graph(self) -> "CapabilityGraphDefinition":
        if not self.target_profile_keys:
            raise ValueError(f"Capability graph '{self.key}' must define target_profile_keys")
        if not self.source_summary_keys:
            raise ValueError(f"Capability graph '{self.key}' must define source_summary_keys")
        if not self.edges:
            raise ValueError(f"Capability graph '{self.key}' must define edges")
        if not self.citations:
            raise ValueError(f"Capability graph '{self.key}' must define citations")
        return self


class KnowledgeOntologyIndex(BaseModel):
    version: int = 1
    program: str
    phase: int = 2
    challenge_family_path: str
    attack_primitive_path: str
    workflow_state_path: str
    role_model_path: str
    proof_contract_path: str
    planner_action_path: str
    capability_graph_path: str


class ChallengeFamilyCatalog(BaseModel):
    version: int = 1
    program: str
    phase: int = 2
    generated_at: datetime
    families: list[ChallengeFamilyDefinition] = Field(default_factory=list)


class AttackPrimitiveCatalog(BaseModel):
    version: int = 1
    program: str
    phase: int = 2
    generated_at: datetime
    attack_primitives: list[AttackPrimitiveDefinition] = Field(default_factory=list)


class WorkflowStateCatalog(BaseModel):
    version: int = 1
    program: str
    phase: int = 2
    generated_at: datetime
    workflow_states: list[WorkflowStateDefinition] = Field(default_factory=list)


class RoleModelCatalog(BaseModel):
    version: int = 1
    program: str
    phase: int = 2
    generated_at: datetime
    role_models: list[RoleModelDefinition] = Field(default_factory=list)


class ProofContractCatalog(BaseModel):
    version: int = 1
    program: str
    phase: int = 2
    generated_at: datetime
    proof_contracts: list[ProofContractDefinition] = Field(default_factory=list)


class PlannerActionCatalog(BaseModel):
    version: int = 1
    program: str
    phase: int = 2
    generated_at: datetime
    planner_actions: list[PlannerActionDefinition] = Field(default_factory=list)


class CapabilityGraphCatalog(BaseModel):
    version: int = 1
    program: str
    phase: int = 2
    generated_at: datetime
    capability_graphs: list[CapabilityGraphDefinition] = Field(default_factory=list)
