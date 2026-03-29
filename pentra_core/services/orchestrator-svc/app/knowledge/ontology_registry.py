"""Phase 2 ontology loader and validator for the public-source-first program."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from pentra_common.schemas.knowledge_ontology import (
    AttackPrimitiveCatalog,
    CapabilityGraphCatalog,
    ChallengeFamilyCatalog,
    KnowledgeOntologyIndex,
    PlannerActionCatalog,
    ProofContractCatalog,
    RoleModelCatalog,
    WorkflowStateCatalog,
)

from app.knowledge.corpus_registry import load_corpus_bundle
from app.knowledge.source_registry import load_knowledge_governance_bundle

_PENTRA_CORE_DIR = Path(__file__).resolve().parents[4]
_KNOWLEDGE_DIR = _PENTRA_CORE_DIR / "knowledge"
_ONTOLOGY_DIR = _KNOWLEDGE_DIR / "ontology"
_ONTOLOGY_INDEX_PATH = _ONTOLOGY_DIR / "index.yaml"


@dataclass(frozen=True)
class KnowledgeOntologyBundle:
    index: KnowledgeOntologyIndex
    challenge_families: ChallengeFamilyCatalog
    attack_primitives: AttackPrimitiveCatalog
    workflow_states: WorkflowStateCatalog
    role_models: RoleModelCatalog
    proof_contracts: ProofContractCatalog
    planner_actions: PlannerActionCatalog
    capability_graphs: CapabilityGraphCatalog

    def get_family(self, key: str):
        return next((family for family in self.challenge_families.families if family.key == key), None)

    def get_attack_primitive(self, key: str):
        return next(
            (primitive for primitive in self.attack_primitives.attack_primitives if primitive.key == key),
            None,
        )

    def get_proof_contract(self, key: str):
        return next((proof for proof in self.proof_contracts.proof_contracts if proof.key == key), None)

    def get_planner_action(self, key: str):
        return next((action for action in self.planner_actions.planner_actions if action.key == key), None)

    def family_for_category_label(self, label: str) -> list:
        lowered = label.strip().lower()
        return [
            family
            for family in self.challenge_families.families
            if lowered in {value.lower() for value in family.category_labels}
        ]

    def families_for_target(self, target_key: str) -> list:
        return [
            family
            for family in self.challenge_families.families
            if target_key in family.benchmark_target_keys
        ]

    def planner_actions_for_family(self, family_key: str) -> list:
        family = self.get_family(family_key)
        if family is None:
            return []
        return [
            action
            for action_key in family.planner_action_keys
            if (action := self.get_planner_action(action_key)) is not None
        ]

    def proof_contracts_for_family(self, family_key: str) -> list:
        family = self.get_family(family_key)
        if family is None:
            return []
        return [
            proof
            for proof_key in family.proof_contract_keys
            if (proof := self.get_proof_contract(proof_key)) is not None
        ]

    def category_action_map(self, target_key: str) -> dict[str, list[str]]:
        mapping: dict[str, list[str]] = {}
        for family in self.families_for_target(target_key):
            actions = [action.key for action in self.planner_actions_for_family(family.key)]
            for label in family.category_labels:
                mapping[label] = actions
        return mapping


@dataclass(frozen=True)
class CapabilityGraphAlignment:
    graph_key: str
    score: int
    matched_target_profile_keys: list[str]
    matched_challenge_family_keys: list[str]
    matched_attack_primitive_keys: list[str]
    matched_proof_contract_keys: list[str]
    matched_planner_action_keys: list[str]
    matched_benchmark_target_keys: list[str]
    rationale: list[str]


def _load_yaml(path: Path) -> dict:
    payload = yaml.safe_load(path.read_text()) or {}
    if not isinstance(payload, dict):
        raise RuntimeError(f"Knowledge ontology file must contain a YAML object: {path}")
    return payload


def load_ontology_index(path: Path | None = None) -> KnowledgeOntologyIndex:
    return KnowledgeOntologyIndex.model_validate(_load_yaml(path or _ONTOLOGY_INDEX_PATH))


@lru_cache(maxsize=1)
def load_ontology_bundle(index_path: Path | None = None) -> KnowledgeOntologyBundle:
    index = load_ontology_index(index_path)
    bundle = KnowledgeOntologyBundle(
        index=index,
        challenge_families=ChallengeFamilyCatalog.model_validate(
            _load_yaml(_ONTOLOGY_DIR / index.challenge_family_path)
        ),
        attack_primitives=AttackPrimitiveCatalog.model_validate(
            _load_yaml(_ONTOLOGY_DIR / index.attack_primitive_path)
        ),
        workflow_states=WorkflowStateCatalog.model_validate(
            _load_yaml(_ONTOLOGY_DIR / index.workflow_state_path)
        ),
        role_models=RoleModelCatalog.model_validate(
            _load_yaml(_ONTOLOGY_DIR / index.role_model_path)
        ),
        proof_contracts=ProofContractCatalog.model_validate(
            _load_yaml(_ONTOLOGY_DIR / index.proof_contract_path)
        ),
        planner_actions=PlannerActionCatalog.model_validate(
            _load_yaml(_ONTOLOGY_DIR / index.planner_action_path)
        ),
        capability_graphs=CapabilityGraphCatalog.model_validate(
            _load_yaml(_ONTOLOGY_DIR / index.capability_graph_path)
        ),
    )
    _validate_ontology_bundle(bundle)
    return bundle


def align_capability_graphs(
    *,
    target_profile_keys: list[str],
    challenge_family_keys: list[str],
    attack_primitive_keys: list[str],
    proof_contract_keys: list[str],
    planner_action_keys: list[str],
    benchmark_target_keys: list[str],
) -> list[CapabilityGraphAlignment]:
    bundle = load_ontology_bundle()
    target_profile_set = {item.strip() for item in target_profile_keys if str(item).strip()}
    family_set = {item.strip() for item in challenge_family_keys if str(item).strip()}
    primitive_set = {item.strip() for item in attack_primitive_keys if str(item).strip()}
    proof_set = {item.strip() for item in proof_contract_keys if str(item).strip()}
    planner_set = {item.strip() for item in planner_action_keys if str(item).strip()}
    benchmark_set = {item.strip() for item in benchmark_target_keys if str(item).strip()}

    alignments: list[CapabilityGraphAlignment] = []
    for graph in bundle.capability_graphs.capability_graphs:
        matched_target_profiles = sorted(target_profile_set & set(graph.target_profile_keys))
        matched_families = sorted(family_set & set(graph.challenge_family_keys))
        matched_primitives = sorted(primitive_set & set(graph.attack_primitive_keys))
        matched_proofs = sorted(proof_set & set(graph.proof_contract_keys))
        matched_actions = sorted(planner_set & set(graph.planner_action_keys))
        matched_targets = sorted(benchmark_set & set(graph.benchmark_target_keys))
        if not (
            matched_target_profiles
            or matched_families
            or matched_primitives
            or matched_proofs
            or matched_actions
            or matched_targets
        ):
            continue

        score = (
            len(matched_target_profiles) * 8
            + len(matched_families) * 6
            + len(matched_actions) * 4
            + len(matched_proofs) * 3
            + len(matched_primitives) * 2
            + (12 if matched_targets else 0)
        )
        rationale: list[str] = []
        if matched_target_profiles:
            rationale.append(
                f"target-profile overlap with {graph.key}: {', '.join(matched_target_profiles[:3])}"
            )
        if matched_targets:
            rationale.append(
                f"benchmark target overlap with {graph.key}: {', '.join(matched_targets[:3])}"
            )
        if matched_families:
            rationale.append(
                f"challenge-family overlap with {graph.key}: {', '.join(matched_families[:4])}"
            )
        if matched_actions:
            rationale.append(
                f"planner-action overlap with {graph.key}: {', '.join(matched_actions[:4])}"
            )
        if matched_proofs:
            rationale.append(
                f"proof-contract overlap with {graph.key}: {', '.join(matched_proofs[:4])}"
            )
        if matched_primitives:
            rationale.append(
                f"attack-primitive overlap with {graph.key}: {', '.join(matched_primitives[:4])}"
            )

        alignments.append(
            CapabilityGraphAlignment(
                graph_key=graph.key,
                score=score,
                matched_target_profile_keys=matched_target_profiles,
                matched_challenge_family_keys=matched_families,
                matched_attack_primitive_keys=matched_primitives,
                matched_proof_contract_keys=matched_proofs,
                matched_planner_action_keys=matched_actions,
                matched_benchmark_target_keys=matched_targets,
                rationale=rationale,
            )
        )

    alignments.sort(key=lambda item: (-item.score, item.graph_key))
    return alignments


def _validate_ontology_bundle(bundle: KnowledgeOntologyBundle) -> None:
    governance = load_knowledge_governance_bundle()
    corpus = load_corpus_bundle()

    registry = governance.registry
    contract = governance.provenance_contract
    allowed_tiers = set(contract.allowed_trust_tiers) | set(contract.optional_trust_tiers)
    default_profile = registry.get_profile()
    if default_profile is None:
        raise RuntimeError("Default source profile could not be loaded for ontology validation")
    source_keys = {source.key for source in registry.sources}
    source_summary_keys = {document.key for document in corpus.documents}

    family_keys = {family.key for family in bundle.challenge_families.families}
    primitive_keys = {primitive.key for primitive in bundle.attack_primitives.attack_primitives}
    workflow_keys = {state.key for state in bundle.workflow_states.workflow_states}
    role_model_keys = {role.key for role in bundle.role_models.role_models}
    proof_keys = {proof.key for proof in bundle.proof_contracts.proof_contracts}
    planner_keys = {action.key for action in bundle.planner_actions.planner_actions}

    if len(family_keys) != len(bundle.challenge_families.families):
        raise RuntimeError("Phase 2 ontology contains duplicate challenge family keys")
    if len(primitive_keys) != len(bundle.attack_primitives.attack_primitives):
        raise RuntimeError("Phase 2 ontology contains duplicate attack primitive keys")
    if len(workflow_keys) != len(bundle.workflow_states.workflow_states):
        raise RuntimeError("Phase 2 ontology contains duplicate workflow state keys")
    if len(role_model_keys) != len(bundle.role_models.role_models):
        raise RuntimeError("Phase 2 ontology contains duplicate role model keys")
    if len(proof_keys) != len(bundle.proof_contracts.proof_contracts):
        raise RuntimeError("Phase 2 ontology contains duplicate proof contract keys")
    if len(planner_keys) != len(bundle.planner_actions.planner_actions):
        raise RuntimeError("Phase 2 ontology contains duplicate planner action keys")

    def validate_sources(owner: str, summary_keys: list[str], citations: list) -> None:
        missing_summaries = set(summary_keys) - source_summary_keys
        if missing_summaries:
            raise RuntimeError(f"{owner} references unknown source summaries: {sorted(missing_summaries)}")
        for citation in citations:
            if citation.source_key not in source_keys:
                raise RuntimeError(f"{owner} references unknown citation source '{citation.source_key}'")
            citation_source = registry.get_source(citation.source_key)
            if citation_source is None or not default_profile.allows_tier(citation_source.trust_tier):
                raise RuntimeError(
                    f"{owner} references citation source '{citation.source_key}' outside the default active profile"
                )
            if citation.trust_tier != citation_source.trust_tier:
                raise RuntimeError(
                    f"{owner} citation trust tier does not match source '{citation.source_key}'"
                )
            if citation.trust_tier not in allowed_tiers:
                raise RuntimeError(f"{owner} uses blocked trust tier '{citation.trust_tier}'")

    for family in bundle.challenge_families.families:
        validate_sources(f"challenge family '{family.key}'", family.source_summary_keys, family.citations)
        if set(family.attack_primitive_keys) - primitive_keys:
            raise RuntimeError(f"Challenge family '{family.key}' references unknown attack primitives")
        if set(family.workflow_state_keys) - workflow_keys:
            raise RuntimeError(f"Challenge family '{family.key}' references unknown workflow states")
        if set(family.role_model_keys) - role_model_keys:
            raise RuntimeError(f"Challenge family '{family.key}' references unknown role models")
        if set(family.proof_contract_keys) - proof_keys:
            raise RuntimeError(f"Challenge family '{family.key}' references unknown proof contracts")
        if set(family.planner_action_keys) - planner_keys:
            raise RuntimeError(f"Challenge family '{family.key}' references unknown planner actions")

    for primitive in bundle.attack_primitives.attack_primitives:
        validate_sources(f"attack primitive '{primitive.key}'", primitive.source_summary_keys, primitive.citations)
        if set(primitive.challenge_family_keys) - family_keys:
            raise RuntimeError(f"Attack primitive '{primitive.key}' references unknown challenge families")
        if set(primitive.proof_contract_keys) - proof_keys:
            raise RuntimeError(f"Attack primitive '{primitive.key}' references unknown proof contracts")
        if set(primitive.planner_action_keys) - planner_keys:
            raise RuntimeError(f"Attack primitive '{primitive.key}' references unknown planner actions")

    for state in bundle.workflow_states.workflow_states:
        validate_sources(f"workflow state '{state.key}'", state.source_summary_keys, state.citations)

    for role_model in bundle.role_models.role_models:
        validate_sources(f"role model '{role_model.key}'", role_model.source_summary_keys, role_model.citations)

    for proof in bundle.proof_contracts.proof_contracts:
        validate_sources(f"proof contract '{proof.key}'", proof.source_summary_keys, proof.citations)

    for action in bundle.planner_actions.planner_actions:
        validate_sources(f"planner action '{action.key}'", action.source_summary_keys, action.citations)

    node_sets = {
        "challenge_family": family_keys,
        "attack_primitive": primitive_keys,
        "workflow_state": workflow_keys,
        "role_model": role_model_keys,
        "proof_contract": proof_keys,
        "planner_action": planner_keys,
    }

    for graph in bundle.capability_graphs.capability_graphs:
        validate_sources(f"capability graph '{graph.key}'", graph.source_summary_keys, graph.citations)
        if set(graph.challenge_family_keys) - family_keys:
            raise RuntimeError(f"Capability graph '{graph.key}' references unknown challenge families")
        if set(graph.attack_primitive_keys) - primitive_keys:
            raise RuntimeError(f"Capability graph '{graph.key}' references unknown attack primitives")
        if set(graph.workflow_state_keys) - workflow_keys:
            raise RuntimeError(f"Capability graph '{graph.key}' references unknown workflow states")
        if set(graph.role_model_keys) - role_model_keys:
            raise RuntimeError(f"Capability graph '{graph.key}' references unknown role models")
        if set(graph.proof_contract_keys) - proof_keys:
            raise RuntimeError(f"Capability graph '{graph.key}' references unknown proof contracts")
        if set(graph.planner_action_keys) - planner_keys:
            raise RuntimeError(f"Capability graph '{graph.key}' references unknown planner actions")

        for edge in graph.edges:
            if edge.source_key not in node_sets[edge.source_type]:
                raise RuntimeError(
                    f"Capability graph '{graph.key}' edge source '{edge.source_key}' is invalid for {edge.source_type}"
                )
            if edge.target_key not in node_sets[edge.target_type]:
                raise RuntimeError(
                    f"Capability graph '{graph.key}' edge target '{edge.target_key}' is invalid for {edge.target_type}"
                )

    runtime_document = next(
        (document for document in corpus.documents if document.key == "juice_shop_runtime_inventory_local_19_2_1"),
        None,
    )
    if runtime_document is None:
        raise RuntimeError("Phase 2 ontology validation requires the Juice Shop runtime summary document")
    category_fact = next(
        (fact for fact in runtime_document.facts if fact.fact_key == "juice_shop_local_19_2_1_category_counts"),
        None,
    )
    if category_fact is None:
        raise RuntimeError("Juice Shop runtime summary is missing category-count truth")
    runtime_categories = set(category_fact.data["category_counts"].keys())
    mapped_categories = {
        label
        for family in bundle.challenge_families.families
        for label in family.category_labels
    }
    missing_categories = runtime_categories - mapped_categories
    if missing_categories:
        raise RuntimeError(
            f"Phase 2 ontology is missing family mappings for runtime categories: {sorted(missing_categories)}"
        )
