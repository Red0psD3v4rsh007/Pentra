"""Phase 10 source-governance loader for the public-source-first program."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from pentra_common.schemas.knowledge_source import (
    KnowledgeProvenanceContract,
    KnowledgeSourceRegistry,
)

_PENTRA_CORE_DIR = Path(__file__).resolve().parents[4]
_KNOWLEDGE_DIR = _PENTRA_CORE_DIR / "knowledge"
_SOURCE_REGISTRY_PATH = _KNOWLEDGE_DIR / "source_registry.yaml"
_PROVENANCE_CONTRACT_PATH = _KNOWLEDGE_DIR / "provenance_contract.yaml"


@dataclass(frozen=True)
class KnowledgeGovernanceBundle:
    registry: KnowledgeSourceRegistry
    provenance_contract: KnowledgeProvenanceContract


def _load_yaml(path: Path) -> dict:
    payload = yaml.safe_load(path.read_text()) or {}
    if not isinstance(payload, dict):
        raise RuntimeError(f"Knowledge governance file must contain a YAML object: {path}")
    return payload


def load_source_registry(path: Path | None = None) -> KnowledgeSourceRegistry:
    registry = KnowledgeSourceRegistry.model_validate(
        _load_yaml(path or _SOURCE_REGISTRY_PATH)
    )
    return registry


def load_provenance_contract(path: Path | None = None) -> KnowledgeProvenanceContract:
    contract = KnowledgeProvenanceContract.model_validate(
        _load_yaml(path or _PROVENANCE_CONTRACT_PATH)
    )
    return contract


def load_knowledge_governance_bundle(
    *,
    registry_path: Path | None = None,
    provenance_contract_path: Path | None = None,
) -> KnowledgeGovernanceBundle:
    registry = load_source_registry(registry_path)
    contract = load_provenance_contract(provenance_contract_path)
    _validate_bundle(registry=registry, contract=contract)
    return KnowledgeGovernanceBundle(
        registry=registry,
        provenance_contract=contract,
    )


def _validate_bundle(
    *,
    registry: KnowledgeSourceRegistry,
    contract: KnowledgeProvenanceContract,
) -> None:
    if registry.program != contract.program:
        raise RuntimeError(
            "Knowledge governance program mismatch between registry and provenance contract"
        )

    default_profile = registry.get_profile()
    if default_profile is None:
        raise RuntimeError("Knowledge source registry default profile could not be loaded")

    profile_allowed = set(default_profile.allowed_trust_tiers)
    contract_allowed = set(contract.allowed_trust_tiers)
    if profile_allowed != contract_allowed:
        raise RuntimeError(
            "Default profile allowed trust tiers do not match the provenance contract"
        )

    profile_optional = set(default_profile.optional_trust_tiers)
    contract_optional = set(contract.optional_trust_tiers)
    if profile_optional != contract_optional:
        raise RuntimeError(
            "Default profile optional trust tiers do not match the provenance contract"
        )

    profile_blocked = set(default_profile.blocked_trust_tiers)
    contract_blocked = set(contract.blocked_trust_tiers)
    if profile_blocked != contract_blocked:
        raise RuntimeError(
            "Default profile blocked trust tiers do not match the provenance contract"
        )

    runtime_truth_sources = [
        source
        for source in registry.sources
        if source.trust_tier == "runtime_truth"
    ]
    if not runtime_truth_sources:
        raise RuntimeError("Knowledge source registry must define at least one runtime-truth source")
