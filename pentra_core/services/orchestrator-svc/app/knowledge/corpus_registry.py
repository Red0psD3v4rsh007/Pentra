"""Phase 1 corpus loader and validator for the public-source-first program."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from pentra_common.schemas.knowledge_corpus import (
    KnowledgeAcquisitionManifest,
    KnowledgeCorpusIndex,
    KnowledgeSummaryDocument,
)

from app.knowledge.source_registry import load_knowledge_governance_bundle

_PENTRA_CORE_DIR = Path(__file__).resolve().parents[4]
_KNOWLEDGE_DIR = _PENTRA_CORE_DIR / "knowledge"
_CORPUS_DIR = _KNOWLEDGE_DIR / "corpus"
_CORPUS_INDEX_PATH = _CORPUS_DIR / "index.yaml"


@dataclass(frozen=True)
class KnowledgeCorpusBundle:
    index: KnowledgeCorpusIndex
    manifests: list[KnowledgeAcquisitionManifest]
    documents: list[KnowledgeSummaryDocument]


def _load_yaml(path: Path) -> dict:
    payload = yaml.safe_load(path.read_text()) or {}
    if not isinstance(payload, dict):
        raise RuntimeError(f"Knowledge corpus file must contain a YAML object: {path}")
    return payload


def load_corpus_index(path: Path | None = None) -> KnowledgeCorpusIndex:
    return KnowledgeCorpusIndex.model_validate(_load_yaml(path or _CORPUS_INDEX_PATH))


def load_acquisition_manifest(relative_path: str | Path) -> KnowledgeAcquisitionManifest:
    path = _CORPUS_DIR / Path(relative_path)
    return KnowledgeAcquisitionManifest.model_validate(_load_yaml(path))


def load_summary_document(relative_path: str | Path) -> KnowledgeSummaryDocument:
    path = _CORPUS_DIR / Path(relative_path)
    return KnowledgeSummaryDocument.model_validate(_load_yaml(path))


def load_corpus_bundle(index_path: Path | None = None) -> KnowledgeCorpusBundle:
    index = load_corpus_index(index_path)
    manifests = [load_acquisition_manifest(path) for path in index.raw_manifest_paths]
    documents = [load_summary_document(path) for path in index.normalized_document_paths]
    _validate_bundle(index=index, manifests=manifests, documents=documents)
    return KnowledgeCorpusBundle(index=index, manifests=manifests, documents=documents)


def _validate_bundle(
    *,
    index: KnowledgeCorpusIndex,
    manifests: list[KnowledgeAcquisitionManifest],
    documents: list[KnowledgeSummaryDocument],
) -> None:
    governance = load_knowledge_governance_bundle()
    registry = governance.registry
    contract = governance.provenance_contract
    default_profile = registry.get_profile()
    if default_profile is None:
        raise RuntimeError("Default source profile could not be loaded for corpus validation")

    manifest_keys = [manifest.key for manifest in manifests]
    if len(manifest_keys) != len(set(manifest_keys)):
        raise RuntimeError("Knowledge corpus bundle contains duplicate manifest keys")

    document_keys = [document.key for document in documents]
    if len(document_keys) != len(set(document_keys)):
        raise RuntimeError("Knowledge corpus bundle contains duplicate document keys")

    allowed_tiers = set(contract.allowed_trust_tiers) | set(contract.optional_trust_tiers)
    source_keys = {source.key for source in registry.sources}

    for manifest in manifests:
        if manifest.source_key not in source_keys:
            raise RuntimeError(f"Manifest '{manifest.key}' references unknown source '{manifest.source_key}'")
        source = registry.get_source(manifest.source_key)
        if source is None or not default_profile.allows_tier(source.trust_tier):
            raise RuntimeError(
                f"Manifest '{manifest.key}' uses source '{manifest.source_key}' outside the default active profile"
            )
        for target_output in manifest.target_outputs:
            if target_output not in index.normalized_document_paths:
                raise RuntimeError(
                    f"Manifest '{manifest.key}' target_output '{target_output}' is missing from corpus index"
                )
        for citation in manifest.citations:
            if citation.source_key not in source_keys:
                raise RuntimeError(
                    f"Manifest '{manifest.key}' citation references unknown source '{citation.source_key}'"
                )
            citation_source = registry.get_source(citation.source_key)
            if citation_source is None or not default_profile.allows_tier(citation_source.trust_tier):
                raise RuntimeError(
                    f"Manifest '{manifest.key}' citation source '{citation.source_key}' is outside the default active profile"
                )
            if citation.trust_tier != citation_source.trust_tier:
                raise RuntimeError(
                    f"Manifest '{manifest.key}' citation trust tier does not match source '{citation.source_key}'"
                )
            if citation.trust_tier not in allowed_tiers:
                raise RuntimeError(
                    f"Manifest '{manifest.key}' citation uses blocked trust tier '{citation.trust_tier}'"
                )

    for document in documents:
        if document.source_key not in source_keys:
            raise RuntimeError(
                f"Knowledge summary document '{document.key}' references unknown source '{document.source_key}'"
            )
        for fact in document.facts:
            for citation in fact.citations:
                if citation.source_key not in source_keys:
                    raise RuntimeError(
                        f"Knowledge fact '{fact.fact_key}' references unknown source '{citation.source_key}'"
                    )
                citation_source = registry.get_source(citation.source_key)
                if citation_source is None or not default_profile.allows_tier(citation_source.trust_tier):
                    raise RuntimeError(
                        f"Knowledge fact '{fact.fact_key}' citation source '{citation.source_key}' is outside the default active profile"
                    )
                if citation.trust_tier != citation_source.trust_tier:
                    raise RuntimeError(
                        f"Knowledge fact '{fact.fact_key}' citation trust tier does not match source '{citation.source_key}'"
                    )
                if citation.trust_tier not in allowed_tiers:
                    raise RuntimeError(
                        f"Knowledge fact '{fact.fact_key}' uses blocked trust tier '{citation.trust_tier}'"
                    )

    manifest_source_keys = {manifest.source_key for manifest in manifests}
    document_source_keys = {document.source_key for document in documents}
    if manifest_source_keys != document_source_keys:
        raise RuntimeError(
            "Knowledge corpus manifests and normalized documents do not cover the same source keys"
        )
