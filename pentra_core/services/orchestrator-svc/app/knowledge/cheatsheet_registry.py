"""Structured cheat-sheet registry loader and validator for Phase 3 prep."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from pentra_common.schemas.knowledge_cheatsheet import (
    CheatSheetCategoryCatalog,
    CheatSheetCategoryDefinition,
    CheatSheetIndex,
)

from app.knowledge.ontology_registry import load_ontology_bundle
from app.knowledge.source_registry import load_knowledge_governance_bundle

_PENTRA_CORE_DIR = Path(__file__).resolve().parents[4]
_KNOWLEDGE_DIR = _PENTRA_CORE_DIR / "knowledge"
_CHEATSHEET_DIR = _KNOWLEDGE_DIR / "cheatsheets"
_CHEATSHEET_INDEX_PATH = _CHEATSHEET_DIR / "index.yaml"


@dataclass(frozen=True)
class CheatSheetRegistryBundle:
    index: CheatSheetIndex
    catalog: CheatSheetCategoryCatalog

    def get_category(self, key: str) -> CheatSheetCategoryDefinition | None:
        return next((category for category in self.catalog.categories if category.key == key), None)

    def categories_for_family(self, family_key: str) -> list[CheatSheetCategoryDefinition]:
        return [
            category
            for category in self.catalog.categories
            if family_key in category.ontology_family_keys
        ]

    def categories_for_pack(self, pack_key: str) -> list[CheatSheetCategoryDefinition]:
        return [
            category
            for category in self.catalog.categories
            if pack_key in category.phase3_pack_keys
        ]


def _load_yaml(path: Path) -> dict:
    payload = yaml.safe_load(path.read_text()) or {}
    if not isinstance(payload, dict):
        raise RuntimeError(f"Knowledge cheatsheet file must contain a YAML object: {path}")
    return payload


def load_cheatsheet_index(path: Path | None = None) -> CheatSheetIndex:
    return CheatSheetIndex.model_validate(_load_yaml(path or _CHEATSHEET_INDEX_PATH))


def load_cheatsheet_catalog(relative_path: str | Path | None = None) -> CheatSheetCategoryCatalog:
    index = load_cheatsheet_index()
    path = _CHEATSHEET_DIR / Path(relative_path or index.category_catalog_path)
    return CheatSheetCategoryCatalog.model_validate(_load_yaml(path))


def load_cheatsheet_bundle(index_path: Path | None = None) -> CheatSheetRegistryBundle:
    index = load_cheatsheet_index(index_path)
    catalog = load_cheatsheet_catalog(index.category_catalog_path)
    bundle = CheatSheetRegistryBundle(index=index, catalog=catalog)
    _validate_bundle(bundle)
    return bundle


def _validate_bundle(bundle: CheatSheetRegistryBundle) -> None:
    governance = load_knowledge_governance_bundle()
    ontology = load_ontology_bundle()

    registry = governance.registry
    contract = governance.provenance_contract
    default_profile = registry.get_profile()
    if default_profile is None:
        raise RuntimeError("Default source profile could not be loaded for cheat-sheet validation")

    allowed_tiers = set(contract.allowed_trust_tiers) | set(contract.optional_trust_tiers)
    source_keys = {source.key for source in registry.sources}
    family_keys = {family.key for family in ontology.challenge_families.families}

    category_keys = [category.key for category in bundle.catalog.categories]
    if len(category_keys) != len(set(category_keys)):
        raise RuntimeError("Cheat-sheet registry contains duplicate category keys")

    all_entry_keys: list[str] = []

    def validate_citations(owner: str, citations: list) -> None:
        for citation in citations:
            if citation.source_key not in source_keys:
                raise RuntimeError(f"{owner} references unknown citation source '{citation.source_key}'")
            source = registry.get_source(citation.source_key)
            if source is None or not default_profile.allows_tier(source.trust_tier):
                raise RuntimeError(
                    f"{owner} references citation source '{citation.source_key}' outside the default active profile"
                )
            if citation.trust_tier != source.trust_tier:
                raise RuntimeError(
                    f"{owner} citation trust tier does not match source '{citation.source_key}'"
                )
            if citation.trust_tier not in allowed_tiers:
                raise RuntimeError(f"{owner} uses blocked trust tier '{citation.trust_tier}'")

    for category in bundle.catalog.categories:
        if set(category.ontology_family_keys) - family_keys:
            raise RuntimeError(
                f"Cheat-sheet category '{category.key}' references unknown ontology family keys"
            )
        validate_citations(f"cheat-sheet category '{category.key}'", category.citations)
        if not all(pack_key.startswith("p3") for pack_key in category.phase3_pack_keys):
            raise RuntimeError(
                f"Cheat-sheet category '{category.key}' contains invalid Phase 3 pack keys"
            )
        authoritative_entries = 0
        for entry in category.entries:
            all_entry_keys.append(entry.key)
            if entry.source_key not in source_keys:
                raise RuntimeError(
                    f"Cheat-sheet entry '{entry.key}' references unknown source '{entry.source_key}'"
                )
            source = registry.get_source(entry.source_key)
            if source is None or not default_profile.allows_tier(source.trust_tier):
                raise RuntimeError(
                    f"Cheat-sheet entry '{entry.key}' source '{entry.source_key}' is outside the default active profile"
                )
            validate_citations(f"cheat-sheet entry '{entry.key}'", entry.citations)
            if any(citation.source_key != entry.source_key for citation in entry.citations):
                raise RuntimeError(
                    f"Cheat-sheet entry '{entry.key}' citations must point at the entry source_key"
                )
            if entry.trust_role == "authoritative":
                if source.trust_tier == "community_public":
                    raise RuntimeError(
                        f"Cheat-sheet entry '{entry.key}' cannot mark a community source as authoritative"
                    )
                authoritative_entries += 1
            if entry.trust_role == "supplemental" and source.trust_tier != "community_public":
                continue
        if authoritative_entries == 0:
            raise RuntimeError(
                f"Cheat-sheet category '{category.key}' must define at least one authoritative official source"
            )

    if len(all_entry_keys) != len(set(all_entry_keys)):
        raise RuntimeError("Cheat-sheet registry contains duplicate entry keys")
