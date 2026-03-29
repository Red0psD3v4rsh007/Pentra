"""Structured cheat-sheet registry schemas for Phase 3 capability prep."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from pentra_common.schemas.knowledge_source import KnowledgeFactCitation
from pentra_common.schemas.target_profile import TargetProfileKey
Phase3PackKey = Literal[
    "p3a_browser_xss",
    "p3a_multi_role_stateful_auth",
    "p3a_access_control_workflow_abuse",
    "p3a_injection",
    "p3a_parser_file_abuse",
    "p3a_disclosure_misconfig_crypto",
]
CheatSheetTrustRole = Literal["authoritative", "supplemental"]
PayloadInclusionMode = Literal[
    "metadata_only",
    "curated_archetypes",
    "supplemental_variants",
]


class CheatSheetEntryDefinition(BaseModel):
    key: str
    source_key: str
    title: str
    trust_role: CheatSheetTrustRole
    purpose: str
    applicable_contexts: list[str] = Field(default_factory=list)
    applicable_target_profile_keys: list[TargetProfileKey] = Field(default_factory=list)
    payload_inclusion_mode: PayloadInclusionMode = "metadata_only"
    selection_tags: list[str] = Field(default_factory=list)
    usage_notes: str | None = None
    citations: list[KnowledgeFactCitation] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_entry(self) -> "CheatSheetEntryDefinition":
        if not self.applicable_target_profile_keys:
            raise ValueError(f"Cheat-sheet entry '{self.key}' must define applicable_target_profile_keys")
        if not self.citations:
            raise ValueError(f"Cheat-sheet entry '{self.key}' must define citations")
        return self


class CheatSheetCategoryDefinition(BaseModel):
    key: str
    title: str
    description: str
    ontology_family_keys: list[str] = Field(default_factory=list)
    phase3_pack_keys: list[Phase3PackKey] = Field(default_factory=list)
    target_profile_keys: list[TargetProfileKey] = Field(default_factory=list)
    focus_areas: list[str] = Field(default_factory=list)
    selection_policy: list[str] = Field(default_factory=list)
    benchmark_target_keys: list[str] = Field(default_factory=list)
    entries: list[CheatSheetEntryDefinition] = Field(default_factory=list)
    citations: list[KnowledgeFactCitation] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_category(self) -> "CheatSheetCategoryDefinition":
        if not self.ontology_family_keys:
            raise ValueError(f"Cheat-sheet category '{self.key}' must define ontology_family_keys")
        if not self.phase3_pack_keys:
            raise ValueError(f"Cheat-sheet category '{self.key}' must define phase3_pack_keys")
        if not self.target_profile_keys:
            raise ValueError(f"Cheat-sheet category '{self.key}' must define target_profile_keys")
        if not self.selection_policy:
            raise ValueError(f"Cheat-sheet category '{self.key}' must define selection_policy")
        if not self.entries:
            raise ValueError(f"Cheat-sheet category '{self.key}' must define entries")
        if not self.citations:
            raise ValueError(f"Cheat-sheet category '{self.key}' must define citations")
        return self


class CheatSheetIndex(BaseModel):
    version: int = 1
    program: str
    phase: int = 2
    category_catalog_path: str


class CheatSheetCategoryCatalog(BaseModel):
    version: int = 1
    program: str
    phase: int = 2
    generated_at: datetime
    categories: list[CheatSheetCategoryDefinition] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_catalog(self) -> "CheatSheetCategoryCatalog":
        if not self.categories:
            raise ValueError("Cheat-sheet category catalog must define categories")
        return self
