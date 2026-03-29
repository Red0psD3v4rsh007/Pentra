"""Knowledge corpus schemas for Phase 1 public-source acquisition."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

from pentra_common.schemas.knowledge_source import KnowledgeFactCitation


KnowledgeDocumentType = Literal[
    "source_summary",
    "runtime_inventory_summary",
]


class KnowledgeAcquisitionManifest(BaseModel):
    key: str
    phase: int = 1
    source_key: str
    title: str
    acquisition_scope: str
    parser_key: str
    normalization_units: list[str] = Field(default_factory=list)
    target_outputs: list[str] = Field(default_factory=list)
    focus_areas: list[str] = Field(default_factory=list)
    benchmark_target_keys: list[str] = Field(default_factory=list)
    usage_notes: str | None = None
    citations: list[KnowledgeFactCitation] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_manifest(self) -> "KnowledgeAcquisitionManifest":
        if self.phase < 1:
            raise ValueError("Knowledge acquisition manifest phase must be >= 1")
        if not self.normalization_units:
            raise ValueError(
                f"Knowledge acquisition manifest '{self.key}' must define normalization_units"
            )
        if not self.target_outputs:
            raise ValueError(
                f"Knowledge acquisition manifest '{self.key}' must define target_outputs"
            )
        if not self.citations:
            raise ValueError(
                f"Knowledge acquisition manifest '{self.key}' must define at least one citation"
            )
        return self


class NormalizedKnowledgeFact(BaseModel):
    fact_key: str
    title: str
    fact_type: str
    summary: str = ""
    tags: list[str] = Field(default_factory=list)
    data: dict[str, Any] = Field(default_factory=dict)
    citations: list[KnowledgeFactCitation] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_fact(self) -> "NormalizedKnowledgeFact":
        if not self.citations:
            raise ValueError(f"Normalized knowledge fact '{self.fact_key}' must define citations")
        return self


class KnowledgeSummaryDocument(BaseModel):
    key: str
    title: str
    source_key: str
    document_type: KnowledgeDocumentType
    generated_at: datetime
    summary: str
    facts: list[NormalizedKnowledgeFact] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_document(self) -> "KnowledgeSummaryDocument":
        if not self.facts:
            raise ValueError(f"Knowledge summary document '{self.key}' must define facts")
        return self


class KnowledgeCorpusIndex(BaseModel):
    version: int = 1
    program: str
    phase: int = 1
    raw_manifest_paths: list[str] = Field(default_factory=list)
    normalized_document_paths: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_index(self) -> "KnowledgeCorpusIndex":
        if self.phase < 1:
            raise ValueError("Knowledge corpus index phase must be >= 1")
        if not self.raw_manifest_paths:
            raise ValueError("Knowledge corpus index must define raw_manifest_paths")
        if not self.normalized_document_paths:
            raise ValueError("Knowledge corpus index must define normalized_document_paths")
        if len(self.raw_manifest_paths) != len(set(self.raw_manifest_paths)):
            raise ValueError("Knowledge corpus index contains duplicate raw manifest paths")
        if len(self.normalized_document_paths) != len(set(self.normalized_document_paths)):
            raise ValueError("Knowledge corpus index contains duplicate normalized document paths")
        return self
