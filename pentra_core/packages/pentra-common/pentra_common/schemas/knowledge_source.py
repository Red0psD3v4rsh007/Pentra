"""Knowledge-source governance schemas for the public-source-first program."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, model_validator


TrustTier = Literal[
    "official_public",
    "official_project",
    "runtime_truth",
    "community_public",
    "credentialed_optional",
    "proprietary_private",
]
AccessLevel = Literal["public", "gated", "local_runtime"]
VersionPolicy = Literal["floating", "source_pinned", "runtime_pinned"]
ExtractionMode = Literal["browse", "runtime_api", "repo_source", "manual"]


class KnowledgeSourceProfile(BaseModel):
    key: str
    description: str = ""
    allowed_trust_tiers: list[TrustTier] = Field(default_factory=list)
    optional_trust_tiers: list[TrustTier] = Field(default_factory=list)
    blocked_trust_tiers: list[TrustTier] = Field(default_factory=list)

    def active_trust_tiers(self) -> list[TrustTier]:
        ordered = [*self.allowed_trust_tiers, *self.optional_trust_tiers]
        deduped: list[TrustTier] = []
        for value in ordered:
            if value not in deduped:
                deduped.append(value)
        return deduped

    def allows_tier(self, tier: TrustTier) -> bool:
        return tier in self.active_trust_tiers() and tier not in self.blocked_trust_tiers

    @model_validator(mode="after")
    def _validate_profile(self) -> "KnowledgeSourceProfile":
        overlap = set(self.allowed_trust_tiers) & set(self.blocked_trust_tiers)
        if overlap:
            raise ValueError(f"Profile trust tiers overlap between allowed and blocked: {sorted(overlap)}")
        return self


class KnowledgeSourceRecord(BaseModel):
    key: str
    title: str
    provider: str
    trust_tier: TrustTier
    access_level: AccessLevel
    source_types: list[str] = Field(default_factory=list)
    authority_for: list[str] = Field(default_factory=list)
    version_policy: VersionPolicy = "floating"
    source_version: str | None = None
    target_key: str | None = None
    target_version: str | None = None
    artifact_path: str | None = None
    extraction_mode: ExtractionMode = "browse"
    urls: list[str] = Field(default_factory=list)
    enabled: bool = True
    notes: str | None = None

    @property
    def is_runtime_truth(self) -> bool:
        return self.trust_tier == "runtime_truth"

    @property
    def is_version_pinned(self) -> bool:
        return self.version_policy in {"source_pinned", "runtime_pinned"}

    @model_validator(mode="after")
    def _validate_source(self) -> "KnowledgeSourceRecord":
        if not self.urls:
            raise ValueError(f"Knowledge source '{self.key}' must define at least one URL")
        if self.version_policy == "source_pinned" and not self.source_version:
            raise ValueError(f"Knowledge source '{self.key}' is source_pinned but has no source_version")
        if self.version_policy == "runtime_pinned":
            if not self.target_key or not self.target_version:
                raise ValueError(
                    f"Knowledge source '{self.key}' is runtime_pinned but missing target_key or target_version"
                )
        if self.is_runtime_truth and not self.artifact_path:
            raise ValueError(f"Runtime-truth source '{self.key}' must carry an artifact_path")
        return self


class KnowledgeSourceRegistry(BaseModel):
    version: int = 1
    program: str
    default_profile: str
    profiles: list[KnowledgeSourceProfile] = Field(default_factory=list)
    sources: list[KnowledgeSourceRecord] = Field(default_factory=list)

    def get_profile(self, key: str | None = None) -> KnowledgeSourceProfile | None:
        target = key or self.default_profile
        return next((profile for profile in self.profiles if profile.key == target), None)

    def get_source(self, key: str) -> KnowledgeSourceRecord | None:
        return next((source for source in self.sources if source.key == key), None)

    def active_sources(self, profile_key: str | None = None) -> list[KnowledgeSourceRecord]:
        profile = self.get_profile(profile_key)
        if profile is None:
            return []
        return [
            source
            for source in self.sources
            if source.enabled and profile.allows_tier(source.trust_tier)
        ]

    @model_validator(mode="after")
    def _validate_registry(self) -> "KnowledgeSourceRegistry":
        profile_keys = [profile.key for profile in self.profiles]
        if self.default_profile not in profile_keys:
            raise ValueError(f"default_profile '{self.default_profile}' is not defined in profiles")

        source_keys = [source.key for source in self.sources]
        if len(source_keys) != len(set(source_keys)):
            raise ValueError("Knowledge source registry contains duplicate source keys")
        return self


class KnowledgeFactCitation(BaseModel):
    fact_key: str
    title: str
    source_key: str
    source_url: str
    trust_tier: TrustTier
    retrieved_at: datetime
    extraction_mode: ExtractionMode
    authority_for: list[str] = Field(default_factory=list)
    source_version: str | None = None
    target_key: str | None = None
    target_version: str | None = None
    artifact_path: str | None = None


class KnowledgeProvenanceContract(BaseModel):
    version: int = 1
    program: str
    allowed_trust_tiers: list[TrustTier] = Field(default_factory=list)
    optional_trust_tiers: list[TrustTier] = Field(default_factory=list)
    blocked_trust_tiers: list[TrustTier] = Field(default_factory=list)
    required_citation_fields: list[str] = Field(default_factory=list)
    required_benchmark_truth_fields: list[str] = Field(default_factory=list)
    normalized_fact_rules: list[str] = Field(default_factory=list)
    benchmark_truth_rules: list[str] = Field(default_factory=list)
    storage_modes: dict[str, str] = Field(default_factory=dict)
    restricted_content_policy: str = ""

    @model_validator(mode="after")
    def _validate_contract(self) -> "KnowledgeProvenanceContract":
        overlap = set(self.allowed_trust_tiers) & set(self.blocked_trust_tiers)
        if overlap:
            raise ValueError(f"Provenance contract trust tiers overlap between allowed and blocked: {sorted(overlap)}")
        return self
