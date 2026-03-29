"""Target-profile catalog loader and runtime classifier for Phase 3."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from pentra_common.schemas.target_profile import (
    TargetProfileCatalog,
    TargetProfileDefinition,
    TargetProfileHypothesis,
)

from app.knowledge.cheatsheet_registry import load_cheatsheet_bundle
from app.knowledge.ontology_registry import load_ontology_bundle

_PENTRA_CORE_DIR = Path(__file__).resolve().parents[4]
_KNOWLEDGE_DIR = _PENTRA_CORE_DIR / "knowledge"
_TARGET_PROFILE_PATH = _KNOWLEDGE_DIR / "target_profiles.yaml"


@dataclass(frozen=True)
class TargetProfileRegistryBundle:
    catalog: TargetProfileCatalog

    def get_profile(self, key: str) -> TargetProfileDefinition | None:
        return next((profile for profile in self.catalog.target_profiles if profile.key == key), None)


def _load_yaml(path: Path) -> dict:
    payload = yaml.safe_load(path.read_text()) or {}
    if not isinstance(payload, dict):
        raise RuntimeError(f"Target profile file must contain a YAML object: {path}")
    return payload


def load_target_profile_catalog(path: Path | None = None) -> TargetProfileCatalog:
    return TargetProfileCatalog.model_validate(_load_yaml(path or _TARGET_PROFILE_PATH))


def load_target_profile_bundle(path: Path | None = None) -> TargetProfileRegistryBundle:
    bundle = TargetProfileRegistryBundle(catalog=load_target_profile_catalog(path))
    _validate_bundle(bundle)
    return bundle


def classify_target_profiles(
    *,
    route_groups: list[str],
    source_artifact_types: list[str],
    auth_surface_count: int,
    workflow_edge_count: int,
    capability_pack_keys: list[str],
    benchmark_target_keys: list[str] | None = None,
) -> list[TargetProfileHypothesis]:
    bundle = load_target_profile_bundle()
    route_text = " ".join(route_groups).lower()
    artifact_types = {str(item).strip().lower() for item in source_artifact_types if str(item).strip()}
    pack_keys = {str(item).strip() for item in capability_pack_keys if str(item).strip()}
    benchmark_keys = {str(item).strip() for item in benchmark_target_keys or [] if str(item).strip()}

    hypotheses: list[TargetProfileHypothesis] = []
    for profile in bundle.catalog.target_profiles:
        score = 0.0
        evidence: list[str] = []

        route_matches = [
            indicator
            for indicator in profile.route_indicators
            if indicator.strip().lower() in route_text
        ]
        if route_matches:
            score += min(0.18 * len(route_matches), 0.36)
            evidence.append(f"route indicators: {', '.join(route_matches[:3])}")

        asset_matches = [
            indicator
            for indicator in profile.asset_indicators
            if indicator.strip().lower() in artifact_types
        ]
        if asset_matches:
            score += min(0.10 * len(asset_matches), 0.20)
            evidence.append(f"artifact indicators: {', '.join(asset_matches[:3])}")

        if "multi_role" in profile.auth_expectations and auth_surface_count >= 2:
            score += 0.18
            evidence.append("multiple auth surfaces observed")
        if "privileged_routes" in profile.auth_expectations and any(
            marker in route_text for marker in ("/admin", "/manage", "/settings")
        ):
            score += 0.18
            evidence.append("privileged route indicators observed")
        if "workflow_state" in profile.auth_expectations and workflow_edge_count >= 2:
            score += 0.14
            evidence.append("workflow edges observed")
        if "multi_step_replay" in profile.auth_expectations and workflow_edge_count >= 2:
            score += 0.10
            evidence.append("multi-step workflow activity observed")
        if "api_auth" in profile.auth_expectations and any(
            marker in route_text for marker in ("/api/", "/rest/", "/graphql")
        ):
            score += 0.12
            evidence.append("API auth surface indicators observed")
        if "form_login" in profile.auth_expectations and any(
            marker in route_text for marker in ("/login", "/signin", "/register")
        ):
            score += 0.12
            evidence.append("form-login indicators observed")

        if pack_keys.intersection(profile.preferred_capability_pack_keys):
            score += 0.08
            evidence.append("preferred capability pressure present")

        if benchmark_keys.intersection(profile.benchmark_target_keys):
            score += 0.10
            evidence.append("benchmark profile alignment")

        confidence = min(score, 0.95)
        if confidence < 0.20:
            continue

        hypotheses.append(
            TargetProfileHypothesis(
                key=profile.key,
                confidence=round(confidence, 3),
                evidence=evidence,
                preferred_capability_pack_keys=list(profile.preferred_capability_pack_keys),
                planner_bias_rules=list(profile.planner_bias_rules),
                benchmark_target_keys=list(profile.benchmark_target_keys),
            )
        )

    hypotheses.sort(key=lambda item: (-item.confidence, item.key))
    return hypotheses


def _validate_bundle(bundle: TargetProfileRegistryBundle) -> None:
    ontology = load_ontology_bundle()
    cheatsheets = load_cheatsheet_bundle()

    workflow_keys = {state.key for state in ontology.workflow_states.workflow_states}
    family_keys = {family.key for family in ontology.challenge_families.families}
    known_pack_keys = {
        pack_key
        for category in cheatsheets.catalog.categories
        for pack_key in category.phase3_pack_keys
    }

    profile_keys = [profile.key for profile in bundle.catalog.target_profiles]
    if len(profile_keys) != len(set(profile_keys)):
        raise RuntimeError("Target profile catalog contains duplicate profile keys")

    for profile in bundle.catalog.target_profiles:
        if set(profile.workflow_state_keys) - workflow_keys:
            raise RuntimeError(f"Target profile '{profile.key}' references unknown workflow_state_keys")
        if set(profile.likely_challenge_family_keys) - family_keys:
            raise RuntimeError(f"Target profile '{profile.key}' references unknown likely_challenge_family_keys")
        if set(profile.preferred_capability_pack_keys) - known_pack_keys:
            raise RuntimeError(f"Target profile '{profile.key}' references unknown preferred_capability_pack_keys")
