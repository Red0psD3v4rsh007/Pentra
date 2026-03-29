#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[3]
_PENTRA_CORE_ROOT = _REPO_ROOT / "pentra_core"
_PENTRA_COMMON_ROOT = _PENTRA_CORE_ROOT / "packages" / "pentra-common"
_ORCHESTRATOR_ROOT = _PENTRA_CORE_ROOT / "services" / "orchestrator-svc"
for candidate in (str(_PENTRA_COMMON_ROOT), str(_ORCHESTRATOR_ROOT)):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

from pentra_common.schemas.capability import CapabilityManifest


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Report Phase 10 capability-pack source and target-profile coverage."
    )
    parser.add_argument("--output", help="Optional path to write JSON output.")
    args = parser.parse_args()

    repo_root = _PENTRA_CORE_ROOT
    worker_capabilities_dir = (
        repo_root / "services" / "worker-svc" / "app" / "engine" / "capabilities"
    )

    from app.knowledge.cheatsheet_registry import load_cheatsheet_bundle
    from app.knowledge.source_registry import load_source_registry
    from app.knowledge.target_profile_registry import load_target_profile_bundle

    registry = load_source_registry()
    cheatsheets = load_cheatsheet_bundle()
    target_profiles = load_target_profile_bundle()

    manifest_paths = sorted(worker_capabilities_dir.glob("*/capability_manifest.yaml"))
    report_items: list[dict[str, object]] = []

    for manifest_path in manifest_paths:
        payload = yaml.safe_load(manifest_path.read_text()) or {}
        manifest = CapabilityManifest.model_validate(payload)
        knowledge = manifest.knowledge_dependencies

        official_sources = []
        supplemental_sources = []
        for source_key in knowledge.source_registry_keys:
            source = registry.get_source(source_key)
            if source is None:
                continue
            item = {
                "key": source.key,
                "title": source.title,
                "trust_tier": source.trust_tier,
                "reference_urls": list(source.urls),
            }
            if source.trust_tier in {"official_public", "official_project", "runtime_truth"}:
                official_sources.append(item)
            else:
                supplemental_sources.append(item)

        report_items.append(
            {
                "pack_key": manifest.pack_key,
                "name": manifest.name,
                "manifest_path": str(manifest_path.relative_to(repo_root)),
                "target_profile_keys": list(manifest.target_profile_keys),
                "target_profiles": [
                    {
                        "key": profile.key,
                        "name": profile.name,
                    }
                    for profile in target_profiles.catalog.target_profiles
                    if profile.key in manifest.target_profile_keys
                ],
                "proof_contract_keys": list(manifest.proof_contract_keys),
                "cheatsheet_category_keys": list(knowledge.cheatsheet_category_keys),
                "cheatsheet_categories": [
                    {
                        "key": category.key,
                        "title": category.title,
                    }
                    for category in cheatsheets.catalog.categories
                    if category.key in knowledge.cheatsheet_category_keys
                ],
                "official_sources": official_sources,
                "supplemental_sources": supplemental_sources,
                "official_source_count": len(official_sources),
                "supplemental_source_count": len(supplemental_sources),
            }
        )

    output = {
        "program": "phase10_frontend_visible_real_target_readiness",
        "pack_count": len(report_items),
        "packs": report_items,
    }

    rendered = json.dumps(output, indent=2, sort_keys=True)
    if args.output:
        output_path = Path(args.output)
        output_path.write_text(rendered + "\n")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
