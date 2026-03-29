"""Shared capability-pack discovery and execution for worker runtime."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import importlib
import inspect
from pathlib import Path
from typing import Any, Callable

import yaml

from pentra_common.schemas.capability import CapabilityManifest, CapabilityResult

_CAPABILITY_DIR = Path(__file__).resolve().parent


@dataclass(frozen=True)
class CapabilityPackRegistration:
    manifest: CapabilityManifest
    module_name: str
    builder: Callable[..., dict[str, Any]]


def _load_yaml(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text()) or {}
    if not isinstance(payload, dict):
        raise RuntimeError(f"Capability manifest must contain a YAML object: {path}")
    return payload


@lru_cache(maxsize=1)
def load_capability_registry() -> dict[str, CapabilityPackRegistration]:
    registrations: dict[str, CapabilityPackRegistration] = {}
    for manifest_path in sorted(_CAPABILITY_DIR.glob("*/capability_manifest.yaml")):
        module_dir = manifest_path.parent.name
        manifest = CapabilityManifest.model_validate(_load_yaml(manifest_path))
        module_name = f"app.engine.capabilities.{module_dir}"
        module = importlib.import_module(module_name)
        builder = getattr(module, "build_capability_pack", None)
        if not callable(builder):
            raise RuntimeError(
                f"Capability pack '{manifest.pack_key}' is missing build_capability_pack in {module_name}"
            )
        registrations[manifest.pack_key] = CapabilityPackRegistration(
            manifest=manifest,
            module_name=module_name,
            builder=builder,
        )
    return registrations


def execute_capability_packs(**context: Any) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    registry = load_capability_registry()
    for pack_key in _execution_order(registry):
        registration = registry[pack_key]
        execution_context = dict(context)
        execution_context["capability_results"] = results
        raw_result = registration.builder(**_builder_kwargs(registration.builder, execution_context))
        if isinstance(raw_result, CapabilityResult):
            result_model = raw_result
        else:
            capability_summary = {}
            candidates: list[dict[str, Any]] = []
            negative_evidence: list[dict[str, Any]] = []
            advisory_context: dict[str, Any] = {}
            if isinstance(raw_result, dict):
                capability_summary = raw_result.get("capability_summary") or {}
                candidates = list(raw_result.get("candidates") or [])
                negative_evidence = list(
                    raw_result.get("negative_evidence")
                    or capability_summary.get("negative_evidence")
                    or []
                )
                advisory_context = dict(
                    raw_result.get("advisory_context")
                    or capability_summary.get("advisory_context")
                    or capability_summary.get("ai_advisory_bundle")
                    or {}
                )
            result_model = CapabilityResult(
                pack_key=pack_key,
                capability_summary=capability_summary,
                candidates=candidates,
                negative_evidence=negative_evidence,
                advisory_context=advisory_context,
            )
        results[pack_key] = result_model.model_dump(mode="json")
    return results


def _builder_kwargs(builder: Callable[..., dict[str, Any]], context: dict[str, Any]) -> dict[str, Any]:
    signature = inspect.signature(builder)
    if any(param.kind == inspect.Parameter.VAR_KEYWORD for param in signature.parameters.values()):
        return dict(context)

    kwargs: dict[str, Any] = {}
    for name, param in signature.parameters.items():
        if param.kind not in {inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY}:
            continue
        if name in context:
            kwargs[name] = context[name]
    return kwargs


def _execution_order(registry: dict[str, CapabilityPackRegistration]) -> list[str]:
    ordered: list[str] = []
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(pack_key: str) -> None:
        if pack_key in visited:
            return
        if pack_key in visiting:
            raise RuntimeError(f"Cyclic capability pack dependency detected at '{pack_key}'")
        visiting.add(pack_key)
        registration = registry.get(pack_key)
        if registration is None:
            raise RuntimeError(f"Capability pack dependency '{pack_key}' is not registered")
        for dependency_key in registration.manifest.pack_dependency_keys:
            if dependency_key not in registry:
                raise RuntimeError(
                    f"Capability pack '{pack_key}' depends on missing pack '{dependency_key}'"
                )
            visit(dependency_key)
        visiting.remove(pack_key)
        visited.add(pack_key)
        ordered.append(pack_key)

    for pack_key in sorted(registry.keys()):
        visit(pack_key)
    return ordered
