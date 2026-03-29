"""Generate a runtime ownership map for Pentra's canonical product path."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
DOC_PATH = REPO_ROOT / "pentra_core" / "docs" / "runtime_ownership_map.md"

CANONICAL_RUNTIME = [
    ("frontend", "Operator UI, runtime diagnostics, planner visibility, and scan launch."),
    ("services/api-gateway", "Canonical public API, websocket bridge, auth, and reporting surface."),
    ("services/orchestrator-svc", "Planner, capability advisory execution, DAG control, and runtime coordination."),
    ("services/worker-svc", "Live tool execution, capability-pack runtime, crawling, and verification."),
    ("packages/pentra-common", "Shared schemas, config, storage, auth, profiles, and provider routing."),
    ("knowledge", "Pinned methodology, corpus, ontology, target profiles, and capability graphs."),
    ("scripts/local", "Supported local boot and validation entrypoints for the canonical stack."),
    ("run_pentra_local.sh", "Top-level local stack launcher for the canonical stack."),
]

QUARANTINED_TREES = [
    (
        "services/orchestrator-svc/app/engine/_experimental",
        "Quarantined shadow engine tree. Not supported for production/runtime imports.",
    ),
]

ENTRYPOINTS = [
    ("run_pentra_local.sh", "Boots the canonical local product stack."),
    ("pentra_core/scripts/local/run_api.sh", "Starts api-gateway."),
    ("pentra_core/scripts/local/run_orchestrator.sh", "Starts orchestrator-svc."),
    ("pentra_core/scripts/local/run_worker.sh", "Starts worker-svc."),
]


def build_markdown() -> str:
    generated_at = datetime.now(timezone.utc).isoformat()
    lines = [
        "# Runtime Ownership Map",
        "",
        f"Generated: {generated_at}",
        "",
        "## Canonical Runtime Path",
        "",
        "Only these paths are considered product runtime truth:",
        "",
    ]
    for path, description in CANONICAL_RUNTIME:
        lines.append(f"- `{path}`: {description}")

    lines.extend(
        [
            "",
            "## Quarantined Trees",
            "",
            "These paths remain in-repo for reference only and must not be imported by canonical runtime code:",
            "",
        ]
    )
    for path, description in QUARANTINED_TREES:
        lines.append(f"- `{path}`: {description}")

    lines.extend(
        [
            "",
            "## Canonical Entrypoints",
            "",
        ]
    )
    for path, description in ENTRYPOINTS:
        lines.append(f"- `{path}`: {description}")

    lines.extend(
        [
            "",
            "## Enforcement Notes",
            "",
            "- Canonical runtime code must not import `app.engine._experimental`.",
            "- Local startup scripts must only boot the canonical services listed above.",
            "- Benchmark validation is separate from authorized field-validation operation.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    DOC_PATH.parent.mkdir(parents=True, exist_ok=True)
    DOC_PATH.write_text(build_markdown(), encoding="utf-8")
    print(DOC_PATH)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
