from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[4]


def test_runtime_ownership_map_documents_canonical_and_quarantined_paths() -> None:
    doc = REPO_ROOT / "pentra_core" / "docs" / "runtime_ownership_map.md"
    text = doc.read_text(encoding="utf-8")

    assert "Canonical Runtime Path" in text
    assert "`frontend`" in text
    assert "`services/api-gateway`" in text
    assert "`services/orchestrator-svc`" in text
    assert "`services/worker-svc`" in text
    assert "`packages/pentra-common`" in text
    assert "`knowledge`" in text
    assert "`services/orchestrator-svc/app/engine/_experimental`" in text


def test_canonical_runtime_code_does_not_import_quarantined_experimental_tree() -> None:
    canonical_roots = [
        REPO_ROOT / "pentra_core" / "frontend",
        REPO_ROOT / "pentra_core" / "services" / "api-gateway" / "app",
        REPO_ROOT / "pentra_core" / "services" / "orchestrator-svc" / "app",
        REPO_ROOT / "pentra_core" / "services" / "worker-svc" / "app",
        REPO_ROOT / "pentra_core" / "scripts" / "local",
    ]

    forbidden_tokens = [
        "from app.engine._experimental",
        "import app.engine._experimental",
        "from ._experimental",
        "import _experimental",
    ]

    for root in canonical_roots:
        for path in root.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            assert not any(token in text for token in forbidden_tokens), path


def test_local_runtime_entrypoints_boot_only_canonical_services() -> None:
    expected_targets = {
        "run_pentra_local.sh": [
            "pentra_core/scripts/local/run_api.sh",
            "pentra_core/scripts/local/run_orchestrator.sh",
            "pentra_core/scripts/local/run_worker.sh",
        ],
        "pentra_core/scripts/local/run_api.sh": ["pentra_core/services/api-gateway"],
        "pentra_core/scripts/local/run_orchestrator.sh": ["pentra_core/services/orchestrator-svc"],
        "pentra_core/scripts/local/run_worker.sh": ["pentra_core/services/worker-svc"],
    }

    for relative_path, expected in expected_targets.items():
        text = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
        for token in expected:
            assert token in text, relative_path
        assert "_experimental" not in text, relative_path
