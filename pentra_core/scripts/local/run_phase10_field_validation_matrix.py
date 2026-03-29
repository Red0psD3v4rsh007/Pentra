"""Fetch and persist the field-validation readiness summary outside benchmark matrices."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen


REPO_ROOT = Path(__file__).resolve().parents[3]
OUTPUT_DIR = REPO_ROOT / ".local" / "pentra" / "phase10"
SUMMARY_PATH = OUTPUT_DIR / "field_validation_summary_latest.json"
MATRIX_PATH = OUTPUT_DIR / "field_validation_matrix_latest.json"


def _api_base_url() -> str:
    return os.getenv("PENTRA_API_BASE_URL", "http://127.0.0.1:8000").rstrip("/")


def _fetch_summary(limit: int) -> dict:
    url = f"{_api_base_url()}/api/v1/scans/field-validation/summary?limit={limit}"
    request = Request(url, headers={"Accept": "application/json"})
    with urlopen(request, timeout=20) as response:  # noqa: S310 - local operator utility
        return json.loads(response.read().decode("utf-8"))


def _build_matrix(summary: dict) -> dict:
    items = list(summary.get("items") or [])
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "definition": "Authorized field-validation readiness matrix separate from benchmark matrices.",
        "total_scans": int(summary.get("total_scans", 0) or 0),
        "by_state": dict(summary.get("by_state") or {}),
        "verified_scans": sum(1 for item in items if item.get("assessment_state") == "verified"),
        "needs_evidence_scans": sum(
            1 for item in items if item.get("assessment_state") == "needs_evidence"
        ),
        "benchmark_inputs_disabled_share": round(
            (
                sum(1 for item in items if bool(item.get("benchmark_inputs_disabled_confirmed")))
                / len(items)
            ),
            3,
        )
        if items
        else 0.0,
        "items": items,
    }


def main() -> int:
    limit = int(os.getenv("PENTRA_FIELD_VALIDATION_LIMIT", "25") or 25)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    summary = _fetch_summary(limit)
    matrix = _build_matrix(summary)
    SUMMARY_PATH.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    MATRIX_PATH.write_text(json.dumps(matrix, indent=2, sort_keys=True), encoding="utf-8")
    print(SUMMARY_PATH)
    print(MATRIX_PATH)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
