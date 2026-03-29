"""Shared execution-truth helpers for tool/runtime and policy classification."""

from __future__ import annotations

from typing import Any, Final, Literal


ExecutionClass = Literal["external_tool", "pentra_native"]
ToolPolicyState = Literal[
    "auto_live",
    "approval_required",
    "approved",
    "blocked",
    "derived",
    "unsupported",
]

PENTRA_NATIVE_TOOL_IDS: Final[frozenset[str]] = frozenset(
    {
        "scope_check",
        "custom_poc",
        "web_interact",
    }
)
DERIVED_TOOL_IDS: Final[frozenset[str]] = frozenset({"ai_triage", "report_gen"})
UNSUPPORTED_TOOL_IDS: Final[frozenset[str]] = frozenset()


def _normalize_tool_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    items: list[str] = []
    seen: set[str] = set()
    for item in value:
        normalized = str(item or "").strip()
        lowered = normalized.lower()
        if not normalized or lowered in seen:
            continue
        seen.add(lowered)
        items.append(normalized)
    return items


def classify_tool_execution(tool_name: str | None) -> ExecutionClass:
    normalized = str(tool_name or "").strip().lower()
    if normalized in PENTRA_NATIVE_TOOL_IDS:
        return "pentra_native"
    return "external_tool"


def classify_tool_policy_state(
    *,
    tool_name: str | None,
    execution_contract: dict[str, Any] | None = None,
    scan_config: dict[str, Any] | None = None,
    execution_provenance: str | None = None,
    execution_reason: str | None = None,
) -> ToolPolicyState:
    normalized_tool = str(tool_name or "").strip().lower()
    if normalized_tool in DERIVED_TOOL_IDS:
        return "derived"
    if normalized_tool in UNSUPPORTED_TOOL_IDS:
        return "unsupported"

    contract = execution_contract if isinstance(execution_contract, dict) else {}
    config = scan_config if isinstance(scan_config, dict) else {}
    execution = config.get("execution") if isinstance(config.get("execution"), dict) else {}

    live_tools = {
        item.lower()
        for item in _normalize_tool_list(
            contract.get("live_tools") or execution.get("allowed_live_tools")
        )
    }
    approval_required_tools = {
        item.lower()
        for item in _normalize_tool_list(
            contract.get("approval_required_tools") or execution.get("approval_required_tools")
        )
    }
    approved_live_tools = {
        item.lower() for item in _normalize_tool_list(config.get("approved_live_tools"))
    }

    normalized_reason = str(execution_reason or "").strip().lower()
    normalized_provenance = str(execution_provenance or "").strip().lower()

    if normalized_provenance == "blocked" and normalized_reason not in {"approval_required"}:
        return "blocked"
    if normalized_reason in {
        "target_policy_blocked",
        "not_supported",
        "gated_by_evidence",
        "gated_by_prerequisite",
        "out_of_scope",
    }:
        return "blocked"
    if normalized_tool in approval_required_tools:
        return "approved" if normalized_tool in approved_live_tools else "approval_required"
    if normalized_tool in live_tools:
        return "auto_live"
    if normalized_provenance == "blocked":
        return "blocked"
    return "auto_live"
