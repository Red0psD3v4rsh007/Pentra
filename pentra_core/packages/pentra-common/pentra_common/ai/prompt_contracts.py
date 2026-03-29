"""Prompt contract metadata shared by Pentra AI services."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PromptContract:
    """Describes one structured AI prompt contract."""

    contract_id: str
    prompt_version: str
    task_type: str
    response_format: str = "json_object"


def advisory_prompt_contract(advisory_mode: str) -> PromptContract:
    return PromptContract(
        contract_id="pentra.ai.advisory",
        prompt_version=f"phase5.advisory.v3.{advisory_mode}",
        task_type="advisory_reasoning",
    )


def strategy_prompt_contract() -> PromptContract:
    return PromptContract(
        contract_id="pentra.ai.strategy",
        prompt_version="phase9.strategy.v1",
        task_type="phase_strategy",
    )


def build_json_user_prompt(
    contract: PromptContract,
    *,
    context: dict[str, Any],
    preamble: str,
) -> str:
    return (
        f"{preamble}\n\n"
        f"Contract ID: {contract.contract_id}\n"
        f"Prompt version: {contract.prompt_version}\n"
        f"Expected response format: {contract.response_format}\n"
        f"Context JSON:\n{json.dumps(context, indent=2, sort_keys=True, default=str)}"
    )
