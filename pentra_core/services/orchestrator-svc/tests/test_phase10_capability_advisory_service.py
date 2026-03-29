from __future__ import annotations

import asyncio
import os
import sys
import uuid


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def test_phase10_capability_advisory_service_falls_back_to_heuristics() -> None:
    from pentra_common.config.settings import Settings
    from pentra_common.storage.artifacts import write_json_artifact

    from app.engine.capability_advisory_service import CapabilityAdvisoryService

    storage_ref = f"artifacts/test/capability_advisory/{uuid.uuid4()}.json"
    write_json_artifact(
        storage_ref,
        {
            "artifact_type": "endpoints",
            "browser_xss_capability": {
                "pack_key": "p3a_browser_xss",
                "target_profile_keys": ["spa_rest_api"],
                "benchmark_target_keys": ["juice_shop_local"],
                "advisory_context": {
                    "enabled": True,
                    "advisory_mode": "browser_xss_route_focus",
                    "prompt_contract": {
                        "contract_id": "pentra.ai.advisory",
                        "prompt_version": "phase5.advisory.v3.browser_xss_route_focus",
                    },
                    "focus_routes": [
                        {
                            "route_group": "/#/search",
                            "advisory_priority": 77,
                            "parameter_hypotheses": ["q", "search"],
                            "evidence_gaps": ["verification"],
                            "reasoning": "Route exposes source and sink pressure.",
                        }
                    ],
                    "evidence_gap_summary": ["verification"],
                    "user_prompt": "Review the browser XSS focus routes.",
                },
            },
        },
    )
    service = CapabilityAdvisoryService(
        settings=Settings(
            anthropic_api_key="",
            openai_api_key="",
            groq_api_key="",
            gemini_api_key="",
            ollama_default_model="",
            ollama_deep_model="",
        )
    )

    responses = asyncio.run(
        service.recommend_from_artifact_refs(
            artifact_refs=[
                {
                    "pack_key": "p3a_browser_xss",
                    "storage_ref": storage_ref,
                    "advisory_mode": "browser_xss_route_focus",
                }
            ],
            target_model_summary={
                "top_focus": {"route_group": "/#/search"},
                "target_profile_hypotheses": [{"key": "spa_rest_api", "confidence": 0.7, "evidence": ["hash route indicators observed"]}],
                "capability_pressures": [{"pack_key": "p3a_browser_xss", "pressure_score": 44}],
            },
        )
    )

    assert len(responses) == 1
    assert responses[0].pack_key == "p3a_browser_xss"
    assert responses[0].provider == "heuristic"
    assert responses[0].fallback_used is True
    assert responses[0].focus_items
    assert "verification" in responses[0].evidence_gap_priorities


def test_phase10_capability_advisory_service_limits_runtime_chain_to_primary_and_fallback() -> None:
    from pentra_common.config.settings import Settings

    from app.engine.capability_advisory_service import CapabilityAdvisoryService

    service = CapabilityAdvisoryService(
        settings=Settings(
            ai_reasoning_primary_provider="openai",
            ai_reasoning_fallback_provider="groq",
            ai_reasoning_additional_providers="ollama,gemini",
            openai_api_key="openai-key",
            openai_default_model="gpt-4o-mini",
            openai_base_url="https://api.openai.com/v1",
            groq_api_key="groq-key",
            groq_default_model="llama-3.3-70b-versatile",
            groq_base_url="https://api.groq.com/openai/v1",
            ollama_default_model="qwen2.5:14b-instruct",
            ollama_base_url="http://127.0.0.1:11434/v1",
            gemini_api_key="gemini-key",
            gemini_default_model="gemini-2.5-flash",
            gemini_base_url="https://generativelanguage.googleapis.com/v1beta/openai",
        )
    )

    configs = service._provider_configs()

    assert [config.provider for config in configs] == ["openai", "groq"]
