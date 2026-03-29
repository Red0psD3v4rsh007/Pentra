"""Live local validation harness for Phase 10 P3A.1 against Juice Shop."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
from typing import Any

import httpx

REPO_ROOT = Path(__file__).resolve().parents[3]
PACKAGES_DIR = REPO_ROOT / "pentra_core" / "packages" / "pentra-common"
WORKER_APP_ROOT = REPO_ROOT / "pentra_core" / "services" / "worker-svc"
if str(PACKAGES_DIR) not in sys.path:
    sys.path.insert(0, str(PACKAGES_DIR))
if str(WORKER_APP_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKER_APP_ROOT))

from app.engine.capabilities.browser_xss import (
    summarize_browser_xss_verification_feedback,
    verify_browser_xss_canary,
)
from app.engine.web_interaction_runner import WebInteractionRunner

BENCHMARK_PATH = REPO_ROOT / "pentra_core" / "dev_targets" / "capability_benchmarks" / "juice_shop.json"
OUTPUT_PATH = REPO_ROOT / ".local" / "pentra" / "phase10" / "juice_shop_browser_xss_live_latest.json"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_benchmark_scan_config() -> tuple[dict[str, Any], dict[str, Any]]:
    payload = json.loads(BENCHMARK_PATH.read_text())
    plan = (payload.get("scan_plans") or [{}])[0]
    scan_config = dict(plan.get("config_overrides") or {})
    return payload, scan_config


async def _fetch_live_inventory(target: str) -> dict[str, Any]:
    inventory_url = target.rstrip("/") + "/api/Challenges"
    async with httpx.AsyncClient(timeout=20.0) as client:
        response = await client.get(inventory_url)
        response.raise_for_status()
        payload = response.json()
    challenges = payload.get("data") or []
    if not isinstance(challenges, list):
        challenges = []
    xss = [
        {
            "key": str(item.get("key") or ""),
            "name": str(item.get("name") or ""),
            "difficulty": item.get("difficulty"),
        }
        for item in challenges
        if isinstance(item, dict) and str(item.get("category") or "") == "XSS"
    ]
    return {
        "inventory_url": inventory_url,
        "challenge_count": len(challenges),
        "xss_challenge_count": len(xss),
        "xss_challenges": xss,
    }


def _top_candidates(discovery: dict[str, Any], limit: int) -> list[dict[str, Any]]:
    candidates = discovery.get("xss_candidates") or []
    if not isinstance(candidates, list):
        return []
    ranked = sorted(
        [item for item in candidates if isinstance(item, dict)],
        key=lambda item: (
            -int(str(item.get("proof_contract") or "").strip() == "stored_execution_xss"),
            -int(str(item.get("route_group") or "").strip() != "/"),
            -int(bool((item.get("verification_context") or {}).get("field_names"))),
            -int(item.get("confidence") or 0),
            -int(item.get("verification_confidence") or 0),
            str(item.get("route_group") or ""),
        ),
    )
    selected: list[dict[str, Any]] = []
    seen_slots: set[tuple[str, str]] = set()
    for item in ranked:
        slot = (
            str(item.get("route_group") or "").strip(),
            str(item.get("proof_contract") or "").strip(),
        )
        if slot in seen_slots:
            continue
        selected.append(item)
        seen_slots.add(slot)
        if len(selected) >= limit:
            return selected

    for item in ranked:
        if item in selected:
            continue
        selected.append(item)
        if len(selected) >= limit:
            break
    return selected[:limit]


def _top_route_assessments(discovery: dict[str, Any], limit: int = 10) -> list[dict[str, Any]]:
    capability = discovery.get("browser_xss_capability") or {}
    route_assessments = capability.get("route_assessments") or []
    if not isinstance(route_assessments, list):
        return []
    return [item for item in route_assessments if isinstance(item, dict)][:limit]


async def _verify_candidates(candidates: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    outcomes: list[dict[str, Any]] = []
    for candidate in candidates:
        request_url = str(candidate.get("request_url") or candidate.get("url") or "").strip()
        verification_context = candidate.get("verification_context") or {}
        if not request_url or not isinstance(verification_context, dict):
            continue
        route_group = str(candidate.get("route_group") or verification_context.get("route_group") or "").strip()
        proof_contract = str(candidate.get("proof_contract") or verification_context.get("proof_contract") or "").strip()
        try:
            result = await verify_browser_xss_canary(
                {
                    "request_url": request_url,
                    "verification_context": verification_context,
                }
            )
            if isinstance(result, list):
                verified = [item for item in result if isinstance(item, dict)]
                findings.extend(verified)
                outcomes.append(
                    {
                        "route_group": route_group,
                        "request_url": request_url,
                        "proof_contract": proof_contract,
                        "verification_state": "verified" if verified else "no_observation",
                        "finding_count": len(verified),
                    }
                )
        except Exception as exc:  # pragma: no cover - live runtime dependent
            outcomes.append(
                {
                    "route_group": route_group,
                    "request_url": request_url,
                    "proof_contract": proof_contract,
                    "verification_state": "error",
                    "finding_count": 0,
                    "description": str(exc),
                }
            )
            findings.append(
                {
                    "target": request_url,
                    "endpoint": request_url,
                    "verification_state": "error",
                    "title": "Browser XSS live verification error",
                    "description": str(exc),
                    "challenge_family": "xss",
                    "capability_pack": "p3a_browser_xss",
                    "verification_context": verification_context,
                }
            )
    return findings, outcomes


async def main() -> int:
    benchmark, scan_config = _load_benchmark_scan_config()
    target = str(benchmark.get("target") or "http://127.0.0.1:3001").strip()
    xss_settings = ((scan_config.get("stateful_testing") or {}).get("xss") or {})
    verify_limit = int(xss_settings.get("verify_candidate_limit") or 2)

    inventory = await _fetch_live_inventory(target)
    runner = WebInteractionRunner()
    discovery = await runner.run_discovery(base_url=target, scan_config=scan_config)
    top_candidates = _top_candidates(discovery, verify_limit)
    verified_findings, verification_outcomes = await _verify_candidates(top_candidates)
    verification_feedback = summarize_browser_xss_verification_feedback(
        candidates=top_candidates,
        verification_outcomes=verification_outcomes,
        verified_findings=verified_findings,
    )

    payload = {
        "captured_at": _utc_now(),
        "target": target,
        "benchmark_key": benchmark.get("key"),
        "benchmark_inventory_summary": benchmark.get("benchmark_inventory") or {},
        "live_inventory_summary": inventory,
        "browser_xss_capability": discovery.get("browser_xss_capability") or {},
        "summary": discovery.get("summary") or {},
        "top_route_assessments": _top_route_assessments(discovery),
        "top_candidates": top_candidates,
        "verification_outcomes": verification_outcomes,
        "verification_feedback": verification_feedback,
        "verified_findings": verified_findings,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(payload, indent=2))
    print(str(OUTPUT_PATH))
    print(
        json.dumps(
            {
                "xss_challenge_count": inventory["xss_challenge_count"],
                "candidate_count": len(discovery.get("xss_candidates") or []),
                "verified_findings": len([item for item in verified_findings if item.get("verification_state") == "verified"]),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
