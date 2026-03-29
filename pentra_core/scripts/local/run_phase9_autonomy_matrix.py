"""Phase 9 autonomy proof harness.

Runs a live stateful scan against the local demo target and proves whether the
planner materially changed runtime execution beyond the static template path.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import sys
import time
from typing import Any

import asyncpg
import httpx

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
    from proof_contract import new_run_id, stamp_proof_payload
else:
    from .proof_contract import new_run_id, stamp_proof_payload

ROOT_DIR = Path(__file__).resolve().parents[3]
PACKAGES_DIR = ROOT_DIR / "pentra_core" / "packages" / "pentra-common"
ORCHESTRATOR_SERVICE_DIR = ROOT_DIR / "pentra_core" / "services" / "orchestrator-svc"
if str(PACKAGES_DIR) not in sys.path:
    sys.path.insert(0, str(PACKAGES_DIR))
if str(ORCHESTRATOR_SERVICE_DIR) not in sys.path:
    sys.path.insert(0, str(ORCHESTRATOR_SERVICE_DIR))

from app.engine.dag_builder import get_tool_catalog
from pentra_common.storage.artifacts import read_json_artifact


API_BASE_URL = os.getenv("PENTRA_API_BASE_URL", "http://127.0.0.1:8000")
ORCH_BASE_URL = os.getenv("PENTRA_ORCHESTRATOR_BASE_URL", "http://127.0.0.1:8001")
DEMO_TARGET_URL = os.getenv("PENTRA_PHASE9_DEMO_URL", "http://127.0.0.1:8088")
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://pentra:pentra@localhost:5433/pentra_dev",
)
ASSET_ID = os.getenv("PENTRA_PHASE9_ASSET_ID", "55555555-5555-5555-5555-555555555555")
TIMEOUT_SECONDS = int(os.getenv("PENTRA_PHASE9_TIMEOUT_SECONDS", "300"))
POLL_INTERVAL_SECONDS = float(os.getenv("PENTRA_PHASE9_POLL_INTERVAL_SECONDS", "3"))
EXISTING_SCAN_ID = os.getenv("PENTRA_PHASE9_EXISTING_SCAN_ID", "").strip()
ALLOW_NONTERMINAL_PROOF = os.getenv(
    "PENTRA_PHASE9_ALLOW_NONTERMINAL_PROOF", "false"
).strip().lower() in {"1", "true", "yes", "on"}

OUTPUT_DIR = ROOT_DIR / ".local" / "pentra" / "phase9"
OUTPUT_PATH = OUTPUT_DIR / "autonomy_matrix_latest.json"
PLANNER_OUTPUT_PATH = OUTPUT_DIR / "planner_effect_latest.json"
PROOF_RUN_ID = new_run_id()

STATEFUL_FULL_CONFIG: dict[str, Any] = {
    "profile_id": "external_web_api_v1",
    "stateful_testing": {
        "enabled": True,
        "crawl_max_depth": 2,
        "max_pages": 20,
        "max_replays": 4,
        "seed_paths": ["/", "/login", "/portal/dashboard", "/portal/checkout/cart"],
        "default_csrf_token": "demo-csrf",
        "auth": {
            "login_page_path": "/login",
            "username_field": "username",
            "password_field": "password",
            "success_path_contains": "/portal/dashboard",
            "credentials": [
                {"label": "john", "username": "john", "password": "test", "role": "user"},
                {"label": "admin", "username": "admin", "password": "admin123", "role": "admin"},
            ],
        },
    },
}


def _sync_db_url(database_url: str) -> str:
    return database_url.replace("postgresql+asyncpg://", "postgresql://", 1)


async def _assert_http_ok(client: httpx.AsyncClient, url: str, label: str) -> None:
    response = await client.get(url)
    response.raise_for_status()
    print(f"[ok] {label}: {response.status_code}")


async def _create_scan(client: httpx.AsyncClient) -> dict[str, Any]:
    response = await client.post(
        f"{API_BASE_URL}/api/v1/scans",
        json={
            "asset_id": ASSET_ID,
            "scan_type": "full",
            "priority": "normal",
            "config": STATEFUL_FULL_CONFIG,
        },
    )
    response.raise_for_status()
    payload = response.json()
    print(f"[ok] phase9 autonomy scan created: {payload['id']}")
    return payload


def _target_model_pressure_detected(target_model: Any) -> bool:
    target_model_focus = target_model.get("planner_focus") if isinstance(target_model, dict) else []
    return any(
        isinstance(item, dict) and int(item.get("focus_score") or 0) > 0
        for item in target_model_focus
    )


def _r3_proof_detected(
    *,
    terminal: dict[str, Any],
    target_model: Any,
    db_metrics: dict[str, Any],
    planner_artifacts: dict[str, Any],
    allow_nonterminal: bool,
) -> bool:
    status = str(terminal.get("status") or "")
    if status not in {"completed", "failed", "rejected"} and not allow_nonterminal:
        return False
    if planner_artifacts["total"] <= 0:
        return False
    if not _target_model_pressure_detected(target_model):
        return False
    return (
        db_metrics["planner_action_node_count"] > 0
        or db_metrics["skipped_node_count"] > 0
        or any(entry.get("planner_effect_detected") for entry in planner_artifacts["entries"])
    )


async def _poll_scan(
    client: httpx.AsyncClient,
    scan_id: str,
    *,
    allow_nonterminal_proof: bool = False,
) -> dict[str, Any]:
    deadline = time.monotonic() + TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        response = await client.get(f"{API_BASE_URL}/api/v1/scans/{scan_id}")
        response.raise_for_status()
        payload = response.json()
        print(f"[wait] scan={scan_id} status={payload['status']} progress={payload['progress']}%")
        if payload["status"] in {"completed", "failed", "rejected"}:
            return payload
        if allow_nonterminal_proof:
            target_model = await _fetch_json(client, f"/api/v1/scans/{scan_id}/target-model")
            db_metrics = await _collect_db_metrics(scan_id)
            planner_artifacts = await _collect_planner_artifacts(scan_id)
            if _r3_proof_detected(
                terminal=payload,
                target_model=target_model,
                db_metrics=db_metrics,
                planner_artifacts=planner_artifacts,
                allow_nonterminal=True,
            ):
                print(
                    "[ok] live R3 proof detected before terminal scan completion; "
                    "stamping proof from current scan state"
                )
                return payload
        await asyncio.sleep(POLL_INTERVAL_SECONDS)
    raise RuntimeError(f"Phase 9 autonomy scan {scan_id} did not finish within {TIMEOUT_SECONDS}s")


async def _fetch_json(client: httpx.AsyncClient, path: str) -> Any:
    response = await client.get(f"{API_BASE_URL}{path}")
    response.raise_for_status()
    return response.json()


async def _collect_db_metrics(scan_id: str) -> dict[str, Any]:
    conn = await asyncpg.connect(_sync_db_url(DATABASE_URL))
    try:
        row = await conn.fetchrow(
            """
            SELECT
                d.id AS dag_id,
                d.scan_type,
                d.asset_type,
                COUNT(n.id) AS total_nodes,
                COUNT(*) FILTER (WHERE n.is_dynamic = true) AS dynamic_node_count,
                COUNT(*) FILTER (
                    WHERE n.is_dynamic = true
                      AND COALESCE((n.config->>'ai_strategy_generated')::boolean, false) = true
                ) AS ai_strategy_generated_node_count,
                ARRAY_REMOVE(
                    ARRAY_AGG(DISTINCT n.tool) FILTER (
                        WHERE n.is_dynamic = true
                          AND COALESCE((n.config->>'ai_strategy_generated')::boolean, false) = true
                    ),
                    NULL
                ) AS ai_strategy_generated_tools,
                COUNT(*) FILTER (WHERE n.status = 'skipped') AS skipped_node_count,
                ARRAY_REMOVE(
                    ARRAY_AGG(DISTINCT n.tool) FILTER (WHERE n.status = 'skipped'),
                    NULL
                ) AS skipped_tools,
                COUNT(*) FILTER (
                    WHERE n.is_dynamic = true
                      AND COALESCE((n.config->>'ai_strategy_generated')::boolean, false) = true
                      AND (n.config ? 'planner_action_type')
                ) AS planner_action_node_count,
                ARRAY_REMOVE(
                    ARRAY_AGG(DISTINCT n.tool) FILTER (
                        WHERE n.is_dynamic = true
                          AND COALESCE((n.config->>'ai_strategy_generated')::boolean, false) = true
                          AND (n.config ? 'planner_action_type')
                    ),
                    NULL
                ) AS planner_action_tools,
                ARRAY_REMOVE(
                    ARRAY_AGG(DISTINCT n.config->>'planner_action_type') FILTER (
                        WHERE n.is_dynamic = true
                          AND COALESCE((n.config->>'ai_strategy_generated')::boolean, false) = true
                          AND (n.config ? 'planner_action_type')
                    ),
                    NULL
                ) AS planner_action_types
            FROM scan_dags d
            JOIN scan_nodes n ON n.dag_id = d.id
            WHERE d.scan_id = $1
            GROUP BY d.id, d.scan_type, d.asset_type
            """,
            scan_id,
        )
        if row is None:
            raise RuntimeError(f"No DAG metrics found for scan {scan_id}")

        template_catalog = get_tool_catalog(
            str(row["scan_type"]),
            str(row["asset_type"]),
            STATEFUL_FULL_CONFIG,
        )
        ai_tools = sorted(str(item) for item in (row["ai_strategy_generated_tools"] or []))
        skipped_tools = sorted(str(item) for item in (row["skipped_tools"] or []))
        planner_action_tools = sorted(str(item) for item in (row["planner_action_tools"] or []))
        planner_action_types = sorted(
            str(item) for item in (row["planner_action_types"] or [])
        )
        return {
            "dag_id": str(row["dag_id"]),
            "scan_type": str(row["scan_type"]),
            "asset_type": str(row["asset_type"]),
            "template_node_count": len(template_catalog),
            "template_tools": sorted(tool.name for tool in template_catalog),
            "total_node_count": int(row["total_nodes"] or 0),
            "dynamic_node_count": int(row["dynamic_node_count"] or 0),
            "ai_strategy_generated_node_count": int(row["ai_strategy_generated_node_count"] or 0),
            "ai_strategy_generated_tools": ai_tools,
            "skipped_node_count": int(row["skipped_node_count"] or 0),
            "skipped_tools": skipped_tools,
            "planner_action_node_count": int(row["planner_action_node_count"] or 0),
            "planner_action_tools": planner_action_tools,
            "planner_action_types": planner_action_types,
        }
    finally:
        await conn.close()


async def _collect_planner_artifacts(scan_id: str) -> dict[str, Any]:
    conn = await asyncpg.connect(_sync_db_url(DATABASE_URL))
    try:
        rows = await conn.fetch(
            """
            SELECT id, storage_ref, metadata, created_at
            FROM scan_artifacts
            WHERE scan_id = $1
              AND artifact_type = 'planner_effect'
            ORDER BY created_at ASC
            """,
            scan_id,
        )
        entries: list[dict[str, Any]] = []
        all_action_types: set[str] = set()
        all_route_groups: set[str] = set()
        all_suppressed_tools: set[str] = set()
        all_followup_tools: set[str] = set()
        payload_present_count = 0
        for row in rows:
            metadata_raw = row["metadata"]
            if isinstance(metadata_raw, dict):
                metadata = metadata_raw
            elif isinstance(metadata_raw, str):
                try:
                    parsed_metadata = json.loads(metadata_raw)
                except json.JSONDecodeError:
                    parsed_metadata = {}
                metadata = parsed_metadata if isinstance(parsed_metadata, dict) else {}
            else:
                metadata = {}
            payload = read_json_artifact(str(row["storage_ref"]))
            payload_present = isinstance(payload, dict)
            if payload_present:
                payload_present_count += 1
            strategic_plan = (
                payload.get("strategic_plan")
                if payload_present
                else {}
            )
            if not isinstance(strategic_plan, dict):
                strategic_plan = {}
            mutation_result = (
                payload.get("mutation_result")
                if payload_present
                else {}
            )
            if not isinstance(mutation_result, dict):
                mutation_result = {}
            runtime_effect = (
                payload.get("runtime_effect")
                if payload_present
                else {}
            )
            if not isinstance(runtime_effect, dict):
                runtime_effect = {}
            target_model_summary = (
                payload.get("target_model_summary")
                if payload_present
                else {}
            )
            if not isinstance(target_model_summary, dict):
                target_model_summary = {}
            top_focus = (
                target_model_summary.get("top_focus")
                if isinstance(target_model_summary.get("top_focus"), dict)
                else {}
            )
            summary = metadata.get("summary") if isinstance(metadata.get("summary"), dict) else {}
            planner_actions = strategic_plan.get("actions", [])
            action_types = sorted(
                {
                    str(item.get("action_type"))
                    for item in planner_actions
                    if isinstance(item, dict) and str(item.get("action_type") or "").strip()
                }
            )
            route_groups = sorted(
                {
                    str(item.get("route_group"))
                    for item in planner_actions
                    if isinstance(item, dict) and str(item.get("route_group") or "").strip()
                }
            )
            suppressed_tools = sorted(
                {
                    str(item)
                    for item in (
                        metadata.get("suppressed_tool_ids")
                        or mutation_result.get("suppressed_tool_ids")
                        or []
                    )
                    if str(item).strip()
                }
            )
            followup_tools = sorted(
                {
                    str(item)
                    for item in (
                        metadata.get("followup_dispatched_tools")
                        or runtime_effect.get("planner_followup_dispatched_tools")
                        or mutation_result.get("dispatched_tools")
                        or []
                    )
                    if str(item).strip()
                }
            )
            planner_decision = metadata.get("planner_decision") or strategic_plan.get("decision")
            mutation_kind = metadata.get("mutation_kind") or mutation_result.get("mutation_kind")
            planner_status = metadata.get("planner_status") or mutation_result.get("status")
            target_model_pressure_detected = bool(
                metadata.get("target_model_pressure_detected")
                or target_model_summary.get("has_meaningful_pressure")
            )
            planner_effect_detected = bool(
                metadata.get("planner_effect_detected")
                or runtime_effect.get("planner_effect_detected")
            )
            top_focus_route_group = metadata.get("top_focus_route_group") or top_focus.get("route_group")
            top_focus_score = int(
                metadata.get("top_focus_score")
                or top_focus.get("focus_score")
                or 0
            )
            if not summary:
                summary = {
                    "decision": planner_decision,
                    "mutation_kind": mutation_kind,
                    "planner_action_count": len(action_types),
                    "suppressed_tools": suppressed_tools,
                    "followup_tools": followup_tools,
                    "top_focus_route_group": top_focus_route_group,
                    "effect_detected": planner_effect_detected,
                }
            all_action_types.update(action_types)
            all_route_groups.update(route_groups)
            all_suppressed_tools.update(suppressed_tools)
            all_followup_tools.update(followup_tools)
            entries.append(
                {
                    "id": str(row["id"]),
                    "created_at": str(row["created_at"]),
                    "phase_completed": metadata.get("phase_completed"),
                    "storage_ref": str(row["storage_ref"]),
                    "payload_present": payload_present,
                    "planner_decision": planner_decision,
                    "mutation_kind": mutation_kind,
                    "planner_status": planner_status,
                    "planner_action_types": action_types,
                    "route_groups": route_groups,
                    "suppressed_tool_ids": suppressed_tools,
                    "followup_dispatched_tools": followup_tools,
                    "top_focus_route_group": top_focus_route_group,
                    "top_focus_score": top_focus_score,
                    "target_model_pressure_detected": target_model_pressure_detected,
                    "planner_effect_detected": planner_effect_detected,
                    "summary": summary,
                }
            )
        return {
            "total": len(entries),
            "payload_present_count": payload_present_count,
            "payload_missing_count": len(entries) - payload_present_count,
            "entries": entries,
            "planner_action_types": sorted(all_action_types),
            "route_groups": sorted(all_route_groups),
            "suppressed_tool_ids": sorted(all_suppressed_tools),
            "followup_dispatched_tools": sorted(all_followup_tools),
        }
    finally:
        await conn.close()


async def run_autonomy_matrix() -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=20.0, trust_env=False) as client:
        await _assert_http_ok(client, f"{API_BASE_URL}/health", "api health")
        await _assert_http_ok(client, f"{ORCH_BASE_URL}/health", "orchestrator health")
        await _assert_http_ok(client, f"{DEMO_TARGET_URL}/healthz", "demo target health")

        if EXISTING_SCAN_ID:
            scan_id = EXISTING_SCAN_ID
            terminal = await _fetch_json(client, f"/api/v1/scans/{scan_id}")
            status = str(terminal.get("status") or "")
            print(f"[reuse] phase9 autonomy scan: {scan_id} status={status}")
            if status not in {"completed", "failed", "rejected"}:
                terminal = await _poll_scan(
                    client,
                    scan_id,
                    allow_nonterminal_proof=ALLOW_NONTERMINAL_PROOF,
                )
        else:
            created = await _create_scan(client)
            scan_id = str(created["id"])
            terminal = await _poll_scan(
                client,
                scan_id,
                allow_nonterminal_proof=ALLOW_NONTERMINAL_PROOF,
            )
        strategy_log = await _fetch_json(client, f"/api/v1/scans/{scan_id}/strategy-log")
        jobs = await _fetch_json(client, f"/api/v1/scans/{scan_id}/jobs")
        target_model = await _fetch_json(client, f"/api/v1/scans/{scan_id}/target-model")
        db_metrics = await _collect_db_metrics(scan_id)
        planner_artifacts = await _collect_planner_artifacts(scan_id)

    p92_planner_effect_detected = (
        str(terminal.get("status")) == "completed"
        and db_metrics["ai_strategy_generated_node_count"] > 0
        and db_metrics["total_node_count"] > db_metrics["template_node_count"]
    )
    target_model_focus = target_model.get("planner_focus") if isinstance(target_model, dict) else []
    target_model_pressure_detected = _target_model_pressure_detected(target_model)
    r3_planner_effect_detected = _r3_proof_detected(
        terminal=terminal,
        target_model=target_model,
        db_metrics=db_metrics,
        planner_artifacts=planner_artifacts,
        allow_nonterminal=ALLOW_NONTERMINAL_PROOF,
    )

    payload = {
        "status": "passed" if r3_planner_effect_detected else "failed",
        "phase": "R3",
        "allow_nonterminal_proof": ALLOW_NONTERMINAL_PROOF,
        "api_base_url": API_BASE_URL,
        "orchestrator_base_url": ORCH_BASE_URL,
        "demo_target_url": DEMO_TARGET_URL,
        "scan": {
            "id": str(terminal.get("id") or scan_id),
            "source": "reused" if EXISTING_SCAN_ID else "fresh_run",
            "status": str(terminal.get("status") or "unknown"),
            "progress": int(terminal.get("progress") or 0),
            "created_at": terminal.get("created_at"),
            "started_at": terminal.get("started_at"),
            "completed_at": terminal.get("completed_at"),
        },
        "p92_baseline_autonomy": {
            "detected": p92_planner_effect_detected,
            "reason": (
                "dynamic ai_strategy_generated nodes expanded the DAG beyond the static template path"
                if p92_planner_effect_detected
                else "no measurable planner-driven DAG expansion was observed"
            ),
            **db_metrics,
        },
        "r3_planner_effect": {
            "detected": r3_planner_effect_detected,
            "reason": (
                "planner-effect artifacts captured target-model-driven actions with suppression and/or bounded follow-up dispatch"
                if r3_planner_effect_detected
                else "no durable target-model-driven planner effect was captured in this live run"
            ),
            "planner_artifact_count": planner_artifacts["total"],
            "planner_action_types": planner_artifacts["planner_action_types"],
            "planner_route_groups": planner_artifacts["route_groups"],
            "suppressed_tool_ids": sorted(
                set(planner_artifacts["suppressed_tool_ids"]) | set(db_metrics["skipped_tools"])
            ),
            "followup_dispatched_tools": sorted(
                set(planner_artifacts["followup_dispatched_tools"]) | set(db_metrics["planner_action_tools"])
            ),
            "target_model_pressure_detected": target_model_pressure_detected,
            "target_model_focus": target_model_focus,
            "planner_action_node_count": db_metrics["planner_action_node_count"],
            "planner_action_tools": db_metrics["planner_action_tools"],
            "skipped_node_count": db_metrics["skipped_node_count"],
            "skipped_tools": db_metrics["skipped_tools"],
        },
        "target_model": {
            "overview": target_model.get("overview") if isinstance(target_model, dict) else {},
            "planner_focus": target_model_focus,
        },
        "planner_artifacts": planner_artifacts,
        "strategy_log": {
            "total_entries": int(strategy_log.get("total") or 0),
            "entries": strategy_log.get("entries") or [],
        },
        "jobs": {
            "total": len(jobs) if isinstance(jobs, list) else 0,
            "tools": sorted(
                {
                    str(item.get("tool"))
                    for item in jobs
                    if isinstance(item, dict) and str(item.get("tool") or "").strip()
                }
            ) if isinstance(jobs, list) else [],
        },
    }

    stamped = stamp_proof_payload(
        payload,
        artifact_kind="autonomy_matrix",
        phase="R3",
        script_path="pentra_core/scripts/local/run_phase9_autonomy_matrix.py",
        root_dir=ROOT_DIR,
        environment_context={
            "api_base_url": API_BASE_URL,
            "orchestrator_base_url": ORCH_BASE_URL,
            "demo_target_url": DEMO_TARGET_URL,
            "asset_id": ASSET_ID,
            "existing_scan_id": EXISTING_SCAN_ID or None,
            "allow_nonterminal_proof": ALLOW_NONTERMINAL_PROOF,
        },
        run_id=PROOF_RUN_ID,
    )
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(stamped, indent=2, sort_keys=True))
    PLANNER_OUTPUT_PATH.write_text(json.dumps(stamped, indent=2, sort_keys=True))
    return stamped


def main() -> None:
    payload = asyncio.run(run_autonomy_matrix())
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
