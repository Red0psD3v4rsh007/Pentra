"""Phase 6 live scenario matrix runner.

Executes the supported local safe-live scenarios against the seeded demo asset,
captures scan/job/finding/report evidence, and writes a proof artifact into the
repo workspace.

The current local supported matrix is intentionally limited to the product-safe
profile catalog advertised by ``/api/v1/scan-profiles``:
  - recon
  - vuln
  - full

Standalone ``exploit_verify`` exists at the schema layer, but it is not part of
the advertised product-safe profile catalog and is omitted from this live matrix.
"""

from __future__ import annotations

import asyncio
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import sys
import time
from typing import Any
from urllib.parse import quote

import httpx

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from pentra_core.scripts.local.proof_contract import new_run_id, stamp_proof_payload
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(line_buffering=True)
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(line_buffering=True)

API_BASE_URL = os.getenv("PENTRA_API_BASE_URL", "http://127.0.0.1:8000")
ORCH_BASE_URL = os.getenv("PENTRA_ORCHESTRATOR_BASE_URL", "http://127.0.0.1:8001")
DEMO_TARGET_URL = os.getenv("PENTRA_PHASE6_DEMO_URL", "http://127.0.0.1:8088")
ASSET_ID = os.getenv("PENTRA_PHASE6_ASSET_ID", "55555555-5555-5555-5555-555555555555")
POLL_INTERVAL_SECONDS = float(os.getenv("PENTRA_PHASE6_POLL_INTERVAL_SECONDS", "3"))
DEFAULT_TIMEOUT_SECONDS = int(os.getenv("PENTRA_PHASE6_TIMEOUT_SECONDS", "360"))
ROOT_DIR = Path(__file__).resolve().parents[3]
OUTPUT_DIR = ROOT_DIR / ".local" / "pentra" / "phase6"
OUTPUT_PATH = OUTPUT_DIR / "scenario_matrix_latest.json"
PROOF_RUN_ID = new_run_id()


@dataclass(frozen=True)
class ScenarioDefinition:
    key: str
    label: str
    scan_type: str
    config: dict[str, Any]
    timeout_seconds: int
    required_completed_tools: tuple[str, ...]
    required_present_tools: tuple[str, ...] = ()
    required_dynamic_tools: tuple[str, ...] = ()
    min_findings: int = 0
    min_artifacts: int = 0
    require_evidence: bool = False
    require_report: bool = False
    require_attack_graph: bool = False
    min_verified_findings: int = 0
    require_stateful_context: bool = False
    required_stateful_finding_types: tuple[str, ...] = ()


SCENARIOS: tuple[ScenarioDefinition, ...] = (
    ScenarioDefinition(
        key="recon_web_api_v1",
        label="Recon / external_web_api_v1",
        scan_type="recon",
        config={"profile_id": "external_web_api_v1"},
        timeout_seconds=180,
        required_completed_tools=("scope_check", "httpx_probe"),
        min_artifacts=2,
    ),
    ScenarioDefinition(
        key="vuln_web_api_v1",
        label="Vuln / external_web_api_v1",
        scan_type="vuln",
        config={"profile_id": "external_web_api_v1"},
        timeout_seconds=240,
        required_completed_tools=(
            "scope_check",
            "httpx_probe",
            "web_interact",
            "ffuf",
            "nuclei",
            "sqlmap",
            "nikto",
        ),
        required_present_tools=("ai_triage", "report_gen"),
        min_findings=1,
        min_artifacts=5,
        require_evidence=True,
        require_report=True,
    ),
    ScenarioDefinition(
        key="full_safe_verify_web_api_v1",
        label="Full Safe Verify / external_web_api_v1",
        scan_type="full",
        config={"profile_id": "external_web_api_v1"},
        timeout_seconds=300,
        required_completed_tools=(
            "scope_check",
            "httpx_probe",
            "web_interact",
            "ffuf",
            "nuclei",
            "sqlmap",
            "nikto",
        ),
        required_present_tools=("ai_triage", "report_gen"),
        required_dynamic_tools=("sqlmap_verify", "custom_poc"),
        min_findings=1,
        min_artifacts=6,
        require_evidence=True,
        require_report=True,
        require_attack_graph=True,
        min_verified_findings=1,
    ),
    ScenarioDefinition(
        key="full_stateful_web_api_v1",
        label="Full Stateful / external_web_api_v1",
        scan_type="full",
        config={
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
        },
        timeout_seconds=DEFAULT_TIMEOUT_SECONDS,
        required_completed_tools=(
            "scope_check",
            "httpx_probe",
            "web_interact",
            "ffuf",
            "nuclei",
            "sqlmap",
            "nikto",
        ),
        required_present_tools=("ai_triage", "report_gen"),
        required_dynamic_tools=("custom_poc",),
        min_findings=1,
        min_artifacts=6,
        require_evidence=True,
        require_report=True,
        require_attack_graph=True,
        require_stateful_context=True,
        required_stateful_finding_types=(
            "workflow_bypass",
            "auth_bypass",
            "idor",
            "privilege_escalation",
        ),
    ),
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _unwrap_items(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        items = payload.get("items")
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
    return []


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def _iso_duration_seconds(started_at: str | None, completed_at: str | None) -> float | None:
    start_dt = _parse_datetime(started_at)
    end_dt = _parse_datetime(completed_at)
    if start_dt is None or end_dt is None:
        return None
    return round((end_dt - start_dt).total_seconds(), 2)


def _execution_counts(items: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts = Counter(str(item.get(key) or "unknown") for item in items)
    return dict(sorted(counts.items()))


def _job_status_map(jobs: list[dict[str, Any]]) -> dict[str, str]:
    return {str(job.get("tool")): str(job.get("status")) for job in jobs if job.get("tool")}


def _required_missing(job_status: dict[str, str], required_tools: tuple[str, ...]) -> list[str]:
    return [tool for tool in required_tools if job_status.get(tool) != "completed"]


def _required_absent(job_status: dict[str, str], required_tools: tuple[str, ...]) -> list[str]:
    allowed_statuses = {"completed", "blocked"}
    return [tool for tool in required_tools if job_status.get(tool) not in allowed_statuses]


def _artifact_for_tool(
    artifacts: list[dict[str, Any]],
    *,
    tool_name: str,
) -> dict[str, Any] | None:
    return next((item for item in artifacts if item.get("tool") == tool_name), None)


def _stateful_context(artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    web_interact = _artifact_for_tool(artifacts, tool_name="web_interact")
    if not isinstance(web_interact, dict):
        return {}
    summary = web_interact.get("summary")
    if not isinstance(summary, dict):
        return {}
    stateful = summary.get("stateful_context")
    if not isinstance(stateful, dict):
        return {}
    return stateful


def _report_label(report: dict[str, Any] | None) -> str | None:
    if not isinstance(report, dict):
        return None
    title = str(report.get("title") or "").strip()
    if title:
        return title
    summary = str(report.get("executive_summary") or "").strip()
    return summary[:140] if summary else None


async def _assert_http_ok(client: httpx.AsyncClient, url: str, label: str) -> None:
    response = await client.get(url)
    response.raise_for_status()
    print(f"[ok] {label}: {response.status_code}")


async def _fetch_json(client: httpx.AsyncClient, path: str) -> Any:
    response = await client.get(f"{API_BASE_URL}{path}")
    response.raise_for_status()
    return response.json()


async def _create_scan(
    client: httpx.AsyncClient,
    *,
    scan_type: str,
    config: dict[str, Any],
) -> dict[str, Any]:
    response = await client.post(
        f"{API_BASE_URL}/api/v1/scans",
        json={
            "asset_id": ASSET_ID,
            "scan_type": scan_type,
            "priority": "normal",
            "config": config,
        },
    )
    response.raise_for_status()
    return response.json()


async def _poll_scan(
    client: httpx.AsyncClient,
    *,
    scan_id: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        response = await client.get(f"{API_BASE_URL}/api/v1/scans/{scan_id}")
        response.raise_for_status()
        payload = response.json()
        print(
            f"[wait] scan={scan_id} status={payload['status']} progress={payload['progress']}%"
        )
        if payload["status"] in {"completed", "failed", "rejected", "cancelled"}:
            return payload
        await asyncio.sleep(POLL_INTERVAL_SECONDS)
    raise RuntimeError(
        f"Scan {scan_id} did not reach a terminal state within {timeout_seconds}s"
    )


async def _fetch_contracts(
    client: httpx.AsyncClient,
    *,
    asset_type: str,
    target: str,
) -> dict[str, dict[str, Any]]:
    query = (
        "/api/v1/scan-profiles"
        f"?asset_type={quote(asset_type, safe='')}"
        f"&target={quote(target, safe=':/')}"
    )
    contracts = await _fetch_json(client, query)
    items = _unwrap_items(contracts) if not isinstance(contracts, list) else contracts
    return {
        str(item["scan_type"]): item
        for item in items
        if isinstance(item, dict) and item.get("scan_type")
    }


def _build_contract_alignment(
    *,
    contract: dict[str, Any] | None,
    jobs: list[dict[str, Any]],
) -> dict[str, Any]:
    if not isinstance(contract, dict):
        return {
            "advertised": False,
            "missing_live_tools": [],
            "unexpected_runtime_tools": [],
        }

    actual_tools = {
        str(job.get("tool"))
        for job in jobs
        if job.get("tool") and str(job.get("status")) not in {"skipped"}
    }
    live_tools = {
        str(tool)
        for tool in contract.get("live_tools", [])
        if str(tool).strip()
    }
    conditional_tools = {
        str(tool)
        for tool in contract.get("conditional_live_tools", [])
        if str(tool).strip()
    }
    derived_tools = {
        str(tool)
        for tool in contract.get("derived_tools", [])
        if str(tool).strip()
    }
    allowed_runtime = live_tools | conditional_tools | derived_tools
    return {
        "advertised": True,
        "live_tools": sorted(live_tools),
        "conditional_live_tools": sorted(conditional_tools),
        "derived_tools": sorted(derived_tools),
        "missing_live_tools": sorted(live_tools - actual_tools),
        "unexpected_runtime_tools": sorted(actual_tools - allowed_runtime),
    }


def _verify_scenario(
    *,
    scenario: ScenarioDefinition,
    scan: dict[str, Any],
    jobs: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    artifacts: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    attack_graph: dict[str, Any] | None,
    report: dict[str, Any] | None,
) -> None:
    if scan["status"] != "completed":
        raise RuntimeError(
            f"Scenario ended in {scan['status']}: {scan.get('error_message')}"
        )

    job_status = _job_status_map(jobs)
    missing = _required_missing(job_status, scenario.required_completed_tools)
    if missing:
        raise RuntimeError(f"Required tools did not complete: {', '.join(missing)}")

    missing_dynamic = _required_missing(job_status, scenario.required_dynamic_tools)
    if missing_dynamic:
        raise RuntimeError(
            f"Required dynamic verification tools did not complete: {', '.join(missing_dynamic)}"
        )

    missing_present = _required_absent(job_status, scenario.required_present_tools)
    if missing_present:
        raise RuntimeError(
            "Required derived tools were not observed in a terminal state: "
            + ", ".join(missing_present)
        )

    if len(findings) < scenario.min_findings:
        raise RuntimeError(
            f"Expected at least {scenario.min_findings} findings, got {len(findings)}"
        )
    if len(artifacts) < scenario.min_artifacts:
        raise RuntimeError(
            f"Expected at least {scenario.min_artifacts} artifacts, got {len(artifacts)}"
        )
    if scenario.require_evidence and not evidence:
        raise RuntimeError("Expected evidence references, but none were returned")
    if scenario.require_report:
        if not isinstance(report, dict) or not str(report.get("executive_summary") or "").strip():
            raise RuntimeError("Expected report output, but no executive summary was returned")
    if scenario.require_attack_graph:
        if not isinstance(attack_graph, dict) or not attack_graph.get("nodes"):
            raise RuntimeError("Expected attack graph nodes, but none were returned")
    if scenario.min_verified_findings:
        verified_count = sum(
            1 for finding in findings if str(finding.get("verification_state") or "") == "verified"
        )
        if verified_count < scenario.min_verified_findings:
            raise RuntimeError(
                "Expected at least "
                f"{scenario.min_verified_findings} verified findings, got {verified_count}"
            )

    if scenario.require_stateful_context:
        stateful = _stateful_context(artifacts)
        if int(stateful.get("session_count", 0) or 0) < 1:
            raise RuntimeError("Expected authenticated session context from web_interact")
        if int(stateful.get("form_count", 0) or 0) < 1:
            raise RuntimeError("Expected discovered forms from web_interact")
        if int(stateful.get("replay_count", 0) or 0) < 1:
            raise RuntimeError("Expected safe replay activity from web_interact")

        required_types = set(scenario.required_stateful_finding_types)
        actual_types = {
            str(finding.get("vulnerability_type"))
            for finding in findings
            if finding.get("vulnerability_type")
        }
        if required_types and not (required_types & actual_types):
            raise RuntimeError("Expected stateful finding types were not surfaced")


def _build_scenario_result(
    *,
    scenario: ScenarioDefinition,
    scan: dict[str, Any],
    jobs: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    artifacts: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    attack_graph: dict[str, Any] | None,
    report: dict[str, Any] | None,
    contract: dict[str, Any] | None,
) -> dict[str, Any]:
    job_status = _job_status_map(jobs)
    verified_findings = [
        finding for finding in findings if str(finding.get("verification_state") or "") == "verified"
    ]
    failed_jobs = [
        {
            "tool": job.get("tool"),
            "status": job.get("status"),
            "error_message": job.get("error_message"),
            "execution_reason": job.get("execution_reason"),
            "execution_provenance": job.get("execution_provenance"),
        }
        for job in jobs
        if str(job.get("status")) not in {"completed", "skipped"}
    ]
    stateful = _stateful_context(artifacts)
    verification_summary = _build_verification_summary(
        findings=findings,
        profile_id=str(scenario.config.get("profile_id") or "") or None,
        scan_type=scenario.scan_type,
    )
    return {
        "scenario_key": scenario.key,
        "label": scenario.label,
        "scan_id": scan["id"],
        "scan_type": scenario.scan_type,
        "status": scan["status"],
        "progress": scan.get("progress"),
        "started_at": scan.get("started_at"),
        "completed_at": scan.get("completed_at"),
        "scan_duration_seconds": _iso_duration_seconds(
            scan.get("started_at"),
            scan.get("completed_at"),
        ),
        "job_counts": _execution_counts(jobs, "status"),
        "job_provenance_counts": _execution_counts(jobs, "execution_provenance"),
        "finding_counts_by_source": _execution_counts(findings, "source_type"),
        "severity_counts": Counter(str(finding.get("severity") or "unknown") for finding in findings),
        "verification_counts": Counter(
            str(finding.get("verification_state") or "unknown") for finding in findings
        ),
        "verification_summary": verification_summary,
        "artifact_counts_by_tool": Counter(
            str(artifact.get("tool") or artifact.get("artifact_type") or "unknown")
            for artifact in artifacts
        ),
        "required_tool_status": {
            tool: job_status.get(tool, "missing") for tool in scenario.required_completed_tools
        },
        "required_dynamic_tool_status": {
            tool: job_status.get(tool, "missing") for tool in scenario.required_dynamic_tools
        },
        "required_present_tool_status": {
            tool: job_status.get(tool, "missing") for tool in scenario.required_present_tools
        },
        "core_metrics": {
            "findings": len(findings),
            "verified_findings": len(verified_findings),
            "artifacts": len(artifacts),
            "evidence": len(evidence),
            "attack_graph_nodes": int(len((attack_graph or {}).get("nodes", []))),
            "attack_graph_edges": int(len((attack_graph or {}).get("edges", []))),
        },
        "stateful_context": stateful,
        "stateful_finding_types": sorted(
            {
                str(finding.get("vulnerability_type"))
                for finding in findings
                if finding.get("vulnerability_type")
            }
        ),
        "report_summary": _report_label(report),
        "failed_jobs": failed_jobs,
        "contract_alignment": _build_contract_alignment(contract=contract, jobs=jobs),
    }


def _build_verification_summary(
    *,
    findings: list[dict[str, Any]],
    profile_id: str | None,
    scan_type: str,
) -> dict[str, Any]:
    by_type: dict[str, dict[str, Any]] = {}
    overall = {
        "total_findings": len(findings),
        "verified": 0,
        "suspected": 0,
        "detected": 0,
        "verified_share": 0.0,
    }

    for finding in findings:
        vulnerability_type = str(finding.get("vulnerability_type") or "unclassified")
        verification_state = str(finding.get("verification_state") or "detected")
        if verification_state not in {"verified", "suspected", "detected"}:
            verification_state = "detected"

        group = by_type.setdefault(
            vulnerability_type,
            {
                "vulnerability_type": vulnerability_type,
                "total_findings": 0,
                "verified": 0,
                "suspected": 0,
                "detected": 0,
                "verified_share": 0.0,
            },
        )
        group["total_findings"] += 1
        group[verification_state] += 1
        overall[verification_state] += 1

    for group in by_type.values():
        total = int(group["total_findings"])
        group["verified_share"] = round(int(group["verified"]) / total, 3) if total else 0.0

    total_findings = int(overall["total_findings"])
    overall["verified_share"] = (
        round(int(overall["verified"]) / total_findings, 3) if total_findings else 0.0
    )

    ordered = sorted(
        by_type.values(),
        key=lambda item: (-int(item["verified"]), str(item["vulnerability_type"])),
    )
    return {
        "profile_id": profile_id,
        "scan_type": scan_type,
        "overall": overall,
        "by_type": ordered,
    }


def _json_ready(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_ready(item) for item in value]
    if isinstance(value, tuple):
        return [_json_ready(item) for item in value]
    if isinstance(value, Counter):
        return dict(value)
    return value


def _write_output(payload: dict[str, Any]) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    stamped = stamp_proof_payload(
        _json_ready(payload),
        artifact_kind="scenario_matrix",
        phase="P6.2",
        script_path="pentra_core/scripts/local/run_phase6_scenario_matrix.py",
        root_dir=ROOT_DIR,
        environment_context={
            "api_base_url": API_BASE_URL,
            "orchestrator_base_url": ORCH_BASE_URL,
            "demo_target_url": DEMO_TARGET_URL,
            "asset_id": ASSET_ID,
            "supported_scan_types": ["recon", "vuln", "full"],
        },
        run_id=PROOF_RUN_ID,
    )
    OUTPUT_PATH.write_text(json.dumps(stamped, indent=2, default=str))


async def _run_scenario(
    client: httpx.AsyncClient,
    *,
    scenario: ScenarioDefinition,
    contracts_by_type: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    created = await _create_scan(
        client,
        scan_type=scenario.scan_type,
        config=scenario.config,
    )
    scan_id = str(created["id"])
    print(f"[ok] scenario created: {scenario.key} scan={scan_id}")

    finished = await _poll_scan(
        client,
        scan_id=scan_id,
        timeout_seconds=scenario.timeout_seconds,
    )

    jobs = _unwrap_items(await _fetch_json(client, f"/api/v1/scans/{scan_id}/jobs"))
    findings = _unwrap_items(await _fetch_json(client, f"/api/v1/scans/{scan_id}/findings"))
    artifacts = _unwrap_items(await _fetch_json(client, f"/api/v1/scans/{scan_id}/artifacts/summary"))
    evidence = _unwrap_items(await _fetch_json(client, f"/api/v1/scans/{scan_id}/evidence"))
    attack_graph = await _fetch_json(client, f"/api/v1/scans/{scan_id}/attack-graph")
    report = await _fetch_json(client, f"/api/v1/scans/{scan_id}/report")

    _verify_scenario(
        scenario=scenario,
        scan=finished,
        jobs=jobs,
        findings=findings,
        artifacts=artifacts,
        evidence=evidence,
        attack_graph=attack_graph,
        report=report,
    )

    print(
        "[ok] scenario complete:",
        f"{scenario.key} status={finished['status']}",
        f"findings={len(findings)} artifacts={len(artifacts)} evidence={len(evidence)}",
    )

    return _build_scenario_result(
        scenario=scenario,
        scan=finished,
        jobs=jobs,
        findings=findings,
        artifacts=artifacts,
        evidence=evidence,
        attack_graph=attack_graph,
        report=report,
        contract=contracts_by_type.get(scenario.scan_type),
    )


async def main() -> int:
    run_started_at = _utc_now()
    results: list[dict[str, Any]] = []
    payload: dict[str, Any] = {
        "phase": "P6.2",
        "status": "in_progress",
        "generated_at": run_started_at,
        "asset_id": ASSET_ID,
        "api_base_url": API_BASE_URL,
        "orchestrator_base_url": ORCH_BASE_URL,
        "demo_target_url": DEMO_TARGET_URL,
        "output_path": str(OUTPUT_PATH),
        "supported_scan_types": ["recon", "vuln", "full"],
        "excluded_schema_scan_types": [
            {
                "scan_type": "exploit_verify",
                "reason": (
                    "Not advertised by /api/v1/scan-profiles and omitted from the "
                    "product-safe local live matrix."
                ),
            }
        ],
        "scenarios": results,
    }

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            await _assert_http_ok(client, f"{API_BASE_URL}/health", "api health")
            await _assert_http_ok(client, f"{ORCH_BASE_URL}/health", "orchestrator health")
            await _assert_http_ok(client, f"{DEMO_TARGET_URL}/healthz", "demo target health")

            asset = await _fetch_json(client, f"/api/v1/assets/{ASSET_ID}")
            contracts_by_type = await _fetch_contracts(
                client,
                asset_type=str(asset["asset_type"]),
                target=str(asset["target"]),
            )
            payload["asset"] = asset
            payload["advertised_scan_profiles"] = contracts_by_type

            for scenario in SCENARIOS:
                scenario_started = _utc_now()
                try:
                    result = await _run_scenario(
                        client,
                        scenario=scenario,
                        contracts_by_type=contracts_by_type,
                    )
                    result["result"] = "passed"
                    result["scenario_started_at"] = scenario_started
                    result["scenario_finished_at"] = _utc_now()
                    results.append(result)
                    _write_output(payload)
                except Exception as exc:
                    failure = {
                        "scenario_key": scenario.key,
                        "label": scenario.label,
                        "scan_type": scenario.scan_type,
                        "result": "failed",
                        "scenario_started_at": scenario_started,
                        "scenario_finished_at": _utc_now(),
                        "error": str(exc),
                    }
                    results.append(failure)
                    payload["failure"] = failure
                    _write_output(payload)
                    raise

        payload["summary"] = {
            "total_scenarios": len(results),
            "passed": sum(1 for item in results if item.get("result") == "passed"),
            "failed": sum(1 for item in results if item.get("result") == "failed"),
        }
        payload["status"] = "passed"
        payload["generated_at"] = _utc_now()
        _write_output(payload)
        print(f"[done] Phase 6 scenario matrix passed: {OUTPUT_PATH}")
        return 0
    except Exception as exc:
        payload["generated_at"] = _utc_now()
        payload["status"] = "failed"
        payload.setdefault("summary", {})
        payload["summary"]["failed"] = sum(
            1 for item in results if item.get("result") == "failed"
        ) or 1
        payload["error"] = str(exc)
        _write_output(payload)
        print(f"[error] {exc}", file=sys.stderr)
        print(f"[artifact] partial results written to {OUTPUT_PATH}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
