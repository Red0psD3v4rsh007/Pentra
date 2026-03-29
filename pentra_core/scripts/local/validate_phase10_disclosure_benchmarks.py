"""Live local validation harness for Phase 10 P3A.6 against disclosure benchmarks."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import html
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlparse

REPO_ROOT = Path(__file__).resolve().parents[3]
PACKAGES_DIR = REPO_ROOT / "pentra_core" / "packages" / "pentra-common"
WORKER_APP_ROOT = REPO_ROOT / "pentra_core" / "services" / "worker-svc"
if str(PACKAGES_DIR) not in sys.path:
    sys.path.insert(0, str(PACKAGES_DIR))
if str(WORKER_APP_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKER_APP_ROOT))

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import run_phase8_capability_matrix as phase8
else:
    from . import run_phase8_capability_matrix as phase8

from app.engine.capabilities.disclosure_misconfig_crypto import build_disclosure_misconfig_crypto_pack

BENCHMARK_PATHS = [
    REPO_ROOT / "pentra_core" / "dev_targets" / "capability_benchmarks" / "repo_demo_api.json",
]
OUTPUT_DIR = REPO_ROOT / ".local" / "pentra" / "phase10"
OUTPUT_PATH = OUTPUT_DIR / "disclosure_benchmarks_live_latest.json"

_DISCLOSURE_EXPECTATION_TYPES = {
    "sensitive_data_exposure",
    "stack_trace_exposure",
    "openapi_exposure",
    "credential_exposure",
    "debug_exposure",
    "cors_misconfiguration",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_benchmark(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text())
    if not isinstance(payload, dict):
        raise RuntimeError(f"Benchmark manifest must be a JSON object: {path}")
    return payload


def _selected_strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    items: list[str] = []
    seen: set[str] = set()
    for item in value:
        text = str(item).strip()
        key = text.lower()
        if not text or key in seen:
            continue
        seen.add(key)
        items.append(text)
    return items


def _route_group(url: str) -> str:
    parsed = urlparse(url)
    path = (parsed.path or "/").strip() or "/"
    if not path.startswith("/"):
        path = f"/{path}"
    return path


def _selected_seed_paths(scan_config: dict[str, Any]) -> list[str]:
    stateful = scan_config.get("stateful_testing")
    if not isinstance(stateful, dict):
        return ["/"]
    seeds = _selected_strings(stateful.get("seed_paths"))
    return seeds or ["/"]


def _extract_links(*, base_url: str, body: str) -> list[str]:
    matches = re.findall(r"""href=["']([^"'#]+)["']""", body, flags=re.IGNORECASE)
    base_origin = urlparse(base_url)
    links: list[str] = []
    seen: set[str] = set()
    for match in matches:
        absolute = urljoin(base_url, html.unescape(match))
        parsed = urlparse(absolute)
        if parsed.scheme not in {"http", "https"}:
            continue
        if (parsed.scheme, parsed.netloc) != (base_origin.scheme, base_origin.netloc):
            continue
        normalized = absolute.split("#", 1)[0]
        if normalized in seen:
            continue
        seen.add(normalized)
        links.append(normalized)
    return links


def _fetch_page(url: str) -> dict[str, Any] | None:
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            body_bytes = response.read()
            content_type = response.headers.get("content-type", "")
            body = body_bytes.decode("utf-8", errors="ignore")
            return {
                "url": response.geturl(),
                "status_code": response.status,
                "content_type": content_type,
                "body": body,
            }
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="ignore")
        return {
            "url": exc.geturl(),
            "status_code": exc.code,
            "content_type": exc.headers.get("content-type", ""),
            "body": body,
        }
    except Exception:
        return None


def _page_record(page: dict[str, Any]) -> dict[str, Any]:
    page_url = str(page.get("url") or "").strip()
    body = str(page.get("body") or "")
    title_match = re.search(r"<title>(.*?)</title>", body, flags=re.IGNORECASE | re.DOTALL)
    title = re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else ""
    preview = re.sub(r"\s+", " ", body).strip()[:400]
    return {
        "page_key": page_url,
        "url": page_url,
        "route_group": _route_group(page_url),
        "status_code": int(page.get("status_code") or 0),
        "content_type": str(page.get("content_type") or ""),
        "response_preview": preview,
        "title": title,
        "session_label": "unauthenticated",
        "auth_state": "none",
        "requires_auth": False,
    }


def _build_live_discovery_sync(base_url: str, scan_config: dict[str, Any]) -> dict[str, Any]:
    base_origin = urlparse(base_url)
    queue: list[str] = [urljoin(base_url, seed) for seed in _selected_seed_paths(scan_config)]
    seen: set[str] = set()
    fetched_pages: list[dict[str, Any]] = []
    max_pages = 12

    while queue and len(fetched_pages) < max_pages:
        current = queue.pop(0)
        normalized = current.split("#", 1)[0]
        if normalized in seen:
            continue
        seen.add(normalized)
        page = _fetch_page(normalized)
        if not page:
            continue
        fetched_pages.append(page)
        content_type = str(page.get("content_type") or "").lower()
        if "html" not in content_type:
            continue
        for link in _extract_links(base_url=normalized, body=str(page.get("body") or "")):
            parsed = urlparse(link)
            if (parsed.scheme, parsed.netloc) != (base_origin.scheme, base_origin.netloc):
                continue
            if link.split("#", 1)[0] not in seen:
                queue.append(link)

    pages = [_page_record(page) for page in fetched_pages]
    pack = build_disclosure_misconfig_crypto_pack(
        base_url=base_url,
        scan_config=scan_config,
        pages=pages,
        forms=[],
        sessions=[],
        replays=[],
        probe_findings=[],
        capability_results={},
    )
    return {
        "pages": pages,
        "disclosure_misconfig_crypto_capability": pack["capability_summary"],
        "disclosure_candidates": pack["candidates"],
    }


async def _build_live_discovery(base_url: str, scan_config: dict[str, Any]) -> dict[str, Any]:
    return _build_live_discovery_sync(base_url, scan_config)


def _resolve_scan_config(target_spec: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    plans = target_spec.get("scan_plans")
    if not isinstance(plans, list) or not plans or not isinstance(plans[0], dict):
        raise RuntimeError(f"Benchmark target '{target_spec.get('key')}' is missing a usable scan plan")
    plan = plans[0]
    scan_config = phase8.resolve_scan_plan_config(
        config_template=str(plan.get("config_template") or "default_external_web_api_v1"),
        config_overrides=plan.get("config_overrides") if isinstance(plan.get("config_overrides"), dict) else None,
    )
    return plan, scan_config


def _probe(url: str) -> dict[str, Any]:
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            body = response.read().decode("utf-8", errors="ignore")
            return {
                "reachable": response.status < 500,
                "status_code": response.status,
                "detail": body[:200],
            }
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="ignore")
        return {
            "reachable": exc.code < 500,
            "status_code": exc.code,
            "detail": body[:200],
        }
    except Exception as exc:  # pragma: no cover - live runtime dependent
        return {"reachable": False, "status_code": None, "detail": str(exc)}


async def _wait_for_http(url: str, timeout_seconds: int) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last: dict[str, Any] = {"reachable": False, "status_code": None, "detail": "timeout"}
    while time.monotonic() < deadline:
        last = _probe(url)
        if last.get("reachable"):
            return last
        await asyncio.sleep(1)
    return last


def _ensure_repo_local_target_process(target_spec: dict[str, Any]) -> dict[str, Any]:
    script_value = str(target_spec.get("repo_local_launch_script") or "").strip()
    if not script_value:
        return {"status": "skipped", "detail": "missing_repo_local_launch_script"}

    script_path = (REPO_ROOT / script_value).resolve()
    key = str(target_spec.get("key") or "repo_local_target").strip() or "repo_local_target"
    safe_key = key.replace("/", "-")
    log_path = OUTPUT_DIR / f"{safe_key}_target.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT) + (f":{env['PYTHONPATH']}" if env.get("PYTHONPATH") else "")
    with log_path.open("ab") as stream:
        process = subprocess.Popen(  # noqa: S603,S607
            [str(script_path)],
            cwd=REPO_ROOT,
            stdout=stream,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            env=env,
        )
    return {
        "status": "started",
        "pid": process.pid,
        "detail": f"spawned {script_value}",
        "script": script_value,
        "log_path": str(log_path),
    }


async def _ensure_target(target_spec: dict[str, Any]) -> dict[str, Any]:
    healthcheck_url = str(target_spec.get("healthcheck_url") or target_spec.get("target") or "").strip()
    preflight = _probe(healthcheck_url)
    if preflight.get("reachable"):
        return {"status": "already_running", "health": preflight}

    if str(target_spec.get("launch_mode") or "").strip() == "repo_local":
        launch = _ensure_repo_local_target_process(target_spec)
        health = await _wait_for_http(healthcheck_url, 45)
        return {"status": "ok" if health.get("reachable") else "launch_failed", "launch": launch, "health": health}

    return {"status": "unavailable", "health": preflight}


def _pack_expectations(target_spec: dict[str, Any]) -> list[str]:
    coverage = target_spec.get("pack_coverage_expectations")
    if isinstance(coverage, dict):
        pack = coverage.get("p3a_disclosure_misconfig_crypto")
        if isinstance(pack, dict):
            return [
                item
                for item in _selected_strings(pack.get("expected_vulnerability_types"))
                if item in _DISCLOSURE_EXPECTATION_TYPES
            ]
    expectations = target_spec.get("expectations") if isinstance(target_spec.get("expectations"), dict) else {}
    return [
        item
        for item in _selected_strings(expectations.get("expected_vulnerability_types"))
        if item in _DISCLOSURE_EXPECTATION_TYPES
    ]


def _top_route_assessments(discovery: dict[str, Any], limit: int = 10) -> list[dict[str, Any]]:
    capability = discovery.get("disclosure_misconfig_crypto_capability") or {}
    route_assessments = capability.get("route_assessments") or []
    if not isinstance(route_assessments, list):
        return []
    return [item for item in route_assessments if isinstance(item, dict)][:limit]


def _top_candidates(discovery: dict[str, Any], limit: int = 10) -> list[dict[str, Any]]:
    candidates = discovery.get("disclosure_candidates") or []
    if not isinstance(candidates, list):
        return []
    ranked = sorted(
        [item for item in candidates if isinstance(item, dict)],
        key=lambda item: (
            -int(str(item.get("vulnerability_type") or "").strip() == "stack_trace_exposure"),
            -int(str(item.get("vulnerability_type") or "").strip() == "openapi_exposure"),
            -int(item.get("confidence") or 0),
            str(item.get("route_group") or ""),
        ),
    )
    return ranked[:limit]


def _evaluate_disclosure_assessment(
    *,
    target_spec: dict[str, Any],
    discovery: dict[str, Any],
) -> dict[str, Any]:
    expected_types = set(_pack_expectations(target_spec))
    candidates = discovery.get("disclosure_candidates") or []
    detected_types = {
        str(item.get("vulnerability_type") or "").strip()
        for item in candidates
        if isinstance(item, dict) and str(item.get("vulnerability_type") or "").strip()
    }
    detected_expected = sorted(expected_types & detected_types)
    missed_expected = sorted(expected_types - detected_types)
    unexpected_detected = sorted(detected_types - expected_types)

    detected_recall = round(len(detected_expected) / len(expected_types), 3) if expected_types else None
    capability = discovery.get("disclosure_misconfig_crypto_capability") or {}
    route_counts = capability.get("route_assessment_counts") or {}
    negative_evidence_count = int(route_counts.get("negative_evidence_routes") or capability.get("negative_evidence_count") or 0)
    planner_hook_count = int(capability.get("planner_hook_count") or 0)
    candidate_count = int(capability.get("candidate_count") or len(candidates))
    minimum_detected_recall = 1.0 if expected_types else 0.0

    return {
        "scope": "disclosure_only",
        "expected_vulnerability_types": sorted(expected_types),
        "detected_types": sorted(detected_types),
        "detected_expected_types": detected_expected,
        "missed_expected_types": missed_expected,
        "unexpected_detected_types": unexpected_detected,
        "detected_recall": detected_recall,
        "minimum_detected_recall": minimum_detected_recall,
        "meets_detected_recall": detected_recall is None or detected_recall >= minimum_detected_recall,
        "meets_target_bar": detected_recall is None or detected_recall >= minimum_detected_recall,
        "candidate_count": candidate_count,
        "planner_hook_count": planner_hook_count,
        "negative_evidence_count": negative_evidence_count,
    }


async def _validate_target(path: Path) -> dict[str, Any]:
    target_spec = _load_benchmark(path)
    plan, scan_config = _resolve_scan_config(target_spec)
    ensure_result = await _ensure_target(target_spec)
    health = ensure_result.get("health") if isinstance(ensure_result, dict) else {}
    if not isinstance(health, dict):
        health = {}

    target = str(target_spec.get("target") or "").strip()
    record: dict[str, Any] = {
        "captured_at": _utc_now(),
        "benchmark_key": str(target_spec.get("key") or ""),
        "manifest_path": str(path.relative_to(REPO_ROOT)),
        "target": target,
        "healthcheck_url": str(target_spec.get("healthcheck_url") or ""),
        "launch_mode": str(target_spec.get("launch_mode") or ""),
        "launch_result": ensure_result,
        "scan_plan_key": str(plan.get("key") or ""),
        "scan_plan_label": str(plan.get("label") or ""),
        "config_template": str(plan.get("config_template") or ""),
        "seed_paths": _selected_strings(((scan_config.get("stateful_testing") or {}).get("seed_paths") or [])),
    }

    if not health.get("reachable"):
        record["status"] = "unavailable"
        record["detail"] = "Target health check failed after launch attempt."
        return record

    discovery = await _build_live_discovery(target, scan_config)
    assessment = _evaluate_disclosure_assessment(target_spec=target_spec, discovery=discovery)
    capability = discovery.get("disclosure_misconfig_crypto_capability") or {}

    record.update(
        {
            "status": "passed" if assessment["meets_target_bar"] else "failed",
            "detail": (
                "Disclosure capability met the target bar."
                if assessment["meets_target_bar"]
                else "Disclosure capability missed the target bar."
            ),
            "capability_assessment": assessment,
            "disclosure_misconfig_crypto_capability": capability,
            "disclosure_candidates": discovery.get("disclosure_candidates") or [],
            "top_route_assessments": _top_route_assessments(discovery),
            "top_candidates": _top_candidates(discovery),
        }
    )
    return record


async def _main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    results = [await _validate_target(path) for path in BENCHMARK_PATHS]
    payload = {
        "captured_at": _utc_now(),
        "targets": results,
        "summary": {
            "target_count": len(results),
            "passed_targets": sum(1 for item in results if item.get("status") == "passed"),
            "failed_targets": sum(1 for item in results if item.get("status") == "failed"),
            "unavailable_targets": sum(1 for item in results if item.get("status") == "unavailable"),
        },
    }
    OUTPUT_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True))
    for item in results:
        key = str(item.get("benchmark_key") or "target")
        artifact_path = OUTPUT_DIR / f"{key}_disclosure_live_latest.json"
        artifact_path.write_text(json.dumps(item, indent=2, sort_keys=True))
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    asyncio.run(_main())
