"""Stateful web interaction runner for authenticated crawl and workflow replay."""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx

from app.engine.capabilities import execute_capability_packs
from app.engine.capabilities.browser_xss import (
    build_browser_xss_pack,
    extract_dom_xss_markers as _capability_extract_dom_xss_markers,
)

@dataclass
class _FormInput:
    name: str
    input_type: str = "text"
    value: str = ""


@dataclass
class _ParsedForm:
    action: str
    method: str = "get"
    enctype: str = "application/x-www-form-urlencoded"
    inputs: list[_FormInput] = field(default_factory=list)


class _DiscoveryParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[_ParsedForm] = []
        self.title: str = ""
        self.ajax_urls: list[str] = []
        self.script_urls: list[str] = []
        self.inline_scripts: list[str] = []
        self._current_form: _ParsedForm | None = None
        self._in_title = False
        self._in_script = False
        self._script_content = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {name.lower(): value or "" for name, value in attrs}
        if tag == "a":
            href = attr_map.get("href", "").strip()
            if href:
                self.links.append(href)
            self.links.extend(_client_route_links_from_attrs(attr_map))
            return

        self.links.extend(_client_route_links_from_attrs(attr_map))

        if tag == "form":
            self._current_form = _ParsedForm(
                action=attr_map.get("action", "").strip(),
                method=(attr_map.get("method") or "get").strip().lower(),
                enctype=(attr_map.get("enctype") or "application/x-www-form-urlencoded").strip().lower(),
            )
            self.forms.append(self._current_form)
            return

        if tag in {"input", "textarea"} and self._current_form is not None:
            name = attr_map.get("name", "").strip()
            if not name:
                return
            self._current_form.inputs.append(
                _FormInput(
                    name=name,
                    input_type=("textarea" if tag == "textarea" else (attr_map.get("type") or "text")).strip().lower(),
                    value=attr_map.get("value", ""),
                )
            )
            return

        if tag == "title":
            self._in_title = True

        if tag == "link":
            rel = attr_map.get("rel", "").strip().lower()
            href = attr_map.get("href", "").strip()
            as_attr = attr_map.get("as", "").strip().lower()
            if href and (
                "modulepreload" in rel
                or (as_attr == "script" and "preload" in rel)
                or href.endswith(".js")
            ):
                self.script_urls.append(href)

        if tag == "script":
            src = attr_map.get("src", "").strip()
            if src:
                self.script_urls.append(src)
            self._in_script = True
            self._script_content = ""

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current_form = None
        elif tag == "title":
            self._in_title = False
        elif tag == "script":
            self._in_script = False
            if self._script_content:
                self.inline_scripts.append(self._script_content)
                self.ajax_urls.extend(_extract_ajax_urls(self._script_content))

    def handle_data(self, data: str) -> None:
        if self._in_title and data.strip():
            self.title += data.strip()
        if self._in_script:
            self._script_content += data


class WebInteractionRunner:
    """Performs bounded authenticated crawl and safe workflow mutation replay."""

    async def run_discovery(
        self,
        *,
        base_url: str,
        scan_config: dict[str, Any],
    ) -> dict[str, Any]:
        stateful = _stateful_config(scan_config)
        seed_paths = _discovery_seed_paths(scan_config)
        start_urls = [_join_url(base_url, path) for path in seed_paths]

        max_depth = _bounded_int(stateful.get("crawl_max_depth"), default=3, minimum=1, maximum=6)
        max_pages = _bounded_int(stateful.get("max_pages"), default=24, minimum=1, maximum=60)
        max_replays = _bounded_int(stateful.get("max_replays"), default=4, minimum=0, maximum=10)
        max_script_assets = _bounded_int(
            stateful.get("max_script_assets"),
            default=8,
            minimum=0,
            maximum=20,
        )

        pages: list[dict[str, Any]] = []
        forms: list[dict[str, Any]] = []
        sessions: list[dict[str, Any]] = []
        workflows: list[dict[str, Any]] = []
        replays: list[dict[str, Any]] = []

        # Crawl the public surface first.
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=10.0,
            headers={"User-Agent": "Pentra-WebInteract/phase6"},
        ) as client:
            public = await self._crawl_session(
                client=client,
                base_url=base_url,
                start_urls=start_urls,
                session_label="unauthenticated",
                auth_state="none",
                max_depth=max_depth,
                max_pages=max_pages,
                max_replays=max_replays,
                max_script_assets=max_script_assets,
            )
            pages.extend(public["pages"])
            forms.extend(public["forms"])
            workflows.extend(public["workflows"])
            replays.extend(public["replays"])
            sessions.append(
                {
                    "session_label": "unauthenticated",
                    "auth_state": "none",
                    "cookie_names": [],
                    "csrf_tokens": [],
                    "landing_url": public.get("landing_url") or start_urls[0],
                }
            )
        # Try API-token auth if configured (Bearer / X-API-Key)
        for token_config in _api_token_credentials(scan_config):
            auth_header = _build_auth_header(token_config)
            if not auth_header:
                continue
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=10.0,
                headers={"User-Agent": "Pentra-WebInteract/phase8", **auth_header},
            ) as client:
                token_label = str(token_config.get("label") or "api_token")
                token_crawl = await self._crawl_session(
                    client=client,
                    base_url=base_url,
                    start_urls=start_urls,
                    session_label=token_label,
                    auth_state="authenticated",
                    max_depth=max_depth,
                    max_pages=max_pages,
                    max_replays=max_replays,
                    max_script_assets=max_script_assets,
                )
                pages.extend(token_crawl["pages"])
                forms.extend(token_crawl["forms"])
                workflows.extend(token_crawl["workflows"])
                replays.extend(token_crawl["replays"])
                sessions.append(
                    {
                        "session_label": token_label,
                        "auth_state": "authenticated",
                        "auth_method": "api_token",
                        "cookie_names": [],
                        "csrf_tokens": [],
                        "landing_url": token_crawl.get("landing_url") or start_urls[0],
                    }
                )

        # Try form-based login for each credential set
        for credentials in _auth_credentials(scan_config):
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=10.0,
                headers={"User-Agent": "Pentra-WebInteract/phase6"},
            ) as client:
                login_result = await self._login(
                    client=client,
                    base_url=base_url,
                    scan_config=scan_config,
                    credentials=credentials,
                )
                if not login_result["success"]:
                    continue

                sessions.append(login_result["session"])
                crawl = await self._crawl_session(
                    client=client,
                    base_url=base_url,
                    start_urls=[login_result["landing_url"], *start_urls],
                    session_label=login_result["session"]["session_label"],
                    auth_state=login_result["session"]["auth_state"],
                    max_depth=max_depth,
                    max_pages=max_pages,
                    max_replays=max_replays,
                    max_script_assets=max_script_assets,
                    extra_workflow={
                        "source_url": login_result["login_url"],
                        "target_url": login_result["landing_url"],
                        "action": "login",
                        "requires_auth": False,
                        "session_label": login_result["session"]["session_label"],
                    },
                )
                pages.extend(crawl["pages"])
                forms.extend(crawl["forms"])
                workflows.extend(crawl["workflows"])
                replays.extend(crawl["replays"])

        probe_findings = await self._run_enabled_stateful_probes(
            base_url=base_url,
            scan_config=scan_config,
        )
        deduped_probe_findings = _dedupe_probe_findings(probe_findings)
        capability_results = execute_capability_packs(
            base_url=base_url,
            scan_config=scan_config,
            pages=pages,
            forms=forms,
            sessions=sessions,
            workflows=workflows,
            replays=replays,
            probe_findings=deduped_probe_findings,
        )
        browser_xss_pack = capability_results.get(
            "p3a_browser_xss",
            {"capability_summary": {"pack_key": "p3a_browser_xss", "enabled": False}, "candidates": []},
        )
        auth_pack = capability_results.get(
            "p3a_multi_role_stateful_auth",
            {
                "capability_summary": {"pack_key": "p3a_multi_role_stateful_auth", "enabled": False},
                "candidates": [],
            },
        )
        access_pack = capability_results.get(
            "p3a_access_control_workflow_abuse",
            {
                "capability_summary": {"pack_key": "p3a_access_control_workflow_abuse", "enabled": False},
                "candidates": [],
            },
        )
        injection_pack = capability_results.get(
            "p3a_injection",
            {
                "capability_summary": {"pack_key": "p3a_injection", "enabled": False},
                "candidates": [],
            },
        )
        parser_pack = capability_results.get(
            "p3a_parser_file_abuse",
            {
                "capability_summary": {"pack_key": "p3a_parser_file_abuse", "enabled": False},
                "candidates": [],
            },
        )
        disclosure_pack = capability_results.get(
            "p3a_disclosure_misconfig_crypto",
            {
                "capability_summary": {"pack_key": "p3a_disclosure_misconfig_crypto", "enabled": False},
                "candidates": [],
            },
        )
        xss_candidates = _dedupe_dicts(list(browser_xss_pack.get("candidates") or []), key="candidate_key")
        auth_candidates = _dedupe_dicts(list(auth_pack.get("candidates") or []), key="candidate_key")
        access_candidates = _dedupe_dicts(list(access_pack.get("candidates") or []), key="candidate_key")
        injection_candidates = _dedupe_dicts(list(injection_pack.get("candidates") or []), key="candidate_key")
        parser_candidates = _dedupe_dicts(list(parser_pack.get("candidates") or []), key="candidate_key")
        disclosure_candidates = _dedupe_dicts(list(disclosure_pack.get("candidates") or []), key="candidate_key")

        return {
            "pages": _dedupe_dicts(pages, key="page_key"),
            "forms": _dedupe_dicts(forms, key="form_key"),
            "sessions": sessions,
            "workflows": _dedupe_dicts(workflows, key="workflow_key"),
            "replays": _dedupe_dicts(replays, key="replay_key"),
            "capabilities": capability_results,
            "browser_xss_capability": browser_xss_pack["capability_summary"],
            "xss_candidates": xss_candidates,
            "multi_role_stateful_auth_capability": auth_pack["capability_summary"],
            "auth_candidates": auth_candidates,
            "access_control_workflow_abuse_capability": access_pack["capability_summary"],
            "access_control_candidates": access_candidates,
            "injection_capability": injection_pack["capability_summary"],
            "injection_candidates": injection_candidates,
            "parser_file_abuse_capability": parser_pack["capability_summary"],
            "parser_file_candidates": parser_candidates,
            "disclosure_misconfig_crypto_capability": disclosure_pack["capability_summary"],
            "disclosure_candidates": disclosure_candidates,
            "probe_findings": deduped_probe_findings,
            "summary": {
                "page_count": len(_dedupe_dicts(pages, key="page_key")),
                "form_count": len(_dedupe_dicts(forms, key="form_key")),
                "session_count": len(sessions),
                "workflow_count": len(_dedupe_dicts(workflows, key="workflow_key")),
                "replay_count": len(_dedupe_dicts(replays, key="replay_key")),
                "capability_pack_count": len(capability_results),
                "xss_candidate_count": len(xss_candidates),
                "browser_xss_target_profile": browser_xss_pack["capability_summary"].get("target_profile"),
                "browser_xss_planner_hook_count": len(
                    browser_xss_pack["capability_summary"].get("planner_hooks") or []
                ),
                "auth_candidate_count": len(auth_candidates),
                "multi_role_auth_target_profile": auth_pack["capability_summary"].get("target_profile"),
                "multi_role_auth_planner_hook_count": len(
                    auth_pack["capability_summary"].get("planner_hooks") or []
                ),
                "access_control_candidate_count": len(access_candidates),
                "access_control_workflow_target_profile": access_pack["capability_summary"].get("target_profile"),
                "access_control_workflow_planner_hook_count": len(
                    access_pack["capability_summary"].get("planner_hooks") or []
                ),
                "injection_candidate_count": len(injection_candidates),
                "injection_target_profile": injection_pack["capability_summary"].get("target_profile"),
                "injection_planner_hook_count": len(
                    injection_pack["capability_summary"].get("planner_hooks") or []
                ),
                "parser_file_candidate_count": len(parser_candidates),
                "parser_file_target_profile": parser_pack["capability_summary"].get("target_profile"),
                "parser_file_planner_hook_count": len(
                    parser_pack["capability_summary"].get("planner_hooks") or []
                ),
                "disclosure_candidate_count": len(disclosure_candidates),
                "disclosure_target_profile": disclosure_pack["capability_summary"].get("target_profile"),
                "disclosure_planner_hook_count": len(
                    disclosure_pack["capability_summary"].get("planner_hooks") or []
                ),
                "probe_finding_count": len(deduped_probe_findings),
            },
        }

    async def run_workflow_mutation(
        self,
        *,
        base_url: str,
        scan_config: dict[str, Any],
        target: str,
    ) -> list[dict[str, Any]]:
        mutation_type = str(scan_config.get("workflow_mutation") or "").strip().lower()
        if not mutation_type:
            return []

        sequence_urls = [
            _join_url(base_url, value)
            for value in _string_list(scan_config.get("sequence_urls"))
            if value
        ]
        target_url = _join_url(base_url, str(scan_config.get("target_url") or target or "").strip())
        workflow_type = str(scan_config.get("workflow_type") or "stateful").strip().lower()

        if not target_url:
            return []

        response: dict[str, Any] = {"status_code": 0, "body": "", "headers": {}}
        request_line = ""
        credential = _preferred_workflow_credential(scan_config)

        if mutation_type == "cross_session":
            async with httpx.AsyncClient(
                follow_redirects=False,
                timeout=10.0,
                headers={"User-Agent": "Pentra-Custom-POC/phase6"},
            ) as client:
                http_response = await client.get(target_url)
                response = _response_payload(http_response)
                request_line = f"GET {target_url}"
        else:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=10.0,
                headers={"User-Agent": "Pentra-Custom-POC/phase6"},
            ) as client:
                if credential is not None:
                    await self._login(
                        client=client,
                        base_url=base_url,
                        scan_config=scan_config,
                        credentials=credential,
                    )

                if mutation_type == "modify_id":
                    mutated_url = _mutate_identifier(target_url)
                    if mutated_url == target_url:
                        return []
                    http_response = await client.get(mutated_url)
                    response = _response_payload(http_response)
                    request_line = f"GET {mutated_url}"
                elif mutation_type == "repeat_step":
                    await client.get(target_url)
                    http_response = await client.get(target_url)
                    response = _response_payload(http_response)
                    request_line = f"GET {target_url} (replayed)"
                elif mutation_type == "swap_order":
                    reverse_sequence = list(reversed(sequence_urls or [target_url]))
                    http_response = await self._replay_sequence(client, reverse_sequence)
                    response = _response_payload(http_response)
                    request_line = f"GET {reverse_sequence[0]} (reverse sequence)"
                else:
                    candidate = sequence_urls[-1] if sequence_urls else target_url
                    http_response = await self._submit_skip_step(
                        client=client,
                        candidate_url=candidate,
                        csrf_token=_stateful_config(scan_config).get("default_csrf_token", "demo-csrf"),
                    )
                    response = _response_payload(http_response)
                    request_line = f"POST {candidate}"

        result = _analyze_workflow_response(
            response=response,
            mutation_type=mutation_type,
            workflow_type=workflow_type,
            target_url=target_url,
        )
        if result["verdict"] == "negative" or result["flaw_type"] == "none":
            return []

        severity = "high" if result["flaw_type"] in {"auth_bypass", "idor", "privilege_escalation"} else "medium"
        title = {
            "auth_bypass": "Authorization bypass confirmed via stateful replay",
            "idor": "IDOR confirmed via workflow mutation",
            "workflow_bypass": "Workflow bypass confirmed via stateful replay",
            "privilege_escalation": "Privilege escalation indicators confirmed via workflow replay",
        }.get(result["flaw_type"], "Stateful workflow weakness confirmed")
        description = (
            f"Pentra replayed the {mutation_type.replace('_', ' ')} mutation against the "
            f"{workflow_type} workflow and observed evidence: {', '.join(result['evidence'])}."
        )
        verification_confidence = max(90, int(float(result["confidence"]) * 100))

        return [
            {
                "title": title,
                "severity": severity,
                "confidence": max(55, int(float(result["confidence"]) * 100)),
                "target": target_url,
                "endpoint": target_url,
                "description": description,
                "tool_source": "custom_poc",
                "vulnerability_type": result["flaw_type"],
                "request": request_line,
                "response": _format_response_for_evidence(response),
                "payload": mutation_type,
                "exploit_result": ", ".join(result["evidence"]),
                "surface": "web",
                "route_group": _route_group(target_url),
                "exploitability": "medium" if severity == "medium" else "high",
                "exploitability_score": 72 if severity == "medium" else 84,
                "verification_state": "verified",
                "verification_confidence": verification_confidence,
                "references": [f"workflow:{workflow_type}", *result["evidence"]],
            }
        ]

    async def run_rate_limit_check(
        self,
        *,
        base_url: str,
        scan_config: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Check for missing rate limiting on sensitive endpoints."""
        stateful = _stateful_config(scan_config)
        auth = stateful.get("auth", {})
        auth_login_path = ""
        if isinstance(auth, dict):
            auth_login_path = str(auth.get("login_page_path") or "").strip()
        endpoints = _string_list(stateful.get("rate_limit_endpoints")) or [
            auth_login_path or "/login"
        ]
        findings: list[dict[str, Any]] = []

        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=5.0,
            headers={"User-Agent": "Pentra-RateLimitCheck/phase8"},
        ) as client:
            for endpoint in endpoints[:3]:
                url = _join_url(base_url, endpoint)
                success_count = 0
                for _ in range(10):
                    try:
                        resp = await client.post(url, data={"username": "test", "password": "test"})
                        if resp.status_code not in {429, 503}:
                            success_count += 1
                    except httpx.HTTPError:
                        break

                if success_count >= 8:
                    findings.append({
                        "title": f"Missing Rate Limiting on {endpoint}",
                        "severity": "medium",
                        "confidence": 80,
                        "target": url,
                        "endpoint": url,
                        "description": (
                            f"Pentra sent 10 rapid requests to {endpoint} and received "
                            f"{success_count} successful responses without rate limiting."
                        ),
                        "tool_source": "web_interact",
                        "vulnerability_type": "missing_rate_limit",
                        "surface": "web",
                        "route_group": _route_group(url),
                    })
        return findings

    async def run_parameter_tampering(
        self,
        *,
        base_url: str,
        scan_config: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Tamper with price/quantity fields in discovered forms."""
        stateful = _stateful_config(scan_config)
        if not stateful.get("parameter_tampering", True):
            return []

        findings: list[dict[str, Any]] = []
        credential = _preferred_workflow_credential(scan_config)

        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=10.0,
            headers={"User-Agent": "Pentra-ParamTamper/phase8"},
        ) as client:
            if credential is not None:
                await self._login(
                    client=client,
                    base_url=base_url,
                    scan_config=scan_config,
                    credentials=credential,
                )

            tamper_paths = _string_list(stateful.get("tamper_endpoints")) or [
                "/portal/checkout/confirm", "/api/v1/orders",
            ]
            for path in tamper_paths[:3]:
                url = _join_url(base_url, path)
                for field, original, tampered in [
                    ("price", "29.99", "0.01"),
                    ("quantity", "1", "-1"),
                    ("discount", "0", "100"),
                ]:
                    try:
                        resp = await client.post(
                            url,
                            data={field: tampered, "item_id": "widget-7", "csrf_token": "demo-csrf"},
                        )
                        if resp.status_code == 200 and "error" not in resp.text.lower():
                            findings.append({
                                "title": f"Parameter Tampering Accepted: {field}={tampered}",
                                "severity": "high",
                                "confidence": 75,
                                "target": url,
                                "endpoint": url,
                                "description": (
                                    f"Server accepted {field}={tampered} (original: {original}) "
                                    f"without validation."
                                ),
                                "tool_source": "web_interact",
                                "vulnerability_type": "parameter_tampering",
                                "payload": f"{field}={tampered}",
                                "surface": "web",
                                "route_group": _route_group(url),
                            })
                            break  # One finding per endpoint is enough
                    except httpx.HTTPError:
                        continue
        return findings

    async def run_role_switch_test(
        self,
        *,
        base_url: str,
        scan_config: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Access admin-only pages with lower-privilege credentials."""
        credentials = _auth_credentials(scan_config)
        if len(credentials) < 2:
            return []

        admin_creds = [c for c in credentials if str(c.get("role") or "").lower() in {"admin", "superuser"}]
        user_creds = [c for c in credentials if c not in admin_creds]
        if not admin_creds or not user_creds:
            return []

        stateful = _stateful_config(scan_config)
        admin_paths = _string_list(stateful.get("admin_paths")) or [
            "/admin", "/admin/users", "/portal/admin/settings",
        ]
        findings: list[dict[str, Any]] = []

        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=10.0,
            headers={"User-Agent": "Pentra-RoleSwitch/phase8"},
        ) as client:
            login_result = await self._login(
                client=client,
                base_url=base_url,
                scan_config=scan_config,
                credentials=user_creds[0],
            )
            if not login_result["success"]:
                return []

            for path in admin_paths[:4]:
                url = _join_url(base_url, path)
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200 and "admin" in resp.text.lower():
                        findings.append({
                            "title": f"Privilege Escalation — Admin Page Accessible",
                            "severity": "critical",
                            "confidence": 85,
                            "target": url,
                            "endpoint": url,
                            "description": (
                                f"User '{user_creds[0].get('username')}' (role: user) "
                                f"can access admin page {path}."
                            ),
                            "tool_source": "web_interact",
                            "vulnerability_type": "privilege_escalation",
                            "surface": "web",
                            "route_group": _route_group(url),
                        })
                except httpx.HTTPError:
                    continue
        return findings

    async def _crawl_session(
        self,
        *,
        client: httpx.AsyncClient,
        base_url: str,
        start_urls: list[str],
        session_label: str,
        auth_state: str,
        max_depth: int,
        max_pages: int,
        max_replays: int,
        max_script_assets: int,
        extra_workflow: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        queue: list[tuple[str, int, str | None]] = []
        seen_urls: set[str] = set()
        queued_urls: set[str] = set()
        seen_script_urls: set[str] = set()
        pages: list[dict[str, Any]] = []
        forms: list[dict[str, Any]] = []
        workflows: list[dict[str, Any]] = []
        replays: list[dict[str, Any]] = []

        if extra_workflow is not None:
            workflows.append({**extra_workflow, "workflow_key": _workflow_key(extra_workflow)})

        for url in start_urls:
            normalized = _normalize_discovery_url(base_url, url)
            if normalized:
                queue.append((normalized, 0, None))
                queued_urls.add(normalized)

        while queue and len(pages) < max_pages:
            url, depth, source_url = queue.pop(0)
            queued_urls.discard(url)
            if url in seen_urls:
                continue
            seen_urls.add(url)
            requested_url = url

            try:
                response = await client.get(url)
            except httpx.HTTPError:
                continue

            content_type = response.headers.get("content-type", "")
            body = response.text
            page_record = {
                "page_key": f"{session_label}:{requested_url}",
                "url": requested_url if urlparse(requested_url).fragment else str(response.url),
                "title": "",
                "status_code": response.status_code,
                "surface": "web",
                "session_label": session_label,
                "auth_state": auth_state,
                "requires_auth": auth_state != "none",
                "content_length": len(body),
                "content_type": content_type,
                "response_preview": body[:4000],
                "route_group": _browser_route_group(requested_url if urlparse(requested_url).fragment else str(response.url)),
                "source_url": source_url,
                "entity_key": _entity_key("endpoint", requested_url if urlparse(requested_url).fragment else str(response.url)),
            }
            detection = _infer_discovery_finding(
                target_url=str(response.url),
                status_code=response.status_code,
                content_type=content_type,
                body=body,
            )
            if detection:
                page_record.update(detection)

            if source_url:
                workflow = {
                    "source_url": source_url,
                    "target_url": str(response.url),
                    "action": "navigate",
                    "requires_auth": auth_state != "none",
                    "session_label": session_label,
                }
                workflow["workflow_key"] = _workflow_key(workflow)
                workflows.append(workflow)

            if _looks_like_script_asset(target_url=str(response.url), content_type=content_type):
                signal_markers = _extract_dom_xss_markers(body)
                page_record["dom_sink_markers"] = signal_markers["sink_markers"]
                page_record["dom_source_markers"] = signal_markers["source_markers"]
                page_record["script_signal_count"] = len(signal_markers["sink_markers"]) + len(
                    signal_markers["source_markers"]
                )
                pages.append(page_record)
                discovered_urls = _extract_script_discovery_urls(base_url, body)
                pages.extend(
                    _build_script_discovery_pages(
                        discovered_urls=discovered_urls,
                        source_url=str(response.url),
                        signal_markers=signal_markers,
                        session_label=session_label,
                        auth_state=auth_state,
                    )
                )
                for discovered_url in discovered_urls:
                    if depth + 1 > max_depth:
                        continue
                    if discovered_url in seen_urls or discovered_url in queued_urls:
                        continue
                    queue.append((discovered_url, depth + 1, str(response.url)))
                    queued_urls.add(discovered_url)
                continue

            if "html" not in content_type.lower():
                pages.append(page_record)
                continue

            parser = _DiscoveryParser()
            parser.feed(body)
            page_record["title"] = parser.title or urlparse(str(response.url)).path or str(response.url)
            inline_script_markers = _extract_dom_xss_markers("\n".join(parser.inline_scripts))
            page_record["dom_sink_markers"] = inline_script_markers["sink_markers"]
            page_record["dom_source_markers"] = inline_script_markers["source_markers"]
            page_record["inline_script_count"] = len(parser.inline_scripts)
            pages.append(page_record)

            inline_script_urls = _dedupe_strings(
                [
                    discovered
                    for script_content in parser.inline_scripts
                    for discovered in _extract_script_discovery_urls(base_url, script_content)
                ]
            )
            pages.extend(
                _build_script_discovery_pages(
                    discovered_urls=inline_script_urls,
                    source_url=str(response.url),
                    signal_markers=inline_script_markers,
                    session_label=session_label,
                    auth_state=auth_state,
                )
            )

            for candidate_url in [*parser.links, *parser.ajax_urls, *inline_script_urls]:
                next_url = _normalize_discovery_url(base_url, urljoin(str(response.url), candidate_url))
                if not next_url:
                    continue
                if depth + 1 <= max_depth and next_url not in seen_urls and next_url not in queued_urls:
                    queue.append((next_url, depth + 1, str(response.url)))
                    queued_urls.add(next_url)

            for script_ref in parser.script_urls:
                if len(seen_script_urls) >= max_script_assets:
                    break
                script_url = _normalize_discovery_url(base_url, urljoin(str(response.url), script_ref))
                if not script_url or script_url in seen_script_urls:
                    continue
                if not _looks_like_script_asset(target_url=script_url, content_type=""):
                    continue
                seen_script_urls.add(script_url)
                if depth + 1 <= max_depth and script_url not in seen_urls and script_url not in queued_urls:
                    queue.append((script_url, depth + 1, str(response.url)))
                    queued_urls.add(script_url)

            for parsed_form in parser.forms:
                action_url = _normalize_discovery_url(
                    base_url,
                    urljoin(str(response.url), parsed_form.action or str(response.url)),
                )
                if not action_url:
                    continue

                hidden_fields = {
                    field.name: field.value
                    for field in parsed_form.inputs
                    if field.input_type == "hidden"
                }
                form_fields = [field.name for field in parsed_form.inputs]
                field_type_map = {
                    field.name: field.input_type
                    for field in parsed_form.inputs
                    if field.name
                }
                file_field_names = sorted(
                    field.name
                    for field in parsed_form.inputs
                    if field.input_type == "file" and field.name
                )
                form_record = {
                    "form_key": f"{session_label}:{str(response.url)}:{action_url}:{parsed_form.method}",
                    "page_url": str(response.url),
                    "action_url": action_url,
                    "method": parsed_form.method.upper(),
                    "enctype": parsed_form.enctype,
                    "multipart": "multipart/form-data" in parsed_form.enctype,
                    "field_names": form_fields,
                    "field_type_map": field_type_map,
                    "file_field_names": file_field_names,
                    "hidden_field_names": sorted(hidden_fields.keys()),
                    "hidden_fields": hidden_fields if hidden_fields else {},
                    "has_csrf": any("csrf" in name.lower() for name in hidden_fields),
                    "requires_auth": auth_state != "none",
                    "session_label": session_label,
                    "safe_replay": str(hidden_fields.get("pentra_safe_replay", "")).lower() == "true",
                    "entity_key": _entity_key("endpoint", action_url),
                }
                forms.append(form_record)

                workflow = {
                    "source_url": str(response.url),
                    "target_url": action_url,
                    "action": "login" if _looks_like_login_form(form_fields) else "submit",
                    "requires_auth": auth_state != "none",
                    "session_label": session_label,
                }
                workflow["workflow_key"] = _workflow_key(workflow)
                workflows.append(workflow)

                if len(replays) >= max_replays:
                    continue
                if not form_record["safe_replay"] and not _looks_like_login_form(form_fields):
                    continue

                replay = await self._replay_form(
                    client=client,
                    action_url=action_url,
                    parsed_form=parsed_form,
                    response_url=str(response.url),
                    session_label=session_label,
                )
                if replay is not None:
                    replays.append(replay)

        return {
            "pages": pages,
            "forms": forms,
            "workflows": workflows,
            "replays": replays,
            "landing_url": pages[0]["url"] if pages else (start_urls[0] if start_urls else base_url),
        }

    async def _login(
        self,
        *,
        client: httpx.AsyncClient,
        base_url: str,
        scan_config: dict[str, Any],
        credentials: dict[str, Any],
    ) -> dict[str, Any]:
        stateful = _stateful_config(scan_config)
        auth = stateful.get("auth", {})
        if not isinstance(auth, dict):
            auth = {}

        bootstrap_success = await self._bootstrap_credential(
            client=client,
            base_url=base_url,
            credentials=credentials,
        )
        if not bootstrap_success:
            return {"success": False}

        if str(auth.get("login_api_path") or "").strip():
            api_login = await self._login_via_api(
                client=client,
                base_url=base_url,
                auth=auth,
                credentials=credentials,
            )
            if api_login["success"]:
                return api_login

        login_page_url = _join_url(base_url, str(auth.get("login_page_path") or "/login"))
        username_field = str(auth.get("username_field") or "username")
        password_field = str(auth.get("password_field") or "password")
        success_path = str(auth.get("success_path_contains") or "/dashboard")
        session_label = str(credentials.get("label") or credentials.get("username") or "authenticated")
        auth_state = "elevated" if str(credentials.get("role") or "").lower() in {"admin", "superuser"} else "authenticated"

        response = await client.get(login_page_url)
        parser = _DiscoveryParser()
        parser.feed(response.text)
        login_form = next(
            (
                form
                for form in parser.forms
                if _looks_like_login_form([field.name for field in form.inputs])
            ),
            None,
        )
        if login_form is None:
            return {"success": False}

        action_url = _join_url(base_url, login_form.action or "/login")
        payload = {
            field.name: field.value
            for field in login_form.inputs
            if field.input_type == "hidden" and field.name
        }
        payload[username_field] = str(credentials.get("username") or "")
        payload[password_field] = str(credentials.get("password") or "")

        login_response = await client.post(action_url, data=payload)
        landing_url = str(login_response.url)
        if success_path and success_path not in landing_url and success_path not in login_response.text:
            return {"success": False}

        session = {
            "session_label": session_label,
            "auth_state": auth_state,
            "role": credentials.get("role") or "user",
            "cookie_names": sorted(client.cookies.keys()),
            "csrf_tokens": sorted(
                [
                    value
                    for key, value in payload.items()
                    if "csrf" in key.lower() and value
                ]
            ),
            "login_url": action_url,
            "landing_url": landing_url,
        }
        return {
            "success": True,
            "session": session,
            "login_url": action_url,
            "landing_url": landing_url,
        }

    async def _login_via_api(
        self,
        *,
        client: httpx.AsyncClient,
        base_url: str,
        auth: dict[str, Any],
        credentials: dict[str, Any],
    ) -> dict[str, Any]:
        login_api_path = str(auth.get("login_api_path") or "").strip()
        if not login_api_path:
            return {"success": False}

        username_field = str(auth.get("username_field") or "username").strip() or "username"
        password_field = str(auth.get("password_field") or "password").strip() or "password"
        request_format = str(auth.get("login_request_format") or "json").strip().lower()
        success_path = str(auth.get("success_path_contains") or "").strip()
        whoami_path = str(auth.get("whoami_path") or "").strip()
        token_json_path = str(auth.get("token_json_path") or "authentication.token").strip()
        post_login_path = str(auth.get("post_login_path") or whoami_path or "/").strip() or "/"
        login_url = _join_url(base_url, login_api_path)

        payload: dict[str, Any] = {}
        extra_payload = auth.get("login_payload")
        if isinstance(extra_payload, dict):
            payload.update({str(key): value for key, value in extra_payload.items()})
        payload[username_field] = str(
            credentials.get("username")
            or credentials.get("email")
            or ""
        )
        payload[password_field] = str(credentials.get("password") or "")

        request_kwargs = {"json": payload} if request_format == "json" else {"data": payload}
        response = await client.post(login_url, **request_kwargs)
        if response.status_code >= 400:
            return {"success": False}

        response_json: dict[str, Any] | None = None
        try:
            candidate = response.json()
            response_json = candidate if isinstance(candidate, dict) else None
        except ValueError:
            response_json = None

        token = _extract_nested_string(response_json, token_json_path)
        if token:
            client.headers["Authorization"] = f"Bearer {token}"

        user_email = str(credentials.get("username") or credentials.get("email") or "").strip()
        if user_email:
            client.headers["X-User-Email"] = user_email

        whoami_ok = False
        if whoami_path:
            try:
                whoami_response = await client.get(_join_url(base_url, whoami_path))
                whoami_ok = whoami_response.status_code < 400
            except httpx.HTTPError:
                whoami_ok = False

        success = False
        if whoami_ok or token:
            success = True
        elif success_path and (
            success_path in str(response.url)
            or success_path.lower() in response.text.lower()
        ):
            success = True
        elif response_json and "authentication" in response_json:
            success = True

        if not success:
            return {"success": False}

        session_label = str(credentials.get("label") or credentials.get("username") or "authenticated")
        auth_state = (
            "elevated"
            if str(credentials.get("role") or "").lower() in {"admin", "superuser"}
            else "authenticated"
        )
        landing_url = _join_url(base_url, post_login_path)
        session = {
            "session_label": session_label,
            "auth_state": auth_state,
            "auth_method": "api_login",
            "role": credentials.get("role") or "user",
            "cookie_names": sorted(client.cookies.keys()),
            "csrf_tokens": [],
            "login_url": login_url,
            "landing_url": landing_url,
        }
        return {
            "success": True,
            "session": session,
            "login_url": login_url,
            "landing_url": landing_url,
        }

    async def _run_enabled_stateful_probes(
        self,
        *,
        base_url: str,
        scan_config: dict[str, Any],
    ) -> list[dict[str, Any]]:
        probes = _stateful_probe_settings(scan_config)
        findings: list[dict[str, Any]] = []

        if probes.get("role_switch"):
            findings.extend(
                await self.run_role_switch_test(
                    base_url=base_url,
                    scan_config=scan_config,
                )
            )
        if probes.get("parameter_tampering"):
            findings.extend(
                await self.run_parameter_tampering(
                    base_url=base_url,
                    scan_config=scan_config,
                )
            )
        if probes.get("rate_limit"):
            findings.extend(
                await self.run_rate_limit_check(
                    base_url=base_url,
                    scan_config=scan_config,
                )
            )
        return findings

    async def _bootstrap_credential(
        self,
        *,
        client: httpx.AsyncClient,
        base_url: str,
        credentials: dict[str, Any],
    ) -> bool:
        bootstrap = credentials.get("bootstrap")
        if not isinstance(bootstrap, dict):
            return True

        mode = str(bootstrap.get("mode") or "").strip().lower()
        if not mode:
            return True
        if mode == "juice_shop_register":
            return await self._bootstrap_juice_shop_registration(
                client=client,
                base_url=base_url,
                credentials=credentials,
                bootstrap=bootstrap,
            )
        return True

    async def _bootstrap_juice_shop_registration(
        self,
        *,
        client: httpx.AsyncClient,
        base_url: str,
        credentials: dict[str, Any],
        bootstrap: dict[str, Any],
    ) -> bool:
        email = str(credentials.get("username") or credentials.get("email") or "").strip()
        password = str(credentials.get("password") or "").strip()
        if not email or not password:
            return False

        question_id = int(bootstrap.get("security_question_id") or 1)
        security_answer = str(
            bootstrap.get("security_answer") or "pentra-bootstrap"
        ).strip() or "pentra-bootstrap"

        questions_url = _join_url(
            base_url,
            str(bootstrap.get("questions_api_path") or "/api/SecurityQuestions/"),
        )
        register_url = _join_url(
            base_url,
            str(bootstrap.get("register_api_path") or "/api/Users/"),
        )
        answers_url = _join_url(
            base_url,
            str(bootstrap.get("security_answers_api_path") or "/api/SecurityAnswers/"),
        )

        try:
            question_response = await client.get(questions_url)
            if question_response.status_code >= 400:
                return False
            questions_payload = question_response.json()
            questions = _data_items(questions_payload)
            selected_question = next(
                (
                    item
                    for item in questions
                    if int(item.get("id") or 0) == question_id
                ),
                None,
            ) or (questions[0] if questions else None)
            if not isinstance(selected_question, dict):
                return False

            register_payload = {
                "email": email,
                "password": password,
                "passwordRepeat": password,
                "securityQuestion": selected_question,
                "securityAnswer": security_answer,
            }
            register_response = await client.post(register_url, json=register_payload)

            if register_response.status_code == 409:
                return True
            if register_response.status_code >= 400:
                body = register_response.text.lower()
                return "already exists" in body or "duplicate" in body

            register_payload_json = register_response.json()
            user_id = _extract_numeric_id(register_payload_json)
            if not user_id:
                return True

            security_answer_response = await client.post(
                answers_url,
                json={
                    "UserId": user_id,
                    "answer": security_answer,
                    "SecurityQuestionId": int(selected_question.get("id") or question_id),
                },
            )
            if security_answer_response.status_code == 409:
                return True
            return security_answer_response.status_code < 400
        except Exception:
            return False

    async def _replay_form(
        self,
        *,
        client: httpx.AsyncClient,
        action_url: str,
        parsed_form: _ParsedForm,
        response_url: str,
        session_label: str,
    ) -> dict[str, Any] | None:
        payload = _build_safe_form_payload(parsed_form.inputs)
        if not payload:
            return None

        if parsed_form.method.lower() == "get":
            replay_response = await client.get(action_url, params=payload)
            request_target = f"GET {action_url}?{urlencode(payload)}"
        else:
            replay_response = await client.post(action_url, data=payload)
            request_target = f"POST {action_url}"

        replay = {
            "replay_key": f"{session_label}:{request_target}",
            "request": request_target,
            "target_url": action_url,
            "session_label": session_label,
            "status_code": replay_response.status_code,
            "response_preview": replay_response.text[:500],
            "source_url": response_url,
        }
        return replay

    async def _replay_sequence(
        self,
        client: httpx.AsyncClient,
        sequence_urls: list[str],
    ) -> httpx.Response:
        response: httpx.Response | None = None
        for url in sequence_urls:
            response = await client.get(url)
        assert response is not None
        return response

    async def _submit_skip_step(
        self,
        *,
        client: httpx.AsyncClient,
        candidate_url: str,
        csrf_token: str,
    ) -> httpx.Response:
        return await client.post(
            candidate_url,
            data={
                "csrf_token": csrf_token,
                "item_id": "widget-7",
                "quantity": "2",
                "pentra_safe_replay": "true",
            },
        )


def _auth_credentials(scan_config: dict[str, Any]) -> list[dict[str, Any]]:
    auth = _stateful_config(scan_config).get("auth", {})
    if not isinstance(auth, dict):
        return []
    credentials = auth.get("credentials", [])
    if not isinstance(credentials, list):
        return []
    return [credential for credential in credentials if isinstance(credential, dict)]


def _preferred_workflow_credential(scan_config: dict[str, Any]) -> dict[str, Any] | None:
    credentials = _auth_credentials(scan_config)
    if not credentials:
        return None
    for credential in credentials:
        if str(credential.get("role") or "").lower() != "admin":
            return credential
    return credentials[0]


def _stateful_config(scan_config: dict[str, Any]) -> dict[str, Any]:
    value = scan_config.get("stateful_testing", {})
    return value if isinstance(value, dict) else {}


def _stateful_probe_settings(scan_config: dict[str, Any]) -> dict[str, bool]:
    value = _stateful_config(scan_config).get("probes", {})
    if not isinstance(value, dict):
        return {}
    return {
        key: bool(value.get(key))
        for key in ("role_switch", "parameter_tampering", "rate_limit")
    }


def _extract_ajax_urls(script_content: str) -> list[str]:
    """Extract API endpoint URLs from JavaScript source (fetch/XHR patterns)."""
    patterns = [
        r"""fetch\s*\(\s*['"]([^'"]+)['"]""",            # fetch('/api/...')
        r"""\.open\s*\(\s*['"][A-Z]+['"]\s*,\s*['"]([^'"]+)['"]""",  # xhr.open('GET', '/api/...')
        r"""axios\s*\.\w+\s*\(\s*['"]([^'"]+)['"]""",    # axios.get('/api/...')
        r"""\.\s*(?:get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]""",
        r"""url\s*:\s*['"]([^'"]+api[^'"]+)['"]""",       # url: '/api/...'
    ]
    urls: list[str] = []
    for pattern in patterns:
        for match in re.finditer(pattern, script_content):
            candidate = match.group(1).strip()
            if candidate and candidate.startswith("/"):
                urls.append(candidate)
    return urls


def _client_route_links_from_attrs(attr_map: dict[str, str]) -> list[str]:
    candidates: list[str] = []
    for key in ("routerlink", "ng-reflect-router-link", "data-router-link", "data-route"):
        value = attr_map.get(key, "").strip()
        if value:
            candidates.extend(_expand_client_route_candidate(value))
    return _dedupe_strings(candidates)


def _expand_client_route_candidate(candidate: str) -> list[str]:
    normalized = candidate.strip().replace("\\/", "/")
    if not normalized:
        return []
    lowered = normalized.lower()
    if lowered.startswith(("http://", "https://", "//", "javascript:", "mailto:", "tel:")):
        return []
    if normalized.startswith("/#/"):
        return [normalized]
    if normalized.startswith("#/"):
        return [f"/{normalized}"]
    if normalized.startswith("#"):
        return []
    trimmed = normalized.lstrip("/")
    if not _looks_like_client_route_path(trimmed):
        return []
    return [f"/#/{trimmed}"]


def _looks_like_client_route_path(candidate: str) -> bool:
    normalized = candidate.strip().strip("/")
    if not normalized or len(normalized) > 80:
        return False
    lowered = normalized.lower()
    if normalized != lowered:
        return False
    if lowered in {"*", "**"}:
        return False
    if lowered.startswith(("api/", "rest/", "graphql", "assets/", "static/", ".well-known/")):
        return False
    if any(char in normalized for char in (".", "{", "}", "<", ">", "(", ")", "$")):
        return False
    segments = [segment for segment in normalized.split("/") if segment]
    if not segments:
        return False
    if any(segment in {"*", "**"} or segment.startswith(":") for segment in segments):
        return False
    return all(re.fullmatch(r"[A-Za-z0-9_-]+", segment) for segment in segments)


def _extract_script_route_candidates(script_content: str) -> list[str]:
    routes: list[str] = []
    patterns = [
        r"""['"](/#/[^'"]+)['"]""",
        r"""['"](#/[^'"]+)['"]""",
        r"""(?:path|redirectTo)\s*:\s*['"]([^'"]+)['"]""",
        r"""(?:routerLink|router-link)\s*[:=]\s*['"]([^'"]+)['"]""",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, script_content):
            routes.extend(_expand_client_route_candidate(match.group(1)))
    return _dedupe_strings(routes)


def _extract_script_discovery_urls(base_url: str, script_content: str) -> list[str]:
    discovered: list[str] = []
    for candidate in _extract_ajax_urls(script_content):
        normalized = _normalize_discovery_url(base_url, candidate)
        if normalized:
            discovered.append(normalized)
    for candidate in _extract_script_route_candidates(script_content):
        normalized = _normalize_discovery_url(base_url, candidate)
        if normalized:
            discovered.append(normalized)
    return _dedupe_strings(discovered)


def _build_script_discovery_pages(
    *,
    discovered_urls: list[str],
    source_url: str,
    signal_markers: dict[str, list[str]],
    session_label: str,
    auth_state: str,
) -> list[dict[str, Any]]:
    sink_markers = [str(marker).strip() for marker in signal_markers.get("sink_markers") or [] if str(marker).strip()]
    source_markers = [str(marker).strip() for marker in signal_markers.get("source_markers") or [] if str(marker).strip()]
    if not discovered_urls or (not sink_markers and not source_markers):
        return []
    signal_count = len(sink_markers) + len(source_markers)
    pages: list[dict[str, Any]] = []
    for discovered_url in _dedupe_strings(discovered_urls):
        pages.append(
            {
                "page_key": f"{session_label}:script-discovery:{discovered_url}",
                "url": discovered_url,
                "title": f"Script-discovered route {_browser_route_group(discovered_url)}",
                "status_code": 200,
                "surface": "web",
                "session_label": session_label,
                "auth_state": auth_state,
                "requires_auth": auth_state != "none",
                "content_length": 0,
                "content_type": "text/x-pentra-script-discovery",
                "response_preview": "",
                "route_group": _browser_route_group(discovered_url),
                "source_url": source_url,
                "entity_key": _entity_key("endpoint", discovered_url),
                "dom_sink_markers": sink_markers[:],
                "dom_source_markers": source_markers[:],
                "script_signal_count": signal_count,
                "synthetic_discovery": True,
                "discovery_source": "client_script",
            }
        )
    return pages


def _extract_dom_xss_markers(script_content: str) -> dict[str, list[str]]:
    return _capability_extract_dom_xss_markers(script_content)


def _browser_route_group(target_url: str) -> str:
    parsed = urlparse(target_url)
    if parsed.fragment.startswith("/"):
        fragment_path = parsed.fragment.split("?", 1)[0].strip("/")
        return f"/#/{fragment_path}" if fragment_path else "/#"
    return _route_group(target_url) or "/"


def _xss_settings(scan_config: dict[str, Any]) -> dict[str, Any]:
    value = _stateful_config(scan_config).get("xss", {})
    return value if isinstance(value, dict) else {}


def _xss_seed_paths(scan_config: dict[str, Any]) -> list[str]:
    settings = _xss_settings(scan_config)
    seed_paths = _string_list(settings.get("seed_paths"))
    return _dedupe_strings(seed_paths)


def _is_xss_candidate_parameter(name: str) -> bool:
    lowered = name.strip().lower()
    return lowered in {
        "q",
        "query",
        "search",
        "term",
        "s",
        "message",
        "comment",
        "feedback",
        "name",
        "redirect",
        "returnurl",
    }


def _request_url_for_seed(base_url: str, seed_path: str) -> str:
    if seed_path.startswith("http://") or seed_path.startswith("https://"):
        return seed_path
    if seed_path.startswith("/#"):
        return base_url.rstrip("/") + seed_path
    return _join_url(base_url, seed_path)


def _candidate_from_request_url(request_url: str) -> tuple[str, str | None]:
    parsed = urlparse(request_url)
    query = list(parse_qsl(parsed.query, keep_blank_values=True))
    if query:
        key, _ = query[0]
        return "query", key

    fragment = parsed.fragment or ""
    _, has_hash_query, fragment_query = fragment.partition("?")
    if has_hash_query:
        fragment_pairs = list(parse_qsl(fragment_query, keep_blank_values=True))
        if fragment_pairs:
            key, _ = fragment_pairs[0]
            return "hash_query", key
    if fragment:
        return "hash_fragment", None
    return "query", None


def _build_browser_xss_candidates(
    *,
    base_url: str,
    scan_config: dict[str, Any],
    pages: list[dict[str, Any]],
    forms: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return build_browser_xss_pack(
        base_url=base_url,
        scan_config=scan_config,
        pages=pages,
        forms=forms,
    )["candidates"]


def _build_xss_candidate(
    *,
    request_url: str,
    page_url: str,
    sink_markers: list[str],
    source_markers: list[str],
    field_names: list[str],
) -> dict[str, Any] | None:
    if not sink_markers:
        return None

    candidate_kind, parameter_name = _candidate_from_request_url(request_url)
    if candidate_kind in {"query", "hash_query"} and not parameter_name:
        return None
    if candidate_kind == "query" and not _is_xss_candidate_parameter(parameter_name or ""):
        return None

    confidence = 70
    if source_markers:
        confidence += 10
    if parameter_name and _is_xss_candidate_parameter(parameter_name):
        confidence += 6
    if candidate_kind.startswith("hash"):
        confidence += 4
    confidence = min(confidence, 88)

    route_group = _browser_route_group(request_url)
    parameter_summary = parameter_name or "fragment"
    sink_summary = ", ".join(sink_markers[:3])
    source_summary = ", ".join(source_markers[:3]) or "dynamic browser input"
    title = "Browser-backed XSS candidate"
    description = (
        "Loaded client-side scripts referenced DOM XSS sink markers "
        f"({sink_summary}) and source markers ({source_summary}). "
        f"Pentra generated a route-specific browser verification seed for {parameter_summary}."
    )

    candidate_key = f"{route_group}:{candidate_kind}:{parameter_name or 'fragment'}"
    return {
        "candidate_key": candidate_key,
        "url": request_url,
        "target": request_url,
        "endpoint": request_url,
        "title": title,
        "severity": "medium",
        "confidence": confidence,
        "description": description,
        "tool_source": "web_interact",
        "vulnerability_type": "xss",
        "request": f"GET {request_url}",
        "payload": candidate_kind,
        "surface": "web",
        "route_group": route_group,
        "verification_state": "suspected",
        "verification_confidence": confidence,
        "references": [f"sink:{marker}" for marker in sink_markers[:4]] + [
            f"source:{marker}" for marker in source_markers[:4]
        ],
        "verification_context": {
            "verify_type": "xss_browser",
            "page_url": page_url,
            "request_url": request_url,
            "candidate_kind": candidate_kind,
            "parameter_name": parameter_name,
            "sink_markers": sink_markers[:6],
            "source_markers": source_markers[:6],
            "field_names": field_names[:8],
        },
    }


def _api_token_credentials(scan_config: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract API-token auth configurations from scan_config."""
    stateful = _stateful_config(scan_config)
    auth = stateful.get("auth", {})
    if not isinstance(auth, dict):
        return []
    tokens = auth.get("api_tokens", [])
    if not isinstance(tokens, list):
        return []
    return [t for t in tokens if isinstance(t, dict) and (t.get("token") or t.get("api_key"))]


def _build_auth_header(token_config: dict[str, Any]) -> dict[str, str]:
    """Build an HTTP auth header from a token configuration."""
    token = str(token_config.get("token") or "").strip()
    api_key = str(token_config.get("api_key") or "").strip()
    header_name = str(token_config.get("header") or "").strip()

    if token:
        return {"Authorization": f"Bearer {token}"}
    if api_key and header_name:
        return {header_name: api_key}
    if api_key:
        return {"X-API-Key": api_key}
    return {}


def _data_items(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        data = payload.get("data")
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        return [payload]
    return []


def _extract_numeric_id(payload: Any) -> int | None:
    if isinstance(payload, dict):
        if isinstance(payload.get("id"), int):
            return int(payload["id"])
        data = payload.get("data")
        if isinstance(data, dict) and isinstance(data.get("id"), int):
            return int(data["id"])
    return None


def _dedupe_probe_findings(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[str, dict[str, Any]] = {}
    for item in items:
        key = "|".join(
            [
                str(item.get("vulnerability_type") or "").strip().lower(),
                str(item.get("route_group") or item.get("endpoint") or item.get("target") or "").strip().lower(),
                str(item.get("title") or "").strip().lower(),
            ]
        )
        if key and key not in deduped:
            deduped[key] = item
    return list(deduped.values())


def _selected_checks(scan_config: dict[str, Any]) -> dict[str, Any]:
    value = scan_config.get("selected_checks", {})
    return value if isinstance(value, dict) else {}


def _discovery_seed_paths(scan_config: dict[str, Any]) -> list[str]:
    stateful = _stateful_config(scan_config)
    selected_checks = _selected_checks(scan_config)
    auth = stateful.get("auth", {})

    seed_paths: list[str] = []
    seed_paths.extend(_string_list(stateful.get("seed_paths")))
    seed_paths.extend(_string_list(selected_checks.get("content_paths")))
    seed_paths.extend(_string_list(selected_checks.get("http_probe_paths")))

    if isinstance(auth, dict):
        for candidate in (
            auth.get("login_page_path"),
            auth.get("login_api_path"),
            auth.get("whoami_path"),
            auth.get("post_login_path"),
        ):
            value = str(candidate or "").strip()
            if value:
                seed_paths.append(value)

    if not seed_paths:
        return ["/"]
    return _dedupe_strings(seed_paths)



def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _bounded_int(value: Any, *, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(parsed, maximum))


def _dedupe_dicts(items: list[dict[str, Any]], *, key: str) -> list[dict[str, Any]]:
    seen: dict[str, dict[str, Any]] = {}
    for item in items:
        identity = str(item.get(key) or "")
        if not identity:
            continue
        seen.setdefault(identity, item)
    return list(seen.values())


def _dedupe_strings(items: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for item in items:
        normalized = str(item).strip()
        if normalized:
            seen.setdefault(normalized, None)
    return list(seen.keys())


def _normalize_discovery_url(base_url: str, candidate: str) -> str:
    if not candidate:
        return ""
    parsed_base = urlparse(base_url)
    normalized = urljoin(base_url.rstrip("/") + "/", candidate)
    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"}:
        return ""
    if parsed.netloc != parsed_base.netloc:
        return ""
    if parsed.fragment and not parsed.fragment.startswith("/"):
        parsed = parsed._replace(fragment="")
    return parsed.geturl()


def _join_url(base_url: str, candidate: str) -> str:
    candidate = candidate.strip()
    if not candidate:
        return base_url.rstrip("/")
    if candidate.startswith("http://") or candidate.startswith("https://"):
        return candidate
    return urljoin(base_url.rstrip("/") + "/", candidate.lstrip("/"))


def _looks_like_script_asset(*, target_url: str, content_type: str) -> bool:
    lowered_type = content_type.lower()
    lowered_path = (urlparse(target_url).path or "").lower()
    return (
        "javascript" in lowered_type
        or "ecmascript" in lowered_type
        or lowered_path.endswith(".js")
        or lowered_path.endswith(".mjs")
    )


def _extract_nested_string(payload: dict[str, Any] | None, path: str) -> str:
    if not isinstance(payload, dict) or not path.strip():
        return ""
    current: Any = payload
    for segment in path.split("."):
        key = segment.strip()
        if not key or not isinstance(current, dict) or key not in current:
            return ""
        current = current[key]
    return str(current).strip() if current is not None else ""


def _route_group(target: str | None) -> str | None:
    if not target:
        return None
    parsed = urlparse(target)
    if not parsed.path:
        return "/"
    segments = [segment for segment in parsed.path.split("/") if segment]
    normalized: list[str] = []
    for segment in segments[:4]:
        normalized.append("{id}" if segment.isdigit() else segment)
    return "/" + "/".join(normalized)


def _entity_key(kind: str, value: str) -> str:
    return f"{kind}:{value.lower()}"


def _looks_like_login_form(field_names: list[str]) -> bool:
    lowered = {field.lower() for field in field_names}
    return any(name in lowered for name in {"username", "email", "login"}) and "password" in lowered


def _build_safe_form_payload(inputs: list[_FormInput]) -> dict[str, str]:
    payload: dict[str, str] = {}
    for field in inputs:
        if not field.name:
            continue
        lowered = field.name.lower()
        if field.input_type == "hidden":
            payload[field.name] = field.value
        elif field.input_type == "file":
            payload[field.name] = field.value or "pentra-safe-upload.txt"
        elif lowered in {"username", "email", "password"}:
            continue
        elif lowered in {"item_id", "order_id"}:
            payload[field.name] = field.value or "widget-7"
        elif lowered in {"quantity", "qty"}:
            payload[field.name] = field.value or "1"
        elif lowered in {"query", "search", "term"}:
            payload[field.name] = field.value or "pentra"
        else:
            payload[field.name] = field.value or "pentra-safe"
    return payload


def _workflow_key(item: dict[str, Any]) -> str:
    return ":".join(
        [
            str(item.get("session_label") or ""),
            str(item.get("action") or ""),
            str(item.get("source_url") or ""),
            str(item.get("target_url") or ""),
        ]
    )


def _response_payload(response: httpx.Response) -> dict[str, Any]:
    return {
        "status_code": response.status_code,
        "body": response.text[:4000],
        "headers": dict(response.headers),
    }


def _format_response_for_evidence(response: dict[str, Any]) -> str:
    headers = "\n".join(
        f"{key}: {value}"
        for key, value in sorted((response.get("headers") or {}).items())
        if key.lower() in {"location", "content-type", "set-cookie"}
    )
    return "\n".join(
        [
            f"HTTP/1.1 {response.get('status_code', 0)}",
            headers,
            "",
            str(response.get("body") or ""),
        ]
    ).strip()


def _mutate_identifier(target_url: str) -> str:
    parsed = urlparse(target_url)
    path_segments = [segment for segment in parsed.path.split("/") if segment]
    for index in range(len(path_segments) - 1, -1, -1):
        if path_segments[index].isdigit():
            path_segments[index] = str(int(path_segments[index]) + 1)
            return urlunparse(parsed._replace(path="/" + "/".join(path_segments)))

    query = list(parse_qsl(parsed.query, keep_blank_values=True))
    for index, (key, value) in enumerate(query):
        if value.isdigit():
            query[index] = (key, str(int(value) + 1))
            return urlunparse(parsed._replace(query=urlencode(query)))

    return target_url


def _analyze_workflow_response(
    *,
    response: dict[str, Any],
    mutation_type: str,
    workflow_type: str,
    target_url: str,
) -> dict[str, Any]:
    status = int(response.get("status_code", 0) or 0)
    body = str(response.get("body") or "")
    headers = response.get("headers") or {}
    lowered = body.lower()
    if _looks_like_auth_gate(target_url=target_url, body=lowered):
        return {
            "mutation_type": mutation_type,
            "workflow_type": workflow_type,
            "target_url": target_url,
            "verdict": "negative",
            "confidence": 0.0,
            "flaw_type": "none",
            "evidence": [],
        }
    evidence: list[str] = []
    flaw_type = "none"

    if mutation_type == "skip_step":
        if "order confirmed successfully" in lowered:
            evidence.append("step_bypass_succeeded")
            evidence.append("data_returned_after_skip")
            flaw_type = "workflow_bypass"
    elif mutation_type == "cross_session":
        if status == 200 and any(
            marker in lowered
            for marker in (
                "account details",
                "order history",
                "profile details",
                "admin panel",
                "user profile",
            )
        ):
            evidence.append("unauthenticated_access_succeeded")
            flaw_type = "auth_bypass"
        location = str(headers.get("location") or headers.get("Location") or "").lower()
        if status in {301, 302} and "login" not in location:
            evidence.append("redirect_without_auth_check")
    elif mutation_type == "modify_id":
        if status == 200 and any(
            marker in lowered for marker in ("email", "salary", "account number", "user id", "\"email\"", "\"id\"")
        ):
            evidence.append("different_user_data_returned")
            flaw_type = "idor"
        if any(marker in lowered for marker in ("email", "salary")):
            evidence.append("pii_exposure")
    elif mutation_type == "repeat_step":
        if status == 200 and any(
            marker in lowered
            for marker in ("already processed", "order confirmed", "receipt", "transaction id", "checkout complete")
        ):
            evidence.append("duplicate_operation_succeeded")
            flaw_type = "workflow_bypass"
    elif mutation_type == "swap_order":
        if status == 200 and any(
            marker in lowered
            for marker in ("order confirmed", "checkout complete", "payment successful", "transaction id")
        ):
            evidence.append("reversed_workflow_succeeded")
            flaw_type = "workflow_bypass"

    if status == 200 and mutation_type in {"cross_session", "skip_step"}:
        if any(marker in lowered for marker in ("admin", "role", "privilege")):
            evidence.append("privilege_indicators")
            flaw_type = "privilege_escalation"

    verdict = "negative"
    confidence = 0.0
    strong = {
        "unauthenticated_access_succeeded",
        "different_user_data_returned",
        "step_bypass_succeeded",
        "privilege_indicators",
    }
    has_strong = any(item in strong for item in evidence)
    if evidence:
        verdict = "likely"
        confidence = 0.3
    if has_strong:
        verdict = "likely"
        confidence = min(0.8, 0.4 + len(evidence) * 0.15)
    if len(evidence) >= 3 or (has_strong and len(evidence) >= 2):
        verdict = "confirmed"
        confidence = min(0.95, 0.5 + len(evidence) * 0.15)

    return {
        "mutation_type": mutation_type,
        "workflow_type": workflow_type,
        "target_url": target_url,
        "verdict": verdict,
        "confidence": round(confidence, 2),
        "flaw_type": flaw_type,
        "evidence": evidence,
    }


def _looks_like_auth_gate(*, target_url: str, body: str) -> bool:
    path = (urlparse(target_url).path or "/").lower()
    if path in {"/", "/index.php"}:
        return True
    if "login" in path or "signin" in path or "sign-in" in path:
        return True
    return any(
        marker in body
        for marker in (
            'name="password"',
            'type="password"',
            'label for="pass"',
            'label for="user"',
            "login ::",
            "sign in",
            "log in",
        )
    )


def _infer_discovery_finding(
    *,
    target_url: str,
    status_code: int,
    content_type: str,
    body: str,
) -> dict[str, Any]:
    if status_code not in {200, 401, 403, 500}:
        return {}

    lowered_path = (urlparse(target_url).path or "/").lower()
    lowered_body = body.lower()
    lowered_type = content_type.lower()

    if "application-configuration" in lowered_path and (
        "json" in lowered_type or body.strip().startswith("{")
    ):
        markers = [
            marker
            for marker in (
                '"config"',
                '"baseurl"',
                '"showversionnumber"',
                '"localbackupenabled"',
                '"privacycontactemail"',
                '"chatbot"',
            )
            if marker in lowered_body
        ]
        if markers:
            marker_names = ", ".join(marker.strip('"') for marker in markers[:4])
            return {
                "title": "Exposed application configuration",
                "severity": "high",
                "confidence": 86,
                "description": (
                    "Public application configuration data was returned without authentication. "
                    f"Observed markers: {marker_names}."
                ),
                "tool_source": "web_interact",
                "vulnerability_type": "sensitive_data_exposure",
                "request": f"GET {target_url}",
                "response": _format_response_for_evidence(
                    {
                        "status_code": status_code,
                        "headers": {"content-type": content_type},
                        "body": body[:4000],
                    }
                ),
                "payload": "public_config_probe",
                "exploit_result": (
                    "Configuration endpoint exposed internal application settings without "
                    "authentication."
                ),
                "surface": "api" if "/rest/" in lowered_path else "web",
                "route_group": _route_group(target_url),
                "exploitability": "medium",
                "exploitability_score": 72,
                "verification_state": "detected",
                "verification_confidence": 86,
                "references": [f"marker:{marker.strip('\"')}" for marker in markers[:6]],
            }

    sensitive_api_paths = (
        "/api/users",
        "/rest/user/authentication-details",
    )
    if any(path in lowered_path for path in sensitive_api_paths) and (
        "json" in lowered_type or body.strip().startswith("{")
    ):
        markers = [
            marker
            for marker in (
                "email",
                "role",
                "password",
                "totpsecret",
                "deluxetoken",
                "lastloginip",
                "profileimage",
            )
            if f'"{marker}"' in lowered_body
        ]
        if len(markers) >= 2 and '"data":[{' in lowered_body:
            marker_names = ", ".join(markers[:5])
            unauthorized = status_code in {401, 403}
            critical_markers = {"password", "totpsecret", "deluxetoken", "lastloginip"}
            severity = "critical" if critical_markers.intersection(markers) else "high"
            confidence = 95 if unauthorized else 90
            title = (
                "Sensitive API data exposed despite authorization response"
                if unauthorized
                else "Sensitive API data exposure"
            )
            return {
                "title": title,
                "severity": severity,
                "confidence": confidence,
                "description": (
                    "The API response exposed sensitive user-account fields "
                    f"({marker_names})"
                    + (
                        f" even though the server responded with HTTP {status_code}."
                        if unauthorized
                        else "."
                    )
                ),
                "tool_source": "web_interact",
                "vulnerability_type": "sensitive_data_exposure",
                "request": f"GET {target_url}",
                "response": _format_response_for_evidence(
                    {
                        "status_code": status_code,
                        "headers": {"content-type": content_type},
                        "body": body[:4000],
                    }
                ),
                "payload": "unauthorized_body_leak_probe" if unauthorized else "api_data_exposure_probe",
                "exploit_result": (
                    "Sensitive user-account fields returned in API response: "
                    + marker_names
                ),
                "surface": "api",
                "route_group": _route_group(target_url),
                "exploitability": "high",
                "exploitability_score": 90 if severity == "critical" else 82,
                "verification_state": "detected",
                "verification_confidence": confidence,
                "references": [f"marker:{marker}" for marker in markers[:6]],
            }

    stack_trace_markers = [
        marker
        for marker in (
            "<ul id=\"stacktrace\">",
            "error: unexpected path:",
            "error: blocked illegal activity by",
            "at /juice-shop/build/",
            "/node_modules/express/lib/router/",
            "router.process_params",
            "express ^",
        )
        if marker in lowered_body
    ]
    if status_code >= 500 and stack_trace_markers:
        marker_names = ", ".join(stack_trace_markers[:4])
        return {
            "title": "Server stack trace exposure",
            "severity": "high",
            "confidence": 84,
            "description": (
                "The application returned a verbose error page with stack-trace markers, "
                f"including: {marker_names}."
            ),
            "tool_source": "web_interact",
            "vulnerability_type": "stack_trace_exposure",
            "request": f"GET {target_url}",
            "response": _format_response_for_evidence(
                {
                    "status_code": status_code,
                    "headers": {"content-type": content_type},
                    "body": body[:4000],
                }
            ),
            "payload": "error_surface_probe",
            "exploit_result": "Verbose framework error page exposed internal stack frames.",
            "surface": "api" if "/api/" in lowered_path or "/rest/" in lowered_path else "web",
            "route_group": _route_group(target_url),
            "exploitability": "medium",
            "exploitability_score": 64,
            "verification_state": "detected",
            "verification_confidence": 84,
            "references": [f"marker:{marker}" for marker in stack_trace_markers[:6]],
        }

    return {}
