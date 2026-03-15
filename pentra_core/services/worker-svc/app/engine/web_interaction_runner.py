"""Stateful web interaction runner for authenticated crawl and workflow replay."""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx


@dataclass
class _FormInput:
    name: str
    input_type: str = "text"
    value: str = ""


@dataclass
class _ParsedForm:
    action: str
    method: str = "get"
    inputs: list[_FormInput] = field(default_factory=list)


class _DiscoveryParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[_ParsedForm] = []
        self.title: str = ""
        self._current_form: _ParsedForm | None = None
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {name.lower(): value or "" for name, value in attrs}
        if tag == "a":
            href = attr_map.get("href", "").strip()
            if href:
                self.links.append(href)
            return

        if tag == "form":
            self._current_form = _ParsedForm(
                action=attr_map.get("action", "").strip(),
                method=(attr_map.get("method") or "get").strip().lower(),
            )
            self.forms.append(self._current_form)
            return

        if tag == "input" and self._current_form is not None:
            name = attr_map.get("name", "").strip()
            if not name:
                return
            self._current_form.inputs.append(
                _FormInput(
                    name=name,
                    input_type=(attr_map.get("type") or "text").strip().lower(),
                    value=attr_map.get("value", ""),
                )
            )
            return

        if tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current_form = None
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title and data.strip():
            self.title += data.strip()


class WebInteractionRunner:
    """Performs bounded authenticated crawl and safe workflow mutation replay."""

    async def run_discovery(
        self,
        *,
        base_url: str,
        scan_config: dict[str, Any],
    ) -> dict[str, Any]:
        stateful = _stateful_config(scan_config)
        seed_paths = _string_list(stateful.get("seed_paths")) or ["/", "/login"]
        start_urls = [_join_url(base_url, path) for path in seed_paths]

        max_depth = _bounded_int(stateful.get("crawl_max_depth"), default=2, minimum=1, maximum=4)
        max_pages = _bounded_int(stateful.get("max_pages"), default=18, minimum=1, maximum=40)
        max_replays = _bounded_int(stateful.get("max_replays"), default=4, minimum=0, maximum=10)

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

        return {
            "pages": _dedupe_dicts(pages, key="page_key"),
            "forms": _dedupe_dicts(forms, key="form_key"),
            "sessions": sessions,
            "workflows": _dedupe_dicts(workflows, key="workflow_key"),
            "replays": _dedupe_dicts(replays, key="replay_key"),
            "summary": {
                "page_count": len(_dedupe_dicts(pages, key="page_key")),
                "form_count": len(_dedupe_dicts(forms, key="form_key")),
                "session_count": len(sessions),
                "workflow_count": len(_dedupe_dicts(workflows, key="workflow_key")),
                "replay_count": len(_dedupe_dicts(replays, key="replay_key")),
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
                "references": [f"workflow:{workflow_type}", *result["evidence"]],
            }
        ]

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
        extra_workflow: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        queue: list[tuple[str, int, str | None]] = []
        seen_urls: set[str] = set()
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

        while queue and len(pages) < max_pages:
            url, depth, source_url = queue.pop(0)
            if url in seen_urls:
                continue
            seen_urls.add(url)

            try:
                response = await client.get(url)
            except httpx.HTTPError:
                continue

            content_type = response.headers.get("content-type", "")
            body = response.text
            page_record = {
                "page_key": f"{session_label}:{url}",
                "url": str(response.url),
                "title": "",
                "status_code": response.status_code,
                "surface": "web",
                "session_label": session_label,
                "auth_state": auth_state,
                "requires_auth": auth_state != "none",
                "content_length": len(body),
                "route_group": _route_group(str(response.url)),
                "source_url": source_url,
                "entity_key": _entity_key("endpoint", str(response.url)),
            }

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

            if "html" not in content_type.lower():
                pages.append(page_record)
                continue

            parser = _DiscoveryParser()
            parser.feed(body)
            page_record["title"] = parser.title or urlparse(str(response.url)).path or str(response.url)
            pages.append(page_record)

            for link in parser.links:
                next_url = _normalize_discovery_url(base_url, urljoin(str(response.url), link))
                if not next_url:
                    continue
                if depth + 1 <= max_depth and next_url not in seen_urls:
                    queue.append((next_url, depth + 1, str(response.url)))

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
                form_record = {
                    "form_key": f"{session_label}:{str(response.url)}:{action_url}:{parsed_form.method}",
                    "page_url": str(response.url),
                    "action_url": action_url,
                    "method": parsed_form.method.upper(),
                    "field_names": form_fields,
                    "hidden_field_names": sorted(hidden_fields.keys()),
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
    if parsed.fragment:
        parsed = parsed._replace(fragment="")
    return parsed.geturl()


def _join_url(base_url: str, candidate: str) -> str:
    candidate = candidate.strip()
    if not candidate:
        return base_url.rstrip("/")
    if candidate.startswith("http://") or candidate.startswith("https://"):
        return candidate
    return urljoin(base_url.rstrip("/") + "/", candidate.lstrip("/"))


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
    evidence: list[str] = []
    flaw_type = "none"

    if mutation_type == "skip_step":
        if status == 200:
            evidence.append("step_bypass_succeeded")
            flaw_type = "workflow_bypass"
        if "order confirmed successfully" in lowered:
            evidence.append("data_returned_after_skip")
    elif mutation_type == "cross_session":
        if status == 200:
            evidence.append("unauthenticated_access_succeeded")
            flaw_type = "auth_bypass"
        location = str(headers.get("location") or headers.get("Location") or "").lower()
        if status in {301, 302} and "login" not in location:
            evidence.append("redirect_without_auth_check")
    elif mutation_type == "modify_id":
        if status == 200 and any(marker in lowered for marker in ("email", "salary", "username")):
            evidence.append("different_user_data_returned")
            flaw_type = "idor"
        if any(marker in lowered for marker in ("email", "salary")):
            evidence.append("pii_exposure")
    elif mutation_type == "repeat_step":
        if status == 200:
            evidence.append("duplicate_operation_succeeded")
            flaw_type = "workflow_bypass"
    elif mutation_type == "swap_order":
        if status == 200:
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
