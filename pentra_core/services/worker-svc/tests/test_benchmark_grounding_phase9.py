from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)


def test_sqlmap_normalizer_ignores_non_confirming_output() -> None:
    from app.engine.artifact_handler import normalize_output

    raw_output = """
http://127.0.0.1:3001/api/v1/auth/login (GET)
[INFO] testing URL 'http://127.0.0.1:3001/api/v1/auth/login'
[WARNING] URI parameter '#1*' does not appear to be dynamic
[WARNING] heuristic (basic) test shows that URI parameter '#1*' might not be injectable
"""

    with tempfile.TemporaryDirectory() as tmpdir:
        Path(tmpdir, "sqlmap.txt").write_text(raw_output)
        artifact = normalize_output(
            output_dir=tmpdir,
            output_parser="raw",
            tool_name="sqlmap",
            artifact_type="vulnerabilities",
            scan_id="scan-1",
            node_id="node-1",
            tenant_id="tenant-1",
            exit_code=0,
        )

        assert artifact["item_count"] == 0
        assert artifact["findings"] == []


def test_sqlmap_normalizer_requires_explicit_injection_markers() -> None:
    from app.engine.artifact_handler import normalize_output

    raw_output = """
http://127.0.0.1:3002/vulnerabilities/sqli/?id=1&Submit=Submit (GET)
sqlmap identified the following injection point(s) with a total of 1 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1=1
---
back-end DBMS: MySQL >= 5.0
"""

    with tempfile.TemporaryDirectory() as tmpdir:
        Path(tmpdir, "sqlmap.txt").write_text(raw_output)
        artifact = normalize_output(
            output_dir=tmpdir,
            output_parser="raw",
            tool_name="sqlmap",
            artifact_type="vulnerabilities",
            scan_id="scan-1",
            node_id="node-1",
            tenant_id="tenant-1",
            exit_code=0,
        )

        assert artifact["item_count"] == 1
        finding = artifact["findings"][0]
        assert finding["endpoint"] == "http://127.0.0.1:3002/vulnerabilities/sqli/"
        assert "injectable parameter 'id'" in finding["description"]


def test_workflow_analysis_rejects_login_page_false_positive() -> None:
    from app.engine.web_interaction_runner import _analyze_workflow_response

    result = _analyze_workflow_response(
        response={
            "status_code": 200,
            "body": """
                <html>
                  <title>Login :: Damn Vulnerable Web Application</title>
                  <form action="login.php" method="post">
                    <label for="user">Username</label>
                    <input type="text" name="username">
                    <label for="pass">Password</label>
                    <input type="password" name="password">
                  </form>
                </html>
            """,
            "headers": {"content-type": "text/html"},
        },
        mutation_type="modify_id",
        workflow_type="auth",
        target_url="http://127.0.0.1:3002/",
    )

    assert result["verdict"] == "negative"
    assert result["flaw_type"] == "none"


def test_runtime_credentials_bootstrap_cookie_from_stateful_login(monkeypatch) -> None:
    import asyncio

    from app.engine.web_interaction_runner import WebInteractionRunner
    from app.services.worker_service import _resolve_runtime_credentials

    async def fake_login(self, *, client, base_url, scan_config, credentials):
        client.cookies.set("PHPSESSID", "phase9-cookie")
        client.cookies.set("security", "low")
        return {"success": True}

    monkeypatch.setattr(WebInteractionRunner, "_login", fake_login)

    creds = asyncio.run(
        _resolve_runtime_credentials(
            tool_name="sqlmap",
            base_url="http://127.0.0.1:3002",
            config={
                "stateful_testing": {
                    "enabled": True,
                    "auth": {
                        "login_page_path": "/login.php",
                        "credentials": [
                            {"username": "admin", "password": "password", "role": "admin"}
                        ],
                    },
                }
            },
            explicit_credentials={},
            web_runner=WebInteractionRunner(),
        )
    )

    assert creds["type"] == "cookie"
    assert "PHPSESSID=phase9-cookie" in creds["cookie"]


def test_registry_loads_phase9_specialized_live_tools() -> None:
    from app.tools.tool_registry import get_tool

    for tool_name in ("dalfox", "graphql_cop", "jwt_tool", "cors_scanner", "header_audit_tool"):
        tool = get_tool(tool_name)
        assert tool is not None
        assert tool.command


def test_registry_preserves_specialized_tool_runtime_metadata() -> None:
    from app.tools.tool_registry import get_tool

    dalfox = get_tool("dalfox")
    graphql_cop = get_tool("graphql_cop")

    assert dalfox is not None
    assert dalfox.command[0] == "/app/dalfox"
    assert dalfox.working_dir is None

    assert graphql_cop is not None
    assert graphql_cop.working_dir == "/app"
    assert graphql_cop.command[0] == "-t"
    assert graphql_cop.command[2:4] == ["-o", "json"]


def test_graphql_cop_credentials_use_json_header_format() -> None:
    from app.engine.credential_injector import inject_credentials

    cookie_command = inject_credentials(
        "graphql_cop",
        ["python", "graphql-cop.py", "-t", "http://127.0.0.1:8088/graphql", "-o", "json"],
        {"type": "cookie", "cookie": "session=abc123"},
    )
    bearer_command = inject_credentials(
        "graphql_cop",
        ["python", "graphql-cop.py", "-t", "http://127.0.0.1:8088/graphql", "-o", "json"],
        {"type": "bearer", "token": "secret-token"},
    )

    assert "{\"Cookie\":\"session=abc123\"}" in cookie_command
    assert "{\"Authorization\":\"Bearer secret-token\"}" in bearer_command


def test_container_runner_preserves_subpath_target_root_for_webgoat() -> None:
    from app.engine.container_runner import _base_url_from_target
    from app.services.worker_service import _base_url_from_target as worker_base_url

    target = "http://127.0.0.1:3003/WebGoat"
    assert _base_url_from_target(target) == target
    assert worker_base_url(target) == target


def test_container_runner_prepares_dalfox_urls_from_endpoints() -> None:
    from app.engine.container_runner import ContainerRunner

    runner = ContainerRunner()
    with tempfile.TemporaryDirectory() as tmpdir:
        input_dir = Path(tmpdir)
        endpoints = [
            {"url": "http://127.0.0.1:3001/rest/products/search"},
            {"url": "http://127.0.0.1:3001/rest/user/whoami"},
        ]
        (input_dir / "endpoints.json").write_text(json.dumps(endpoints))

        runner._prepare_runtime_inputs(
            tool_name="dalfox",
            target="http://127.0.0.1:3001",
            input_dir=input_dir,
            scan_config={
                "selected_checks": {
                    "dalfox": {"max_targets": 2},
                    "http_probe_paths": ["/", "/rest/products/search?q=test"],
                }
            },
        )

        dalfox_targets = (input_dir / "dalfox_urls.txt").read_text().splitlines()
        assert "http://127.0.0.1:3001/rest/products/search?q=test" in dalfox_targets
        assert "http://127.0.0.1:3001/rest/user/whoami" not in dalfox_targets
        assert "http://127.0.0.1:3001" not in dalfox_targets
        assert "http://127.0.0.1:3001/graphql" not in dalfox_targets
        assert len(dalfox_targets) <= 2


def test_container_runner_skips_dalfox_path_only_fallback_targets() -> None:
    from app.engine.container_runner import _build_dalfox_targets

    with tempfile.TemporaryDirectory() as tmpdir:
        input_dir = Path(tmpdir)
        (input_dir / "endpoints.json").write_text(
            json.dumps(
                [
                    {"url": "http://127.0.0.1:3001/"},
                    {"url": "http://127.0.0.1:3001/rest/user/whoami"},
                ]
            )
        )

        targets = _build_dalfox_targets(
            base_url="http://127.0.0.1:3001",
            input_dir=input_dir,
            selected_checks={"http_probe_paths": ["/", "/rest/user/whoami"]},
        )

        assert targets == []


def test_stateful_discovery_marks_exposed_application_config() -> None:
    from app.engine.web_interaction_runner import _infer_discovery_finding

    finding = _infer_discovery_finding(
        target_url="http://127.0.0.1:3001/rest/admin/application-configuration",
        status_code=200,
        content_type="application/json",
        body=(
            '{"config":{"server":{"baseUrl":"http://localhost:3000"},'
            '"application":{"showVersionNumber":true,"localBackupEnabled":true}}}'
        ),
    )

    assert finding["vulnerability_type"] == "sensitive_data_exposure"
    assert finding["severity"] == "high"


def test_stateful_discovery_marks_unauthorized_api_data_exposure() -> None:
    from app.engine.web_interaction_runner import _infer_discovery_finding

    finding = _infer_discovery_finding(
        target_url="http://127.0.0.1:3001/api/Users",
        status_code=401,
        content_type="application/json",
        body=(
            '{"status":"success","data":[{"email":"admin@juice-sh.op","role":"admin",'
            '"deluxeToken":"abc123","lastLoginIp":"127.0.0.1"}]}'
        ),
    )

    assert finding["vulnerability_type"] == "sensitive_data_exposure"
    assert finding["severity"] == "critical"


def test_stateful_discovery_marks_stack_trace_exposure() -> None:
    from app.engine.web_interaction_runner import _infer_discovery_finding

    finding = _infer_discovery_finding(
        target_url="http://127.0.0.1:3001/rest/order-history",
        status_code=500,
        content_type="text/html",
        body=(
            "<html><h2><em>500</em> Error: Blocked illegal activity by ::ffff:172.17.0.1</h2>"
            "<ul id=\"stacktrace\"><li>at /juice-shop/build/routes/orderHistory.js:43:18</li>"
            "<li>at /juice-shop/node_modules/express/lib/router/index.js:280:10</li></ul></html>"
        ),
    )

    assert finding["vulnerability_type"] == "stack_trace_exposure"
    assert finding["severity"] == "high"


def test_custom_poc_verifies_stack_trace_exposure() -> None:
    from app.engine.container_runner import ContainerRunner

    runner = ContainerRunner()

    payload = runner._build_custom_poc_verification_payload(
        verify_type="stack_trace_exposure",
        request_url="http://127.0.0.1:3001/rest/admin",
        response={
            "status_code": 500,
            "body": (
                "<html><h2>500 Error: Unexpected path: /rest/admin</h2>"
                "<ul id=\"stacktrace\"></ul><pre>/node_modules/express/lib/router/</pre></html>"
            ),
            "content_type": "text/html",
        },
        verification_context={"route_group": "/rest/admin"},
    )

    assert len(payload) == 1
    finding = payload[0]
    assert finding["vulnerability_type"] == "stack_trace_exposure"
    assert finding["verification_state"] == "verified"
    assert finding["title"] == "Verified stack trace exposure"


def test_stateful_endpoint_merge_prefers_descriptive_detection_title() -> None:
    from app.engine.artifact_handler import _merge_stateful_endpoint_item

    merged = _merge_stateful_endpoint_item(
        {
            "title": "UnauthorizedError: No Authorization header was found",
            "session_label": "unauthenticated",
            "auth_variants": ["unauthenticated"],
        },
        {
            "title": "Sensitive API data exposure",
            "session_label": "juice-shop-admin",
        },
    )

    assert merged["title"] == "Sensitive API data exposure"


def test_vulnerability_merge_prefers_descriptive_detection_title() -> None:
    from app.engine.artifact_handler import _merge_vulnerability_items

    merged = _merge_vulnerability_items(
        {
            "title": "UnauthorizedError: No Authorization header was found",
            "severity": "medium",
            "confidence": 60,
            "references": [],
        },
        {
            "title": "Sensitive API data exposed despite authorization response",
            "severity": "critical",
            "confidence": 95,
            "references": [],
        },
    )

    assert merged["title"] == "Sensitive API data exposed despite authorization response"
    assert merged["severity"] == "critical"


def test_stateful_discovery_seed_paths_merge_selected_checks_and_auth() -> None:
    from app.engine.web_interaction_runner import _discovery_seed_paths

    seed_paths = _discovery_seed_paths(
        {
            "selected_checks": {
                "content_paths": ["/api/Users", "/rest/user/whoami"],
                "http_probe_paths": ["/", "/rest/admin/application-configuration"],
            },
            "stateful_testing": {
                "seed_paths": ["/login"],
                "auth": {
                    "login_api_path": "/rest/user/login",
                    "whoami_path": "/rest/user/whoami",
                },
            },
        }
    )

    assert seed_paths == [
        "/login",
        "/api/Users",
        "/rest/user/whoami",
        "/",
        "/rest/admin/application-configuration",
        "/rest/user/login",
    ]


def test_stateful_discovery_extracts_script_urls_from_html() -> None:
    from app.engine.web_interaction_runner import _DiscoveryParser

    parser = _DiscoveryParser()
    parser.feed(
        """
        <html>
          <head>
            <link rel="modulepreload" href="/main.js">
            <script src="/polyfills.js"></script>
          </head>
          <body>
            <script>fetch('/rest/user/whoami')</script>
          </body>
        </html>
        """
    )

    assert "/main.js" in parser.script_urls
    assert "/polyfills.js" in parser.script_urls
    assert "/rest/user/whoami" in parser.ajax_urls


def test_stateful_discovery_extracts_api_routes_from_script_bundle() -> None:
    from app.engine.web_interaction_runner import _extract_script_discovery_urls

    urls = _extract_script_discovery_urls(
        "http://127.0.0.1:3001",
        """
        app.login = () => http.post('/rest/user/login', payload)
        app.whoami = () => fetch('/rest/user/whoami')
        app.users = () => axios.get('/api/Users')
        """,
    )

    assert set(urls) == {
        "http://127.0.0.1:3001/rest/user/login",
        "http://127.0.0.1:3001/rest/user/whoami",
        "http://127.0.0.1:3001/api/Users",
    }


def test_stateful_discovery_extracts_dom_xss_markers_from_script_bundle() -> None:
    from app.engine.web_interaction_runner import _extract_dom_xss_markers

    markers = _extract_dom_xss_markers(
        """
        const params = new URLSearchParams(location.search)
        document.getElementById('searchValue').innerHTML = params.get('q')
        """
    )

    assert "urlsearchparams" in markers["source_markers"]
    assert "location.search" in markers["source_markers"]
    assert "innerHTML" in markers["sink_markers"]


def test_stateful_discovery_builds_browser_xss_candidate_from_hash_seed() -> None:
    from app.engine.web_interaction_runner import _build_browser_xss_candidates

    candidates = _build_browser_xss_candidates(
        base_url="http://127.0.0.1:3001",
        scan_config={
            "stateful_testing": {
                "xss": {
                    "enabled": True,
                    "benchmark_inputs_enabled": True,
                    "seed_paths": ["/#/search?q=pentra-seed"],
                }
            }
        },
        pages=[
            {
                "url": "http://127.0.0.1:3001/main.js",
                "content_type": "application/javascript",
                "response_preview": "",
                "source_url": "http://127.0.0.1:3001/",
                "dom_sink_markers": ["innerHTML"],
                "dom_source_markers": ["location.search", "urlsearchparams"],
            }
        ],
        forms=[],
    )

    assert len(candidates) >= 1
    candidate = next(item for item in candidates if item["route_group"] == "/#/search")
    assert candidate["vulnerability_type"] == "xss"
    assert candidate["verification_state"] == "suspected"
    assert candidate["route_group"] == "/#/search"
    assert candidate["verification_context"]["verify_type"] == "xss_browser"
    assert candidate["verification_context"]["candidate_kind"] == "hash_query"
    assert candidate["verification_context"]["parameter_name"] == "q"


def test_api_login_bootstraps_bearer_headers_for_stateful_crawl() -> None:
    import asyncio

    import httpx

    from app.engine.web_interaction_runner import WebInteractionRunner

    async def run() -> dict[str, str]:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/rest/user/login":
                return httpx.Response(
                    200,
                    json={"authentication": {"token": "phase9-token"}},
                )
            if request.url.path == "/rest/user/whoami":
                assert request.headers.get("Authorization") == "Bearer phase9-token"
                assert request.headers.get("X-User-Email") == "admin@juice-sh.op"
                return httpx.Response(200, json={"user": {"email": "admin@juice-sh.op"}})
            raise AssertionError(f"Unexpected request to {request.url}")

        runner = WebInteractionRunner()
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:3001") as client:
            result = await runner._login_via_api(
                client=client,
                base_url="http://127.0.0.1:3001",
                auth={
                    "login_api_path": "/rest/user/login",
                    "login_request_format": "json",
                    "username_field": "email",
                    "password_field": "password",
                    "token_json_path": "authentication.token",
                    "whoami_path": "/rest/user/whoami",
                    "post_login_path": "/rest/user/whoami",
                },
                credentials={
                    "username": "admin@juice-sh.op",
                    "password": "admin123",
                    "role": "admin",
                },
            )
            assert result["success"] is True
            return {
                "authorization": client.headers.get("Authorization", ""),
                "user_email": client.headers.get("X-User-Email", ""),
            }

    headers = asyncio.run(run())

    assert headers["authorization"] == "Bearer phase9-token"
    assert headers["user_email"] == "admin@juice-sh.op"


def test_login_bootstraps_juice_shop_customer_registration_before_api_login() -> None:
    import asyncio

    import httpx

    from app.engine.web_interaction_runner import WebInteractionRunner

    async def run() -> list[tuple[str, str]]:
        calls: list[tuple[str, str]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append((request.method, request.url.path))
            if request.method == "GET" and request.url.path == "/api/SecurityQuestions/":
                return httpx.Response(
                    200,
                    json={"data": [{"id": 1, "question": "Name of your first pet?"}]},
                )
            if request.method == "POST" and request.url.path == "/api/Users/":
                payload = json.loads(request.content.decode())
                assert payload["email"] == "pentra.customer@juice-sh.op"
                assert payload["password"] == "Pentra123!"
                assert payload["passwordRepeat"] == "Pentra123!"
                assert payload["securityQuestion"]["id"] == 1
                assert payload["securityAnswer"] == "pentra-bootstrap"
                return httpx.Response(201, json={"id": 42, "email": payload["email"]})
            if request.method == "POST" and request.url.path == "/api/SecurityAnswers/":
                payload = json.loads(request.content.decode())
                assert payload == {
                    "UserId": 42,
                    "answer": "pentra-bootstrap",
                    "SecurityQuestionId": 1,
                }
                return httpx.Response(201, json={"data": {"id": 99}})
            if request.method == "POST" and request.url.path == "/rest/user/login":
                return httpx.Response(200, json={"authentication": {"token": "customer-token"}})
            if request.method == "GET" and request.url.path == "/rest/user/whoami":
                assert request.headers.get("Authorization") == "Bearer customer-token"
                assert request.headers.get("X-User-Email") == "pentra.customer@juice-sh.op"
                return httpx.Response(200, json={"user": {"email": "pentra.customer@juice-sh.op"}})
            raise AssertionError(f"Unexpected request to {request.url}")

        runner = WebInteractionRunner()
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:3001") as client:
            result = await runner._login(
                client=client,
                base_url="http://127.0.0.1:3001",
                scan_config={
                    "stateful_testing": {
                        "auth": {
                            "login_api_path": "/rest/user/login",
                            "login_request_format": "json",
                            "username_field": "email",
                            "password_field": "password",
                            "token_json_path": "authentication.token",
                            "whoami_path": "/rest/user/whoami",
                            "post_login_path": "/rest/user/whoami",
                        }
                    }
                },
                credentials={
                    "label": "juice-shop-customer",
                    "username": "pentra.customer@juice-sh.op",
                    "password": "Pentra123!",
                    "role": "customer",
                    "bootstrap": {
                        "mode": "juice_shop_register",
                        "security_question_id": 1,
                        "security_answer": "pentra-bootstrap",
                    },
                },
            )
            assert result["success"] is True
            return calls

    calls = asyncio.run(run())

    assert calls[:5] == [
        ("GET", "/api/SecurityQuestions/"),
        ("POST", "/api/Users/"),
        ("POST", "/api/SecurityAnswers/"),
        ("POST", "/rest/user/login"),
        ("GET", "/rest/user/whoami"),
    ]


def test_login_allows_existing_bootstrapped_juice_shop_customer() -> None:
    import asyncio

    import httpx

    from app.engine.web_interaction_runner import WebInteractionRunner

    async def run() -> bool:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET" and request.url.path == "/api/SecurityQuestions/":
                return httpx.Response(
                    200,
                    json={"data": [{"id": 1, "question": "Name of your first pet?"}]},
                )
            if request.method == "POST" and request.url.path == "/api/Users/":
                return httpx.Response(409, json={"error": "User already exists"})
            if request.method == "POST" and request.url.path == "/rest/user/login":
                return httpx.Response(200, json={"authentication": {"token": "customer-token"}})
            if request.method == "GET" and request.url.path == "/rest/user/whoami":
                return httpx.Response(200, json={"user": {"email": "pentra.customer@juice-sh.op"}})
            raise AssertionError(f"Unexpected request to {request.url}")

        runner = WebInteractionRunner()
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:3001") as client:
            result = await runner._login(
                client=client,
                base_url="http://127.0.0.1:3001",
                scan_config={
                    "stateful_testing": {
                        "auth": {
                            "login_api_path": "/rest/user/login",
                            "login_request_format": "json",
                            "username_field": "email",
                            "password_field": "password",
                            "token_json_path": "authentication.token",
                            "whoami_path": "/rest/user/whoami",
                        }
                    }
                },
                credentials={
                    "username": "pentra.customer@juice-sh.op",
                    "password": "Pentra123!",
                    "role": "customer",
                    "bootstrap": {
                        "mode": "juice_shop_register",
                        "security_question_id": 1,
                    },
                },
            )
            return bool(result["success"])

    assert asyncio.run(run()) is True


def test_custom_poc_verifier_supports_sensitive_config_exposure() -> None:
    from app.engine.container_runner import ContainerRunner

    runner = ContainerRunner()
    findings = runner._build_custom_poc_verification_payload(
        verify_type="sensitive_config_exposure",
        request_url="http://127.0.0.1:3001/rest/admin/application-configuration",
        response={
            "status_code": 200,
            "content_type": "application/json",
            "body": (
                '{"config":{"server":{"baseUrl":"http://localhost:3000"},'
                '"application":{"showVersionNumber":true,"localBackupEnabled":true}}}'
            ),
        },
        verification_context={
            "route_group": "/rest/admin/application-configuration",
            "sensitive_markers": ["config", "baseurl", "showversionnumber"],
        },
    )

    assert findings
    assert findings[0]["vulnerability_type"] == "sensitive_data_exposure"
    assert findings[0]["title"] == "Verified exposed application configuration"


def test_custom_poc_verifier_supports_browser_xss(monkeypatch) -> None:
    import asyncio
    import uuid

    from app.engine.container_runner import ContainerRunner

    async def fake_browser_verifier(self, *, request_url, verification_context, output_dir):  # noqa: ARG001
        return [
            {
                "target": request_url,
                "title": "Verified browser-executed XSS",
                "severity": "high",
                "confidence": 97,
                "description": "Browser-backed proof observed DOM execution.",
                "request": f"GET {request_url}",
                "response": "<html></html>",
                "payload": "probe",
                "exploit_result": "sentinel hit",
                "surface": "web",
                "route_group": verification_context.get("route_group"),
                "vulnerability_type": "xss",
                "verification_state": "verified",
                "verification_confidence": 97,
                "exploitability": "high",
                "exploitability_score": 91,
            }
        ]

    monkeypatch.setattr(
        ContainerRunner,
        "_run_browser_xss_verifier",
        fake_browser_verifier,
    )

    runner = ContainerRunner()

    with tempfile.TemporaryDirectory() as tmpdir:
        result = asyncio.run(
            runner._run_custom_poc_verifier(
                target="http://127.0.0.1:3001/#/search?q=pentra-seed",
                output_dir=tmpdir,
                job_id=uuid.uuid4(),
                scan_config={
                    "verification_context": {
                        "verify_type": "xss_browser",
                        "request_url": "http://127.0.0.1:3001/#/search?q=pentra-seed",
                        "route_group": "/#/search",
                        "candidate_kind": "hash_query",
                        "parameter_name": "q",
                    }
                },
                execution_mode="controlled_live_local",
            )
        )

        assert result.exit_code == 0
        payload = json.loads(Path(tmpdir, "poc_result.json").read_text())
        assert payload[0]["title"] == "Verified browser-executed XSS"
        assert payload[0]["vulnerability_type"] == "xss"


def test_custom_poc_verifier_supports_sensitive_api_exposure_with_unauthorized_status() -> None:
    from app.engine.container_runner import ContainerRunner

    runner = ContainerRunner()
    findings = runner._build_custom_poc_verification_payload(
        verify_type="sensitive_config_exposure",
        request_url="http://127.0.0.1:3001/rest/user/authentication-details/",
        response={
            "status_code": 401,
            "content_type": "application/json",
            "body": (
                '{"status":"success","data":[{"email":"admin@juice-sh.op","password":"********",'
                '"role":"admin","totpSecret":"********"}]}'
            ),
        },
        verification_context={
            "route_group": "/rest/user/authentication-details",
            "sensitive_markers": ["email", "password", "role", "totpsecret"],
        },
    )

    assert findings
    assert findings[0]["vulnerability_type"] == "sensitive_data_exposure"
    assert findings[0]["severity"] == "critical"
    assert "authorization response" in findings[0]["title"].lower()


def test_fetch_http_response_preserves_http_error_body(monkeypatch) -> None:
    import io
    from urllib.error import HTTPError

    import app.engine.container_runner as container_runner
    from app.engine.container_runner import ContainerRunner

    def fake_urlopen(request, timeout):  # noqa: ARG001
        raise HTTPError(
            url=request.full_url,
            code=401,
            msg="Unauthorized",
            hdrs={"Content-Type": "application/json"},
            fp=io.BytesIO(b'{"status":"success","data":[{"email":"admin@juice-sh.op"}]}'),
        )

    monkeypatch.setattr(container_runner, "urlopen", fake_urlopen)

    runner = ContainerRunner()
    response = runner._fetch_http_response(
        "http://127.0.0.1:3001/api/Users",
        {"Accept": "application/json"},
    )

    assert response["status_code"] == 401
    assert "admin@juice-sh.op" in str(response["body"])


def test_normalize_web_interact_preserves_browser_xss_candidate_context() -> None:
    from app.engine.artifact_handler import normalize_output

    with tempfile.TemporaryDirectory() as tmpdir:
        Path(tmpdir, "web_interactions.json").write_text(
            json.dumps(
                {
                    "pages": [],
                    "forms": [],
                    "sessions": [],
                    "workflows": [],
                    "replays": [],
                    "xss_candidates": [
                        {
                            "request_url": "http://127.0.0.1:3001/#/search?q=pentra-seed",
                            "title": "Browser-backed XSS candidate",
                            "severity": "medium",
                            "confidence": 82,
                            "tool_source": "web_interact",
                            "vulnerability_type": "xss",
                            "request": "GET http://127.0.0.1:3001/#/search?q=pentra-seed",
                            "surface": "web",
                            "route_group": "/#/search",
                            "verification_state": "suspected",
                            "verification_confidence": 82,
                            "references": ["sink:innerHTML", "source:location.search"],
                            "verification_context": {
                                "verify_type": "xss_browser",
                                "candidate_kind": "hash_query",
                                "parameter_name": "q",
                            },
                        }
                    ],
                }
            )
        )

        artifact = normalize_output(
            output_dir=tmpdir,
            output_parser="json",
            tool_name="web_interact",
            artifact_type="endpoints",
            scan_id="scan-1",
            node_id="node-1",
            tenant_id="tenant-1",
            exit_code=0,
        )

        assert artifact["item_count"] == 1
        assert artifact["summary"]["finding_count"] == 1
        finding = artifact["findings"][0]
        verification_context = finding["evidence"]["metadata"]["verification_context"]
        assert verification_context["verify_type"] == "xss_browser"
        assert verification_context["candidate_kind"] == "hash_query"
        assert verification_context["parameter_name"] == "q"


def test_normalize_web_interact_preserves_probe_findings() -> None:
    from app.engine.artifact_handler import normalize_output

    with tempfile.TemporaryDirectory() as tmpdir:
        Path(tmpdir, "web_interactions.json").write_text(
            json.dumps(
                {
                    "pages": [],
                    "forms": [],
                    "sessions": [],
                    "workflows": [],
                    "replays": [],
                    "probe_findings": [
                        {
                            "target": "http://127.0.0.1:3001/rest/admin",
                            "endpoint": "http://127.0.0.1:3001/rest/admin",
                            "title": "Privilege Escalation — Admin Page Accessible",
                            "severity": "critical",
                            "confidence": 85,
                            "description": "Customer session reached admin route.",
                            "tool_source": "web_interact",
                            "vulnerability_type": "privilege_escalation",
                            "surface": "api",
                            "route_group": "/rest/admin",
                            "verification_state": "detected",
                            "verification_confidence": 85,
                        }
                    ],
                }
            )
        )

        artifact = normalize_output(
            output_dir=tmpdir,
            output_parser="json",
            tool_name="web_interact",
            artifact_type="endpoints",
            scan_id="scan-1",
            node_id="node-1",
            tenant_id="tenant-1",
            exit_code=0,
        )

        assert artifact["summary"]["stateful_context"]["probe_finding_count"] == 1
        assert artifact["summary"]["finding_count"] == 1
        finding = artifact["findings"][0]
        assert finding["vulnerability_type"] == "privilege_escalation"
        assert finding["route_group"] == "/rest/admin"
