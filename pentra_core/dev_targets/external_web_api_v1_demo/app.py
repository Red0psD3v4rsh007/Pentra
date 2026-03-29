"""Controlled local target for live web/API and stateful interaction scans."""

from __future__ import annotations

import json
import sqlite3
from typing import Any
from urllib.parse import parse_qs

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse

app = FastAPI(
    title="Pentra Demo Portal",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

_DB = sqlite3.connect(":memory:", check_same_thread=False)
_DB.row_factory = sqlite3.Row
_DB.executescript(
    """
    CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        email TEXT NOT NULL,
        salary INTEGER NOT NULL,
        role TEXT NOT NULL
    );

    INSERT INTO users (id, username, password, email, salary, role) VALUES
        (1, 'admin', 'admin123', 'admin@example.test', 120000, 'admin'),
        (2, 'john', 'test', 'john.doe@example.test', 85000, 'user'),
        (3, 'sarah', 'test', 'sarah.lee@example.test', 92000, 'user');
    """
)

_CSRF_TOKEN = "demo-csrf"


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
async def root() -> str:
    return """
    <html>
      <head><title>Pentra Demo Portal</title></head>
      <body>
        <h1>Pentra Demo Portal</h1>
        <p>External Web + API validation target.</p>
        <ul>
          <li><a href="/login">Login</a></li>
          <li><a href="/openapi.json">OpenAPI</a></li>
          <li><a href="/graphql">GraphQL</a></li>
          <li><a href="/internal/debug">Debug</a></li>
        </ul>
      </body>
    </html>
    """


@app.get("/login", response_class=HTMLResponse)
async def login_page() -> str:
    return f"""
    <html>
      <head><title>Pentra Login</title></head>
      <body>
        <h1>Login</h1>
        <form action="/login" method="post">
          <input type="hidden" name="csrf_token" value="{_CSRF_TOKEN}" />
          <input type="hidden" name="pentra_safe_replay" value="true" />
          <label>Username <input type="text" name="username" value="john" /></label>
          <label>Password <input type="password" name="password" value="test" /></label>
          <button type="submit">Sign in</button>
        </form>
      </body>
    </html>
    """


@app.post("/login")
async def login_submit(request: Request):
    username, password, csrf_token = await _extract_credentials(request)
    if csrf_token != _CSRF_TOKEN:
        return JSONResponse({"success": False, "message": "Invalid CSRF token"}, status_code=403)

    query = (
        "SELECT id, username, role FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )
    row = _DB.execute(query).fetchone()
    if row is None:
        return JSONResponse({"success": False, "message": "Invalid credentials"}, status_code=401)

    response = RedirectResponse(url="/portal/dashboard", status_code=302)
    response.set_cookie("pentra_session", str(row["id"]))
    response.set_cookie("csrf_token", _CSRF_TOKEN)
    return response


@app.get("/portal/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    user = _require_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=302)

    admin_link = '<li><a href="/portal/admin">Admin Console</a></li>' if user["role"] == "admin" else ""
    return HTMLResponse(
        f"""
        <html>
          <head><title>Customer Dashboard</title></head>
          <body>
            <h1>Customer Dashboard</h1>
            <p>Hello {user["username"]}</p>
            <ul>
              <li><a href="/portal/account">Account Profile</a></li>
              <li><a href="/portal/orders/new">Create Order</a></li>
              <li><a href="/portal/checkout/cart">Checkout Cart</a></li>
              {admin_link}
            </ul>
            <form action="/portal/account/search" method="get">
              <input type="hidden" name="pentra_safe_replay" value="true" />
              <input type="text" name="query" value="invoice" />
              <button type="submit">Search</button>
            </form>
          </body>
        </html>
        """
    )


@app.get("/portal/account", response_class=HTMLResponse)
async def account_page(request: Request):
    user = _require_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=302)
    return HTMLResponse(
        f"""
        <html>
          <head><title>Account Profile</title></head>
          <body>
            <h1>Account Profile</h1>
            <p>Email: {user["email"]}</p>
            <a href="/api/v1/users/{user["id"]}">View API profile</a>
          </body>
        </html>
        """
    )


@app.get("/portal/account/search", response_class=HTMLResponse)
async def account_search(request: Request, query: str = "invoice"):
    user = _require_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=302)
    return HTMLResponse(
        f"""
        <html>
          <head><title>Account Search</title></head>
          <body>
            <h1>Account Search</h1>
            <p>Results for {query}</p>
            <a href="/portal/checkout/cart">Go to checkout</a>
          </body>
        </html>
        """
    )


@app.get("/portal/orders/new", response_class=HTMLResponse)
async def new_order_page(request: Request):
    user = _require_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=302)
    return HTMLResponse(
        f"""
        <html>
          <head><title>Create Order</title></head>
          <body>
            <h1>Create Order</h1>
            <form action="/portal/orders/review" method="post">
              <input type="hidden" name="csrf_token" value="{_CSRF_TOKEN}" />
              <input type="hidden" name="pentra_safe_replay" value="true" />
              <input type="text" name="item_id" value="widget-7" />
              <input type="number" name="quantity" value="1" />
              <button type="submit">Review Order</button>
            </form>
          </body>
        </html>
        """
    )


@app.post("/portal/orders/review", response_class=HTMLResponse)
async def review_order(request: Request):
    user = _require_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=302)

    form = await _read_form_data(request)
    item_id = str(form.get("item_id", "widget-7"))
    quantity = str(form.get("quantity", "1"))
    response = HTMLResponse(
        f"""
        <html>
          <head><title>Order Review</title></head>
          <body>
            <h1>Order Review</h1>
            <p>Item {item_id} × {quantity}</p>
            <a href="/portal/checkout/cart">Continue to checkout</a>
          </body>
        </html>
        """
    )
    response.set_cookie("order_reviewed", "true")
    return response


@app.get("/portal/checkout/cart", response_class=HTMLResponse)
async def checkout_cart(request: Request):
    user = _require_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=302)

    response = HTMLResponse(
        f"""
        <html>
          <head><title>Checkout Cart</title></head>
          <body>
            <h1>Checkout Cart</h1>
            <form action="/portal/checkout/confirm" method="post">
              <input type="hidden" name="csrf_token" value="{_CSRF_TOKEN}" />
              <input type="hidden" name="pentra_safe_replay" value="true" />
              <input type="text" name="item_id" value="widget-7" />
              <input type="number" name="quantity" value="2" />
              <button type="submit">Confirm Purchase</button>
            </form>
          </body>
        </html>
        """
    )
    response.set_cookie("checkout_step", "cart")
    return response


@app.post("/portal/checkout/confirm", response_class=HTMLResponse)
async def checkout_confirm(request: Request):
    user = _require_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=302)

    form = await _read_form_data(request)
    item_id = str(form.get("item_id", "widget-7"))
    quantity = str(form.get("quantity", "1"))
    step_cookie = request.cookies.get("checkout_step")

    # Intentional workflow bypass: direct confirmation succeeds without the cart step.
    step_message = "cart-step-missing-but-accepted" if step_cookie != "cart" else "checkout_cart_verified"
    return HTMLResponse(
        f"""
        <html>
          <head><title>Order Confirmed</title></head>
          <body>
            <h1>Order Confirmed</h1>
            <p>Order confirmed successfully for {item_id} × {quantity}</p>
            <p>{step_message}</p>
            <p>account={user["username"]}; role={user["role"]}</p>
          </body>
        </html>
        """
    )


@app.get("/portal/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    user = _require_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=302)
    if user["role"] != "admin":
        return HTMLResponse("<h1>Forbidden</h1>", status_code=403)
    return HTMLResponse("<h1>Admin Console</h1><p>role=admin</p>")


@app.get("/openapi.json")
async def openapi_schema() -> JSONResponse:
    payload = {
        "openapi": "3.0.3",
        "info": {
            "title": "Pentra Demo API",
            "version": "1.0.0",
        },
        "paths": {
            "/api/v1/auth/login": {"post": {"summary": "Authenticate user"}},
            "/api/v1/users/{user_id}": {"get": {"summary": "Get user profile"}},
            "/graphql": {"post": {"summary": "GraphQL endpoint"}},
            "/portal/checkout/confirm": {"post": {"summary": "Confirm checkout"}},
        },
    }
    return JSONResponse(payload)


@app.api_route("/graphql", methods=["GET", "POST"])
async def graphql(request: Request) -> JSONResponse:
    return JSONResponse(
        {
            "data": {
                "__typename": "Query",
                "__schema": {
                    "types": [{"name": "Query"}, {"name": "User"}, {"name": "Mutation"}]
                }
            }
        }
    )


@app.get("/internal/debug", response_class=HTMLResponse)
async def debug_page() -> HTMLResponse:
    return HTMLResponse(
        "<pre>debug=true\nstacktrace=demo-only\nuid=1000(appuser)</pre>",
        status_code=500,
    )


@app.api_route("/api/v1/auth/login", methods=["GET", "POST"])
async def login(request: Request) -> JSONResponse:
    username, password, _ = await _extract_credentials(request)

    # Intentional SQL injection vulnerability for local Phase 3+ verification.
    query = (
        "SELECT id, username FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )
    row = _DB.execute(query).fetchone()

    if row:
        return JSONResponse(
            {
                "success": True,
                "token": "eyJhbGciOiJIUzI1NiJ9.phase3.demo",
                "user": {"id": row["id"], "username": row["username"]},
            }
        )

    return JSONResponse({"success": False, "message": "Invalid credentials"}, status_code=401)


@app.get("/api/v1/users/{user_id}")
async def get_user(user_id: int) -> JSONResponse:
    row = _DB.execute(
        "SELECT id, username, email, salary FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    if row is None:
        return JSONResponse({"detail": "Not found"}, status_code=404)

    # Intentional IDOR: no auth or tenant check.
    return JSONResponse(dict(row))


@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots() -> str:
    return "User-agent: *\nDisallow: /internal\n"


def _require_user(request: Request) -> sqlite3.Row | None:
    session_value = request.cookies.get("pentra_session")
    if not session_value or not session_value.isdigit():
        return None
    return _DB.execute(
        "SELECT id, username, email, salary, role FROM users WHERE id = ?",
        (int(session_value),),
    ).fetchone()


async def _extract_credentials(request: Request) -> tuple[str, str, str]:
    if request.method == "GET":
        return (
            request.query_params.get("username", ""),
            request.query_params.get("password", ""),
            request.query_params.get("csrf_token", ""),
        )

    body = await request.body()
    content_type = request.headers.get("content-type", "")
    raw_body = body.decode("utf-8", errors="ignore")

    if "application/json" in content_type:
        try:
            payload: dict[str, Any] = json.loads(raw_body or "{}")
        except json.JSONDecodeError:
            payload = {}
        return (
            str(payload.get("username", "")),
            str(payload.get("password", "")),
            str(payload.get("csrf_token", "")),
        )

    form = parse_qs(raw_body, keep_blank_values=True)
    return (
        str(form.get("username", [""])[0]),
        str(form.get("password", [""])[0]),
        str(form.get("csrf_token", [""])[0]),
    )


async def _read_form_data(request: Request) -> dict[str, str]:
    body = await request.body()
    raw_body = body.decode("utf-8", errors="ignore")
    parsed = parse_qs(raw_body, keep_blank_values=True)
    return {
        key: str(values[0]) if values else ""
        for key, values in parsed.items()
    }
