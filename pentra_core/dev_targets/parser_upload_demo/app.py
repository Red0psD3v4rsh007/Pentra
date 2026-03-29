"""Controlled local target for parser/upload capability validation."""

from __future__ import annotations

import html
from typing import Any
from urllib.parse import parse_qsl

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

app = FastAPI(
    title="Pentra Parser Upload Demo",
    docs_url=None,
    redoc_url=None,
)

_CSRF_TOKEN = "parser-demo-csrf"
_USERS = {
    "uploader": {
        "username": "uploader",
        "password": "upload123",
        "role": "uploader",
    }
}


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
async def root(request: Request) -> str:
    user = _require_user(request)
    auth_block = (
        '<li><a href="/portal/upload">Upload preview</a></li>'
        '<li><a href="/portal/import/xml">XML import</a></li>'
        '<li><a href="/portal/deserialize">Serialized import</a></li>'
        '<li><a href="/portal/attachments">Attachments</a></li>'
        if user is not None
        else '<li><a href="/login">Login</a></li>'
    )
    return f"""
    <html>
      <head><title>Pentra Parser Upload Demo</title></head>
      <body>
        <h1>Pentra Parser Upload Demo</h1>
        <p>Controlled parser, file, and upload benchmark target.</p>
        <ul>
          {auth_block}
          <li><a href="/openapi.json">OpenAPI</a></li>
        </ul>
      </body>
    </html>
    """


@app.get("/login", response_class=HTMLResponse)
async def login_page() -> str:
    return f"""
    <html>
      <head><title>Parser Demo Login</title></head>
      <body>
        <h1>Login</h1>
        <form action="/login" method="post">
          <input type="hidden" name="csrf_token" value="{_CSRF_TOKEN}" />
          <input type="hidden" name="pentra_safe_replay" value="true" />
          <label>Username <input type="text" name="username" value="uploader" /></label>
          <label>Password <input type="password" name="password" value="upload123" /></label>
          <button type="submit">Sign in</button>
        </form>
      </body>
    </html>
    """


@app.post("/login")
async def login_submit(request: Request):
    form = await _read_form_data(request)
    username = str(form.get("username") or "")
    password = str(form.get("password") or "")
    csrf_token = str(form.get("csrf_token") or "")
    user = _USERS.get(username)
    if csrf_token != _CSRF_TOKEN or user is None or password != user["password"]:
        return JSONResponse({"success": False, "message": "Invalid credentials"}, status_code=401)

    response = RedirectResponse(url="/portal/upload", status_code=302)
    response.set_cookie("parser_demo_user", username)
    response.set_cookie("csrf_token", _CSRF_TOKEN)
    return response


@app.get("/portal/upload", response_class=HTMLResponse)
async def upload_page(request: Request):
    user = _require_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=302)

    return HTMLResponse(
        f"""
        <html>
          <head><title>Upload Preview</title></head>
          <body>
            <h1>Upload Preview</h1>
            <p>Signed in as {html.escape(user["username"])}</p>
            <form action="/portal/upload/preview" method="post" enctype="multipart/form-data">
              <input type="hidden" name="csrf_token" value="{_CSRF_TOKEN}" />
              <input type="hidden" name="pentra_safe_replay" value="true" />
              <label>Filename <input type="text" name="filename" value="invoice.xml" /></label>
              <label>Document <input type="file" name="document" /></label>
              <label>File contents <input type="text" name="file_contents" value="&lt;invoice&gt;pentra&lt;/invoice&gt;" /></label>
              <label>Metadata XML <input type="text" name="metadata_xml" value="&lt;invoice id='7'&gt;ok&lt;/invoice&gt;" /></label>
              <button type="submit">Preview upload</button>
            </form>
            <a href="/portal/import/xml">Import XML directly</a>
          </body>
        </html>
        """
    )


@app.post("/portal/upload/preview", response_class=HTMLResponse)
async def upload_preview(request: Request):
    user = _require_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=302)

    form = await _read_form_data(request)
    filename = str(form.get("filename") or "invoice.xml")
    file_contents = str(form.get("file_contents") or "")
    metadata_xml = str(form.get("metadata_xml") or "")
    parser_note = _parser_note(file_contents, metadata_xml)
    status = 400 if parser_note["parser_error"] else 200
    return HTMLResponse(
        f"""
        <html>
          <head><title>Upload Preview Result</title></head>
          <body>
            <h1>Upload Preview Result</h1>
            <p>Filename: {html.escape(filename)}</p>
            <p>Upload workflow parser result: {html.escape(parser_note["message"])}</p>
            <a href="/portal/attachments">Continue to attachments</a>
          </body>
        </html>
        """,
        status_code=status,
    )


@app.get("/portal/import/xml", response_class=HTMLResponse)
async def xml_import_page(request: Request):
    user = _require_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=302)

    return HTMLResponse(
        f"""
        <html>
          <head><title>XML Import</title></head>
          <body>
            <h1>XML Import</h1>
            <form action="/portal/import/xml" method="post">
              <input type="hidden" name="csrf_token" value="{_CSRF_TOKEN}" />
              <input type="hidden" name="pentra_safe_replay" value="true" />
              <label>XML document <input type="text" name="xml_document" value="&lt;invoice&gt;safe&lt;/invoice&gt;" /></label>
              <label>Import mode <input type="text" name="import_mode" value="xml" /></label>
              <button type="submit">Import XML</button>
            </form>
          </body>
        </html>
        """
    )


@app.post("/portal/import/xml")
async def xml_import_submit(request: Request):
    user = _require_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=302)

    form = await _read_form_data(request)
    xml_document = str(form.get("xml_document") or "")
    import_mode = str(form.get("import_mode") or "xml")
    parser_note = _parser_note(xml_document)
    payload = {
        "route": "/portal/import/xml",
        "import_mode": import_mode,
        "parser_message": parser_note["message"],
        "xml_length": len(xml_document),
    }
    status = 400 if parser_note["parser_error"] else 200
    return JSONResponse(payload, status_code=status)


@app.get("/portal/deserialize", response_class=HTMLResponse)
async def deserialize_page(request: Request):
    user = _require_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=302)

    return HTMLResponse(
        f"""
        <html>
          <head><title>Serialized Import</title></head>
          <body>
            <h1>Serialized Import</h1>
            <form action="/portal/deserialize" method="post">
              <input type="hidden" name="csrf_token" value="{_CSRF_TOKEN}" />
              <input type="hidden" name="pentra_safe_replay" value="true" />
              <label>Serialized payload <input type="text" name="serialized_payload" value='{{"kind":"invoice","id":7}}' /></label>
              <label>Encoding <input type="text" name="encoding" value="json" /></label>
              <button type="submit">Preview object</button>
            </form>
          </body>
        </html>
        """
    )


@app.post("/portal/deserialize")
async def deserialize_submit(request: Request):
    user = _require_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=302)

    form = await _read_form_data(request)
    serialized_payload = str(form.get("serialized_payload") or "")
    encoding = str(form.get("encoding") or "json")
    parser_note = _deserialization_note(serialized_payload)
    payload = {
        "route": "/portal/deserialize",
        "encoding": encoding,
        "parser_message": parser_note["message"],
        "payload_length": len(serialized_payload),
    }
    status = 422 if parser_note["parser_error"] else 200
    return JSONResponse(payload, status_code=status)


@app.get("/portal/attachments", response_class=HTMLResponse)
async def attachments_page(request: Request):
    user = _require_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=302)

    return HTMLResponse(
        """
        <html>
          <head><title>Attachments</title></head>
          <body>
            <h1>Attachments</h1>
            <ul>
              <li><a href="/portal/upload">Upload another file</a></li>
              <li><a href="/portal/import/xml">Import XML</a></li>
              <li><a href="/portal/deserialize">Import serialized data</a></li>
            </ul>
          </body>
        </html>
        """
    )


@app.post("/api/v1/import/xml")
async def xml_import_api(request: Request):
    body = (await request.body()).decode("utf-8", errors="ignore")
    parser_note = _parser_note(body)
    status = 400 if parser_note["parser_error"] else 200
    return JSONResponse(
        {
            "route": "/api/v1/import/xml",
            "parser_message": parser_note["message"],
        },
        status_code=status,
    )


@app.post("/api/v1/deserialize")
async def deserialize_api(request: Request):
    body = (await request.body()).decode("utf-8", errors="ignore")
    parser_note = _deserialization_note(body)
    status = 422 if parser_note["parser_error"] else 200
    return JSONResponse(
        {
            "route": "/api/v1/deserialize",
            "parser_message": parser_note["message"],
        },
        status_code=status,
    )


def _parser_note(*parts: str) -> dict[str, Any]:
    content = " ".join(parts).lower()
    if "<!doctype" in content or "&xxe;" in content or "system \"" in content:
        return {
            "parser_error": True,
            "message": "XML parser error near DOCTYPE; external entity handling must remain disabled.",
        }
    if "<?xml" in content or "<invoice" in content or "<report" in content:
        return {
            "parser_error": False,
            "message": "XML parser boundary reached with replayable document input.",
        }
    return {
        "parser_error": False,
        "message": "Upload metadata accepted without parser-specific delta.",
    }


def _deserialization_note(content: str) -> dict[str, Any]:
    lowered = content.lower()
    if lowered.startswith("rO0".lower()) or "!!python" in lowered or "objectinputstream" in lowered or "o:" in lowered:
        return {
            "parser_error": True,
            "message": "Unsafe serialized object marker reached the parser boundary during preview.",
        }
    if lowered.strip().startswith("{") or lowered.strip().startswith("["):
        return {
            "parser_error": False,
            "message": "Structured object payload accepted in bounded preview mode.",
        }
    return {
        "parser_error": False,
        "message": "Serialized payload route reached without unsafe object markers.",
    }


def _require_user(request: Request) -> dict[str, str] | None:
    username = str(request.cookies.get("parser_demo_user") or "")
    user = _USERS.get(username)
    return dict(user) if user is not None else None


async def _read_form_data(request: Request) -> dict[str, str]:
    content_type = str(request.headers.get("content-type") or "").lower()
    body = await request.body()
    if "application/x-www-form-urlencoded" in content_type or "=" in body.decode(
        "utf-8", errors="ignore"
    ):
        return {
            str(key): str(value)
            for key, value in parse_qsl(body.decode("utf-8", errors="ignore"), keep_blank_values=True)
        }
    if "multipart/form-data" in content_type:
        return _parse_multipart_form_data(body=body, content_type=content_type)
    return {}


def _parse_multipart_form_data(*, body: bytes, content_type: str) -> dict[str, str]:
    boundary = _multipart_boundary(content_type)
    if not boundary:
        return {}

    delimiter = f"--{boundary}".encode("utf-8")
    payload: dict[str, str] = {}
    for part in body.split(delimiter):
        chunk = part.strip()
        if not chunk or chunk == b"--":
            continue
        if chunk.endswith(b"--"):
            chunk = chunk[:-2]
        chunk = chunk.strip(b"\r\n")
        if b"\r\n\r\n" not in chunk:
            continue
        raw_headers, raw_value = chunk.split(b"\r\n\r\n", 1)
        disposition = ""
        for header in raw_headers.decode("utf-8", errors="ignore").split("\r\n"):
            if header.lower().startswith("content-disposition:"):
                disposition = header
                break
        name = _content_disposition_attr(disposition, "name")
        if not name:
            continue
        filename = _content_disposition_attr(disposition, "filename")
        value = filename or raw_value.rstrip(b"\r\n").decode("utf-8", errors="ignore")
        payload[name] = value
    return payload


def _multipart_boundary(content_type: str) -> str:
    for segment in content_type.split(";"):
        key, separator, value = segment.strip().partition("=")
        if separator and key.strip().lower() == "boundary":
            return value.strip().strip('"')
    return ""


def _content_disposition_attr(disposition: str, key: str) -> str:
    needle = key.strip().lower()
    for segment in disposition.split(";"):
        name, separator, value = segment.strip().partition("=")
        if separator and name.strip().lower() == needle:
            return value.strip().strip('"')
    return ""
