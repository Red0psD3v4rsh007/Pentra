from __future__ import annotations

import os
import sys

import httpx
import pytest


_this_dir = os.path.dirname(os.path.abspath(__file__))
_svc_root = os.path.dirname(_this_dir)
_repo_root = os.path.dirname(os.path.dirname(os.path.dirname(_svc_root)))
if _svc_root not in sys.path:
    sys.path.insert(0, _svc_root)
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_parser_demo_login_xml_and_deserialization_routes_work_without_python_multipart() -> None:
    from pentra_core.dev_targets.parser_upload_demo.app import app

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://parser-demo.test",
        follow_redirects=True,
    ) as client:
        login = await client.post(
            "/login",
            data={
                "csrf_token": "parser-demo-csrf",
                "pentra_safe_replay": "true",
                "username": "uploader",
                "password": "upload123",
            },
        )
        assert login.status_code == 200
        assert "Upload Preview" in login.text

        xml_import = await client.post(
            "/portal/import/xml",
            data={
                "csrf_token": "parser-demo-csrf",
                "pentra_safe_replay": "true",
                "xml_document": '<!DOCTYPE invoice [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><invoice>&xxe;</invoice>',
                "import_mode": "xml",
            },
        )
        assert xml_import.status_code == 400
        assert "XML parser error" in xml_import.json()["parser_message"]

        deserialize = await client.post(
            "/portal/deserialize",
            data={
                "csrf_token": "parser-demo-csrf",
                "pentra_safe_replay": "true",
                "serialized_payload": "O:8:\"Exploit\":0:{}",
                "encoding": "php",
            },
        )
        assert deserialize.status_code == 422
        assert "Unsafe serialized object marker" in deserialize.json()["parser_message"]


@pytest.mark.anyio
async def test_parser_demo_upload_preview_accepts_multipart_without_python_multipart() -> None:
    from pentra_core.dev_targets.parser_upload_demo.app import app

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://parser-demo.test",
        follow_redirects=True,
    ) as client:
        await client.post(
            "/login",
            data={
                "csrf_token": "parser-demo-csrf",
                "pentra_safe_replay": "true",
                "username": "uploader",
                "password": "upload123",
            },
        )

        preview = await client.post(
            "/portal/upload/preview",
            data={
                "csrf_token": "parser-demo-csrf",
                "pentra_safe_replay": "true",
                "filename": "invoice.xml",
                "file_contents": "<invoice>safe</invoice>",
                "metadata_xml": "<invoice id='7'>ok</invoice>",
            },
            files={"document": ("invoice.xml", b"<invoice>safe</invoice>", "text/xml")},
        )
        assert preview.status_code == 200
        assert "Upload Preview Result" in preview.text
