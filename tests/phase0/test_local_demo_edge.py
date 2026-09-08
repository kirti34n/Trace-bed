"""The opt-in local demo edge has its own loopback-only boundary."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from tracebed.edge import local_demo
from tracebed.edge.local_demo import LocalDemoSettings, create_app

pytestmark = pytest.mark.phase0

_ORIGIN = "http://127.0.0.1:48049"
_KEY = "tb_sk_demo-key1.abcdefghijklmnop"
_MANIFEST: dict[str, Any] = {
    "schema_version": 1,
    "mode": "local_demo",
    "title": "Demo",
    "provenance": "Imported after execution.",
    "runs": [],
}


def _client(seen: list[httpx.Request]) -> TestClient:
    async def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/admin/whoami":
            return httpx.Response(
                200,
                json={
                    "project_id": "11111111-1111-1111-1111-111111111111",
                    "agent_type_id": "22222222-2222-2222-2222-222222222222",
                    "principal_id": "33333333-3333-3333-3333-333333333333",
                },
            )
        if request.url.path == "/export/project":
            return httpx.Response(200, content=b'{"table":"trace_index","row":{}}\n')
        return httpx.Response(202, json={"status": "accepted"})

    return TestClient(
        create_app(
            LocalDemoSettings(origin=_ORIGIN),
            upstream_http=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
            api_key_loader=lambda: _KEY,
            manifest_loader=lambda: _MANIFEST,
        ),
        base_url=_ORIGIN,
        client=("10.77.15.3", 43_210),
        headers={"X-Tracebed-Client-Address": "10.77.15.1"},
    )


def test_local_demo_admits_only_fixed_loopback_ingress_and_keeps_key_server_side() -> None:
    seen: list[httpx.Request] = []
    with _client(seen) as client:
        manifest = client.get("/auth/demo-manifest")
        assert manifest.status_code == 200
        assert manifest.json() == _MANIFEST

        login = client.get("/auth/login", follow_redirects=False)
        assert login.status_code == 303
        cookie = login.headers["set-cookie"]
        assert "HttpOnly" in cookie
        assert "SameSite=lax" in cookie
        assert "Secure" not in cookie
        assert _KEY not in login.text and _KEY not in cookie
        assert seen[0].headers["x-api-key"] == _KEY
        assert "authorization" not in seen[0].headers

        csrf = client.get("/auth/csrf").json()["csrf_token"]
        result = client.post(
            "/v1/trace",
            json={"event": "ordinary"},
            headers={
                "Origin": _ORIGIN,
                "X-CSRF-Token": csrf,
                "Authorization": "Bearer browser-forged",
                "X-API-Key": "browser-forged",
                "X-Admin-Key": "browser-forged",
            },
        )
        assert result.status_code == 202
        proxied = seen[-1]
        assert proxied.headers["x-api-key"] == _KEY
        assert "authorization" not in proxied.headers
        assert "x-admin-key" not in proxied.headers


def test_local_demo_rejects_rebinding_and_preserves_csrf() -> None:
    seen: list[httpx.Request] = []
    with _client(seen) as client:
        assert (
            client.get(
                "/auth/login", headers={"X-Tracebed-Client-Address": "127.0.0.1"}
            ).status_code
            == 403
        )
        assert client.get("/auth/login", headers={"Host": "evil.example"}).status_code == 403
        assert (
            client.post("/v1/trace", json={"x": 1}, headers={"Origin": _ORIGIN}).status_code == 401
        )
        assert client.get("/auth/login", follow_redirects=False).status_code == 303
        csrf = client.get("/auth/csrf").json()["csrf_token"]
        assert (
            client.post(
                "/v1/trace",
                json={"x": 1},
                headers={"Origin": "http://127.0.0.1:49000", "X-CSRF-Token": csrf},
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/v1/trace", json={"x": 1}, headers={"Origin": _ORIGIN, "X-CSRF-Token": "forged"}
            ).status_code
            == 403
        )


@pytest.mark.parametrize(
    "origin",
    [
        "https://127.0.0.1:48049",
        "http://localhost:48049",
        "http://127.0.0.1:80",
        "http://127.0.0.1:48049/not-root",
        "http://127.0.0.1:48049?rebind=yes",
    ],
)
def test_local_demo_refuses_non_exact_loopback_origins(origin: str) -> None:
    with pytest.raises(ValueError):
        LocalDemoSettings(origin=origin)


@pytest.mark.parametrize("suffix", ["", "\n"])
def test_local_demo_secret_accepts_one_normal_line_ending(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, suffix: str
) -> None:
    secret = tmp_path / "demo_api_key_secret"
    secret.write_text(_KEY + suffix, encoding="utf-8")
    monkeypatch.setattr(local_demo, "_DEMO_SECRET_PATH", secret)
    assert local_demo._load_demo_api_key() == _KEY


@pytest.mark.parametrize("value", [_KEY + "\n\n", _KEY + "\nwrong"])
def test_local_demo_secret_rejects_embedded_newlines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    secret = tmp_path / "demo_api_key_secret"
    secret.write_text(value, encoding="utf-8")
    monkeypatch.setattr(local_demo, "_DEMO_SECRET_PATH", secret)
    with pytest.raises(RuntimeError, match="local demo secret is invalid"):
        local_demo._load_demo_api_key()
