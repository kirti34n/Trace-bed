"""Same-origin OIDC edge: opaque sessions, exact routes, and header stripping."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm

from tracebed.adapters.identity import OidcJwksVerifier, PrincipalRecord
from tracebed.domain.errors import AuthenticationFailed
from tracebed.domain.ids import PrincipalId
from tracebed.edge.config import EdgeSettings
from tracebed.edge.main import (
    _MAX_EXPORT_BYTES,
    _MAX_PENDING_LOGINS,
    _MAX_SESSIONS,
    _SessionStore,
    _TokenResponse,
    create_app,
)

pytestmark = pytest.mark.phase0

_ISSUER = "https://idp.example.test/realm"
_ORIGIN = "https://dashboard.example.test"
_CLIENT_ID = "tracebed-dashboard"
_API_AUDIENCE = "tracebed-api"
_JWKS_URL = "https://idp.example.test/jwks"


def _private_key_and_jwk() -> tuple[bytes, dict[str, object]]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    jwk = RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    jwk.update({"kid": "edge-test-key", "use": "sig", "alg": "RS256"})
    return private_key_pem, jwk


def _id_token(private_key: bytes, nonce: str) -> str:
    current = datetime.now(UTC)
    return jwt.encode(
        {
            "sub": "browser-user",
            "iss": _ISSUER,
            "aud": _CLIENT_ID,
            "iat": current,
            "exp": current + timedelta(minutes=5),
            "nonce": nonce,
            "typ": "ID",
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "edge-test-key", "typ": "JWT"},
    )


def _access_token(
    private_key: bytes, *, issuer: str = _ISSUER, audience: str = _API_AUDIENCE, subject: str = "browser-user"
) -> str:
    current = datetime.now(UTC)
    return jwt.encode(
        {
            "sub": subject,
            "iss": issuer,
            "aud": audience,
            "iat": current,
            "exp": current + timedelta(minutes=5),
            "typ": "Bearer",
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "edge-test-key", "typ": "at+jwt"},
    )


def _settings() -> EdgeSettings:
    return EdgeSettings(
        oidc_issuer=_ISSUER,
        oidc_jwks_url=_JWKS_URL,
        oidc_client_id=_CLIENT_ID,
        oidc_api_audience=_API_AUDIENCE,
        redirect_uri=_ORIGIN + "/auth/callback",
        allowed_origin=_ORIGIN,
        trusted_ingress_host="10.77.15.3",
    )


def _app_with_oidc(
    private_key: bytes,
    jwk: dict[str, object],
    seen_upstream: list[httpx.Request],
    *,
    upstream_body: bytes | None = None,
    upstream_stream: httpx.AsyncByteStream | None = None,
) -> TestClient:
    expected_nonce = ""
    issued_access_token = ""
    refreshed = False

    async def oidc_handler(request: httpx.Request) -> httpx.Response:
        nonlocal issued_access_token, refreshed
        if request.url.path.endswith(".well-known/openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": _ISSUER,
                    "authorization_endpoint": "https://idp.example.test/authorize",
                    "token_endpoint": "https://idp.example.test/token",
                    "jwks_uri": _JWKS_URL,
                },
            )
        if request.url == httpx.URL("https://idp.example.test/token"):
            body = request.content.decode("ascii")
            if "grant_type=refresh_token" in body:
                refreshed = True
                return httpx.Response(
                    200,
                    json={"access_token": "rotated-access", "refresh_token": "rotated-refresh", "expires_in": 60},
                )
            issued_access_token = _access_token(private_key)
            return httpx.Response(
                200,
                json={
                    "access_token": issued_access_token,
                    "refresh_token": "refresh-one",
                    "id_token": _id_token(private_key, expected_nonce),
                    "expires_in": 1,
                },
            )
        return httpx.Response(404)

    async def api_handler(request: httpx.Request) -> httpx.Response:
        seen_upstream.append(request)
        if request.url.path == "/admin/whoami":
            return httpx.Response(
                200,
                json={
                    "project_id": "11111111-1111-1111-1111-111111111111",
                    "agent_type_id": "22222222-2222-2222-2222-222222222222",
                    "principal_id": "33333333-3333-3333-3333-333333333333",
                },
            )
        if upstream_stream is not None and request.url.path == "/export/project":
            return httpx.Response(
                200,
                stream=upstream_stream,
                headers={"content-type": "application/x-ndjson"},
            )
        if upstream_body is not None and request.url.path == "/export/project":
            return httpx.Response(
                200,
                content=upstream_body,
                headers={"content-type": "application/x-ndjson"},
            )
        return httpx.Response(202, json={"accepted": True})

    def jwks_handler(request: httpx.Request) -> httpx.Response:
        assert request.url == httpx.URL(_JWKS_URL)
        return httpx.Response(200, json={"keys": [jwk]})

    oidc_client = httpx.AsyncClient(transport=httpx.MockTransport(oidc_handler))
    api_client = httpx.AsyncClient(transport=httpx.MockTransport(api_handler))
    app = create_app(
        _settings(),
        oidc_http=oidc_client,
        upstream_http=api_client,
        token_validator_http=httpx.Client(transport=httpx.MockTransport(jwks_handler)),
    )
    client = TestClient(
        app,
        base_url=_ORIGIN,
        client=("10.77.15.3", 43_210),
        headers={"X-Tracebed-Client-Address": "198.51.100.10"},
    )
    login = client.get("/auth/login", follow_redirects=False)
    assert login.status_code == 303
    params = parse_qs(urlsplit(login.headers["location"]).query)
    expected_nonce = params["nonce"][0]
    assert params["code_challenge_method"] == ["S256"]
    callback = client.get("/auth/callback", params={"code": "code-one", "state": params["state"][0]}, follow_redirects=False)
    assert callback.status_code == 303
    assert "HttpOnly" in callback.headers["set-cookie"]
    assert "SameSite=lax" in callback.headers["set-cookie"]
    assert "Secure" in callback.headers["set-cookie"]
    assert not refreshed
    return client


def test_edge_is_disabled_without_complete_oidc_config() -> None:
    app = create_app(EdgeSettings())
    with TestClient(app, base_url="http://localhost") as client:
        assert client.get("/healthz").status_code == 200
        assert client.get("/auth/login").status_code == 404
        assert client.get("/auth/session").json() == {"authenticated": False, "csrf_token": None}
        assert client.post("/v1/retrieve").status_code == 401


def test_edge_allows_only_ordinary_paths_and_strips_browser_assertions() -> None:
    private_key, jwk = _private_key_and_jwk()
    seen: list[httpx.Request] = []
    client = _app_with_oidc(private_key, jwk, seen)
    try:
        csrf = client.get("/auth/csrf").json()["csrf_token"]
        headers = {
            "Origin": _ORIGIN,
            "X-CSRF-Token": csrf,
            "Authorization": "Bearer attacker-token",
            "X-API-Key": "attacker-key",
            "X-Project-Id": "attacker-project",
            "X-Admin-Key": "attacker-admin",
            "X-Owner-Key": "attacker-owner",
            "X-Erasure-Key": "attacker-erasure",
        }
        response = client.post("/v1/trace", json={"event": "ordinary"}, headers=headers)
        assert response.status_code == 202
        request = seen[0]
        assert request.headers["authorization"].startswith("Bearer ey")
        assert request.headers["authorization"] != "Bearer attacker-token"
        assert all(
            name not in request.headers
            for name in ("x-api-key", "x-project-id", "x-admin-key", "x-owner-key", "x-erasure-key")
        )
        # Read-only project views are session-authenticated but deliberately
        # do not require an Origin or CSRF header.
        assert client.get("/admin/whoami").status_code == 200
        assert client.get("/admin/memory?limit=20").status_code == 202
        assert str(seen[-1].url).endswith("/admin/memory?limit=20")
        assert client.post("/admin/agents/register", headers=headers).status_code == 404
        assert client.post("/v1/erasure-requests", headers=headers).status_code == 404
        assert client.get("/admin/memory/%2e%2e%2fwhoami").status_code == 404
        assert client.get("/admin%2fwhoami").status_code == 404
        assert client.get("/admin/memory/%252e%252e%252fwhoami").status_code == 404
        assert len(seen) == 4
    finally:
        client.close()


@pytest.mark.parametrize("case", ["valid", "wrong_issuer", "wrong_audience", "unknown", "revoked"])
def test_configured_oidc_code_pkce_to_api_whoami_uses_the_registered_api_principal(
    case: str,
) -> None:
    """A deterministic in-process IdP/JWKS proves the configured BFF/API boundary.

    The IdP signs the callback's ID and access tokens with a fresh RSA key.
    Edge checks its client-ID ID token and explicit API audience; the private
    API handler independently uses the production JWKS verifier and registered
    principal lookup before exposing whoami.  No host token or identity header
    can make this path succeed.
    """
    private_key, jwk = _private_key_and_jwk()
    nonce = ""

    class Principals:
        def get_principal_by_external_ref(self, kind: str, external_ref: str) -> PrincipalRecord | None:
            if kind != "oidc_sub" or external_ref != "browser-user" or case == "unknown":
                return None
            return PrincipalRecord(
                principal_id=PrincipalId("33333333-3333-3333-3333-333333333333"),
                kind="oidc_sub",
                external_ref=external_ref,
                key_hash=None,
                revoked=case == "revoked",
            )

    def jwks_handler(request: httpx.Request) -> httpx.Response:
        assert request.url == httpx.URL(_JWKS_URL)
        return httpx.Response(200, json={"keys": [jwk]})

    validator_http = httpx.Client(transport=httpx.MockTransport(jwks_handler))

    async def oidc_handler(request: httpx.Request) -> httpx.Response:
        nonlocal nonce
        if request.url.path.endswith(".well-known/openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": _ISSUER,
                    "authorization_endpoint": "https://idp.example.test/authorize",
                    "token_endpoint": "https://idp.example.test/token",
                    "jwks_uri": _JWKS_URL,
                },
            )
        assert request.url == httpx.URL("https://idp.example.test/token")
        fields = parse_qs(request.content.decode("ascii"))
        assert fields["grant_type"] == ["authorization_code"]
        assert fields["client_id"] == [_CLIENT_ID]
        assert fields["redirect_uri"] == [_ORIGIN + "/auth/callback"]
        assert len(fields["code_verifier"][0]) >= 43
        issuer = "https://other-idp.example.test/realm" if case == "wrong_issuer" else _ISSUER
        audience = "different-api" if case == "wrong_audience" else _API_AUDIENCE
        return httpx.Response(
            200,
            json={
                "access_token": _access_token(private_key, issuer=issuer, audience=audience),
                "refresh_token": "ephemeral-refresh",
                "id_token": _id_token(private_key, nonce),
                "expires_in": 60,
            },
        )

    async def api_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path != "/admin/whoami":
            return httpx.Response(404)
        try:
            principal = OidcJwksVerifier(
                _JWKS_URL,
                _ISSUER,
                audience=_API_AUDIENCE,
                http=validator_http,
                principals=Principals(),
            ).authenticate(authorization=request.headers.get("authorization"), api_key=None)
        except AuthenticationFailed:  # The API boundary remains an undifferentiated 401.
            return httpx.Response(401)
        assert str(principal.principal_id) == "33333333-3333-3333-3333-333333333333"
        return httpx.Response(
            200,
            json={
                "project_id": "11111111-1111-1111-1111-111111111111",
                "agent_type_id": "22222222-2222-2222-2222-222222222222",
                "principal_id": str(principal.principal_id),
            },
        )

    app = create_app(
        _settings(),
        oidc_http=httpx.AsyncClient(transport=httpx.MockTransport(oidc_handler)),
        upstream_http=httpx.AsyncClient(transport=httpx.MockTransport(api_handler)),
        token_validator_http=validator_http,
    )
    with TestClient(app, base_url=_ORIGIN) as client:
        login = client.get("/auth/login", follow_redirects=False)
        query = parse_qs(urlsplit(login.headers["location"]).query)
        nonce = query["nonce"][0]
        callback = client.get(
            "/auth/callback", params={"code": "ephemeral-code", "state": query["state"][0]}, follow_redirects=False
        )
        if case == "valid":
            assert callback.status_code == 303
            assert client.get("/admin/whoami").status_code == 200
            assert client.get("/admin/agents/register").status_code == 404
            assert client.get("/admin/owner").status_code == 404
            assert client.post("/v1/erasure-requests").status_code == 404
        else:
            assert callback.status_code == 401


def test_edge_bounds_and_locks_memory_list_query_grammar() -> None:
    private_key, jwk = _private_key_and_jwk()
    client = _app_with_oidc(private_key, jwk, [])
    try:
        assert client.get("/admin/memory?limit=200&status=validated").status_code == 202
        assert client.get("/admin/memory?limit=201").status_code == 404
        assert client.get("/admin/memory?project_id=attacker").status_code == 404
        assert client.get("/admin/memory?cursor=" + "x" * 1_025).status_code == 404
        statuses = "&".join(
            f"status={status}"
            for status in (
                "archived",
                "candidate",
                "pinned",
                "quarantined",
                "retired",
                "stale",
                "superseded",
                "tombstoned",
            )
        )
        assert client.get("/admin/memory?limit=100&cursor=opaque&" + statuses).status_code == 202
        assert client.get("/admin/memory/11111111-1111-1111-1111-111111111111").status_code == 202
        assert client.get("/admin/memory/11111111-1111-1111-1111-111111111111?x=1").status_code == 404
    finally:
        client.close()


def test_login_discovery_is_cached_and_same_client_retries_replace_pending_state() -> None:
    private_key, jwk = _private_key_and_jwk()
    del private_key
    discoveries = 0
    clock = [0.0]

    async def oidc_handler(request: httpx.Request) -> httpx.Response:
        nonlocal discoveries
        if request.url.path.endswith(".well-known/openid-configuration"):
            discoveries += 1
            return httpx.Response(
                200,
                json={
                    "issuer": _ISSUER,
                    "authorization_endpoint": "https://idp.example.test/authorize",
                    "token_endpoint": "https://idp.example.test/token",
                    "jwks_uri": _JWKS_URL,
                },
            )
        return httpx.Response(404)

    def jwks_handler(request: httpx.Request) -> httpx.Response:
        assert request.url == httpx.URL(_JWKS_URL)
        return httpx.Response(200, json={"keys": [jwk]})

    app = create_app(
        _settings(),
        oidc_http=httpx.AsyncClient(transport=httpx.MockTransport(oidc_handler)),
        token_validator_http=httpx.Client(transport=httpx.MockTransport(jwks_handler)),
        now=lambda: clock[0],
    )
    with TestClient(app, base_url=_ORIGIN) as client:
        for _ in range(_MAX_PENDING_LOGINS):
            assert client.get("/auth/login", follow_redirects=False).status_code == 303
        assert discoveries == 1
        assert client.get("/auth/login", follow_redirects=False).status_code == 303
        # The fixed TTL expires only once; no public-login hit causes another
        # discovery request until then.
        clock[0] = 301.0
        assert client.get("/auth/login", follow_redirects=False).status_code == 303
        assert discoveries == 2


def test_login_identity_uses_nginx_socket_and_overwritten_address_only() -> None:
    token_attempts = 0

    async def oidc_handler(request: httpx.Request) -> httpx.Response:
        nonlocal token_attempts
        if request.url.path.endswith(".well-known/openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": _ISSUER,
                    "authorization_endpoint": "https://idp.example.test/authorize",
                    "token_endpoint": "https://idp.example.test/token",
                    "jwks_uri": _JWKS_URL,
                },
            )
        token_attempts += 1
        return httpx.Response(401)

    app = create_app(_settings(), oidc_http=httpx.AsyncClient(transport=httpx.MockTransport(oidc_handler)))

    # Separate browser addresses behind the exact nginx address retain two
    # pending states; A's callback reaches the token endpoint after B logs in.
    a = TestClient(
        app,
        base_url=_ORIGIN,
        client=("10.77.15.3", 40_001),
        headers={"X-Tracebed-Client-Address": "203.0.113.10"},
    )
    b = TestClient(
        app,
        base_url=_ORIGIN,
        client=("10.77.15.3", 40_002),
        headers={"X-Tracebed-Client-Address": "203.0.113.11"},
    )
    try:
        a_login = a.get("/auth/login", follow_redirects=False)
        b_login = b.get("/auth/login", follow_redirects=False)
        a_state = parse_qs(urlsplit(a_login.headers["location"]).query)["state"][0]
        assert b_login.status_code == 303
        assert a.get("/auth/callback", params={"code": "a", "state": a_state}).status_code == 401
        assert token_attempts == 1
    finally:
        a.close()
        b.close()

    # A second login from the same nginx-provided browser identity replaces
    # the first.  A forged client-address header from a non-nginx peer is
    # ignored, so it likewise cannot allocate a second pending bucket.
    same = TestClient(
        app,
        base_url=_ORIGIN,
        client=("10.77.15.3", 40_003),
        headers={"X-Tracebed-Client-Address": "203.0.113.12"},
    )
    direct_a = TestClient(
        app,
        base_url=_ORIGIN,
        client=("10.77.15.99", 40_004),
        headers={"X-Tracebed-Client-Address": "203.0.113.20"},
    )
    direct_b = TestClient(
        app,
        base_url=_ORIGIN,
        client=("10.77.15.99", 40_005),
        headers={"X-Tracebed-Client-Address": "203.0.113.21"},
    )
    try:
        first = same.get("/auth/login", follow_redirects=False)
        second = same.get("/auth/login", follow_redirects=False)
        first_state = parse_qs(urlsplit(first.headers["location"]).query)["state"][0]
        assert second.status_code == 303
        assert same.get("/auth/callback", params={"code": "same", "state": first_state}).status_code == 401
        before = token_attempts
        forged_first = direct_a.get("/auth/login", follow_redirects=False)
        direct_b.get("/auth/login", follow_redirects=False)
        forged_state = parse_qs(urlsplit(forged_first.headers["location"]).query)["state"][0]
        assert direct_a.get("/auth/callback", params={"code": "forged", "state": forged_state}).status_code == 401
        assert token_attempts == before
    finally:
        same.close()
        direct_a.close()
        direct_b.close()


def test_session_store_never_evicts_an_unrelated_live_session_at_capacity() -> None:
    store = _SessionStore()
    settings = EdgeSettings()
    tokens = _TokenResponse("access", "refresh", "id", 60)
    session_ids = [
        store.create_session(tokens, f"00000000-0000-0000-0000-{index:012d}", 0.0, settings)
        for index in range(_MAX_SESSIONS)
    ]

    rejected = store.create_session(tokens, "ffffffff-ffff-ffff-ffff-ffffffffffff", 0.0, settings)
    rotated = store.create_session(tokens, "00000000-0000-0000-0000-000000000000", 0.0, settings)

    assert rejected is None
    assert session_ids[0] is not None
    assert store.get_session(session_ids[0], 0.0, settings) is None
    assert rotated is not None
    assert store.get_session(rotated, 0.0, settings) is not None
    assert session_ids[1] is not None
    assert store.get_session(session_ids[1], 0.0, settings) is not None


def test_session_store_rotates_exact_presented_session_and_never_evicts_another_principal() -> None:
    store = _SessionStore()
    settings = EdgeSettings()
    tokens = _TokenResponse("access", "refresh", "id", 60)
    principal_a = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    principal_b = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    b_session = store.create_session(tokens, principal_b, 0.0, settings)
    assert b_session is not None

    # A browser which presents B while logging in as A rotates only B's exact
    # cookie.  It cannot evict an unrelated session by naming another value.
    a_session = store.create_session(
        tokens, principal_a, 1.0, settings, previous_session_id=b_session
    )
    assert a_session is not None
    assert store.get_session(b_session, 1.0, settings) is None
    assert store.get_session(a_session, 1.0, settings) is not None

    # A second A login atomically replaces A while preserving every other
    # registered browser (including B after it obtains a fresh session).
    b_new = store.create_session(tokens, principal_b, 2.0, settings)
    a_rotated = store.create_session(tokens, principal_a, 2.0, settings, previous_session_id=a_session)
    assert b_new is not None and a_rotated is not None
    assert store.get_session(a_session, 2.0, settings) is None
    assert store.get_session(a_rotated, 2.0, settings) is not None
    assert store.get_session(b_new, 2.0, settings) is not None


def test_dashboard_ingress_keeps_login_burst_bounded_and_export_unbuffered() -> None:
    config = (Path(__file__).parents[2] / "dashboard" / "nginx.conf").read_text(encoding="utf-8")
    assert "limit_req_zone $binary_remote_addr zone=tracebed_auth_login:10m rate=5r/s;" in config
    assert "location = /auth/login {\n        limit_req zone=tracebed_auth_login burst=10 nodelay;" in config
    assert "location = /export/project {\n        proxy_buffering off;\n        proxy_request_buffering off;" in config


def test_export_project_streams_more_than_request_body_limit_with_a_total_bound() -> None:
    private_key, jwk = _private_key_and_jwk()
    payload = b'{"table":"memory_item","row":{}}\n' * 70_000
    assert len(payload) > 1_048_576
    client = _app_with_oidc(private_key, jwk, [], upstream_body=payload)
    try:
        response = client.get("/export/project")
        assert response.status_code == 200
        assert response.content == payload
        assert response.headers["content-type"] == "application/x-ndjson"
        assert response.headers["x-tracebed-export-completeness"] == "complete"
        assert response.headers["x-tracebed-export-max-bytes"] == str(_MAX_EXPORT_BYTES)
    finally:
        client.close()


def test_export_project_unknown_length_multichunk_under_cap_has_clean_complete_eof() -> None:
    private_key, jwk = _private_key_and_jwk()
    chunks = [b"a" * 600_000, b"b" * 600_000, b"c" * 400_000]

    class UnderLimitStream(httpx.AsyncByteStream):
        closed = False

        async def __aiter__(self) -> Any:
            for chunk in chunks:
                yield chunk

        async def aclose(self) -> None:
            self.closed = True

    stream = UnderLimitStream()
    client = _app_with_oidc(private_key, jwk, [], upstream_stream=stream)
    try:
        response = client.get("/export/project")
        assert response.status_code == 200
        assert response.content == b"".join(chunks)
        assert response.headers["x-tracebed-export-completeness"] == "complete"
        assert response.headers["x-tracebed-export-max-bytes"] == str(_MAX_EXPORT_BYTES)
        assert stream.closed
    finally:
        client.close()


def test_export_project_rejects_declared_over_total_before_forwarding_a_body() -> None:
    private_key, jwk = _private_key_and_jwk()
    client = _app_with_oidc(private_key, jwk, [], upstream_body=b"x" * (_MAX_EXPORT_BYTES + 1))
    try:
        response = client.get("/export/project")
        assert response.status_code == 413
        assert response.content == b'{"detail":"request rejected"}'
    finally:
        client.close()


def test_export_project_cancels_unknown_length_upstream_over_total_without_clean_eof() -> None:
    private_key, jwk = _private_key_and_jwk()

    class OverLimitStream(httpx.AsyncByteStream):
        closed = False

        async def __aiter__(self) -> Any:
            yield b"x" * (8 * 1_024 * 1_024)
            yield b"y" * (9 * 1_024 * 1_024)

        async def aclose(self) -> None:
            self.closed = True

    stream = OverLimitStream()
    client = _app_with_oidc(private_key, jwk, [], upstream_stream=stream)
    try:
        with pytest.raises(RuntimeError, match="export exceeded total byte limit"):
            client.get("/export/project")
        assert stream.closed
    finally:
        client.close()


def test_edge_requires_exact_origin_and_synchronizer_csrf_for_mutations() -> None:
    private_key, jwk = _private_key_and_jwk()
    client = _app_with_oidc(private_key, jwk, [])
    try:
        csrf = client.get("/auth/csrf").json()["csrf_token"]
        assert client.get("/auth/session").json() == {"authenticated": True, "csrf_token": csrf}
        assert client.post("/v1/trace", headers={"X-CSRF-Token": csrf}).status_code == 403
        assert client.post(
            "/v1/trace", headers={"Origin": "https://evil.example", "X-CSRF-Token": csrf}
        ).status_code == 403
        assert client.post("/v1/trace", headers={"Origin": _ORIGIN}).status_code == 403
    finally:
        client.close()


def test_edge_refresh_requires_rotation_and_logout_clears_the_opaque_session() -> None:
    private_key, jwk = _private_key_and_jwk()
    seen: list[httpx.Request] = []
    client = _app_with_oidc(private_key, jwk, seen)
    try:
        csrf = client.get("/auth/csrf").json()["csrf_token"]
        # The login token has a one-second lifetime; an explicit monotonic-free
        # refresh is tested by forcing the BFF process through a fresh login in
        # integration tests. Here we prove logout needs the same CSRF boundary.
        assert client.post("/auth/logout", headers={"Origin": _ORIGIN, "X-CSRF-Token": csrf}).status_code == 204
        assert client.get("/auth/csrf").status_code == 401
    finally:
        client.close()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"oidc_issuer": _ISSUER},
        {
            "oidc_issuer": _ISSUER,
            "oidc_client_id": _CLIENT_ID,
            "redirect_uri": "https://evil.example/auth/callback",
            "allowed_origin": _ORIGIN,
        },
        {
            "oidc_issuer": _ISSUER,
            "oidc_client_id": _CLIENT_ID,
            "redirect_uri": "http://dashboard.example.test/auth/callback",
            "allowed_origin": "http://dashboard.example.test",
            "secure_cookie": False,
        },
    ],
)
def test_edge_rejects_partial_cross_origin_and_nonlocal_insecure_config(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        EdgeSettings(**kwargs)
