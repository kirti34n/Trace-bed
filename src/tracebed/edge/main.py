"""Same-origin OIDC BFF with opaque server-held browser sessions."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from ipaddress import ip_address
from typing import Any, Final, cast
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit
from uuid import UUID

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse, RedirectResponse, StreamingResponse
from pydantic import BaseModel

from tracebed.adapters.identity import (
    OidcJwksVerifier,
    PrincipalKind,
    PrincipalLookup,
    PrincipalRecord,
)
from tracebed.domain.deadline import RemainingBudget
from tracebed.domain.errors import AuthenticationFailed
from tracebed.edge.config import EdgeSettings

__all__ = ["EdgeSettings", "create_app", "run"]

_COOKIE_NAME: Final = "tracebed_session"
_LOGIN_COOKIE_NAME: Final = "tracebed_login"
_CLIENT_IDENTITY_HEADER: Final = "x-tracebed-client-address"
_MAX_BODY_BYTES: Final = 1_048_576
_MAX_EXPORT_BYTES: Final = 16 * 1_024 * 1_024
_MAX_OIDC_RESPONSE_BYTES: Final = 262_144
_MAX_TOKEN_BYTES: Final = 16 * 1024
_MAX_QUERY_BYTES: Final = 2_048
_MAX_QUERY_PAIRS: Final = 10
_MAX_QUERY_KEY_BYTES: Final = 32
_MAX_QUERY_VALUE_BYTES: Final = 1_024
_PENDING_TTL_SECONDS: Final = 300
_MAX_PENDING_LOGINS: Final = 1_024
_MAX_SESSIONS: Final = 2_048
_OIDC_METADATA_TTL_SECONDS: Final = 300
_OIDC_METADATA_RETRY_COOLDOWN_SECONDS: Final = 15
_ALLOWED_PROXY_ROUTES: Final = frozenset(
    {
        ("POST", "v1/retrieve"),
        ("POST", "v1/trace"),
        ("POST", "v1/trace/batch"),
        ("POST", "v1/feedback"),
        ("POST", "v1/propose_memory"),
        ("POST", "v1/invalidation"),
    }
)
_ALLOWED_READ_ROUTES: Final = frozenset(
    {
        "admin/whoami",
        "admin/memory",
        "admin/injections",
        "admin/review_queue",
        "admin/killswitch_state",
        "admin/invalidations",
        "admin/spend",
        "admin/config",
        "admin/lift/report",
        "admin/staleness/report",
        "admin/consolidation/diffs",
        "export/project",
    }
)


class _NoPrincipalLookup(PrincipalLookup):
    """The BFF verifies an ID token but never turns it into application scope."""

    def get_principal_by_external_ref(
        self,
        kind: PrincipalKind,
        external_ref: str,
        *,
        deadline: RemainingBudget | None = None,
    ) -> PrincipalRecord | None:
        del kind, external_ref, deadline
        return None


@dataclass(slots=True)
class _PendingLogin:
    transaction_id: str
    nonce: str
    verifier: str
    expires_at: float


@dataclass(slots=True)
class _Session:
    access_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    csrf_token: str = field(repr=False)
    created_at: float
    last_seen_at: float
    absolute_expires_at: float
    access_expires_at: float
    principal_id: str


class _SessionStore:
    """Small process-local state store: restart intentionally invalidates sessions."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pending: dict[str, _PendingLogin] = {}
        self._pending_by_client: dict[str, str] = {}
        self._sessions: dict[str, _Session] = {}
        self._session_by_principal: dict[str, str] = {}
        # Entries are appended in expiry/creation order.  The map remains the
        # authority, so consuming/deleting an entry does not need a costly
        # queue rebuild; stale queue entries are discarded lazily.
        self._pending_expiry: deque[tuple[float, str]] = deque()
        self._session_expiry: deque[tuple[float, str]] = deque()

    def create_pending(self, now: float, client_id: str) -> tuple[str, _PendingLogin] | None:
        state = secrets.token_urlsafe(32)
        pending = _PendingLogin(
            transaction_id=secrets.token_urlsafe(32),
            nonce=secrets.token_urlsafe(32),
            verifier=secrets.token_urlsafe(64),
            expires_at=now + _PENDING_TTL_SECONDS,
        )
        with self._lock:
            self._prune(now)
            previous = self._pending_by_client.get(client_id)
            if previous is not None:
                # One browser address has one live login transaction. This
                # prevents a retry/flood from consuming global pending slots
                # while preserving unrelated clients' callbacks.
                self._pending.pop(previous, None)
            # Refuse rather than displacing a live login transaction.  This
            # keeps state/cookie pairs one-to-one under a login flood.
            if len(self._pending) >= _MAX_PENDING_LOGINS:
                return None
            self._pending[state] = pending
            self._pending_by_client[client_id] = state
            self._pending_expiry.append((pending.expires_at, state))
        return state, pending

    def consume_pending(
        self, state: str, transaction_id: str | None, now: float
    ) -> _PendingLogin | None:
        with self._lock:
            self._prune(now)
            pending = self._pending.pop(state, None)
            for client_id, pending_state in tuple(self._pending_by_client.items()):
                if pending_state == state:
                    self._pending_by_client.pop(client_id, None)
            if (
                pending is None
                or transaction_id is None
                or not hmac.compare_digest(pending.transaction_id, transaction_id)
            ):
                return None
            return pending

    def create_session(
        self,
        tokens: _TokenResponse,
        principal_id: str,
        now: float,
        settings: EdgeSettings,
        *,
        previous_session_id: str | None = None,
    ) -> str | None:
        session_id = secrets.token_urlsafe(32)
        session = _Session(
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            csrf_token=secrets.token_urlsafe(32),
            created_at=now,
            last_seen_at=now,
            absolute_expires_at=now + settings.session_absolute_seconds,
            access_expires_at=now + tokens.expires_in,
            principal_id=principal_id,
        )
        with self._lock:
            self._prune(now)
            if previous_session_id is not None:
                # A presented browser session is replaced under the SAME lock
                # as admission. This handles B→A deliberately: B's old cookie
                # cannot survive a successful new identity login.
                self._delete_session_locked(previous_session_id)
            old_session_id = self._session_by_principal.get(principal_id)
            if old_session_id is not None:
                self._delete_session_locked(old_session_id)
            elif len(self._sessions) >= _MAX_SESSIONS:
                # Capacity pressure never evicts a live, unrelated browser.
                return None
            self._sessions[session_id] = session
            self._session_by_principal[principal_id] = session_id
            self._session_expiry.append((session.absolute_expires_at, session_id))
        return session_id

    def get_session(self, session_id: str, now: float, settings: EdgeSettings) -> _Session | None:
        with self._lock:
            self._prune(now)
            session = self._sessions.get(session_id)
            if session is None or now - session.last_seen_at > settings.session_idle_seconds:
                self._delete_session_locked(session_id)
                return None
            session.last_seen_at = now
            return session

    def delete_session(self, session_id: str) -> None:
        with self._lock:
            self._delete_session_locked(session_id)

    def _delete_session_locked(self, session_id: str) -> None:
        session = self._sessions.pop(session_id, None)
        if (
            session is not None
            and self._session_by_principal.get(session.principal_id) == session_id
        ):
            self._session_by_principal.pop(session.principal_id, None)

    def _prune(self, now: float) -> None:
        while self._pending_expiry and self._pending_expiry[0][0] <= now:
            _, state = self._pending_expiry.popleft()
            pending = self._pending.get(state)
            if pending is not None and pending.expires_at <= now:
                self._pending.pop(state, None)
                for client_id, pending_state in tuple(self._pending_by_client.items()):
                    if pending_state == state:
                        self._pending_by_client.pop(client_id, None)
        while self._session_expiry and self._session_expiry[0][0] <= now:
            _, session_id = self._session_expiry.popleft()
            session = self._sessions.get(session_id)
            if session is not None and session.absolute_expires_at <= now:
                self._delete_session_locked(session_id)


@dataclass(frozen=True, slots=True)
class _OidcMetadata:
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str


@dataclass(frozen=True, slots=True)
class _TokenResponse:
    access_token: str
    refresh_token: str
    id_token: str
    expires_in: int


class _OidcMetadataCache:
    """Bound discovery fetches and fail closed during an IdP outage."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._value: _OidcMetadata | None = None
        self._expires_at = 0.0
        self._retry_after = 0.0

    async def get(
        self, fetch: Callable[[], Awaitable[_OidcMetadata]], now: Callable[[], float]
    ) -> _OidcMetadata:
        current = now()
        if self._value is not None and current < self._expires_at:
            return self._value
        async with self._lock:
            current = now()
            if self._value is not None and current < self._expires_at:
                return self._value
            if current < self._retry_after:
                raise _generic(503)
            try:
                metadata = await fetch()
            except HTTPException:
                self._retry_after = current + _OIDC_METADATA_RETRY_COOLDOWN_SECONDS
                raise
            self._value = metadata
            self._expires_at = current + _OIDC_METADATA_TTL_SECONDS
            self._retry_after = 0.0
            return metadata


class CsrfOut(BaseModel):
    csrf_token: str


class SessionStatusOut(BaseModel):
    authenticated: bool
    csrf_token: str | None = None


def _pkce_challenge(verifier: str) -> str:
    return (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        .rstrip(b"=")
        .decode("ascii")
    )


def _generic(status_code: int) -> HTTPException:
    return HTTPException(status_code=status_code, detail="request rejected")


def _same_origin_url(issuer: str, candidate: object) -> str:
    if not isinstance(candidate, str):
        raise AuthenticationFailed("OIDC metadata is invalid")
    issuer_parts = urlsplit(issuer)
    endpoint = urlsplit(candidate)
    if (
        endpoint.scheme != "https"
        or endpoint.scheme != issuer_parts.scheme
        or endpoint.netloc != issuer_parts.netloc
        or endpoint.username is not None
        or endpoint.password is not None
        or endpoint.query
        or endpoint.fragment
    ):
        raise AuthenticationFailed("OIDC metadata is invalid")
    return candidate


def _bounded_query(path: str, query: str) -> bool:
    """Bound every forwarded query; lock the vault's small public grammar."""
    try:
        if len(query.encode("ascii")) > _MAX_QUERY_BYTES:
            return False
        pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True)
    except (UnicodeEncodeError, ValueError):
        return False
    if len(pairs) > _MAX_QUERY_PAIRS:
        return False
    for key, value in pairs:
        if (
            not key
            or len(key.encode("utf-8")) > _MAX_QUERY_KEY_BYTES
            or len(value.encode("utf-8")) > _MAX_QUERY_VALUE_BYTES
        ):
            return False
    if path != "admin/memory":
        return True
    for key, value in pairs:
        if key not in {"limit", "status", "cursor"}:
            return False
        if key == "limit" and (
            not value.isascii() or not value.isdecimal() or not 1 <= int(value) <= 200
        ):
            return False
        if key == "status" and value not in {
            "archived",
            "candidate",
            "pinned",
            "quarantined",
            "retired",
            "stale",
            "superseded",
            "tombstoned",
            "validated",
        }:
            return False
        if key == "cursor" and (not value or len(value) > _MAX_QUERY_VALUE_BYTES):
            return False
    return True


def _allowed_proxy_route(method: str, path: str, raw_path: object, query: str) -> bool:
    """Allow only the dashboard's explicit project-scoped API contract.

    The raw-path equality rejects encoded separators, traversal, and
    double-encoding before a proxy can normalize them into an allowlisted path.
    """

    try:
        expected_raw_path = ("/" + path).encode("ascii")
    except UnicodeEncodeError:
        return False
    if not isinstance(raw_path, bytes) or raw_path != expected_raw_path:
        return False
    if (method, path) in _ALLOWED_PROXY_ROUTES or (
        method == "GET" and path in _ALLOWED_READ_ROUTES
    ):
        return _bounded_query(path, query)
    if method != "GET" or not path.startswith("admin/memory/"):
        return False
    memory_id = path.removeprefix("admin/memory/")
    try:
        return not query and _bounded_query(path, query) and str(UUID(memory_id)) == memory_id
    except ValueError:
        return False


def create_app(
    settings: EdgeSettings | None = None,
    *,
    oidc_http: httpx.AsyncClient | None = None,
    upstream_http: httpx.AsyncClient | None = None,
    token_validator_http: httpx.Client | None = None,
    now: Callable[[], float] = time.monotonic,
) -> FastAPI:
    """Create the browser edge with only explicit project-scoped read/write routes."""

    configured = settings if settings is not None else EdgeSettings()
    oidc_client = oidc_http or httpx.AsyncClient(
        timeout=httpx.Timeout(5.0), follow_redirects=False, trust_env=False
    )
    api_client = upstream_http or httpx.AsyncClient(
        timeout=httpx.Timeout(5.0), follow_redirects=False, trust_env=False
    )
    validator_client = token_validator_http or httpx.Client(
        timeout=httpx.Timeout(2.0), follow_redirects=False, trust_env=False
    )
    sessions = _SessionStore()
    metadata_cache = _OidcMetadataCache()

    def _access_verifier(metadata: _OidcMetadata) -> OidcJwksVerifier:
        if configured.oidc_issuer is None or configured.oidc_api_audience is None:
            raise _generic(401)
        return OidcJwksVerifier(
            metadata.jwks_uri,
            configured.oidc_issuer,
            audience=configured.oidc_api_audience,
            http=validator_client,
            principals=_NoPrincipalLookup(),
        )

    @asynccontextmanager
    async def _lifespan(_: FastAPI) -> AsyncIterator[None]:
        try:
            if configured.enabled:
                # Deployment errors are discovered before this worker admits a
                # callback: issuer discovery and same-origin endpoint checks
                # are a startup boundary, not a first-user surprise.
                metadata = await _metadata()
                # Fetch the same discovered JWKS the API is configured to
                # trust before serving a callback.  This makes a mismatched
                # issuer/JWKS deployment fail closed at worker startup.
                _access_verifier(metadata).preflight()
            yield
        finally:
            if oidc_http is None:
                await oidc_client.aclose()
            if upstream_http is None:
                await api_client.aclose()
            if token_validator_http is None:
                validator_client.close()

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=_lifespan)
    parsed_origin_host = (
        urlsplit(configured.allowed_origin).hostname if configured.allowed_origin else None
    )
    origin_host = parsed_origin_host or "localhost"
    # Health probes are container-local; browser traffic remains pinned to its
    # one configured origin host.
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=[origin_host, "localhost", "127.0.0.1"])

    @app.middleware("http")
    async def _no_store(request: Request, call_next: Callable[[Request], Any]) -> Response:
        response = cast(Response, await call_next(request))
        response.headers["Cache-Control"] = "private, no-store"
        return response

    @app.exception_handler(Exception)
    async def _unexpected_error(_: Request, __: Exception) -> JSONResponse:
        """Do not return implementation details or credential-bearing messages."""

        return JSONResponse(status_code=500, content={"detail": "request rejected"})

    async def _oidc_json(url: str, *, data: dict[str, str] | None = None) -> dict[str, Any]:
        try:
            method = "POST" if data is not None else "GET"
            async with oidc_client.stream(
                method, url, data=data, headers={"Accept": "application/json"}
            ) as response:
                response.raise_for_status()
                if response.history or response.is_redirect:
                    raise ValueError
                parsed = json.loads(await _bounded_async_body(response, _MAX_OIDC_RESPONSE_BYTES))
        except (httpx.HTTPError, ValueError) as exc:
            raise _generic(401) from exc
        if not isinstance(parsed, dict):
            raise _generic(401)
        return cast("dict[str, Any]", parsed)

    async def _fetch_metadata() -> _OidcMetadata:
        if not configured.enabled or configured.oidc_issuer is None:
            raise _generic(404)
        document = await _oidc_json(
            urljoin(configured.oidc_issuer + "/", ".well-known/openid-configuration")
        )
        if document.get("issuer") != configured.oidc_issuer:
            raise _generic(401)
        try:
            metadata = _OidcMetadata(
                authorization_endpoint=_same_origin_url(
                    configured.oidc_issuer, document.get("authorization_endpoint")
                ),
                token_endpoint=_same_origin_url(
                    configured.oidc_issuer, document.get("token_endpoint")
                ),
                jwks_uri=_same_origin_url(configured.oidc_issuer, document.get("jwks_uri")),
            )
            if metadata.jwks_uri != configured.oidc_jwks_url:
                raise AuthenticationFailed("OIDC metadata JWKS does not match API configuration")
            return metadata
        except AuthenticationFailed as exc:
            raise _generic(401) from exc

    async def _metadata() -> _OidcMetadata:
        return await metadata_cache.get(_fetch_metadata, now)

    def _cookie(response: Response, session_id: str, max_age: int) -> None:
        response.set_cookie(
            key=_COOKIE_NAME,
            value=session_id,
            max_age=max_age,
            httponly=True,
            secure=configured.secure_cookie,
            samesite="lax",
            path="/",
        )

    def _clear_login_cookie(response: Response) -> None:
        response.delete_cookie(_LOGIN_COOKIE_NAME, path="/")

    def _session(request: Request) -> tuple[str, _Session]:
        session_id = request.cookies.get(_COOKIE_NAME)
        if not session_id or len(session_id) > 256:
            raise _generic(401)
        session = sessions.get_session(session_id, now(), configured)
        if session is None:
            raise _generic(401)
        return session_id, session

    def _csrf(request: Request, session: _Session) -> None:
        if request.headers.get("origin") != configured.allowed_origin:
            raise _generic(403)
        presented = request.headers.get("x-csrf-token")
        if not presented or not hmac.compare_digest(presented, session.csrf_token):
            raise _generic(403)

    def _client_identity(request: Request) -> str:
        # nginx overwrites this dedicated header from `$remote_addr`.  Do not
        # honour it from another direct peer: that would let an attacker choose
        # a pending-login/rate bucket.  A direct caller without nginx is still
        # safe and is independently bucketed by its socket address.
        client = request.client
        host = client.host if client is not None else "unknown"
        if host == configured.trusted_ingress_host:
            supplied = request.headers.get(_CLIENT_IDENTITY_HEADER)
            if supplied is None or len(supplied) > 45:
                raise _generic(400)
            try:
                # Normalise equivalent IPv6 spellings, avoid a caller-selected
                # textual representation becoming another bucket.
                return str(ip_address(supplied))
            except ValueError as exc:
                raise _generic(400) from exc
        return host[:128]

    def _tokens(payload: dict[str, Any], *, require_id_token: bool = True) -> _TokenResponse:
        access = payload.get("access_token")
        refresh = payload.get("refresh_token")
        id_token = payload.get("id_token")
        expires_in = payload.get("expires_in")
        if (
            not isinstance(access, str)
            or not isinstance(refresh, str)
            or (require_id_token and not isinstance(id_token, str))
            or type(expires_in) is not int
            or not 1 <= expires_in <= 86_400
            or any(
                not value or len(value.encode("utf-8")) > _MAX_TOKEN_BYTES
                for value in (
                    access,
                    refresh,
                    id_token if require_id_token else "refresh-id-token-not-required",
                )
            )
        ):
            raise _generic(401)
        return _TokenResponse(
            access, refresh, id_token if isinstance(id_token, str) else "", expires_in
        )

    async def _refresh(session: _Session, metadata: _OidcMetadata) -> None:
        if configured.oidc_client_id is None:
            raise _generic(401)
        tokens = _tokens(
            await _oidc_json(
                metadata.token_endpoint,
                data={
                    "grant_type": "refresh_token",
                    "client_id": configured.oidc_client_id,
                    "refresh_token": session.refresh_token,
                },
            ),
            require_id_token=False,
        )
        if hmac.compare_digest(tokens.refresh_token, session.refresh_token):
            raise _generic(401)
        session.access_token = tokens.access_token
        session.refresh_token = tokens.refresh_token
        session.access_expires_at = now() + tokens.expires_in

    async def _admit_principal(access_token: str) -> str:
        """Ask the private API to authenticate the access token before session commit.

        The BFF validates the browser's ID-token/nonce; the API remains the
        sole authority for access-token audience, principal registration,
        revocation, and project grants.  A bounded `whoami` response gives the
        BFF a stable immutable principal key without trusting JWT claims here.
        """
        try:
            request = api_client.build_request(
                "GET",
                configured.api_base_url + "/admin/whoami",
                headers={"Authorization": "Bearer " + access_token},
            )
            response = await api_client.send(request, stream=True)
            try:
                if response.status_code != 200 or response.history or response.is_redirect:
                    raise ValueError
                payload = json.loads(await _bounded_async_body(response, 4_096))
            finally:
                await response.aclose()
            if not isinstance(payload, dict) or set(payload) != {
                "project_id",
                "agent_type_id",
                "principal_id",
            }:
                raise ValueError
            principal_id = payload["principal_id"]
            if not isinstance(principal_id, str) or str(UUID(principal_id)) != principal_id:
                raise ValueError
            return principal_id
        except (httpx.HTTPError, ValueError, json.JSONDecodeError) as exc:
            raise _generic(401) from exc

    @app.get("/healthz", response_model=dict[str, str])
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/auth/login")
    async def login(request: Request) -> Response:
        metadata = await _metadata()
        if configured.oidc_client_id is None or configured.redirect_uri is None:
            raise _generic(404)
        created = sessions.create_pending(now(), _client_identity(request))
        if created is None:
            raise _generic(503)
        state, pending = created
        query = urlencode(
            {
                "response_type": "code",
                "client_id": configured.oidc_client_id,
                "redirect_uri": configured.redirect_uri,
                "scope": "openid",
                "state": state,
                "nonce": pending.nonce,
                "code_challenge": _pkce_challenge(pending.verifier),
                "code_challenge_method": "S256",
            }
        )
        response = RedirectResponse(metadata.authorization_endpoint + "?" + query, status_code=303)
        response.set_cookie(
            _LOGIN_COOKIE_NAME,
            pending.transaction_id,
            max_age=_PENDING_TTL_SECONDS,
            httponly=True,
            secure=configured.secure_cookie,
            samesite="lax",
            path="/",
        )
        return response

    @app.get("/auth/callback")
    async def callback(request: Request, code: str, state: str) -> Response:
        rejected = Response(status_code=401)
        _clear_login_cookie(rejected)
        if len(code) > 2_048 or len(state) > 512:
            return rejected
        pending = sessions.consume_pending(state, request.cookies.get(_LOGIN_COOKIE_NAME), now())
        if pending is None or configured.oidc_client_id is None or configured.redirect_uri is None:
            return rejected
        metadata = await _metadata()
        tokens = _tokens(
            await _oidc_json(
                metadata.token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "client_id": configured.oidc_client_id,
                    "redirect_uri": configured.redirect_uri,
                    "code_verifier": pending.verifier,
                },
            )
        )
        if configured.oidc_issuer is None or configured.oidc_client_id is None:
            raise _generic(401)
        try:
            OidcJwksVerifier(
                metadata.jwks_uri,
                configured.oidc_issuer,
                audience=configured.oidc_client_id,
                http=validator_client,
                principals=_NoPrincipalLookup(),
            ).verify_id_token(tokens.id_token, nonce=pending.nonce)
            # The API independently authenticates this token before session
            # admission.  Verify its explicit API audience here as well so a
            # dashboard ID token, or an access token for a different resource,
            # cannot reach that private boundary.
            _access_verifier(metadata).verify_access_token(tokens.access_token)
        except (AuthenticationFailed, ValueError) as exc:
            raise _generic(401) from exc
        principal_id = await _admit_principal(tokens.access_token)
        old_session_id = request.cookies.get(_COOKIE_NAME)
        if old_session_id is not None and len(old_session_id) <= 256:
            # Read the exact browser-presented id before replacing it; an
            # expired/unknown value is never treated as authority over another
            # live session.
            if sessions.get_session(old_session_id, now(), configured) is None:
                old_session_id = None
        else:
            old_session_id = None
        session_id = sessions.create_session(
            tokens,
            principal_id,
            now(),
            configured,
            previous_session_id=old_session_id,
        )
        if session_id is None:
            raise _generic(503)
        response = RedirectResponse("/", status_code=303)
        _clear_login_cookie(response)
        _cookie(response, session_id, configured.session_absolute_seconds)
        return response

    @app.get("/auth/csrf", response_model=CsrfOut)
    async def csrf(request: Request) -> CsrfOut:
        _, session = _session(request)
        return CsrfOut(csrf_token=session.csrf_token)

    @app.get("/auth/session", response_model=SessionStatusOut)
    async def session_status(request: Request) -> SessionStatusOut:
        """A status probe, not an authentication challenge or identity endpoint."""

        session_id = request.cookies.get(_COOKIE_NAME)
        if not session_id or len(session_id) > 256:
            return SessionStatusOut(authenticated=False)
        session = sessions.get_session(session_id, now(), configured)
        if session is None:
            return SessionStatusOut(authenticated=False)
        return SessionStatusOut(authenticated=True, csrf_token=session.csrf_token)

    @app.post("/auth/logout", status_code=204)
    async def logout(request: Request) -> Response:
        session_id, session = _session(request)
        _csrf(request, session)
        sessions.delete_session(session_id)
        response = Response(status_code=204)
        response.delete_cookie(_COOKIE_NAME, path="/")
        return response

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    async def proxy(path: str, request: Request) -> Response:
        if not _allowed_proxy_route(
            request.method, path, request.scope.get("raw_path"), request.url.query
        ):
            raise _generic(404)
        session_id, session = _session(request)
        del session_id
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            _csrf(request, session)
        if session.access_expires_at <= now():
            await _refresh(session, await _metadata())
        try:
            content_length = int(request.headers.get("content-length", "0"))
        except ValueError as exc:
            raise _generic(413) from exc
        if content_length < 0 or content_length > _MAX_BODY_BYTES:
            raise _generic(413)
        body = await _bounded_request_body(request)
        headers = {"Authorization": "Bearer " + session.access_token}
        for name in ("accept", "content-type"):
            value = request.headers.get(name)
            if value is not None and len(value) <= 512:
                headers[name] = value
        target = configured.api_base_url + "/" + path
        if request.url.query:
            target += "?" + request.url.query
        try:
            upstream_request = api_client.build_request(
                request.method, target, content=body, headers=headers
            )
            upstream = await api_client.send(upstream_request, stream=True)
        except (httpx.HTTPError, ValueError) as exc:
            raise _generic(502) from exc
        if path == "export/project":
            return await _stream_export(upstream)
        try:
            upstream_body = await _bounded_async_body(upstream, _MAX_BODY_BYTES)
            upstream_status_code = upstream.status_code
            upstream_headers = dict(upstream.headers)
        finally:
            await upstream.aclose()
        response_headers: dict[str, str] = {}
        for name in ("content-type", "cache-control"):
            value = upstream_headers.get(name)
            if value is not None:
                response_headers[name] = value
        return Response(
            content=upstream_body, status_code=upstream_status_code, headers=response_headers
        )

    return app


def run() -> None:
    import uvicorn

    uvicorn.run(
        create_app(),
        host="0.0.0.0",  # noqa: S104 - the edge is isolated on Compose's ingress network.
        port=8120,
        proxy_headers=False,
        server_header=False,
        access_log=False,
    )


async def _bounded_async_body(response: httpx.Response, limit: int) -> bytes:
    body = bytearray()
    async for chunk in response.aiter_bytes():
        body.extend(chunk)
        if len(body) > limit:
            raise ValueError("response exceeds the configured bound")
    return bytes(body)


async def _stream_export(upstream: httpx.Response) -> StreamingResponse:
    """Relay an export without converting an unbounded upstream into RAM use.

    A declared over-limit response is rejected before any body is sent.  For a
    chunked response, the explicit limit is advertised to consumers and an
    over-limit upstream is cancelled and the downstream stream raises rather
    than returning a clean EOF. HTTP cannot revise a response status after its
    headers are committed; terminating the chunked response is therefore the
    only honest signal that a partial export did not complete.
    """

    declared_size: int | None = None
    raw_content_length = upstream.headers.get("content-length")
    if raw_content_length is not None:
        try:
            declared_size = int(raw_content_length)
        except ValueError as exc:
            await upstream.aclose()
            raise _generic(502) from exc
        if declared_size < 0 or declared_size > _MAX_EXPORT_BYTES:
            await upstream.aclose()
            raise _generic(413)

    response_headers: dict[str, str] = {
        "X-Tracebed-Export-Max-Bytes": str(_MAX_EXPORT_BYTES),
        # A normal chunked body is a complete export prospectively.  If it
        # crosses the absolute cap the generator raises and the client sees a
        # transport failure rather than a clean partial EOF.
        "X-Tracebed-Export-Completeness": "complete",
    }
    for name in ("content-type", "cache-control", "content-disposition"):
        value = upstream.headers.get(name)
        if value is not None:
            response_headers[name] = value
    if declared_size is not None:
        response_headers["content-length"] = str(declared_size)

    async def _body() -> AsyncIterator[bytes]:
        observed = 0
        try:
            async for chunk in upstream.aiter_bytes():
                observed += len(chunk)
                if observed > _MAX_EXPORT_BYTES:
                    # Closing upstream propagates cancellation to its producer;
                    # raising makes the client observe a broken stream, never
                    # a clean success EOF carrying a partial export.
                    await upstream.aclose()
                    raise RuntimeError("export exceeded total byte limit")
                yield chunk
        finally:
            await upstream.aclose()

    return StreamingResponse(_body(), status_code=upstream.status_code, headers=response_headers)


async def _bounded_request_body(request: Request) -> bytes:
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > _MAX_BODY_BYTES:
            raise _generic(413)
    return bytes(body)
