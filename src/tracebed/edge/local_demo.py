"""Explicitly local-only dashboard demo edge.

This is deliberately a separate entrypoint from :mod:`tracebed.edge.main`.
It is useful for a checkout demonstration, but it is not an alternate OIDC
mode and cannot be enabled through the production edge configuration.
"""

from __future__ import annotations

import hmac
import json
import re
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from importlib.resources import files
from pathlib import Path
from typing import Any, Final, cast
from urllib.parse import urlsplit
from uuid import UUID

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from tracebed.edge.main import (
    _COOKIE_NAME,
    _MAX_BODY_BYTES,
    _allowed_proxy_route,
    _bounded_async_body,
    _bounded_request_body,
    _generic,
    _Session,
    _SessionStore,
    _stream_export,
    _TokenResponse,
)

__all__ = ["LocalDemoSettings", "create_app", "run"]

_API_BASE_URL: Final = "http://api:8110"
_DEMO_SECRET_PATH: Final = Path("/run/secrets/demo_api_key_secret")
_TRUSTED_INGRESS_HOST: Final = "10.77.15.3"
_CLIENT_ADDRESS_HEADER: Final = "x-tracebed-client-address"
_LOOPBACK_PUBLICATION_GATEWAY: Final = "10.77.15.1"
_KEY_RE: Final = re.compile(r"\Atb_sk_[A-Za-z0-9_-]{8,128}\.[A-Za-z0-9_-]{16,512}\Z")


class LocalDemoSettings(BaseSettings):
    """The one local-only knob is the browser origin published by Compose."""

    model_config = SettingsConfigDict(env_prefix="TB_LOCAL_DEMO_", extra="forbid", frozen=True)

    origin: str
    session_idle_seconds: int = 1_800
    session_absolute_seconds: int = 28_800

    @field_validator("origin")
    @classmethod
    def _exact_loopback_origin(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "http"
            or parsed.hostname != "127.0.0.1"
            or parsed.port is None
            or not 1024 <= parsed.port <= 65535
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("local demo origin must be exact http://127.0.0.1:<port>")
        return value.rstrip("/")

    @model_validator(mode="after")
    def _bound_session_lifetimes(self) -> LocalDemoSettings:
        if not 60 <= self.session_idle_seconds <= 86_400:
            raise ValueError("local demo idle session lifetime is invalid")
        if not 300 <= self.session_absolute_seconds <= 86_400:
            raise ValueError("local demo absolute session lifetime is invalid")
        return self


class CsrfOut(BaseModel):
    csrf_token: str


class SessionStatusOut(BaseModel):
    authenticated: bool
    csrf_token: str | None = None


def _load_demo_api_key() -> str:
    """Read the dedicated Compose secret without ever logging its value/path."""

    try:
        value = _DEMO_SECRET_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError("local demo secret is unavailable") from exc
    # Docker secret files conventionally contain a final newline, while a
    # manually created local secret often does not. Both name the same one
    # line; reject any embedded/multiple newline representation instead.
    if value.endswith("\n"):
        value = value[:-1]
    if "\n" in value or "\r" in value:
        raise RuntimeError("local demo secret is invalid")
    if not _KEY_RE.fullmatch(value):
        raise RuntimeError("local demo secret is invalid")
    return value


def _load_manifest() -> dict[str, Any]:
    """Load only checked-in, non-secret evidence visible to local demo users."""

    try:
        raw = (
            files("tracebed").joinpath("_demo", "validation-runs.json").read_text(encoding="utf-8")
        )
    except FileNotFoundError:
        # Source checkouts use the versioned top-level asset; wheels contain
        # the same checked-in file under ``tracebed/_demo``.
        try:
            raw = (Path(__file__).resolve().parents[3] / "demo" / "validation-runs.json").read_text(
                encoding="utf-8"
            )
        except OSError as exc:
            raise RuntimeError("local demo manifest is unavailable") from exc
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("local demo manifest is invalid") from exc
    if (
        not isinstance(value, dict)
        or value.get("mode") != "local_demo"
        or not isinstance(value.get("runs"), list)
    ):
        raise RuntimeError("local demo manifest is invalid")
    return cast("dict[str, Any]", value)


def create_app(
    settings: LocalDemoSettings | None = None,
    *,
    upstream_http: httpx.AsyncClient | None = None,
    api_key_loader: Callable[[], str] = _load_demo_api_key,
    manifest_loader: Callable[[], dict[str, Any]] = _load_manifest,
    now: Callable[[], float] = time.monotonic,
) -> FastAPI:
    """Create the local edge; never import or alter the production OIDC app."""

    configured = settings if settings is not None else LocalDemoSettings()
    # Acquire once at process construction; it remains in private process
    # memory, never an environment value or browser response. A deliberate
    # secret rotation requires a restart, which also invalidates sessions.
    demo_api_key = api_key_loader()
    api_client = upstream_http or httpx.AsyncClient(
        timeout=httpx.Timeout(5.0), follow_redirects=False, trust_env=False
    )
    sessions = _SessionStore()
    manifest = manifest_loader()

    @asynccontextmanager
    async def _lifespan(_: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            if upstream_http is None:
                await api_client.aclose()

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=_lifespan)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"])

    @app.middleware("http")
    async def _local_only(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # Container health checks do not carry browser headers. Everything else
        # must have passed through the one fixed dashboard ingress and be from
        # the one bridge gateway created by Docker's loopback-only port
        # publication. The gateway is not a user-selectable forwarded address:
        # nginx overwrites it, and only its fixed direct peer is accepted.
        if request.url.path != "/healthz":
            client = request.client
            host = client.host if client is not None else ""
            forwarded = request.headers.get(_CLIENT_ADDRESS_HEADER)
            requested_host = request.headers.get("host", "")
            expected_port = urlsplit(configured.origin).port
            host_ok = (
                requested_host == "127.0.0.1" or requested_host == f"127.0.0.1:{expected_port}"
            )
            if (
                host != _TRUSTED_INGRESS_HOST
                or forwarded != _LOOPBACK_PUBLICATION_GATEWAY
                or not host_ok
            ):
                return JSONResponse(
                    status_code=403,
                    content={"detail": "request rejected"},
                    headers={"Cache-Control": "private, no-store"},
                )
        response = await call_next(request)
        response.headers["Cache-Control"] = "private, no-store"
        return response

    @app.exception_handler(Exception)
    async def _unexpected_error(_: Request, __: Exception) -> JSONResponse:
        return JSONResponse(status_code=500, content={"detail": "request rejected"})

    def _cookie(response: Response, session_id: str) -> None:
        response.set_cookie(
            key=_COOKIE_NAME,
            value=session_id,
            max_age=configured.session_absolute_seconds,
            httponly=True,
            secure=False,
            samesite="lax",
            path="/",
        )

    def _session(request: Request) -> tuple[str, _Session]:
        session_id = request.cookies.get(_COOKIE_NAME)
        if not session_id or len(session_id) > 256:
            raise _generic(401)
        session = sessions.get_session(session_id, now(), configured)  # type: ignore[arg-type]
        if session is None:
            raise _generic(401)
        return session_id, session

    def _csrf(request: Request, session: _Session) -> None:
        if request.headers.get("origin") != configured.origin:
            raise _generic(403)
        presented = request.headers.get("x-csrf-token")
        if not presented or not hmac.compare_digest(presented, session.csrf_token):
            raise _generic(403)

    async def _admit(api_key: str) -> str:
        try:
            upstream_request = api_client.build_request(
                "GET", _API_BASE_URL + "/admin/whoami", headers={"X-API-Key": api_key}
            )
            response = await api_client.send(upstream_request, stream=True)
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

    @app.get("/auth/demo-manifest")
    async def demo_manifest() -> dict[str, Any]:
        return manifest

    @app.get("/auth/login")
    async def login(request: Request) -> Response:
        principal_id = await _admit(demo_api_key)
        old_session_id = request.cookies.get(_COOKIE_NAME)
        if old_session_id is not None and len(old_session_id) <= 256:
            if sessions.get_session(old_session_id, now(), configured) is None:  # type: ignore[arg-type]
                old_session_id = None
        else:
            old_session_id = None
        # _SessionStore is reused only for its bounded opaque-cookie and CSRF
        # mechanics. Its token field remains server memory and carries the
        # dedicated API key; no browser response includes it.
        session_id = sessions.create_session(
            _TokenResponse(demo_api_key, "", "", configured.session_absolute_seconds),
            principal_id,
            now(),
            configured,  # type: ignore[arg-type]
            previous_session_id=old_session_id,
        )
        if session_id is None:
            raise _generic(503)
        response = RedirectResponse("/", status_code=303)
        _cookie(response, session_id)
        return response

    @app.get("/auth/csrf", response_model=CsrfOut)
    async def csrf(request: Request) -> CsrfOut:
        _, session = _session(request)
        return CsrfOut(csrf_token=session.csrf_token)

    @app.get("/auth/session", response_model=SessionStatusOut)
    async def session_status(request: Request) -> SessionStatusOut:
        session_id = request.cookies.get(_COOKIE_NAME)
        if not session_id or len(session_id) > 256:
            return SessionStatusOut(authenticated=False)
        session = sessions.get_session(session_id, now(), configured)  # type: ignore[arg-type]
        return SessionStatusOut(
            authenticated=session is not None, csrf_token=session.csrf_token if session else None
        )

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
        _, session = _session(request)
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            _csrf(request, session)
        try:
            content_length = int(request.headers.get("content-length", "0"))
        except ValueError as exc:
            raise _generic(413) from exc
        if content_length < 0 or content_length > _MAX_BODY_BYTES:
            raise _generic(413)
        body = await _bounded_request_body(request)
        headers = {"X-API-Key": session.access_token}
        for name in ("accept", "content-type"):
            value = request.headers.get(name)
            if value is not None and len(value) <= 512:
                headers[name] = value
        target = _API_BASE_URL + "/" + path
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
            status_code = upstream.status_code
            upstream_headers = dict(upstream.headers)
        finally:
            await upstream.aclose()
        response_headers = {
            name: value
            for name in ("content-type", "cache-control")
            if (value := upstream_headers.get(name)) is not None
        }
        return Response(content=upstream_body, status_code=status_code, headers=response_headers)

    return app


def run() -> None:
    import uvicorn

    uvicorn.run(
        create_app(),
        host="0.0.0.0",  # noqa: S104 - fixed to the isolated Compose ingress bridge.
        port=8120,
        proxy_headers=False,
        server_header=False,
        access_log=False,
    )
