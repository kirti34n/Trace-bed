"""App factory + `run()` entry point (PHASE0-CONTRACT.md §9.2/§9.4).

`create_app(settings, deps)` is pure wiring: it never opens a socket, a
connection pool, or a file — every I/O-touching object arrives already built
in `deps` (contract §9.2's whole point: `TestClient(create_app(settings,
FakeAppDeps))` runs with zero services). `create_app_from_env()` is likewise
zero-I/O; its ASGI lifespan builds real adapters only at process startup.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from hmac import compare_digest
from typing import Any, cast

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from psycopg_pool import ConnectionPool
from starlette.types import Lifespan

from tracebed.adapters.embedding.factory import build_embedding_driver
from tracebed.adapters.identity import (
    ApiKeyVerifier,
    ChainVerifier,
    OidcJwksVerifier,
    PrincipalKind,
    PrincipalRecord,
)
from tracebed.adapters.ports import EmbeddingPort
from tracebed.api import admin as admin_routes
from tracebed.api import reports as reports_routes
from tracebed.api import routes_v1
from tracebed.api.admin import MemoryCursorSigner
from tracebed.api.deps import AppDeps
from tracebed.api.models import RetrieveIn
from tracebed.api.retrieval_admission import RetrievalAdmission
from tracebed.crypto.shred import EnvMasterKeyProvider
from tracebed.domain.clock import SystemClock
from tracebed.domain.config import ConfigResolver, TracebedSettings
from tracebed.domain.deadline import RemainingBudget
from tracebed.domain.errors import (
    ActivityBusy,
    AuthenticationFailed,
    AuthorizationDenied,
    ConfigError,
    DuplicateRegistration,
    ErasureFenced,
    ErasureRequestNotFound,
    ErasureTargetConflict,
    NotFound,
    ProjectInactive,
    ProjectProvisioningConflict,
    RequestDeadlineExceeded,
    RetrievalAuditUnavailable,
    RunAuthorityDenied,
    ScopeResolutionFailed,
    TracebedError,
)
from tracebed.hotpath.assembly import CandidateAssembly
from tracebed.hotpath.budget import Deadline
from tracebed.hotpath.holdout import read_salt
from tracebed.hotpath.pipeline import Pipeline
from tracebed.hotpath.retriever import Retriever
from tracebed.stores.pg.activity import ActivityGate, create_activity_pool
from tracebed.stores.pg.authority import (
    AuthorityStore,
    AuthorizedInvalidationWriter,
    AuthorizedReadGate,
    AuthorizedRetrievalOpener,
)
from tracebed.stores.pg.authority_dsn import RuntimeDsn, runtime_dsn_from_environment
from tracebed.stores.pg.erasure import ErasureRequestStore
from tracebed.stores.pg.pool import create_pool
from tracebed.stores.pg.queue import AuthorizedWorkQueue
from tracebed.stores.pg.repo import Repo
from tracebed.stores.pg.reports import ReportsRepo
from tracebed.stores.pg.runtime_identity import probe_runtime_readiness, runtime_pool_configure
from tracebed.stores.pg.search import SearchStore
from tracebed.stores.pg.telemetry import Telemetry

__all__ = ["create_app", "create_app_from_env", "run"]

_COMPOSE_READY_TOKEN_FILE = "/run/secrets/readyz_token"  # noqa: S105
_COMPOSE_READY_TOKEN_ENV = "TB_READYZ_TOKEN_FILE"  # noqa: S105


@dataclass(slots=True)
class _RuntimeResources:
    """I/O-backed runtime ownership, including the retriever's thread pool.

    The pool must outlive the retriever while requests drain, but shutdown
    closes the retriever first so its executor cannot submit or retain work
    against an already-closed database pool.
    """

    deps: AppDeps
    reports_store: ReportsRepo
    pool: ConnectionPool
    activity_pool: ConnectionPool
    retriever: Retriever
    memory_cursor_signer: MemoryCursorSigner | None = None

    def close(self) -> None:
        try:
            self.retriever.close()
        finally:
            try:
                self.pool.close()
            finally:
                self.activity_pool.close()


def _load_api_runtime_configuration() -> tuple[RuntimeDsn, TracebedSettings]:
    """Read the exclusive API DB credential before ordinary process settings.

    The credential resolver examines the *whole* inherited environment and
    rejects unsafe libpq/legacy inputs before settings or a pool are touched.
    ``TracebedSettings`` remains responsible for non-database settings such
    as Valkey, trace-store and pool bounds; its legacy library ``pg_dsn``
    field must remain unset for a production listener.
    """

    runtime_dsn = runtime_dsn_from_environment("tracebed_api", os.environ)
    settings = TracebedSettings()
    if settings.storage.pg_dsn is not None:
        raise ConfigError("runtime database credential configuration is invalid")
    return runtime_dsn, settings


def create_app(settings: TracebedSettings, deps: AppDeps) -> FastAPI:
    """Builds the FastAPI app around an already-constructed `AppDeps`.

    Stashes injected dependencies and registers routes and error mapping.
    """
    app = _create_base_app(settings, lifespan=_admission_lifespan)
    app.state.deps = deps
    app.state.retrieval_admission = RetrievalAdmission(
        capacity=settings.api.retrieval_admission_capacity
    )
    # Injected/offline applications have no mounted runtime secrets.  This
    # fixed test-only key never reaches the production factory, where the
    # mounted master key is mandatory before workers accept requests.
    app.state.memory_cursor_signer = MemoryCursorSigner(b"\x00" * 32)
    app.state.runtime_readiness = None

    return app


def _create_base_app(
    settings: TracebedSettings, *, lifespan: Lifespan[FastAPI] | None = None
) -> FastAPI:
    """Build routes and handlers without constructing any runtime adapter."""
    app = FastAPI(title="tracebed", version="0.1.0", lifespan=lifespan)
    app.state.settings = settings

    def openapi_with_retrieve_body() -> dict[str, Any]:
        """Restore Request-only retrieve's public Pydantic schema components."""
        if app.openapi_schema is not None:
            return app.openapi_schema
        schema = get_openapi(title=app.title, version=app.version, routes=app.routes)
        retrieve_schema = RetrieveIn.model_json_schema(ref_template="#/components/schemas/{model}")
        definitions = retrieve_schema.pop("$defs", {})
        components = schema.setdefault("components", {}).setdefault("schemas", {})
        components.update(definitions)
        components["RetrieveIn"] = retrieve_schema
        app.openapi_schema = schema
        return schema

    app.openapi = openapi_with_retrieve_body  # type: ignore[method-assign]

    @app.middleware("http")
    async def retrieval_deadline(request: Request, call_next: Any) -> Any:
        if request.method == "POST" and request.url.path == "/v1/retrieve":
            deps = getattr(request.app.state, "deps", None)
            clock = deps.clock if deps is not None else SystemClock()
            request.state.retrieval_deadline = Deadline(
                clock=clock,
                total_budget_ms=settings.api.retrieval_request_ceiling_ms,
                embed_timeout_ms=settings.api.retrieval_request_ceiling_ms,
            )
        response = await call_next(request)
        deadline = getattr(request.state, "retrieval_deadline", None)
        if deadline is not None and deadline.total_exceeded():
            return JSONResponse(status_code=503, content={"detail": "unavailable"})
        return response

    app.include_router(routes_v1.router)
    app.include_router(admin_routes.router)
    app.include_router(reports_routes.router)
    _register_exception_handlers(app)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        """Compose/liveness only (contract §9.3) — deliberately the one
        unauthenticated route (§14 api-auth DO-NOT list)."""
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz(request: Request) -> JSONResponse:
        """Dependency-backed readiness; liveness stays intentionally shallow."""

        ready_token_path = os.environ.get(_COMPOSE_READY_TOKEN_ENV)
        if ready_token_path is not None:
            if ready_token_path != _COMPOSE_READY_TOKEN_FILE:
                return JSONResponse(status_code=503, content={"status": "not ready"})
            try:
                expected_token = open(ready_token_path, encoding="utf-8").read().rstrip("\n")  # noqa: SIM115
            except OSError:
                return JSONResponse(status_code=503, content={"status": "not ready"})
            presented_token = request.headers.get("x-tracebed-readiness", "")
            if not expected_token or not compare_digest(presented_token, expected_token):
                return JSONResponse(status_code=401, content={"status": "not ready"})
        readiness = getattr(app.state, "runtime_readiness", None)
        if readiness is None:
            return JSONResponse(status_code=503, content={"status": "not ready"})
        try:
            readiness()
        except ConfigError:
            return JSONResponse(status_code=503, content={"status": "not ready"})
        return JSONResponse(status_code=200, content={"status": "ready"})

    return app


def create_app_from_env() -> FastAPI:
    """Build an environment-configured API app without opening external resources.

    Importing this module and calling the Uvicorn factory reads configuration
    and environment variable names only.  Pool creation, provider wiring, and
    all network/disk I/O are deferred to startup so a wheel can be imported and
    inspected without needing a running stack.  ``create_app(settings, deps)``
    remains the pure injected-dependency factory used by offline tests.
    """
    runtime_dsn, settings = _load_api_runtime_configuration()
    app = _create_base_app(settings, lifespan=_runtime_lifespan)
    app.state.runtime_settings = settings
    app.state.runtime_dsn = runtime_dsn
    app.state.deps = None
    app.state.reports_store = None
    app.state.runtime_pool = None
    app.state.runtime_resources = None
    app.state.runtime_readiness = None
    app.state.retrieval_admission = RetrievalAdmission(
        capacity=settings.api.retrieval_admission_capacity
    )
    return app


@asynccontextmanager
async def _admission_lifespan(app: FastAPI) -> AsyncIterator[None]:
    try:
        yield
    finally:
        # Do not release database/runtime resources until an abandoned worker
        # exits; it may still hold an authorization fence.
        app.state.retrieval_admission.close()


@asynccontextmanager
async def _runtime_lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Attach external dependencies only while the ASGI process is running."""
    settings = cast(TracebedSettings, app.state.runtime_settings)
    runtime_dsn = cast(RuntimeDsn, app.state.runtime_dsn)
    resources = _build_runtime_dependencies(settings, runtime_dsn)
    app.state.deps = resources.deps
    app.state.reports_store = resources.reports_store
    app.state.runtime_pool = resources.pool
    app.state.runtime_resources = resources
    app.state.runtime_readiness = lambda: probe_runtime_readiness(
        resources.pool, expected_role="tracebed_api"
    )
    app.state.memory_cursor_signer = resources.memory_cursor_signer
    try:
        yield
    finally:
        app.state.retrieval_admission.close()
        resources.close()
        app.state.deps = None
        app.state.reports_store = None
        app.state.runtime_pool = None
        app.state.runtime_resources = None
        app.state.runtime_readiness = None
        app.state.memory_cursor_signer = None


def _register_exception_handlers(app: FastAPI) -> None:
    """The §9.4 mapping, one handler per exception class. Starlette's
    `ExceptionMiddleware` walks `type(exc).__mro__` and dispatches to the
    most specific registered handler, so registering both a subclass (e.g.
    `AuthenticationFailed`) and the `TracebedError` base is not a race —
    an `AuthenticationFailed` instance always matches its own handler first,
    and anything else deliberately-raised-but-unmapped falls through to the
    base handler's opaque 500 (no class name, no message leaks to the wire).
    """

    @app.exception_handler(AuthenticationFailed)
    async def _authentication_failed(request: Request, exc: AuthenticationFailed) -> JSONResponse:
        del request, exc
        return JSONResponse(status_code=401, content={"detail": "authentication failed"})

    @app.exception_handler(RequestDeadlineExceeded)
    async def _request_deadline_exceeded(
        request: Request, exc: RequestDeadlineExceeded
    ) -> JSONResponse:
        del request, exc
        return JSONResponse(status_code=503, content={"detail": "unavailable"})

    @app.exception_handler(RetrievalAuditUnavailable)
    async def _retrieval_audit_unavailable(
        request: Request, exc: RetrievalAuditUnavailable
    ) -> JSONResponse:
        del request, exc
        return JSONResponse(status_code=503, content={"detail": "unavailable"})

    @app.exception_handler(RequestValidationError)
    async def _erasure_validation_failed(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Keep raw subject tags out of FastAPI's default 422 echo.

        Other established routes preserve FastAPI's structured validation
        response for compatibility.  The erasure request body is an identity
        boundary, so an invalid raw tag must never be reflected in a response
        body (or logged by a default handler).
        """

        if request.url.path.startswith("/v1/erasure-requests"):
            del exc
            # A malformed status identifier is not a request-body validation
            # error: it must be indistinguishable from missing, foreign, or
            # invisible request state. Keep POST's raw-tag boundary opaque
            # but preserve its established 422 contract.
            if request.method == "GET":
                return JSONResponse(status_code=404, content={"detail": "not found"})
            return JSONResponse(status_code=422, content={"detail": "invalid request"})
        # Re-raise through FastAPI's default serializer for legacy routes.
        from fastapi.exception_handlers import request_validation_exception_handler

        return await request_validation_exception_handler(request, exc)

    @app.exception_handler(ScopeResolutionFailed)
    async def _scope_resolution_failed(
        request: Request, exc: ScopeResolutionFailed
    ) -> JSONResponse:
        del request, exc
        return JSONResponse(status_code=403, content={"detail": "no project registration"})

    @app.exception_handler(AuthorizationDenied)
    @app.exception_handler(ProjectInactive)
    async def _authorization_denied(request: Request, exc: TracebedError) -> JSONResponse:
        del request, exc
        return JSONResponse(status_code=403, content={"detail": "access denied"})

    @app.exception_handler(NotFound)
    @app.exception_handler(ErasureRequestNotFound)
    async def _not_found(request: Request, exc: NotFound) -> JSONResponse:
        # EXACTLY this body for both "does not exist" and "not your project"
        # (leak-suite probe 2) — never derived from `exc`'s message.
        del request, exc
        return JSONResponse(status_code=404, content={"detail": "not found"})

    @app.exception_handler(RunAuthorityDenied)
    async def _run_authority_denied(request: Request, exc: RunAuthorityDenied) -> JSONResponse:
        del request, exc
        return JSONResponse(status_code=404, content={"detail": "not found"})

    @app.exception_handler(ActivityBusy)
    async def _activity_busy(request: Request, exc: ActivityBusy) -> JSONResponse:
        del request, exc
        return JSONResponse(status_code=503, content={"detail": "activity busy"})

    @app.exception_handler(DuplicateRegistration)
    async def _duplicate_registration(request: Request, exc: DuplicateRegistration) -> JSONResponse:
        del request, exc
        return JSONResponse(status_code=409, content={"detail": "principal already registered"})

    @app.exception_handler(ProjectProvisioningConflict)
    async def _project_provisioning_conflict(
        request: Request, exc: ProjectProvisioningConflict
    ) -> JSONResponse:
        del request, exc
        return JSONResponse(status_code=409, content={"detail": "project provisioning conflict"})

    @app.exception_handler(ErasureTargetConflict)
    @app.exception_handler(ErasureFenced)
    async def _erasure_conflict(request: Request, exc: TracebedError) -> JSONResponse:
        del request, exc
        return JSONResponse(status_code=409, content={"detail": "erasure request conflict"})

    @app.exception_handler(TracebedError)
    async def _tracebed_error_fallback(request: Request, exc: TracebedError) -> JSONResponse:
        # Anything Tracebed raises deliberately that has no specific mapping
        # above (ProvenanceIncomplete, ScanRejected, ...) — none of Phase 0's
        # stub routes raise these, but the fallback exists so a future route
        # never leaks a class name or message instead of failing safe.
        del request, exc
        return JSONResponse(status_code=500, content={"detail": "internal error"})


class _RepoPrincipalLookup:
    """Adapts `Repo.get_principal_by_external_ref` to the
    `adapters.identity.PrincipalLookup` Protocol's `(kind, external_ref)`
    shape: the Protocol takes `kind` positionally first, `Repo` takes it
    keyword-only second (C-29), and `Repo` returns a `PrincipalRow` where the
    Protocol promises a `PrincipalRecord` with a boolean `revoked`.

    `kind` is forwarded, not post-filtered. That matters: it makes the query
    hit `principal`'s real `UNIQUE(kind, external_ref)` constraint, so an
    IdP-controlled `sub` that collides with a server-minted api-key id can
    neither return the wrong row nor (as the pre-C-29 fail-closed path did)
    knock BOTH identities out of authentication. The `row.kind != kind`
    re-check below is belt-and-braces against a future edit to the query.
    """

    def __init__(self, repo: Repo) -> None:
        self._repo = repo

    def get_principal_by_external_ref(
        self,
        kind: PrincipalKind,
        external_ref: str,
        *,
        deadline: RemainingBudget | None = None,
    ) -> PrincipalRecord | None:
        if deadline is None:
            row = self._repo.get_principal_by_external_ref(external_ref, kind=kind)
        else:
            row = self._repo.get_principal_by_external_ref(
                external_ref, kind=kind, deadline=deadline
            )
        if row is None or row.kind != kind:
            return None
        return PrincipalRecord(
            principal_id=row.principal_id,
            kind=kind,
            external_ref=row.external_ref,
            key_hash=row.key_hash,
            revoked=row.revoked_at is not None,
        )


def _build_embedder(settings: TracebedSettings, clock: SystemClock) -> EmbeddingPort:
    """Delegates to `adapters.embedding.factory.build_embedding_driver`.

    The body moved there (D-128) so the `tracebed-worker` process, whose embedding sweep is
    the only writer of `embedding_model_id`/`embedding_model_version`, builds its driver from
    the SAME constructor this process builds its query embedder from. Two processes reading
    the same config through two constructors is how query vectors and stored vectors end up in
    different spaces while every row still carries a correct-looking pin. Kept as a
    module-private wrapper rather than deleted because `api.main`'s own tests reference it.
    """
    return build_embedding_driver(settings, clock)


def _build_pipeline(
    settings: TracebedSettings,
    pool: ConnectionPool,
    repo: Repo,
    telemetry: Telemetry,
    clock: SystemClock,
) -> tuple[Pipeline, Retriever]:
    """The hot read plane, assembled once per process (PLAN.md §3).

    Everything here is long-lived on purpose. `Retriever` holds a two-thread pool
    (one per search arm) for the life of the process rather than creating one per
    request on a 300ms p99 path, and the killswitch salt is read from the environment
    ONCE here — not per request — because `holdout.read_salt` is an `os.environ` lookup
    and the arm it seeds must be stable for the life of a session (D-027).

    `read_salt` raises when the salt is unset, and that exception is deliberately not
    caught: a deployment whose arm assignment is unsalted produces a *predictable*
    holdout, so the lift measurement the kill switch reads is compromised from the
    first request. Failing to start is recoverable in a way that silently mis-measuring
    for two weeks is not.
    """
    retriever = Retriever(SearchStore(pool), _build_embedder(settings, clock), clock)
    try:
        pipeline = Pipeline(
            clock=clock,
            config=ConfigResolver(settings, repo),
            telemetry=telemetry,
            retriever=retriever,
            assembly=CandidateAssembly(SearchStore(pool), clock),
            injections=telemetry,
            holdout_salt=read_salt(settings.killswitch.salt_env),
        )
    except Exception:
        retriever.close()
        raise
    return pipeline, retriever


def _build_runtime_dependencies(
    settings: TracebedSettings,
    runtime_dsn: RuntimeDsn,
) -> _RuntimeResources:
    """Construct the I/O-backed dependencies during ASGI startup only."""
    clock = SystemClock()
    # D-139: both process-level connection bounds are wired here rather than left at the library
    # defaults. This is the HOT-PATH pool; the per-statement bound is not set here because it
    # varies per project with `retrieval.total_budget_ms` -- `hotpath.retriever` derives it per
    # arm and `stores.pg.search` issues it transaction-scoped.
    pool = create_pool(
        runtime_dsn.value,
        connect_timeout_s=settings.storage.pg_connect_timeout_s,
        checkout_timeout_s=settings.storage.pg_checkout_timeout_s,
        configure=runtime_pool_configure("tracebed_api"),
        checkout_check=ConnectionPool.check_connection,
    )
    activity_pool: ConnectionPool | None = None
    retriever: Retriever | None = None
    try:
        # The activity gate is an advisory-lock coordination channel already
        # required by the authorized B1 producer. It is not a B3 API/worker
        # DSN split: it uses the same application DSN and owns no query surface.
        activity_pool = create_activity_pool(
            runtime_dsn.value,
            connect_timeout_s=settings.storage.pg_connect_timeout_s,
            checkout_timeout_s=settings.storage.pg_checkout_timeout_s,
            connection_check=runtime_pool_configure("tracebed_api"),
            checkout_check=ConnectionPool.check_connection,
        )
        repo = Repo(pool, clock)
        activity = ActivityGate(activity_pool)
        queue = AuthorizedWorkQueue(pool, clock, settings.queue, activity=activity)

        # The Compose wrapper reads the mounted master secret immediately
        # before exec.  Fail before opening a listener if it is absent/bad, and
        # derive the cursor MAC key from it so every Uvicorn worker shares one
        # opaque-cursor authority without rendering key material in settings.
        memory_cursor_signer = MemoryCursorSigner(EnvMasterKeyProvider().master_key())
        principals = _RepoPrincipalLookup(repo)
        oidc = (
            OidcJwksVerifier(
                settings.auth.oidc_jwks_url,
                settings.auth.oidc_issuer,
                audience=settings.auth.oidc_audience,
                principals=principals,
                clock=clock,
            )
            if (
                settings.auth.oidc_jwks_url
                and settings.auth.oidc_issuer
                and settings.auth.oidc_audience
            )
            else None
        )
        if oidc is not None:
            oidc.preflight()
        api_key_verifier = ApiKeyVerifier(principals) if settings.auth.api_key_mode else None
        verifier = ChainVerifier(
            oidc=oidc, api_key=api_key_verifier, api_key_mode=settings.auth.api_key_mode
        )

        telemetry = Telemetry(repo, clock)

        pipeline, built_retriever = _build_pipeline(settings, pool, repo, telemetry, clock)
        retriever = built_retriever
        deps = AppDeps(
            verifier=verifier,
            resolver=repo,
            queue=queue,
            telemetry=telemetry,
            memory_reader=repo,
            exporter=repo,
            invalidations=AuthorizedInvalidationWriter(pool, clock, activity=activity),
            retrieval_opener=AuthorizedRetrievalOpener(pool, activity=activity, audit_repo=repo),
            access_resolver=AuthorityStore(pool),
            clock=clock,
            pipeline=pipeline,
            control_plane=repo,
            erasure_requests=ErasureRequestStore(pool, activity=activity),
            read_gate=AuthorizedReadGate(pool, activity=activity),
        )
        return _RuntimeResources(
            deps=deps,
            reports_store=ReportsRepo(pool, clock),
            pool=pool,
            activity_pool=activity_pool,
            retriever=built_retriever,
            memory_cursor_signer=memory_cursor_signer,
        )
    except Exception:
        if retriever is not None:
            try:
                retriever.close()
            finally:
                try:
                    pool.close()
                finally:
                    if activity_pool is not None:
                        activity_pool.close()
        else:
            try:
                pool.close()
            finally:
                if activity_pool is not None:
                    activity_pool.close()
        raise


def run() -> None:
    """Installed console entry point for the lazy ASGI app factory."""
    import uvicorn

    _runtime_dsn, settings = _load_api_runtime_configuration()
    uvicorn.run(
        "tracebed.api.main:create_app_from_env",
        factory=True,
        host="0.0.0.0",  # noqa: S104 - bind-all is the deployment's choice, not a route's
        port=settings.api.port,
        workers=settings.api.workers,
    )
