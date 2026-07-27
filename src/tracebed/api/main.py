"""App factory + `run()` entry point (PHASE0-CONTRACT.md §9.2/§9.4).

`create_app(settings, deps)` is pure wiring: it never opens a socket, a
connection pool, or a file — every I/O-touching object arrives already built
in `deps` (contract §9.2's whole point: `TestClient(create_app(settings,
FakeAppDeps))` runs with zero services). `run()` is the one function in this
chunk that is allowed to build real adapters and actually bind a port.
"""

from __future__ import annotations

import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from psycopg_pool import ConnectionPool

from tracebed.adapters.embedding.gemini import GeminiEmbeddingClient
from tracebed.adapters.embedding.pinning import ModelPin
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
from tracebed.api.deps import AppDeps
from tracebed.crypto.shred import EnvMasterKeyProvider, SubjectKeyManager
from tracebed.domain.canonical import sha256_hex
from tracebed.domain.clock import SystemClock
from tracebed.domain.config import ConfigResolver, TracebedSettings
from tracebed.domain.errors import (
    AuthenticationFailed,
    ConfigError,
    DuplicateRegistration,
    NotFound,
    ScopeResolutionFailed,
    TracebedError,
)
from tracebed.domain.ids import ProjectId
from tracebed.hotpath.assembly import CandidateAssembly
from tracebed.hotpath.holdout import read_salt
from tracebed.hotpath.pipeline import Pipeline
from tracebed.hotpath.retriever import Retriever
from tracebed.stores.pg.partitions import create_project_partitions
from tracebed.stores.pg.pool import create_pool
from tracebed.stores.pg.queue import WorkQueue
from tracebed.stores.pg.repo import Repo
from tracebed.stores.pg.reports import ReportsRepo
from tracebed.stores.pg.search import SearchStore
from tracebed.stores.pg.telemetry import Telemetry

__all__ = ["create_app", "run"]


def create_app(settings: TracebedSettings, deps: AppDeps) -> FastAPI:
    """Builds the FastAPI app around an already-constructed `AppDeps`.

    Stashes `deps` and the admin-key hash on `app.state` — the one shared
    surface `api.deps._app_deps`/`require_admin_key` read from (contract
    §9.2). Registers every router and the §9.4 error->HTTP mapping.
    """
    app = FastAPI(title="tracebed", version="0.1.0")
    app.state.deps = deps
    app.state.admin_key_hash = _resolve_admin_key_hash(settings)

    app.include_router(routes_v1.router)
    app.include_router(admin_routes.router)
    app.include_router(reports_routes.router)
    _register_exception_handlers(app)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        """Compose/liveness only (contract §9.3) — deliberately the one
        unauthenticated route (§14 api-auth DO-NOT list)."""
        return {"status": "ok"}

    return app


def _resolve_admin_key_hash(settings: TracebedSettings) -> str | None:
    """sha256 hex of the bootstrap admin key named by `settings.auth.admin_key_env`
    (C-02), or `None` if that env var is unset — an app with no admin key
    configured serves every admin route a uniform 401 rather than failing to
    start (a deployment that genuinely has no need for `/admin/*` yet, e.g.
    a read-replica dashboard process, must still boot)."""
    raw = os.environ.get(settings.auth.admin_key_env)
    return sha256_hex(raw.encode("utf-8")) if raw else None


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

    @app.exception_handler(ScopeResolutionFailed)
    async def _scope_resolution_failed(
        request: Request, exc: ScopeResolutionFailed
    ) -> JSONResponse:
        del request, exc
        return JSONResponse(status_code=403, content={"detail": "no project registration"})

    @app.exception_handler(NotFound)
    async def _not_found(request: Request, exc: NotFound) -> JSONResponse:
        # EXACTLY this body for both "does not exist" and "not your project"
        # (leak-suite probe 2) — never derived from `exc`'s message.
        del request, exc
        return JSONResponse(status_code=404, content={"detail": "not found"})

    @app.exception_handler(DuplicateRegistration)
    async def _duplicate_registration(
        request: Request, exc: DuplicateRegistration
    ) -> JSONResponse:
        del request, exc
        return JSONResponse(status_code=409, content={"detail": "principal already registered"})

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
        self, kind: PrincipalKind, external_ref: str
    ) -> PrincipalRecord | None:
        row = self._repo.get_principal_by_external_ref(external_ref, kind=kind)
        if row is None or row.kind != kind:
            return None
        return PrincipalRecord(
            principal_id=row.principal_id,
            kind=kind,
            external_ref=row.external_ref,
            key_hash=row.key_hash,
            revoked=row.revoked_at is not None,
        )


class _PoolPartitionsAdapter:
    """Binds `stores.pg.partitions.create_project_partitions` — which takes a
    raw `psycopg.Connection`, not a pooled/scoped one (contract §5.5: DDL
    runs under migration/admin privileges) — to the `PartitionsPort` Protocol
    `api/admin.py` depends on, by closing over a connection pool and opening
    one connection per call.
    """

    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool

    def create_project_partitions(self, project_id: ProjectId) -> None:
        with self._pool.connection() as conn:
            create_project_partitions(conn, project_id)


def _build_embedder(settings: TracebedSettings, clock: SystemClock) -> EmbeddingPort:
    """The configured `EmbeddingPort` driver, pinned (D-007, PLAN.md §6 `embedding.*`).

    A vector endpoint, never a generative client — invariant 1 permits exactly this
    one outbound model call on the read path, under its own `embed_timeout_ms`
    sub-budget. Note that this function lives in `api/`, not in `hotpath/`: the
    driver is *injected into* the hot path, so `scripts/purity_check.py`'s
    reachability walk over `hotpath/` still sees only `adapters.embedding`.
    """
    pin = ModelPin(
        model_id=settings.embedding.model_id,
        model_version=settings.embedding.model_version,
        dim=settings.embedding.dim,
    )
    if settings.embedding.driver == "onnx-local":
        if settings.embedding.onnx_model_path is None or settings.embedding.onnx_model_hash is None:
            raise ConfigError(
                "embedding.driver='onnx-local' requires embedding.onnx_model_path and "
                "embedding.onnx_model_hash (the pinned model and its integrity hash)"
            )
        raise ConfigError(
            "the onnx-local embedding driver needs an injected tokenizer, which no "
            "deployment in this repository names yet; configure embedding.driver='gemini'"
        )
    api_key = os.environ.get(settings.llm.api_key_env)
    if not api_key:
        # Loud at startup rather than a per-request `EmbeddingProviderError` that the
        # retriever would fail open on: an embedder that can never succeed makes every
        # single retrieval a silent `degraded_lexical`, which looks like a working
        # deployment on every dashboard.
        raise ConfigError(
            f"embedding driver 'gemini' needs an API key in ${settings.llm.api_key_env}"
        )
    return GeminiEmbeddingClient(
        base_url=settings.llm.base_url, api_key=api_key, pin=pin, clock=clock
    )


def _build_pipeline(
    settings: TracebedSettings,
    pool: ConnectionPool,
    repo: Repo,
    telemetry: Telemetry,
    clock: SystemClock,
) -> Pipeline:
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
    return Pipeline(
        clock=clock,
        config=ConfigResolver(settings, repo),
        telemetry=telemetry,
        retriever=Retriever(SearchStore(pool), _build_embedder(settings, clock), clock),
        assembly=CandidateAssembly(SearchStore(pool), clock),
        injections=telemetry,
        holdout_salt=read_salt(settings.killswitch.salt_env),
    )


def run() -> None:
    """Console entry point: builds real adapters from `TracebedSettings` read
    off the process environment, then serves on `:api.port` (contract §9.2).
    """
    import uvicorn

    settings = TracebedSettings()
    clock = SystemClock()
    pool = create_pool(settings.storage.pg_dsn)
    repo = Repo(pool, clock)
    queue = WorkQueue(pool, clock, settings.queue)

    principals = _RepoPrincipalLookup(repo)
    oidc = (
        OidcJwksVerifier(
            settings.auth.oidc_jwks_url,
            settings.auth.oidc_issuer,
            principals=principals,
            clock=clock,
        )
        if settings.auth.oidc_jwks_url and settings.auth.oidc_issuer
        else None
    )
    api_key_verifier = ApiKeyVerifier(principals) if settings.auth.api_key_mode else None
    verifier = ChainVerifier(
        oidc=oidc, api_key=api_key_verifier, api_key_mode=settings.auth.api_key_mode
    )

    keys = SubjectKeyManager(store=repo, master=EnvMasterKeyProvider(), clock=clock)
    telemetry = Telemetry(repo, clock)

    deps = AppDeps(
        verifier=verifier,
        resolver=repo,
        queue=queue,
        telemetry=telemetry,
        memory_reader=repo,
        exporter=repo,
        invalidations=repo,
        admin=repo,
        partitions=_PoolPartitionsAdapter(pool),
        keys=keys,
        clock=clock,
        pipeline=_build_pipeline(settings, pool, repo, telemetry, clock),
        control_plane=repo,
    )
    app = create_app(settings, deps)
    # `api.reports`'s D-093 report routes read through `ReportsRepo`, not `AppDeps` -- see that
    # module's own wiring note for why: `AppDeps` is a frozen, `slots=True` dataclass declared
    # in `api/deps.py`, which is outside this chunk's file list, so a new required field cannot
    # be added there. Attaching the real, pool-backed instance to `app.state` here (after
    # `create_app` returns, exactly like `admin_key_hash` already lives beside `app.state.deps`
    # rather than inside it) is the whole of this router's wiring; `create_app` itself opens no
    # connection and stays pure.
    app.state.reports_store = ReportsRepo(pool, clock)
    uvicorn.run(app, host="0.0.0.0", port=settings.api.port)  # noqa: S104 - bind-all is the deployment's choice, not a route's
