"""`AppDeps` + the auth/scope FastAPI dependency chain (PHASE0-CONTRACT.md §9.2).

`AppDeps` is a container of *Protocols*, not concrete classes — the whole
point (per the contract) is that `api/routes_v1.py` and `api/admin.py` can be
exercised with `TestClient` against hand-written fakes on a machine with no
Postgres, no Valkey, and no object store, and `api/main.py`'s `run()` wires
the same routers against real `Repo`/`WorkQueue`/`Telemetry`/... instances.

The flow is fixed (contract §3.3 / invariant 4) and has no other legal shape:

    request -> get_principal (authenticates; -> 401)
            -> get_scope (Repo.resolve_project; -> 403)
            -> route handler, which passes scope.project_id to every
               repo/queue/telemetry call and never reads one from the body
"""

from __future__ import annotations

import hmac
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from typing import Annotated, Final, Literal, Protocol, runtime_checkable
from uuid import UUID

from fastapi import Depends, Request

from tracebed.adapters.identity import Principal
from tracebed.adapters.ports import (
    PrincipalPort,
    ProjectResolverPort,
    QueueProducerPort,
    TelemetryPort,
)
from tracebed.domain.canonical import sha256_hex
from tracebed.domain.clock import Clock
from tracebed.domain.errors import AuthenticationFailed
from tracebed.domain.events import RetrieveResult, RunContext
from tracebed.domain.ids import AgentTypeId, MemoryId, PrincipalId, ProjectId
from tracebed.domain.scope import ProjectScope
from tracebed.domain.state_machine import Status
from tracebed.stores.pg.rows import (
    InvalidationEventRow,
    KillswitchStateRow,
    MemoryItemRow,
    ReviewQueueRow,
    SpendRow,
)

__all__ = [
    "AdminPort",
    "AppDeps",
    "AppDepsDep",
    "ControlPlaneReadPort",
    "ExportPort",
    "InvalidationWriterPort",
    "MemoryReaderPort",
    "PartitionsPort",
    "PipelinePort",
    "ScopeDep",
    "SubjectKeyProvisionerPort",
    "get_app_deps",
    "get_principal",
    "get_scope",
    "require_admin_key",
]


# --------------------------------------------------------------------------- #
# Small Protocols declared here (contract §9.2): they exist purely so the API
# is testable offline. Each mirrors a real adapter's signature exactly —
# `Repo`/`stores.pg.partitions`/`SubjectKeyManager` satisfy them structurally
# — so `api/main.py` wires the real thing with no adapter classes needed
# beyond the ones this file's own docstring notes as contract_gaps.
# --------------------------------------------------------------------------- #


@runtime_checkable
class MemoryReaderPort(Protocol):
    """`Repo.get_memory_by_id` (contract §5.1) — `GET /admin/memory/{id}`."""

    def get_memory_by_id(self, project_id: ProjectId, memory_id: MemoryId) -> MemoryItemRow: ...


@runtime_checkable
class ExportPort(Protocol):
    """`Repo.iter_export_rows` (contract §5.1) — `GET /export/project`."""

    def iter_export_rows(self, project_id: ProjectId) -> Iterator[dict[str, object]]: ...


@runtime_checkable
class ControlPlaneReadPort(Protocol):
    """The read surface PLAN.md §3's control plane needs and Phase 0 never got
    (D-093). `Repo` satisfies it structurally, exactly like `MemoryReaderPort`.

    Every method here already existed as a WRITE on `Repo` with no reader
    anywhere (`insert_review_item`, `spend_add`, `insert_invalidation_event`)
    or as a reader shaped for a different consumer (`get_killswitch_overlay`
    returns a bare `mem_type -> disabled` map for the config resolver, with no
    evidence and no timestamp). A dashboard cannot govern what it cannot read,
    so the four tables the control plane owns get one read each — and nothing
    else. There is deliberately no write method on this port: every status
    change is a state-machine transition (PLAN.md §10) and no admin bypass
    exists in code.

    Optional on `AppDeps` because `create_app` must keep working against the
    Phase 0 fakes that predate it; the routes below fail closed when it is
    absent rather than inventing an empty result, since "this deployment did
    not wire a control-plane reader" and "this project has no review items"
    must never render the same way.
    """

    def list_memories(
        self,
        project_id: ProjectId,
        *,
        statuses: Sequence[Status] | None = None,
        limit: int = 100,
    ) -> list[MemoryItemRow]: ...

    def list_review_items(
        self, project_id: ProjectId, *, include_resolved: bool = False, limit: int = 100
    ) -> list[ReviewQueueRow]: ...

    def list_killswitch_state(self, project_id: ProjectId) -> list[KillswitchStateRow]: ...

    def list_invalidation_events(
        self, project_id: ProjectId, *, limit: int = 100
    ) -> list[InvalidationEventRow]: ...

    def spend_since(self, project_id: ProjectId, since: date) -> list[SpendRow]: ...

    def get_project_config(self, project_id: ProjectId) -> Mapping[str, object]: ...

    def get_agent_type_config(
        self, project_id: ProjectId, agent_type_id: AgentTypeId
    ) -> Mapping[str, object]: ...


@runtime_checkable
class AdminPort(Protocol):
    """The registry-write surface `POST /admin/projects` and
    `POST /admin/agents/register` compose (contract §5.1: `Repo` satisfies
    this structurally).

    `create_agent_registration` rather than the three separate
    `create_agent_type`/`create_principal`/`register_agent` builders: those
    three are still on `Repo`, but composing them from a route gives three
    independent transactions, and a failure on the last one leaves a live
    `principal.key_hash` whose plaintext was never returned to anyone (C-30).
    A registry write that is only atomic inside `Repo` must be *reachable*
    only through the atomic entry point, so the Protocol declares that one.
    """

    def create_project(
        self, name: str, retention_policy: Mapping[str, object] | None = None
    ) -> ProjectId: ...

    def create_agent_registration(
        self,
        project_id: ProjectId,
        agent_type_name: str,
        principal_kind: Literal["oidc_sub", "api_key"],
        external_ref: str,
        key_hash: str | None,
    ) -> tuple[PrincipalId, AgentTypeId]: ...


@runtime_checkable
class InvalidationWriterPort(Protocol):
    """`Repo.insert_invalidation_event` (C-31) — `POST /v1/invalidation`.

    Small and synchronous on purpose: §14's queue DO-NOT list forbids a fourth
    topic, so the alternative to this port is the route returning "accepted"
    for an event it drops on the floor.
    """

    def insert_invalidation_event(
        self, project_id: ProjectId, event_type: str, selector: Mapping[str, object] | None = None
    ) -> UUID: ...


@runtime_checkable
class PipelinePort(Protocol):
    """`hotpath.pipeline.Pipeline.retrieve` (PLAN.md §3 hot read plane).

    Optional on `AppDeps` (`pipeline: PipelinePort | None = None`) because a
    real `Pipeline` needs a Postgres pool, a `SearchStore`, an `EmbeddingPort`
    and a killswitch salt — none of which a `TestClient` run against fakes has,
    and none of which the Phase 0 routes needed. `api/main.py::run()` builds one
    when the deployment can support it; `create_app` neither builds nor requires
    one, so the "no services at all" test path is unchanged.

    A route MUST NOT pass the request body's `agent_type` through: `Pipeline`
    reads `scope.agent_type_id`, which `Repo.resolve_project()` derived from the
    caller's `agent_registration` row (invariant 4), and it deliberately has no
    parameter that would let a caller assert one.
    """

    def retrieve(
        self, scope: ProjectScope, run_ctx: RunContext, *, session_id: str | None = None
    ) -> RetrieveResult: ...


@runtime_checkable
class PartitionsPort(Protocol):
    """`create_project_partitions` bound to a connection factory (contract
    §9.2) — `stores.pg.partitions.create_project_partitions` takes a raw
    `psycopg.Connection`, so `api/main.py`'s real implementation closes over
    the pool and opens one; the fake in tests just records the call.
    """

    def create_project_partitions(self, project_id: ProjectId) -> None: ...


@runtime_checkable
class SubjectKeyProvisionerPort(Protocol):
    """`SubjectKeyManager.ensure_project_kek` (contract §6.2) — provisions the
    reserved `"__project__"` KEK row at project creation (C-14)."""

    def ensure_project_kek(self, project_id: ProjectId) -> None: ...


# Fixed decoy digest, hashed once at import and derived from no real secret —
# the "no admin key configured" branch of `require_admin_key` compares against
# this so that branch does the same work as a wrong-key rejection.
_DUMMY_ADMIN_KEY_HASH: Final = sha256_hex(b"tracebed-admin-key-constant-time-decoy")


@dataclass(slots=True)
class AppDeps:
    """Everything `create_app` needs, typed as Protocols (contract §9.2)."""

    verifier: PrincipalPort
    resolver: ProjectResolverPort
    queue: QueueProducerPort
    telemetry: TelemetryPort
    memory_reader: MemoryReaderPort
    exporter: ExportPort
    invalidations: InvalidationWriterPort
    admin: AdminPort
    partitions: PartitionsPort
    keys: SubjectKeyProvisionerPort
    clock: Clock
    pipeline: PipelinePort | None = None
    """The hot read plane, when this deployment has one (see `PipelinePort`).
    Last and defaulted so every existing `AppDeps(...)` construction — including
    every offline fake in the test suite — keeps working unchanged."""
    control_plane: ControlPlaneReadPort | None = None
    """The dashboard's read surface (D-093), defaulted for the same reason
    `pipeline` is. `api/main.py::run()` wires the real `Repo`; the routes that
    need it raise `ConfigError` (-> opaque 500) when it is absent, never an
    empty list, because a misconfigured deployment must not be able to render
    as a clean project."""


def _app_deps(request: Request) -> AppDeps:
    """The one place a route's dependency chain reaches into `app.state` —
    everything else in this module takes `AppDeps` only through this call, so
    there is exactly one line to audit for "how does a dependency function
    reach the container `create_app` built."""
    deps = getattr(request.app.state, "deps", None)
    if deps is None:  # pragma: no cover - defensive; create_app always sets this
        raise RuntimeError("AppDeps is not configured on this FastAPI app")
    return deps  # type: ignore[no-any-return]


def get_app_deps(request: Request) -> AppDeps:
    """Route-usable form of `_app_deps` — `Depends(get_app_deps)` is how
    `api/routes_v1.py`/`api/admin.py` reach `queue`/`telemetry`/`clock`/... for
    handlers that need more of the container than just auth+scope."""
    return _app_deps(request)


def get_principal(request: Request) -> Principal:
    """Authenticates the caller's own credential (contract §9.2). Raises
    `AuthenticationFailed` (mapped to 401 by `api/main.py`'s handler) — never
    returns an unauthenticated `Principal`, and never reads a host-asserted
    actor header (invariant 4's threat model)."""
    deps = _app_deps(request)
    return deps.verifier.authenticate(
        authorization=request.headers.get("authorization"),
        api_key=request.headers.get("x-api-key"),
    )


def get_scope(
    request: Request, principal: Annotated[Principal, Depends(get_principal)]
) -> ProjectScope:
    """Server-side scope derivation (invariant 4): the *only* legal way a
    route obtains a `ProjectScope`. Raises `ScopeResolutionFailed` (mapped to
    403) for an authenticated principal with no `agent_registration` row."""
    deps = _app_deps(request)
    return deps.resolver.resolve_project(principal.principal_id)


def require_admin_key(request: Request) -> None:
    """C-20 bootstrap auth for registry-creating admin routes: `X-Admin-Key`
    compared (constant-time, over its sha256) against the static `TB_ADMIN_KEY`
    env value `api/main.py` hashed once at `create_app` time and stashed on
    `app.state.admin_key_hash`. These routes cannot use principal auth — no
    registration exists yet for the caller creating one (chicken-and-egg).

    Hashes *something* and compares against *something* on every call —
    header present or not, admin key configured or not — so all three
    rejection paths cost the same one `hmac.compare_digest` over two
    equal-length hex digests. A short-circuit on the unconfigured case would
    make "this deployment has no admin key at all" measurably cheaper than
    "your key is wrong", which tells an attacker whether guessing is even
    worth attempting.
    """
    expected_hash: str | None = getattr(request.app.state, "admin_key_hash", None)
    presented = request.headers.get("x-admin-key") or ""
    presented_hash = sha256_hex(presented.encode("utf-8"))
    configured = expected_hash is not None
    if not hmac.compare_digest(
        presented_hash, expected_hash if expected_hash is not None else _DUMMY_ADMIN_KEY_HASH
    ):
        raise AuthenticationFailed("invalid admin key")
    if not configured:
        # Only reachable if the caller guessed the decoy's preimage, which is
        # not a value that exists anywhere; fail closed regardless.
        raise AuthenticationFailed("invalid admin key")


# Reusable `Annotated[..., Depends(...)]` aliases (PEP 593 style) so route
# handlers in `api/routes_v1.py`/`api/admin.py` never write `= Depends(...)` in
# an argument default — that form is flake8-bugbear B008 ("do not perform a
# function call in argument defaults"), which `pyproject.toml`'s [frozen]
# ruff config selects and this chunk may not edit.
ScopeDep = Annotated[ProjectScope, Depends(get_scope)]
AppDepsDep = Annotated[AppDeps, Depends(get_app_deps)]
