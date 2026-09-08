"""`AppDeps` + the auth/scope FastAPI dependency chain (PHASE0-CONTRACT.md §9.2).

`AppDeps` is a container of *Protocols*, not concrete classes — the whole
point is that `api/routes_v1.py` and `api/admin.py` can be exercised with
`TestClient` against hand-written fakes on a machine with no Postgres, no
Valkey, and no object store, while `api/main.py` wires production adapters.

The flow is fixed (contract §3.3 / invariant 4) and has no other legal shape:

    request -> get_principal (authenticates; -> 401)
            -> get_access (resolves active durable grants; -> 403)
            -> route role guard
            -> route handler, which passes only the resolved context onward
"""

from __future__ import annotations

import hmac
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import date, datetime
from typing import Annotated, Final, Protocol, runtime_checkable
from uuid import UUID

from fastapi import Depends, Request

from tracebed.adapters.identity import Principal
from tracebed.adapters.ports import (
    AccessResolverPort,
    AuthorizedQueueProducerPort,
    PrincipalPort,
    ProjectResolverPort,
    TelemetryPort,
)
from tracebed.domain.authority import AccessContext, ErasureRequestStatus
from tracebed.domain.canonical import sha256_hex
from tracebed.domain.clock import Clock
from tracebed.domain.deadline import RemainingBudget
from tracebed.domain.enums import ProjectRole
from tracebed.domain.errors import (
    AuthenticationFailed,
    AuthorizationDenied,
    RequestDeadlineExceeded,
)
from tracebed.domain.events import RetrieveResult, RunContext
from tracebed.domain.ids import AgentTypeId, MemoryId, PrincipalId, ProjectId, RunId
from tracebed.domain.scope import ProjectScope
from tracebed.domain.state_machine import Status
from tracebed.hotpath.budget import Deadline
from tracebed.hotpath.pipeline import RetrievalAuditPort
from tracebed.stores.pg.rows import (
    InvalidationEventRow,
    KillswitchStateRow,
    MemoryItemRow,
    ReviewQueueRow,
    SpendRow,
)

__all__ = [
    "AdminDep",
    "AdminReadDep",
    "AnyRoleDep",
    "AppDeps",
    "AppDepsDep",
    "ControlPlaneReadPort",
    "DataDep",
    "ErasureRequestDep",
    "ErasureRequestPort",
    "ExportDep",
    "ExportPort",
    "FeedbackDep",
    "InvalidationWriterPort",
    "MemoryReaderPort",
    "PipelinePort",
    "PrincipalDep",
    "ReadGatePort",
    "RetrievalOpenerPort",
    "get_access",
    "get_admin_access",
    "get_admin_read_access",
    "get_any_role_access",
    "get_app_deps",
    "get_data_access",
    "get_erasure_request_access",
    "get_export_access",
    "get_feedback_access",
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
    anywhere (`insert_review_item`, `spend_add`, the authority-gated invalidation writer)
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

    def list_memories_page(
        self,
        project_id: ProjectId,
        *,
        statuses: Sequence[Status] | None = None,
        limit: int = 100,
        before_created_at: datetime | None = None,
        before_id: MemoryId | None = None,
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
class InvalidationWriterPort(Protocol):
    """Authority-checked, transactional invalidation write."""

    def insert(
        self, access: AccessContext, event_type: str, selector: Mapping[str, object] | None = None
    ) -> UUID: ...


@runtime_checkable
class RetrievalOpenerPort(Protocol):
    """Opens a retrieval run after rechecking the DATA grant atomically."""

    def open(
        self,
        access: AccessContext,
        run_id: RunId,
        *,
        subject_tags: tuple[str, ...] = (),
    ) -> object: ...

    def hold(
        self,
        access: AccessContext,
        run_id: RunId,
        *,
        subject_tags: tuple[str, ...] = (),
        deadline: RemainingBudget | None = None,
    ) -> AbstractContextManager[RetrievalAuditScopePort]: ...


@runtime_checkable
class RetrievalAuditScopePort(Protocol):
    @property
    def audit(self) -> RetrievalAuditPort | None: ...


@runtime_checkable
class ReadGatePort(Protocol):
    """Shared E2 read/disclosure lifetime gate."""

    def hold(
        self,
        access: AccessContext,
        required_role: ProjectRole,
    ) -> AbstractContextManager[object]: ...


@runtime_checkable
class ErasureRequestPort(Protocol):
    """API-only request/fence publication authority boundary.

    The caller can supply only the strict public target facts.  The concrete
    store derives target digests and all durable actor/session attribution
    from ``AccessContext`` and its database session.
    """

    def request(
        self,
        access: AccessContext,
        *,
        scope: str,
        subject_tag: str | None,
    ) -> ErasureRequestStatus: ...

    def status(self, access: AccessContext, request_id: UUID) -> ErasureRequestStatus: ...

    def status_by_actor(self, principal: Principal, request_id: UUID) -> ErasureRequestStatus: ...


# Kept as a standalone compatibility utility for deployments that have their
# own non-API operator console. It is intentionally not used by any Tracebed
# API route; B2 moved all onboarding out of the listener.
_DUMMY_ADMIN_KEY_HASH: Final = sha256_hex(b"tracebed-admin-key-constant-time-decoy")


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
        self,
        scope: ProjectScope,
        run_ctx: RunContext,
        *,
        session_id: str | None = None,
        run_id: RunId | None = None,
        deadline: Deadline | None = None,
        audit: RetrievalAuditPort | None = None,
    ) -> RetrieveResult: ...


@dataclass(slots=True)
class AppDeps:
    """Everything `create_app` needs, typed as Protocols (contract §9.2)."""

    verifier: PrincipalPort
    resolver: ProjectResolverPort
    queue: AuthorizedQueueProducerPort
    telemetry: TelemetryPort
    memory_reader: MemoryReaderPort
    exporter: ExportPort
    invalidations: InvalidationWriterPort
    retrieval_opener: RetrievalOpenerPort
    access_resolver: AccessResolverPort
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
    erasure_requests: ErasureRequestPort | None = None
    """E2 request/fence publication store.  It is optional only so older
    offline fixtures remain constructible; its routes fail closed if absent."""
    read_gate: ReadGatePort | None = None
    """E2 gate retained through an authenticated read/disclosure lifetime."""


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
    """Deprecated compatibility projection; no API route uses this path."""
    deps = _app_deps(request)
    return deps.resolver.resolve_project(principal.principal_id)


def get_access(
    request: Request, principal: Annotated[Principal, Depends(get_principal)]
) -> AccessContext:
    """Resolve server-side grants; credential kind is never a role default."""

    resolver = _app_deps(request).access_resolver
    # Production ``AppDeps`` requires this port. Keep a defensive fail-closed
    # guard for a malformed hand-built ASGI state rather than turning it into a
    # 500 that distinguishes an authority wiring mistake on the wire.
    if resolver is None:
        raise AuthorizationDenied()
    access = resolver.resolve_access(principal.principal_id)
    if (
        type(access) is not AccessContext
        or type(access.principal_id) is not PrincipalId
        or access.principal_id != principal.principal_id
    ):
        # A malformed adapter must not make an unvalidated object look like
        # authority simply because it exposes similarly named attributes.
        raise AuthorizationDenied()
    return access


def authenticate_data_access(
    deps: AppDeps,
    *,
    authorization: str | None,
    api_key: str | None,
    deadline: RemainingBudget | None = None,
) -> AccessContext:
    """Retrieve-only synchronous auth path, run inside bounded admission."""
    if deadline is not None and deadline.remaining_ms() <= 0:
        raise RequestDeadlineExceeded()
    if deadline is None:
        principal = deps.verifier.authenticate(authorization=authorization, api_key=api_key)
    else:
        principal = deps.verifier.authenticate(
            authorization=authorization, api_key=api_key, deadline=deadline
        )
        if deadline.remaining_ms() <= 0:
            # Authentication completed, but no later authority stage may begin once this
            # request's absolute budget has elapsed.
            raise RequestDeadlineExceeded()
    resolver = deps.access_resolver
    if resolver is None:
        raise AuthorizationDenied()
    if deadline is None:
        access = resolver.resolve_access(principal.principal_id)
    else:
        access = resolver.resolve_access(principal.principal_id, deadline=deadline)
    if (
        type(access) is not AccessContext
        or type(access.principal_id) is not PrincipalId
        or access.principal_id != principal.principal_id
    ):
        raise AuthorizationDenied()
    access = _require_role(access, ProjectRole.DATA)
    if deadline is not None and deadline.remaining_ms() <= 0:
        raise RequestDeadlineExceeded()
    return access


def _require_role(access: AccessContext, role: ProjectRole) -> AccessContext:
    if access.grant_for(role) is None:
        raise AuthorizationDenied()
    return access


def _role_guard(role: ProjectRole) -> Callable[[AccessContext], AccessContext]:
    if type(role) is not ProjectRole:
        raise TypeError("role guard requires a ProjectRole")

    def _guard(access: Annotated[AccessContext, Depends(get_access)]) -> AccessContext:
        return _require_role(access, role)

    return _guard


get_data_access = _role_guard(ProjectRole.DATA)
get_erasure_request_access = _role_guard(ProjectRole.ERASURE_REQUEST)
get_feedback_access = _role_guard(ProjectRole.FEEDBACK)
get_admin_access = _role_guard(ProjectRole.ADMIN)
get_export_access = _role_guard(ProjectRole.EXPORT)


def get_admin_read_access(
    access: Annotated[AccessContext, Depends(get_admin_access)],
    deps: Annotated[AppDeps, Depends(get_app_deps)],
) -> Iterator[AccessContext]:
    """Reauthenticate ADMIN and hold the shared E2 guard through the response."""

    if deps.read_gate is None:
        yield access
        return
    with deps.read_gate.hold(access, ProjectRole.ADMIN):
        yield access


def get_any_role_access(access: Annotated[AccessContext, Depends(get_access)]) -> AccessContext:
    """Require resolved authority without choosing a default role."""

    # AccessContext itself rejects an empty grant tuple.  Preserve the check
    # here so a future internal mutation cannot turn AnyRole into allow-all.
    if not access.roles:
        raise AuthorizationDenied()
    return access


def require_admin_key(request: Request) -> None:
    """Legacy standalone key guard; no normal API route depends on it."""

    expected_hash: str | None = getattr(request.app.state, "admin_key_hash", None)
    presented_hash = sha256_hex((request.headers.get("x-admin-key") or "").encode("utf-8"))
    if (
        not hmac.compare_digest(
            presented_hash, expected_hash if expected_hash is not None else _DUMMY_ADMIN_KEY_HASH
        )
        or expected_hash is None
    ):
        raise AuthenticationFailed("invalid admin key")


# `ScopeDep` remains importable for explicitly legacy, offline compatibility
# fixtures only. New route code must use one of the authority aliases below.
ScopeDep = Annotated[ProjectScope, Depends(get_scope)]
AppDepsDep = Annotated[AppDeps, Depends(get_app_deps)]
DataDep = Annotated[AccessContext, Depends(get_data_access)]
ErasureRequestDep = Annotated[AccessContext, Depends(get_erasure_request_access)]
FeedbackDep = Annotated[AccessContext, Depends(get_feedback_access)]
AdminDep = Annotated[AccessContext, Depends(get_admin_access)]
AdminReadDep = Annotated[AccessContext, Depends(get_admin_read_access)]
ExportDep = Annotated[AccessContext, Depends(get_export_access)]
AnyRoleDep = Annotated[AccessContext, Depends(get_any_role_access)]
PrincipalDep = Annotated[Principal, Depends(get_principal)]
