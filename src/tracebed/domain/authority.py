"""Pure, fail-closed authority carriers for the Phase 3 grant boundary.

These are deliberately domain values, not database rows or HTTP models.  The
durable persistence design makes ``principal_grant`` reference an agent
registration with a composite foreign key, project state is evaluated as an
active/deletion-safe registry fact, and activity coordination uses a SHA-256
signed-64 key.  The corresponding PostgreSQL stores own those checks; this
module remains the pure, strict value boundary they reconstruct.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from re import compile as re_compile
from uuid import UUID

from tracebed.domain.enums import FeedbackSource, ProjectRole, RunOrigin
from tracebed.domain.ids import AgentTypeId, PrincipalId, ProjectId, RunId
from tracebed.domain.scope import ProjectScope

__all__ = ["AccessContext", "ErasureRequestStatus", "GrantBinding", "RunAuthority"]


_ERASURE_SCOPES = frozenset({"subject", "project"})
_ERASURE_PHASES = frozenset(
    {
        "requested",
        "fenced",
        "crypto_erased",
        "primary_purged",
        "external_purged",
        "verified",
        "scope_complete",
    }
)
_ERASURE_DISPOSITIONS = frozenset({"active", "retry_wait", "operator_blocked", "scope_complete"})
_ERASURE_CODE_RE = re_compile(r"[a-z][a-z0-9_]{0,63}\Z")


def _require_exact(value: object, expected: type[object], *, field: str) -> None:
    if type(value) is not expected:
        raise TypeError(f"{field}: expected {expected.__name__}, got {type(value).__name__}")


@dataclass(frozen=True, slots=True)
class GrantBinding:
    """One resolved active role grant, including its public feedback source.

    A feedback capability is source-specific.  Other capabilities must carry
    no feedback source at all, so a role cannot be widened later by attaching
    a source string to an otherwise unrelated grant.
    """

    grant_id: UUID
    role: ProjectRole
    feedback_source: FeedbackSource | None = None

    def __post_init__(self) -> None:
        _require_exact(self.grant_id, UUID, field="grant_id")
        _require_exact(self.role, ProjectRole, field="role")
        if self.role is ProjectRole.FEEDBACK:
            _require_exact(self.feedback_source, FeedbackSource, field="feedback_source")
        elif self.feedback_source is not None:
            raise ValueError("non-feedback grants must not carry a feedback_source")


@dataclass(frozen=True, slots=True)
class AccessContext:
    """The complete server-resolved authority for one authenticated principal."""

    project_id: ProjectId
    agent_type_id: AgentTypeId
    principal_id: PrincipalId
    grants: tuple[GrantBinding, ...]

    def __post_init__(self) -> None:
        _require_exact(self.project_id, ProjectId, field="project_id")
        _require_exact(self.agent_type_id, AgentTypeId, field="agent_type_id")
        _require_exact(self.principal_id, PrincipalId, field="principal_id")
        if type(self.grants) is not tuple:
            raise TypeError("grants: expected an exact tuple")
        if not self.grants:
            raise ValueError("grants must not be empty")
        seen_roles: set[ProjectRole] = set()
        seen_grant_ids: set[UUID] = set()
        for grant in self.grants:
            _require_exact(grant, GrantBinding, field="grants item")
            if grant.role in seen_roles:
                raise ValueError("grants must not contain duplicate active roles")
            if grant.grant_id in seen_grant_ids:
                raise ValueError("grants must not contain duplicate active grant ids")
            seen_roles.add(grant.role)
            seen_grant_ids.add(grant.grant_id)

    @property
    def roles(self) -> frozenset[ProjectRole]:
        """Resolved roles as an immutable set, never caller-supplied strings."""

        return frozenset(grant.role for grant in self.grants)

    def grant_for(self, role: ProjectRole) -> GrantBinding | None:
        _require_exact(role, ProjectRole, field="role")
        return next((grant for grant in self.grants if grant.role is role), None)

    @property
    def feedback_source(self) -> FeedbackSource | None:
        grant = self.grant_for(ProjectRole.FEEDBACK)
        return None if grant is None else grant.feedback_source

    @property
    def scope(self) -> ProjectScope:
        """Compatibility projection for code that needs only identity scope."""

        return ProjectScope(
            project_id=self.project_id,
            agent_type_id=self.agent_type_id,
            principal_id=self.principal_id,
        )


@dataclass(frozen=True, slots=True)
class ErasureRequestStatus:
    """The deliberately small public projection of an erasure request.

    Attribution, target digest, worker lease, closure membership and receipts
    are intentionally absent.  This is the only value an API request/status
    store may return to the listener.
    """

    request_id: UUID
    scope: str
    phase: str
    disposition: str
    last_code: str | None
    limitation_codes: tuple[str, ...]
    requested_at: datetime
    updated_at: datetime
    completed_at: datetime | None

    def __post_init__(self) -> None:
        _require_exact(self.request_id, UUID, field="request_id")
        if self.scope not in _ERASURE_SCOPES:
            raise ValueError("erasure scope is invalid")
        if self.phase not in _ERASURE_PHASES:
            raise ValueError("erasure phase is invalid")
        if self.disposition not in _ERASURE_DISPOSITIONS:
            raise ValueError("erasure disposition is invalid")
        if self.last_code is not None and (
            type(self.last_code) is not str or _ERASURE_CODE_RE.fullmatch(self.last_code) is None
        ):
            raise ValueError("erasure last code is invalid")
        if type(self.limitation_codes) is not tuple or len(self.limitation_codes) > 64 or any(
            type(code) is not str or _ERASURE_CODE_RE.fullmatch(code) is None
            for code in self.limitation_codes
        ):
            raise ValueError("erasure limitation codes are invalid")
        if tuple(sorted(self.limitation_codes)) != self.limitation_codes:
            raise ValueError("erasure limitation codes are not canonical")
        _require_exact(self.requested_at, datetime, field="requested_at")
        _require_exact(self.updated_at, datetime, field="updated_at")
        if self.completed_at is not None:
            _require_exact(self.completed_at, datetime, field="completed_at")


@dataclass(frozen=True, slots=True)
class RunAuthority:
    """Server-derived ownership binding for an individual run.

    This is a value carrier only at this checkpoint.  A later store resolves
    it under the project wall before any feedback/activity operation begins.
    """

    project_id: ProjectId
    run_id: RunId
    owner_principal_id: PrincipalId
    agent_type_id: AgentTypeId
    origin: RunOrigin

    def __post_init__(self) -> None:
        _require_exact(self.project_id, ProjectId, field="project_id")
        _require_exact(self.run_id, RunId, field="run_id")
        _require_exact(self.owner_principal_id, PrincipalId, field="owner_principal_id")
        _require_exact(self.agent_type_id, AgentTypeId, field="agent_type_id")
        _require_exact(self.origin, RunOrigin, field="origin")

    @property
    def principal_id(self) -> PrincipalId:
        """The run owner, named consistently with :class:`AccessContext`."""

        return self.owner_principal_id
