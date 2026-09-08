"""Durable Phase 3 authority and immutable run-owner bindings.

The tables referenced here land with the authority migration, not this code
checkpoint.  There is deliberately no fallback to the legacy scope resolver:
an unavailable authority schema is a deployment error, never permission to
infer a grant from a credential or project scope.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from typing import Any, Final, cast
from uuid import UUID

import psycopg
from psycopg import Connection
from psycopg.rows import dict_row
from psycopg.types.json import Json
from psycopg_pool import ConnectionPool

from tracebed.domain.authority import AccessContext, GrantBinding, RunAuthority
from tracebed.domain.clock import Clock
from tracebed.domain.deadline import RemainingBudget
from tracebed.domain.enums import FeedbackSource, ProjectRole, RunOrigin
from tracebed.domain.errors import (
    AuthorizationDenied,
    ErasureFenced,
    RequestDeadlineExceeded,
    RetrievalAuditUnavailable,
    RunAuthorityDenied,
    TracebedError,
)
from tracebed.domain.ids import AgentTypeId, PrincipalId, ProjectId, RunId
from tracebed.hotpath.pipeline import RetrievalAuditPort
from tracebed.stores.pg.activity import ActivityGate
from tracebed.stores.pg.pool import (
    PoolDeadlineExceeded,
    _unscoped,
    is_expired_deadline_query_cancellation,
    refresh_deadline_statement_timeout,
    scoped,
)
from tracebed.stores.pg.repo import _AUTHORIZED_RETRIEVAL_AUDIT_CAPABILITY, Repo

__all__ = [
    "AuthorityStore",
    "AuthorizedInvalidationWriter",
    "AuthorizedReadGate",
    "AuthorizedRetrievalOpener",
    "RunAuthorityStore",
]


_RESOLVE_SNAPSHOT_SQL: Final = "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
_RESOLVE_ACCESS_SQL: Final = """
SELECT
    pr.principal_id,
    ar.project_id,
    ar.agent_type_id,
    g.grant_id,
    g.role,
    g.feedback_source
FROM principal AS pr
JOIN agent_registration AS ar ON ar.principal_id = pr.principal_id
JOIN project AS p ON p.project_id = ar.project_id
JOIN agent_type AS at
  ON at.agent_type_id = ar.agent_type_id AND at.project_id = ar.project_id
JOIN principal_grant AS g
  ON g.project_id = ar.project_id
 AND g.principal_id = pr.principal_id
WHERE pr.principal_id = %(principal_id)s
  AND pr.revoked_at IS NULL
  AND ar.revoked_at IS NULL
  AND p.status = 'active'
  AND p.deleted_at IS NULL
  AND g.revoked_at IS NULL
ORDER BY g.role, g.grant_id
""".strip()

_REQUIRE_ACTIVE_GRANT_SQL: Final = """
SELECT grant_id, role, feedback_source
FROM public.tracebed_require_active_grant(
    %(project_id)s::uuid,
    %(principal_id)s::uuid,
    %(agent_type_id)s::uuid,
    %(grant_id)s::uuid,
    %(role)s::text,
    %(feedback_source)s::text
)
""".strip()

_RUN_OWNER_INSERT_SQL: Final = """
INSERT INTO run_owner
    (project_id, run_id, principal_id, agent_type_id, origin, bound_at)
VALUES
    (%(project_id)s, %(run_id)s, %(principal_id)s, %(agent_type_id)s, %(origin)s, now())
ON CONFLICT (project_id, run_id) DO NOTHING
RETURNING project_id, run_id, principal_id, agent_type_id, origin
""".strip()

_RUN_OWNER_SELECT_SQL: Final = """
SELECT project_id, run_id, principal_id, agent_type_id, origin
FROM run_owner
WHERE project_id = %(project_id)s AND run_id = %(run_id)s
""".strip()

_OPEN_ERASURE_GUARDED_RUN_SQL: Final = """
SELECT writable, late_bind_eligible, origin
FROM public.tracebed_open_erasure_guarded_run(
    %(project_id)s::uuid,
    %(principal_id)s::uuid,
    %(agent_type_id)s::uuid,
    %(grant_id)s::uuid,
    %(run_id)s::uuid,
    %(origin)s::text
)
""".strip()

_BIND_RUN_SUBJECT_TAGS_SQL: Final = """
SELECT subject_digests, writable
FROM public.tracebed_bind_run_subject_tags(
    %(project_id)s::uuid,
    %(principal_id)s::uuid,
    %(agent_type_id)s::uuid,
    %(grant_id)s::uuid,
    %(run_id)s::uuid,
    %(role)s::text,
    %(subject_tags)s::text[]
)
""".strip()

_INSERT_AUTHORIZED_INVALIDATION_SQL: Final = """
SELECT public.tracebed_insert_authorized_invalidation(
    %(project_id)s::uuid,
    %(principal_id)s::uuid,
    %(agent_type_id)s::uuid,
    %(grant_id)s::uuid,
    %(event_type)s::text,
    %(selector)s::jsonb
) AS event_id
""".strip()


def _require_exact(value: object, expected: type[object]) -> None:
    if type(value) is not expected:
        raise TypeError(f"expected {expected.__name__}")


def _require_remaining(deadline: RemainingBudget) -> None:
    """Stop before beginning another authority statement after request expiry."""

    if deadline.remaining_ms() <= 0:
        raise RequestDeadlineExceeded()


def _as_uuid(value: object) -> UUID:
    if type(value) is UUID:
        return value
    raise ValueError("malformed authority row")


@dataclass(frozen=True, slots=True)
class _RunOpenOutcome:
    """Internal open result that separates business admission from containment."""

    authority: RunAuthority | None
    writable: bool
    late_bind_eligible: bool


@dataclass(frozen=True, slots=True)
class _SubjectBindOutcome:
    """Opaque bind result; ``False`` means containment was durably recorded."""

    subject_digests: tuple[bytes, ...]
    writable: bool


@dataclass(frozen=True, slots=True)
class AuthorizedRetrievalScope:
    authority: RunAuthority
    audit: RetrievalAuditPort | None


def _grant_from_row(row: Mapping[str, object]) -> GrantBinding:
    try:
        role_raw = row["role"]
        if type(role_raw) is not str:
            raise ValueError("malformed authority row")
        role = ProjectRole(role_raw)
        source_raw = row["feedback_source"]
        if source_raw is not None and type(source_raw) is not str:
            raise ValueError("malformed authority row")
        source = FeedbackSource(source_raw) if source_raw is not None else None
        return GrantBinding(grant_id=_as_uuid(row["grant_id"]), role=role, feedback_source=source)
    except (KeyError, TypeError, ValueError):
        raise AuthorizationDenied() from None


class AuthorityStore:
    """Read and recheck active grants without deriving them from credentials."""

    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool

    def resolve_access(
        self, principal_id: PrincipalId, *, deadline: RemainingBudget | None = None
    ) -> AccessContext:
        _require_exact(principal_id, PrincipalId)
        try:
            if deadline is not None and deadline.remaining_ms() <= 0:
                raise RequestDeadlineExceeded()
            if deadline is None:
                connection = _unscoped(self._pool)
            else:
                connection = _unscoped(self._pool, deadline=deadline)
            with connection as conn:
                if deadline is not None and deadline.remaining_ms() <= 0:
                    raise RequestDeadlineExceeded()
                # This transaction characteristic must remain the first SQL statement.  The
                # deadline timeout refresh follows it immediately before the grant SELECT.
                conn.execute(_RESOLVE_SNAPSHOT_SQL)
                if deadline is not None:
                    refresh_deadline_statement_timeout(conn, deadline)
                with conn.cursor(row_factory=dict_row) as cur:
                    cur.execute(_RESOLVE_ACCESS_SQL, {"principal_id": principal_id.value})
                    rows = cur.fetchall()
            access = self._access_from_rows(principal_id, rows)
            if deadline is not None and deadline.remaining_ms() <= 0:
                raise RequestDeadlineExceeded()
            return access
        except AuthorizationDenied:
            raise
        except RequestDeadlineExceeded:
            raise
        except PoolDeadlineExceeded as exc:
            raise RequestDeadlineExceeded() from exc
        except (KeyError, TypeError, ValueError):
            raise AuthorizationDenied() from None
        except Exception as exc:
            if is_expired_deadline_query_cancellation(exc, deadline):
                raise RequestDeadlineExceeded() from exc
            raise

    @staticmethod
    def _access_from_rows(
        principal_id: PrincipalId, rows: Sequence[Mapping[str, Any]]
    ) -> AccessContext:
        if not rows:
            raise AuthorizationDenied()
        try:
            first = rows[0]
            db_principal = PrincipalId(_as_uuid(first["principal_id"]))
            project_id = ProjectId(_as_uuid(first["project_id"]))
            agent_type_id = AgentTypeId(_as_uuid(first["agent_type_id"]))
            if db_principal != principal_id:
                raise AuthorizationDenied()
            grants: list[GrantBinding] = []
            for row in rows:
                if (
                    PrincipalId(_as_uuid(row["principal_id"])) != db_principal
                    or ProjectId(_as_uuid(row["project_id"])) != project_id
                    or AgentTypeId(_as_uuid(row["agent_type_id"])) != agent_type_id
                ):
                    raise AuthorizationDenied()
                grants.append(_grant_from_row(row))
            return AccessContext(
                project_id=project_id,
                agent_type_id=agent_type_id,
                principal_id=db_principal,
                grants=tuple(grants),
            )
        except AuthorizationDenied:
            raise
        except (KeyError, TypeError, ValueError):
            raise AuthorizationDenied() from None

    def require_active_grant_on(
        self,
        conn: Connection[Any],
        access: AccessContext,
        required_role: ProjectRole,
        *,
        deadline: RemainingBudget | None = None,
    ) -> GrantBinding:
        _require_exact(access, AccessContext)
        _require_exact(required_role, ProjectRole)
        expected = access.grant_for(required_role)
        if expected is None:
            raise AuthorizationDenied()
        try:
            if deadline is not None:
                _require_remaining(deadline)
                refresh_deadline_statement_timeout(conn, deadline)
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    _REQUIRE_ACTIVE_GRANT_SQL,
                    {
                        "project_id": access.project_id.value,
                        "principal_id": access.principal_id.value,
                        "agent_type_id": access.agent_type_id.value,
                        "grant_id": expected.grant_id,
                        "role": required_role.value,
                        "feedback_source": (
                            expected.feedback_source.value
                            if expected.feedback_source is not None
                            else None
                        ),
                    },
                )
                row = cur.fetchone()
        except psycopg.Error as error:
            if is_expired_deadline_query_cancellation(error, deadline):
                raise RequestDeadlineExceeded() from error
            # The trusted database routine deliberately reports no authority
            # detail to the API role. Keep that opaque at this boundary too.
            raise AuthorizationDenied() from None
        if row is None:
            raise AuthorizationDenied()
        grant = _grant_from_row(row)
        if grant != expected:
            raise AuthorizationDenied()
        return grant


class AuthorizedReadGate:
    """Hold E2's shared activity fence around an authenticated read lifetime.

    API dependencies resolve a grant before a handler starts, but that is only
    an admission hint: the exact grant must be rechecked once inside the
    guarded lifetime before the first database read or streamed byte.  The
    Both the gate and the exact authority transaction remain held through the
    caller's final disclosed byte.  A later scoped read cannot replace this
    lifetime proof: a revoke or exclusive erasure request must wait behind
    the same grant/project locks as the response construction itself.
    """

    def __init__(
        self,
        pool: ConnectionPool,
        *,
        activity: ActivityGate,
    ) -> None:
        self._pool = pool
        self._activity = activity
        self._authority = AuthorityStore(pool)

    @contextmanager
    def hold(
        self,
        access: AccessContext,
        required_role: ProjectRole,
    ) -> Iterator[Connection[Any]]:
        _require_exact(access, AccessContext)
        _require_exact(required_role, ProjectRole)
        with (
            self._activity.shared(access.project_id),
            scoped(self._pool, access.project_id) as conn,
        ):
            # Keep the exact grant/project authority tuple locks until the
            # caller has finished constructing its response (or streaming its
            # final byte).  A pre-yield recheck alone leaves a revoke race in
            # which the ActivityGate remains shared but authorization no
            # longer does.
            self._authority.require_active_grant_on(conn, access, required_role)
            yield conn


class RunAuthorityStore:
    """First-writer immutable run ownership, kept separate from queue delivery."""

    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool

    def bind_or_assert(
        self,
        access: AccessContext,
        run_id: RunId,
        *,
        origin: RunOrigin,
    ) -> RunAuthority:
        _require_exact(access, AccessContext)
        _require_exact(run_id, RunId)
        _require_exact(origin, RunOrigin)
        with scoped(self._pool, access.project_id) as conn:
            return self.bind_or_assert_on(conn, access, run_id, origin=origin)

    def bind_or_assert_on(
        self,
        conn: Connection[Any],
        access: AccessContext,
        run_id: RunId,
        *,
        origin: RunOrigin,
    ) -> RunAuthority:
        outcome = self.open_for_subject_bind_on(conn, access, run_id, origin=origin)
        if not outcome.writable:
            raise ErasureFenced()
        if outcome.authority is None:  # pragma: no cover - outcome shape is checked below
            raise TracebedError()
        return outcome.authority

    def open_for_subject_bind_on(
        self,
        conn: Connection[Any],
        access: AccessContext,
        run_id: RunId,
        *,
        origin: RunOrigin,
        deadline: RemainingBudget | None = None,
    ) -> _RunOpenOutcome:
        """Open a run or expose its narrow late-bind containment outcome.

        A false ``writable`` value is not always an error inside this
        transaction.  For an existing same-owner live run it can mean the
        low-level binder must durably attach a just-discovered subject to the
        active request.  Callers that do not implement that containment path
        continue through :meth:`bind_or_assert_on`, which raises normally.
        """

        _require_exact(access, AccessContext)
        _require_exact(run_id, RunId)
        _require_exact(origin, RunOrigin)
        grant = access.grant_for(ProjectRole.DATA)
        if grant is None:
            raise AuthorizationDenied()
        params = {
            "project_id": access.project_id.value,
            "run_id": run_id.value,
            "principal_id": access.principal_id.value,
            "agent_type_id": access.agent_type_id.value,
            "grant_id": grant.grant_id,
            "origin": origin.value,
        }
        try:
            if deadline is not None:
                _require_remaining(deadline)
                refresh_deadline_statement_timeout(conn, deadline)
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(_OPEN_ERASURE_GUARDED_RUN_SQL, params)
                gate_row = cur.fetchone()
                if gate_row is None:
                    raise TracebedError()
                writable = gate_row.get("writable")
                late_bind_eligible = gate_row.get("late_bind_eligible")
                if type(writable) is not bool or type(late_bind_eligible) is not bool:
                    raise TracebedError()
                if writable and late_bind_eligible:
                    raise TracebedError()
        except psycopg.Error as error:
            if is_expired_deadline_query_cancellation(error, deadline):
                raise RequestDeadlineExceeded() from error
            if error.sqlstate == "42501":
                raise AuthorizationDenied() from None
            if error.sqlstate == "P0002":
                raise RunAuthorityDenied() from None
            if error.sqlstate == "P0005":
                raise ErasureFenced() from None
            raise TracebedError() from None
        if not writable and not late_bind_eligible:
            return _RunOpenOutcome(None, writable=False, late_bind_eligible=False)
        origin_raw = gate_row.get("origin")
        if type(origin_raw) is not str:
            raise TracebedError()
        try:
            persisted_origin = RunOrigin(origin_raw)
        except ValueError:
            raise TracebedError() from None
        # The profiled function has just locked and verified the exact owner
        # tuple.  Returning its bounded persisted origin lets the API avoid a
        # direct run_owner read (which c12 deliberately does not authorize).
        authority = RunAuthority(
            project_id=access.project_id,
            run_id=run_id,
            owner_principal_id=access.principal_id,
            agent_type_id=access.agent_type_id,
            origin=persisted_origin,
        )
        return _RunOpenOutcome(
            authority,
            writable=writable,
            late_bind_eligible=late_bind_eligible,
        )

    def bind_subject_tags_on(
        self,
        conn: Connection[Any],
        access: AccessContext,
        run_id: RunId,
        *,
        required_role: ProjectRole,
        subject_tags: tuple[str, ...],
    ) -> tuple[bytes, ...]:
        """Atomically bind/propagate the full authoritative run union.

        The PostgreSQL function takes raw tags only long enough to validate and
        hash them.  It returns opaque sorted digests and refuses a sealed,
        fenced, stale, or capacity-invalid lineage before queue business work
        is inserted.
        """

        outcome = self.bind_subject_tags_outcome_on(
            conn,
            access,
            run_id,
            required_role=required_role,
            subject_tags=subject_tags,
        )
        if not outcome.writable:
            raise ErasureFenced()
        return outcome.subject_digests

    def bind_subject_tags_outcome_on(
        self,
        conn: Connection[Any],
        access: AccessContext,
        run_id: RunId,
        *,
        required_role: ProjectRole,
        subject_tags: tuple[str, ...],
        deadline: RemainingBudget | None = None,
    ) -> _SubjectBindOutcome:
        """Bind tags and retain a non-writable containment result for callers.

        The false outcome is intentionally not raised here: the caller must
        first let its scoped transaction commit the late run/subject/closure
        evidence, then reject the business operation outside that transaction.
        """

        _require_exact(access, AccessContext)
        _require_exact(run_id, RunId)
        _require_exact(required_role, ProjectRole)
        if type(subject_tags) is not tuple or any(type(tag) is not str for tag in subject_tags):
            raise TypeError("subject_tags must be an exact tuple of strings")
        grant = access.grant_for(required_role)
        if grant is None:
            raise AuthorizationDenied()
        try:
            if deadline is not None:
                _require_remaining(deadline)
                refresh_deadline_statement_timeout(conn, deadline)
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    _BIND_RUN_SUBJECT_TAGS_SQL,
                    {
                        "project_id": access.project_id.value,
                        "principal_id": access.principal_id.value,
                        "agent_type_id": access.agent_type_id.value,
                        "grant_id": grant.grant_id,
                        "run_id": run_id.value,
                        "role": required_role.value,
                        "subject_tags": list(subject_tags),
                    },
                )
                row = cur.fetchone()
        except psycopg.Error as error:
            if is_expired_deadline_query_cancellation(error, deadline):
                raise RequestDeadlineExceeded() from error
            if error.sqlstate == "42501":
                raise AuthorizationDenied() from None
            if error.sqlstate == "P0002":
                raise RunAuthorityDenied() from None
            if error.sqlstate == "P0004":
                raise ErasureFenced() from None
            if error.sqlstate == "P0005":
                raise ErasureFenced() from None
            raise TracebedError() from None
        if row is None or type(row.get("writable")) is not bool:
            raise TracebedError()
        writable = cast(bool, row["writable"])
        if not writable:
            # The profiled binder may intentionally return the *attempted*
            # 65-element union while recording a late fenced association.
            # That diagnostic union is not business input and must never make
            # this transaction fail: callers need to commit the durable
            # containment before returning their opaque refusal.  Successful
            # admissions below remain strictly validated as a canonical
            # <=64-digest union.
            return _SubjectBindOutcome((), writable=False)
        raw_digests = row.get("subject_digests")
        if type(raw_digests) not in {list, tuple}:
            raise TracebedError()
        digests = tuple(cast(list[object] | tuple[object, ...], raw_digests))
        if any(type(digest) is not bytes or len(digest) != 32 for digest in digests):
            raise TracebedError()
        typed_digests = cast(tuple[bytes, ...], digests)
        if (
            tuple(sorted(typed_digests)) != typed_digests
            or len(set(typed_digests)) != len(typed_digests)
            or len(typed_digests) > 64
        ):
            raise TracebedError()
        return _SubjectBindOutcome(typed_digests, writable=True)

    def require(self, project_id: ProjectId, run_id: RunId) -> RunAuthority:
        _require_exact(project_id, ProjectId)
        _require_exact(run_id, RunId)
        with scoped(self._pool, project_id) as conn:
            return self.require_on(conn, project_id, run_id)

    def require_on(
        self,
        conn: Connection[Any],
        project_id: ProjectId,
        run_id: RunId,
    ) -> RunAuthority:
        _require_exact(project_id, ProjectId)
        _require_exact(run_id, RunId)
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                _RUN_OWNER_SELECT_SQL,
                {"project_id": project_id.value, "run_id": run_id.value},
            )
            row = cur.fetchone()
        return self._run_authority_from_row(row, project_id, run_id)

    @staticmethod
    def _run_authority_from_row(
        row: Mapping[str, object] | None,
        project_id: ProjectId,
        run_id: RunId,
    ) -> RunAuthority:
        if row is None:
            raise RunAuthorityDenied()
        try:
            db_project = ProjectId(_as_uuid(row["project_id"]))
            db_run = RunId(_as_uuid(row["run_id"]))
            if db_project != project_id or db_run != run_id:
                raise RunAuthorityDenied()
            return RunAuthority(
                project_id=db_project,
                run_id=db_run,
                owner_principal_id=PrincipalId(_as_uuid(row["principal_id"])),
                agent_type_id=AgentTypeId(_as_uuid(row["agent_type_id"])),
                origin=RunOrigin(_require_str(row["origin"])),
            )
        except RunAuthorityDenied:
            raise
        except (KeyError, TypeError, ValueError):
            raise RunAuthorityDenied() from None


def _require_str(value: object) -> str:
    if type(value) is not str:
        raise ValueError("malformed authority row")
    return value


class AuthorizedRetrievalOpener:
    """Recheck DATA and bind retrieval ownership before hot-path execution.

    The route's earlier access resolution is only an admission hint.  This
    transaction is the authority decision that matters: a grant revoked or a
    project suspended between dependency resolution and pipeline execution
    cannot open a new run.
    """

    def __init__(
        self, pool: ConnectionPool, *, activity: ActivityGate, audit_repo: Repo | None = None
    ) -> None:
        self._pool = pool
        self._activity = activity
        self._authority = AuthorityStore(pool)
        self._runs = RunAuthorityStore(pool)
        self._audit_repo = audit_repo

    def open(
        self,
        access: AccessContext,
        run_id: RunId,
        *,
        subject_tags: tuple[str, ...] = (),
    ) -> RunAuthority:
        """Compatibility one-shot opener.

        New HTTP retrieval uses :meth:`hold` so the gate outlives binding and
        covers search, final fetch, telemetry and response construction.  Keep
        this narrow form for non-HTTP callers and old offline seams.
        """

        with self.hold(access, run_id, subject_tags=subject_tags) as scope:
            return scope.authority

    @contextmanager
    def hold(
        self,
        access: AccessContext,
        run_id: RunId,
        *,
        subject_tags: tuple[str, ...] = (),
        deadline: RemainingBudget | None = None,
    ) -> Iterator[AuthorizedRetrievalScope]:
        """Bind a run then retain the project shared fence until ``yield`` exits."""

        _require_exact(access, AccessContext)
        _require_exact(run_id, RunId)
        if type(subject_tags) is not tuple or any(type(tag) is not str for tag in subject_tags):
            raise TypeError("subject_tags must be an exact tuple of strings")
        if deadline is not None and deadline.remaining_ms() <= 0:
            raise RequestDeadlineExceeded()
        if deadline is None:
            activity_hold = self._activity.shared(access.project_id)
        else:
            activity_hold = self._activity.shared(access.project_id, deadline=deadline)
        with activity_hold:
            if deadline is not None and deadline.remaining_ms() <= 0:
                raise RequestDeadlineExceeded()
            fenced = False
            authority: RunAuthority | None = None
            if deadline is None:
                connection = scoped(self._pool, access.project_id)
            else:
                connection = scoped(self._pool, access.project_id, deadline=deadline)
            with ExitStack() as stack:
                try:
                    conn = stack.enter_context(connection)
                except PoolDeadlineExceeded as exc:
                    if deadline is None:
                        raise
                    raise RequestDeadlineExceeded() from exc
                except psycopg.Error as exc:
                    if is_expired_deadline_query_cancellation(exc, deadline):
                        raise RequestDeadlineExceeded() from exc
                    raise
                try:
                    # This transaction deliberately remains open through the
                    # caller's retrieval/read lifetime. The active DATA grant
                    # and project row locks therefore serialize a
                    # revoke/suspension with the last search/final-fetch/telemetry
                    # byte, not merely with run binding.
                    if deadline is None:
                        self._authority.require_active_grant_on(conn, access, ProjectRole.DATA)
                    else:
                        self._authority.require_active_grant_on(
                            conn, access, ProjectRole.DATA, deadline=deadline
                        )
                        _require_remaining(deadline)
                    if deadline is None:
                        opened = self._runs.open_for_subject_bind_on(
                            conn, access, run_id, origin=RunOrigin.RETRIEVE
                        )
                    else:
                        opened = self._runs.open_for_subject_bind_on(
                            conn, access, run_id, origin=RunOrigin.RETRIEVE, deadline=deadline
                        )
                    if opened.writable or opened.late_bind_eligible:
                        authority = opened.authority
                        if authority is None:  # pragma: no cover - checked by outcome parser
                            raise TracebedError()
                        if subject_tags:
                            if deadline is None:
                                bound = self._runs.bind_subject_tags_outcome_on(
                                    conn,
                                    access,
                                    run_id,
                                    required_role=ProjectRole.DATA,
                                    subject_tags=subject_tags,
                                )
                            else:
                                _require_remaining(deadline)
                                bound = self._runs.bind_subject_tags_outcome_on(
                                    conn,
                                    access,
                                    run_id,
                                    required_role=ProjectRole.DATA,
                                    subject_tags=subject_tags,
                                    deadline=deadline,
                                )
                            fenced = not bound.writable
                            # A false bind durably records containment. Let
                            # its transaction commit even when the request
                            # budget elapsed while recording that evidence.
                            if not fenced and deadline is not None:
                                _require_remaining(deadline)
                        else:
                            # An active subject request may expose an existing
                            # live owner solely to a subsequent tag bind. A
                            # tag-less retrieval cannot add containment, so it is
                            # refused after this clean transaction exit.
                            fenced = not opened.writable
                            if not fenced and deadline is not None:
                                _require_remaining(deadline)
                    else:
                        fenced = True
                except PoolDeadlineExceeded as exc:
                    if deadline is None:
                        raise
                    raise RequestDeadlineExceeded() from exc
                if not fenced:
                    assert authority is not None
                    # Keep this outside the setup exception handler. A body
                    # error from the yielded retrieval keeps its identity.
                    audit = (
                        self._audit_repo._authorized_retrieval_audit(
                            conn,
                            access.project_id,
                            run_id,
                            deadline,
                            _capability=_AUTHORIZED_RETRIEVAL_AUDIT_CAPABILITY,
                        )
                        if self._audit_repo is not None and deadline is not None
                        else None
                    )
                    try:
                        yield AuthorizedRetrievalScope(authority, audit)
                    except BaseException:
                        if audit is not None:
                            cast(Any, audit)._close()
                        raise
                    else:
                        if audit is not None:
                            assert deadline is not None
                            try:
                                cast(Any, audit)._require_complete()
                                _require_remaining(deadline)
                                refresh_deadline_statement_timeout(conn, deadline)
                            except PoolDeadlineExceeded as exc:
                                raise RequestDeadlineExceeded() from exc
                            except psycopg.Error as exc:
                                if is_expired_deadline_query_cancellation(exc, deadline):
                                    raise RequestDeadlineExceeded() from exc
                                raise RetrievalAuditUnavailable() from exc
                            except (
                                RequestDeadlineExceeded,
                                ErasureFenced,
                                AuthorizationDenied,
                                RunAuthorityDenied,
                            ):
                                raise
                            except Exception as exc:
                                raise RetrievalAuditUnavailable() from exc
                            finally:
                                cast(Any, audit)._close()
                            commit_stack = stack.pop_all()
                            try:
                                commit_stack.close()
                            except PoolDeadlineExceeded as exc:
                                raise RequestDeadlineExceeded() from exc
                            except (
                                RequestDeadlineExceeded,
                                ErasureFenced,
                                AuthorizationDenied,
                                RunAuthorityDenied,
                            ):
                                raise
                            except psycopg.Error as exc:
                                if is_expired_deadline_query_cancellation(exc, deadline):
                                    raise RequestDeadlineExceeded() from exc
                                raise RetrievalAuditUnavailable() from exc
                            except Exception as exc:
                                raise RetrievalAuditUnavailable() from exc
            # A false binder result has already appended and fenced the late
            # closure. Raising inside ``scoped`` would roll it all back; wait
            # until its clean exit then return the opaque refusal.
            if fenced:
                raise ErasureFenced()


class AuthorizedInvalidationWriter:
    """A DATA-gated invalidation write with its recheck and INSERT in one tx."""

    def __init__(self, pool: ConnectionPool, clock: Clock, *, activity: ActivityGate) -> None:
        self._pool = pool
        self._clock = clock
        self._activity = activity
        self._authority = AuthorityStore(pool)

    def insert(
        self,
        access: AccessContext,
        event_type: str,
        selector: Mapping[str, object] | None = None,
    ) -> UUID:
        _require_exact(access, AccessContext)
        if type(event_type) is not str or not event_type:
            raise ValueError("invalidation event_type must be a non-empty string")
        if selector is not None and not isinstance(selector, Mapping):
            raise TypeError("invalidation selector must be a mapping or None")
        with (
            self._activity.shared(access.project_id),
            scoped(self._pool, access.project_id) as conn,
        ):
            grant = self._authority.require_active_grant_on(conn, access, ProjectRole.DATA)
            try:
                row = conn.execute(
                    _INSERT_AUTHORIZED_INVALIDATION_SQL,
                    {
                        "project_id": access.project_id.value,
                        "principal_id": access.principal_id.value,
                        "agent_type_id": access.agent_type_id.value,
                        # The exact durable grant recheck above is the only
                        # authority source for this SECDEF call.  AccessContext
                        # intentionally carries a grant set, never a mutable
                        # ambient ``grant`` attribute a caller could forge.
                        "grant_id": grant.grant_id,
                        "event_type": event_type,
                        "selector": Json(dict(selector)) if selector is not None else None,
                    },
                ).fetchone()
            except psycopg.Error as error:
                if error.sqlstate == "42501":
                    raise AuthorizationDenied() from None
                if error.sqlstate == "P0002":
                    raise ErasureFenced() from None
                raise TracebedError() from None
        if row is None or type(row[0]) is not UUID:
            raise TracebedError()
        return row[0]
