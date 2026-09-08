"""API-only E2 request/fence publication store.

This module intentionally contains no saga claimant, key destruction, or
external-store operation.  Its two calls enter the profiled PostgreSQL
SECURITY DEFINER boundary, which is the only runtime surface with authority to
persist/read an erasure request or its fences.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Final, cast
from uuid import UUID

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from tracebed.adapters.identity import Principal
from tracebed.domain.authority import AccessContext, ErasureRequestStatus
from tracebed.domain.enums import ProjectRole
from tracebed.domain.errors import (
    AuthorizationDenied,
    ErasureFenced,
    ErasureRequestNotFound,
    ErasureSnapshotStale,
    ErasureTargetConflict,
    TracebedError,
)
from tracebed.domain.ids import ProjectId, RunId
from tracebed.domain.subject_tags import validate_subject_tag
from tracebed.stores.pg.activity import ActivityGate
from tracebed.stores.pg.pool import scoped

__all__ = ["ErasureRequestStore", "ErasureSnapshotGuard", "WorkerErasureGuard"]


_REQUEST_SQL: Final = """
SELECT request_id, scope, phase, disposition, last_code, limitation_codes,
       requested_at, updated_at, completed_at
FROM public.tracebed_request_erasure(
    %(project_id)s::uuid,
    %(principal_id)s::uuid,
    %(agent_type_id)s::uuid,
    %(grant_id)s::uuid,
    %(scope)s::text,
    %(subject_tag)s::text
)
""".strip()

_STATUS_SQL: Final = """
SELECT request_id, scope, phase, disposition, last_code, limitation_codes,
       requested_at, updated_at, completed_at
FROM public.tracebed_erasure_request_status(
    %(project_id)s::uuid,
    %(principal_id)s::uuid,
    %(agent_type_id)s::uuid,
    %(grant_id)s::uuid,
    %(request_id)s::uuid
)
""".strip()

_STATUS_BY_ACTOR_SQL: Final = """
SELECT request_id, scope, phase, disposition, last_code, limitation_codes,
       requested_at, updated_at, completed_at
FROM public.tracebed_erasure_request_status_by_actor(
    %(principal_id)s::uuid,
    %(request_id)s::uuid
)
""".strip()

_LOCK_RUN_SUBJECT_SNAPSHOT_SQL: Final = """
SELECT public.tracebed_lock_run_subject_snapshot(
    %(project_id)s::uuid,
    %(run_id)s::uuid,
    %(subject_digests)s::bytea[]
) AS subject_digests
""".strip()


def _require_exact(value: object, expected: type[object], *, field: str) -> None:
    if type(value) is not expected:
        raise TypeError(f"{field} must be an exact {expected.__name__}")


def _canonical_digests(values: Sequence[bytes]) -> tuple[bytes, ...]:
    if type(values) not in {tuple, list}:
        raise TypeError("subject digests must be a concrete sequence")
    digests = tuple(values)
    if (
        len(digests) > 64
        or any(type(digest) is not bytes or len(digest) != 32 for digest in digests)
        or tuple(sorted(digests)) != digests
        or len(set(digests)) != len(digests)
    ):
        raise ValueError("subject digests are not canonical")
    return digests


class ErasureSnapshotGuard:
    """Minimal worker guard seam used before a side-effecting run operation."""

    def assert_snapshot(
        self,
        project_id: ProjectId,
        run_id: RunId,
        subject_digests: Sequence[bytes],
    ) -> tuple[bytes, ...]:
        raise NotImplementedError


class WorkerErasureGuard(ErasureSnapshotGuard):
    """Worker-only guard over the profiled run-snapshot routine."""

    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool

    def assert_snapshot(
        self,
        project_id: ProjectId,
        run_id: RunId,
        subject_digests: Sequence[bytes],
    ) -> tuple[bytes, ...]:
        _require_exact(project_id, ProjectId, field="project_id")
        _require_exact(run_id, RunId, field="run_id")
        expected = _canonical_digests(subject_digests)
        try:
            with (
                scoped(self._pool, project_id) as conn,
                conn.cursor(row_factory=dict_row) as cur,
            ):
                cur.execute(
                    _LOCK_RUN_SUBJECT_SNAPSHOT_SQL,
                    {
                        "project_id": project_id.value,
                        "run_id": run_id.value,
                        "subject_digests": list(expected),
                    },
                )
                row = cur.fetchone()
        except psycopg.Error as error:
            if error.sqlstate == "P0002":
                raise ErasureFenced() from None
            if error.sqlstate == "P0003":
                raise ErasureSnapshotStale() from None
            raise TracebedError() from None
        if row is None:
            raise TracebedError()
        raw = row.get("subject_digests")
        if type(raw) not in {list, tuple}:
            raise TracebedError()
        actual = _canonical_digests(cast(Sequence[bytes], raw))
        if actual != expected:
            raise ErasureSnapshotStale()
        return actual


def _status_from_row(row: Mapping[str, object] | None) -> ErasureRequestStatus:
    if row is None:
        raise ErasureRequestNotFound()
    try:
        raw_codes = row["limitation_codes"]
        if type(raw_codes) not in {list, tuple}:
            raise ValueError("malformed erasure status row")
        codes = cast(list[object] | tuple[object, ...], raw_codes)
        if any(type(code) is not str for code in codes):
            raise ValueError("malformed erasure status row")
        request_id = row["request_id"]
        scope = row["scope"]
        phase = row["phase"]
        disposition = row["disposition"]
        last_code = row["last_code"]
        requested_at = row["requested_at"]
        updated_at = row["updated_at"]
        completed_at = row["completed_at"]
        if (
            type(request_id) is not UUID
            or type(scope) is not str
            or type(phase) is not str
            or type(disposition) is not str
            or (last_code is not None and type(last_code) is not str)
            or type(requested_at) is not datetime
            or type(updated_at) is not datetime
            or (completed_at is not None and type(completed_at) is not datetime)
        ):
            raise ValueError("malformed erasure status row")
        return ErasureRequestStatus(
            request_id=request_id,
            scope=scope,
            phase=phase,
            disposition=disposition,
            last_code=last_code,
            limitation_codes=tuple(cast(list[str] | tuple[str, ...], codes)),
            requested_at=requested_at,
            updated_at=updated_at,
            completed_at=completed_at,
        )
    except (KeyError, TypeError, ValueError):
        # A malformed privileged function result is a deployment failure, not
        # a not-found oracle and never a value to echo through the API.
        raise TracebedError() from None


class ErasureRequestStore:
    """Request/replay/status adapter over the E2 profiled function surface."""

    def __init__(self, pool: ConnectionPool, *, activity: ActivityGate) -> None:
        self._pool = pool
        self._activity = activity

    @staticmethod
    def _parameters(
        access: AccessContext,
        *,
        scope: str,
        subject_tag: str | None,
    ) -> dict[str, object]:
        _require_exact(access, AccessContext, field="access")
        grant = access.grant_for(ProjectRole.ERASURE_REQUEST)
        if grant is None:
            raise AuthorizationDenied()
        if scope not in {"subject", "project"}:
            raise ValueError("erasure scope is invalid")
        if scope == "subject":
            if type(subject_tag) is not str:
                raise ValueError("subject erasure requires a subject tag")
            # Repeat exact canonical validation at the port boundary.  The
            # function validates again; neither layer normalizes or logs it.
            subject_tag = validate_subject_tag(subject_tag)
        elif subject_tag is not None:
            raise ValueError("project erasure cannot carry a subject tag")
        return {
            "project_id": access.project_id.value,
            "principal_id": access.principal_id.value,
            "agent_type_id": access.agent_type_id.value,
            "grant_id": grant.grant_id,
            "scope": scope,
            "subject_tag": subject_tag,
        }

    @staticmethod
    def _map_database_error(error: psycopg.Error) -> TracebedError:
        # The function's controlled SQLSTATEs are purpose-built opaque API
        # outcomes.  Every other database error remains an opaque 500.
        if error.sqlstate == "P0001":
            return ErasureTargetConflict()
        if error.sqlstate == "P0005":
            # The recursive closure proof intentionally refuses instead of
            # truncating at depth 1024.  Keep the externally visible result
            # opaque and non-accepting; the operator-only SQL diagnostic is
            # not surfaced through this API boundary.
            return ErasureFenced()
        if error.sqlstate == "42501":
            return AuthorizationDenied()
        return TracebedError()

    def request(
        self,
        access: AccessContext,
        *,
        scope: str,
        subject_tag: str | None,
    ) -> ErasureRequestStatus:
        params = self._parameters(access, scope=scope, subject_tag=subject_tag)
        try:
            # The exclusive process gate is only a fast drain: the SECDEF
            # routine repeats project/actor authority and installs durable
            # fences before the response can become observable.
            with (
                self._activity.exclusive(access.project_id),
                scoped(self._pool, access.project_id) as conn,
                conn.cursor(row_factory=dict_row) as cur,
            ):
                cur.execute(_REQUEST_SQL, params)
                row = cur.fetchone()
        except psycopg.Error as error:
            raise self._map_database_error(error) from None
        return _status_from_row(row)

    def status(self, access: AccessContext, request_id: UUID) -> ErasureRequestStatus:
        _require_exact(access, AccessContext, field="access")
        _require_exact(request_id, UUID, field="request_id")
        grant = access.grant_for(ProjectRole.ERASURE_REQUEST)
        if grant is None:
            raise AuthorizationDenied()
        params: dict[str, object] = {
            "project_id": access.project_id.value,
            "principal_id": access.principal_id.value,
            "agent_type_id": access.agent_type_id.value,
            "grant_id": grant.grant_id,
            "request_id": request_id,
        }
        try:
            # Status is deliberately outside ActivityGate: it is the one
            # non-side-effecting observation allowed while an exclusive
            # request drains the project.  Its SQL function still rechecks
            # the exact active ERASURE_REQUEST grant in this transaction.
            with (
                scoped(self._pool, access.project_id) as conn,
                conn.cursor(row_factory=dict_row) as cur,
            ):
                cur.execute(_STATUS_SQL, params)
                row = cur.fetchone()
        except psycopg.Error as error:
            raise self._map_database_error(error) from None
        return _status_from_row(row)

    def status_by_actor(self, principal: Principal, request_id: UUID) -> ErasureRequestStatus:
        """Terminal project tombstones remain observable only by the actor.

        This deliberately bypasses normal project-scope resolution: after a
        project tombstone no normal access context may be reconstructed.  The
        profiled SQL function preserves E2's active-grant rule while live and
        performs the narrower terminal credential check after deletion.
        """

        _require_exact(principal, Principal, field="principal")
        _require_exact(request_id, UUID, field="request_id")
        try:
            with (
                self._pool.connection() as conn,
                conn.transaction(),
                conn.cursor(row_factory=dict_row) as cur,
            ):
                cur.execute(
                    _STATUS_BY_ACTOR_SQL,
                    {"principal_id": principal.principal_id.value, "request_id": request_id},
                )
                row = cur.fetchone()
        except psycopg.Error as error:
            if error.sqlstate in {"P0002", "42501"}:
                raise ErasureRequestNotFound() from None
            raise TracebedError() from None
        return _status_from_row(row)
