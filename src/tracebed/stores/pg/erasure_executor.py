"""PostgreSQL adapter for the non-runtime E3 erasure function surface."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Final, Literal, cast
from uuid import UUID

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from tracebed.domain.errors import (
    ErasureClosureChanged,
    ErasureLeaseLost,
    ErasureOperatorBlocked,
    TracebedError,
)
from tracebed.domain.ids import ProjectId
from tracebed.erasure.domain import (
    ErasureLease,
    ErasureResultCode,
    ExternalStoreCode,
    ExternalWork,
    StepOutcome,
    StoreResult,
)
from tracebed.erasure.executor import (
    ErasureDatabasePort,
    ErasureStatus,
    TraceManifestRef,
    _PrimaryBatch,
)
from tracebed.stores.pg.pool import scoped

__all__ = ["PgErasureExecutorStore"]

_CLAIM_NEXT_SQL: Final = """
SELECT project_id, request_id, scope, phase, generation, lease_token, lease_expires_at, closure_revision
FROM public.tracebed_erasure_claim_next(%(owner)s::text, %(lease_seconds)s::integer, %(manifest)s::text[])
"""
_CLAIM_REQUEST_SQL: Final = """
SELECT project_id, request_id, scope, phase, generation, lease_token, lease_expires_at, closure_revision
FROM public.tracebed_erasure_claim_request(%(request_id)s::uuid, %(owner)s::text, %(lease_seconds)s::integer, %(manifest)s::text[])
"""
_RENEW_SQL: Final = """
SELECT public.tracebed_erasure_renew(%(project_id)s::uuid, %(request_id)s::uuid, %(generation)s::integer,
 %(lease_token)s::uuid, %(owner)s::text, %(lease_seconds)s::integer) AS lease_expires_at
"""
_CRYPTO_SQL: Final = """
SELECT phase, affected_rows, closure_revision, result_code
FROM public.tracebed_erasure_crypto_step(%(project_id)s::uuid, %(request_id)s::uuid, %(generation)s::integer,
 %(lease_token)s::uuid, %(owner)s::text)
"""
_REFS_SQL: Final = """
SELECT run_id, payload_ref
FROM public.tracebed_erasure_trace_refs_batch(%(project_id)s::uuid, %(request_id)s::uuid, %(generation)s::integer,
 %(lease_token)s::uuid, %(owner)s::text, %(revision)s::bigint, %(after_run_id)s::uuid,
 %(after_payload_ref)s::text, %(limit)s::integer)
"""
_SEAL_SQL: Final = """
SELECT public.tracebed_erasure_seal_trace_manifest(%(project_id)s::uuid, %(request_id)s::uuid,
 %(generation)s::integer, %(lease_token)s::uuid, %(owner)s::text, %(revision)s::bigint,
 %(count)s::bigint, %(digest)s::bytea)
"""
_PREPARE_SQL: Final = """
SELECT closure_revision, pending_external
FROM public.tracebed_erasure_prepare_primary(%(project_id)s::uuid, %(request_id)s::uuid,
 %(generation)s::integer, %(lease_token)s::uuid, %(owner)s::text)
"""
_PRIMARY_SQL: Final = """
SELECT batch_code, affected_rows, remaining, closure_revision, postcondition_digest
FROM public.tracebed_erasure_primary_batch(%(project_id)s::uuid, %(request_id)s::uuid, %(generation)s::integer,
 %(lease_token)s::uuid, %(owner)s::text, %(limit)s::integer)
"""
_WORK_SQL: Final = """
SELECT work_id, target_kind, target_id, work_revision, attempt
FROM public.tracebed_erasure_external_work_batch(%(project_id)s::uuid, %(request_id)s::uuid,
 %(generation)s::integer, %(lease_token)s::uuid, %(owner)s::text, %(store_code)s::text, %(limit)s::integer)
"""
_MARK_SQL: Final = """
SELECT public.tracebed_erasure_mark_external_work(%(project_id)s::uuid, %(request_id)s::uuid,
 %(generation)s::integer, %(lease_token)s::uuid, %(owner)s::text, %(work_id)s::uuid,
 %(work_revision)s::bigint, %(affected_rows)s::bigint, %(digest)s::bytea, %(result_code)s::text)
"""
_CLOSE_SQL: Final = """
SELECT phase, closure_revision
FROM public.tracebed_erasure_close_external_step(%(project_id)s::uuid, %(request_id)s::uuid,
 %(generation)s::integer, %(lease_token)s::uuid, %(owner)s::text, %(store_code)s::text,
 %(target_count)s::bigint, %(affected_rows)s::bigint, %(digest)s::bytea, %(result_code)s::text)
"""
_COMPLETE_SQL: Final = """
SELECT completed, phase, disposition, closure_revision, last_code
FROM public.tracebed_erasure_verify_and_complete(%(project_id)s::uuid, %(request_id)s::uuid,
 %(generation)s::integer, %(lease_token)s::uuid, %(owner)s::text)
"""
_FAIL_SQL: Final = """
SELECT public.tracebed_erasure_fail(%(project_id)s::uuid, %(request_id)s::uuid, %(generation)s::integer,
 %(lease_token)s::uuid, %(owner)s::text, %(step)s::text, %(result)s::text, %(result_code)s::text,
 %(affected_rows)s::bigint, %(digest)s::bytea)
"""
_RELEASE_SQL: Final = """
SELECT public.tracebed_erasure_release(%(project_id)s::uuid, %(request_id)s::uuid, %(generation)s::integer,
 %(lease_token)s::uuid, %(owner)s::text)
"""
_INSPECT_SQL: Final = """
SELECT request_id, scope, phase, disposition, generation, retry_not_before, last_code, closure_revision,
       pending_work, verified_stores, total_stores
FROM public.tracebed_erasure_inspect(%(request_id)s::uuid)
"""
_RESUME_SQL: Final = (
    "SELECT public.tracebed_erasure_resume_blocked(%(request_id)s::uuid, %(operator_code)s::text)"
)
_ADMISSION_OPEN_SQL: Final = "SELECT public.tracebed_erasure_admission_is_open()"
_SET_STATEMENT_TIMEOUT_SQL: Final = (
    "SELECT set_config('statement_timeout', %(statement_timeout_ms)s, true)"
)
_DEFAULT_STATEMENT_TIMEOUT_MS: Final = 20_000


def _require_uuid(row: Mapping[str, object], name: str) -> UUID:
    value = row.get(name)
    if type(value) is not UUID:
        raise TracebedError()
    return value


def _require_int(row: Mapping[str, object], name: str, *, minimum: int = 0) -> int:
    value = row.get(name)
    if type(value) is not int or isinstance(value, bool) or value < minimum:
        raise TracebedError()
    return value


def _require_text(row: Mapping[str, object], name: str) -> str:
    value = row.get(name)
    if type(value) is not str:
        raise TracebedError()
    return value


class PgErasureExecutorStore(ErasureDatabasePort):
    """A strict, server-side-bounded parser over the E3 function contract.

    Every executor transaction carries a local statement timeout.  A crashed
    container can otherwise leave PostgreSQL executing a blocked destructive
    statement, retaining its request-row lock after the client has gone and
    preventing an expired lease from being reclaimed.  The runtime supplies
    its heartbeat as this bound; the default preserves that fixed deployment
    relation for direct construction in integration tests.
    """

    def __init__(self, pool: ConnectionPool, *, statement_timeout_ms: int = _DEFAULT_STATEMENT_TIMEOUT_MS) -> None:
        if type(statement_timeout_ms) is not int or statement_timeout_ms <= 0:
            raise ValueError("erasure statement timeout is invalid")
        self._pool = pool
        self._statement_timeout_ms = statement_timeout_ms

    @contextmanager
    def _global(self) -> Iterator[psycopg.Connection[Any]]:
        try:
            with self._pool.connection() as conn, conn.transaction():
                conn.execute(
                    _SET_STATEMENT_TIMEOUT_SQL,
                    {"statement_timeout_ms": str(self._statement_timeout_ms)},
                )
                yield conn
        except psycopg.Error as error:
            self._raise_database_error(error)

    @contextmanager
    def _project(self, project_id: UUID) -> Iterator[psycopg.Connection[Any]]:
        try:
            with scoped(
                self._pool,
                ProjectId(project_id),
                statement_timeout_ms=self._statement_timeout_ms,
            ) as conn:
                yield conn
        except psycopg.Error as error:
            self._raise_database_error(error)

    @staticmethod
    def _raise_database_error(error: psycopg.Error) -> None:
        if error.sqlstate == "P0011":
            raise ErasureLeaseLost() from None
        if error.sqlstate == "P0014":
            raise ErasureClosureChanged() from None
        if error.sqlstate in {"P0012", "P0013"}:
            raise ErasureOperatorBlocked() from None
        raise TracebedError() from None

    @staticmethod
    def _lease_params(lease: ErasureLease, owner: str) -> dict[str, object]:
        return {
            "project_id": lease.project_id,
            "request_id": lease.request_id,
            "generation": lease.generation,
            "lease_token": lease.lease_token,
            "owner": owner,
        }

    @staticmethod
    def _lease(row: Mapping[str, object]) -> ErasureLease:
        scope = _require_text(row, "scope")
        phase = _require_text(row, "phase")
        expires = row.get("lease_expires_at")
        if type(expires) is not datetime:
            raise TracebedError()
        return ErasureLease(
            project_id=_require_uuid(row, "project_id"),
            request_id=_require_uuid(row, "request_id"),
            scope=cast(Literal["subject", "project"], scope),
            phase=cast(Any, phase),
            generation=_require_int(row, "generation", minimum=1),
            lease_token=_require_uuid(row, "lease_token"),
            lease_expires_at=expires,
            closure_revision=_require_int(row, "closure_revision", minimum=1),
        )

    def claim_next(
        self, owner: str, lease_seconds: int, manifest: tuple[ExternalStoreCode, ...]
    ) -> ErasureLease | None:
        with self._global() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                _CLAIM_NEXT_SQL,
                {"owner": owner, "lease_seconds": lease_seconds, "manifest": list(manifest)},
            )
            row = cur.fetchone()
        return None if row is None else self._lease(row)

    def admission_open(self) -> bool:
        """Read the E4 admission gate before issuing any claim mutation."""

        with self._global() as conn, conn.cursor() as cur:
            cur.execute(_ADMISSION_OPEN_SQL)
            row = cur.fetchone()
        if row != (True,):
            if row == (False,):
                return False
            raise TracebedError()
        return True

    def claim_request(
        self,
        request_id: UUID,
        owner: str,
        lease_seconds: int,
        manifest: tuple[ExternalStoreCode, ...],
    ) -> ErasureLease | None:
        with self._global() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                _CLAIM_REQUEST_SQL,
                {
                    "request_id": request_id,
                    "owner": owner,
                    "lease_seconds": lease_seconds,
                    "manifest": list(manifest),
                },
            )
            row = cur.fetchone()
        return None if row is None else self._lease(row)

    def renew(self, lease: ErasureLease, owner: str, lease_seconds: int) -> datetime:
        params = self._lease_params(lease, owner) | {"lease_seconds": lease_seconds}
        with self._project(lease.project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(_RENEW_SQL, params)
            row = cur.fetchone()
        if row is None or type(row.get("lease_expires_at")) is not datetime:
            raise TracebedError()
        return cast(datetime, row["lease_expires_at"])

    def _step(self, sql: str, lease: ErasureLease, owner: str) -> StepOutcome:
        with self._project(lease.project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, self._lease_params(lease, owner))
            row = cur.fetchone()
        if row is None:
            raise TracebedError()
        return StepOutcome(
            phase=cast(Any, _require_text(row, "phase")),
            affected_rows=_require_int(row, "affected_rows"),
            closure_revision=_require_int(row, "closure_revision", minimum=1),
            result_code=cast(Any, _require_text(row, "result_code")),
        )

    def crypto_step(self, lease: ErasureLease, owner: str) -> StepOutcome:
        return self._step(_CRYPTO_SQL, lease, owner)

    def trace_refs_batch(
        self,
        lease: ErasureLease,
        owner: str,
        revision: int,
        after_run_id: UUID | None,
        after_payload_ref: str | None,
        limit: int,
    ) -> tuple[TraceManifestRef, ...]:
        params = self._lease_params(lease, owner) | {
            "revision": revision,
            "after_run_id": after_run_id,
            "after_payload_ref": after_payload_ref,
            "limit": limit,
        }
        with self._project(lease.project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(_REFS_SQL, params)
            rows = cur.fetchall()
        return tuple(
            TraceManifestRef(_require_uuid(row, "run_id"), _require_text(row, "payload_ref"))
            for row in rows
        )

    def seal_trace_manifest(
        self, lease: ErasureLease, owner: str, revision: int, count: int, digest: bytes
    ) -> None:
        params = self._lease_params(lease, owner) | {
            "revision": revision,
            "count": count,
            "digest": digest,
        }
        with self._project(lease.project_id) as conn:
            conn.execute(_SEAL_SQL, params)

    def prepare_primary(self, lease: ErasureLease, owner: str) -> StepOutcome:
        with self._project(lease.project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(_PREPARE_SQL, self._lease_params(lease, owner))
            row = cur.fetchone()
        if row is None:
            raise TracebedError()
        # The SQL contract intentionally returns only preparation facts.  The
        # lease's phase is authoritative here; fabricating crypto_erased would
        # make a late closure look like an illegal durable phase regression.
        return StepOutcome(
            lease.phase,
            _require_int(row, "pending_external"),
            _require_int(row, "closure_revision", minimum=1),
            "ok",
        )

    def primary_batch(self, lease: ErasureLease, owner: str, batch_size: int) -> _PrimaryBatch:
        params = self._lease_params(lease, owner) | {"limit": batch_size}
        with self._project(lease.project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(_PRIMARY_SQL, params)
            row = cur.fetchone()
        if row is None or type(row.get("postcondition_digest")) is not bytes:
            raise TracebedError()
        return _PrimaryBatch(
            _require_text(row, "batch_code"),
            _require_int(row, "affected_rows"),
            _require_int(row, "remaining"),
            _require_int(row, "closure_revision", minimum=1),
            cast(bytes, row["postcondition_digest"]),
        )

    def external_work_batch(
        self, lease: ErasureLease, owner: str, store_code: ExternalStoreCode, limit: int
    ) -> tuple[ExternalWork, ...]:
        params = self._lease_params(lease, owner) | {"store_code": store_code, "limit": limit}
        with self._project(lease.project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(_WORK_SQL, params)
            rows = cur.fetchall()
        return tuple(
            ExternalWork(
                _require_uuid(row, "work_id"),
                cast(Any, _require_text(row, "target_kind")),
                cast(UUID | None, row.get("target_id")),
                _require_int(row, "work_revision", minimum=1),
                _require_int(row, "attempt", minimum=1),
            )
            for row in rows
        )

    def mark_external_work(
        self, lease: ErasureLease, owner: str, work: ExternalWork, result: StoreResult
    ) -> None:
        params = self._lease_params(lease, owner) | {
            "work_id": work.work_id,
            "work_revision": work.work_revision,
            "affected_rows": result.affected_rows,
            "digest": result.postcondition_digest,
            "result_code": result.result_code,
        }
        with self._project(lease.project_id) as conn:
            conn.execute(_MARK_SQL, params)

    def close_external_step(
        self,
        lease: ErasureLease,
        owner: str,
        store_code: ExternalStoreCode,
        target_count: int,
        result: StoreResult,
    ) -> StepOutcome:
        params = self._lease_params(lease, owner) | {
            "store_code": store_code,
            "target_count": target_count,
            "affected_rows": result.affected_rows,
            "digest": result.postcondition_digest,
            "result_code": result.result_code,
        }
        with self._project(lease.project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(_CLOSE_SQL, params)
            row = cur.fetchone()
        if row is None:
            raise TracebedError()
        return StepOutcome(
            cast(Any, _require_text(row, "phase")),
            0,
            _require_int(row, "closure_revision", minimum=1),
            "ok",
        )

    def verify_and_complete(self, lease: ErasureLease, owner: str) -> StepOutcome:
        with self._project(lease.project_id) as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(_COMPLETE_SQL, self._lease_params(lease, owner))
            row = cur.fetchone()
        if row is None or row.get("completed") is not True:
            raise TracebedError()
        return StepOutcome(
            cast(Any, _require_text(row, "phase")),
            0,
            _require_int(row, "closure_revision", minimum=1),
            "ok",
        )

    def fail(
        self,
        lease: ErasureLease,
        owner: str,
        step: str,
        result: Literal["retryable", "blocked"],
        result_code: ErasureResultCode,
        affected_rows: int = 0,
        postcondition_digest: bytes | None = None,
    ) -> None:
        digest = postcondition_digest if postcondition_digest is not None else b"\x00" * 32
        params = self._lease_params(lease, owner) | {
            "step": step,
            "result": result,
            "result_code": result_code,
            "affected_rows": affected_rows,
            "digest": digest,
        }
        with self._project(lease.project_id) as conn:
            conn.execute(_FAIL_SQL, params)

    def release(self, lease: ErasureLease, owner: str) -> None:
        with self._project(lease.project_id) as conn:
            conn.execute(_RELEASE_SQL, self._lease_params(lease, owner))

    def inspect(self, request_id: UUID) -> ErasureStatus | None:
        with self._global() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(_INSPECT_SQL, {"request_id": request_id})
            row = cur.fetchone()
        if row is None:
            return None
        retry = row.get("retry_not_before")
        if retry is not None and type(retry) is not datetime:
            raise TracebedError()
        last = row.get("last_code")
        if last is not None and type(last) is not str:
            raise TracebedError()
        return ErasureStatus(
            _require_uuid(row, "request_id"),
            cast(Any, _require_text(row, "scope")),
            _require_text(row, "phase"),
            _require_text(row, "disposition"),
            _require_int(row, "generation"),
            retry,
            last,
            _require_int(row, "closure_revision", minimum=1),
            _require_int(row, "pending_work"),
            _require_int(row, "verified_stores"),
            _require_int(row, "total_stores"),
        )

    def resume_blocked(self, request_id: UUID, operator_code: str) -> None:
        with self._global() as conn:
            conn.execute(_RESUME_SQL, {"request_id": request_id, "operator_code": operator_code})
