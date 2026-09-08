"""Crash/lease ordering proofs for the offline E3 coordinator."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID, uuid4

import pytest

from tracebed.domain.errors import (
    ErasureClosureChanged,
    ErasureDependencyTimeout,
    ErasureLeaseLost,
    ErasureOperatorBlocked,
)
from tracebed.erasure.domain import ErasureLease, ExternalWork, StepOutcome, StoreResult
from tracebed.erasure.executor import (
    ErasureExecutor,
    ErasureStatus,
    TraceManifestRef,
    _PrimaryBatch,
)
from tracebed.stores.pg import erasure_executor as pg_erasure_executor
from tracebed.stores.pg.erasure_executor import PgErasureExecutorStore

pytestmark = pytest.mark.phase3

_MANIFEST = ("graph_none", "trace_fs_v1", "valkey_v1", "vector_none")


def _digest(value: str) -> bytes:
    return hashlib.sha256(value.encode("ascii")).digest()


class _Store:
    def __init__(self) -> None:
        self.io: list[str] = []

    def validate_manifest_ref(self, project_id: UUID, run_id: UUID, payload_ref: str) -> bytes:
        del project_id
        self.io.append("validate")
        return run_id.bytes + payload_ref.encode("utf-8")

    def erase_run(self, project_id: UUID, run_id: UUID, *, timeout_seconds: float) -> StoreResult:
        del project_id, run_id, timeout_seconds
        self.io.append("erase_run")
        return StoreResult("ok", 1, _digest("erase-run"))

    def verify_run_absent(
        self, project_id: UUID, run_id: UUID, *, timeout_seconds: float
    ) -> StoreResult:
        del project_id, run_id, timeout_seconds
        self.io.append("verify_run")
        return StoreResult("already_absent", 0, _digest("verify-run"))

    def erase_project(self, project_id: UUID, *, timeout_seconds: float) -> StoreResult:
        del project_id, timeout_seconds
        self.io.append("erase_project")
        return StoreResult("ok", 1, _digest("erase-project"))

    def verify_project_absent(self, project_id: UUID, *, timeout_seconds: float) -> StoreResult:
        del project_id, timeout_seconds
        self.io.append("verify_project")
        return StoreResult("already_absent", 0, _digest("verify-project"))


class _SubjectTraceStore(_Store):
    def verify_project_absent(self, project_id: UUID, *, timeout_seconds: float) -> StoreResult:
        del project_id, timeout_seconds
        raise AssertionError("subject trace erasure must not require project absence")


class _Db:
    def __init__(self, *, phase: str = "fenced") -> None:
        self.project_id = uuid4()
        self.request_id = uuid4()
        self.token = uuid4()
        self.run_id = uuid4()
        self.phase = phase
        self.refs_sent = False
        self.work_sent: set[str] = set()
        self.marks: list[str] = []
        self.closes: list[str] = []
        self.failures: list[tuple[str, str, str]] = []
        self.released = False

    def _lease(self) -> ErasureLease:
        return ErasureLease(
            self.project_id,
            self.request_id,
            "subject",
            self.phase,  # type: ignore[arg-type]
            1,
            self.token,
            datetime.now(UTC) + timedelta(minutes=1),
            1,
        )

    def claim_next(self, owner: str, lease_seconds: int, manifest: tuple[str, ...]) -> ErasureLease:
        del owner, lease_seconds
        assert manifest == _MANIFEST
        return self._lease()

    def claim_request(
        self, request_id: UUID, owner: str, lease_seconds: int, manifest: tuple[str, ...]
    ) -> ErasureLease | None:
        del owner, lease_seconds, manifest
        return self._lease() if request_id == self.request_id else None

    def renew(self, lease: ErasureLease, owner: str, lease_seconds: int) -> datetime:
        del lease, owner, lease_seconds
        return datetime.now(UTC) + timedelta(minutes=1)

    def crypto_step(self, lease: ErasureLease, owner: str) -> StepOutcome:
        del lease, owner
        self.phase = "crypto_erased"
        return StepOutcome("crypto_erased", 1, 1, "ok")

    def trace_refs_batch(
        self,
        lease: ErasureLease,
        owner: str,
        revision: int,
        after_run_id: UUID | None,
        after_payload_ref: str | None,
        limit: int,
    ) -> tuple[TraceManifestRef, ...]:
        del lease, owner, revision, after_run_id, after_payload_ref, limit
        if self.refs_sent:
            return ()
        self.refs_sent = True
        return (TraceManifestRef(self.run_id, "fs://opaque"),)

    def seal_trace_manifest(
        self, lease: ErasureLease, owner: str, revision: int, count: int, digest: bytes
    ) -> None:
        del lease, owner, revision
        assert count == 1 and len(digest) == 32

    def prepare_primary(self, lease: ErasureLease, owner: str) -> StepOutcome:
        del owner
        return StepOutcome(lease.phase, 0, 1, "ok")

    def primary_batch(self, lease: ErasureLease, owner: str, batch_size: int) -> _PrimaryBatch:
        del lease, owner, batch_size
        self.phase = "primary_purged"
        return _PrimaryBatch("postgres", 1, 0, 1, _digest("primary"))

    def external_work_batch(
        self, lease: ErasureLease, owner: str, store_code: str, limit: int
    ) -> tuple[ExternalWork, ...]:
        del lease, owner, limit
        if store_code in self.work_sent:
            return ()
        self.work_sent.add(store_code)
        if store_code == "trace_fs_v1":
            return (ExternalWork(uuid4(), "run", self.run_id, 1, 1),)
        return (ExternalWork(uuid4(), "project", None, 1, 1),)

    def mark_external_work(
        self, lease: ErasureLease, owner: str, work: ExternalWork, result: StoreResult
    ) -> None:
        del lease, owner, work
        assert len(result.postcondition_digest) == 32
        self.marks.append(result.result_code)

    def close_external_step(
        self,
        lease: ErasureLease,
        owner: str,
        store_code: str,
        target_count: int,
        result: StoreResult,
    ) -> StepOutcome:
        del lease, owner, target_count
        self.closes.append(store_code)
        self.phase = "external_purged" if len(self.closes) == len(_MANIFEST) else "primary_purged"
        return StepOutcome(cast(Any, self.phase), 0, 1, result.result_code)

    def verify_and_complete(self, lease: ErasureLease, owner: str) -> StepOutcome:
        del lease, owner
        self.phase = "scope_complete"
        return StepOutcome("scope_complete", 0, 1, "ok")

    def fail(
        self,
        lease: ErasureLease,
        owner: str,
        step: str,
        result: str,
        result_code: str,
        affected_rows: int = 0,
        postcondition_digest: bytes | None = None,
    ) -> None:
        del lease, owner, affected_rows, postcondition_digest
        self.failures.append((step, result, result_code))

    def release(self, lease: ErasureLease, owner: str) -> None:
        del lease, owner
        self.released = True

    def inspect(self, request_id: UUID) -> ErasureStatus | None:
        del request_id
        return None

    def resume_blocked(self, request_id: UUID, operator_code: str) -> None:
        del request_id, operator_code


def _executor(
    db: _Db,
    stores: dict[str, object],
    *,
    now_monotonic: Callable[[], float] = lambda: 0.0,
) -> ErasureExecutor:
    return ErasureExecutor(
        db,
        manifest=cast(Any, _MANIFEST),
        owner="offline-e3",
        lease_seconds=90,
        heartbeat_seconds=20,
        batch_size=10,
        external_timeout_seconds=5.0,
        stores=stores,  # type: ignore[arg-type]
        now_monotonic=now_monotonic,
    )


def test_pg_executor_binds_the_heartbeat_timeout_on_global_and_project_transactions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A crashed blocked query cannot retain a request lock past its lease."""

    global_calls: list[tuple[str, dict[str, str]]] = []
    project_calls: list[int | None] = []

    class _Connection:
        @contextmanager
        def transaction(self) -> Iterator[_Connection]:
            yield self

        def execute(self, statement: str, params: dict[str, str]) -> None:
            global_calls.append((statement, params))

    class _Pool:
        @contextmanager
        def connection(self) -> Iterator[_Connection]:
            yield _Connection()

    @contextmanager
    def fake_scoped(
        pool: object,
        project_id: object,
        *,
        statement_timeout_ms: int | None = None,
    ) -> Iterator[_Connection]:
        del pool, project_id
        project_calls.append(statement_timeout_ms)
        yield _Connection()

    monkeypatch.setattr(pg_erasure_executor, "scoped", fake_scoped)
    store = PgErasureExecutorStore(cast(Any, _Pool()), statement_timeout_ms=20_000)

    with store._global():
        pass
    with store._project(uuid4()):
        pass

    assert global_calls == [
        (
            pg_erasure_executor._SET_STATEMENT_TIMEOUT_SQL,
            {"statement_timeout_ms": "20000"},
        )
    ]
    assert project_calls == [20_000]


def test_subject_happy_path_is_ordered_and_never_requires_project_trace_absence() -> None:
    db = _Db()
    trace = _SubjectTraceStore()
    generic = _Store()
    outcome = _executor(
        db,
        {"trace_fs_v1": trace, "valkey_v1": generic, "vector_none": generic, "graph_none": generic},
    ).run_next()
    assert outcome is not None and outcome.phase == "scope_complete"
    assert db.failures == []
    assert db.closes == list(_MANIFEST)
    assert len(db.marks) == 4
    assert trace.io == ["validate", "erase_run", "verify_run"]


def test_blocking_configuration_writes_exactly_one_fixed_failure_receipt() -> None:
    db = _Db()
    generic = _Store()
    executor = _executor(
        db,
        {"valkey_v1": generic, "vector_none": generic, "graph_none": generic},
    )
    with pytest.raises(ErasureOperatorBlocked):
        executor.run_next()
    assert db.failures == [("trace_store", "blocked", "configuration_mismatch")]


def test_stale_lease_stops_before_any_external_io_or_failure_mutation() -> None:
    class _StaleDb(_Db):
        def crypto_step(self, lease: ErasureLease, owner: str) -> StepOutcome:
            del lease, owner
            raise ErasureLeaseLost()

    db = _StaleDb()
    trace = _Store()
    with pytest.raises(ErasureLeaseLost):
        _executor(
            db,
            {"trace_fs_v1": trace, "valkey_v1": trace, "vector_none": trace, "graph_none": trace},
        ).run_next()
    assert trace.io == []
    assert db.failures == []


def test_trace_manifest_ref_repr_never_exposes_run_or_locator() -> None:
    run_id = uuid4()
    reference = "fs://opaque/trace-locator"
    value = TraceManifestRef(run_id, reference)
    assert str(run_id) not in repr(value)
    assert reference not in repr(value)


def test_restart_after_all_external_checkpoints_skips_conflicting_reclose_and_finalizes() -> None:
    """A crash after ``external_purged`` resumes from durable checkpoints.

    The replacement worker can still reseal/zero-check the primary state, but
    it must not attempt to recreate an aggregate digest from no work rows.
    """

    db = _Db(phase="external_purged")
    trace = _Store()
    generic = _Store()
    outcome = _executor(
        db,
        {"trace_fs_v1": trace, "valkey_v1": generic, "vector_none": generic, "graph_none": generic},
    ).run_next()
    assert outcome is not None and outcome.phase == "scope_complete"
    assert db.closes == []
    assert trace.io == ["validate"]
    assert generic.io == []


def test_p0014_schedules_a_closure_changed_receipt_then_repasses_on_the_next_claim() -> None:
    class _ClosureChangesOnceDb(_Db):
        def __init__(self) -> None:
            super().__init__()
            self.prepare_calls = 0

        def trace_refs_batch(
            self,
            lease: ErasureLease,
            owner: str,
            revision: int,
            after_run_id: UUID | None,
            after_payload_ref: str | None,
            limit: int,
        ) -> tuple[TraceManifestRef, ...]:
            del lease, owner, revision, after_payload_ref, limit
            return (TraceManifestRef(self.run_id, "fs://opaque"),) if after_run_id is None else ()

        def prepare_primary(self, lease: ErasureLease, owner: str) -> StepOutcome:
            self.prepare_calls += 1
            if self.prepare_calls == 1:
                raise ErasureClosureChanged()
            return super().prepare_primary(lease, owner)

    class _P0014:
        sqlstate = "P0014"

    with pytest.raises(ErasureClosureChanged):
        PgErasureExecutorStore._raise_database_error(cast(Any, _P0014()))

    db = _ClosureChangesOnceDb()
    trace = _Store()
    generic = _Store()
    executor = _executor(
        db,
        {"trace_fs_v1": trace, "valkey_v1": generic, "vector_none": generic, "graph_none": generic},
    )
    with pytest.raises(ErasureClosureChanged):
        executor.run_next()
    assert db.failures == [("postgres", "retryable", "closure_changed")]

    outcome = executor.run_next()
    assert outcome is not None and outcome.phase == "scope_complete"
    assert db.prepare_calls == 2


def test_timeout_is_a_retryable_fixed_code_and_never_marks_external_work() -> None:
    class _TimeoutStore(_Store):
        def erase_run(
            self, project_id: UUID, run_id: UUID, *, timeout_seconds: float
        ) -> StoreResult:
            del project_id, run_id, timeout_seconds
            raise ErasureDependencyTimeout()

        def erase_project(self, project_id: UUID, *, timeout_seconds: float) -> StoreResult:
            del project_id, timeout_seconds
            raise ErasureDependencyTimeout()

    db = _Db()
    timeout = _TimeoutStore()
    with pytest.raises(ErasureDependencyTimeout):
        _executor(
            db,
            {
                "trace_fs_v1": timeout,
                "valkey_v1": timeout,
                "vector_none": timeout,
                "graph_none": timeout,
            },
        ).run_next()
    assert db.marks == []
    assert db.failures == [("graph", "retryable", "dependency_timeout")]


def test_executor_renews_between_external_erase_and_absence_proof() -> None:
    class _RenewingDb(_Db):
        def __init__(self) -> None:
            super().__init__()
            self.renewals = 0

        def renew(self, lease: ErasureLease, owner: str, lease_seconds: int) -> datetime:
            del lease, owner, lease_seconds
            self.renewals += 1
            return datetime.now(UTC) + timedelta(minutes=1)

    class _ClockAdvancingTrace(_Store):
        def __init__(self, clock: list[float]) -> None:
            super().__init__()
            self._clock = clock

        def erase_run(
            self, project_id: UUID, run_id: UUID, *, timeout_seconds: float
        ) -> StoreResult:
            result = super().erase_run(project_id, run_id, timeout_seconds=timeout_seconds)
            self._clock[0] = 21.0
            return result

    clock = [0.0]
    db = _RenewingDb()
    trace = _ClockAdvancingTrace(clock)
    generic = _Store()
    outcome = _executor(
        db,
        {"trace_fs_v1": trace, "valkey_v1": generic, "vector_none": generic, "graph_none": generic},
        now_monotonic=lambda: clock[0],
    ).run_next()
    assert outcome is not None and outcome.phase == "scope_complete"
    assert db.renewals >= 1
