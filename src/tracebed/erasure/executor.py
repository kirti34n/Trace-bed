"""Crash-safe coordinator for the separately credentialed E3 erasure saga.

It deliberately contains no SQL and no normal-worker imports.  PostgreSQL
owns the authoritative state transitions/receipts; this coordinator only
orders short database calls around idempotent delete+verify adapter calls.
"""

from __future__ import annotations

import hashlib
import inspect
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, Protocol, cast
from uuid import UUID

from tracebed.domain.errors import (
    ErasureClosureChanged,
    ErasureDependencyTimeout,
    ErasureLeaseLost,
    ErasureOperatorBlocked,
    TracebedError,
)
from tracebed.erasure.domain import (
    ErasureLease,
    ErasureResultCode,
    ExternalStoreCode,
    ExternalWork,
    StepOutcome,
    StoreResult,
)
from tracebed.erasure.ports import ExternalErasurePort, TraceErasurePort

__all__ = ["ErasureExecutor", "ErasureStatus", "TraceManifestRef"]


@dataclass(frozen=True, slots=True)
class TraceManifestRef:
    """A database-derived trace ref; never rendered by the coordinator."""

    run_id: UUID = field(repr=False)
    payload_ref: str = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.run_id) is not UUID or type(self.payload_ref) is not str:
            raise TypeError("trace manifest ref is invalid")


@dataclass(frozen=True, slots=True)
class _PrimaryBatch:
    code: str
    affected_rows: int
    remaining: int
    closure_revision: int
    postcondition_digest: bytes

    def __post_init__(self) -> None:
        if (
            type(self.code) is not str
            or type(self.affected_rows) is not int
            or type(self.remaining) is not int
            or self.affected_rows < 0
            or self.remaining < 0
            or type(self.closure_revision) is not int
            or self.closure_revision < 1
            or type(self.postcondition_digest) is not bytes
            or len(self.postcondition_digest) != 32
        ):
            raise ValueError("primary batch result is invalid")


@dataclass(frozen=True, slots=True)
class ErasureStatus:
    """Bounded operator/CLI projection; it intentionally excludes locators."""

    request_id: UUID
    scope: Literal["subject", "project"]
    phase: str
    disposition: str
    generation: int
    retry_not_before: datetime | None
    last_code: str | None
    closure_revision: int
    pending_work: int
    verified_stores: int
    total_stores: int


class ErasureDatabasePort(Protocol):
    """The sole database boundary the coordinator needs.

    Methods return only strongly bounded values.  An implementation must map
    uncontrolled database/provider errors to opaque typed failures; it must
    never surface a raw SQL string, row or target through this port.
    """

    def claim_next(
        self, owner: str, lease_seconds: int, manifest: tuple[ExternalStoreCode, ...]
    ) -> ErasureLease | None: ...

    def claim_request(
        self,
        request_id: UUID,
        owner: str,
        lease_seconds: int,
        manifest: tuple[ExternalStoreCode, ...],
    ) -> ErasureLease | None: ...

    def renew(self, lease: ErasureLease, owner: str, lease_seconds: int) -> datetime: ...

    def crypto_step(self, lease: ErasureLease, owner: str) -> StepOutcome: ...

    def trace_refs_batch(
        self,
        lease: ErasureLease,
        owner: str,
        revision: int,
        after_run_id: UUID | None,
        after_payload_ref: str | None,
        limit: int,
    ) -> tuple[TraceManifestRef, ...]: ...

    def seal_trace_manifest(
        self, lease: ErasureLease, owner: str, revision: int, count: int, digest: bytes
    ) -> None: ...

    def prepare_primary(self, lease: ErasureLease, owner: str) -> StepOutcome: ...

    def primary_batch(self, lease: ErasureLease, owner: str, batch_size: int) -> _PrimaryBatch: ...

    def external_work_batch(
        self, lease: ErasureLease, owner: str, store_code: ExternalStoreCode, limit: int
    ) -> tuple[ExternalWork, ...]: ...

    def mark_external_work(
        self,
        lease: ErasureLease,
        owner: str,
        work: ExternalWork,
        result: StoreResult,
    ) -> None: ...

    def close_external_step(
        self,
        lease: ErasureLease,
        owner: str,
        store_code: ExternalStoreCode,
        target_count: int,
        result: StoreResult,
    ) -> StepOutcome: ...

    def verify_and_complete(self, lease: ErasureLease, owner: str) -> StepOutcome: ...

    def fail(
        self,
        lease: ErasureLease,
        owner: str,
        step: str,
        result: Literal["retryable", "blocked"],
        result_code: ErasureResultCode,
        affected_rows: int = 0,
        postcondition_digest: bytes | None = None,
    ) -> None: ...

    def release(self, lease: ErasureLease, owner: str) -> None: ...

    def inspect(self, request_id: UUID) -> ErasureStatus | None: ...

    def resume_blocked(self, request_id: UUID, operator_code: str) -> None: ...


class _Blocked(ErasureOperatorBlocked):
    """Internal fixed-code block signal; never rendered or logged."""

    def __init__(self, result_code: ErasureResultCode) -> None:
        self.result_code = result_code


class _Heartbeat:
    """Centralizes the no-I/O-after-lease-loss rule."""

    def __init__(
        self,
        db: ErasureDatabasePort,
        lease: ErasureLease,
        owner: str,
        lease_seconds: int,
        now: Callable[[], float],
        interval_seconds: float,
    ) -> None:
        self._db = db
        self._lease = lease
        self._owner = owner
        self._lease_seconds = lease_seconds
        self._now = now
        self._interval = interval_seconds
        self._next = now() + interval_seconds

    def before_side_effect(self) -> None:
        if self._now() < self._next:
            return
        try:
            self._db.renew(self._lease, self._owner, self._lease_seconds)
        except ErasureLeaseLost:
            raise
        except TracebedError as exc:
            # A dependency failure does not license blind deletion.  Treat the
            # lease as lost for this process; expiry/takeover is safe.
            raise ErasureLeaseLost() from exc
        self._next = self._now() + self._interval


class ErasureExecutor:
    """Runs one complete eligible request or a bounded claimed request.

    All durable state changes are database calls.  This class never commits a
    ``verified`` state itself and never treats a delete call as evidence: every
    target is independently checked before it can be marked.
    """

    def __init__(
        self,
        db: ErasureDatabasePort,
        *,
        manifest: tuple[ExternalStoreCode, ...],
        owner: str,
        lease_seconds: int,
        heartbeat_seconds: int,
        batch_size: int,
        external_timeout_seconds: float,
        stores: Mapping[ExternalStoreCode, object],
        now_monotonic: Callable[[], float],
    ) -> None:
        if type(owner) is not str or not owner or len(owner) > 96:
            raise ValueError("erasure owner is invalid")
        if lease_seconds < 30 or lease_seconds > 900 or 3 * heartbeat_seconds >= lease_seconds:
            raise ValueError("erasure lease/heartbeat configuration is invalid")
        if (
            batch_size < 1
            or external_timeout_seconds <= 0
            or external_timeout_seconds >= heartbeat_seconds
        ):
            raise ValueError("erasure execution configuration is invalid")
        self._db = db
        self._manifest = manifest
        self._owner = owner
        self._lease_seconds = lease_seconds
        self._heartbeat_seconds = heartbeat_seconds
        self._batch_size = batch_size
        self._external_timeout_seconds = external_timeout_seconds
        self._stores = dict(stores)
        self._now = now_monotonic

    def run_next(self) -> StepOutcome | None:
        lease = self._db.claim_next(self._owner, self._lease_seconds, self._manifest)
        if lease is None:
            return None
        return self._run(lease)

    def run_request(self, request_id: UUID) -> StepOutcome | None:
        if type(request_id) is not UUID:
            raise TypeError("request_id must be an exact UUID")
        lease = self._db.claim_request(request_id, self._owner, self._lease_seconds, self._manifest)
        if lease is None:
            return None
        return self._run(lease)

    def cancel(self, lease: ErasureLease) -> None:
        """Best-effort exact-live release; a stale lease is already safe."""

        try:
            self._db.release(lease, self._owner)
        except ErasureLeaseLost:
            return

    def _run(self, lease: ErasureLease) -> StepOutcome:
        heartbeat = _Heartbeat(
            self._db,
            lease,
            self._owner,
            self._lease_seconds,
            self._now,
            self._heartbeat_seconds,
        )
        failure_step = "crypto"
        try:
            if lease.phase == "fenced":
                failure_step = "crypto"
                outcome = self._db.crypto_step(lease, self._owner)
                lease = self._at_revision(lease, outcome.closure_revision, outcome.phase)
            # A certified late bind never regresses the durable phase.  It
            # only advances closure_revision, so re-seal/re-prepare and run a
            # full zero pass for every nonterminal post-crypto phase.  These
            # calls are revision-idempotent when no late bind occurred.
            if lease.phase in {"crypto_erased", "primary_purged", "external_purged"}:
                failure_step = "trace_store"
                self._seal_trace_manifest(lease, heartbeat)
                failure_step = "postgres"
                outcome = self._db.prepare_primary(lease, self._owner)
                lease = self._at_revision(lease, outcome.closure_revision, outcome.phase)
                # ``external_purged`` is a durable checkpointed state, not a
                # hint that we should re-close every store on restart.  A
                # preparation with no current-revision work means a process
                # died after all checkpoints committed and may proceed to
                # the final transaction.  A late closure makes preparation
                # create pending work, which deliberately routes through the
                # complete primary/external pass again without regressing the
                # database phase.
                needs_external = outcome.affected_rows > 0
                prepared_phase = lease.phase
                while True:
                    failure_step = "postgres"
                    heartbeat.before_side_effect()
                    batch = self._db.primary_batch(lease, self._owner, self._batch_size)
                    if batch.remaining == 0:
                        next_phase = (
                            "external_purged"
                            if prepared_phase == "external_purged" and not needs_external
                            else "primary_purged"
                        )
                        lease = self._at_revision(lease, batch.closure_revision, next_phase)
                        break
                    # The DB never regresses phase after a late closure.  In
                    # memory we represent a still-pending primary pass with
                    # primary_purged too, because the only legal next action
                    # is another fixed DB batch, not external I/O.
                    lease = self._at_revision(lease, batch.closure_revision, "primary_purged")
            if lease.phase == "primary_purged":
                for code in self._manifest:
                    failure_step = self._step_for_store(code)
                    heartbeat.before_side_effect()
                    outcome = self._run_external_store(lease, heartbeat, code)
                    lease = self._at_revision(lease, outcome.closure_revision, outcome.phase)
            if lease.phase == "external_purged":
                failure_step = "verify"
                return self._db.verify_and_complete(lease, self._owner)
            if lease.phase == "scope_complete":
                return StepOutcome("scope_complete", 0, lease.closure_revision, "ok")
            # A closure change may turn a previously prepared phase back into
            # an earlier required work phase.  The SQL transition owns that;
            # this coordinator refuses to assume a missing transition means
            # safety and schedules an opaque retry instead.
            self._db.fail(lease, self._owner, failure_step, "retryable", "closure_changed")
            raise ErasureLeaseLost()
        except ErasureLeaseLost:
            # No mark/release attempt after a failed exact lease assertion.
            raise
        except ErasureClosureChanged:
            # P0014 is a fresh authoritative closure, not a malformed store
            # response.  Persist the retry receipt while this lease is live;
            # the next claim restarts the revision-sensitive seal/primary/
            # external pass from durable state.
            self._db.fail(lease, self._owner, failure_step, "retryable", "closure_changed")
            raise
        except ErasureOperatorBlocked as error:
            # The database records a bounded blocked receipt/disposition
            # while the exact lease is still live.  Nested routines only
            # signal; they never write their own failure receipt, preventing
            # a crash/error branch from double-recording the same failure.
            result_code: ErasureResultCode = (
                error.result_code if isinstance(error, _Blocked) else "verification_failed"
            )
            self._db.fail(lease, self._owner, failure_step, "blocked", result_code)
            raise
        except ErasureDependencyTimeout:
            # A timed-out delete may have completed externally.  It is never
            # marked; the next lease holder repeats delete+independent proof.
            self._db.fail(lease, self._owner, failure_step, "retryable", "dependency_timeout")
            raise
        except TracebedError:
            # Adapter/domain errors deliberately carry no opaque provider
            # detail.  Persist only a fixed retry code.
            self._db.fail(lease, self._owner, failure_step, "retryable", "dependency_unavailable")
            raise

    @staticmethod
    def _at_revision(lease: ErasureLease, revision: int, phase: str) -> ErasureLease:
        if phase not in {"crypto_erased", "primary_purged", "external_purged", "scope_complete"}:
            raise ErasureLeaseLost()
        return ErasureLease(
            project_id=lease.project_id,
            request_id=lease.request_id,
            scope=lease.scope,
            phase=phase,  # type: ignore[arg-type]
            generation=lease.generation,
            lease_token=lease.lease_token,
            lease_expires_at=lease.lease_expires_at,
            closure_revision=revision,
        )

    def _seal_trace_manifest(self, lease: ErasureLease, heartbeat: _Heartbeat) -> None:
        trace = self._stores.get("trace_fs_v1") or self._stores.get("trace_s3_v1")
        if trace is None or not callable(getattr(trace, "validate_manifest_ref", None)):
            raise _Blocked("configuration_mismatch")
        port = cast(TraceErasurePort, trace)
        after_run: UUID | None = None
        after_ref: str | None = None
        count = 0
        hasher = hashlib.sha256(b"tracebed.erasure-trace-manifest/v1\x00")
        while True:
            heartbeat.before_side_effect()
            refs = self._db.trace_refs_batch(
                lease, self._owner, lease.closure_revision, after_run, after_ref, self._batch_size
            )
            if not refs:
                break
            for ref in refs:
                heartbeat.before_side_effect()
                try:
                    frame = port.validate_manifest_ref(
                        lease.project_id, ref.run_id, ref.payload_ref
                    )
                except Exception as exc:  # adapter must not leak target/provider content
                    raise _Blocked("unsafe_path") from exc
                if type(frame) is not bytes or len(frame) == 0:
                    raise _Blocked("integrity_failed")
                hasher.update(len(frame).to_bytes(8, "big"))
                hasher.update(frame)
                count += 1
                after_run, after_ref = ref.run_id, ref.payload_ref
            if len(refs) < self._batch_size:
                break
        self._db.seal_trace_manifest(
            lease, self._owner, lease.closure_revision, count, hasher.digest()
        )

    def _run_external_store(
        self, lease: ErasureLease, heartbeat: _Heartbeat, code: ExternalStoreCode
    ) -> StepOutcome:
        port = self._stores.get(code)
        if port is None:
            raise _Blocked("configuration_mismatch")
        total = 0
        aggregate = hashlib.sha256(f"tracebed.erasure-store/v1:{code}".encode()).digest()
        try:
            while True:
                heartbeat.before_side_effect()
                work_batch = self._db.external_work_batch(
                    lease, self._owner, code, self._batch_size
                )
                if not work_batch:
                    break
                for work in work_batch:
                    heartbeat.before_side_effect()
                    result = self._delete_and_verify(port, lease.project_id, work, heartbeat)
                    heartbeat.before_side_effect()
                    self._db.mark_external_work(lease, self._owner, work, result)
                    total += 1
                    aggregate = hashlib.sha256(aggregate + result.postcondition_digest).digest()
            heartbeat.before_side_effect()
            # A close requires a fresh adapter-wide zero proof as well as every
            # marked target.  It intentionally does not reuse a work result.
            if code.startswith("trace_") and lease.scope == "subject":
                # Subject trace erasure proves each entire fenced run prefix
                # independently.  A project-wide absence check would leak or
                # incorrectly require deletion of unrelated subjects.
                close_proof = StoreResult(
                    "ok",
                    0,
                    hashlib.sha256(b"tracebed.erasure-trace-targets/v1" + aggregate).digest(),
                )
            else:
                close_proof = self._verify_project_zero(port, lease.project_id, heartbeat)
            aggregate = hashlib.sha256(aggregate + close_proof.postcondition_digest).digest()
            return self._db.close_external_step(
                lease,
                self._owner,
                code,
                total,
                StoreResult(close_proof.result_code, close_proof.affected_rows, aggregate),
            )
        except ErasureOperatorBlocked:
            raise
        except ErasureLeaseLost:
            raise
        except ErasureDependencyTimeout:
            raise
        except Exception as exc:
            # Provider/library failures have no payload-bearing path through
            # the coordinator.  The outer handler writes only the fixed
            # dependency-unavailable receipt code.
            raise TracebedError() from exc

    @staticmethod
    def _step_for_store(code: ExternalStoreCode) -> str:
        if code == "valkey_v1":
            return "valkey"
        if code.startswith("vector_"):
            return "vector"
        if code.startswith("graph_"):
            return "graph"
        return "trace_store"

    def _call_store(
        self,
        operation: object,
        *args: object,
        heartbeat: _Heartbeat,
    ) -> object:
        """Call an E3 adapter without assuming its optional progress hook.

        E3 adapters accept ``before_page`` and invoke it between bounded
        filesystem/scan/HTTP pages.  Small test doubles and third-party
        deployment adapters written against the original narrow port need
        not implement that optional hook, so detect it without turning a
        genuine adapter ``TypeError`` into a fallback call.
        """

        if not callable(operation):
            raise ErasureOperatorBlocked()
        kwargs: dict[str, object] = {"timeout_seconds": self._external_timeout_seconds}
        try:
            accepts_progress = "before_page" in inspect.signature(operation).parameters
        except (TypeError, ValueError):
            accepts_progress = False
        if accepts_progress:
            kwargs["before_page"] = heartbeat.before_side_effect
        return operation(*args, **kwargs)

    def _delete_and_verify(
        self, port: object, project_id: UUID, work: ExternalWork, heartbeat: _Heartbeat
    ) -> StoreResult:
        if work.target_kind == "run":
            if not hasattr(port, "erase_run") or not hasattr(port, "verify_run_absent"):
                raise ErasureOperatorBlocked()
            assert work.target_id is not None
            external = cast(ExternalErasurePort, port)
            erased = self._call_store(
                external.erase_run, project_id, work.target_id, heartbeat=heartbeat
            )
            if not isinstance(erased, StoreResult):
                raise ErasureOperatorBlocked()
            # A lease may expire during a slow but successful destructive
            # operation.  Do not start its independent proof until the
            # dedicated heartbeat has re-established exact lease ownership.
            heartbeat.before_side_effect()
            result = self._call_store(
                external.verify_run_absent, project_id, work.target_id, heartbeat=heartbeat
            )
            if not isinstance(result, StoreResult):
                raise ErasureOperatorBlocked()
            return result
        if not hasattr(port, "erase_project") or not hasattr(port, "verify_project_absent"):
            raise ErasureOperatorBlocked()
        external = cast(ExternalErasurePort, port)
        erased = self._call_store(external.erase_project, project_id, heartbeat=heartbeat)
        if not isinstance(erased, StoreResult):
            raise ErasureOperatorBlocked()
        heartbeat.before_side_effect()
        result = self._call_store(external.verify_project_absent, project_id, heartbeat=heartbeat)
        if not isinstance(result, StoreResult):
            raise ErasureOperatorBlocked()
        return result

    def _verify_project_zero(
        self, port: object, project_id: UUID, heartbeat: _Heartbeat
    ) -> StoreResult:
        if not hasattr(port, "verify_project_absent"):
            raise ErasureOperatorBlocked()
        external = cast(ExternalErasurePort, port)
        result = self._call_store(external.verify_project_absent, project_id, heartbeat=heartbeat)
        if not isinstance(result, StoreResult):
            raise ErasureOperatorBlocked()
        return result
