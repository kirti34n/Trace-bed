"""The bounded Tier-A/v1 trace-learning control loop.

This module owns orchestration only.  It deliberately resolves project/agent
configuration *after* the strict archive read, constructs a fresh pure lane
for that job, and performs no durable write except through the full-key,
lease-fenced finalizer.  A lost lease is therefore a discard rather than a
partial result.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from threading import Event, Lock, Thread
from typing import Protocol

from tracebed.domain.clock import Clock
from tracebed.domain.config import EffectiveConfig
from tracebed.domain.errors import (
    ActivityBusy,
    ConfigError,
    ErasureFenced,
    ErasureSnapshotStale,
    ProjectInactive,
)
from tracebed.domain.ids import AgentTypeId, ProjectId, RunId, mint_memory_id
from tracebed.domain.scope import ProjectScope
from tracebed.ingest.trace_archive import (
    ARCHIVE_AUTH_FAILED,
    ARCHIVE_DIGEST_MISMATCH,
    ARCHIVE_INVALID,
    PRIVACY_TOMBSTONED,
    TRACE_UNAVAILABLE,
    ArchivedTrace,
    TraceArchiveDisposition,
    TraceArchiveReadError,
)
from tracebed.stores.pg.activity import ActivityGate
from tracebed.stores.pg.erasure import ErasureSnapshotGuard
from tracebed.workers.tier_a_lane import TierALane, TierAPlan
from tracebed.workers.trace_learning import (
    PreparedTierACandidate,
    PreparedTierARejection,
    PreparedTierAResult,
    TraceLearningFinalizerPort,
    TraceLearningJobPort,
    TraceLearningLease,
    TraceLearningState,
    is_safe_owner,
    prepare_tier_a_result,
    validate_digest,
)

__all__ = ["TraceLearningCoordinator", "TraceLearningRunner", "build_tier_a_lane"]


class _ArchiveReader(Protocol):
    def read_complete(
        self,
        project_id: ProjectId,
        run_id: RunId,
        *,
        expected_digest: bytes | None = None,
        expected_ended_at: datetime | None = None,
    ) -> ArchivedTrace: ...


class _ConfigProvider(Protocol):
    def effective(
        self, project_id: ProjectId, agent_type_id: AgentTypeId | None = None
    ) -> EffectiveConfig: ...


_LaneFactory = Callable[[EffectiveConfig, Clock], TierALane]
_TERMINAL_ARCHIVE_CODES = frozenset(
    {ARCHIVE_INVALID, ARCHIVE_AUTH_FAILED, ARCHIVE_DIGEST_MISMATCH}
)


def build_tier_a_lane(config: EffectiveConfig, clock: Clock) -> TierALane:
    """Construct the real pure lane after one job's config resolution."""

    return TierALane(cfg=config, clock=clock)


@dataclass(slots=True)
class _Heartbeat:
    """Renew one lease in the background and publish one terminal snapshot.

    Renewal failures are recorded rather than raised on a background thread.
    The coordinator then performs exactly one foreground final renew after it
    stops the heartbeat; this either resolves a transient failure or raises to
    process supervision.  ``stop`` is deliberately idempotent so exception
    paths cannot perform a second implicit fence.
    """

    jobs: TraceLearningJobPort
    lease: TraceLearningLease
    interval: timedelta
    _stop: Event = field(init=False, repr=False)
    _lock: Lock = field(init=False, repr=False)
    _lost: bool = field(init=False, default=False)
    _error: Exception | None = field(init=False, default=None)
    _stopped: bool = field(init=False, default=False)
    _snapshot: TraceLearningLease | None = field(init=False, default=None)
    _thread: Thread = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._stop = Event()
        self._lock = Lock()
        self._thread = Thread(target=self._run, name="trace-learning-heartbeat", daemon=False)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> TraceLearningLease | None:
        """Stop once and return the last live lease snapshot, if any."""

        with self._lock:
            if self._stopped:
                return self._snapshot
            self._stop.set()
        self._thread.join()
        with self._lock:
            if not self._stopped:
                self._snapshot = None if self._lost else self.lease
                self._stopped = True
            return self._snapshot

    @property
    def renewal_error(self) -> Exception | None:
        with self._lock:
            return self._error

    def _run(self) -> None:
        while not self._stop.wait(self.interval.total_seconds()):
            with self._lock:
                previous = self.lease
            try:
                renewed = self.jobs.renew(previous)
            except Exception as exc:  # surfaced by the foreground final fence
                with self._lock:
                    self._error = exc
                return
            with self._lock:
                if renewed is None:
                    self._lost = True
                    return
                self.lease = renewed


@dataclass(slots=True)
class TraceLearningCoordinator:
    """Claim and complete only the shipped Tier-A/v1 job identity."""

    jobs: TraceLearningJobPort
    reader: _ArchiveReader
    config: _ConfigProvider
    finalizer: TraceLearningFinalizerPort
    clock: Clock
    owner: str
    lease_seconds: int
    lane_factory: _LaneFactory = build_tier_a_lane
    retry_backoff: timedelta = timedelta(seconds=30)
    activity: ActivityGate | None = None
    erasure_guard: ErasureSnapshotGuard | None = None

    def __post_init__(self) -> None:
        if self.lease_seconds < 1:
            raise ValueError("trace-learning lease_seconds must be at least one")
        if not is_safe_owner(self.owner):
            raise ValueError("trace-learning owner is unsafe")
        if self.retry_backoff < timedelta(0):
            raise ValueError("trace-learning retry backoff must not be negative")

    def run_project_once(self, project_id: ProjectId) -> int:
        """Claim at most one job for this project and process it synchronously."""

        from tracebed.workers.trace_learning import TIER_A_PIPELINE, TIER_A_PIPELINE_VERSION

        try:
            if self.activity is None:
                return self._run_project_once(project_id, TIER_A_PIPELINE, TIER_A_PIPELINE_VERSION)
            # Hold the same shared drain from claim through archive read,
            # extraction/model work, final database commit, and the terminal
            # lease decision. The finalizer also repeats the durable snapshot
            # under its own transaction, so releasing this fast lock cannot
            # reopen a fenced lineage.
            with self.activity.shared(project_id):
                return self._run_project_once(project_id, TIER_A_PIPELINE, TIER_A_PIPELINE_VERSION)
        except (ActivityBusy, ProjectInactive):
            # Scheduled work has no caller ACK to NACK. A drain fence is
            # retryable; a suspended/tombstoned project is deliberately
            # skipped.  In both cases no archive or model side effect ran,
            # and one inactive project must not terminate the process-wide
            # worker supervisor.
            return 0

    def _run_project_once(self, project_id: ProjectId, pipeline: str, pipeline_version: int) -> int:
        leases = self.jobs.claim(project_id, pipeline, pipeline_version, self.owner, 1)
        completed = 0
        for lease in leases:
            try:
                if self.erasure_guard is not None:
                    self.erasure_guard.assert_snapshot(
                        lease.project_id, lease.run_id, lease.subject_digests
                    )
                self._process(lease)
                completed += 1
            except (ErasureFenced, ErasureSnapshotStale):
                # The job row is deliberately not terminalized: propagation
                # may have enlarged its durable union, and an eventual worker
                # must reclaim that current row rather than convert staleness
                # into a false dead-letter result.
                continue
        return completed

    def _process(self, initial_lease: TraceLearningLease) -> None:
        heartbeat = _Heartbeat(
            jobs=self.jobs,
            lease=initial_lease,
            interval=timedelta(seconds=self.lease_seconds / 3),
        )
        heartbeat.start()
        archive: ArchivedTrace | None = None
        try:
            try:
                archive = self.reader.read_complete(
                    initial_lease.project_id,
                    initial_lease.run_id,
                    expected_digest=initial_lease.trace_digest,
                    expected_ended_at=initial_lease.trace_ended_at,
                )
            except TraceArchiveReadError as error:
                # A malformed typed reader error is an invariant failure, not
                # a reason to touch a lease or terminalize a job.  Validate it
                # before the final fence so test doubles and future readers
                # cannot smuggle an arbitrary terminal code through this loop.
                self._validate_archive_error(error)
                lease = self._final_lease(heartbeat)
                if lease is not None:
                    self._finish_archive_error(lease, error)
                return

            try:
                effective = self.config.effective(
                    archive.index.project_id, archive.index.agent_type_id
                )
            except ConfigError:
                lease = self._final_lease(heartbeat)
                if lease is not None:
                    self._expect_terminal(
                        self.finalizer.finalize_dead(lease, "config_invalid", archive.trace_digest),
                        TraceLearningState.DEAD,
                    )
                return

            try:
                lane = self.lane_factory(effective, self.clock)
                plan = lane.plan(
                    ProjectScope(
                        project_id=archive.index.project_id,
                        agent_type_id=archive.index.agent_type_id,
                        principal_id=archive.index.submitter_principal,
                    ),
                    {archive.index.run_id: archive.events},
                )
                prepared = self._prepare(initial_lease, archive, plan)
            except (TypeError, ValueError):
                lease = self._final_lease(heartbeat)
                if lease is not None:
                    self._expect_terminal(
                        self.finalizer.finalize_dead(
                            lease, "extractor_failure", archive.trace_digest
                        ),
                        TraceLearningState.DEAD,
                    )
                return

            # No plaintext-derived value crosses a lost final fence.  Stop
            # first so this explicit foreground renew owns the only live lease
            # value.  A heartbeat error is intentionally resolved by this one
            # final renew; it is not swallowed and it is never retried in
            # ``finally``.
            lease = self._final_lease(heartbeat)
            if lease is None:
                return
            self._expect_states(
                self.finalizer.finalize_success(lease, archive, prepared),
                {TraceLearningState.SUCCEEDED, TraceLearningState.SKIPPED},
            )
        finally:
            # ``stop`` is idempotent after ``_final_lease``.  Retaining no
            # archive reference makes an accidental later handler unable to
            # expose plaintext event values.
            heartbeat.stop()
            archive = None

    def _final_lease(self, heartbeat: _Heartbeat) -> TraceLearningLease | None:
        """Take the one final fence; ``None`` always means discard.

        Even after a background renewal exception, the caller gets one fresh
        foreground renew to distinguish a transient heartbeat failure from a
        lost lease.  Any exception from that authoritative operation reaches
        supervision unchanged.
        """

        lease = heartbeat.stop()
        if lease is None:
            return None
        return self.jobs.renew(lease)

    def _finish_archive_error(
        self,
        lease: TraceLearningLease,
        error: TraceArchiveReadError,
    ) -> None:
        """Route only the reader's closed, privacy-safe disposition matrix."""

        if error.disposition is TraceArchiveDisposition.RETRY:
            self._expect_retry(
                self.jobs.retry(lease, self.retry_backoff, TRACE_UNAVAILABLE, error.observed_digest)
            )
            return
        if error.disposition is TraceArchiveDisposition.PRIVACY_SKIP:
            assert error.observed_digest is not None  # checked before fencing
            self._expect_terminal(
                self.finalizer.finalize_skip(lease, error.observed_digest, PRIVACY_TOMBSTONED),
                TraceLearningState.SKIPPED,
            )
            return
        if error.disposition is TraceArchiveDisposition.DEAD:
            self._expect_terminal(
                self.finalizer.finalize_dead(lease, error.code, error.observed_digest),
                TraceLearningState.DEAD,
            )
            return
        raise ValueError("unknown archive disposition")

    @staticmethod
    def _validate_archive_error(error: TraceArchiveReadError) -> None:
        """Reject impossible reader disposition/code/digest combinations pre-fence."""

        validate_digest(error.observed_digest, field="archive observed_digest")
        if error.disposition is TraceArchiveDisposition.RETRY:
            if error.code != TRACE_UNAVAILABLE:
                raise ValueError("invalid retry archive disposition")
            return
        if error.disposition is TraceArchiveDisposition.PRIVACY_SKIP:
            if error.code != PRIVACY_TOMBSTONED or error.observed_digest is None:
                raise ValueError("invalid privacy archive disposition")
            return
        if error.disposition is TraceArchiveDisposition.DEAD:
            if error.code not in _TERMINAL_ARCHIVE_CODES:
                raise ValueError("invalid dead archive disposition")
            if error.code == ARCHIVE_DIGEST_MISMATCH and error.observed_digest is None:
                raise ValueError("digest mismatch requires an observed digest")
            return
        raise ValueError("unknown archive disposition")

    @staticmethod
    def _expect_terminal(result: TraceLearningState | None, expected: TraceLearningState) -> bool:
        if result is None:
            return False
        if result is not expected:
            raise RuntimeError(f"trace-learning finalizer returned {result!r}, expected {expected!r}")
        return True

    @staticmethod
    def _expect_states(
        result: TraceLearningState | None, expected: set[TraceLearningState]
    ) -> bool:
        if result is None:
            return False
        if result not in expected:
            raise RuntimeError(
                f"trace-learning finalizer returned {result!r}, expected one of {expected!r}"
            )
        return True

    @staticmethod
    def _expect_retry(result: TraceLearningState | None) -> bool:
        if result is None:
            return False
        if result not in {TraceLearningState.RETRY, TraceLearningState.DEAD}:
            raise RuntimeError(f"trace-learning retry returned invalid state {result!r}")
        return True

    def _prepare(
        self,
        lease: TraceLearningLease,
        archive: ArchivedTrace,
        plan: TierAPlan,
    ) -> PreparedTierAResult:
        candidates = tuple(
            PreparedTierACandidate(
                # The final transaction may be retried under a replacement
                # lease, but it must never mint IDs *after* it has begun
                # inserting rows.  A prepared item therefore owns one
                # caller-visible, non-null ID before the fence is acquired.
                item=replace(candidate.item, id=mint_memory_id()),
                scan_verdict=candidate.scan_result.verdict(clock=self.clock),
                content_hash=candidate.scan_result.content_hash,
                scan_suite_version=candidate.scan_result.suite_version,
                primary_run_id=candidate.primary_run_id,
                contributing_run_ids=candidate.contributing_run_ids,
            )
            for candidate in plan.candidates
        )
        rejections = tuple(
            PreparedTierARejection(
                content_hash=rejection.content_hash,
                mem_type=rejection.mem_type,
                suite_version=rejection.suite_version,
                reasons=rejection.reasons,
            )
            for rejection in plan.rejections
        )
        return prepare_tier_a_result(
            lease=lease,
            trace_digest=archive.trace_digest,
            candidates=candidates,
            rejections=rejections,
            rejection_overflow=plan.rejection_overflow,
        )


@dataclass(slots=True)
class TraceLearningRunner:
    """Serial dynamic project pull loop; process supervision remains the host's job."""

    coordinator: TraceLearningCoordinator
    list_project_ids: Callable[[], Sequence[ProjectId]]
    poll_interval: timedelta

    def __post_init__(self) -> None:
        if self.poll_interval < timedelta(0):
            raise ValueError("trace-learning poll_interval must not be negative")

    def run_once(self, stop: Event | None = None) -> int:
        """Perform one fresh sorted sweep, stopping between projects only."""

        project_ids = sorted(set(self.list_project_ids()), key=lambda project_id: str(project_id.value))
        claimed = 0
        for project_id in project_ids:
            if stop is not None and stop.is_set():
                break
            claimed += self.coordinator.run_project_once(project_id)
        return claimed

    def run_forever(self, stop: Event, *, max_iterations: int | None = None) -> None:
        """Sweep dynamically; wait only when no project yielded work."""

        if max_iterations is not None and max_iterations < 1:
            raise ValueError("trace-learning max_iterations must be at least one")
        iterations = 0
        while not stop.is_set():
            claimed = self.run_once(stop)
            iterations += 1
            if stop.is_set():
                return
            if max_iterations is not None and iterations >= max_iterations:
                return
            if claimed == 0:
                stop.wait(self.poll_interval.total_seconds())
