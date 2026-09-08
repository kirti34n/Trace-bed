"""Coordinator routing and lease-fence behavior without database plaintext fixtures."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from threading import Event
from uuid import UUID, uuid4

import pytest

from tracebed.domain.clock import FakeClock
from tracebed.domain.enums import Arm, InstrumentationSource, TraceOutcomeStatus
from tracebed.domain.errors import ConfigError, ProjectInactive
from tracebed.domain.ids import AgentTypeId, PrincipalId, ProjectId, RunId
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
from tracebed.stores.pg.rows import TraceIndexRow
from tracebed.workers.tier_a_lane import TierAPlan
from tracebed.workers.trace_learning import (
    TIER_A_PIPELINE,
    TIER_A_PIPELINE_VERSION,
    TraceLearningLease,
    TraceLearningState,
)
from tracebed.workers.trace_learning_coordinator import (
    TraceLearningCoordinator,
    TraceLearningRunner,
)

pytestmark = pytest.mark.phase2

_NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _lease(project_id: ProjectId | None = None) -> TraceLearningLease:
    return TraceLearningLease(
        project_id=project_id or ProjectId(uuid4()),
        run_id=RunId(uuid4()),
        pipeline=TIER_A_PIPELINE,
        pipeline_version=TIER_A_PIPELINE_VERSION,
        lease_token=UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        lease_owner="coordinator-test",
        attempts=1,
        max_attempts=3,
        lease_expires_at=_NOW + timedelta(minutes=1),
        trace_ended_at=_NOW,
        trace_digest=None,
    )


def _archive(lease: TraceLearningLease) -> ArchivedTrace:
    return ArchivedTrace(
        index=TraceIndexRow(
            project_id=lease.project_id,
            run_id=lease.run_id,
            agent_type_id=AgentTypeId(uuid4()),
            workflow_template_id=None,
            submitter_principal=PrincipalId(uuid4()),
            input_signature_hash=b"x" * 32,
            instrumentation_source=InstrumentationSource.SDK,
            arm=Arm.MEMORY_ON,
            path={
                "end_seq": 0,
                "end_status": "ok",
                "seq_ranges": [[0, 0]],
                "payload_refs": ["fs://x"],
            },
            started_at=_NOW,
            ended_at=lease.trace_ended_at,
            payload_ref="fs://x",
            outcome_status=TraceOutcomeStatus.OK,
        ),
        events=(),
        trace_digest=b"d" * 32,
        subject_key_bindings=(),
    )


@dataclass
class _Jobs:
    leases: list[TraceLearningLease]
    renew_results: list[TraceLearningLease | Exception | None] = field(default_factory=list)
    claims: list[tuple[ProjectId, str, int, str, int]] = field(default_factory=list)
    retries: list[tuple[str, bytes | None]] = field(default_factory=list)
    renew_calls: int = 0
    renewal_started: Event = field(default_factory=Event)

    def claim(
        self, project_id: ProjectId, pipeline: str, version: int, owner: str, limit: int
    ) -> list[TraceLearningLease]:
        self.claims.append((project_id, pipeline, version, owner, limit))
        leases, self.leases = self.leases, []
        return leases

    def renew(self, lease: TraceLearningLease) -> TraceLearningLease | None:
        self.renew_calls += 1
        self.renewal_started.set()
        result = self.renew_results.pop(0) if self.renew_results else lease
        if isinstance(result, Exception):
            raise result
        return result

    def retry(
        self,
        lease: TraceLearningLease,
        _backoff: timedelta,
        code: str,
        digest: bytes | None = None,
    ) -> TraceLearningState:
        assert lease.pipeline == TIER_A_PIPELINE
        self.retries.append((code, digest))
        return TraceLearningState.RETRY


@dataclass
class _Reader:
    result: ArchivedTrace | TraceArchiveReadError | Exception
    calls: list[tuple[ProjectId, RunId, bytes | None, datetime]] = field(default_factory=list)
    wait_for_renewal: Event | None = None

    def read_complete(
        self,
        project_id: ProjectId,
        run_id: RunId,
        *,
        expected_digest: bytes | None,
        expected_ended_at: datetime,
    ) -> ArchivedTrace:
        self.calls.append((project_id, run_id, expected_digest, expected_ended_at))
        if self.wait_for_renewal is not None:
            assert self.wait_for_renewal.wait(timeout=2), "heartbeat did not renew"
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


@dataclass
class _Config:
    result: object | Exception = field(default_factory=object)
    calls: list[tuple[ProjectId, AgentTypeId]] = field(default_factory=list)

    def effective(self, project_id: ProjectId, agent_type_id: AgentTypeId | None = None) -> object:
        assert agent_type_id is not None
        self.calls.append((project_id, agent_type_id))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


@dataclass
class _Lane:
    plan_result: TierAPlan | Exception = field(
        default_factory=lambda: TierAPlan(candidates=(), rejections=(), outcomes=())
    )
    calls: list[tuple[object, object]] = field(default_factory=list)

    def plan(self, scope: object, traces: object) -> TierAPlan:
        self.calls.append((scope, traces))
        if isinstance(self.plan_result, Exception):
            raise self.plan_result
        return self.plan_result


@dataclass
class _Finalizer:
    success: list[object] = field(default_factory=list)
    skipped: list[tuple[str, bytes]] = field(default_factory=list)
    dead: list[tuple[str, bytes | None]] = field(default_factory=list)
    success_result: TraceLearningState | Exception | None = TraceLearningState.SUCCEEDED
    skip_result: TraceLearningState | Exception | None = TraceLearningState.SKIPPED
    dead_result: TraceLearningState | Exception | None = TraceLearningState.DEAD

    def finalize_success(
        self, lease: TraceLearningLease, archived: ArchivedTrace, prepared: object
    ) -> TraceLearningState | None:
        self.success.append((lease, archived, prepared))
        if isinstance(self.success_result, Exception):
            raise self.success_result
        return self.success_result

    def finalize_skip(
        self, _lease: TraceLearningLease, digest: bytes, code: str
    ) -> TraceLearningState | None:
        self.skipped.append((code, digest))
        if isinstance(self.skip_result, Exception):
            raise self.skip_result
        return self.skip_result

    def finalize_dead(
        self, _lease: TraceLearningLease, code: str, digest: bytes | None = None
    ) -> TraceLearningState | None:
        self.dead.append((code, digest))
        if isinstance(self.dead_result, Exception):
            raise self.dead_result
        return self.dead_result


def _coordinator(
    jobs: _Jobs,
    reader: _Reader,
    finalizer: _Finalizer,
    *,
    config: _Config | None = None,
    lane: _Lane | None = None,
    lane_factory: Callable[[object, FakeClock], _Lane] | None = None,
) -> TraceLearningCoordinator:
    config = config or _Config()
    lane = lane or _Lane()
    return TraceLearningCoordinator(
        jobs=jobs,
        reader=reader,
        config=config,  # type: ignore[arg-type]
        lane_factory=lane_factory or (lambda _cfg, _clock: lane),  # type: ignore[arg-type]
        finalizer=finalizer,
        clock=FakeClock(_NOW),
        owner="coordinator-test",
        lease_seconds=1,
    )


def test_success_claims_exact_v1_resolves_config_per_archive_and_passes_overflow() -> None:
    lease = _lease()
    jobs = _Jobs([lease], [lease])
    archive = _archive(lease)
    reader = _Reader(archive)
    config = _Config(result="effective-a")
    constructed: list[object] = []
    lane = _Lane()
    finalizer = _Finalizer()

    coordinator = _coordinator(
        jobs,
        reader,
        finalizer,
        config=config,
        lane_factory=lambda effective, _clock: (constructed.append(effective) or lane),
    )

    assert coordinator.run_project_once(lease.project_id) == 1
    assert jobs.claims == [(lease.project_id, "tier_a", 1, "coordinator-test", 1)]
    assert reader.calls == [(lease.project_id, lease.run_id, None, lease.trace_ended_at)]
    assert config.calls == [(archive.index.project_id, archive.index.agent_type_id)]
    assert constructed == ["effective-a"]
    assert len(finalizer.success) == 1
    assert finalizer.dead == finalizer.skipped == []


def test_inactive_project_is_skipped_without_terminating_the_trace_learning_loop() -> None:
    lease = _lease()
    jobs = _Jobs([lease])
    coordinator = _coordinator(jobs, _Reader(_archive(lease)), _Finalizer())

    class _InactiveActivity:
        def shared(self, _project_id: ProjectId) -> None:
            raise ProjectInactive()

    coordinator.activity = _InactiveActivity()  # type: ignore[assignment]

    assert coordinator.run_project_once(lease.project_id) == 0
    assert jobs.claims == []


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (TraceArchiveReadError(TraceArchiveDisposition.RETRY, TRACE_UNAVAILABLE), "retry"),
        (
            TraceArchiveReadError(
                TraceArchiveDisposition.PRIVACY_SKIP,
                PRIVACY_TOMBSTONED,
                observed_digest=b"p" * 32,
            ),
            "skip",
        ),
        (
            TraceArchiveReadError(
                TraceArchiveDisposition.DEAD, ARCHIVE_INVALID, observed_digest=b"x" * 32
            ),
            "dead",
        ),
        (
            TraceArchiveReadError(
                TraceArchiveDisposition.DEAD,
                ARCHIVE_AUTH_FAILED,
                observed_digest=b"x" * 32,
            ),
            "dead",
        ),
        (
            TraceArchiveReadError(
                TraceArchiveDisposition.DEAD,
                ARCHIVE_DIGEST_MISMATCH,
                observed_digest=b"x" * 32,
            ),
            "dead",
        ),
    ],
)
def test_reader_closed_disposition_matrix(error: TraceArchiveReadError, expected: str) -> None:
    lease = _lease()
    jobs = _Jobs([lease], [lease])
    finalizer = _Finalizer()

    _coordinator(jobs, _Reader(error), finalizer).run_project_once(lease.project_id)

    if expected == "retry":
        assert jobs.retries == [(TRACE_UNAVAILABLE, error.observed_digest)]
        assert finalizer.dead == finalizer.skipped == []
    elif expected == "skip":
        assert finalizer.skipped == [(PRIVACY_TOMBSTONED, b"p" * 32)]
        assert jobs.retries == finalizer.dead == []
    else:
        assert finalizer.dead == [(error.code, b"x" * 32)]
        assert jobs.retries == finalizer.skipped == []


@pytest.mark.parametrize(
    "error",
    [
        TraceArchiveReadError(TraceArchiveDisposition.RETRY, ARCHIVE_INVALID),
        TraceArchiveReadError(TraceArchiveDisposition.PRIVACY_SKIP, PRIVACY_TOMBSTONED),
        TraceArchiveReadError(TraceArchiveDisposition.DEAD, "unexpected"),
    ],
)
def test_malformed_reader_disposition_propagates_without_mutation(error: TraceArchiveReadError) -> None:
    lease = _lease()
    jobs = _Jobs([lease], [lease])
    finalizer = _Finalizer()

    with pytest.raises(ValueError, match="archive disposition"):
        _coordinator(jobs, _Reader(error), finalizer).run_project_once(lease.project_id)

    assert jobs.retries == finalizer.dead == finalizer.skipped == []
    assert jobs.renew_calls == 0


def test_config_and_planner_expected_errors_become_closed_dead_codes() -> None:
    lease = _lease()
    config_finalizer = _Finalizer()
    _coordinator(
        _Jobs([lease], [lease]),
        _Reader(_archive(lease)),
        config_finalizer,
        config=_Config(ConfigError("bad override")),
    ).run_project_once(lease.project_id)
    assert config_finalizer.dead == [("config_invalid", b"d" * 32)]

    planner_lease = _lease()
    planner_finalizer = _Finalizer()
    _coordinator(
        _Jobs([planner_lease], [planner_lease]),
        _Reader(_archive(planner_lease)),
        planner_finalizer,
        lane=_Lane(ValueError("bad extractor input")),
    ).run_project_once(planner_lease.project_id)
    assert planner_finalizer.dead == [("extractor_failure", b"d" * 32)]


@pytest.mark.parametrize(
    "source",
    ["reader", "config", "planner", "finalizer"],
)
def test_unexpected_failures_propagate_without_reclassification(source: str) -> None:
    lease = _lease()
    jobs = _Jobs([lease], [lease])
    finalizer = _Finalizer()
    reader = _Reader(_archive(lease))
    config = _Config()
    lane = _Lane()
    if source == "reader":
        reader.result = RuntimeError("reader infrastructure")
    elif source == "config":
        config.result = RuntimeError("config infrastructure")
    elif source == "planner":
        lane.plan_result = RuntimeError("planner bug")
    else:
        finalizer.success_result = RuntimeError("finalizer infrastructure")

    with pytest.raises(RuntimeError):
        _coordinator(jobs, reader, finalizer, config=config, lane=lane).run_project_once(
            lease.project_id
        )

    if source != "finalizer":
        assert finalizer.dead == []


@pytest.mark.parametrize(
    ("method", "result"),
    [
        ("success", TraceLearningState.DEAD),
        ("skip", TraceLearningState.SUCCEEDED),
        ("dead", TraceLearningState.RETRY),
    ],
)
def test_invalid_terminal_state_propagates(method: str, result: TraceLearningState) -> None:
    lease = _lease()
    finalizer = _Finalizer()
    setattr(finalizer, f"{method}_result", result)
    if method == "success":
        reader: _Reader = _Reader(_archive(lease))
    elif method == "skip":
        reader = _Reader(
            TraceArchiveReadError(
                TraceArchiveDisposition.PRIVACY_SKIP,
                PRIVACY_TOMBSTONED,
                observed_digest=b"p" * 32,
            )
        )
    else:
        reader = _Reader(TraceArchiveReadError(TraceArchiveDisposition.DEAD, ARCHIVE_INVALID))

    with pytest.raises(RuntimeError, match="finalizer returned"):
        _coordinator(_Jobs([lease], [lease]), reader, finalizer).run_project_once(lease.project_id)


def test_none_finalizer_result_is_a_stale_discard() -> None:
    lease = _lease()
    finalizer = _Finalizer(success_result=None)
    _coordinator(_Jobs([lease], [lease]), _Reader(_archive(lease)), finalizer).run_project_once(
        lease.project_id
    )
    assert len(finalizer.success) == 1


def test_success_finalizer_may_report_privacy_skip_when_erasure_wins() -> None:
    lease = _lease()
    finalizer = _Finalizer(success_result=TraceLearningState.SKIPPED)
    _coordinator(_Jobs([lease], [lease]), _Reader(_archive(lease)), finalizer).run_project_once(
        lease.project_id
    )
    assert len(finalizer.success) == 1


def test_coordinator_resolves_background_heartbeat_error_with_one_foreground_fence() -> None:
    lease = _lease()
    jobs = _Jobs([lease], [RuntimeError("temporary heartbeat"), lease])
    finalizer = _Finalizer()
    reader = _Reader(_archive(lease), wait_for_renewal=jobs.renewal_started)

    _coordinator(jobs, reader, finalizer).run_project_once(lease.project_id)

    # The reader's event barrier makes the first result the background
    # heartbeat exception.  The coordinator then performs one, and only one,
    # foreground fence before finalizing.
    assert jobs.renew_calls == 2
    assert len(finalizer.success) == 1


def test_coordinator_discards_on_background_lease_loss_without_a_foreground_fence() -> None:
    lease = _lease()
    jobs = _Jobs([lease], [None])
    finalizer = _Finalizer()
    reader = _Reader(_archive(lease), wait_for_renewal=jobs.renewal_started)

    _coordinator(jobs, reader, finalizer).run_project_once(lease.project_id)

    assert jobs.renew_calls == 1
    assert finalizer.success == finalizer.dead == finalizer.skipped == []
    assert jobs.retries == []


@pytest.mark.parametrize(
    "route",
    ["success", "reader-retry", "reader-skip", "reader-dead", "config", "extractor"],
)
def test_final_fence_loss_per_route_performs_no_terminal_or_retry_write(route: str) -> None:
    lease = _lease()
    finalizer = _Finalizer()
    jobs = _Jobs([lease], [None])
    reader: _Reader = _Reader(_archive(lease))
    config: _Config | None = None
    lane: _Lane | None = None
    if route == "reader-retry":
        reader = _Reader(TraceArchiveReadError(TraceArchiveDisposition.RETRY, TRACE_UNAVAILABLE))
    elif route == "reader-skip":
        reader = _Reader(
            TraceArchiveReadError(
                TraceArchiveDisposition.PRIVACY_SKIP,
                PRIVACY_TOMBSTONED,
                observed_digest=b"p" * 32,
            )
        )
    elif route == "reader-dead":
        reader = _Reader(TraceArchiveReadError(TraceArchiveDisposition.DEAD, ARCHIVE_INVALID))
    elif route == "config":
        config = _Config(ConfigError("invalid config"))
    elif route == "extractor":
        lane = _Lane(ValueError("invalid extractor input"))

    _coordinator(jobs, reader, finalizer, config=config, lane=lane).run_project_once(
        lease.project_id
    )

    assert jobs.renew_calls == 1
    assert jobs.retries == []
    assert finalizer.success == finalizer.dead == finalizer.skipped == []


def test_lost_final_fence_discards_and_final_renew_exception_propagates() -> None:
    lost = _lease()
    lost_finalizer = _Finalizer()
    _coordinator(_Jobs([lost], [None]), _Reader(_archive(lost)), lost_finalizer).run_project_once(
        lost.project_id
    )
    assert lost_finalizer.success == []

    broken = _lease()
    with pytest.raises(RuntimeError, match="renew failed"):
        _coordinator(
            _Jobs([broken], [RuntimeError("renew failed")]),
            _Reader(_archive(broken)),
            _Finalizer(),
        ).run_project_once(broken.project_id)


def test_constructor_rejects_unsafe_owner_and_zero_second_lease() -> None:
    lease = _lease()
    with pytest.raises(ValueError, match="at least one"):
        TraceLearningCoordinator(
            jobs=_Jobs([]),
            reader=_Reader(_archive(lease)),
            config=_Config(),  # type: ignore[arg-type]
            lane_factory=lambda _cfg, _clock: _Lane(),  # type: ignore[arg-type]
            finalizer=_Finalizer(),
            clock=FakeClock(_NOW),
            owner="coordinator-test",
            lease_seconds=0,
        )
    with pytest.raises(ValueError, match="unsafe"):
        _coordinator(_Jobs([]), _Reader(_archive(lease)), _Finalizer()).__class__(
            jobs=_Jobs([]),
            reader=_Reader(_archive(lease)),
            config=_Config(),  # type: ignore[arg-type]
            lane_factory=lambda _cfg, _clock: _Lane(),  # type: ignore[arg-type]
            finalizer=_Finalizer(),
            clock=FakeClock(_NOW),
            owner="bad owner",
            lease_seconds=1,
        )


@dataclass
class _CountingCoordinator:
    results: dict[ProjectId, int]
    calls: list[ProjectId] = field(default_factory=list)
    stop_after: Event | None = None

    def run_project_once(self, project_id: ProjectId) -> int:
        self.calls.append(project_id)
        if self.stop_after is not None and len(self.calls) >= 3:
            self.stop_after.set()
        return self.results[project_id]


def test_runner_reenumerates_sorts_and_stops_between_projects() -> None:
    a, b = ProjectId(UUID("00000000-0000-0000-0000-000000000001")), ProjectId(
        UUID("00000000-0000-0000-0000-000000000002")
    )
    snapshots: list[Sequence[ProjectId]] = [(b, a), (a,)]
    coordinator = _CountingCoordinator({a: 1, b: 0})
    runner = TraceLearningRunner(
        coordinator=coordinator,  # type: ignore[arg-type]
        list_project_ids=lambda: snapshots.pop(0),
        poll_interval=timedelta(0),
    )
    assert runner.run_once() == 1
    assert runner.run_once() == 1
    assert coordinator.calls == [a, b, a]

    stop = Event()
    coordinator = _CountingCoordinator({a: 1, b: 1}, stop_after=stop)
    dynamic = TraceLearningRunner(
        coordinator=coordinator,  # type: ignore[arg-type]
        list_project_ids=lambda: (b, a),
        poll_interval=timedelta(days=1),
    )
    dynamic.run_forever(stop)
    # First sweep has work, so no idle wait; the second fresh sweep sees the
    # stop only between project calls.
    assert coordinator.calls == [a, b, a]


def test_runner_waits_only_when_idle_and_propagates_errors() -> None:
    class _Stop:
        def __init__(self) -> None:
            self._set = False
            self.waits: list[float] = []

        def is_set(self) -> bool:
            return self._set

        def wait(self, seconds: float) -> bool:
            self.waits.append(seconds)
            self._set = True
            return True

    class _Boom:
        def run_project_once(self, _project_id: ProjectId) -> int:
            raise RuntimeError("project failure")

    stop = _Stop()
    idle = TraceLearningRunner(
        coordinator=_CountingCoordinator({}),  # type: ignore[arg-type]
        list_project_ids=lambda: (),
        poll_interval=timedelta(seconds=7),
    )
    idle.run_forever(stop)  # type: ignore[arg-type]
    assert stop.waits == [7]

    with pytest.raises(RuntimeError, match="project failure"):
        TraceLearningRunner(
            coordinator=_Boom(),  # type: ignore[arg-type]
            list_project_ids=lambda: (_lease().project_id,),
            poll_interval=timedelta(0),
        ).run_once()


def test_runner_max_iterations_is_a_deterministic_test_seam() -> None:
    project = _lease().project_id
    coordinator = _CountingCoordinator({project: 1})
    runner = TraceLearningRunner(
        coordinator=coordinator,  # type: ignore[arg-type]
        list_project_ids=lambda: (project,),
        poll_interval=timedelta(0),
    )
    runner.run_forever(Event(), max_iterations=2)
    assert coordinator.calls == [project, project]
    with pytest.raises(ValueError, match="at least one"):
        runner.run_forever(Event(), max_iterations=0)
