"""`workers.gc` -- queue/trace-store maintenance (PLAN.md §7 Phase 2, chunk
`worker-runner`).

Offline throughout: every Protocol (`QueueObservabilityPort`,
`TraceIndexLister`, `DeadLetterReaperPort`, `ExpiredLeasePort`) is satisfied
by a small fake defined in this file, per this codebase's convention that
fakes are per-test-module rather than shared (contract §13.1).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from uuid import uuid4

import pytest

from tracebed.domain.clock import FakeClock
from tracebed.domain.ids import ProjectId, RunId, mint_run_id
from tracebed.stores.pg.rows import TraceIndexRow
from tracebed.stores.tracestore import PayloadRef
from tracebed.workers.gc import (
    expired_lease_counts,
    find_orphaned_trace_payloads,
    queue_health,
    reap_dead_letter,
    run_gc_cycle,
)

# --------------------------------------------------------------------------- #
# Tier 1 fakes: QueueObservabilityPort, TraceIndexLister, TraceStorePort
# --------------------------------------------------------------------------- #


@dataclass
class FakeObservability:
    depths: dict[str, int] = field(default_factory=dict)
    dead_letters: dict[str, int] = field(default_factory=dict)
    ages: dict[str, float | None] = field(default_factory=dict)
    xmin_alarm: bool = False

    def depth(self, topic: str) -> int:
        return self.depths.get(topic, 0)

    def dead_letter_count(self, topic: str) -> int:
        return self.dead_letters.get(topic, 0)

    def oldest_age_s(self, topic: str) -> float | None:
        return self.ages.get(topic)

    def xmin_horizon_alarm(self) -> bool:
        return self.xmin_alarm


def _trace_row(run_id: RunId, payload_ref: str | None, project_id: ProjectId) -> TraceIndexRow:
    from tracebed.domain.enums import Arm, InstrumentationSource, TraceOutcomeStatus
    from tracebed.domain.ids import AgentTypeId, PrincipalId

    return TraceIndexRow(
        project_id=project_id,
        run_id=run_id,
        agent_type_id=AgentTypeId(uuid4()),
        workflow_template_id=None,
        submitter_principal=PrincipalId(uuid4()),
        input_signature_hash=b"\x00" * 40,
        instrumentation_source=InstrumentationSource.SDK,
        arm=Arm.MEMORY_ON,
        path=None,
        started_at=None,
        ended_at=None,
        payload_ref=payload_ref,
        outcome_status=TraceOutcomeStatus.OK,
    )


@dataclass
class FakeTraceLister:
    rows: list[TraceIndexRow]

    def list_runs(self, project_id: ProjectId, *, limit: int = 100) -> list[TraceIndexRow]:
        return self.rows[:limit]


@dataclass
class FakeTraceStore:
    present: set[str]  # PayloadRef.key values that resolve

    def exists(self, project_id: ProjectId, ref: PayloadRef) -> bool:
        return ref.key in self.present

    def put(self, project_id: ProjectId, run_id: RunId, first_seq: int, payload: bytes) -> PayloadRef:  # pragma: no cover - unused
        raise NotImplementedError

    def get(self, project_id: ProjectId, ref: PayloadRef) -> bytes:  # pragma: no cover - unused
        raise NotImplementedError

    def delete_project(self, project_id: ProjectId) -> int:  # pragma: no cover - unused
        raise NotImplementedError


# --------------------------------------------------------------------------- #
# Tier 2 fakes: DeadLetterReaperPort, ExpiredLeasePort
# --------------------------------------------------------------------------- #


@dataclass
class FakeReaper:
    """In-memory dead_letter rows keyed by topic, each with a `failed_at`."""

    rows: dict[str, list[datetime]] = field(default_factory=dict)
    purge_calls: list[tuple[str, datetime]] = field(default_factory=list)

    def purge_dead_letter(self, topic: str, *, older_than: datetime) -> int:
        self.purge_calls.append((topic, older_than))
        before = self.rows.get(topic, [])
        kept = [ts for ts in before if ts >= older_than]
        purged = len(before) - len(kept)
        self.rows[topic] = kept
        return purged


@dataclass
class FakeLeaseCounter:
    counts: dict[str, int] = field(default_factory=dict)

    def count_expired_leases(self, topic: str) -> int:
        return self.counts.get(topic, 0)


# --------------------------------------------------------------------------- #
# queue_health
# --------------------------------------------------------------------------- #


def test_queue_health_reports_raw_stats_per_topic() -> None:
    port = FakeObservability(
        depths={"a": 3, "b": 0},
        dead_letters={"a": 1, "b": 0},
        ages={"a": 5.0, "b": None},
    )
    report = queue_health(port, ["a", "b"], lease_seconds=30)
    by_topic = {s.topic: s for s in report.stats}
    assert by_topic["a"].depth == 3
    assert by_topic["a"].dead_letter_count == 1
    assert by_topic["a"].oldest_age_s == 5.0
    assert by_topic["b"].oldest_age_s is None


def test_queue_health_marks_a_topic_stuck_only_past_one_full_lease_period() -> None:
    """`d` sits at EXACTLY one lease period and must not be stuck: without
    the boundary case, flipping `>` to `>=` passes every other assertion
    here."""
    port = FakeObservability(ages={"a": 29.0, "b": 30.0001, "c": None, "d": 30.0})
    report = queue_health(port, ["a", "b", "c", "d"], lease_seconds=30)
    assert report.stuck_topics == ("b",)


def test_queue_health_rejects_non_positive_lease_seconds() -> None:
    with pytest.raises(ValueError):
        queue_health(FakeObservability(), ["a"], lease_seconds=0)


def test_the_xmin_alarm_fires_past_threshold_and_is_surfaced_verbatim() -> None:
    """`queue_health` does not recompute the xmin-horizon threshold itself
    (that constant lives in `stores.pg.queue`); it only surfaces whatever
    `port.xmin_horizon_alarm()` -- which owns the real threshold check --
    already decided."""
    calm = queue_health(FakeObservability(xmin_alarm=False), [], lease_seconds=30)
    assert calm.xmin_horizon_alarm is False

    alarming = queue_health(FakeObservability(xmin_alarm=True), [], lease_seconds=30)
    assert alarming.xmin_horizon_alarm is True


# --------------------------------------------------------------------------- #
# find_orphaned_trace_payloads
# --------------------------------------------------------------------------- #


def test_find_orphaned_trace_payloads_flags_rows_whose_object_is_missing() -> None:
    project = ProjectId(uuid4())
    present_run = mint_run_id()
    missing_run = mint_run_id()
    no_payload_run = mint_run_id()

    present_ref = PayloadRef(driver="fs", key=f"{project.value}/present/00000000.tbz")
    missing_ref = PayloadRef(driver="fs", key=f"{project.value}/missing/00000000.tbz")

    repo = FakeTraceLister(
        rows=[
            _trace_row(present_run, str(present_ref), project),
            _trace_row(missing_run, str(missing_ref), project),
            _trace_row(no_payload_run, None, project),
        ]
    )
    store = FakeTraceStore(present={present_ref.key})

    orphans = find_orphaned_trace_payloads(repo, store, project)

    assert len(orphans) == 1
    assert orphans[0].run_id == missing_run
    assert orphans[0].payload_ref == str(missing_ref)


def test_find_orphaned_trace_payloads_refuses_a_row_belonging_to_another_project() -> None:
    """A real `TraceStorePort.exists` answers `False` for any ref outside the
    asked-for project's prefix (invariant 4), so without an explicit check a
    foreign row would be quietly reported as an ordinary missing object --
    an isolation failure downgraded into a routine maintenance line."""
    project = ProjectId(uuid4())
    other = ProjectId(uuid4())
    foreign_ref = PayloadRef(driver="fs", key=f"{other.value}/run/00000000.tbz")
    repo = FakeTraceLister(rows=[_trace_row(mint_run_id(), str(foreign_ref), other)])

    with pytest.raises(TypeError):
        find_orphaned_trace_payloads(repo, FakeTraceStore(present=set()), project)


def test_find_orphaned_trace_payloads_rejects_non_positive_limit() -> None:
    with pytest.raises(ValueError):
        find_orphaned_trace_payloads(
            FakeTraceLister(rows=[]), FakeTraceStore(present=set()), ProjectId(uuid4()), limit=0
        )


# --------------------------------------------------------------------------- #
# Tier 2: dead-letter reaping and expired-lease cleanup
# --------------------------------------------------------------------------- #


def test_dead_letter_reaping_purges_only_rows_older_than_retention() -> None:
    clock = FakeClock()
    now = clock.now()
    reaper = FakeReaper(
        rows={
            "t": [now - timedelta(days=10), now - timedelta(days=1)],
            "u": [now - timedelta(days=40)],
        }
    )

    purged = reap_dead_letter(reaper, ["t", "u"], clock, retention=timedelta(days=7))

    assert purged == {"t": 1, "u": 1}
    # The still-fresh row in "t" survives.
    assert reaper.rows["t"] == [now - timedelta(days=1)]
    assert reaper.rows["u"] == []
    # The cutoff actually passed to the port is `now - retention`.
    for _topic, cutoff in reaper.purge_calls:
        assert cutoff == now - timedelta(days=7)


def test_dead_letter_reaping_rejects_non_positive_retention() -> None:
    with pytest.raises(ValueError):
        reap_dead_letter(FakeReaper(), ["t"], FakeClock(), retention=timedelta(0))
    with pytest.raises(ValueError):
        reap_dead_letter(FakeReaper(), ["t"], FakeClock(), retention=timedelta(seconds=-1))


def test_expired_lease_counts_reports_per_topic_counts() -> None:
    counter = FakeLeaseCounter(counts={"t": 4, "u": 0})
    counts = expired_lease_counts(counter, ["t", "u", "v"])
    assert counts == {"t": 4, "u": 0, "v": 0}


# --------------------------------------------------------------------------- #
# run_gc_cycle: orchestration
# --------------------------------------------------------------------------- #


def test_run_gc_cycle_always_computes_health_but_skips_tier_2_when_no_adapter_given() -> None:
    port = FakeObservability(depths={"t": 1}, ages={"t": 5.0})
    health, gc_report = run_gc_cycle(observability=port, topics=["t"], lease_seconds=30)

    assert health.stats[0].topic == "t"
    assert gc_report.purged_dead_letter == {}
    assert gc_report.expired_leases == {}


def test_run_gc_cycle_wires_reaping_and_lease_counting_when_given() -> None:
    clock = FakeClock()
    now = clock.now()
    reaper = FakeReaper(rows={"t": [now - timedelta(days=40)]})
    lease_counter = FakeLeaseCounter(counts={"t": 2})
    port = FakeObservability()

    health, gc_report = run_gc_cycle(
        observability=port,
        topics=["t"],
        lease_seconds=30,
        reaper=reaper,
        lease_counter=lease_counter,
        clock=clock,
        dead_letter_retention=timedelta(days=7),
    )

    assert gc_report.purged_dead_letter == {"t": 1}
    assert gc_report.expired_leases == {"t": 2}
    assert health.stuck_topics == ()


def test_run_gc_cycle_requires_clock_and_retention_when_reaper_is_given() -> None:
    with pytest.raises(ValueError):
        run_gc_cycle(
            observability=FakeObservability(),
            topics=["t"],
            lease_seconds=30,
            reaper=FakeReaper(),
        )
