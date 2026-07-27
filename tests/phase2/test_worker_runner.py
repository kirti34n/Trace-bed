"""`workers.runner` -- WorkerRunner dispatch, WorkBatch homogeneity, and
`workers.scheduler` cadence (PLAN.md §7 Phase 2, chunk `worker-runner`).

Everything here is offline: a fake `QueueConsumerPort` and `FakeClock`, no
Postgres, no wall-clock sleeps. `Scheduler` is tested here rather than in a
dedicated file because this chunk's FILE LIST names only
`tests/phase2/test_worker_runner.py`/`tests/phase2/test_gc.py` for its three
source files (`runner.py`, `scheduler.py`, `gc.py`) -- `scheduler.py` has no
file of its own, so its tests live alongside `runner.py`'s.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from types import MappingProxyType
from uuid import uuid4

import pytest

from tracebed.domain.clock import FakeClock
from tracebed.domain.config import QueueConfig
from tracebed.domain.ids import ProjectId
from tracebed.stores.pg.queue import QueueItem, compute_backoff
from tracebed.workers.runner import WorkBatch, WorkerRunner, group_by_project
from tracebed.workers.scheduler import _MAX_CATCH_UP_RUNS_PER_TICK, ScheduledJob, Scheduler

# Read off the real config model rather than restated as a literal, so a
# change to `QueueConfig.lease_seconds` cannot leave these tests asserting
# against a lease length the queue no longer grants.
_LEASE_SECONDS = QueueConfig().lease_seconds

# --------------------------------------------------------------------------- #
# Fakes -- one per test module, per this codebase's own convention (contract
# §13.1: "a shared fakes module would be a merge collision").
# --------------------------------------------------------------------------- #


@dataclass
class _Row:
    id: int
    topic: str
    project_id: ProjectId
    payload: dict[str, object]
    attempts: int = 0
    leased: bool = False


class FakeQueue:
    """A minimal `QueueConsumerPort`: `claim()` only returns rows that are
    not already leased (so a test can assert a claimed-but-unacked row is
    NOT claimable again -- the at-least-once/no-double-claim property),
    `ack()` removes the row, `nack()` clears the lease so it becomes
    claimable again immediately.
    """

    def __init__(self) -> None:
        self._rows: dict[int, _Row] = {}
        self._next_id = 1
        self.acked: list[int] = []
        self.nacked: list[tuple[int, timedelta]] = []
        self.claim_calls: list[tuple[str, int]] = []

    def enqueue(self, topic: str, project_id: ProjectId, payload: dict[str, object]) -> int:
        row_id = self._next_id
        self._next_id += 1
        self._rows[row_id] = _Row(id=row_id, topic=topic, project_id=project_id, payload=payload)
        return row_id

    def claim(self, topic: str, n: int) -> list[QueueItem]:
        self.claim_calls.append((topic, n))
        claimed: list[QueueItem] = []
        for row in self._rows.values():
            if row.topic != topic or row.leased:
                continue
            if len(claimed) >= n:
                break
            row.leased = True
            row.attempts += 1
            claimed.append(
                QueueItem(
                    id=row.id,
                    topic=row.topic,
                    project_id=row.project_id,
                    payload=MappingProxyType(dict(row.payload)),
                    priority=100,
                    attempts=row.attempts,
                )
            )
        return claimed

    def ack(self, item_id: int) -> None:
        self._rows.pop(item_id, None)
        self.acked.append(item_id)

    def nack(self, item_id: int, backoff: timedelta) -> None:
        if item_id in self._rows:
            self._rows[item_id].leased = False
        self.nacked.append((item_id, backoff))

    def depth(self, topic: str) -> int:
        return sum(1 for row in self._rows.values() if row.topic == topic)


@dataclass
class RecordingHandler:
    """Records every batch it is handed, in order. `fail_on` names project
    ids whose batch should raise instead of succeeding -- once per project
    id present, so a test can assert retried behaviour precisely."""

    seen: list[WorkBatch] = field(default_factory=list)
    fail_on: frozenset[ProjectId] = frozenset()
    on_handle: Callable[[WorkBatch], None] | None = None

    def handle(self, batch: WorkBatch) -> None:
        self.seen.append(batch)
        if self.on_handle is not None:
            self.on_handle(batch)
        if batch.project_id in self.fail_on:
            raise RuntimeError(f"synthetic failure for {batch.project_id}")


def _project() -> ProjectId:
    return ProjectId(uuid4())


# --------------------------------------------------------------------------- #
# WorkBatch homogeneity
# --------------------------------------------------------------------------- #


def _item(project_id: ProjectId, topic: str = "t", item_id: int = 1) -> QueueItem:
    return QueueItem(
        id=item_id,
        topic=topic,
        project_id=project_id,
        payload=MappingProxyType({}),
        priority=100,
        attempts=1,
    )


def test_workbatch_cannot_be_constructed_spanning_two_projects() -> None:
    """PLAN.md §10: a worker batch must never mix projects. Constructing one
    that does is a `TypeError` at construction -- not a value returned for a
    caller to inspect and possibly use anyway."""
    p1, p2 = _project(), _project()
    with pytest.raises(TypeError):
        WorkBatch(project_id=p1, topic="t", items=(_item(p1), _item(p2)))


def test_workbatch_rejects_a_topic_mismatch_too() -> None:
    p1 = _project()
    with pytest.raises(TypeError):
        WorkBatch(project_id=p1, topic="t", items=(_item(p1, topic="other"),))


def test_workbatch_accepts_homogeneous_items() -> None:
    p1 = _project()
    batch = WorkBatch(project_id=p1, topic="t", items=(_item(p1, item_id=1), _item(p1, item_id=2)))
    assert len(batch.items) == 2


def test_workbatch_freezes_a_caller_supplied_list_so_it_cannot_gain_a_foreign_item() -> None:
    """Validating a mutable sequence and then storing that same sequence
    leaves the one-project-per-batch check open to an append AFTER it passed.
    The batch must own an immutable copy."""
    p1, p2 = _project(), _project()
    supplied = [_item(p1, item_id=1)]
    batch = WorkBatch(project_id=p1, topic="t", items=supplied)  # type: ignore[arg-type]

    supplied.append(_item(p2, item_id=2))

    assert isinstance(batch.items, tuple)
    assert [item.id for item in batch.items] == [1]
    assert {item.project_id for item in batch.items} == {p1}


def test_group_by_project_splits_a_mixed_claim_into_homogeneous_batches() -> None:
    p1, p2 = _project(), _project()
    items = [
        _item(p1, item_id=1),
        _item(p2, item_id=2),
        _item(p1, item_id=3),
    ]
    batches = group_by_project("t", items)
    assert [b.project_id for b in batches] == [p1, p2]
    assert [item.id for item in batches[0].items] == [1, 3]
    assert [item.id for item in batches[1].items] == [2]


# --------------------------------------------------------------------------- #
# WorkerRunner: dispatch, ack/nack, project homogeneity end to end
# --------------------------------------------------------------------------- #


def test_run_once_dispatches_project_homogeneous_batches_and_acks_on_success() -> None:
    queue = FakeQueue()
    p1, p2 = _project(), _project()
    queue.enqueue("t", p1, {"n": 1})
    queue.enqueue("t", p2, {"n": 2})
    queue.enqueue("t", p1, {"n": 3})

    handler = RecordingHandler()
    runner = WorkerRunner(queue=queue, clock=FakeClock(), handlers={"t": handler}, batch_size=10, lease_seconds=_LEASE_SECONDS)

    processed = runner.run_once()

    assert processed == 3
    assert len(handler.seen) == 2  # one batch per distinct project
    assert {b.project_id for b in handler.seen} == {p1, p2}
    for batch in handler.seen:
        assert len({item.project_id for item in batch.items}) == 1
    assert sorted(queue.acked) == [1, 2, 3]
    assert queue.nacked == []


def test_a_raising_handler_does_not_kill_the_runner_and_the_item_is_nacked_with_backoff() -> None:
    queue = FakeQueue()
    p1, p2 = _project(), _project()
    queue.enqueue("t", p1, {})  # will fail
    queue.enqueue("t", p2, {})  # will succeed

    handler = RecordingHandler(fail_on=frozenset({p1}))
    runner = WorkerRunner(queue=queue, clock=FakeClock(), handlers={"t": handler}, batch_size=10, lease_seconds=_LEASE_SECONDS)

    # Must not raise out of run_once -- a worker raising does not kill the runner.
    processed = runner.run_once()

    assert processed == 2
    assert queue.acked == [2]
    assert [item_id for item_id, _backoff in queue.nacked] == [1]
    # The backoff must be derived from the item's OWN attempts count (1 at
    # first claim), not from a constant: asserting the exact value is what
    # makes `compute_backoff(0)` / `compute_backoff(<literal>)` a red test
    # rather than a survivable mutation.
    assert queue.nacked[0][1] == compute_backoff(1)

    # The failed item is still present (nacked, not lost) and becomes claimable
    # again -- at-least-once redelivery, not silent loss.
    again = runner.run_once()
    assert again == 1
    assert queue.acked == [2]  # unchanged: the retry handler still fails it
    assert len(queue.nacked) == 2
    # Second delivery -> attempts == 2 -> a strictly longer backoff. A constant
    # backoff would make these two equal.
    assert queue.nacked[1][1] == compute_backoff(2)
    assert queue.nacked[1][1] > queue.nacked[0][1]


def test_graceful_shutdown_mid_batch_loses_nothing_and_double_acks_nothing() -> None:
    """A handler sets `stop` mid-processing (simulating a shutdown signal
    arriving while `run_once()` is in flight). The batch already claimed
    must still be driven to ack in full, and `run_forever` must not start
    another round afterwards."""
    queue = FakeQueue()
    p1 = _project()
    for i in range(1, 4):
        queue.enqueue("t", p1, {"i": i})

    stop = threading.Event()

    def _stop_after_first(batch: WorkBatch) -> None:
        stop.set()

    handler = RecordingHandler(on_handle=_stop_after_first)
    runner = WorkerRunner(queue=queue, clock=FakeClock(), handlers={"t": handler}, batch_size=10, lease_seconds=_LEASE_SECONDS)

    runner.run_forever(stop, poll_interval=timedelta(milliseconds=1))

    # Exactly one batch was formed (all three items, same project) and it was
    # acked in full -- nothing lost, nothing double-acked.
    assert len(handler.seen) == 1
    assert sorted(queue.acked) == [1, 2, 3]
    assert queue.nacked == []
    assert len(set(queue.acked)) == len(queue.acked)  # no id acked twice


def test_run_forever_runs_exactly_max_iterations_when_queue_stays_empty() -> None:
    """`max_iterations` is the only thing that makes `run_forever` finite in a
    test, so the count itself must be asserted, not just the exit. Counting
    `claim()` calls is what kills both "return before the loop" and an
    off-by-one on the iteration bound -- an assertion on `stop` alone survives
    either."""
    queue = FakeQueue()
    runner = WorkerRunner(queue=queue, clock=FakeClock(), handlers={"t": RecordingHandler()}, batch_size=10, lease_seconds=_LEASE_SECONDS)
    stop = threading.Event()

    runner.run_forever(stop, poll_interval=timedelta(milliseconds=1), max_iterations=3)

    assert queue.claim_calls == [("t", 10)] * 3
    assert not stop.is_set()  # stopped by max_iterations, not by a shutdown signal


def test_run_forever_drains_a_backlog_across_iterations_without_sleeping() -> None:
    """A queue with more rows than one batch must be drained by successive
    rounds; `run_forever` only sleeps on an idle round."""
    queue = FakeQueue()
    p1 = _project()
    for i in range(5):
        queue.enqueue("t", p1, {"i": i})

    handler = RecordingHandler()
    runner = WorkerRunner(queue=queue, clock=FakeClock(), handlers={"t": handler}, batch_size=2, lease_seconds=_LEASE_SECONDS)

    runner.run_forever(threading.Event(), poll_interval=timedelta(milliseconds=1), max_iterations=3)

    assert sorted(queue.acked) == [1, 2, 3, 4, 5]
    assert queue.depth("t") == 0
    assert [len(b.items) for b in handler.seen] == [2, 2, 1]


def test_batch_size_must_be_positive() -> None:
    with pytest.raises(ValueError):
        WorkerRunner(queue=FakeQueue(), clock=FakeClock(), handlers={}, batch_size=0, lease_seconds=_LEASE_SECONDS)


def test_lease_seconds_must_be_positive() -> None:
    with pytest.raises(ValueError):
        WorkerRunner(queue=FakeQueue(), clock=FakeClock(), handlers={}, batch_size=1, lease_seconds=0)


# --------------------------------------------------------------------------- #
# Lease overrun: the one case where nacking would STEAL a live lease
# --------------------------------------------------------------------------- #


def test_a_failing_handler_that_outran_its_lease_is_not_nacked() -> None:
    """`WorkQueue.nack` sets `lease_expires_at = NULL` unconditionally. Once
    this runner's own lease has expired the rows are already redeliverable, so
    another consumer may hold them -- nacking then clears THAT consumer's
    lease and hands the rows to a third. The runner must leave them to expire
    instead. Nothing is lost: an expired lease is claimable on its own."""
    queue = FakeQueue()
    p1 = _project()
    queue.enqueue("t", p1, {})
    clock = FakeClock()

    def _overrun_then_fail(batch: WorkBatch) -> None:
        clock.advance(seconds=_LEASE_SECONDS + 1)
        raise RuntimeError("slow and broken")

    handler = RecordingHandler(on_handle=_overrun_then_fail)
    runner = WorkerRunner(queue=queue, clock=clock, handlers={"t": handler}, batch_size=10, lease_seconds=_LEASE_SECONDS)

    processed = runner.run_once()

    assert processed == 1  # still reported as handled this round
    assert queue.nacked == []  # the whole point
    assert queue.acked == []  # and definitely not acked -- the handler failed


def test_a_failing_handler_inside_its_lease_is_still_nacked() -> None:
    """The complement of the test above: without it, "never nack" would pass
    just as well as "never nack after an overrun"."""
    queue = FakeQueue()
    p1 = _project()
    queue.enqueue("t", p1, {})
    clock = FakeClock()

    def _fast_then_fail(batch: WorkBatch) -> None:
        clock.advance(seconds=_LEASE_SECONDS - 1)
        raise RuntimeError("fast and broken")

    handler = RecordingHandler(on_handle=_fast_then_fail)
    runner = WorkerRunner(queue=queue, clock=clock, handlers={"t": handler}, batch_size=10, lease_seconds=_LEASE_SECONDS)

    runner.run_once()

    assert [item_id for item_id, _backoff in queue.nacked] == [1]


def test_a_succeeding_handler_that_outran_its_lease_still_acks() -> None:
    """The work IS done; a redelivered duplicate's later ack is a documented
    no-op. Refusing to ack here would guarantee a third delivery."""
    queue = FakeQueue()
    p1 = _project()
    queue.enqueue("t", p1, {})
    clock = FakeClock()

    handler = RecordingHandler(on_handle=lambda batch: clock.advance(seconds=_LEASE_SECONDS + 1))
    runner = WorkerRunner(queue=queue, clock=clock, handlers={"t": handler}, batch_size=10, lease_seconds=_LEASE_SECONDS)

    runner.run_once()

    assert queue.acked == [1]
    assert queue.nacked == []


# --------------------------------------------------------------------------- #
# Scheduler: cadence driven purely by an injectable Clock
# --------------------------------------------------------------------------- #


def test_scheduled_job_rejects_a_non_positive_interval() -> None:
    with pytest.raises(ValueError):
        ScheduledJob(name="x", interval=timedelta(0), run=lambda: None)
    with pytest.raises(ValueError):
        ScheduledJob(name="x", interval=timedelta(seconds=-1), run=lambda: None)


def test_scheduler_rejects_duplicate_job_names() -> None:
    clock = FakeClock()
    job = ScheduledJob(name="dup", interval=timedelta(hours=1), run=lambda: None)
    with pytest.raises(ValueError):
        Scheduler(clock, jobs=[job, job])


def test_scheduler_does_not_fire_before_its_first_interval_elapses() -> None:
    clock = FakeClock()
    calls: list[None] = []
    scheduler = Scheduler(
        clock, jobs=[ScheduledJob(name="j", interval=timedelta(hours=1), run=lambda: calls.append(None))]
    )
    clock.advance(minutes=59)
    fired = scheduler.tick()
    assert fired == {}
    assert calls == []


def test_scheduler_fires_each_job_at_its_own_cadence_across_30_simulated_days() -> None:
    """The Phase 2 soak's own shape: advance a FakeClock by 30 simulated
    days in ONE step and call `tick()` once. Each job must fire EXACTLY
    floor(30 days / interval) times -- not more, not fewer -- regardless of
    how coarsely the clock was advanced between ticks."""
    clock = FakeClock()
    hourly_calls: list[None] = []
    daily_calls: list[None] = []
    scheduler = Scheduler(
        clock,
        jobs=[
            ScheduledJob(name="hourly", interval=timedelta(hours=1), run=lambda: hourly_calls.append(None)),
            ScheduledJob(name="daily", interval=timedelta(days=1), run=lambda: daily_calls.append(None)),
        ],
    )

    clock.advance(days=30)
    fired = scheduler.tick()

    assert len(hourly_calls) == 30 * 24
    assert len(daily_calls) == 30
    assert fired["hourly"] == 30 * 24
    assert fired["daily"] == 30

    # A second, immediate tick with no further clock advance must not fire
    # either job again -- "not more often than the cadence".
    fired_again = scheduler.tick()
    assert fired_again == {}


def test_scheduler_cadence_is_identical_whether_ticked_coarsely_or_finely() -> None:
    """Cross-checks the single-big-jump result above against ticking once
    per simulated hour -- the total fire count must agree exactly, proving
    the catch-up loop is not an artefact of tick granularity."""
    interval = timedelta(hours=6)

    def _run_with_granularity(step: timedelta, total: timedelta) -> int:
        clock = FakeClock()
        calls = {"n": 0}
        scheduler = Scheduler(
            clock, jobs=[ScheduledJob(name="j", interval=interval, run=lambda: calls.__setitem__("n", calls["n"] + 1))]
        )
        elapsed = timedelta(0)
        while elapsed < total:
            clock.advance(step)
            elapsed += step
            scheduler.tick()
        return calls["n"]

    total = timedelta(days=30)
    coarse = _run_with_granularity(timedelta(days=1), total)
    fine = _run_with_granularity(timedelta(hours=1), total)
    assert coarse == fine
    assert coarse == 30 * 24 // 6


def test_scheduler_job_raising_does_not_stop_other_jobs_or_its_own_next_occurrence() -> None:
    clock = FakeClock()
    calls: list[None] = []

    def _boom() -> None:
        raise RuntimeError("synthetic")

    scheduler = Scheduler(
        clock,
        jobs=[
            ScheduledJob(name="boom", interval=timedelta(hours=1), run=_boom),
            ScheduledJob(name="ok", interval=timedelta(hours=1), run=lambda: calls.append(None)),
        ],
    )

    clock.advance(hours=1)
    fired = scheduler.tick()
    assert fired == {"boom": 1, "ok": 1}
    assert calls == [None]

    # The failing job is still scheduled for its NEXT occurrence, not wedged.
    clock.advance(hours=1)
    fired_again = scheduler.tick()
    assert fired_again == {"boom": 1, "ok": 1}
    assert calls == [None, None]


def test_scheduler_due_in_ms_reports_time_until_next_fire() -> None:
    clock = FakeClock()
    scheduler = Scheduler(clock, jobs=[ScheduledJob(name="j", interval=timedelta(seconds=10), run=lambda: None)])
    assert scheduler.due_in_ms("j") == pytest.approx(10_000.0)
    clock.advance(seconds=4)
    assert scheduler.due_in_ms("j") == pytest.approx(6_000.0)
    with pytest.raises(KeyError):
        scheduler.due_in_ms("missing")


def test_scheduler_catch_up_is_bounded_against_a_pathological_interval() -> None:
    """A degenerate 1ms interval combined with a huge clock jump must not
    hang -- the safety ceiling caps catch-up runs per tick rather than
    looping unbounded, per the module's documented bound."""
    clock = FakeClock()
    calls = {"n": 0}
    scheduler = Scheduler(
        clock,
        jobs=[ScheduledJob(name="fast", interval=timedelta(milliseconds=1), run=lambda: calls.__setitem__("n", calls["n"] + 1))],
    )
    clock.advance(days=1)  # 86,400,000 ms / 1ms interval -> far past the cap
    fired = scheduler.tick()
    # Exactly the cap, not merely "at most" it: `<= cap` is satisfied by any
    # cap, including a mutation that lowers it to 1, so it asserts nothing
    # about the bound actually in force.
    assert fired["fast"] == _MAX_CATCH_UP_RUNS_PER_TICK
    assert calls["n"] == _MAX_CATCH_UP_RUNS_PER_TICK

    # The skipped backlog is dropped, not replayed on the next tick: a
    # subsequent tick with no clock advance must fire nothing at all.
    assert scheduler.tick() == {}
    assert calls["n"] == _MAX_CATCH_UP_RUNS_PER_TICK
