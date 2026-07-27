"""`workers.sweeps` — the quarantine/candidate TTL sweeps and idle decay (PLAN.md §5 state
machine; §6 `lifecycle.*`; §7 Phase 2 gate).

Fully offline: `_FakeRepo` holds `LifecycleMemoryRow`s in memory, records every `persist()`
call, and separately tracks a large, never-consulted `trace_row_count` — proof that a
sweep's cost is a function of matching `memory_item` rows alone, never trace volume
(the Phase 2 gate's explicit clause).
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from tracebed.domain.clock import FakeClock
from tracebed.domain.config import (
    AbstentionConfig,
    BudgetConfig,
    CacheConfig,
    DerivedConfig,
    EffectiveConfig,
    KillswitchConfig,
    LifecycleConfig,
    PromotionConfig,
    ProposalConfig,
    QueueConfig,
    RetirementConfig,
    RetrievalConfig,
    ScoreConfig,
    ScoringConfig,
    SessionConfig,
    SpendConfig,
    TierAConfig,
)
from tracebed.domain.enums import MemType, ProvenanceClass, TrustTier
from tracebed.domain.errors import TracebedError
from tracebed.domain.ids import MemoryId, ProjectId, RunId
from tracebed.domain.memory import Provenance
from tracebed.domain.state_machine import Status
from tracebed.workers.invalidator import LifecycleMemoryRow, LifecycleTransitionWrite
from tracebed.workers.sweeps import (
    _decayed_q_value,
    candidate_ttl_sweep,
    decay_sweep,
    quarantine_ttl_sweep,
    run_all_sweeps,
)

pytestmark = pytest.mark.phase2

PROJECT = ProjectId(uuid4())
EPOCH = datetime(2026, 1, 1, tzinfo=UTC)


def _effective_config(**overrides: object) -> EffectiveConfig:
    sections: dict[str, object] = {
        "retrieval": RetrievalConfig(),
        "abstention": AbstentionConfig(),
        "score": ScoreConfig(),
        "budget": BudgetConfig(),
        "scoring": ScoringConfig(),
        "promotion": PromotionConfig(),
        "retirement": RetirementConfig(),
        "lifecycle": LifecycleConfig(),
        "derived": DerivedConfig(),
        "proposals": ProposalConfig(),
        "tier_a": TierAConfig(),
        "killswitch": KillswitchConfig(),
        "spend": SpendConfig(),
        "cache": CacheConfig(),
        "session": SessionConfig(),
        "queue": QueueConfig(),
    }
    sections.update(overrides)
    return EffectiveConfig(**sections)


def _mid(tag: int) -> MemoryId:
    return MemoryId(UUID(int=tag))


def _row(
    tag: int,
    *,
    status: Status,
    status_changed_at: datetime | None = EPOCH,
    last_retrieved_at: datetime | None = None,
    created_at: datetime = EPOCH,
    q_value: float = 0.5,
    project_id: ProjectId = PROJECT,
) -> LifecycleMemoryRow:
    return LifecycleMemoryRow(
        id=_mid(tag),
        project_id=project_id,
        status=status,
        trust_tier=TrustTier.B,
        mem_type=MemType.LESSON,
        provenance=Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(RunId(uuid4()),)),
        status_changed_at=status_changed_at,
        strike_count=0,
        last_retrieved_at=last_retrieved_at,
        created_at=created_at,
        q_value=q_value,
    )


class _FakeRepo:
    def __init__(self, rows: Sequence[LifecycleMemoryRow], *, trace_row_count: int = 0) -> None:
        self._rows: dict[MemoryId, LifecycleMemoryRow] = {r.id: r for r in rows}
        self.trace_row_count = trace_row_count
        self.persisted: list[LifecycleTransitionWrite] = []
        self.status_calls: list[tuple[Status, ...]] = []

    def select_by_provenance(
        self,
        project_id: ProjectId,
        *,
        tool_refs: Sequence[str] = (),
        trace_ids: Sequence[RunId] = (),
        input_sig_hashes: Sequence[bytes] = (),
    ) -> Sequence[LifecycleMemoryRow]:
        return []

    def select_by_status(
        self, project_id: ProjectId, statuses: Sequence[Status], *, limit: int = 10_000
    ) -> Sequence[LifecycleMemoryRow]:
        self.status_calls.append(tuple(statuses))
        return [r for r in self._rows.values() if r.status in statuses][:limit]

    def select_due_for_revalidation(
        self, project_id: ProjectId, *, older_than: datetime, limit: int = 10_000
    ) -> Sequence[LifecycleMemoryRow]:
        return []

    def persist(self, project_id: ProjectId, write: LifecycleTransitionWrite) -> None:
        self.persisted.append(write)
        old = self._rows[write.memory_id]
        self._rows[write.memory_id] = LifecycleMemoryRow(
            id=old.id,
            project_id=old.project_id,
            status=write.to_status,
            trust_tier=old.trust_tier,
            mem_type=old.mem_type,
            provenance=old.provenance,
            status_changed_at=write.now if write.from_status != write.to_status else old.status_changed_at,
            strike_count=old.strike_count,
            last_retrieved_at=old.last_retrieved_at,
            created_at=old.created_at,
            q_value=write.q_value if write.q_value is not None else old.q_value,
        )


# --------------------------------------------------------------------------- #
# Quarantine / candidate TTL sweeps.
# --------------------------------------------------------------------------- #


def test_quarantine_ttl_sweep_moves_exact_population_and_is_idempotent() -> None:
    due = _row(1, status=Status.QUARANTINED, status_changed_at=EPOCH)
    not_due = _row(2, status=Status.QUARANTINED, status_changed_at=EPOCH + timedelta(days=1))
    repo = _FakeRepo([due, not_due], trace_row_count=10_000_000)
    clock = FakeClock(EPOCH + timedelta(days=30))  # exactly quarantine_ttl_days

    first = quarantine_ttl_sweep(PROJECT, repo, clock, _effective_config())
    assert first.rows_examined == 2
    assert first.transitioned == (due.id,)
    assert repo.persisted[-1].to_status == Status.ARCHIVED

    # Re-run at the identical simulated instant: the archived row no longer matches the
    # QUARANTINED predicate at all, so the sweep's own population shrinks -- idempotent.
    second = quarantine_ttl_sweep(PROJECT, repo, clock, _effective_config())
    assert second.rows_examined == 1
    assert second.transitioned == ()


def test_quarantine_ttl_sweep_never_reads_anything_trace_shaped() -> None:
    rows = [_row(i, status=Status.QUARANTINED, status_changed_at=EPOCH) for i in range(1, 6)]
    repo = _FakeRepo(rows, trace_row_count=50_000_000)
    clock = FakeClock(EPOCH + timedelta(days=30))

    result = quarantine_ttl_sweep(PROJECT, repo, clock, _effective_config())

    assert result.rows_examined == len(rows)  # cost == matching memory rows, not trace_row_count
    assert repo.status_calls == [(Status.QUARANTINED,)]  # exactly one indexed call


def test_candidate_ttl_sweep_moves_exact_population() -> None:
    due = _row(1, status=Status.CANDIDATE, status_changed_at=EPOCH)
    not_due = _row(2, status=Status.CANDIDATE, status_changed_at=EPOCH + timedelta(days=1))
    repo = _FakeRepo([due, not_due])
    clock = FakeClock(EPOCH + timedelta(days=45))  # exactly candidate_ttl_days

    result = candidate_ttl_sweep(PROJECT, repo, clock, _effective_config())

    assert result.transitioned == (due.id,)
    assert not_due.id not in {w.memory_id for w in repo.persisted}


def test_candidate_ttl_sweep_is_idempotent() -> None:
    due = _row(1, status=Status.CANDIDATE, status_changed_at=EPOCH)
    repo = _FakeRepo([due])
    clock = FakeClock(EPOCH + timedelta(days=45))

    first = candidate_ttl_sweep(PROJECT, repo, clock, _effective_config())
    assert first.transitioned == (due.id,)

    second = candidate_ttl_sweep(PROJECT, repo, clock, _effective_config())
    assert second.rows_examined == 0
    assert second.transitioned == ()


def test_candidate_ttl_sweep_not_yet_due_moves_nothing() -> None:
    row = _row(1, status=Status.CANDIDATE, status_changed_at=EPOCH)
    repo = _FakeRepo([row])
    clock = FakeClock(EPOCH + timedelta(days=44, hours=23))

    result = candidate_ttl_sweep(PROJECT, repo, clock, _effective_config())

    assert result.transitioned == ()
    assert repo.persisted == []


def test_a_row_with_no_status_changed_at_is_reported_not_silently_skipped() -> None:
    """`memory_item.status_changed_at` is nullable, and the TTL guard correctly refuses a
    NULL one. Swallowing that as an ordinary "not due yet" makes such a row permanently
    unsweepable AND invisible — it grows the quarantine population forever while the sweep
    that exists to bound it (D-012) reports a clean run every time."""
    undatable = _row(1, status=Status.QUARANTINED, status_changed_at=None)
    due = _row(2, status=Status.QUARANTINED, status_changed_at=EPOCH)
    repo = _FakeRepo([undatable, due])
    clock = FakeClock(EPOCH + timedelta(days=30))

    result = quarantine_ttl_sweep(PROJECT, repo, clock, _effective_config())

    assert result.undatable == (undatable.id,)
    assert result.transitioned == (due.id,)
    assert undatable.id not in {w.memory_id for w in repo.persisted}


def test_a_sweep_refuses_a_row_the_store_returned_with_the_wrong_status() -> None:
    """`select_by_status` is a predicate in a store implementation that does not exist yet;
    every sweep here is a bulk status CHANGE, so a select that over-returns is a bulk
    mis-transition. Archiving a validated memory under the quarantine TTL is only undone by
    an operator restore."""

    class _OverReturningRepo(_FakeRepo):
        def select_by_status(
            self, project_id: ProjectId, statuses: Sequence[Status], *, limit: int = 10_000
        ) -> Sequence[LifecycleMemoryRow]:
            self.status_calls.append(tuple(statuses))
            return list(self._rows.values())

    repo = _OverReturningRepo([_row(1, status=Status.VALIDATED, status_changed_at=EPOCH)])
    clock = FakeClock(EPOCH + timedelta(days=30))

    with pytest.raises(TracebedError, match="must not transition a row off an edge"):
        quarantine_ttl_sweep(PROJECT, repo, clock, _effective_config())
    assert repo.persisted == []


def test_a_sweep_refuses_a_row_scoped_to_another_project() -> None:
    foreign = _row(1, status=Status.QUARANTINED, status_changed_at=EPOCH, project_id=ProjectId(uuid4()))
    repo = _FakeRepo([foreign])
    clock = FakeClock(EPOCH + timedelta(days=30))

    with pytest.raises(TracebedError, match="invariant 4"):
        quarantine_ttl_sweep(PROJECT, repo, clock, _effective_config())
    assert repo.persisted == []


# --------------------------------------------------------------------------- #
# Decay sweep.
# --------------------------------------------------------------------------- #


def test_decay_progresses_without_a_status_change_before_the_floor() -> None:
    row = _row(1, status=Status.VALIDATED, last_retrieved_at=EPOCH)
    repo = _FakeRepo([row])
    clock = FakeClock(EPOCH + timedelta(weeks=1))
    cfg = _effective_config()  # defaults: q_start=0.5, floor=0.15, pct_per_week=5

    result = decay_sweep(PROJECT, repo, clock, cfg)

    assert result.transitioned == ()
    assert result.decayed_only == (row.id,)
    write = repo.persisted[-1]
    assert write.from_status == write.to_status == Status.VALIDATED
    expected_q = 0.15 + (0.5 - 0.15) * 0.95
    assert write.q_value is not None
    assert write.q_value == pytest.approx(expected_q)


def test_decay_reaches_the_archive_floor_and_archives() -> None:
    row = _row(1, status=Status.VALIDATED, last_retrieved_at=EPOCH)
    repo = _FakeRepo([row])
    clock = FakeClock(EPOCH + timedelta(weeks=1))
    # 100%/week decay reaches the floor after exactly one idle week -- a deterministic,
    # fast way to exercise "reaches the floor" without simulating years of idle time.
    cfg = _effective_config(lifecycle=LifecycleConfig(decay_pct_per_idle_week=100))

    result = decay_sweep(PROJECT, repo, clock, cfg)

    assert result.decayed_only == ()
    assert result.transitioned == (row.id,)
    write = repo.persisted[-1]
    assert write.to_status == Status.ARCHIVED
    assert write.q_value == pytest.approx(0.15)


def test_decay_stops_once_archived_a_second_sweep_leaves_it_alone() -> None:
    row = _row(1, status=Status.VALIDATED, last_retrieved_at=EPOCH)
    repo = _FakeRepo([row])
    clock = FakeClock(EPOCH + timedelta(weeks=1))
    cfg = _effective_config(lifecycle=LifecycleConfig(decay_pct_per_idle_week=100))

    decay_sweep(PROJECT, repo, clock, cfg)
    assert len(repo.persisted) == 1

    # Archived now -- select_by_status(VALIDATED) no longer returns it, so a re-run
    # examines zero rows and writes nothing further ("decay ... stops").
    second = decay_sweep(PROJECT, repo, clock, cfg)
    assert second.rows_examined == 0
    assert second.transitioned == ()
    assert second.decayed_only == ()
    assert len(repo.persisted) == 1


def test_decay_does_not_touch_a_row_that_has_not_gone_idle_yet() -> None:
    row = _row(1, status=Status.VALIDATED, last_retrieved_at=EPOCH)
    repo = _FakeRepo([row])
    clock = FakeClock(EPOCH + timedelta(days=6))  # under one idle week

    result = decay_sweep(PROJECT, repo, clock, _effective_config())

    assert result.decayed_only == ()
    assert result.transitioned == ()
    assert repo.persisted == []


def test_decayed_q_value_never_leaves_the_zero_to_one_column_range() -> None:
    """`scoring.q_start` and `lifecycle.archive_floor` are independently overridable per
    project and nothing validates them against each other, so a seed BELOW the floor is a
    reachable config — and without the clamp the curve then runs downward from the seed,
    off the bottom of a column the schema constrains to [0, 1]."""
    below_floor = _decayed_q_value(q_start=0.10, floor=0.15, pct_per_week=5, idle_weeks=1)
    assert below_floor == pytest.approx(0.15)

    # A percentage outside [0, 100] is a caller-supplied number with no Field bound in
    # domain/config.py: >100 would make the decay factor negative (a Q that flips sign and
    # oscillates), <0 would make it grow without bound.
    assert _decayed_q_value(q_start=0.5, floor=0.15, pct_per_week=250, idle_weeks=1) == pytest.approx(0.15)
    assert _decayed_q_value(q_start=0.5, floor=0.15, pct_per_week=-40, idle_weeks=3) == pytest.approx(0.5)

    # And the ordinary case still decays rather than being flattened by either clamp.
    assert _decayed_q_value(q_start=0.5, floor=0.15, pct_per_week=5, idle_weeks=2) == pytest.approx(
        0.15 + 0.35 * 0.95**2
    )


def test_decay_writes_nothing_on_a_second_run_at_the_same_instant() -> None:
    """A sweep that re-writes the identical number for every idle row on every tick is not
    idempotent — it just happens to converge. At vault scale that is the whole `validated`
    population written per sweep for no state change at all."""
    row = _row(1, status=Status.VALIDATED, last_retrieved_at=EPOCH)
    repo = _FakeRepo([row])
    clock = FakeClock(EPOCH + timedelta(weeks=1))
    cfg = _effective_config()

    first = decay_sweep(PROJECT, repo, clock, cfg)
    assert first.decayed_only == (row.id,)
    assert len(repo.persisted) == 1

    second = decay_sweep(PROJECT, repo, clock, cfg)
    assert second.rows_examined == 1  # still examined -- the cost is unchanged
    assert second.decayed_only == ()
    assert second.transitioned == ()
    assert len(repo.persisted) == 1  # ...but nothing was written


def test_decay_never_raises_a_q_value_that_is_already_below_the_curve() -> None:
    """Decay only ever lowers Q. A row already below this idle period's decayed value must
    be left alone, not lifted back up onto the curve."""
    row = _row(1, status=Status.VALIDATED, last_retrieved_at=EPOCH, q_value=0.2)
    repo = _FakeRepo([row])
    clock = FakeClock(EPOCH + timedelta(weeks=1))  # curve value here is 0.4825

    result = decay_sweep(PROJECT, repo, clock, _effective_config())

    assert result.decayed_only == ()
    assert repo.persisted == []


def test_decay_measures_idleness_from_last_retrieved_at_not_created_at() -> None:
    """A memory created a year ago but retrieved yesterday is not idle. Anchoring on
    `created_at` regardless would decay every long-lived, actively-used memory."""
    old_but_used = _row(
        1,
        status=Status.VALIDATED,
        created_at=EPOCH,
        last_retrieved_at=EPOCH + timedelta(weeks=51, days=6),
    )
    repo = _FakeRepo([old_but_used])
    clock = FakeClock(EPOCH + timedelta(weeks=52))  # 52 weeks since creation, 1 day since use

    result = decay_sweep(PROJECT, repo, clock, _effective_config())

    assert result.decayed_only == ()
    assert result.transitioned == ()
    assert repo.persisted == []


def test_decay_falls_back_to_created_at_when_never_retrieved() -> None:
    row = _row(1, status=Status.VALIDATED, last_retrieved_at=None, created_at=EPOCH)
    repo = _FakeRepo([row])
    clock = FakeClock(EPOCH + timedelta(weeks=1))
    cfg = _effective_config(lifecycle=LifecycleConfig(decay_pct_per_idle_week=100))

    result = decay_sweep(PROJECT, repo, clock, cfg)

    assert result.transitioned == (row.id,)


# --------------------------------------------------------------------------- #
# run_all_sweeps + the vault-size-not-trace-volume proof.
# --------------------------------------------------------------------------- #


def test_run_all_sweeps_covers_all_three_and_scales_with_memory_rows_not_traces() -> None:
    rows = [
        _row(1, status=Status.QUARANTINED, status_changed_at=EPOCH),
        _row(2, status=Status.CANDIDATE, status_changed_at=EPOCH),
        _row(3, status=Status.VALIDATED, last_retrieved_at=EPOCH),
    ]
    repo = _FakeRepo(rows, trace_row_count=1_000_000_000)  # a trace count that dwarfs the vault
    clock = FakeClock(EPOCH + timedelta(days=45))

    report = run_all_sweeps(PROJECT, repo, clock, _effective_config())

    assert report.quarantine.rows_examined == 1
    assert report.candidate.rows_examined == 1
    assert report.decay.rows_examined == 1
    # Exactly one indexed call per sweep -- never a scan proportional to trace_row_count.
    assert repo.status_calls == [(Status.QUARANTINED,), (Status.CANDIDATE,), (Status.VALIDATED,)]
