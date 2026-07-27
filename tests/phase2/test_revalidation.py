"""`workers.revalidation` — usage-triggered revalidation, the R-day boundary, and the
two-strike retirement model (PLAN.md §7 Phase 2).

Fully offline: `_FakeRepo` and `_FakeVerifier` are small in-file fakes (this codebase's
convention, contract §13.1). Every assertion that a status changed is cross-checked against
a direct `domain.state_machine.apply()` call with the same evidence, proving the worker
never performs a direct status UPDATE.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
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
from tracebed.domain.errors import GuardNotSatisfied, IllegalTransition, TracebedError
from tracebed.domain.ids import MemoryId, ProjectId, RunId
from tracebed.domain.memory import Provenance
from tracebed.domain.state_machine import Status, TransitionEvidence, TransitionLimits, apply
from tracebed.workers.invalidator import LifecycleMemoryRow, LifecycleTransitionWrite
from tracebed.workers.revalidation import (
    RevalidationWorker,
    is_due_for_revalidation,
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
    last_retrieved_at: datetime | None,
    created_at: datetime = EPOCH,
    strike_count: int = 0,
    status_changed_at: datetime | None = EPOCH,
) -> LifecycleMemoryRow:
    return LifecycleMemoryRow(
        id=_mid(tag),
        project_id=PROJECT,
        status=status,
        trust_tier=TrustTier.B,
        mem_type=MemType.LESSON,
        provenance=Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(RunId(uuid4()),)),
        status_changed_at=status_changed_at,
        strike_count=strike_count,
        last_retrieved_at=last_retrieved_at,
        created_at=created_at,
    )


@dataclass
class _FakeVerifier:
    """Returns a fixed verdict, or one keyed by memory_id when `by_id` is set."""

    default: bool = True
    by_id: dict[MemoryId, bool] = field(default_factory=dict)
    calls: list[MemoryId] = field(default_factory=list)

    def reverify(self, row: LifecycleMemoryRow) -> bool:
        self.calls.append(row.id)
        return self.by_id.get(row.id, self.default)


class _FakeRepo:
    def __init__(self, rows: Sequence[LifecycleMemoryRow]) -> None:
        self._rows: dict[MemoryId, LifecycleMemoryRow] = {r.id: r for r in rows}
        self.persisted: list[LifecycleTransitionWrite] = []

    def select_by_provenance(
        self,
        project_id: ProjectId,
        *,
        tool_refs: Sequence[str] = (),
        trace_ids: Sequence[RunId] = (),
        input_sig_hashes: Sequence[bytes] = (),
    ) -> Sequence[LifecycleMemoryRow]:
        return []  # unused by revalidation.py -- present only for MemoryLifecycleRepoPort conformance

    def select_by_status(
        self, project_id: ProjectId, statuses: Sequence[Status], *, limit: int = 10_000
    ) -> Sequence[LifecycleMemoryRow]:
        return [r for r in self._rows.values() if r.status in statuses][:limit]

    def select_due_for_revalidation(
        self, project_id: ProjectId, *, older_than: datetime, limit: int = 10_000
    ) -> Sequence[LifecycleMemoryRow]:
        out = []
        for r in self._rows.values():
            if r.status is not Status.VALIDATED:
                continue
            reference = r.last_retrieved_at if r.last_retrieved_at is not None else r.created_at
            if reference <= older_than:
                out.append(r)
        return out[:limit]

    def current(self, memory_id: MemoryId) -> LifecycleMemoryRow:
        return self._rows[memory_id]

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
            strike_count=write.strike_count if write.strike_count is not None else old.strike_count,
            last_retrieved_at=old.last_retrieved_at,
            created_at=old.created_at,
        )


# --------------------------------------------------------------------------- #
# is_due_for_revalidation: the exact R-day boundary.
# --------------------------------------------------------------------------- #


def test_due_at_exactly_r_days_and_not_before() -> None:
    row = _row(1, status=Status.VALIDATED, last_retrieved_at=EPOCH)
    just_under = EPOCH + timedelta(days=30) - timedelta(seconds=1)
    exactly = EPOCH + timedelta(days=30)
    assert is_due_for_revalidation(row, r_days=30, now=just_under) is False
    assert is_due_for_revalidation(row, r_days=30, now=exactly) is True


def test_never_retrieved_falls_back_to_created_at() -> None:
    row = _row(1, status=Status.VALIDATED, last_retrieved_at=None, created_at=EPOCH)
    assert is_due_for_revalidation(row, r_days=30, now=EPOCH + timedelta(days=29)) is False
    assert is_due_for_revalidation(row, r_days=30, now=EPOCH + timedelta(days=30)) is True


def test_stale_is_due_on_any_later_instant_but_not_the_one_it_went_stale_on() -> None:
    """"Second strike" names a second OCCASION. `now == status_changed_at` is the first one
    being read twice, which is how one verifier verdict carried a memory from `validated`
    to `retired` when the batch was retried against a frozen clock."""
    stale = _row(1, status=Status.STALE, last_retrieved_at=None, status_changed_at=EPOCH)
    assert is_due_for_revalidation(stale, r_days=30, now=EPOCH) is False
    assert (
        is_due_for_revalidation(stale, r_days=30, now=EPOCH + timedelta(seconds=1)) is True
    )
    # No R-day idle window applies to `stale`: it is excluded from RETRIEVABLE_STATUSES, so
    # nothing will ever retrieve it and no amount of waiting is required beyond distinctness.
    assert is_due_for_revalidation(stale, r_days=30, now=EPOCH + timedelta(days=1)) is True

    # A NULL status_changed_at (the column is nullable) leaves no first occasion to differ
    # from, so the row is due rather than permanently unreachable.
    undated = _row(2, status=Status.STALE, last_retrieved_at=None, status_changed_at=None)
    assert is_due_for_revalidation(undated, r_days=30, now=EPOCH) is True


def test_candidate_and_quarantined_are_never_due() -> None:
    candidate = _row(2, status=Status.CANDIDATE, last_retrieved_at=None)
    quarantined = _row(3, status=Status.QUARANTINED, last_retrieved_at=None)
    assert is_due_for_revalidation(candidate, r_days=30, now=EPOCH + timedelta(days=999)) is False
    assert is_due_for_revalidation(quarantined, r_days=30, now=EPOCH + timedelta(days=999)) is False


# --------------------------------------------------------------------------- #
# check_validated: a failure is strike one.
# --------------------------------------------------------------------------- #


def test_validated_failure_is_strike_one() -> None:
    row = _row(1, status=Status.VALIDATED, last_retrieved_at=EPOCH)
    repo = _FakeRepo([row])
    clock = FakeClock(EPOCH + timedelta(days=30))
    worker = RevalidationWorker(repo, clock)
    verifier = _FakeVerifier(default=False)
    cfg = _effective_config()

    outcome = worker.check_validated(PROJECT, row, verifier=verifier, cfg=cfg)

    limits = TransitionLimits.from_config(cfg)
    evidence = TransitionEvidence(
        now=clock.now(),
        provenance_class=ProvenanceClass.DISTILLER,
        trust_tier=TrustTier.B,
        mem_type=MemType.LESSON,
        status_changed_at=EPOCH,
        revalidation_failed=True,
    )
    expected = apply(Status.VALIDATED, Status.STALE, evidence, limits)

    assert outcome.verified is False
    assert outcome.to_status == expected == Status.STALE
    assert repo.persisted[-1].strike_count == 1


def test_validated_success_touches_last_revalidated_without_a_status_change() -> None:
    row = _row(1, status=Status.VALIDATED, last_retrieved_at=EPOCH)
    repo = _FakeRepo([row])
    clock = FakeClock(EPOCH + timedelta(days=30))
    worker = RevalidationWorker(repo, clock)
    verifier = _FakeVerifier(default=True)

    outcome = worker.check_validated(PROJECT, row, verifier=verifier, cfg=_effective_config())

    assert outcome.verified is True
    assert outcome.to_status is None  # nothing transitioned
    write = repo.persisted[-1]
    assert write.from_status == write.to_status == Status.VALIDATED
    assert write.last_revalidated_at == clock.now()
    # (VALIDATED, VALIDATED) is not a legal edge -- proving apply() was correctly NOT called
    # for this no-op touch (there would be nothing for it to authorise).
    with pytest.raises(IllegalTransition):
        apply(
            Status.VALIDATED,
            Status.VALIDATED,
            TransitionEvidence(
                now=clock.now(),
                provenance_class=ProvenanceClass.DISTILLER,
                trust_tier=TrustTier.B,
                mem_type=MemType.LESSON,
            ),
            TransitionLimits.from_config(_effective_config()),
        )


# --------------------------------------------------------------------------- #
# check_stale: two strikes, not one.
# --------------------------------------------------------------------------- #


def test_second_strike_retires_the_first_strike_alone_does_not() -> None:
    now = EPOCH + timedelta(days=60)

    # Strike 1 already happened elsewhere (workers.invalidator / check_validated both
    # write strike_count=1 on entry to `stale` -- see module docstrings).
    stale_after_one_strike = _row(1, status=Status.STALE, last_retrieved_at=None, strike_count=1)
    repo = _FakeRepo([stale_after_one_strike])
    clock = FakeClock(now)
    worker = RevalidationWorker(repo, clock)
    verifier = _FakeVerifier(default=False)  # fails again -> strike 2

    outcome = worker.check_stale(
        PROJECT, stale_after_one_strike, verifier=verifier, cfg=_effective_config()
    )

    assert outcome.to_status == Status.RETIRED
    assert repo.persisted[-1].strike_count == 2

    # A hypothetical row that entered `stale` with strike_count=0 (should never happen --
    # every route into `stale` writes strike_count=1) fails its first check_stale call:
    # ONE strike must not retire.
    zero_strike_row = _row(2, status=Status.STALE, last_retrieved_at=None, strike_count=0)
    repo2 = _FakeRepo([zero_strike_row])
    worker2 = RevalidationWorker(repo2, FakeClock(now))
    with pytest.raises(GuardNotSatisfied):
        worker2.check_stale(
            PROJECT, zero_strike_row, verifier=_FakeVerifier(default=False), cfg=_effective_config()
        )
    assert repo2.persisted == []  # the guard refused before any write happened


def test_stale_recovers_to_validated_on_a_passing_reverification() -> None:
    row = _row(1, status=Status.STALE, last_retrieved_at=None, strike_count=1)
    repo = _FakeRepo([row])
    clock = FakeClock(EPOCH)
    worker = RevalidationWorker(repo, clock)
    verifier = _FakeVerifier(default=True)

    outcome = worker.check_stale(PROJECT, row, verifier=verifier, cfg=_effective_config())

    assert outcome.to_status == Status.VALIDATED
    write = repo.persisted[-1]
    assert write.strike_count == 0  # the counter resets on recovery


# --------------------------------------------------------------------------- #
# run_once: batches due VALIDATED rows plus every STALE row.
# --------------------------------------------------------------------------- #


def test_run_once_examines_due_validated_rows_and_all_stale_rows() -> None:
    due = _row(1, status=Status.VALIDATED, last_retrieved_at=EPOCH)
    not_due = _row(2, status=Status.VALIDATED, last_retrieved_at=EPOCH + timedelta(days=29))
    stale = _row(3, status=Status.STALE, last_retrieved_at=None, strike_count=1)

    repo = _FakeRepo([due, not_due, stale])
    clock = FakeClock(EPOCH + timedelta(days=30))
    worker = RevalidationWorker(repo, clock)
    verifier = _FakeVerifier(default=True)

    result = worker.run_once(PROJECT, verifier=verifier, cfg=_effective_config())

    assert result.rows_examined == 2  # `due` + `stale`; `not_due` excluded by the repo itself
    checked_ids = {o.memory_id for o in result.outcomes}
    assert checked_ids == {due.id, stale.id}
    assert not_due.id not in verifier.calls


def test_one_run_once_pass_can_never_deliver_both_strikes() -> None:
    """The load-bearing "two strikes, not one" assertion at the batch level: a single failing
    verifier must leave a validated memory at `stale`, never carry it through to `retired`
    inside one pass, whatever order the two loops run in."""
    due = _row(1, status=Status.VALIDATED, last_retrieved_at=EPOCH)
    repo = _FakeRepo([due])
    clock = FakeClock(EPOCH + timedelta(days=30))
    worker = RevalidationWorker(repo, clock)

    result = worker.run_once(PROJECT, verifier=_FakeVerifier(default=False), cfg=_effective_config())

    assert [o.to_status for o in result.outcomes] == [Status.STALE]
    assert [w.to_status for w in repo.persisted] == [Status.STALE]
    assert repo.current(due.id).status is Status.STALE
    assert repo.current(due.id).strike_count == 1


def test_a_row_appearing_in_both_selects_still_gets_only_one_strike() -> None:
    """`run_once` issues two selects. Nothing wraps them in one snapshot, so an invalidation
    event landing between them puts ONE row in both populations: `validated` per the first
    read, `stale` per the second. Without the struck-this-pass set the batch then calls
    check_validated (strike 1) and check_stale (strike 2) on that row inside a single pass,
    retiring it on one verifier verdict."""
    validated_view = _row(1, status=Status.VALIDATED, last_retrieved_at=EPOCH)
    stale_view = _row(
        1, status=Status.STALE, last_retrieved_at=EPOCH, strike_count=1, status_changed_at=EPOCH
    )

    class _RacingRepo(_FakeRepo):
        """Its two selects read two different instants, as two real statements do."""

        def select_due_for_revalidation(
            self, project_id: ProjectId, *, older_than: datetime, limit: int = 10_000
        ) -> Sequence[LifecycleMemoryRow]:
            return [validated_view]

        def select_by_status(
            self, project_id: ProjectId, statuses: Sequence[Status], *, limit: int = 10_000
        ) -> Sequence[LifecycleMemoryRow]:
            return [stale_view] if Status.STALE in statuses else []

    repo = _RacingRepo([validated_view])
    worker = RevalidationWorker(repo, FakeClock(EPOCH + timedelta(days=30)))

    result = worker.run_once(PROJECT, verifier=_FakeVerifier(default=False), cfg=_effective_config())

    assert [o.to_status for o in result.outcomes] == [Status.STALE]
    assert [w.to_status for w in repo.persisted] == [Status.STALE]
    assert Status.RETIRED not in {w.to_status for w in repo.persisted}


def test_re_running_the_batch_at_a_frozen_clock_does_not_escalate_the_strike() -> None:
    """A retry or a duplicated scheduler tick is one observation read twice, not two."""
    due = _row(1, status=Status.VALIDATED, last_retrieved_at=EPOCH)
    repo = _FakeRepo([due])
    clock = FakeClock(EPOCH + timedelta(days=30))
    worker = RevalidationWorker(repo, clock)
    verifier = _FakeVerifier(default=False)
    cfg = _effective_config()

    worker.run_once(PROJECT, verifier=verifier, cfg=cfg)
    second = worker.run_once(PROJECT, verifier=verifier, cfg=cfg)

    assert second.outcomes == ()
    assert repo.current(due.id).status is Status.STALE
    assert len(repo.persisted) == 1


def test_a_later_tick_does_deliver_the_second_strike() -> None:
    """The distinctness guard must not wedge a stale row permanently — the very next tick
    at any later instant retires it, exactly as the two-strike model requires."""
    due = _row(1, status=Status.VALIDATED, last_retrieved_at=EPOCH)
    repo = _FakeRepo([due])
    clock = FakeClock(EPOCH + timedelta(days=30))
    worker = RevalidationWorker(repo, clock)
    verifier = _FakeVerifier(default=False)
    cfg = _effective_config()

    worker.run_once(PROJECT, verifier=verifier, cfg=cfg)
    assert repo.current(due.id).status is Status.STALE

    clock.advance(timedelta(days=1))
    worker.run_once(PROJECT, verifier=verifier, cfg=cfg)
    assert repo.current(due.id).status is Status.RETIRED
    assert repo.persisted[-1].strike_count == 2


@pytest.mark.parametrize("status", [Status.QUARANTINED, Status.STALE, Status.ARCHIVED])
def test_check_validated_refuses_a_row_that_is_not_validated(status: Status) -> None:
    """A fabricated `current` makes `apply()` a rubber stamp: handing this a quarantined row
    previously wrote `validated -> stale` for it, an edge PLAN.md §5's table does not have
    and the machine never saw the row's real status for."""
    row = _row(1, status=status, last_retrieved_at=EPOCH)
    repo = _FakeRepo([row])
    worker = RevalidationWorker(repo, FakeClock(EPOCH + timedelta(days=30)))

    with pytest.raises(TracebedError, match="not 'validated'"):
        worker.check_validated(
            PROJECT, row, verifier=_FakeVerifier(default=False), cfg=_effective_config()
        )
    assert repo.persisted == []


@pytest.mark.parametrize("status", [Status.VALIDATED, Status.CANDIDATE])
def test_check_stale_refuses_a_row_that_is_not_stale(status: Status) -> None:
    row = _row(1, status=status, last_retrieved_at=EPOCH, strike_count=5)
    repo = _FakeRepo([row])
    worker = RevalidationWorker(repo, FakeClock(EPOCH))

    with pytest.raises(TracebedError, match="not 'stale'"):
        worker.check_stale(
            PROJECT, row, verifier=_FakeVerifier(default=False), cfg=_effective_config()
        )
    assert repo.persisted == []


# --------------------------------------------------------------------------- #
# Invariant 4 at the revalidation seam (integration audit)
# --------------------------------------------------------------------------- #

_OTHER_PROJECT = ProjectId(uuid4())


def _foreign_row(tag: int, *, status: Status) -> LifecycleMemoryRow:
    return LifecycleMemoryRow(
        id=_mid(tag),
        project_id=_OTHER_PROJECT,
        status=status,
        trust_tier=TrustTier.B,
        mem_type=MemType.LESSON,
        provenance=Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(RunId(uuid4()),)),
        status_changed_at=EPOCH,
        strike_count=1,
        last_retrieved_at=None,
        created_at=EPOCH,
    )


@pytest.mark.parametrize("status", [Status.VALIDATED, Status.STALE])
def test_a_row_from_another_project_is_refused_with_nothing_written(status: Status) -> None:
    """`sweeps` and `invalidator` both re-assert project scope on every row
    `MemoryLifecycleRepoPort` hands back; revalidation was the one lifecycle
    worker of the three that did not, which no per-chunk audit could see
    because each read only its own module.

    It matters most here: `check_stale` RETIRES on the second strike, so a
    foreign-project row reaching this worker is another project's memory
    retired by this project's verifier, with the write then routed to
    `persist(project_id, ...)` -- the wrong partition -- so the row an
    operator went looking for would not be the row that changed.
    """
    row = _foreign_row(1, status=status)
    repo = _FakeRepo([row])
    worker = RevalidationWorker(repo, FakeClock(EPOCH + timedelta(days=90)))
    check = worker.check_validated if status is Status.VALIDATED else worker.check_stale

    with pytest.raises(TracebedError):
        check(PROJECT, row, verifier=_FakeVerifier(default=False), cfg=_effective_config())

    assert repo.persisted == []


@pytest.mark.parametrize("status", [Status.VALIDATED, Status.STALE])
def test_the_same_row_in_the_callers_own_project_is_processed(status: Status) -> None:
    """Guard the guard: the refusal above must be about the project, not about
    anything else in the fixture."""
    row = _row(
        1,
        status=status,
        last_retrieved_at=None,
        strike_count=1 if status is Status.STALE else 0,
    )
    repo = _FakeRepo([row])
    worker = RevalidationWorker(repo, FakeClock(EPOCH + timedelta(days=90)))
    check = worker.check_validated if status is Status.VALIDATED else worker.check_stale

    outcome = check(PROJECT, row, verifier=_FakeVerifier(default=False), cfg=_effective_config())

    assert outcome.to_status is not None
    assert len(repo.persisted) == 1
