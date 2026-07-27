"""`workers.corroboration` — the shadow-confirmation writer (PLAN.md §2 invariant 7; §5 row
4; M6, docs/FIDELITY-AUDIT.md / PLAN.md §11.1).

Fully offline: `_FakeRepo` and `_FakeSource` are in-file fakes (this codebase's convention,
contract §13.1). The end-to-end section wires the real `workers.shadow_validator.
ShadowValidator` on top of a shared in-memory row to prove this writer's output is exactly
what that worker needs to promote on genuine independence and refuse on correlation --
without this module reimplementing (or even importing) any independence logic itself.

Every fake below models the store contract `CorroborationRepoPort.append_confirming_run`
documents, INCLUDING its third outcome: a row that is no longer quarantined (or not in the
project) reports `ROW_NOT_ELIGIBLE` rather than silently behaving like an already-present
run. A fake that could only ever return the two happy outcomes would make
`test_a_row_that_left_quarantine_between_select_and_append_is_not_reported_as_recorded`
unable to fail, which is the specific defect this suite is written against.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID

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
from tracebed.domain.ids import MemoryId, PrincipalId, ProjectId, RunId
from tracebed.domain.memory import Provenance
from tracebed.domain.state_machine import MAX_CONFIRMATIONS_CONSIDERED, Status
from tracebed.workers.corroboration import (
    AppendOutcome,
    CorroborationRepoPort,
    CorroborationWriter,
    QuarantinedMemoryForCorroboration,
)
from tracebed.workers.epochs import ScoringEpoch
from tracebed.workers.independence import ConfirmingRun
from tracebed.workers.shadow_validator import (
    QuarantinedMemoryRow,
    ShadowTransitionWrite,
    ShadowValidator,
)

pytestmark = pytest.mark.phase3

EPOCH = datetime(2026, 1, 1, tzinfo=UTC)
PROJECT = ProjectId(UUID(int=1))
OTHER_PROJECT = ProjectId(UUID(int=2))

# The run a memory was DISTILLED FROM -- never reused as an "offered" confirming run in the
# arithmetic tests, exactly like `tests/phase3/test_shadow_validation.py::_ORIGIN`.
_ORIGIN = 900


def _mid(tag: int) -> MemoryId:
    return MemoryId(UUID(int=tag))


def _run(tag: int) -> RunId:
    return RunId(UUID(int=tag))


def _principal(tag: int) -> PrincipalId:
    return PrincipalId(UUID(int=tag))


def _far_cluster(tag: int) -> int:
    """A cluster id pairwise far from every other `_far_cluster` value -- see
    `tests/phase3/test_independence.py::_far_cluster` for why small ints will not do."""
    return int.from_bytes(hashlib.sha256(f"cluster:{tag}".encode()).digest()[:8], "big")


def _sig(cluster: int) -> bytes:
    return (b"\x00" * 32) + cluster.to_bytes(8, "big")


_CLUSTER_A = 0x0000000000000000
_CLUSTER_B = 0xFFFFFFFFFFFFFFFF

_DISTILLED = Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(_run(_ORIGIN),))


def _row(
    tag: int,
    *,
    provenance: Provenance = _DISTILLED,
    confirming_run_ids: tuple[RunId, ...] = (),
    status: Status = Status.QUARANTINED,
    project_id: ProjectId = PROJECT,
) -> QuarantinedMemoryForCorroboration:
    return QuarantinedMemoryForCorroboration(
        id=_mid(tag),
        project_id=project_id,
        status=status,
        provenance=provenance,
        confirming_run_ids=confirming_run_ids,
    )


class _FakeRepo:
    """Backs `shadow_confirm_runs` with a plain `dict[MemoryId, list[RunId]]`.

    The three `AppendOutcome` values are all reachable: eligibility is re-derived from the
    fake's own row table at append time (not from the snapshot the caller holds), so a test
    that mutates `rows` after handing a snapshot out gets the same `ROW_NOT_ELIGIBLE` a
    concurrent quarantine-TTL sweep would produce against real SQL. Idempotency is real here
    (a `list` membership check inside one synchronous call), which is what lets the tests
    below assert on it directly -- the docstring on
    `CorroborationRepoPort.append_confirming_run` is what a REAL (Postgres) implementation
    must uphold instead; this fake stands in for that contract without exercising SQL.
    """

    def __init__(self, rows: Sequence[QuarantinedMemoryForCorroboration]) -> None:
        self.rows: dict[MemoryId, QuarantinedMemoryForCorroboration] = {r.id: r for r in rows}
        self.confirmed: dict[MemoryId, list[RunId]] = {
            r.id: list(r.confirming_run_ids) for r in rows
        }
        self.append_calls: list[tuple[MemoryId, RunId]] = []

    def select_quarantined(
        self, project_id: ProjectId
    ) -> Sequence[QuarantinedMemoryForCorroboration]:
        return [
            r
            for r in self.rows.values()
            if r.project_id == project_id and r.status is Status.QUARANTINED
        ]

    def append_confirming_run(
        self, project_id: ProjectId, memory_id: MemoryId, run_id: RunId
    ) -> AppendOutcome:
        self.append_calls.append((memory_id, run_id))
        live = self.rows.get(memory_id)
        if live is None or live.project_id != project_id or live.status is not Status.QUARANTINED:
            return AppendOutcome.ROW_NOT_ELIGIBLE
        bucket = self.confirmed.setdefault(memory_id, [])
        if run_id in bucket:
            return AppendOutcome.ALREADY_PRESENT
        bucket.append(run_id)
        return AppendOutcome.APPENDED


class _OverReturningRepo(_FakeRepo):
    """A store whose `(project_id, status = 'quarantined')` predicate has stopped holding.

    Subclassed rather than monkeypatched so the over-returning select is a real, typed
    implementation of the port -- the failure mode `_require_row` exists for is a store that
    is WRONG, not a store that is absent.
    """

    def __init__(
        self,
        rows: Sequence[QuarantinedMemoryForCorroboration],
        returned: Sequence[QuarantinedMemoryForCorroboration],
    ) -> None:
        super().__init__(rows)
        self._returned = tuple(returned)

    def select_quarantined(
        self, project_id: ProjectId
    ) -> Sequence[QuarantinedMemoryForCorroboration]:
        return self._returned


@dataclass
class _FakeSource:
    offered: dict[MemoryId, tuple[RunId, ...]] = field(default_factory=dict)
    consulted: list[MemoryId] = field(default_factory=list)

    def candidate_runs(
        self, project_id: ProjectId, row: QuarantinedMemoryForCorroboration
    ) -> Sequence[RunId]:
        self.consulted.append(row.id)
        return self.offered.get(row.id, ())


def _worker(repo: CorroborationRepoPort) -> CorroborationWriter:
    return CorroborationWriter(repo)


def _effective_config() -> EffectiveConfig:
    return EffectiveConfig(
        retrieval=RetrievalConfig(),
        abstention=AbstentionConfig(),
        score=ScoreConfig(),
        budget=BudgetConfig(),
        scoring=ScoringConfig(),
        promotion=PromotionConfig(),
        retirement=RetirementConfig(),
        lifecycle=LifecycleConfig(),
        derived=DerivedConfig(),
        proposals=ProposalConfig(),
        tier_a=TierAConfig(),
        killswitch=KillswitchConfig(),
        spend=SpendConfig(),
        cache=CacheConfig(),
        session=SessionConfig(),
        queue=QueueConfig(),
    )


# --------------------------------------------------------------------------- #
# A memory cannot corroborate itself.
# --------------------------------------------------------------------------- #


def test_an_origin_run_is_never_appended() -> None:
    row = _row(1)
    repo = _FakeRepo([row])
    worker = _worker(repo)

    outcome = worker.record_one(PROJECT, row, _run(_ORIGIN))

    assert outcome.recorded is False
    assert outcome.newly_added is False
    assert "cannot corroborate itself" in outcome.reason
    assert repo.confirmed[row.id] == []
    # The repo is never even asked -- the origin exclusion is checked before any I/O.
    assert repo.append_calls == []


def test_proposal_run_id_is_also_an_origin_and_is_never_appended() -> None:
    row = _row(1, provenance=Provenance(cls=ProvenanceClass.PROPOSAL, run_id=_run(_ORIGIN)))
    repo = _FakeRepo([row])
    worker = _worker(repo)

    outcome = worker.record_one(PROJECT, row, _run(_ORIGIN))

    assert outcome.recorded is False
    assert repo.confirmed[row.id] == []


def test_a_store_that_folds_provenance_trace_ids_into_the_snapshot_still_refuses() -> None:
    """The sharper version: the origin run is already sitting in the row's own
    `confirming_run_ids` snapshot (a store that folded `provenance.trace_ids` in, exactly the
    scenario `workers.shadow_validator.origin_runs`'s docstring warns about). The "already
    recorded" fast path must not win over the self-corroboration refusal -- if it did, the
    outcome would report `recorded=True` for a memory's own origin trace."""
    row = _row(1, confirming_run_ids=(_run(_ORIGIN),))
    repo = _FakeRepo([row])
    worker = _worker(repo)

    outcome = worker.record_one(PROJECT, row, _run(_ORIGIN))

    assert outcome.recorded is False
    assert "cannot corroborate itself" in outcome.reason


def test_an_origin_run_is_refused_even_when_the_row_is_already_at_the_cap() -> None:
    """The growth cap must not become a way to change the ANSWER for an origin run. At the
    cap the two refusals give the same `recorded=False`, so only the reason distinguishes
    them -- and an origin run must be refused as self-corroboration, never as "the array is
    full", because the second reason is transient and an operator reading it would be told
    to retry a write invariant 7 forbids outright."""
    already = tuple(_run(i) for i in range(MAX_CONFIRMATIONS_CONSIDERED))
    row = _row(1, confirming_run_ids=already)
    repo = _FakeRepo([row])
    worker = _worker(repo)

    outcome = worker.record_one(PROJECT, row, _run(_ORIGIN))

    assert outcome.recorded is False
    assert "cannot corroborate itself" in outcome.reason
    assert "MAX_CONFIRMATIONS_CONSIDERED" not in outcome.reason


# --------------------------------------------------------------------------- #
# Idempotent append.
# --------------------------------------------------------------------------- #


def test_appending_the_same_run_twice_yields_one_entry() -> None:
    row = _row(1)
    repo = _FakeRepo([row])
    worker = _worker(repo)

    first = worker.record_one(PROJECT, row, _run(1))
    second = worker.record_one(PROJECT, row, _run(1))

    assert first.recorded is True
    assert first.newly_added is True
    assert second.recorded is True
    assert second.newly_added is False
    assert repo.confirmed[row.id] == [_run(1)]


def test_two_workers_observing_the_same_run_do_not_double_count_it() -> None:
    """Simulates two worker processes racing the SAME candidate confirmation against a
    SHARED store: both call through to the repo (each has its own row snapshot, so neither
    takes the "already recorded" fast path), and the repo's own idempotency -- the contract
    `CorroborationRepoPort.append_confirming_run` documents -- is what stops the duplicate,
    not any coordination between the two `CorroborationWriter` instances."""
    row = _row(1)
    repo = _FakeRepo([row])
    worker_a = _worker(repo)
    worker_b = _worker(repo)

    outcome_a = worker_a.record_one(PROJECT, row, _run(5))
    outcome_b = worker_b.record_one(PROJECT, row, _run(5))

    assert {outcome_a.newly_added, outcome_b.newly_added} == {True, False}
    assert outcome_a.recorded is True
    assert outcome_b.recorded is True
    assert repo.confirmed[row.id] == [_run(5)]
    assert repo.append_calls == [(row.id, _run(5)), (row.id, _run(5))]


def test_a_row_that_left_quarantine_between_select_and_append_is_not_reported_as_recorded() -> (
    None
):
    """The race the third `AppendOutcome` exists for: this worker holds a snapshot saying
    `quarantined`, and by the time the append runs the quarantine-TTL sweep has archived the
    row. The store's eligibility predicate lives in the same statement as the mutation, so
    nothing is written -- and the outcome must say so. Folding this into "already present"
    (the shape a `bool` return forces) would report a governance write as recorded for a
    memory that is no longer in quarantine and never will be again."""
    row = _row(1)
    repo = _FakeRepo([row])
    worker = _worker(repo)

    # The sweep commits between the caller's select and this worker's append.
    repo.rows[row.id] = _row(1, status=Status.ARCHIVED)

    outcome = worker.record_one(PROJECT, row, _run(3))

    assert outcome.recorded is False
    assert outcome.newly_added is False
    assert "nothing was recorded" in outcome.reason
    assert repo.confirmed[row.id] == []
    # It was ATTEMPTED -- the refusal came from the store, not from the stale snapshot.
    assert repo.append_calls == [(row.id, _run(3))]


# --------------------------------------------------------------------------- #
# Independence is judged later, not here.
# --------------------------------------------------------------------------- #


def test_two_runs_that_will_prove_correlated_are_both_still_recorded() -> None:
    """`CorroborationWriter` has no principal or cluster concept at all -- it never imports
    `workers.independence` or `domain.state_machine.ShadowConfirmation`, and no lookup is
    reachable from it, so there is nothing here that COULD refuse correlated evidence. This
    test pins that recording is unconditional on independence; the claim that these same two
    runs then fail to promote is made where it can actually be checked, against the real
    `ShadowValidator` with a real principal lookup, in the end-to-end section below."""
    row = _row(1)
    repo = _FakeRepo([row])
    worker = _worker(repo)

    first = worker.record_one(PROJECT, row, _run(11))
    second = worker.record_one(PROJECT, row, _run(12))

    assert first.recorded is True
    assert second.recorded is True
    assert set(repo.confirmed[row.id]) == {_run(11), _run(12)}


# --------------------------------------------------------------------------- #
# Quarantined rows only.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("status", [Status.CANDIDATE, Status.VALIDATED, Status.ARCHIVED])
def test_non_quarantined_row_raises(status: Status) -> None:
    row = _row(1, status=status)
    repo = _FakeRepo([row])
    worker = _worker(repo)
    with pytest.raises(TracebedError, match="not 'quarantined'"):
        worker.record_one(PROJECT, row, _run(1))
    assert repo.append_calls == []


def test_wrong_project_row_raises() -> None:
    row = _row(1, project_id=OTHER_PROJECT)
    repo = _FakeRepo([row])
    worker = _worker(repo)
    with pytest.raises(TracebedError, match="outside the requested project"):
        worker.record_one(PROJECT, row, _run(1))
    assert repo.append_calls == []


# --------------------------------------------------------------------------- #
# Unbounded growth guard (reuses MAX_CONFIRMATIONS_CONSIDERED; never invents a new bound).
# --------------------------------------------------------------------------- #


def test_growth_is_capped_at_max_confirmations_considered() -> None:
    already = tuple(_run(i) for i in range(MAX_CONFIRMATIONS_CONSIDERED))
    row = _row(1, confirming_run_ids=already)
    repo = _FakeRepo([row])
    worker = _worker(repo)

    outcome = worker.record_one(PROJECT, row, _run(MAX_CONFIRMATIONS_CONSIDERED + 1))

    assert outcome.recorded is False
    assert "MAX_CONFIRMATIONS_CONSIDERED" in outcome.reason
    assert repo.append_calls == []


def test_the_last_slot_below_the_cap_is_still_usable() -> None:
    """The boundary in the other direction. Without this, a cap written one too tight
    (`>= MAX - 1`) passes every other test in this file: the refusal tests still refuse and
    the small-batch tests never get near the bound. The array must be allowed to reach
    exactly `MAX_CONFIRMATIONS_CONSIDERED`, because that is precisely how many entries
    `domain.state_machine.independent_confirmations` reads -- a tighter writer-side cap would
    silently discard evidence the guard would have considered."""
    already = tuple(_run(i) for i in range(MAX_CONFIRMATIONS_CONSIDERED - 1))
    row = _row(1, confirming_run_ids=already)
    repo = _FakeRepo([row])
    worker = _worker(repo)

    outcome = worker.record_one(PROJECT, row, _run(MAX_CONFIRMATIONS_CONSIDERED + 1))

    assert outcome.recorded is True
    assert outcome.newly_added is True
    assert len(repo.confirmed[row.id]) == MAX_CONFIRMATIONS_CONSIDERED


def test_growth_guard_does_not_block_re_recording_an_already_present_run() -> None:
    """An already-recorded run must still short-circuit to `recorded=True` even once the
    memory has reached the cap -- the guard is about NEW growth, not about the existing
    entries becoming unre-confirmable."""
    already = tuple(_run(i) for i in range(MAX_CONFIRMATIONS_CONSIDERED))
    row = _row(1, confirming_run_ids=already)
    repo = _FakeRepo([row])
    worker = _worker(repo)

    outcome = worker.record_one(PROJECT, row, already[0])

    assert outcome.recorded is True
    assert outcome.newly_added is False
    assert repo.append_calls == []


# --------------------------------------------------------------------------- #
# Batch entry point.
# --------------------------------------------------------------------------- #


def test_run_once_records_every_offered_run_for_every_quarantined_row() -> None:
    row_a = _row(1)
    row_b = _row(2, provenance=Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(_run(_ORIGIN + 1),)))
    repo = _FakeRepo([row_a, row_b])
    worker = _worker(repo)
    source = _FakeSource(
        offered={
            row_a.id: (_run(1), _run(2)),
            row_b.id: (_run(3),),
        }
    )

    result = worker.run_once(PROJECT, source=source)

    assert result.rows_examined == 2
    assert len(result.outcomes) == 3
    assert all(o.recorded for o in result.outcomes)
    assert repo.confirmed[row_a.id] == [_run(1), _run(2)]
    assert repo.confirmed[row_b.id] == [_run(3)]


def test_run_once_caps_growth_within_a_single_batch() -> None:
    """The cap is a property of the COLUMN, so it has to hold across one sweep, not merely
    between sweeps. A candidate source that offers far more runs than the bound (an
    over-eager producer, or an attacker who can schedule runs) must leave the array at
    exactly `MAX_CONFIRMATIONS_CONSIDERED`. Re-handing `record_one` the pre-batch snapshot
    for every offered run makes the guard compare a constant against the bound and appends
    all of them; only advancing the snapshot as the batch writes keeps this true."""
    row = _row(1)
    repo = _FakeRepo([row])
    worker = _worker(repo)
    offered = tuple(_run(i) for i in range(1_000, 1_000 + MAX_CONFIRMATIONS_CONSIDERED + 50))
    source = _FakeSource(offered={row.id: offered})

    result = worker.run_once(PROJECT, source=source)

    assert len(repo.confirmed[row.id]) == MAX_CONFIRMATIONS_CONSIDERED
    assert sum(1 for o in result.outcomes if o.recorded) == MAX_CONFIRMATIONS_CONSIDERED
    refused = [o for o in result.outcomes if not o.recorded]
    assert len(refused) == 50
    assert all("MAX_CONFIRMATIONS_CONSIDERED" in o.reason for o in refused)
    # The cap is enforced BEFORE the round trip, not by the store rejecting the extras.
    assert len(repo.append_calls) == MAX_CONFIRMATIONS_CONSIDERED


def test_run_once_does_not_re_ask_the_store_about_a_run_offered_twice_in_one_batch() -> None:
    """Same mechanism as the cap, cheaper consequence: once a run is recorded, the advanced
    snapshot makes the "already present" fast path fire for the duplicate instead of paying a
    second round trip for an answer the batch already knows."""
    row = _row(1)
    repo = _FakeRepo([row])
    worker = _worker(repo)
    source = _FakeSource(offered={row.id: (_run(1), _run(1), _run(1))})

    result = worker.run_once(PROJECT, source=source)

    assert [o.newly_added for o in result.outcomes] == [True, False, False]
    assert all(o.recorded for o in result.outcomes)
    assert repo.append_calls == [(row.id, _run(1))]
    assert repo.confirmed[row.id] == [_run(1)]


def test_run_once_never_advances_the_snapshot_on_a_refused_append() -> None:
    """The snapshot may only record what the STORE confirmed. Here the row was quarantined
    when the batch selected it and has been archived by the time the appends run, so every
    attempt reports `ROW_NOT_ELIGIBLE`. If the batch advanced its snapshot on a refusal, the
    second offer of the same run would hit the "already present" fast path and report
    `recorded=True` for a run that is not on the row and never will be -- the same lie the
    third `AppendOutcome` exists to prevent, reintroduced one layer up."""
    row = _row(1)
    repo = _OverReturningRepo([_row(1, status=Status.ARCHIVED)], [row])
    worker = _worker(repo)
    source = _FakeSource(offered={row.id: (_run(1), _run(1))})

    result = worker.run_once(PROJECT, source=source)

    assert [o.recorded for o in result.outcomes] == [False, False]
    assert all("nothing was recorded" in o.reason for o in result.outcomes)
    assert repo.confirmed[row.id] == []
    # Both offers are genuinely attempted: only the store may say a run is present.
    assert repo.append_calls == [(row.id, _run(1)), (row.id, _run(1))]


def test_run_once_refuses_a_select_that_over_returns_a_foreign_project_row() -> None:
    """`CorroborationCandidateSource` is host-supplied third-party code. A store predicate
    that has stopped holding must not reach it: the row (and its provenance) belongs to
    another project, so merely CONSULTING the source about it is an invariant-4 disclosure,
    with no append required. The whole select is validated before any source call and before
    any write, so a broken predicate is a zero-write failure rather than a partial one."""
    good = _row(1)
    foreign = _row(2, project_id=OTHER_PROJECT)
    repo = _OverReturningRepo([good, foreign], [good, foreign])
    worker = _worker(repo)
    source = _FakeSource(offered={good.id: (_run(1),), foreign.id: (_run(2),)})

    with pytest.raises(TracebedError, match="outside the requested project"):
        worker.run_once(PROJECT, source=source)

    assert source.consulted == []
    assert repo.append_calls == []


def test_run_once_refuses_a_select_that_over_returns_a_non_quarantined_row() -> None:
    """The other half of the same over-returning select. `record_one`'s status re-assertion
    is not enough on the batch path on its own -- a row offering no candidate runs would
    never reach it -- so `run_once` checks every row up front."""
    good = _row(1)
    departed = _row(2, status=Status.CANDIDATE)
    repo = _OverReturningRepo([good, departed], [good, departed])
    worker = _worker(repo)
    source = _FakeSource(offered={good.id: (_run(1),)})

    with pytest.raises(TracebedError, match="not 'quarantined'"):
        worker.run_once(PROJECT, source=source)

    assert source.consulted == []
    assert repo.append_calls == []


# --------------------------------------------------------------------------- #
# End to end with the REAL `workers.shadow_validator.ShadowValidator`: this writer's output
# is exactly what that worker needs to promote on genuine independence and refuse on
# correlation, without this module reimplementing any independence logic itself.
# --------------------------------------------------------------------------- #


@dataclass
class _SharedMemoryRow:
    """The one piece of mutable state both fakes below read and write, standing in for a
    single `memory_item` row across two different repo ports -- exactly what a real Postgres
    row is for the two real repo implementations."""

    id: MemoryId
    project_id: ProjectId
    status: Status
    provenance: Provenance
    confirming_run_ids: list[RunId] = field(default_factory=list)


@dataclass
class _SharedCorroborationRepo:
    store: dict[MemoryId, _SharedMemoryRow]

    def select_quarantined(
        self, project_id: ProjectId
    ) -> Sequence[QuarantinedMemoryForCorroboration]:
        return [
            QuarantinedMemoryForCorroboration(
                id=r.id,
                project_id=r.project_id,
                status=r.status,
                provenance=r.provenance,
                confirming_run_ids=tuple(r.confirming_run_ids),
            )
            for r in self.store.values()
            if r.project_id == project_id and r.status is Status.QUARANTINED
        ]

    def append_confirming_run(
        self, project_id: ProjectId, memory_id: MemoryId, run_id: RunId
    ) -> AppendOutcome:
        row = self.store.get(memory_id)
        if row is None or row.project_id != project_id or row.status is not Status.QUARANTINED:
            return AppendOutcome.ROW_NOT_ELIGIBLE
        if run_id in row.confirming_run_ids:
            return AppendOutcome.ALREADY_PRESENT
        row.confirming_run_ids.append(run_id)
        return AppendOutcome.APPENDED


@dataclass
class _SharedShadowRepo:
    store: dict[MemoryId, _SharedMemoryRow]
    persisted: list[ShadowTransitionWrite] = field(default_factory=list)

    def select_quarantined(self, project_id: ProjectId) -> Sequence[QuarantinedMemoryRow]:
        return [
            QuarantinedMemoryRow(
                id=r.id,
                project_id=r.project_id,
                status=r.status,
                trust_tier=TrustTier.B,
                mem_type=MemType.SEMANTIC,
                provenance=r.provenance,
                status_changed_at=EPOCH,
                is_failure_lesson=False,
                confirming_run_ids=tuple(r.confirming_run_ids),
            )
            for r in self.store.values()
            if r.project_id == project_id and r.status is Status.QUARANTINED
        ]

    def persist(self, project_id: ProjectId, write: ShadowTransitionWrite) -> None:
        self.persisted.append(write)
        self.store[write.memory_id].status = write.to_status


@dataclass
class _SharedLookup:
    table: dict[RunId, ConfirmingRun] = field(default_factory=dict)

    def lookup(self, project_id: ProjectId, run_id: RunId) -> ConfirmingRun | None:
        return self.table.get(run_id)

    def add(self, run_id: RunId, principal_id: PrincipalId, cluster: int) -> None:
        self.table[run_id] = ConfirmingRun(run_id, principal_id, _sig(cluster))


_EPOCH_ROW = ScoringEpoch(
    epoch_id=1,
    judge_model_id="gemini-3.1-pro",
    judge_model_version="2026-07-01",
    sampling_params={"temperature": 0},
    prompt_hash="deadbeef",
    started_at=EPOCH,
)


def test_end_to_end_two_independent_confirmations_reach_candidate() -> None:
    memory_id = _mid(1)
    store = {
        memory_id: _SharedMemoryRow(
            id=memory_id,
            project_id=PROJECT,
            status=Status.QUARANTINED,
            provenance=_DISTILLED,
        )
    }
    corroboration_repo = _SharedCorroborationRepo(store)
    corroboration_writer = CorroborationWriter(corroboration_repo)

    row = corroboration_repo.select_quarantined(PROJECT)[0]
    corroboration_writer.record_one(PROJECT, row, _run(1))
    corroboration_writer.record_one(PROJECT, row, _run(2))

    lookup = _SharedLookup()
    lookup.add(_run(1), _principal(1), cluster=_CLUSTER_A)
    lookup.add(_run(2), _principal(2), cluster=_CLUSTER_B)
    shadow_repo = _SharedShadowRepo(store)
    validator = ShadowValidator(shadow_repo, FakeClock(EPOCH), lookup, _EPOCH_ROW)

    shadow_row = shadow_repo.select_quarantined(PROJECT)[0]
    outcome = validator.evaluate_one(PROJECT, shadow_row, cfg=_effective_config())

    assert outcome.promoted is True
    assert outcome.to_status is Status.CANDIDATE
    assert store[memory_id].status is Status.CANDIDATE


def test_end_to_end_the_origin_run_this_writer_refused_would_have_promoted_alone() -> None:
    """Why the self-corroboration refusal is load-bearing rather than tidy. The memory is
    distilled from TWO traces with different principals and different input-signature
    clusters, so if this writer let those two origin runs be recorded they would clear
    `SHADOW_CONFIRM_MIN_INDEPENDENT` on their own -- a Tier B memory exiting quarantine at
    creation with zero observations that arrived after the content existed. The writer
    refuses both, the row's array stays empty, and the real `ShadowValidator` refuses."""
    memory_id = _mid(1)
    origin_a, origin_b = _run(_ORIGIN), _run(_ORIGIN + 1)
    store = {
        memory_id: _SharedMemoryRow(
            id=memory_id,
            project_id=PROJECT,
            status=Status.QUARANTINED,
            provenance=Provenance(
                cls=ProvenanceClass.DISTILLER, trace_ids=(origin_a, origin_b)
            ),
        )
    }
    corroboration_repo = _SharedCorroborationRepo(store)
    corroboration_writer = CorroborationWriter(corroboration_repo)

    row = corroboration_repo.select_quarantined(PROJECT)[0]
    for origin in (origin_a, origin_b):
        assert corroboration_writer.record_one(PROJECT, row, origin).recorded is False
    assert store[memory_id].confirming_run_ids == []

    lookup = _SharedLookup()
    lookup.add(origin_a, _principal(1), cluster=_CLUSTER_A)
    lookup.add(origin_b, _principal(2), cluster=_CLUSTER_B)
    shadow_repo = _SharedShadowRepo(store)
    validator = ShadowValidator(shadow_repo, FakeClock(EPOCH), lookup, _EPOCH_ROW)

    shadow_row = shadow_repo.select_quarantined(PROJECT)[0]
    outcome = validator.evaluate_one(PROJECT, shadow_row, cfg=_effective_config())

    assert outcome.promoted is False
    assert outcome.independent_count == 0
    assert store[memory_id].status is Status.QUARANTINED


def test_end_to_end_twenty_correlated_confirmations_stay_quarantined() -> None:
    """The same red-team shape as `test_shadow_validation
    .test_twenty_runs_one_principal_stays_quarantined`, but the twenty run ids are appended
    THROUGH `CorroborationWriter` rather than injected straight into the row -- proving this
    writer's recording of correlated evidence never, by itself, promotes anything."""
    memory_id = _mid(1)
    store = {
        memory_id: _SharedMemoryRow(
            id=memory_id,
            project_id=PROJECT,
            status=Status.QUARANTINED,
            provenance=_DISTILLED,
        )
    }
    corroboration_repo = _SharedCorroborationRepo(store)
    corroboration_writer = CorroborationWriter(corroboration_repo)

    row = corroboration_repo.select_quarantined(PROJECT)[0]
    lookup = _SharedLookup()
    for i in range(20):
        run_id = _run(i)
        # One Sybil principal, twenty genuinely distinct clusters -- the principal half of
        # D-020 is the only thing that can cap this at 1 independent confirmation.
        lookup.add(run_id, _principal(1), cluster=_far_cluster(i))
        outcome = corroboration_writer.record_one(PROJECT, row, run_id)
        assert outcome.recorded is True  # every one of the twenty is RECORDED

    assert len(store[memory_id].confirming_run_ids) == 20

    shadow_repo = _SharedShadowRepo(store)
    validator = ShadowValidator(shadow_repo, FakeClock(EPOCH), lookup, _EPOCH_ROW)
    shadow_row = shadow_repo.select_quarantined(PROJECT)[0]

    outcome = validator.evaluate_one(PROJECT, shadow_row, cfg=_effective_config())

    assert outcome.promoted is False
    assert outcome.independent_count == 1
    assert store[memory_id].status is Status.QUARANTINED
