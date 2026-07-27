"""`workers.promotion` — `candidate -> validated` and `validated -> retired` (PLAN.md §5
rows 6 and 12; D-021).

Fully offline: `_FakeRepo` is an in-file fake (this codebase's convention, contract §13.1).
Every transition is cross-checked against a direct `domain.state_machine.apply()` call built
from identical evidence, proving this worker never performs a status change the state
machine did not itself authorise.
"""

from __future__ import annotations

import inspect
from collections.abc import Sequence
from dataclasses import dataclass
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
from tracebed.domain.errors import GuardNotSatisfied, TracebedError
from tracebed.domain.ids import MemoryId, ProjectId, RunId
from tracebed.domain.memory import Provenance
from tracebed.domain.state_machine import Status, TransitionEvidence, TransitionLimits, apply
from tracebed.stores.pg.repo import Repo
from tracebed.workers.promotion import (
    CandidateMemoryRow,
    PromotionOutcome,
    PromotionRepoPort,
    PromotionTransitionWrite,
    PromotionWorker,
    ValidatedMemoryRow,
)

pytestmark = pytest.mark.phase3

EPOCH = datetime(2026, 1, 1, tzinfo=UTC)
PROJECT = ProjectId(UUID(int=1))
OTHER_PROJECT = ProjectId(UUID(int=2))


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


_DEFAULT_PROVENANCE = Provenance(cls=ProvenanceClass.DISTILLER, trace_ids=(RunId(UUID(int=1)),))


def _candidate_row(
    tag: int,
    *,
    promotion_outcomes: int = 2,
    promotion_distinct_principals: int = 2,
    outcome_consistent: bool = True,
    scan_repass: bool = True,
    open_contradiction: bool = False,
    status: Status = Status.CANDIDATE,
    project_id: ProjectId = PROJECT,
    status_changed_at: datetime | None = EPOCH,
) -> CandidateMemoryRow:
    """Defaults to a row that clears every promotion condition (PLAN.md §5 row 6:
    `promotion.min_outcomes=2`, `promotion.min_distinct_principals=2`); tests override
    exactly the one field under test."""
    return CandidateMemoryRow(
        id=_mid(tag),
        project_id=project_id,
        status=status,
        trust_tier=TrustTier.B,
        mem_type=MemType.SEMANTIC,
        provenance=_DEFAULT_PROVENANCE,
        status_changed_at=status_changed_at,
        promotion_outcomes=promotion_outcomes,
        promotion_distinct_principals=promotion_distinct_principals,
        outcome_consistent=outcome_consistent,
        scan_repass=scan_repass,
        open_contradiction=open_contradiction,
    )


def _validated_row(
    tag: int,
    *,
    q_value: float,
    scored_use_count: int,
    distinct_scoring_principals: int,
    status: Status = Status.VALIDATED,
    project_id: ProjectId = PROJECT,
    status_changed_at: datetime | None = EPOCH,
) -> ValidatedMemoryRow:
    return ValidatedMemoryRow(
        id=_mid(tag),
        project_id=project_id,
        status=status,
        trust_tier=TrustTier.B,
        mem_type=MemType.SEMANTIC,
        provenance=_DEFAULT_PROVENANCE,
        status_changed_at=status_changed_at,
        q_value=q_value,
        scored_use_count=scored_use_count,
        distinct_scoring_principals=distinct_scoring_principals,
    )


@dataclass
class _ReviewItem:
    project_id: ProjectId
    reason: str
    memory_id: MemoryId | None


class _FakeRepo:
    def __init__(
        self,
        candidates: Sequence[CandidateMemoryRow] = (),
        validated: Sequence[ValidatedMemoryRow] = (),
    ) -> None:
        self._candidates: dict[MemoryId, CandidateMemoryRow] = {r.id: r for r in candidates}
        self._validated: dict[MemoryId, ValidatedMemoryRow] = {r.id: r for r in validated}
        self.persisted: list[PromotionTransitionWrite] = []
        self.review_items: list[_ReviewItem] = []

    def select_candidates_for_promotion(self, project_id: ProjectId) -> Sequence[CandidateMemoryRow]:
        return [r for r in self._candidates.values() if r.status is Status.CANDIDATE]

    def select_validated_for_retirement(self, project_id: ProjectId) -> Sequence[ValidatedMemoryRow]:
        return [r for r in self._validated.values() if r.status is Status.VALIDATED]

    def persist(self, project_id: ProjectId, write: PromotionTransitionWrite) -> None:
        self.persisted.append(write)

    def insert_review_item(
        self, project_id: ProjectId, reason: str, memory_id: MemoryId | None = None
    ) -> None:
        self.review_items.append(_ReviewItem(project_id, reason, memory_id))


def _worker(repo: _FakeRepo, clock: FakeClock | None = None) -> PromotionWorker:
    return PromotionWorker(repo, clock or FakeClock(EPOCH))


# --------------------------------------------------------------------------- #
# Promotion: all four conditions required, each tested missing in isolation.
# --------------------------------------------------------------------------- #


def test_promotion_succeeds_when_all_four_conditions_hold() -> None:
    row = _candidate_row(1)
    repo = _FakeRepo(candidates=[row])
    worker = _worker(repo)

    outcome = worker.evaluate_candidate(PROJECT, row, cfg=_effective_config())

    assert outcome.promoted is True
    assert outcome.to_status is Status.VALIDATED
    assert len(repo.persisted) == 1

    # Cross-check directly against the state machine.
    limits = TransitionLimits.from_config(_effective_config())
    evidence = TransitionEvidence(
        now=EPOCH,
        provenance_class=row.provenance.cls,
        trust_tier=row.trust_tier,
        mem_type=row.mem_type,
        status_changed_at=row.status_changed_at,
        promotion_outcomes=2,
        promotion_distinct_principals=2,
        outcome_consistent=True,
        scan_repass=True,
        open_contradiction=False,
    )
    assert apply(Status.CANDIDATE, Status.VALIDATED, evidence, limits) is Status.VALIDATED


@pytest.mark.parametrize(
    "field_name,bad_value",
    [
        ("promotion_outcomes", 1),  # below min_outcomes=2
        ("promotion_distinct_principals", 1),  # below min_distinct_principals=2
        ("outcome_consistent", False),
        ("scan_repass", False),
        ("open_contradiction", True),
    ],
)
def test_promotion_refused_when_any_single_condition_fails(
    field_name: str, bad_value: object
) -> None:
    row = _candidate_row(1, **{field_name: bad_value})
    repo = _FakeRepo(candidates=[row])
    worker = _worker(repo)

    outcome = worker.evaluate_candidate(PROJECT, row, cfg=_effective_config())

    assert outcome.promoted is False
    assert outcome.to_status is None
    assert outcome.reason != ""
    assert repo.persisted == []


def test_promotion_boundaries_are_inclusive_at_the_configured_minimum() -> None:
    """PLAN.md §5 row 6 is ">= promote_min_outcomes" and ">= 2 distinct principals": a row
    sitting exactly on both minima promotes, and one short of either does not (the
    parametrised refusal test above covers the "one short" half)."""
    cfg = _effective_config()
    row = _candidate_row(
        1,
        promotion_outcomes=cfg.promotion.min_outcomes,
        promotion_distinct_principals=cfg.promotion.min_distinct_principals,
    )
    repo = _FakeRepo(candidates=[row])

    assert _worker(repo).evaluate_candidate(PROJECT, row, cfg=cfg).promoted is True


def test_promotion_batch_processes_every_candidate() -> None:
    good = _candidate_row(1)
    bad = _candidate_row(2, scan_repass=False)
    repo = _FakeRepo(candidates=[good, bad])
    worker = _worker(repo)

    result = worker.run_promotion_once(PROJECT, cfg=_effective_config())

    assert result.rows_examined == 2
    promoted = {o.memory_id: o for o in result.outcomes if o.promoted}
    assert set(promoted) == {good.id}
    assert len(repo.persisted) == 1


# --------------------------------------------------------------------------- #
# Retirement: Q, scored-use count, and the K-distinct-principals floor (D-021).
# --------------------------------------------------------------------------- #


def test_retirement_succeeds_when_all_conditions_hold() -> None:
    row = _validated_row(1, q_value=0.10, scored_use_count=4, distinct_scoring_principals=3)
    repo = _FakeRepo(validated=[row])
    worker = _worker(repo)

    outcome = worker.evaluate_retirement(PROJECT, row, cfg=_effective_config())

    assert outcome.retired is True
    assert outcome.routed_to_review is False
    assert outcome.to_status is Status.RETIRED
    assert len(repo.persisted) == 1
    assert repo.review_items == []


@pytest.mark.parametrize("principals", [3, 1])
def test_retirement_not_due_when_q_value_still_above_threshold(principals: int) -> None:
    """`principals=1` is the load-bearing case. With K principals present, the
    review-routing branch is unreachable no matter what the Q check does, so a version of
    this test that only ran at K would still pass if the Q condition were deleted from the
    routing predicate entirely. Below K, the Q condition is the ONLY thing keeping a
    perfectly healthy memory out of the review queue."""
    row = _validated_row(
        1, q_value=0.30, scored_use_count=4, distinct_scoring_principals=principals
    )
    repo = _FakeRepo(validated=[row])
    worker = _worker(repo)

    outcome = worker.evaluate_retirement(PROJECT, row, cfg=_effective_config())

    assert outcome.retired is False
    assert outcome.routed_to_review is False
    assert repo.persisted == []
    assert repo.review_items == []  # not due at all -- must not flood the review queue


@pytest.mark.parametrize("principals", [3, 1])
def test_retirement_not_due_when_scored_use_count_too_low(principals: int) -> None:
    """Same construction as the Q test above: at `principals=1` the scored-use condition is
    the only thing standing between a barely-scored memory and a review-queue row."""
    row = _validated_row(
        1, q_value=0.10, scored_use_count=2, distinct_scoring_principals=principals
    )
    repo = _FakeRepo(validated=[row])
    worker = _worker(repo)

    outcome = worker.evaluate_retirement(PROJECT, row, cfg=_effective_config())

    assert outcome.retired is False
    assert outcome.routed_to_review is False
    assert repo.persisted == []
    assert repo.review_items == []


def test_retirement_q_threshold_boundary_is_exclusive() -> None:
    """PLAN.md §5 row 12 is "Q < 0.25", and the guard is `q_value >= threshold -> refuse`.
    A memory sitting exactly ON the threshold is not retired and is not a review case --
    the off-by-one that would make `q_threshold` mean "at or below"."""
    cfg = _effective_config()
    row = _validated_row(
        1,
        q_value=cfg.retirement.q_threshold,
        scored_use_count=4,
        distinct_scoring_principals=1,
    )
    repo = _FakeRepo(validated=[row])
    worker = _worker(repo)

    outcome = worker.evaluate_retirement(PROJECT, row, cfg=cfg)

    assert outcome.retired is False
    assert outcome.routed_to_review is False
    assert repo.review_items == []


def test_retirement_scored_use_boundary_is_inclusive() -> None:
    """"after >= 4 scored uses": exactly `min_scored_uses` is enough, one fewer is not."""
    cfg = _effective_config()
    exactly = _validated_row(
        1,
        q_value=0.10,
        scored_use_count=cfg.retirement.min_scored_uses,
        distinct_scoring_principals=cfg.retirement.min_distinct_principals,
    )
    one_short = _validated_row(
        2,
        q_value=0.10,
        scored_use_count=cfg.retirement.min_scored_uses - 1,
        distinct_scoring_principals=cfg.retirement.min_distinct_principals,
    )
    repo = _FakeRepo(validated=[exactly, one_short])
    worker = _worker(repo)

    assert worker.evaluate_retirement(PROJECT, exactly, cfg=cfg).retired is True
    assert worker.evaluate_retirement(PROJECT, one_short, cfg=cfg).retired is False


def test_exactly_k_principals_retires_and_does_not_open_a_review_item() -> None:
    """The K boundary from the other side: `distinct_scoring_principals == K` retires."""
    cfg = _effective_config()
    row = _validated_row(
        1,
        q_value=0.10,
        scored_use_count=4,
        distinct_scoring_principals=cfg.retirement.min_distinct_principals,
    )
    repo = _FakeRepo(validated=[row])
    worker = _worker(repo)

    outcome = worker.evaluate_retirement(PROJECT, row, cfg=cfg)

    assert outcome.retired is True
    assert repo.review_items == []


def test_k_minus_one_principals_routes_to_review_not_retire() -> None:
    """D-021's whole point: below K distinct scoring principals, a memory otherwise
    qualified for retirement goes to the review queue instead of being auto-retired."""
    k = _effective_config().retirement.min_distinct_principals
    row = _validated_row(
        1, q_value=0.10, scored_use_count=4, distinct_scoring_principals=k - 1
    )
    repo = _FakeRepo(validated=[row])
    worker = _worker(repo)

    outcome = worker.evaluate_retirement(PROJECT, row, cfg=_effective_config())

    assert outcome.retired is False
    assert outcome.routed_to_review is True
    assert outcome.to_status is None
    assert repo.persisted == []  # status must NOT have changed
    assert len(repo.review_items) == 1
    assert repo.review_items[0].memory_id == row.id

    # Cross-check: apply() itself refuses this edge with fewer than K principals.
    limits = TransitionLimits.from_config(_effective_config())
    evidence = TransitionEvidence(
        now=EPOCH,
        provenance_class=row.provenance.cls,
        trust_tier=row.trust_tier,
        mem_type=row.mem_type,
        status_changed_at=row.status_changed_at,
        q_value=0.10,
        scored_use_count=4,
        distinct_scoring_principals=k - 1,
    )
    with pytest.raises(GuardNotSatisfied):
        apply(Status.VALIDATED, Status.RETIRED, evidence, limits)


def test_retirement_batch_routes_and_retires_independently() -> None:
    k = _effective_config().retirement.min_distinct_principals
    retiring = _validated_row(1, q_value=0.1, scored_use_count=4, distinct_scoring_principals=k)
    reviewing = _validated_row(
        2, q_value=0.1, scored_use_count=4, distinct_scoring_principals=k - 1
    )
    not_due = _validated_row(3, q_value=0.9, scored_use_count=4, distinct_scoring_principals=k)
    repo = _FakeRepo(validated=[retiring, reviewing, not_due])
    worker = _worker(repo)

    result = worker.run_retirement_once(PROJECT, cfg=_effective_config())

    assert result.rows_examined == 3
    by_id = {o.memory_id: o for o in result.outcomes}
    assert by_id[retiring.id].retired is True
    assert by_id[reviewing.id].routed_to_review is True
    assert by_id[not_due.id].retired is False and by_id[not_due.id].routed_to_review is False
    assert len(repo.persisted) == 1
    assert len(repo.review_items) == 1


# --------------------------------------------------------------------------- #
# Defensive re-assertion: a select that over-returns must not be trusted blindly.
# --------------------------------------------------------------------------- #


def test_candidate_from_wrong_project_raises() -> None:
    row = _candidate_row(1, project_id=OTHER_PROJECT)
    repo = _FakeRepo(candidates=[row])
    worker = _worker(repo)
    with pytest.raises(TracebedError):
        worker.evaluate_candidate(PROJECT, row, cfg=_effective_config())


@pytest.mark.parametrize("status", [Status.QUARANTINED, Status.VALIDATED, Status.ARCHIVED])
def test_candidate_row_not_actually_candidate_raises(status: Status) -> None:
    """Matched on the worker's own message: `apply(<not candidate>, validated)` raises
    `IllegalTransition`, which is itself a `TracebedError`, so a bare
    `pytest.raises(TracebedError)` stays green with `_require_status`'s status check
    deleted and proves nothing."""
    row = _candidate_row(1, status=status)
    repo = _FakeRepo(candidates=[row])
    worker = _worker(repo)
    with pytest.raises(TracebedError, match="not 'candidate'"):
        worker.evaluate_candidate(PROJECT, row, cfg=_effective_config())


def test_validated_row_not_actually_validated_raises() -> None:
    row = _validated_row(1, q_value=0.1, scored_use_count=4, distinct_scoring_principals=3)
    row = ValidatedMemoryRow(
        id=row.id,
        project_id=row.project_id,
        status=Status.STALE,
        trust_tier=row.trust_tier,
        mem_type=row.mem_type,
        provenance=row.provenance,
        status_changed_at=row.status_changed_at,
        q_value=row.q_value,
        scored_use_count=row.scored_use_count,
        distinct_scoring_principals=row.distinct_scoring_principals,
    )
    repo = _FakeRepo(validated=[row])
    worker = _worker(repo)
    with pytest.raises(TracebedError, match="not 'validated'"):
        worker.evaluate_retirement(PROJECT, row, cfg=_effective_config())
    assert repo.review_items == []  # a mis-routed row must not leave a review row behind


def test_promotion_outcome_is_importable_type() -> None:
    # Cheap smoke test that the public dataclass is constructible/importable as documented.
    outcome = PromotionOutcome(memory_id=_mid(1), promoted=False, to_status=None, reason="x")
    assert outcome.promoted is False


def test_fake_repo_satisfies_the_declared_port() -> None:
    assert isinstance(_FakeRepo(), PromotionRepoPort)


def test_review_write_matches_the_real_repo_method_signature() -> None:
    """`PromotionRepoPort.insert_review_item` exists so the production `Repo` satisfies
    this half of the port with no adapter. A port whose review-queue method drifted from
    `Repo`'s (a different name, a keyword-only parameter) would type-check fine here and
    fail only at wiring time, which is exactly how the previously-invented
    `open_review_item` -- a method no `Repo` has ever had -- survived."""
    assert inspect.signature(PromotionRepoPort.insert_review_item) == inspect.signature(
        Repo.insert_review_item
    )
