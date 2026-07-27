"""workers.scorer: invariant 8, the corrected Q update.

Entirely offline: `ScorerRepoPort` and `ContributionJudgePort` are both
`Protocol`-typed and satisfied here by plain in-memory fakes -- no Postgres,
no LLM endpoint.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest

from tracebed.domain.clock import FakeClock
from tracebed.domain.config import ScoringConfig
from tracebed.domain.enums import AdapterClass
from tracebed.domain.errors import CrossEpochComparison
from tracebed.domain.ids import (
    MemoryId,
    PrincipalId,
    ProjectId,
    RunId,
    mint_memory_id,
    mint_run_id,
)
from tracebed.workers.contribution_judge import ContributionVerdict
from tracebed.workers.epochs import ScoringEpoch
from tracebed.workers.scorer import (
    ContributionJudgePort,
    QUpdate,
    ScoreBatchResult,
    ScorerRepoPort,
    ScoringEvent,
    ScoringInputInvalid,
    clamp01,
    compute_new_q,
    resolve_weight,
    run_scorer_batch,
    select_daily_winner,
)

pytestmark = pytest.mark.phase3

_NOW = datetime(2026, 7, 26, 12, 0, tzinfo=UTC)
_PROJECT = ProjectId(uuid4())
_EPOCH = ScoringEpoch(
    epoch_id=1,
    judge_model_id="gemini-3.1-pro",
    judge_model_version="001",
    sampling_params={"temperature": 0.0, "max_tokens": 8},
    prompt_hash="a" * 64,
    started_at=_NOW,
)
_CONFIG = ScoringConfig()  # alpha=0.3, adapter_weights defaults, cap=1/day


def _event(
    *,
    memory_id: MemoryId,
    adapter: AdapterClass = AdapterClass.DOWNSTREAM,
    r: float = 1.0,
    arrived_at: datetime = _NOW,
    event_id: UUID | None = None,
    run_id: RunId | None = None,
    principal_id: PrincipalId | None = None,
    outcome_summary: str = "the run succeeded",
) -> ScoringEvent:
    return ScoringEvent(
        event_id=event_id or uuid4(),
        run_id=run_id or mint_run_id(),
        memory_id=memory_id,
        adapter=adapter,
        r=r,
        principal_id=principal_id or PrincipalId(uuid4()),
        arrived_at=arrived_at,
        outcome_summary=outcome_summary,
    )


class FakeScorerRepo:
    """In-memory `ScorerRepoPort`. Tracks every mutating call it receives so
    a test can assert 'nothing was written' by inspecting `apply_calls`
    directly rather than inferring it from the returned `q` alone."""

    def __init__(self, *, project_id: ProjectId, memory_id: MemoryId, initial_q: float) -> None:
        self._project_id = project_id
        self._memory_id = memory_id
        self.q = initial_q
        self._applied_ids: set[UUID] = set()
        self._updates_by_day: dict[date, int] = {}
        self.apply_calls: list[QUpdate] = []
        self.day_queries: list[date] = []

    def current_q(self, project_id: ProjectId, memory_id: MemoryId) -> float:
        assert project_id == self._project_id
        assert memory_id == self._memory_id
        return self.q

    def applied_event_ids(self, project_id: ProjectId, memory_id: MemoryId) -> set[UUID]:
        assert project_id == self._project_id
        assert memory_id == self._memory_id
        return set(self._applied_ids)

    def scored_updates_today(self, project_id: ProjectId, memory_id: MemoryId, day: date) -> int:
        assert project_id == self._project_id
        assert memory_id == self._memory_id
        self.day_queries.append(day)
        return self._updates_by_day.get(day, 0)

    def apply_q_update(self, project_id: ProjectId, update: QUpdate) -> None:
        assert project_id == self._project_id
        self.apply_calls.append(update)
        self._applied_ids.add(update.event_id)
        self.q = update.new_q
        day = update.scored_at.date()
        self._updates_by_day[day] = self._updates_by_day.get(day, 0) + 1


@dataclass
class FakeJudge:
    factor: float = 1.0
    epoch_id: int = _EPOCH.epoch_id
    calls: list[tuple[str, str]] = field(default_factory=list)

    def judge(self, *, memory_content: str, outcome_summary: str) -> ContributionVerdict:
        self.calls.append((memory_content, outcome_summary))
        return ContributionVerdict(factor=self.factor, epoch_id=self.epoch_id)


def _repo(initial_q: float = 0.5, *, memory_id: MemoryId | None = None) -> FakeScorerRepo:
    return FakeScorerRepo(
        project_id=_PROJECT, memory_id=memory_id or mint_memory_id(), initial_q=initial_q
    )


def _run(
    repo: FakeScorerRepo,
    judge: FakeJudge,
    candidates: Iterable[ScoringEvent],
    *,
    memory_id: MemoryId,
    clock: FakeClock | None = None,
    config: ScoringConfig | None = None,
) -> ScoreBatchResult:
    return run_scorer_batch(
        project_id=_PROJECT,
        memory_id=memory_id,
        memory_content="always retry with exponential backoff",
        candidates=list(candidates),
        repo=repo,
        judge=judge,
        config=config or _CONFIG,
        epoch=_EPOCH,
        clock=clock or FakeClock(start=_NOW),
    )


# --------------------------------------------------------------------------- #
# THE headline test: the corrected formula moves Q UP on a successful event.
# Write this first and watch it fail against the WRONG formula (D-011).
# --------------------------------------------------------------------------- #


def test_the_production_formula_is_not_the_original_weight_as_reward_bug() -> None:
    """D-011's bug was feeding the adapter WEIGHT in as the reward. This runs
    the REAL `compute_new_q` on both readings to show they are not the same
    function: the correct call (r=1 polarity, w=0.3 weight) moves Q up, while
    the substitution the spec made -- the weight standing in the reward's
    place -- moves it down. Both sides come from the implementation, so a
    regression to the buggy formula collapses them and fails here rather than
    merely restating arithmetic that is true no matter what the code does."""
    correct = compute_new_q(current_q=0.5, r=1.0, w=0.3, c=1.0, alpha=0.3)
    weight_as_reward = compute_new_q(current_q=0.5, r=0.3, w=1.0, c=1.0, alpha=0.3)

    assert correct is not None
    assert weight_as_reward is not None
    assert correct > 0.5, "a successful downstream event must RAISE Q"
    assert weight_as_reward < 0.5, "this is what the original spec did -- punish success"


def test_a_successful_downstream_event_moves_q_up() -> None:
    """r=1 (positive outcome), w=0.3 (downstream), c=1.0 (full contribution)
    MUST move Q up from its start -- never down, never flat."""
    new_q = compute_new_q(current_q=0.5, r=1.0, w=0.3, c=1.0, alpha=0.3)
    assert new_q is not None
    assert new_q > 0.5
    assert new_q == pytest.approx(0.545)  # 0.5 + 0.3*0.3*1.0*(1-0.5)


def test_a_negative_downstream_event_moves_q_down() -> None:
    new_q = compute_new_q(current_q=0.5, r=0.0, w=0.3, c=1.0, alpha=0.3)
    assert new_q is not None
    assert new_q < 0.5


@pytest.mark.parametrize(
    ("current_q", "r", "w", "c", "alpha", "expected"),
    [
        # Six hand-computed cases spanning every adapter class that scores.
        (0.5, 1.0, 0.3, 1.0, 0.3, 0.545),  # downstream success  -> UP
        (0.5, 1.0, 1.0, 1.0, 0.3, 0.65),  # verdict success     -> UP
        (0.5, 0.0, 1.0, 1.0, 0.3, 0.35),  # verdict failure     -> DOWN
        (0.5, 1.0, 0.8, 0.5, 0.3, 0.56),  # correction, PARTIAL -> UP, damped
        (0.0, 1.0, 1.0, 1.0, 0.3, 0.3),  # from the floor      -> UP
        (1.0, 1.0, 1.0, 1.0, 0.3, 1.0),  # already at the top  -> flat, no overflow
    ],
)
def test_the_formula_matches_hand_arithmetic(
    current_q: float, r: float, w: float, c: float, alpha: float, expected: float
) -> None:
    result = compute_new_q(current_q=current_q, r=r, w=w, c=c, alpha=alpha)
    assert result is not None
    assert result == pytest.approx(expected)


def test_the_formula_reproduces_the_retirement_trajectory_decisions_computed() -> None:
    """D-021 worked this exact sequence out by hand to argue the Q arithmetic
    was a memory-destruction primitive: from 0.5, four scored negatives at
    w=1, c=1, alpha=0.3 give 0.35 -> 0.245 -> 0.172 -> 0.120. If the
    implementation stops reproducing the numbers DECISIONS reasons about, the
    reasoning behind `retirement.min_distinct_principals` no longer describes
    this code."""
    q = 0.5
    trajectory: list[float] = []
    for _ in range(4):
        nxt = compute_new_q(current_q=q, r=0.0, w=1.0, c=1.0, alpha=0.3)
        assert nxt is not None
        q = nxt
        trajectory.append(q)

    # D-021 quotes these to 3 significant figures (0.1715 printed as 0.172).
    assert trajectory == pytest.approx([0.35, 0.245, 0.1715, 0.12005])
    assert trajectory[1] < 0.25  # the retirement threshold, crossed on scored use 2


def test_end_to_end_a_successful_downstream_event_moves_q_up_through_the_worker() -> None:
    memory_id = mint_memory_id()
    repo = _repo(0.5, memory_id=memory_id)
    judge = FakeJudge(factor=1.0)

    result = _run(
        repo,
        judge,
        [_event(memory_id=memory_id, adapter=AdapterClass.DOWNSTREAM, r=1.0)],
        memory_id=memory_id,
    )

    assert len(result.applied) == 1
    assert result.applied[0].new_q > 0.5
    assert repo.q > 0.5


# --------------------------------------------------------------------------- #
# w == 0 SHORT-CIRCUITS: no update, no row, nothing mutated. Not even judged.
# --------------------------------------------------------------------------- #


def test_w_zero_short_circuits_the_pure_formula() -> None:
    assert compute_new_q(current_q=0.5, r=1.0, w=0.0, c=1.0, alpha=0.3) is None


def test_implicit_adapter_writes_nothing_and_mutates_nothing() -> None:
    memory_id = mint_memory_id()
    repo = _repo(0.5, memory_id=memory_id)
    judge = FakeJudge(factor=1.0)

    result = _run(
        repo,
        judge,
        [_event(memory_id=memory_id, adapter=AdapterClass.IMPLICIT, r=1.0)],
        memory_id=memory_id,
    )

    assert result.applied == ()
    assert repo.apply_calls == []  # no row written
    assert repo.q == 0.5  # nothing mutated
    assert judge.calls == []  # never even judged -- w=0 short-circuits first


def test_an_adapter_class_absent_from_config_resolves_to_zero_weight() -> None:
    assert resolve_weight(AdapterClass.IMPLICIT, {}) == 0.0


def test_a_short_circuited_event_leaves_the_cap_slot_unspent_for_a_real_one() -> None:
    """`skipped_short_circuit` is terminal, `skipped_cap` is retryable. An
    event that could never score must not consume the memory's only slot for
    the day -- otherwise one implicit signal a minute after midnight blocks
    every real verdict for the next 24 hours."""
    memory_id = mint_memory_id()
    repo = _repo(0.5, memory_id=memory_id)
    judge = FakeJudge(factor=1.0)

    _run(
        repo,
        judge,
        [_event(memory_id=memory_id, adapter=AdapterClass.IMPLICIT)],
        memory_id=memory_id,
    )
    result = _run(
        repo,
        judge,
        [_event(memory_id=memory_id, adapter=AdapterClass.VERDICT, r=1.0)],
        memory_id=memory_id,
    )

    assert len(result.applied) == 1
    assert repo.q > 0.5


def test_every_zero_weight_candidate_is_reported_as_short_circuited_not_capped() -> None:
    """The winner holds the MAXIMUM weight, so a zero there means every
    candidate is zero. Reporting the losers as `skipped_cap` would tell an
    orchestrator to retry them tomorrow -- and the day after, forever -- for a
    weight that cannot become non-zero by waiting."""
    memory_id = mint_memory_id()
    repo = _repo(0.5, memory_id=memory_id)
    judge = FakeJudge(factor=1.0)
    events = [
        _event(memory_id=memory_id, adapter=AdapterClass.IMPLICIT, arrived_at=_NOW),
        _event(
            memory_id=memory_id,
            adapter=AdapterClass.IMPLICIT,
            arrived_at=_NOW + timedelta(hours=1),
        ),
    ]

    result = _run(repo, judge, events, memory_id=memory_id)

    assert set(result.skipped_short_circuit) == {e.event_id for e in events}
    assert result.skipped_cap == ()
    assert repo.apply_calls == []


# --------------------------------------------------------------------------- #
# `w` is refused at its only sanctioned producer. `scoring` is an
# OVERRIDABLE_SECTIONS member, so every value below is reachable from a
# `project_config` row -- these are not hypothetical constants.
# --------------------------------------------------------------------------- #


def test_a_negative_configured_weight_resolves_to_zero_rather_than_inverting_the_update() -> None:
    """`alpha*w*c*(r-Q)` with w<0 INVERTS learning: failures raise Q and
    successes lower it. That is a silent poisoning primitive available from a
    single config row, so the weight is refused, never used."""
    assert resolve_weight(AdapterClass.DOWNSTREAM, {"downstream": -1.0}) == 0.0


def test_an_inverting_weight_produces_no_update_at_all_end_to_end() -> None:
    memory_id = mint_memory_id()
    repo = _repo(0.5, memory_id=memory_id)
    judge = FakeJudge(factor=1.0)
    poisoned = ScoringConfig(adapter_weights={"downstream": -1.0})

    result = _run(
        repo,
        judge,
        [_event(memory_id=memory_id, adapter=AdapterClass.DOWNSTREAM, r=0.0)],
        memory_id=memory_id,
        config=poisoned,
    )

    assert result.applied == ()
    assert repo.q == 0.5  # a NEGATIVE outcome did not raise Q
    assert judge.calls == []


def test_an_overweight_configured_weight_resolves_to_zero_rather_than_saturating_q() -> None:
    """alpha*w*c > 1 overshoots past `r` into the clamp: one event would set Q
    to 1.0 (or 0.0) outright instead of moving it. Refusing to score under a
    misconfigured weight is recoverable; a saturated Q is not."""
    assert resolve_weight(AdapterClass.VERDICT, {"verdict": 5.0}) == 0.0


def test_a_nan_configured_weight_resolves_to_zero() -> None:
    assert resolve_weight(AdapterClass.VERDICT, {"verdict": float("nan")}) == 0.0


def test_the_documented_default_weights_all_survive_resolution() -> None:
    """The fail-closed range check must not accidentally refuse the shipped
    configuration (PLAN.md Â§6: verdict 1.0, correction 0.8, downstream 0.3,
    implicit 0.0 short-circuit)."""
    weights = _CONFIG.adapter_weights
    assert resolve_weight(AdapterClass.VERDICT, weights) == 1.0
    assert resolve_weight(AdapterClass.CORRECTION_ADAPTER, weights) == 0.8
    assert resolve_weight(AdapterClass.DOWNSTREAM, weights) == 0.3
    assert resolve_weight(AdapterClass.IMPLICIT, weights) == 0.0


# --------------------------------------------------------------------------- #
# `r`, `c` and the stored Q are ENFORCED in [0, 1], not merely documented.
# This is the clamp's blind spot: an out-of-range reward does not overflow
# into an obvious error, it SATURATES -- one event pinning a memory perfect.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("bad_r", [1.5, 100.0, -0.5, float("nan"), float("inf")])
def test_an_out_of_range_reward_is_refused_not_clamped(bad_r: float) -> None:
    with pytest.raises(ScoringInputInvalid):
        compute_new_q(current_q=0.5, r=bad_r, w=0.3, c=1.0, alpha=0.3)


def test_an_out_of_range_reward_would_otherwise_be_a_one_shot_promotion_primitive() -> None:
    """What the refusal protects against: r=100 with the SHIPPED weight and
    alpha computes 0.5 + 0.3*0.3*1.0*99.5 = 9.455, which `clamp01` would
    present as a flawless 1.0 from a single feedback event."""
    unclamped = 0.5 + 0.3 * 0.3 * 1.0 * (100.0 - 0.5)
    assert unclamped > 1.0
    assert clamp01(unclamped) == 1.0
    with pytest.raises(ScoringInputInvalid):
        compute_new_q(current_q=0.5, r=100.0, w=0.3, c=1.0, alpha=0.3)


@pytest.mark.parametrize("bad_c", [1.5, 50.0, -1.0, float("nan")])
def test_an_out_of_range_contribution_factor_is_refused(bad_c: float) -> None:
    """`ContributionJudgePort` is structural, so the scorer accepts a verdict
    from ANY object with a `judge` method -- a cache, a batching wrapper, a
    host-supplied judge. `c` multiplies the learning rate exactly like `r`."""
    with pytest.raises(ScoringInputInvalid):
        compute_new_q(current_q=0.5, r=1.0, w=0.3, c=bad_c, alpha=0.3)


@pytest.mark.parametrize("bad_q", [1.5, -0.2, float("nan")])
def test_an_out_of_range_stored_q_is_refused(bad_q: float) -> None:
    with pytest.raises(ScoringInputInvalid):
        compute_new_q(current_q=bad_q, r=1.0, w=0.3, c=1.0, alpha=0.3)


def test_a_boolean_is_not_a_reward() -> None:
    """`True == 1.0` in Python and `bool` is a subtype of `int`, so a boolean
    satisfies both the type checker and a bare range check while silently
    reading as a perfect outcome."""
    with pytest.raises(ScoringInputInvalid):
        compute_new_q(current_q=0.5, r=True, w=0.3, c=1.0, alpha=0.3)


def test_a_scoring_event_refuses_an_out_of_range_reward_at_construction() -> None:
    """Refused early enough that the event cannot win the tie-break and spend
    the memory's only slot for the day before the formula sees it."""
    with pytest.raises(ScoringInputInvalid):
        _event(memory_id=mint_memory_id(), r=7.0)


def test_a_scoring_event_refuses_a_timezone_naive_arrival() -> None:
    """`arrived_at` orders the tie-break; a naive value raises TypeError
    mid-sort and would have been reinterpreted in the session TimeZone by
    Postgres besides (the hazard D-043 moved to the wire for `occurred_at`)."""
    with pytest.raises(ScoringInputInvalid):
        _event(memory_id=mint_memory_id(), arrived_at=datetime(2026, 7, 26, 12, 0))


# --------------------------------------------------------------------------- #
# Ambiguous / zero-contribution fixtures produce ZERO Q mutations -- row-level
# equality before/after, not merely "no exception".
# --------------------------------------------------------------------------- #


def test_zero_contribution_produces_zero_q_mutation_as_a_pure_computation() -> None:
    assert compute_new_q(current_q=0.5, r=1.0, w=0.3, c=0.0, alpha=0.3) is None


def test_an_irrelevant_memory_writes_nothing_row_level_equality_before_and_after() -> None:
    memory_id = mint_memory_id()
    repo = _repo(0.5, memory_id=memory_id)
    judge = FakeJudge(factor=0.0)  # contribution judge: this memory did not contribute
    before_q, before_calls = repo.q, list(repo.apply_calls)

    result = _run(
        repo,
        judge,
        [_event(memory_id=memory_id, adapter=AdapterClass.VERDICT, r=1.0)],
        memory_id=memory_id,
    )

    assert result.applied == ()
    assert repo.q == before_q
    assert repo.apply_calls == before_calls  # the whole row-shaped call log, unchanged
    assert judge.calls  # unlike w=0, the judge WAS consulted (c came from it)


# --------------------------------------------------------------------------- #
# Callers never supply weights -- there is no field/keyword that could carry
# one through to the formula.
# --------------------------------------------------------------------------- #


def test_scoring_event_has_no_caller_settable_weight_field() -> None:
    with pytest.raises(TypeError):
        ScoringEvent(  # type: ignore[call-arg]
            event_id=uuid4(),
            run_id=mint_run_id(),
            memory_id=mint_memory_id(),
            adapter=AdapterClass.DOWNSTREAM,
            r=1.0,
            principal_id=PrincipalId(uuid4()),
            arrived_at=_NOW,
            outcome_summary="o",
            w=0.9,
        )


def test_resolve_weight_reads_only_the_adapter_class_and_server_config() -> None:
    """`w` is a required keyword of the pure formula itself, but the ONLY
    sanctioned way to produce a value for it is `resolve_weight`, which
    reads exclusively from server config -- there is no other function in
    this module that hands back a `w`."""
    import inspect

    params = inspect.signature(resolve_weight).parameters
    assert list(params) == ["adapter", "adapter_weights"]


# --------------------------------------------------------------------------- #
# Daily cap + tie-break: highest-w adapter, then earliest arrival, then
# event_id so the ordering is TOTAL.
# --------------------------------------------------------------------------- #


def test_tie_break_picks_the_highest_weight_adapter_first() -> None:
    memory_id = mint_memory_id()
    repo = _repo(0.5, memory_id=memory_id)
    judge = FakeJudge(factor=1.0)
    downstream = _event(  # w=0.3, and EARLIER, so arrival alone would pick it
        memory_id=memory_id, adapter=AdapterClass.DOWNSTREAM, arrived_at=_NOW
    )
    verdict = _event(  # w=1.0
        memory_id=memory_id,
        adapter=AdapterClass.VERDICT,
        arrived_at=_NOW + timedelta(hours=1),
    )

    result = _run(repo, judge, [downstream, verdict], memory_id=memory_id)

    assert len(result.applied) == 1
    assert result.applied[0].event_id == verdict.event_id
    assert downstream.event_id in result.skipped_cap


def test_tie_break_falls_back_to_earliest_arrival_when_weights_are_equal() -> None:
    memory_id = mint_memory_id()
    repo = _repo(0.5, memory_id=memory_id)
    judge = FakeJudge(factor=1.0)
    later = _event(
        memory_id=memory_id, adapter=AdapterClass.VERDICT, arrived_at=_NOW + timedelta(hours=2)
    )
    earlier = _event(memory_id=memory_id, adapter=AdapterClass.VERDICT, arrived_at=_NOW)

    result = _run(repo, judge, [later, earlier], memory_id=memory_id)

    assert result.applied[0].event_id == earlier.event_id
    assert later.event_id in result.skipped_cap


def test_the_tie_break_is_total_when_weight_and_arrival_are_both_identical() -> None:
    """`arrived_at` is a `timestamptz DEFAULT now()`, and `now()` is IDENTICAL
    for every row written inside one transaction -- so two same-adapter events
    really can tie on both of D-011's documented keys. With only those two the
    winner is whatever order the caller's query happened to return, and the
    same pending batch replayed after a restart could pick the other event and
    write a different Q."""
    memory_id = mint_memory_id()
    a = _event(memory_id=memory_id, adapter=AdapterClass.VERDICT, arrived_at=_NOW)
    b = _event(memory_id=memory_id, adapter=AdapterClass.VERDICT, arrived_at=_NOW)

    forward = select_daily_winner([a, b], adapter_weights=_CONFIG.adapter_weights)
    backward = select_daily_winner([b, a], adapter_weights=_CONFIG.adapter_weights)

    assert forward is not None
    assert backward is not None
    assert forward.event_id == backward.event_id
    # Broken by the SERVER-minted run_id, not by the caller-asserted event_id
    # -- see `test_a_chosen_event_id_cannot_win_a_tie_against_a_server_minted_run_id`
    # for why that ordering matters, and
    # `test_event_id_still_closes_the_order_when_every_server_field_ties` for
    # the case where event_id really is the only thing left.
    assert forward.run_id == min(a, b, key=lambda e: e.run_id.value.bytes).run_id


def test_the_total_tie_break_survives_the_whole_worker_not_just_the_selector() -> None:
    memory_id = mint_memory_id()
    a = _event(memory_id=memory_id, adapter=AdapterClass.VERDICT, arrived_at=_NOW, r=1.0)
    b = _event(memory_id=memory_id, adapter=AdapterClass.VERDICT, arrived_at=_NOW, r=0.0)

    first = _run(_repo(0.5, memory_id=memory_id), FakeJudge(), [a, b], memory_id=memory_id)
    second = _run(_repo(0.5, memory_id=memory_id), FakeJudge(), [b, a], memory_id=memory_id)

    assert first.applied[0].event_id == second.applied[0].event_id
    assert first.applied[0].new_q == second.applied[0].new_q


def test_select_daily_winner_returns_none_for_no_candidates() -> None:
    assert select_daily_winner([], adapter_weights=_CONFIG.adapter_weights) is None


def test_the_daily_cap_blocks_a_second_update_the_same_day() -> None:
    memory_id = mint_memory_id()
    repo = _repo(0.5, memory_id=memory_id)
    judge = FakeJudge(factor=1.0)
    first = _event(memory_id=memory_id, adapter=AdapterClass.VERDICT, arrived_at=_NOW)
    _run(repo, judge, [first], memory_id=memory_id)
    assert len(repo.apply_calls) == 1

    second = _event(
        memory_id=memory_id, adapter=AdapterClass.VERDICT, arrived_at=_NOW + timedelta(hours=3)
    )
    result = _run(repo, judge, [second], memory_id=memory_id)

    assert result.applied == ()
    assert second.event_id in result.skipped_cap
    assert len(repo.apply_calls) == 1  # still just the one


def test_two_events_in_one_batch_cannot_both_score_the_same_day() -> None:
    """The cap is per memory per DAY, not per call: handing a whole day's
    events to one invocation must not buy a second slot."""
    memory_id = mint_memory_id()
    repo = _repo(0.5, memory_id=memory_id)
    judge = FakeJudge(factor=1.0)
    events = [
        _event(memory_id=memory_id, adapter=AdapterClass.VERDICT, arrived_at=_NOW),
        _event(
            memory_id=memory_id,
            adapter=AdapterClass.VERDICT,
            arrived_at=_NOW + timedelta(minutes=1),
        ),
        _event(
            memory_id=memory_id,
            adapter=AdapterClass.VERDICT,
            arrived_at=_NOW + timedelta(minutes=2),
        ),
    ]

    result = _run(repo, judge, events, memory_id=memory_id)

    assert len(result.applied) == 1
    assert len(repo.apply_calls) == 1
    assert len(judge.calls) == 1  # the losers never cost an LLM call either
    assert len(result.skipped_cap) == 2


class StepClock:
    """A `Clock` that returns a DIFFERENT instant on every `now()` call.

    A `FakeClock` returns the same instant until something advances it, which
    makes it structurally incapable of telling one clock read from two -- the
    exact property the test below has to prove. Stepping across midnight makes
    the difference observable: with one read the whole tick agrees on a day,
    with two the cap is checked against day D and `scored_at` lands in D+1."""

    def __init__(self, instants: list[datetime]) -> None:
        self._instants = instants
        self.reads = 0

    def now(self) -> datetime:
        instant = self._instants[min(self.reads, len(self._instants) - 1)]
        self.reads += 1
        return instant

    def now_ms(self) -> int:
        return int(self.now().timestamp() * 1000)

    def monotonic_ms(self) -> float:
        return float(self.reads)


def test_the_whole_tick_uses_one_clock_read() -> None:
    """The cap counter is bucketed on `scored_at`, so a second clock read that
    lands past midnight buckets the update on a day the cap was never checked
    for -- and a second update on that day is then allowed. One read is the
    only thing that makes the check and the stamp describe the same day."""
    memory_id = mint_memory_id()
    repo = _repo(0.5, memory_id=memory_id)
    judge = FakeJudge(factor=1.0)
    before = datetime(2026, 7, 26, 23, 59, 59, 999_999, tzinfo=UTC)
    after = datetime(2026, 7, 27, 0, 0, 0, tzinfo=UTC)
    clock = StepClock([before, after, after])

    result = run_scorer_batch(
        project_id=_PROJECT,
        memory_id=memory_id,
        memory_content="m",
        candidates=[_event(memory_id=memory_id, adapter=AdapterClass.VERDICT, arrived_at=before)],
        repo=repo,
        judge=judge,
        config=_CONFIG,
        epoch=_EPOCH,
        clock=clock,
    )

    assert clock.reads == 1
    assert result.applied[0].scored_at == before
    assert repo.scored_updates_today(_PROJECT, memory_id, before.date()) == 1
    assert repo.scored_updates_today(_PROJECT, memory_id, after.date()) == 0


def test_the_daily_cap_resets_on_a_new_day() -> None:
    memory_id = mint_memory_id()
    repo = _repo(0.5, memory_id=memory_id)
    judge = FakeJudge(factor=1.0)
    clock = FakeClock(start=_NOW)
    first = _event(memory_id=memory_id, adapter=AdapterClass.VERDICT, arrived_at=_NOW)
    _run(repo, judge, [first], memory_id=memory_id, clock=clock)

    clock.advance(days=1)
    second = _event(
        memory_id=memory_id, adapter=AdapterClass.VERDICT, arrived_at=_NOW + timedelta(days=1)
    )
    result = _run(repo, judge, [second], memory_id=memory_id, clock=clock)

    assert len(result.applied) == 1
    assert result.applied[0].event_id == second.event_id


# --------------------------------------------------------------------------- #
# The batch belongs to ONE memory. Q, the cap counter and the replay ledger
# are all read for `memory_id`; a mis-grouped candidate would write one
# memory's outcome onto another memory's score.
# --------------------------------------------------------------------------- #


def test_a_candidate_from_another_memory_is_refused_not_scored() -> None:
    memory_id = mint_memory_id()
    other = mint_memory_id()
    repo = _repo(0.5, memory_id=memory_id)
    judge = FakeJudge(factor=1.0)

    with pytest.raises(ScoringInputInvalid):
        _run(
            repo,
            judge,
            [_event(memory_id=other, adapter=AdapterClass.VERDICT, r=1.0)],
            memory_id=memory_id,
        )

    assert repo.apply_calls == []
    assert judge.calls == []


def test_the_memory_check_runs_before_anything_in_the_batch_is_scored() -> None:
    memory_id = mint_memory_id()
    repo = _repo(0.5, memory_id=memory_id)
    judge = FakeJudge(factor=1.0)
    good = _event(memory_id=memory_id, adapter=AdapterClass.VERDICT)
    smuggled = _event(memory_id=mint_memory_id(), adapter=AdapterClass.VERDICT)

    with pytest.raises(ScoringInputInvalid):
        _run(repo, judge, [good, smuggled], memory_id=memory_id)

    assert repo.apply_calls == []


# --------------------------------------------------------------------------- #
# Replay-idempotency via event_id: a replayed event never moves Q twice.
# --------------------------------------------------------------------------- #


def test_replaying_an_applied_event_id_does_not_double_apply() -> None:
    memory_id = mint_memory_id()
    repo = _repo(0.5, memory_id=memory_id)
    judge = FakeJudge(factor=1.0)
    event = _event(memory_id=memory_id, adapter=AdapterClass.VERDICT, r=1.0)

    first_result = _run(repo, judge, [event], memory_id=memory_id)
    q_after_first = repo.q
    assert len(first_result.applied) == 1

    second_result = _run(repo, judge, [event], memory_id=memory_id)

    assert second_result.applied == ()
    assert event.event_id in second_result.skipped_replay
    assert repo.q == q_after_first
    assert len(repo.apply_calls) == 1


def test_a_replayed_event_does_not_consume_a_fresh_cap_slot() -> None:
    """Replaying the winner from a prior day must not block a genuinely new
    event today merely by occupying the (empty) candidate list."""
    memory_id = mint_memory_id()
    repo = _repo(0.5, memory_id=memory_id)
    judge = FakeJudge(factor=1.0)
    clock = FakeClock(start=_NOW)
    event = _event(memory_id=memory_id, adapter=AdapterClass.VERDICT, r=1.0)
    _run(repo, judge, [event], memory_id=memory_id, clock=clock)

    clock.advance(days=1)
    fresh = _event(
        memory_id=memory_id, adapter=AdapterClass.VERDICT, arrived_at=_NOW + timedelta(days=1)
    )
    result = _run(repo, judge, [event, fresh], memory_id=memory_id, clock=clock)

    assert event.event_id in result.skipped_replay
    assert result.applied[0].event_id == fresh.event_id


def test_a_duplicated_candidate_is_collapsed_to_one_decision() -> None:
    """`ScoreBatchResult` promises every distinct event_id lands in exactly
    one bucket. A candidate list that repeats an id -- an at-least-once queue
    redelivering into the same batch -- must not put it in two, and must not
    let the duplicate masquerade as a losing candidate."""
    memory_id = mint_memory_id()
    repo = _repo(0.5, memory_id=memory_id)
    judge = FakeJudge(factor=1.0)
    event = _event(memory_id=memory_id, adapter=AdapterClass.VERDICT, r=1.0)

    result = _run(repo, judge, [event, event, event], memory_id=memory_id)

    assert len(result.applied) == 1
    assert result.skipped_cap == ()
    assert result.skipped_replay == ()
    assert len(repo.apply_calls) == 1
    assert len(judge.calls) == 1

    # Same batch again: the id is now on the replay ledger, and it must appear
    # there exactly ONCE however many times the redelivery repeated it -- a
    # tuple with three copies of one id is a caller counting three skips.
    replay_result = _run(repo, judge, [event, event, event], memory_id=memory_id)

    assert replay_result.skipped_replay == (event.event_id,)
    assert replay_result.applied == ()
    assert len(repo.apply_calls) == 1


# --------------------------------------------------------------------------- #
# Q stays in [0, 1] under adversarial inputs.
# --------------------------------------------------------------------------- #


def test_clamp01_bounds_a_misconfigured_overweight_update_from_above() -> None:
    # alpha*w*c = 1.0 * 5.0 * 1.0 = 5.0 -- a weight that bypassed `resolve_weight`.
    new_q = compute_new_q(current_q=0.95, r=1.0, w=5.0, c=1.0, alpha=1.0)
    assert new_q == 1.0


def test_clamp01_bounds_a_misconfigured_overweight_update_from_below() -> None:
    new_q = compute_new_q(current_q=0.05, r=0.0, w=5.0, c=1.0, alpha=1.0)
    assert new_q == 0.0


@pytest.mark.parametrize("current_q", [0.0, 0.001, 0.5, 0.999, 1.0])
@pytest.mark.parametrize("r", [0.0, 1.0])
@pytest.mark.parametrize("w", [0.3, 0.8, 1.0, 10.0])
def test_compute_new_q_never_leaves_the_unit_interval(
    current_q: float, r: float, w: float
) -> None:
    result = compute_new_q(current_q=current_q, r=r, w=w, c=1.0, alpha=1.0)
    assert result is None or 0.0 <= result <= 1.0


def test_clamp01_rejects_nan() -> None:
    with pytest.raises(ValueError):
        clamp01(float("nan"))


def test_clamp01_rejects_infinity() -> None:
    with pytest.raises(ValueError):
        clamp01(float("inf"))
    with pytest.raises(ValueError):
        clamp01(float("-inf"))


def test_repeated_overshooting_updates_are_bounded_at_one() -> None:
    """alpha*w*c = 1.8 overshoots past `r` on every step and diverges without
    the clamp. A convex update (alpha*w*c <= 1) would stay inside [0, 1] on
    its own arithmetic and pass this assertion with `clamp01` deleted -- which
    is exactly why the parameters here are not convex."""
    q = 0.5
    for _ in range(50):
        nxt = compute_new_q(current_q=q, r=1.0, w=1.0, c=1.0, alpha=1.8)
        assert nxt is not None
        assert 0.0 <= nxt <= 1.0
        q = nxt
    assert q == 1.0


def test_repeated_overshooting_negative_updates_are_bounded_at_zero() -> None:
    q = 0.5
    for _ in range(50):
        nxt = compute_new_q(current_q=q, r=0.0, w=1.0, c=1.0, alpha=1.8)
        assert nxt is not None
        assert 0.0 <= nxt <= 1.0
        q = nxt
    assert q == 0.0


def test_a_long_convex_trajectory_converges_without_float_drift() -> None:
    """500 legally-configured updates: Q approaches `r` monotonically and
    never steps outside [0, 1] through accumulated float error."""
    q = 0.5
    previous = q
    for _ in range(500):
        nxt = compute_new_q(current_q=q, r=1.0, w=1.0, c=1.0, alpha=0.3)
        assert nxt is not None
        assert 0.0 <= nxt <= 1.0
        assert nxt >= previous  # never oscillates downward under a positive stream
        previous, q = nxt, nxt
    assert q == pytest.approx(1.0, abs=1e-9)


# --------------------------------------------------------------------------- #
# scoring_epoch: every applied update is stamped, and a judge answering under
# a different epoch than the one the scorer resolved is refused outright.
# --------------------------------------------------------------------------- #


def test_an_applied_update_is_stamped_with_the_resolved_epoch() -> None:
    memory_id = mint_memory_id()
    repo = _repo(0.5, memory_id=memory_id)
    judge = FakeJudge(factor=1.0, epoch_id=_EPOCH.epoch_id)

    result = _run(
        repo,
        judge,
        [_event(memory_id=memory_id, adapter=AdapterClass.VERDICT)],
        memory_id=memory_id,
    )

    assert result.applied[0].epoch_id == _EPOCH.epoch_id


def test_a_judge_verdict_from_a_different_epoch_is_refused() -> None:
    memory_id = mint_memory_id()
    repo = _repo(0.5, memory_id=memory_id)
    stale_judge = FakeJudge(factor=1.0, epoch_id=_EPOCH.epoch_id + 999)

    with pytest.raises(CrossEpochComparison):
        _run(
            repo,
            stale_judge,
            [_event(memory_id=memory_id, adapter=AdapterClass.VERDICT)],
            memory_id=memory_id,
        )

    assert repo.apply_calls == []  # the refusal happens before any write


# --------------------------------------------------------------------------- #
# The applied update carries the principal that caused it (D-021's K floor).
# --------------------------------------------------------------------------- #


def test_an_applied_update_records_the_principal_that_caused_it() -> None:
    """PLAN.md Â§5: retirement needs ">=4 scored uses FROM >=K distinct
    principals". The qualifier attaches to SCORED uses, while `outcome_event`
    also holds the implicit and cap-skipped events that never moved Q -- so
    counting principals there lets principals who never influenced Q at all
    satisfy a floor that exists to stop one attacker-controlled feedback
    source retiring a memory alone (D-021). The count has to be takeable from
    the applied updates, which means the principal has to be on them."""
    memory_id = mint_memory_id()
    attacker = PrincipalId(uuid4())
    repo = _repo(0.5, memory_id=memory_id)
    judge = FakeJudge(factor=1.0)

    result = _run(
        repo,
        judge,
        [
            _event(
                memory_id=memory_id,
                adapter=AdapterClass.VERDICT,
                r=0.0,
                principal_id=attacker,
            )
        ],
        memory_id=memory_id,
    )

    assert result.applied[0].principal_id == attacker


def test_one_principal_walking_q_down_leaves_one_principal_on_the_scored_ledger() -> None:
    """D-021's attack, made countable: four consecutive scored negatives from
    ONE principal cross both retirement preconditions (Q < 0.25, >= 4 scored
    uses) in four calendar days, and the applied updates show exactly one
    distinct principal -- below K=3, so retirement must route to the review
    queue instead of firing."""
    memory_id = mint_memory_id()
    attacker = PrincipalId(uuid4())
    repo = _repo(0.5, memory_id=memory_id)
    judge = FakeJudge(factor=1.0)
    clock = FakeClock(start=_NOW)

    for day in range(4):
        _run(
            repo,
            judge,
            [
                _event(
                    memory_id=memory_id,
                    adapter=AdapterClass.VERDICT,
                    r=0.0,
                    arrived_at=_NOW + timedelta(days=day),
                    principal_id=attacker,
                )
            ],
            memory_id=memory_id,
            clock=clock,
        )
        clock.advance(days=1)

    assert len(repo.apply_calls) == 4
    assert repo.q < 0.25
    assert {u.principal_id for u in repo.apply_calls} == {attacker}


# --------------------------------------------------------------------------- #
# Structural conformance of the fakes to the Protocols they stand in for.
# --------------------------------------------------------------------------- #


def test_fake_scorer_repo_satisfies_scorer_repo_port() -> None:
    assert isinstance(_repo(), ScorerRepoPort)


def test_fake_judge_satisfies_contribution_judge_port() -> None:
    assert isinstance(FakeJudge(), ContributionJudgePort)


# --------------------------------------------------------------------------- #
# `alpha` is the other factor of `alpha*w*c*(r-Q)` a config row can reach.
# `ScoringConfig.alpha` is `gt=0, le=1` at the pydantic layer, but the pure
# function is exported and a `model_construct`-ed config reaches it unchecked
# (the defence-in-depth `DerivedStateWriter` keeps for the same reason, D-075).
# --------------------------------------------------------------------------- #


def test_a_negative_alpha_is_refused_rather_than_inverting_every_outcome() -> None:
    """Identical primitive to a negative `w`, one factor over: with alpha<0 a
    FAILING outcome raises Q and a succeeding one lowers it, for every memory
    in the project, silently."""
    with pytest.raises(ScoringInputInvalid):
        compute_new_q(current_q=0.5, r=0.0, w=1.0, c=1.0, alpha=-0.3)


def test_a_zero_alpha_is_refused_rather_than_freezing_q_while_spending_the_slot() -> None:
    """alpha=0 makes every update a no-op that still writes a row and still
    consumes the memory's one update for the day -- learning switched off by a
    config row while every dashboard still shows updates being applied."""
    with pytest.raises(ScoringInputInvalid):
        compute_new_q(current_q=0.5, r=1.0, w=1.0, c=1.0, alpha=0.0)


@pytest.mark.parametrize("bad_alpha", [float("nan"), float("inf"), float("-inf"), True])
def test_a_non_finite_or_boolean_alpha_is_refused(bad_alpha: float) -> None:
    with pytest.raises(ScoringInputInvalid):
        compute_new_q(current_q=0.5, r=1.0, w=1.0, c=1.0, alpha=bad_alpha)


def test_an_overshooting_alpha_is_still_allowed_because_the_clamp_is_what_bounds_it() -> None:
    """No UPPER bound here on purpose: the overshoot tests above exercise
    exactly that, and a fast update is a different thing from a broken one."""
    assert compute_new_q(current_q=0.5, r=1.0, w=1.0, c=1.0, alpha=1.8) == 1.0


def test_the_shipped_alpha_survives_the_check() -> None:
    assert compute_new_q(current_q=0.5, r=1.0, w=1.0, c=1.0, alpha=_CONFIG.alpha) is not None


# --------------------------------------------------------------------------- #
# What the applied update actually records. `QUpdate` is the only row a
# retirement/promotion reader ever sees, so every field on it is load-bearing.
# --------------------------------------------------------------------------- #


def test_the_applied_update_records_the_q_it_moved_from_and_the_q_it_moved_to() -> None:
    """`previous_q` is what makes an applied update auditable at all -- a
    forensics reader (improvement 1) replaying a memory's Q trajectory has
    only these rows, and a `previous_q` copied from `new_q` turns every step
    into a flat line that still sums to the right final value."""
    memory_id = mint_memory_id()
    repo = _repo(0.5, memory_id=memory_id)

    result = _run(
        repo,
        FakeJudge(factor=1.0),
        [_event(memory_id=memory_id, adapter=AdapterClass.VERDICT, r=1.0)],
        memory_id=memory_id,
    )

    update = result.applied[0]
    assert update.previous_q == 0.5
    assert update.new_q == pytest.approx(0.65)
    assert update.previous_q != update.new_q


@pytest.mark.parametrize(("factor", "expected_q"), [(0.5, 0.575), (1.0, 0.65)])
def test_the_applied_update_records_the_judged_contribution_it_used(
    factor: float, expected_q: float
) -> None:
    """`contribution` is the audit trail for 'why did this memory earn only
    half a step'. Hard-coding it to 1.0 would leave every PARTIAL verdict
    indistinguishable from a FULL one in the record while the arithmetic
    quietly disagreed."""
    memory_id = mint_memory_id()
    repo = _repo(0.5, memory_id=memory_id)

    result = _run(
        repo,
        FakeJudge(factor=factor),
        [_event(memory_id=memory_id, adapter=AdapterClass.VERDICT, r=1.0)],
        memory_id=memory_id,
    )

    assert result.applied[0].contribution == factor
    assert result.applied[0].new_q == pytest.approx(expected_q)


def test_scored_at_is_the_clock_instant_not_anything_carried_on_the_event() -> None:
    """The store buckets the daily cap on `scored_at`. Stamping it from the
    event's own `arrived_at` instead would bucket a late-arriving outcome --
    feedback legitimately arrives days after its trace (PLAN.md Â§3) -- onto a
    day whose cap was never checked, so a batch of a week's backlog would
    apply one update per backlog DAY in a single tick."""
    memory_id = mint_memory_id()
    repo = _repo(0.5, memory_id=memory_id)
    long_ago = _NOW - timedelta(days=3)

    result = _run(
        repo,
        FakeJudge(factor=1.0),
        [_event(memory_id=memory_id, adapter=AdapterClass.VERDICT, arrived_at=long_ago)],
        memory_id=memory_id,
        clock=FakeClock(start=_NOW),
    )

    assert result.applied[0].scored_at == _NOW
    assert result.applied[0].scored_at != long_ago
    assert repo.day_queries == [_NOW.date()]


# --------------------------------------------------------------------------- #
# The judge is asked about the WINNER, and about THIS memory. Both inputs are
# untrusted text, and both come from a different event than the `r` being
# applied if either is wired to the wrong candidate.
# --------------------------------------------------------------------------- #


def test_the_judge_is_asked_about_the_winning_event_not_a_losing_one() -> None:
    """`outcome_summary` is untrusted, attacker-influenceable run text. Judging
    a LOSING candidate's summary while applying the WINNER's `r` scores one
    outcome against another outcome's evidence -- and hands anyone who can get
    a low-weight event into the same batch a channel into the judge prompt
    that never has to win anything."""
    memory_id = mint_memory_id()
    repo = _repo(0.5, memory_id=memory_id)
    judge = FakeJudge(factor=1.0)
    loser = _event(  # w=0.3, listed FIRST so an index-0 read would pick it
        memory_id=memory_id,
        adapter=AdapterClass.DOWNSTREAM,
        arrived_at=_NOW,
        outcome_summary="LOSER-SUMMARY",
    )
    winner = _event(
        memory_id=memory_id,
        adapter=AdapterClass.VERDICT,
        arrived_at=_NOW + timedelta(hours=1),
        outcome_summary="WINNER-SUMMARY",
    )

    result = _run(repo, judge, [loser, winner], memory_id=memory_id)

    assert result.applied[0].event_id == winner.event_id
    assert judge.calls == [("always retry with exponential backoff", "WINNER-SUMMARY")]


def test_the_judge_is_asked_about_the_batchs_memory_content() -> None:
    """`c` answers 'did THIS memory matter'. An empty or wrong
    `memory_content` asks the judge a question about nothing and then
    multiplies the answer into this memory's Q."""
    memory_id = mint_memory_id()
    repo = _repo(0.5, memory_id=memory_id)
    judge = FakeJudge(factor=1.0)

    run_scorer_batch(
        project_id=_PROJECT,
        memory_id=memory_id,
        memory_content="MEMORY-UNDER-TEST",
        candidates=[_event(memory_id=memory_id, adapter=AdapterClass.VERDICT)],
        repo=repo,
        judge=judge,
        config=_CONFIG,
        epoch=_EPOCH,
        clock=FakeClock(start=_NOW),
    )

    assert judge.calls[0][0] == "MEMORY-UNDER-TEST"


# --------------------------------------------------------------------------- #
# The tie-break's last resort must not be the one field the CALLER chooses.
# --------------------------------------------------------------------------- #


def test_a_chosen_event_id_cannot_win_a_tie_against_a_server_minted_run_id() -> None:
    """`event_id` is asserted by the SIGNAL'S SOURCE (`require_event_id`
    refuses to mint one on its behalf, so replay dedup means something), which
    makes it caller-chosen. Breaking ties on it alone hands an attacker a
    deterministic win over every honest event it ties with -- submit
    `00000000-...` and own that memory's one daily slot whenever weight and
    arrival collide, which is exactly what D-021's four-day walk needs.
    `run_id` is minted by the service and time-ordered, so it goes first."""
    memory_id = mint_memory_id()
    honest = _event(
        memory_id=memory_id,
        adapter=AdapterClass.VERDICT,
        arrived_at=_NOW,
        run_id=RunId(UUID(int=1)),  # earlier run
        event_id=UUID(int=0xFFFF),  # unlucky high id
        r=1.0,
    )
    attacker = _event(
        memory_id=memory_id,
        adapter=AdapterClass.VERDICT,
        arrived_at=_NOW,
        run_id=RunId(UUID(int=2)),  # later run
        event_id=UUID(int=0),  # chosen to sort first
        r=0.0,
    )

    winner = select_daily_winner([attacker, honest], adapter_weights=_CONFIG.adapter_weights)

    assert winner is not None
    assert winner.event_id == honest.event_id


def test_event_id_still_closes_the_order_when_every_server_field_ties() -> None:
    """Two events from ONE run in ONE transaction are genuinely
    indistinguishable by anything the server minted, and the order still has
    to be total or a replayed batch picks a different winner."""
    memory_id = mint_memory_id()
    run_id = mint_run_id()
    a = _event(
        memory_id=memory_id, adapter=AdapterClass.VERDICT, arrived_at=_NOW, run_id=run_id
    )
    b = _event(
        memory_id=memory_id, adapter=AdapterClass.VERDICT, arrived_at=_NOW, run_id=run_id
    )

    forward = select_daily_winner([a, b], adapter_weights=_CONFIG.adapter_weights)
    backward = select_daily_winner([b, a], adapter_weights=_CONFIG.adapter_weights)

    assert forward is not None
    assert backward is not None
    assert forward.event_id == backward.event_id
    assert forward.event_id == min(a, b, key=lambda e: e.event_id.bytes).event_id


# --------------------------------------------------------------------------- #
# The daily cap is a UTC day on both sides of the port.
# --------------------------------------------------------------------------- #


class OffsetClock:
    """An aware, NON-UTC `Clock`. `Clock.now()` is documented UTC, but nothing
    in `workers.scorer` can check a host clock's zone, and the difference is
    only visible on a day boundary the offset straddles."""

    def __init__(self, instant: datetime) -> None:
        self._instant = instant

    def now(self) -> datetime:
        return self._instant

    def now_ms(self) -> int:
        return int(self._instant.timestamp() * 1000)

    def monotonic_ms(self) -> float:
        return 0.0


def test_the_daily_cap_key_and_the_stamp_are_both_utc_even_on_a_non_utc_clock() -> None:
    """02:00 on the 27th at +05:30 is 20:30 on the 26th in UTC.
    `ScorerRepoPort.scored_updates_today` buckets a UTC calendar date, so a
    scorer checking the LOCAL date would ask about a day the store never
    counted -- giving the memory a second scoreable slot on every day boundary
    the offset straddles."""
    memory_id = mint_memory_id()
    repo = _repo(0.5, memory_id=memory_id)
    local = datetime(2026, 7, 27, 2, 0, tzinfo=timezone(timedelta(hours=5, minutes=30)))

    result = run_scorer_batch(
        project_id=_PROJECT,
        memory_id=memory_id,
        memory_content="m",
        candidates=[_event(memory_id=memory_id, adapter=AdapterClass.VERDICT, arrived_at=local)],
        repo=repo,
        judge=FakeJudge(factor=1.0),
        config=_CONFIG,
        epoch=_EPOCH,
        clock=OffsetClock(local),
    )

    assert repo.day_queries == [date(2026, 7, 26)]
    assert result.applied[0].scored_at == local  # same instant...
    assert result.applied[0].scored_at.tzinfo is UTC  # ...expressed in UTC
    assert result.applied[0].scored_at.date() == repo.day_queries[0]


def test_a_naive_clock_is_refused_rather_than_silently_read_in_host_local_time() -> None:
    """`.astimezone()` on a naive value assumes the HOST's zone, so a naive
    clock would not fail -- it would give this process a different midnight
    than the next one, and the daily cap a different length per host."""
    memory_id = mint_memory_id()
    repo = _repo(0.5, memory_id=memory_id)

    with pytest.raises(ScoringInputInvalid):
        run_scorer_batch(
            project_id=_PROJECT,
            memory_id=memory_id,
            memory_content="m",
            candidates=[_event(memory_id=memory_id, adapter=AdapterClass.VERDICT)],
            repo=repo,
            judge=FakeJudge(factor=1.0),
            config=_CONFIG,
            epoch=_EPOCH,
            clock=OffsetClock(datetime(2026, 7, 26, 12, 0)),
        )

    assert repo.apply_calls == []


# --------------------------------------------------------------------------- #
# `ScoreBatchResult` promises a PARTITION: every distinct candidate event_id
# lands in exactly one of the four tuples. An orchestrator drops
# `skipped_short_circuit` and retries `skipped_cap`, so an id that falls out of
# the report entirely is an outcome that is never scored and never retried, and
# an id in two tuples is one that is both.
# --------------------------------------------------------------------------- #


def _partition_of(result: ScoreBatchResult) -> list[UUID]:
    return [
        *(u.event_id for u in result.applied),
        *result.skipped_replay,
        *result.skipped_short_circuit,
        *result.skipped_cap,
    ]


def test_every_candidate_is_reported_exactly_once_across_every_outcome_path() -> None:
    memory_id = mint_memory_id()
    judge_factor_by_case = {
        "applied + losers": (1.0, AdapterClass.VERDICT, 0),
        "zero contribution": (0.0, AdapterClass.VERDICT, 0),
        "zero weight": (1.0, AdapterClass.IMPLICIT, 0),
        "cap already spent": (1.0, AdapterClass.VERDICT, 1),
    }

    for case, (factor, adapter, prespent) in judge_factor_by_case.items():
        repo = _repo(0.5, memory_id=memory_id)
        clock = FakeClock(start=_NOW)
        if prespent:
            _run(
                repo,
                FakeJudge(factor=1.0),
                [_event(memory_id=memory_id, adapter=AdapterClass.VERDICT)],
                memory_id=memory_id,
                clock=clock,
            )
        already = list(repo.apply_calls)
        fresh = [
            _event(memory_id=memory_id, adapter=adapter, arrived_at=_NOW + timedelta(minutes=i))
            for i in range(3)
        ]
        replayed = [u.event_id for u in already]
        candidates = [*fresh, *(_event(memory_id=memory_id, event_id=e) for e in replayed)]

        result = _run(repo, FakeJudge(factor=factor), candidates, memory_id=memory_id, clock=clock)
        reported = _partition_of(result)

        expected = {e.event_id for e in candidates}
        assert len(reported) == len(set(reported)), f"{case}: an id was reported twice"
        assert set(reported) == expected, f"{case}: an id fell out of the report"


def test_a_replayed_event_is_still_reported_when_the_cap_is_already_spent() -> None:
    """The cap-exceeded early return is its own code path, and dropping the
    replay bookkeeping there would make a replayed id vanish from the report
    -- indistinguishable, to an orchestrator, from an id it never sent."""
    memory_id = mint_memory_id()
    repo = _repo(0.5, memory_id=memory_id)
    clock = FakeClock(start=_NOW)
    applied = _event(memory_id=memory_id, adapter=AdapterClass.VERDICT)
    _run(repo, FakeJudge(factor=1.0), [applied], memory_id=memory_id, clock=clock)

    fresh = _event(memory_id=memory_id, adapter=AdapterClass.VERDICT)
    result = _run(repo, FakeJudge(factor=1.0), [applied, fresh], memory_id=memory_id, clock=clock)

    assert result.skipped_replay == (applied.event_id,)
    assert result.skipped_cap == (fresh.event_id,)
    assert set(_partition_of(result)) == {applied.event_id, fresh.event_id}
