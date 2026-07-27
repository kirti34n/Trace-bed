"""`workers.killswitch` — sustained stratified lift, Benjamini-Hochberg correction, and
auto-disable (PLAN.md section 2 / section 6 `killswitch.*` / section 7 Phase 3; D-027).

Fully offline: `_FakeKillswitchStore` is an in-memory fake for `KillswitchStorePort` (this
chunk's own contract gap, documented in `workers/killswitch.py` — no store-backed
implementation exists in `stores/pg/repo.py` yet), matching this codebase's established
per-chunk fake convention (`tests/phase2/test_invalidator.py`'s `_FakeRepo`,
`tests/phase3/test_promotion.py`'s `_FakeRepo`).

`LiftEstimate` values below are constructed directly rather than via
`workers.lift.estimate_lift` — these tests are about the TRIGGER LOGIC (sustained window,
minimum N, BH correction, direction, exactly-one-cell writes), not about the statistics
`tests/phase3/test_lift.py` already covers, so full control over `lower_bound`/`n_treatment`/
`p_value` per synthetic day keeps each scenario legible.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta, timezone
from typing import Any
from uuid import UUID

import pytest

from tracebed.domain.clock import FakeClock
from tracebed.domain.config import KillswitchConfig
from tracebed.domain.enums import MemType
from tracebed.domain.errors import CrossEpochComparison
from tracebed.domain.ids import AgentTypeId, PrincipalId, ProjectId
from tracebed.workers.killswitch import (
    DailyLiftSnapshot,
    KillswitchGridEvaluator,
    TriggerReason,
    benjamini_hochberg,
    evaluate_sustained,
)
from tracebed.workers.lift import AdverseDirection, LiftEstimate, StratumKey
from tracebed.workers.safety_lift import evaluate_safety_grid

pytestmark = pytest.mark.phase3

PROJECT = ProjectId(UUID(int=1))
AGENT_A = AgentTypeId(UUID(int=10))
AGENT_B = AgentTypeId(UUID(int=11))
START = date(2026, 1, 1)
LAST_DAY = START + timedelta(days=13)
CFG = KillswitchConfig(window_days=14, min_cell_n=200)


class _FakeKillswitchStore:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def write_killswitch_state(
        self,
        project_id: ProjectId,
        agent_type_id: AgentTypeId,
        mem_type: MemType,
        *,
        disabled: bool,
        evidence: object,
        changed_at: datetime,
    ) -> None:
        self.calls.append(
            {
                "project_id": project_id,
                "agent_type_id": agent_type_id,
                "mem_type": mem_type,
                "disabled": disabled,
                "evidence": evidence,
                "changed_at": changed_at,
            }
        )


class _NaiveClock:
    """Structurally a `Clock`, but returns a NAIVE instant — the thing the Protocol contracts
    against and cannot enforce."""

    def now(self) -> datetime:
        return datetime(2026, 1, 14, 23, 30)

    def now_ms(self) -> int:  # pragma: no cover - not exercised
        return 0

    def monotonic_ms(self) -> float:  # pragma: no cover - not exercised
        return 0.0


class _EasternClock:
    """A `Clock` returning an aware instant in a non-UTC zone, late enough in the day that the
    local calendar date and the UTC calendar date differ."""

    def now(self) -> datetime:
        return datetime(2026, 1, 14, 20, 0, tzinfo=timezone(timedelta(hours=-5)))

    def now_ms(self) -> int:  # pragma: no cover - not exercised
        return 0

    def monotonic_ms(self) -> float:  # pragma: no cover - not exercised
        return 0.0


def _history(
    *,
    agent_type_id: AgentTypeId,
    mem_type: MemType,
    days: int,
    start: date,
    lower_bound: float | list[float],
    n_treatment: int | list[int],
    n_control: int | list[int],
    p_value: float | list[float],
    point_estimate: float | list[float] | None = None,
    scoring_epoch_id: int | list[int | None] | None = None,
) -> list[DailyLiftSnapshot]:
    def _seq(value: float | int | list[float] | list[int], length: int) -> list[float]:
        if isinstance(value, list):
            assert len(value) == length
            return [float(v) for v in value]
        return [float(value)] * length

    lbs = _seq(lower_bound, days)
    nts = _seq(n_treatment, days)
    ncs = _seq(n_control, days)
    pvs = _seq(p_value, days)
    # Default: a point estimate just above the lower bound, i.e. the same sign as the bound.
    pes = _seq(point_estimate, days) if point_estimate is not None else [lb + 0.05 for lb in lbs]
    epochs: list[int | None]
    if isinstance(scoring_epoch_id, list):
        assert len(scoring_epoch_id) == days
        epochs = list(scoring_epoch_id)
    else:
        epochs = [scoring_epoch_id] * days
    return [
        DailyLiftSnapshot(
            day=start + timedelta(days=i),
            scoring_epoch_id=epochs[i],
            estimate=LiftEstimate(
                agent_type_id=agent_type_id,
                mem_type=mem_type,
                n_treatment=int(nts[i]),
                n_control=int(ncs[i]),
                point_estimate=pes[i],
                lower_bound=lbs[i],
                upper_bound=lbs[i] + 0.2,
                p_value=pvs[i],
                confidence=0.95,
            ),
        )
        for i in range(days)
    ]


class TestEvaluateSustained:
    def test_requires_full_window_coverage(self) -> None:
        history = _history(
            agent_type_id=AGENT_A,
            mem_type=MemType.LESSON,
            days=10,  # short of the 14-day window
            start=START,
            lower_bound=-0.1,
            n_treatment=250,
            n_control=250,
            p_value=0.001,
        )
        result = evaluate_sustained(
            history, window_days=14, min_cell_n=200, now=START + timedelta(days=9)
        )
        assert result.sustained is False
        assert result.min_n_satisfied is False
        assert result.days_covered == 10

    def test_a_hole_in_the_middle_is_not_a_sustained_window(self) -> None:
        """13 adverse days out of 14, with the gap in the middle rather than at the end — the
        one shape a "count the adverse days" implementation would wave through."""
        history = _history(
            agent_type_id=AGENT_A,
            mem_type=MemType.LESSON,
            days=14,
            start=START,
            lower_bound=-0.1,
            n_treatment=250,
            n_control=250,
            p_value=0.001,
        )
        del history[6]
        result = evaluate_sustained(history, window_days=14, min_cell_n=200, now=LAST_DAY)
        assert result.sustained is False
        assert result.days_covered == 13

    def test_duplicate_day_is_refused_not_last_write_wins(self) -> None:
        """Two estimates for one day means the verdict depends on the order the store returned
        rows in — a governance control must not act on order-dependent evidence."""
        history = _history(
            agent_type_id=AGENT_A,
            mem_type=MemType.LESSON,
            days=14,
            start=START,
            lower_bound=-0.1,
            n_treatment=250,
            n_control=250,
            p_value=0.001,
        )
        history.append(history[3])
        with pytest.raises(ValueError, match="two DailyLiftSnapshots"):
            evaluate_sustained(history, window_days=14, min_cell_n=200, now=LAST_DAY)

    def test_one_positive_day_breaks_sustained(self) -> None:
        lbs = [-0.1] * 14
        lbs[6] = 0.02  # one good day in the middle of an otherwise bad window
        history = _history(
            agent_type_id=AGENT_A,
            mem_type=MemType.LESSON,
            days=14,
            start=START,
            lower_bound=lbs,
            n_treatment=250,
            n_control=250,
            p_value=0.001,
        )
        result = evaluate_sustained(history, window_days=14, min_cell_n=200, now=LAST_DAY)
        assert result.sustained is False
        assert result.min_n_satisfied is True  # N was fine every day

    @pytest.mark.parametrize("thin_day", [0, 7, 13])
    def test_one_thin_day_anywhere_breaks_min_n(self, thin_day: int) -> None:
        nts = [250] * 14
        nts[thin_day] = 50  # below min_cell_n on exactly one day
        history = _history(
            agent_type_id=AGENT_A,
            mem_type=MemType.LESSON,
            days=14,
            start=START,
            lower_bound=-0.1,
            n_treatment=nts,
            n_control=250,
            p_value=0.001,
        )
        result = evaluate_sustained(history, window_days=14, min_cell_n=200, now=LAST_DAY)
        assert result.sustained is True
        assert result.min_n_satisfied is False

    def test_thin_control_arm_alone_breaks_min_n(self) -> None:
        """N is required on BOTH arms: 250 treatment runs against 50 shadow controls is not a
        200-per-cell comparison, it is a 50-run comparison with a big number next to it."""
        ncs = [250] * 14
        ncs[5] = 50
        history = _history(
            agent_type_id=AGENT_A,
            mem_type=MemType.LESSON,
            days=14,
            start=START,
            lower_bound=-0.1,
            n_treatment=250,
            n_control=ncs,
            p_value=0.001,
        )
        result = evaluate_sustained(history, window_days=14, min_cell_n=200, now=LAST_DAY)
        assert result.min_n_satisfied is False

    def test_exactly_min_cell_n_is_enough(self) -> None:
        """`min_cell_n` is a floor, not a strict bound — the off-by-one that would make N=200
        fail a `min_cell_n=200` policy."""
        history = _history(
            agent_type_id=AGENT_A,
            mem_type=MemType.LESSON,
            days=14,
            start=START,
            lower_bound=-0.1,
            n_treatment=200,
            n_control=200,
            p_value=0.001,
        )
        result = evaluate_sustained(history, window_days=14, min_cell_n=200, now=LAST_DAY)
        assert result.min_n_satisfied is True

    def test_fully_sustained_window_passes_both(self) -> None:
        history = _history(
            agent_type_id=AGENT_A,
            mem_type=MemType.LESSON,
            days=14,
            start=START,
            lower_bound=-0.1,
            n_treatment=250,
            n_control=250,
            p_value=0.001,
        )
        result = evaluate_sustained(history, window_days=14, min_cell_n=200, now=LAST_DAY)
        assert result.sustained is True
        assert result.min_n_satisfied is True
        assert result.latest_estimate is not None

    def test_window_is_exactly_window_days_long(self) -> None:
        """A 14-day window ending on day 13 starts on day 0 — a 15th day of history before it
        is outside the window and cannot rescue or condemn the cell."""
        history = _history(
            agent_type_id=AGENT_A,
            mem_type=MemType.LESSON,
            days=15,
            start=START - timedelta(days=1),
            lower_bound=[0.5] + [-0.1] * 14,  # the out-of-window day is the healthy one
            n_treatment=250,
            n_control=250,
            p_value=0.001,
        )
        assert evaluate_sustained(
            history, window_days=14, min_cell_n=200, now=LAST_DAY
        ).sustained is True
        # Shift the window one day earlier and the healthy day is now inside it.
        assert evaluate_sustained(
            history, window_days=14, min_cell_n=200, now=LAST_DAY - timedelta(days=1)
        ).sustained is False

    def test_higher_direction_inverts_the_adverse_test(self) -> None:
        history = _history(
            agent_type_id=AGENT_A,
            mem_type=MemType.LESSON,
            days=14,
            start=START,
            lower_bound=0.1,  # violations up: adverse for safety, healthy for task quality
            n_treatment=250,
            n_control=250,
            p_value=0.001,
        )
        assert evaluate_sustained(
            history, window_days=14, min_cell_n=200, now=LAST_DAY
        ).sustained is False
        assert evaluate_sustained(
            history,
            window_days=14,
            min_cell_n=200,
            now=LAST_DAY,
            direction=AdverseDirection.HIGHER,
        ).sustained is True

    @pytest.mark.parametrize(("window_days", "min_cell_n"), [(0, 200), (-1, 200), (14, 0)])
    def test_degenerate_parameters_rejected(self, window_days: int, min_cell_n: int) -> None:
        with pytest.raises(ValueError):
            evaluate_sustained([], window_days=window_days, min_cell_n=min_cell_n, now=START)


class TestBenjaminiHochberg:
    def test_empty_input(self) -> None:
        assert benjamini_hochberg([]) == []

    def test_rejects_more_at_raw_alpha_than_after_correction(self) -> None:
        """20 p-values: 19 realistic independent nulls (spread out, one dips under the raw
        alpha=0.05 by chance) plus one real signal at p=0.0005. Naive testing at alpha=0.05
        flags 2 (the real signal AND the one null that got lucky); BH flags only 1 — the
        exact "BH correction reduces false positives across a 20-cell grid" gate clause.
        """
        nulls = [
            0.03, 0.12, 0.20, 0.28, 0.35, 0.40, 0.45, 0.50, 0.55, 0.58,
            0.62, 0.66, 0.70, 0.74, 0.78, 0.82, 0.85, 0.90, 0.95,
        ]
        assert len(nulls) == 19
        p_values = [0.0005, *nulls]

        naive_significant = sum(1 for p in p_values if p < 0.05)
        assert naive_significant == 2  # 0.0005 and 0.03

        rejected = benjamini_hochberg(p_values, alpha=0.05)
        assert sum(rejected) == 1
        assert rejected[0] is True  # the real signal, p=0.0005
        assert rejected[p_values.index(0.03)] is False  # the lucky null is NOT flagged

    @pytest.mark.parametrize(
        ("p_values", "expected"),
        [
            # rank 2 of 4 at alpha=0.05 -> threshold exactly 0.025, and 0.5 * 0.05 is exactly
            # representable, so this is a true equality and not a float near-miss.
            ([0.001, 0.025, 0.3, 0.4], [True, True, False, False]),
            # rank 4 of 4 -> threshold exactly 0.05, the whole grid rides on the boundary case.
            ([0.001, 0.01, 0.02, 0.05], [True, True, True, True]),
        ],
    )
    def test_a_p_value_exactly_on_its_rank_threshold_is_rejected(
        self, p_values: list[float], expected: list[bool]
    ) -> None:
        """MUTATION GUARD on the comparison itself. Benjamini-Hochberg is defined with `<=`:
        the largest rank k with `p_(k) <= (k/m)*alpha`. Tightening it to `<` silently lowers the
        realised FDR below the level the operator configured — the kill switch then keeps
        serving a memory type whose evidence exactly met the bar it was told to act on, and
        nothing in any report says why."""
        assert benjamini_hochberg(p_values, alpha=0.05) == expected

    def test_is_step_up_not_step_down(self) -> None:
        """The defining behaviour of BH: a p-value that FAILS its own rank threshold is still
        rejected when a LATER rank passes. A step-down implementation (stop at the first
        failure) rejects only the first here; BH rejects all four.

        m=4, alpha=0.05 -> thresholds 0.0125 / 0.025 / 0.0375 / 0.05. p=0.03 fails rank 2 and
        p=0.035 fails rank 3, but p=0.04 passes rank 4, so k=4 and every one is rejected.
        """
        p_values = [0.001, 0.03, 0.035, 0.04]
        assert benjamini_hochberg(p_values, alpha=0.05) == [True] * 4

    def test_order_of_input_does_not_change_which_entries_are_rejected(self) -> None:
        p_values = [0.04, 0.001, 0.035, 0.03]
        rejected = benjamini_hochberg(p_values, alpha=0.05)
        assert rejected == [True] * 4
        shuffled = [0.5, 0.001, 0.5, 0.5]
        assert benjamini_hochberg(shuffled, alpha=0.05) == [False, True, False, False]

    def test_strong_signal_grid_rejects_all(self) -> None:
        p_values = [0.0001] * 5
        assert benjamini_hochberg(p_values, alpha=0.05) == [True] * 5

    def test_nothing_is_rejected_when_no_p_value_clears_its_rank(self) -> None:
        assert benjamini_hochberg([0.2, 0.3, 0.4, 0.5], alpha=0.05) == [False] * 4

    def test_rejects_alpha_out_of_range(self) -> None:
        with pytest.raises(ValueError, match="alpha must be"):
            benjamini_hochberg([0.1, 0.2], alpha=1.5)

    def test_alpha_is_validated_even_on_an_empty_grid(self) -> None:
        with pytest.raises(ValueError, match="alpha must be"):
            benjamini_hochberg([], alpha=1.5)

    def test_rejects_p_value_out_of_range(self) -> None:
        with pytest.raises(ValueError, match="p-value out of"):
            benjamini_hochberg([0.1, 1.5])


def _clock(now: date) -> FakeClock:
    return FakeClock(start=datetime(now.year, now.month, now.day, tzinfo=UTC))


def _evaluator(store: _FakeKillswitchStore | None = None) -> KillswitchGridEvaluator:
    return KillswitchGridEvaluator(store or _FakeKillswitchStore(), _clock(LAST_DAY))


class TestTriggerNeedsAllConditions:
    """"the trigger needs all of {LCB<0, sustained 14d, N>=200} and fires on none of them
    alone" (gate clause, verbatim) — plus the BH correction as the fourth."""

    def _one_cell_grid(self, **history_kwargs: Any) -> dict[StratumKey, list[DailyLiftSnapshot]]:
        history = _history(
            agent_type_id=AGENT_A, mem_type=MemType.LESSON, start=START, **history_kwargs
        )
        return {(AGENT_A, MemType.LESSON): history}

    def test_all_conditions_hold_triggers(self) -> None:
        grid = self._one_cell_grid(
            days=14, lower_bound=-0.1, n_treatment=250, n_control=250, p_value=0.0001
        )
        decisions = _evaluator().evaluate_grid(grid, cfg=CFG, now=LAST_DAY)
        decision = decisions[(AGENT_A, MemType.LESSON)]
        assert decision.sustained is True
        assert decision.min_n_satisfied is True
        assert decision.bh_significant is True
        assert decision.should_disable is True

    def test_lcb_not_sustained_alone_does_not_trigger(self) -> None:
        lbs = [-0.1] * 14
        lbs[5] = 0.05
        grid = self._one_cell_grid(
            days=14, lower_bound=lbs, n_treatment=250, n_control=250, p_value=0.0001
        )
        decisions = _evaluator().evaluate_grid(grid, cfg=CFG, now=LAST_DAY)
        decision = decisions[(AGENT_A, MemType.LESSON)]
        assert decision.sustained is False
        assert decision.min_n_satisfied is True
        assert decision.bh_significant is True
        assert decision.should_disable is False

    def test_min_n_alone_does_not_trigger(self) -> None:
        nts = [250] * 14
        nts[0] = 10
        grid = self._one_cell_grid(
            days=14, lower_bound=-0.1, n_treatment=nts, n_control=250, p_value=0.0001
        )
        decisions = _evaluator().evaluate_grid(grid, cfg=CFG, now=LAST_DAY)
        decision = decisions[(AGENT_A, MemType.LESSON)]
        assert decision.sustained is True
        assert decision.min_n_satisfied is False
        assert decision.should_disable is False

    def test_bh_alone_does_not_trigger(self) -> None:
        """Two cells: this one is sustained + N-satisfied but its own p-value is large (not
        significant); the other cell is a strong true signal. BH must not reject the
        non-significant cell just because it shares a grid with a significant one."""
        weak_cell = self._one_cell_grid(
            days=14, lower_bound=-0.1, n_treatment=250, n_control=250, p_value=0.9
        )
        strong_history = _history(
            agent_type_id=AGENT_B,
            mem_type=MemType.SEMANTIC,
            days=14,
            start=START,
            lower_bound=-0.3,
            n_treatment=250,
            n_control=250,
            p_value=0.0001,
        )
        grid: dict[StratumKey, list[DailyLiftSnapshot]] = {
            **weak_cell,
            (AGENT_B, MemType.SEMANTIC): strong_history,
        }
        decisions = _evaluator().evaluate_grid(grid, cfg=CFG, now=LAST_DAY)
        weak_decision = decisions[(AGENT_A, MemType.LESSON)]
        strong_decision = decisions[(AGENT_B, MemType.SEMANTIC)]
        assert weak_decision.sustained is True
        assert weak_decision.min_n_satisfied is True
        assert weak_decision.bh_significant is False
        assert weak_decision.should_disable is False
        assert strong_decision.should_disable is True

    def test_a_permanently_under_reported_cell_says_so_in_its_evidence(self) -> None:
        """`evaluate_sustained` fails closed on a coverage gap, which for a KILL SWITCH means
        "keep serving this memory type". A cell whose snapshot job misses one day in every
        window can therefore never be disabled, and `sustained=False` reads identically to a
        genuinely healthy cell. The coverage pair is what separates the two on the way out."""
        grid = self._one_cell_grid(
            days=13, lower_bound=-0.1, n_treatment=250, n_control=250, p_value=0.0001
        )
        decision = _evaluator().evaluate_grid(grid, cfg=CFG, now=LAST_DAY)[
            (AGENT_A, MemType.LESSON)
        ]
        assert decision.sustained is False
        assert decision.evidence["days_covered"] == 13
        assert decision.evidence["window_days"] == 14

        healthy = self._one_cell_grid(
            days=14, lower_bound=0.5, n_treatment=250, n_control=250, p_value=0.9
        )
        healthy_decision = _evaluator().evaluate_grid(healthy, cfg=CFG, now=LAST_DAY)[
            (AGENT_A, MemType.LESSON)
        ]
        assert healthy_decision.sustained is False
        assert healthy_decision.evidence["days_covered"] == 14

    def test_missing_snapshot_for_today_is_treated_as_p_one(self) -> None:
        """A cell whose latest day is missing has no p-value to correct; it must be maximally
        non-significant, never carried by its neighbours."""
        history = _history(
            agent_type_id=AGENT_A,
            mem_type=MemType.LESSON,
            days=13,
            start=START,
            lower_bound=-0.1,
            n_treatment=250,
            n_control=250,
            p_value=0.0001,
        )
        decisions = _evaluator().evaluate_grid(
            {(AGENT_A, MemType.LESSON): history}, cfg=CFG, now=LAST_DAY
        )
        decision = decisions[(AGENT_A, MemType.LESSON)]
        assert decision.latest_estimate is None
        assert decision.bh_significant is False
        assert decision.should_disable is False


class TestTriggerDirection:
    """REGRESSION. The trigger's conservative-bound test ("lower bound < 0") and its
    significance test must agree on which sign is bad. They did not: `LiftEstimate.p_value` is
    two-sided, so a cell whose memory type was significantly HELPING (+0.5, p=0.001) but whose
    99% bound dipped below zero satisfied both and was auto-disabled — the kill switch turning
    off the memory that was working."""

    def _helpful_but_wide(self, direction_days: int = 14) -> list[DailyLiftSnapshot]:
        return _history(
            agent_type_id=AGENT_A,
            mem_type=MemType.LESSON,
            days=direction_days,
            start=START,
            lower_bound=-0.05,  # 99% bound dips below zero...
            point_estimate=0.5,  # ...but memory is helping, a lot
            n_treatment=250,
            n_control=250,
            p_value=0.001,  # two-sided: tiny BECAUSE the effect is large
        )

    def test_a_significantly_helping_cell_is_never_disabled(self) -> None:
        grid = {(AGENT_A, MemType.LESSON): self._helpful_but_wide()}
        store = _FakeKillswitchStore()
        evaluator = _evaluator(store)
        decisions = evaluator.evaluate_grid(grid, cfg=CFG, now=LAST_DAY)
        decision = decisions[(AGENT_A, MemType.LESSON)]

        assert decision.sustained is True  # the permissive LCB<0 screen still passes
        assert decision.min_n_satisfied is True
        assert decision.bh_significant is False  # ...but not in the ADVERSE direction
        assert decision.should_disable is False
        assert evaluator.apply(PROJECT, decisions) == ()
        assert store.calls == []

    def test_the_same_magnitude_of_harm_does_disable(self) -> None:
        """The mirror image of the case above, so the regression test cannot pass by simply
        never triggering."""
        harmful = _history(
            agent_type_id=AGENT_A,
            mem_type=MemType.LESSON,
            days=14,
            start=START,
            lower_bound=-0.55,
            point_estimate=-0.5,
            n_treatment=250,
            n_control=250,
            p_value=0.001,
        )
        decisions = _evaluator().evaluate_grid(
            {(AGENT_A, MemType.LESSON): harmful}, cfg=CFG, now=LAST_DAY
        )
        assert decisions[(AGENT_A, MemType.LESSON)].should_disable is True

    def test_evidence_records_the_direction_and_the_directional_p_value(self) -> None:
        grid = {(AGENT_A, MemType.LESSON): self._helpful_but_wide()}
        decisions = _evaluator().evaluate_grid(grid, cfg=CFG, now=LAST_DAY)
        evidence = decisions[(AGENT_A, MemType.LESSON)].evidence
        assert evidence["adverse_direction"] == AdverseDirection.LOWER.value
        assert evidence["p_value"] == 0.001  # the raw two-sided statistic, kept
        assert float(str(evidence["directional_p_value"])) > 0.99  # what BH actually saw


class TestClockAndDayBucketing:
    def test_naive_clock_is_refused_rather_than_bucketed_to_host_local_time(self) -> None:
        evaluator = KillswitchGridEvaluator(_FakeKillswitchStore(), _NaiveClock())
        with pytest.raises(ValueError, match="timezone-aware"):
            evaluator.evaluate_grid({}, cfg=CFG)

    def test_day_is_derived_in_utc_not_in_the_clocks_own_zone(self) -> None:
        """20:00 on 2026-01-14 at UTC-5 is 01:00 on 2026-01-15 UTC. Reading `.date()` off the
        aware-but-not-UTC instant would evaluate the window one day early."""
        history = _history(
            agent_type_id=AGENT_A,
            mem_type=MemType.LESSON,
            days=14,
            start=date(2026, 1, 2),  # window ends 2026-01-15 UTC
            lower_bound=-0.1,
            n_treatment=250,
            n_control=250,
            p_value=0.0001,
        )
        evaluator = KillswitchGridEvaluator(_FakeKillswitchStore(), _EasternClock())
        decisions = evaluator.evaluate_grid({(AGENT_A, MemType.LESSON): history}, cfg=CFG)
        assert decisions[(AGENT_A, MemType.LESSON)].should_disable is True

    def test_naive_changed_at_is_refused(self) -> None:
        evaluator = _evaluator()
        with pytest.raises(ValueError, match="timezone-aware"):
            evaluator.record_override(
                PROJECT,
                AGENT_A,
                MemType.LESSON,
                disabled=False,
                principal_id=PrincipalId(UUID(int=9)),
                justification="mistaken trigger",
                now=datetime(2026, 1, 1),
            )


class TestApplyDisablesExactlyTheCausingCell:
    def _grid(self) -> dict[StratumKey, list[DailyLiftSnapshot]]:
        triggering = _history(
            agent_type_id=AGENT_A, mem_type=MemType.LESSON, days=14, start=START,
            lower_bound=-0.2, n_treatment=250, n_control=250, p_value=0.0001,
        )
        healthy = _history(
            agent_type_id=AGENT_B, mem_type=MemType.SEMANTIC, days=14, start=START,
            lower_bound=0.1, n_treatment=250, n_control=250, p_value=0.9,
        )
        return {
            (AGENT_A, MemType.LESSON): triggering,
            (AGENT_B, MemType.SEMANTIC): healthy,
        }

    def test_only_the_triggering_cell_is_written(self) -> None:
        store = _FakeKillswitchStore()
        evaluator = _evaluator(store)
        decisions = evaluator.evaluate_grid(self._grid(), cfg=CFG, now=LAST_DAY)
        applied = evaluator.apply(PROJECT, decisions)

        assert applied == ((AGENT_A, MemType.LESSON),)
        assert len(store.calls) == 1
        call = store.calls[0]
        assert call["agent_type_id"] == AGENT_A
        assert call["mem_type"] == MemType.LESSON
        assert call["disabled"] is True
        changed_at = call["changed_at"]
        assert isinstance(changed_at, datetime)
        assert changed_at.tzinfo is not None
        evidence = call["evidence"]
        assert isinstance(evidence, dict)
        assert evidence["source"] == "auto_killswitch"
        assert evidence["reason"] == TriggerReason.TASK_QUALITY_LIFT.value

    def test_a_grid_with_nothing_triggering_writes_nothing_at_all(self) -> None:
        """`apply` must be a no-op on a healthy fleet — not "writes disabled=False rows"."""
        healthy_only = {
            key: history
            for key, history in self._grid().items()
            if key != (AGENT_A, MemType.LESSON)
        }
        store = _FakeKillswitchStore()
        evaluator = _evaluator(store)
        decisions = evaluator.evaluate_grid(healthy_only, cfg=CFG, now=LAST_DAY)
        assert evaluator.apply(PROJECT, decisions) == ()
        assert store.calls == []

    def test_a_failing_audit_sink_does_not_undo_the_write(self) -> None:
        class _BrokenAudit:
            def emit(self, event: object) -> None:
                raise RuntimeError("audit sink down")

        store = _FakeKillswitchStore()
        evaluator = KillswitchGridEvaluator(store, _clock(LAST_DAY), audit=_BrokenAudit())
        decisions = evaluator.evaluate_grid(self._grid(), cfg=CFG, now=LAST_DAY)
        assert evaluator.apply(PROJECT, decisions) == ((AGENT_A, MemType.LESSON),)
        assert len(store.calls) == 1

    def test_audit_evidence_cannot_overwrite_the_envelope(self) -> None:
        """`evidence` is a Mapping this class does not own end to end; splatting it into the
        audit event would let a key named `project_id` rewrite whose project the record names."""
        emitted: list[dict[str, object]] = []

        class _Audit:
            def emit(self, event: dict[str, object]) -> None:
                emitted.append(event)

        store = _FakeKillswitchStore()
        evaluator = KillswitchGridEvaluator(store, _clock(LAST_DAY), audit=_Audit())
        evaluator.record_override(
            PROJECT,
            AGENT_A,
            MemType.LESSON,
            disabled=False,
            principal_id=PrincipalId(UUID(int=99)),
            justification="rolled back a bad prompt template",
        )
        assert len(emitted) == 1
        assert emitted[0]["project_id"] == str(PROJECT)
        assert isinstance(emitted[0]["evidence"], dict)


class TestDeveloperOverride:
    def test_override_recorded_distinctly_from_auto_trigger(self) -> None:
        store = _FakeKillswitchStore()
        evaluator = KillswitchGridEvaluator(store, _clock(START))
        principal = PrincipalId(UUID(int=99))

        evaluator.record_override(
            PROJECT,
            AGENT_A,
            MemType.LESSON,
            disabled=False,
            principal_id=principal,
            justification="operator confirmed the lift regression was a bad prompt template",
        )

        assert len(store.calls) == 1
        call = store.calls[0]
        assert call["disabled"] is False
        evidence = call["evidence"]
        assert isinstance(evidence, dict)
        assert evidence["source"] == "operator_override"
        assert evidence["principal_id"] == str(principal)
        assert "operator confirmed" in str(evidence["override_reason"])

    def test_override_records_which_control_it_overrides(self) -> None:
        """An operator re-enabling a mem_type the SAFETY switch disabled, filed under
        `task_quality_lift`, is an audit trail that says the opposite of what happened."""
        store = _FakeKillswitchStore()
        evaluator = KillswitchGridEvaluator(store, _clock(START))
        evaluator.record_override(
            PROJECT,
            AGENT_A,
            MemType.LESSON,
            disabled=False,
            principal_id=PrincipalId(UUID(int=1)),
            justification="violation judge was misconfigured for two weeks",
            trigger_reason=TriggerReason.SAFETY_VIOLATION_RATE,
        )
        evidence = store.calls[0]["evidence"]
        assert isinstance(evidence, dict)
        assert evidence["reason"] == TriggerReason.SAFETY_VIOLATION_RATE.value

    @pytest.mark.parametrize("justification", ["", "   ", "\n\t"])
    def test_override_requires_a_real_justification(self, justification: str) -> None:
        evaluator = _evaluator()
        with pytest.raises(ValueError, match="non-empty justification"):
            evaluator.record_override(
                PROJECT,
                AGENT_A,
                MemType.LESSON,
                disabled=True,
                principal_id=PrincipalId(UUID(int=1)),
                justification=justification,
            )


class TestSafetyGrid:
    """`workers.safety_lift.evaluate_safety_grid` — CUTTABLE improvement 2 (PLAN.md section 8
    item 2). It reuses this module's sustained/min-N/BH/write machinery with the adverse
    direction inverted; before this suite existed nothing imported the module at all, so none
    of that reuse was ever executed."""

    def _rising_violations(self, epoch: int | list[int | None] | None = 7) -> list[
        DailyLiftSnapshot
    ]:
        """Violations significantly HIGHER with memory on, every day for 14 days."""
        return _history(
            agent_type_id=AGENT_A,
            mem_type=MemType.LESSON,
            days=14,
            start=START,
            lower_bound=0.08,
            point_estimate=0.15,
            n_treatment=250,
            n_control=250,
            p_value=0.0001,
            scoring_epoch_id=epoch,
        )

    def test_rising_violation_rate_disables_the_cell(self) -> None:
        store = _FakeKillswitchStore()
        evaluator = _evaluator(store)
        decisions = evaluate_safety_grid(
            evaluator,
            {(AGENT_A, MemType.LESSON): self._rising_violations()},
            cfg=CFG,
            scoring_epoch_id=7,
        )
        decision = decisions[(AGENT_A, MemType.LESSON)]
        assert decision.reason is TriggerReason.SAFETY_VIOLATION_RATE
        assert decision.should_disable is True

        assert evaluator.apply(PROJECT, decisions) == ((AGENT_A, MemType.LESSON),)
        evidence = store.calls[0]["evidence"]
        assert isinstance(evidence, dict)
        assert evidence["reason"] == TriggerReason.SAFETY_VIOLATION_RATE.value
        assert evidence["adverse_direction"] == AdverseDirection.HIGHER.value
        # Hard rule 7: violation_r is a judged artifact, so the decision records its epoch.
        assert evidence["scoring_epoch_id"] == 7

    def test_the_task_quality_switch_does_not_fire_on_the_same_history(self) -> None:
        """The whole reason improvement 2 exists: task quality can be flat or improving
        (lower bound comfortably above zero) while safety degrades. The default direction must
        see nothing here."""
        decisions = _evaluator().evaluate_grid(
            {(AGENT_A, MemType.LESSON): self._rising_violations()}, cfg=CFG, now=LAST_DAY
        )
        assert decisions[(AGENT_A, MemType.LESSON)].should_disable is False

    def test_falling_violation_rate_is_not_adverse(self) -> None:
        """Memory making the fleet SAFER must not trip the safety switch — the mirror of the
        task-quality direction regression."""
        improving = _history(
            agent_type_id=AGENT_A,
            mem_type=MemType.LESSON,
            days=14,
            start=START,
            lower_bound=-0.20,
            point_estimate=-0.15,
            n_treatment=250,
            n_control=250,
            p_value=0.0001,
            scoring_epoch_id=7,
        )
        store = _FakeKillswitchStore()
        evaluator = _evaluator(store)
        decisions = evaluate_safety_grid(
            evaluator,
            {(AGENT_A, MemType.LESSON): improving},
            cfg=CFG,
            scoring_epoch_id=7,
        )
        assert decisions[(AGENT_A, MemType.LESSON)].sustained is False
        assert decisions[(AGENT_A, MemType.LESSON)].should_disable is False
        assert evaluator.apply(PROJECT, decisions) == ()
        assert store.calls == []

    def test_a_noisy_positive_violation_estimate_is_not_sustained(self) -> None:
        """Violations look higher on average but the interval still crosses zero. The safety
        switch acts on the conservative bound, not on the centre -- otherwise every noisy cell
        in a 20-cell grid trips it."""
        noisy = _history(
            agent_type_id=AGENT_A,
            mem_type=MemType.LESSON,
            days=14,
            start=START,
            lower_bound=-0.02,
            point_estimate=0.15,
            n_treatment=250,
            n_control=250,
            p_value=0.0001,
            scoring_epoch_id=7,
        )
        decisions = evaluate_safety_grid(
            _evaluator(), {(AGENT_A, MemType.LESSON): noisy}, cfg=CFG, scoring_epoch_id=7
        )
        decision = decisions[(AGENT_A, MemType.LESSON)]
        assert decision.sustained is False
        assert decision.should_disable is False

    def test_a_judge_swap_mid_window_is_refused_not_averaged(self) -> None:
        """HARD RULE 7, one level up from `compute_stratified_safety_lift`'s own guard.

        `violation_r` is a judged artifact, so a per-day estimate already refuses to pool two
        epochs. But the TRIGGER compares fourteen of those estimates, and a judge swap on day 7
        means half the window measured violations with one ruler and half with another — while
        `evidence["scoring_epoch_id"]` would have claimed a single one. Averaging the two and
        calling the result a safety trend is exactly the silent comparison D-008 forbids."""
        epochs: list[int | None] = [7] * 7 + [8] * 7
        with pytest.raises(CrossEpochComparison, match="scoring_epoch"):
            evaluate_safety_grid(
                _evaluator(),
                {(AGENT_A, MemType.LESSON): self._rising_violations(epochs)},
                cfg=CFG,
                scoring_epoch_id=8,
            )

    def test_an_unstamped_day_is_refused_too(self) -> None:
        """A judged value with no epoch cannot be compared to anything; accepting it would let
        an unstamped day ride along inside a window claiming to be single-epoch."""
        epochs: list[int | None] = [7] * 13 + [None]
        with pytest.raises(CrossEpochComparison, match="scoring_epoch"):
            evaluate_safety_grid(
                _evaluator(),
                {(AGENT_A, MemType.LESSON): self._rising_violations(epochs)},
                cfg=CFG,
                scoring_epoch_id=7,
            )

    def test_an_out_of_window_epoch_change_is_not_a_cross_epoch_comparison(self) -> None:
        """The guard is about what is COMPARED. A day before the window is not compared to
        anything, so an older epoch sitting in the history must not make the window unevaluable
        forever — that would be a control that disarms itself the first time a judge changes."""
        history = _history(
            agent_type_id=AGENT_A,
            mem_type=MemType.LESSON,
            days=15,
            start=START - timedelta(days=1),
            lower_bound=0.08,
            point_estimate=0.15,
            n_treatment=250,
            n_control=250,
            p_value=0.0001,
            scoring_epoch_id=[6] + [7] * 14,
        )
        decisions = evaluate_safety_grid(
            _evaluator(), {(AGENT_A, MemType.LESSON): history}, cfg=CFG, scoring_epoch_id=7
        )
        assert decisions[(AGENT_A, MemType.LESSON)].should_disable is True

    def test_the_task_quality_path_does_not_require_an_epoch(self) -> None:
        """The asymmetry, asserted rather than described: adapter-derived outcome polarity has
        no judge in its lineage, so unstamped task-quality snapshots stay evaluable."""
        decisions = _evaluator().evaluate_grid(
            {(AGENT_A, MemType.LESSON): self._rising_violations(None)}, cfg=CFG, now=LAST_DAY
        )
        assert decisions[(AGENT_A, MemType.LESSON)].sustained is False  # healthy for task quality

    def test_safety_switch_still_needs_sustained_and_min_n(self) -> None:
        """The inverted direction reuses the SAME three conditions, not a shortcut past them."""
        thin = _history(
            agent_type_id=AGENT_A,
            mem_type=MemType.LESSON,
            days=14,
            start=START,
            lower_bound=0.08,
            point_estimate=0.15,
            n_treatment=[199] + [250] * 13,
            n_control=250,
            p_value=0.0001,
            scoring_epoch_id=7,
        )
        decisions = evaluate_safety_grid(
            _evaluator(), {(AGENT_A, MemType.LESSON): thin}, cfg=CFG, scoring_epoch_id=7
        )
        decision = decisions[(AGENT_A, MemType.LESSON)]
        assert decision.sustained is True
        assert decision.min_n_satisfied is False
        assert decision.should_disable is False
