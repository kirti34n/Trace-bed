"""`workers.lift` — stratified kill-switch lift (PLAN.md section 2 / section 7 Phase 3;
D-027).

Fully offline: every `LiftObservation` is built in memory with a fixed-seed `random.Random`
for reproducible synthetic fleets (this codebase's convention for offline probabilistic
tests, e.g. `tests/phase2/test_baseline_drift.py`'s deterministic drift fixtures).
"""

from __future__ import annotations

import math
import random
import statistics
from collections.abc import Sequence
from dataclasses import dataclass
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
from tracebed.domain.enums import Arm, MemType, OutcomeCode, Slot
from tracebed.domain.errors import CrossEpochComparison
from tracebed.domain.events import ContextSlot, RunContext
from tracebed.domain.ids import AgentTypeId, MemoryId, PrincipalId, ProjectId, RunId
from tracebed.domain.scope import ProjectScope
from tracebed.hotpath.fusion import FusedCandidate
from tracebed.hotpath.pipeline import CandidateSetResult, Pipeline
from tracebed.stores.pg.rows import InjectionRow
from tracebed.workers.lift import (
    AdverseDirection,
    LiftEstimate,
    LiftObservation,
    compute_stratified_lift,
    directional_p_value,
    estimate_lift,
    is_adverse,
    is_shadow_control,
    is_treatment,
    naive_aggregate_lift,
    stratify,
)
from tracebed.workers.safety_lift import (
    SafetyObservation,
    assert_single_epoch,
    compute_stratified_safety_lift,
    stratify_safety,
)
from tracebed.workers.safety_lift import is_shadow_control as safety_is_shadow_control
from tracebed.workers.safety_lift import is_treatment as safety_is_treatment

pytestmark = pytest.mark.phase3

AGENT_A = AgentTypeId(UUID(int=1))
AGENT_B = AgentTypeId(UUID(int=2))


def _default_effective_config() -> EffectiveConfig:
    """Shipped defaults throughout — `TestDegradedLexicalIsAmbiguous` is about what the real
    `Pipeline` records, so nothing here may be tuned to produce the answer it asserts."""
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
        # The ONE tuned field, and it is tuned AWAY from an outcome, not towards one: the
        # holdout arm is memory-off (D-099), so at the shipped 5% default a run whose random
        # agent_type happens to hash into holdout records `OutcomeCode.HOLDOUT` instead of
        # whatever fault the test injected — roughly one run in twenty, at random. Pinned to 0
        # so `TestDegradedLexicalIsAmbiguous` observes the arm it is actually about; the
        # holdout arm's own recording behaviour is covered in tests/phase1/test_pipeline.py.
        killswitch=KillswitchConfig(holdout_pct=0.0),
        spend=SpendConfig(),
        cache=CacheConfig(),
        session=SessionConfig(),
        queue=QueueConfig(),
        killswitch_overlay={},
    )


def _run_id(rng: random.Random) -> RunId:
    return RunId(UUID(int=rng.getrandbits(128)))


def _bernoulli_obs(
    rng: random.Random,
    *,
    agent_type_id: AgentTypeId,
    mem_type: MemType | None,
    arm: Arm,
    outcome_code: OutcomeCode,
    p: float,
) -> LiftObservation:
    r = 1.0 if rng.random() < p else 0.0
    return LiftObservation(
        run_id=_run_id(rng),
        agent_type_id=agent_type_id,
        arm=arm,
        outcome_code=outcome_code,
        mem_type=mem_type,
        outcome_r=r,
    )


def _signal_cell(
    rng: random.Random,
    *,
    agent_type_id: AgentTypeId,
    mem_type: MemType,
    p_treatment: float,
    p_control: float,
    n: int,
    control_code: OutcomeCode = OutcomeCode.HOLDOUT,
) -> list[LiftObservation]:
    """`n` treatment (`memory_on`, memory placed) runs at `p_treatment`, plus `n`
    shadow-control (`holdout` arm, memory would have been placed) runs at `p_control`."""
    obs = [
        _bernoulli_obs(
            rng,
            agent_type_id=agent_type_id,
            mem_type=mem_type,
            arm=Arm.MEMORY_ON,
            outcome_code=OutcomeCode.INJECTED,
            p=p_treatment,
        )
        for _ in range(n)
    ]
    obs += [
        _bernoulli_obs(
            rng,
            agent_type_id=agent_type_id,
            mem_type=mem_type,
            arm=Arm.HOLDOUT,
            outcome_code=control_code,
            p=p_control,
        )
        for _ in range(n)
    ]
    return obs


def _non_placing_noise(
    rng: random.Random,
    *,
    agent_type_id: AgentTypeId,
    n: int,
    p: float,
    outcome_code: OutcomeCode = OutcomeCode.ABSTAINED_THRESHOLD,
) -> list[LiftObservation]:
    """Runs where nothing was, or would have been, injected in EITHER arm — abstention at
    `abstention.target_abstention_pct >= 50` dominates a real fleet, and this is what
    `naive_aggregate_lift` wrongly pools in with the signal."""
    obs = []
    for _ in range(n):
        for arm in (Arm.MEMORY_ON, Arm.HOLDOUT):
            obs.append(
                _bernoulli_obs(
                    rng,
                    agent_type_id=agent_type_id,
                    mem_type=None,
                    arm=arm,
                    outcome_code=outcome_code,
                    p=p,
                )
            )
    return obs


def _estimate(
    *,
    point_estimate: float,
    lower_bound: float,
    p_value: float,
    confidence: float = 0.95,
) -> LiftEstimate:
    return LiftEstimate(
        agent_type_id=AGENT_A,
        mem_type=MemType.LESSON,
        n_treatment=250,
        n_control=250,
        point_estimate=point_estimate,
        lower_bound=lower_bound,
        upper_bound=lower_bound + 1.0,
        p_value=p_value,
        confidence=confidence,
    )


class TestLiftObservationValidation:
    def test_injected_requires_mem_type(self) -> None:
        with pytest.raises(ValueError, match="must carry the mem_type"):
            LiftObservation(
                run_id=RunId(UUID(int=1)),
                agent_type_id=AGENT_A,
                arm=Arm.MEMORY_ON,
                outcome_code=OutcomeCode.INJECTED,
                mem_type=None,
                outcome_r=1.0,
            )

    @pytest.mark.parametrize(
        "outcome_code",
        [
            OutcomeCode.ABSTAINED_THRESHOLD,
            OutcomeCode.ABSTAINED_RARITY,
            OutcomeCode.EMPTY_RESULT,
            OutcomeCode.TIMEOUT_PREFIX_ONLY,
            OutcomeCode.STORE_ERROR,
        ],
    )
    @pytest.mark.parametrize("arm", [Arm.MEMORY_ON, Arm.HOLDOUT])
    def test_no_never_placing_code_may_carry_a_mem_type(
        self, outcome_code: OutcomeCode, arm: Arm
    ) -> None:
        """The bad join that would reintroduce "injected vs ALL holdout": a holdout run that
        would have ABSTAINED, handed a mem_type anyway, must not be constructible — in either
        arm and for every code that PROVES nothing was placed, not just the one an example
        happened to use.

        The list is exactly `workers.lift._NEVER_PLACING_CODES`, traced through
        `hotpath.assembly.CandidateAssembly` (its `injections` tuple is non-empty iff its own
        `_outcome_code` returns `injected`) and `hotpath.pipeline.Pipeline._timeout_prefix_only`
        / the `store_error` rung (both leave `_LadderResult.injections` at its empty default).
        `degraded_lexical` is deliberately NOT here — see
        `TestDegradedLexicalIsAmbiguous`."""
        with pytest.raises(ValueError, match="must not carry a mem_type"):
            LiftObservation(
                run_id=RunId(UUID(int=1)),
                agent_type_id=AGENT_A,
                arm=arm,
                outcome_code=outcome_code,
                mem_type=MemType.LESSON,
                outcome_r=1.0,
            )

    def test_holdout_code_constrains_nothing_about_placement(self) -> None:
        """`outcome_code=holdout` is an ARM-level label (D-027: the holdout arm runs the
        retriever and discards the result), so once `hotpath/pipeline.py` starts writing it, it
        will cover shadow-injected AND would-have-abstained holdout runs alike. Treating it as
        proof that something was placed would make every would-have-abstained holdout run
        unrepresentable — i.e. would crash the observation source on the exact runs the
        stratification correction exists to EXCLUDE."""
        with_mem = LiftObservation(
            run_id=RunId(UUID(int=1)),
            agent_type_id=AGENT_A,
            arm=Arm.HOLDOUT,
            outcome_code=OutcomeCode.HOLDOUT,
            mem_type=MemType.LESSON,
            outcome_r=1.0,
        )
        without_mem = LiftObservation(
            run_id=RunId(UUID(int=2)),
            agent_type_id=AGENT_A,
            arm=Arm.HOLDOUT,
            outcome_code=OutcomeCode.HOLDOUT,
            mem_type=None,
            outcome_r=1.0,
        )
        assert is_shadow_control(with_mem) is True
        assert is_shadow_control(without_mem) is False

    def test_holdout_code_requires_holdout_arm(self) -> None:
        with pytest.raises(ValueError, match="holdout arm"):
            LiftObservation(
                run_id=RunId(UUID(int=1)),
                agent_type_id=AGENT_A,
                arm=Arm.MEMORY_ON,
                outcome_code=OutcomeCode.HOLDOUT,
                mem_type=MemType.LESSON,
                outcome_r=1.0,
            )

    def test_injected_code_is_accepted_on_the_holdout_arm(self) -> None:
        """`hotpath.pipeline.Pipeline.retrieve()` does not relabel a holdout-arm run's
        outcome_code (module contract gap 2), so a real shadow-injected control arrives as
        `injected` on the `holdout` arm. Refusing it would make every real control fail
        construction and leave the kill switch permanently unfireable."""
        obs = LiftObservation(
            run_id=RunId(UUID(int=1)),
            agent_type_id=AGENT_A,
            arm=Arm.HOLDOUT,
            outcome_code=OutcomeCode.INJECTED,
            mem_type=MemType.LESSON,
            outcome_r=1.0,
        )
        assert is_shadow_control(obs) is True
        assert is_treatment(obs) is False

    def test_outcome_r_out_of_range_rejected(self) -> None:
        with pytest.raises(ValueError, match=r"outside \[0, 1\]"):
            LiftObservation(
                run_id=RunId(UUID(int=1)),
                agent_type_id=AGENT_A,
                arm=Arm.MEMORY_ON,
                outcome_code=OutcomeCode.EMPTY_RESULT,
                mem_type=None,
                outcome_r=1.5,
            )

    def test_nan_outcome_r_rejected(self) -> None:
        """`float("nan")` fails every comparison, so a naive range check passes it through and
        the whole cell's mean becomes NaN — which then compares False against every threshold,
        silently disabling the trigger for that cell."""
        with pytest.raises(ValueError, match=r"outside \[0, 1\]"):
            LiftObservation(
                run_id=RunId(UUID(int=1)),
                agent_type_id=AGENT_A,
                arm=Arm.MEMORY_ON,
                outcome_code=OutcomeCode.INJECTED,
                mem_type=MemType.LESSON,
                outcome_r=float("nan"),
            )


class TestDegradedLexicalIsAmbiguous:
    """REGRESSION, verified against the real hot path rather than against prose.

    `workers.lift` originally asserted that a run carrying ANY abstention/degradation code may
    not also carry a `mem_type`. That is false about the system as shipped:
    `hotpath.pipeline.Pipeline._run_ladder` overwrites the assembly seam's `outcome_code` with
    `degraded_lexical` whenever the embed sub-budget blew, and passes `assembled.injections`
    straight through to `injection_log` regardless. So a run that DID inject a memory — a
    treatment run by D-027's own definition ("runs where something was actually injected") — is
    recorded `degraded_lexical`. Under the old rule the observation source either crashed on it
    or dropped it, and dropping genuinely-injected runs biases the estimate the kill switch
    fires on.
    """

    def _pipeline_records(self) -> tuple[OutcomeCode, int]:
        """Runs a REAL `Pipeline` whose retriever degraded and whose assembly still placed a
        memory, and reports what `retrieval_event` and `injection_log` actually received."""
        recorded: dict[str, object] = {}
        injected_rows: list[InjectionRow] = []
        memory_id = MemoryId(uuid4())

        @dataclass(frozen=True, slots=True)
        class _DegradedOutcome:
            candidates: tuple[FusedCandidate, ...] = ()
            degraded: bool = True
            embed_latency_ms: int = 210
            candidates_considered: int = 3

        class _Retriever:
            def retrieve(
                self, project_id: ProjectId, query_text: str, *, cfg: RetrievalConfig
            ) -> _DegradedOutcome:
                return _DegradedOutcome()

        class _Assembly:
            def run(
                self,
                scope: ProjectScope,
                *,
                query_text: str,
                candidates: Sequence[FusedCandidate],
                cfg: EffectiveConfig,
            ) -> CandidateSetResult:
                return CandidateSetResult(
                    outcome_code=OutcomeCode.INJECTED,
                    slots=[
                        ContextSlot(
                            slot=Slot.PITFALL,
                            memory_id=memory_id.value,
                            tokens=6,
                            text="this endpoint rejects batch sizes over 50",
                        )
                    ],
                    top_score=0.88,
                    injections=[
                        InjectionRow(
                            memory_id=memory_id, slot=Slot.PITFALL, score=0.88, tokens=6
                        )
                    ],
                )

        class _Config:
            def effective(
                self, project_id: ProjectId, agent_type_id: AgentTypeId | None = None
            ) -> EffectiveConfig:
                return _default_effective_config()

        class _Telemetry:
            def record_retrieval(
                self,
                project_id: ProjectId,
                run_id: RunId,
                *,
                outcome_code: OutcomeCode,
                latency_ms: int,
                embed_latency_ms: int | None,
                candidates_considered: int,
                top_score: float | None,
                arm: Arm,
            ) -> None:
                recorded["outcome_code"] = outcome_code

        class _Injections:
            def record_injections(
                self, project_id: ProjectId, run_id: RunId, rows: Sequence[InjectionRow]
            ) -> None:
                injected_rows.extend(rows)

        pipeline = Pipeline(
            clock=FakeClock(),
            config=_Config(),
            telemetry=_Telemetry(),
            retriever=_Retriever(),
            assembly=_Assembly(),
            injections=_Injections(),
            holdout_salt="lift-audit-salt",
        )
        pipeline.retrieve(
            ProjectScope(
                project_id=ProjectId(UUID(int=1)),
                agent_type_id=AgentTypeId(uuid4()),
                principal_id=PrincipalId(uuid4()),
            ),
            RunContext(query_text="what is the batch size limit here"),
        )
        code = recorded["outcome_code"]
        assert isinstance(code, OutcomeCode)
        return code, len(injected_rows)

    def test_the_real_pipeline_writes_degraded_lexical_alongside_injection_rows(self) -> None:
        code, rows = self._pipeline_records()
        assert code is OutcomeCode.DEGRADED_LEXICAL
        assert rows == 1

    @pytest.mark.parametrize("arm", [Arm.MEMORY_ON, Arm.HOLDOUT])
    def test_a_degraded_run_that_injected_is_representable_and_counts(self, arm: Arm) -> None:
        """The join the previous rule made impossible — and it must land in the right bucket,
        not merely construct."""
        obs = LiftObservation(
            run_id=RunId(UUID(int=1)),
            agent_type_id=AGENT_A,
            arm=arm,
            outcome_code=OutcomeCode.DEGRADED_LEXICAL,
            mem_type=MemType.LESSON,
            outcome_r=1.0,
        )
        assert is_treatment(obs) is (arm is Arm.MEMORY_ON)
        assert is_shadow_control(obs) is (arm is Arm.HOLDOUT)
        treatment, control = stratify([obs])
        bucket = treatment if arm is Arm.MEMORY_ON else control
        assert bucket[(AGENT_A, MemType.LESSON)] == [1.0]

    def test_a_degraded_run_that_injected_nothing_is_still_excluded(self) -> None:
        """`degraded_lexical` is ambiguous, not permissive: the discriminator is still the
        `injection_log` row, so a degraded run that abstained after falling back to lexical-only
        contributes to neither bucket."""
        obs = LiftObservation(
            run_id=RunId(UUID(int=1)),
            agent_type_id=AGENT_A,
            arm=Arm.HOLDOUT,
            outcome_code=OutcomeCode.DEGRADED_LEXICAL,
            mem_type=None,
            outcome_r=1.0,
        )
        assert is_treatment(obs) is False
        assert is_shadow_control(obs) is False
        assert stratify([obs]) == ({}, {})


class TestLiftEstimateValidation:
    """A non-finite statistic makes `is_adverse` return `False` in BOTH directions — a cell that
    can never be disabled, looking exactly like a healthy one. Same refusal D-048 and D-056(d)
    made for `hotpath.abstention` and `hotpath.assembler.Candidate`."""

    @pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
    def test_non_finite_lower_bound_is_refused(self, bad: float) -> None:
        with pytest.raises(ValueError, match="not a finite number"):
            _estimate(point_estimate=-0.1, lower_bound=bad, p_value=0.01)

    def test_non_finite_point_estimate_is_refused(self) -> None:
        with pytest.raises(ValueError, match="not a finite number"):
            _estimate(point_estimate=float("nan"), lower_bound=-0.1, p_value=0.01)

    @pytest.mark.parametrize("bad", [-0.01, 1.01, float("nan")])
    def test_p_value_outside_the_unit_interval_is_refused(self, bad: float) -> None:
        with pytest.raises(ValueError):
            _estimate(point_estimate=-0.1, lower_bound=-0.2, p_value=bad)

    def test_negative_sample_sizes_are_refused(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            LiftEstimate(
                agent_type_id=AGENT_A,
                mem_type=MemType.LESSON,
                n_treatment=-1,
                n_control=250,
                point_estimate=-0.1,
                lower_bound=-0.2,
                upper_bound=0.0,
                p_value=0.01,
                confidence=0.95,
            )

    def test_a_nan_bound_would_otherwise_have_disarmed_the_switch(self) -> None:
        """Why the refusal above matters, stated as the failure it prevents: the comparison a
        NaN bound would have been fed to answers `False` in both directions."""
        nan = float("nan")
        assert (nan < 0.0) is False
        assert (nan > 0.0) is False


class TestEstimateLift:
    def test_requires_at_least_two_per_group(self) -> None:
        with pytest.raises(ValueError, match="at least 2 observations"):
            estimate_lift([1.0], [0.0, 1.0], agent_type_id=AGENT_A, mem_type=MemType.LESSON)

    def test_rejects_degenerate_confidence(self) -> None:
        with pytest.raises(ValueError, match="confidence must be"):
            estimate_lift(
                [1.0, 0.0],
                [0.0, 1.0],
                agent_type_id=AGENT_A,
                mem_type=MemType.LESSON,
                confidence=1.0,
            )

    def test_zero_variance_groups_collapse_bound_to_point(self) -> None:
        estimate = estimate_lift(
            [1.0, 1.0, 1.0], [0.0, 0.0, 0.0], agent_type_id=AGENT_A, mem_type=MemType.LESSON
        )
        assert estimate.point_estimate == 1.0
        assert estimate.lower_bound == estimate.upper_bound == 1.0
        assert estimate.p_value == 0.0

    def test_recovers_true_sign_and_ci_contains_true_value(self) -> None:
        """A single, noise-free cell: true lift is exactly -0.2 (memory hurts). The 95% CI
        from n=250 per arm should both get the sign right and bracket the true value."""
        rng = random.Random(20260726)
        true_treatment_p, true_control_p = 0.40, 0.60
        n = 250
        treatment = [1.0 if rng.random() < true_treatment_p else 0.0 for _ in range(n)]
        control = [1.0 if rng.random() < true_control_p else 0.0 for _ in range(n)]

        estimate = estimate_lift(treatment, control, agent_type_id=AGENT_A, mem_type=MemType.LESSON)

        true_lift = true_treatment_p - true_control_p
        assert estimate.point_estimate < 0.0
        assert estimate.lower_bound < estimate.upper_bound
        assert estimate.lower_bound <= true_lift <= estimate.upper_bound

    def test_the_bound_matches_a_hand_computed_welch_interval(self) -> None:
        """MUTATION GUARD. The two seeded fixtures below both survive an SE that drops the
        control arm's variance term (`sqrt(v1/n1 + v2/n2)` -> `sqrt(v1/n1)`) often enough to be
        luck; understating the SE narrows every interval, which makes the kill switch fire on
        cells it has not actually shown anything about. Pinned against numbers computed by hand
        from the same definition, so the arithmetic itself is the assertion.

        treatment = ten 1.0 and ten 0.0 -> mean 0.5, sample variance 0.5/1.9... exactly
        10*0.25*2/19 = 5/19; control = fifteen 1.0 and five 0.0 -> mean 0.75, sample variance
        (15*0.0625 + 5*0.5625)/19 = 3.75/19.
        """
        treatment = [1.0] * 10 + [0.0] * 10
        control = [1.0] * 15 + [0.0] * 5
        estimate = estimate_lift(
            treatment, control, agent_type_id=AGENT_A, mem_type=MemType.LESSON, confidence=0.95
        )

        var_t = 5.0 / 19.0
        var_c = 3.75 / 19.0
        se = math.sqrt(var_t / 20 + var_c / 20)
        z = statistics.NormalDist().inv_cdf(0.95)

        assert estimate.point_estimate == pytest.approx(-0.25)
        assert estimate.lower_bound == pytest.approx(-0.25 - z * se)
        assert estimate.upper_bound == pytest.approx(-0.25 + z * se)
        assert estimate.p_value == pytest.approx(
            2.0 * (1.0 - statistics.NormalDist().cdf(abs(-0.25 / se)))
        )

    def test_wider_confidence_pushes_the_lower_bound_down(self) -> None:
        """The bound is what the kill switch acts on, so it must actually move with the
        confidence level — a bound that ignored `confidence` would pass every other test here."""
        treatment = [1.0, 0.0] * 30
        control = [1.0, 1.0, 0.0] * 20
        loose = estimate_lift(
            treatment, control, agent_type_id=AGENT_A, mem_type=MemType.LESSON, confidence=0.80
        )
        tight = estimate_lift(
            treatment, control, agent_type_id=AGENT_A, mem_type=MemType.LESSON, confidence=0.99
        )
        assert tight.lower_bound < loose.lower_bound
        assert tight.upper_bound > loose.upper_bound
        assert tight.point_estimate == loose.point_estimate


class TestDirectionalStatistics:
    """`AdverseDirection` exists so the conservative-bound test and the significance test can
    never disagree about which sign is bad — see `workers/killswitch.py`'s docstring for the
    defect this replaced."""

    def test_two_sided_p_splits_into_the_tail_the_effect_landed_in(self) -> None:
        harmful = _estimate(point_estimate=-0.4, lower_bound=-0.5, p_value=0.02)
        assert directional_p_value(harmful, AdverseDirection.LOWER) == pytest.approx(0.01)
        assert directional_p_value(harmful, AdverseDirection.HIGHER) == pytest.approx(0.99)

    def test_helpful_effect_is_maximally_non_significant_in_the_lower_direction(self) -> None:
        helpful = _estimate(point_estimate=0.5, lower_bound=-0.05, p_value=0.001)
        assert directional_p_value(helpful, AdverseDirection.LOWER) > 0.99
        assert directional_p_value(helpful, AdverseDirection.HIGHER) == pytest.approx(0.0005)

    def test_zero_effect_is_half_in_both_directions(self) -> None:
        flat = _estimate(point_estimate=0.0, lower_bound=-0.1, p_value=1.0)
        assert directional_p_value(flat, AdverseDirection.LOWER) == 0.5
        assert directional_p_value(flat, AdverseDirection.HIGHER) == 0.5

    def test_degenerate_zero_variance_estimate_keeps_its_direction(self) -> None:
        """`estimate_lift`'s se == 0 branch reports p_value 0.0. Splitting that must not turn a
        harmful cell into a "significant improvement" or vice versa."""
        harmful = _estimate(point_estimate=-1.0, lower_bound=-1.0, p_value=0.0)
        assert directional_p_value(harmful, AdverseDirection.LOWER) == 0.0
        assert directional_p_value(harmful, AdverseDirection.HIGHER) == 1.0

    def test_is_adverse_uses_the_bound_not_the_point_estimate(self) -> None:
        """The conservative half of the trigger. A cell whose POINT estimate is adverse but
        whose interval still crosses zero has not shown anything -- D-027 says the switch acts
        on the bound precisely so a noisy centre cannot disable a memory type (task quality) or
        raise a safety alarm (violations)."""
        noisy_harm = _estimate(point_estimate=-0.3, lower_bound=0.0, p_value=0.4)
        assert is_adverse(noisy_harm, AdverseDirection.LOWER) is False
        noisy_violations = _estimate(point_estimate=0.3, lower_bound=-0.05, p_value=0.4)
        assert is_adverse(noisy_violations, AdverseDirection.HIGHER) is False

    def test_a_bound_of_exactly_zero_is_adverse_in_neither_direction(self) -> None:
        """MUTATION GUARD on the boundary. A lower bound of exactly 0.0 is the interval that
        just touches "no effect": it is evidence of nothing, in either direction. Relaxing
        either comparison to `<=` / `>=` disables a memory type (or raises a safety alarm) on a
        cell that showed nothing at all — and `estimate_lift`'s zero-variance branch collapses
        the bound onto the point estimate, so an exactly-zero bound is reachable, not
        hypothetical."""
        touching = _estimate(point_estimate=0.0, lower_bound=0.0, p_value=1.0)
        assert is_adverse(touching, AdverseDirection.LOWER) is False
        assert is_adverse(touching, AdverseDirection.HIGHER) is False

        degenerate = estimate_lift(
            [0.5, 0.5], [0.5, 0.5], agent_type_id=AGENT_A, mem_type=MemType.LESSON
        )
        assert degenerate.lower_bound == 0.0
        assert is_adverse(degenerate, AdverseDirection.LOWER) is False
        assert is_adverse(degenerate, AdverseDirection.HIGHER) is False

    def test_is_adverse_tests_the_bound_in_the_named_direction(self) -> None:
        below = _estimate(point_estimate=-0.2, lower_bound=-0.3, p_value=0.01)
        above = _estimate(point_estimate=0.2, lower_bound=0.1, p_value=0.01)
        assert is_adverse(below, AdverseDirection.LOWER) is True
        assert is_adverse(below, AdverseDirection.HIGHER) is False
        assert is_adverse(above, AdverseDirection.HIGHER) is True
        assert is_adverse(above, AdverseDirection.LOWER) is False


class TestStratification:
    def test_only_treatment_and_shadow_control_contribute(self) -> None:
        rng = random.Random(1)
        obs = _signal_cell(
            rng, agent_type_id=AGENT_A, mem_type=MemType.LESSON, p_treatment=0.3, p_control=0.3, n=5
        )
        obs += _non_placing_noise(rng, agent_type_id=AGENT_A, n=100, p=0.9)
        treatment, control = stratify(obs)
        key = (AGENT_A, MemType.LESSON)
        assert len(treatment[key]) == 5
        assert len(control[key]) == 5
        # Nothing else got a bucket at all — a widened predicate would have created one.
        assert set(treatment) == set(control) == {key}

    def test_would_have_abstained_holdout_runs_never_reach_the_control_bucket(self) -> None:
        """THE correction, stated as a test: 2 shadow-injected holdout runs scoring 0.0 and 200
        would-have-abstained holdout runs scoring 1.0. If the control group were "all holdout
        runs", the control mean would be ~0.99 and the cell would look catastrophically
        negative. Stratified correctly, the control mean is exactly 0.0."""
        rng = random.Random(11)
        obs = [
            LiftObservation(
                run_id=_run_id(rng),
                agent_type_id=AGENT_A,
                arm=Arm.HOLDOUT,
                outcome_code=OutcomeCode.HOLDOUT,
                mem_type=MemType.LESSON,
                outcome_r=0.0,
            )
            for _ in range(2)
        ]
        obs += [
            LiftObservation(
                run_id=_run_id(rng),
                agent_type_id=AGENT_A,
                arm=Arm.HOLDOUT,
                outcome_code=OutcomeCode.ABSTAINED_RARITY,
                mem_type=None,
                outcome_r=1.0,
            )
            for _ in range(200)
        ]
        _, control = stratify(obs)
        values = control[(AGENT_A, MemType.LESSON)]
        assert values == [0.0, 0.0]

    def test_predicates_reject_non_placing_runs_in_both_arms(self) -> None:
        """Called directly, not through `stratify`: the predicates are the exported definition
        of "treatment" and "shadow control", and a caller building a report from them must get
        the same exclusions the stratifier applies."""
        rng = random.Random(21)
        for arm in (Arm.MEMORY_ON, Arm.HOLDOUT):
            obs = _bernoulli_obs(
                rng,
                agent_type_id=AGENT_A,
                mem_type=None,
                arm=arm,
                outcome_code=OutcomeCode.ABSTAINED_THRESHOLD,
                p=1.0,
            )
            assert is_treatment(obs) is False
            assert is_shadow_control(obs) is False

    def test_predicates_agree_with_stratify(self) -> None:
        rng = random.Random(2)
        obs = _signal_cell(
            rng, agent_type_id=AGENT_A, mem_type=MemType.LESSON, p_treatment=0.5, p_control=0.5, n=10
        )
        treated = [o for o in obs if is_treatment(o)]
        controlled = [o for o in obs if is_shadow_control(o)]
        assert len(treated) == 10
        assert len(controlled) == 10

    def test_mem_types_do_not_share_a_bucket_within_one_agent_type(self) -> None:
        """The stratum key is the PAIR. Keying on agent_type alone would merge these two."""
        rng = random.Random(5)
        obs = _signal_cell(
            rng, agent_type_id=AGENT_A, mem_type=MemType.LESSON, p_treatment=0.1, p_control=0.9, n=8
        )
        obs += _signal_cell(
            rng, agent_type_id=AGENT_A, mem_type=MemType.SEMANTIC, p_treatment=0.9, p_control=0.1, n=8
        )
        report = compute_stratified_lift(obs)
        assert report.estimates[(AGENT_A, MemType.LESSON)].point_estimate < 0.0
        assert report.estimates[(AGENT_A, MemType.SEMANTIC)].point_estimate > 0.0


class TestStratifiedVsAggregate:
    """The gate evidence (PLAN.md section 7 Phase 3): aggregate lift on the same fleet is
    demonstrably uninformative — that is the evidence for stratifying.

    Two cells with OPPOSITE true effects (A/LESSON hurts, B/SEMANTIC helps), plus abstention
    noise dominating the fleet in both arms identically. Pooling by arm alone (what
    `naive_aggregate_lift` does) cancels the two real effects against each other and dilutes
    what is left with noise; stratifying recovers both, correctly signed, with confidence
    intervals that do not straddle zero.
    """

    def test_aggregate_is_uninformative_while_stratified_is_not(self) -> None:
        rng = random.Random(7)
        n_per_cell = 300
        obs: list[LiftObservation] = []
        obs += _signal_cell(
            rng,
            agent_type_id=AGENT_A,
            mem_type=MemType.LESSON,
            p_treatment=0.30,
            p_control=0.70,
            n=n_per_cell,
        )
        obs += _signal_cell(
            rng,
            agent_type_id=AGENT_B,
            mem_type=MemType.SEMANTIC,
            p_treatment=0.70,
            p_control=0.30,
            n=n_per_cell,
        )
        # Abstention dominates the fleet (>= 50%, PLAN.md section 6
        # abstention.target_abstention_pct): 2400 noise runs vs 1200 signal runs.
        obs += _non_placing_noise(rng, agent_type_id=AGENT_A, n=1200, p=0.5)

        report = compute_stratified_lift(obs)
        cell_a = report.estimates[(AGENT_A, MemType.LESSON)]
        cell_b = report.estimates[(AGENT_B, MemType.SEMANTIC)]

        # Stratified: both cells correctly signed and clearly significant (CI does not
        # straddle zero) — this is the "informative" half of the contrast.
        assert cell_a.point_estimate < 0.0
        assert cell_a.upper_bound < 0.0
        assert cell_b.point_estimate > 0.0
        assert cell_b.lower_bound > 0.0

        # Aggregate: pooled by arm alone across the WHOLE fleet (both cancelling cells plus
        # all the noise). The two real effects cancel and the CI straddles zero — exactly
        # the "compares noise to noise and measures nothing" failure mode.
        aggregate = naive_aggregate_lift(obs)
        assert aggregate.lower_bound < 0.0 < aggregate.upper_bound
        assert abs(aggregate.point_estimate) < min(
            abs(cell_a.point_estimate), abs(cell_b.point_estimate)
        )

    def test_abstention_noise_alone_dilutes_a_single_real_effect(self) -> None:
        """Even with only ONE signal cell (nothing to cancel against), pooling by arm buries a
        true -0.4 effect under would-have-abstained runs: the aggregate interval straddles zero
        while the stratified cell's does not."""
        rng = random.Random(13)
        obs = _signal_cell(
            rng,
            agent_type_id=AGENT_A,
            mem_type=MemType.LESSON,
            p_treatment=0.30,
            p_control=0.70,
            n=150,
        )
        obs += _non_placing_noise(rng, agent_type_id=AGENT_A, n=3000, p=0.5)

        stratified = compute_stratified_lift(obs).estimates[(AGENT_A, MemType.LESSON)]
        aggregate = naive_aggregate_lift(obs)

        assert stratified.upper_bound < 0.0
        assert aggregate.lower_bound < 0.0 < aggregate.upper_bound

    def test_naive_aggregate_requires_both_arms_present(self) -> None:
        rng = random.Random(3)
        obs = [
            _bernoulli_obs(
                rng,
                agent_type_id=AGENT_A,
                mem_type=MemType.LESSON,
                arm=Arm.MEMORY_ON,
                outcome_code=OutcomeCode.INJECTED,
                p=0.5,
            )
            for _ in range(5)
        ]
        with pytest.raises(ValueError, match="at least 2 observations per arm"):
            naive_aggregate_lift(obs)


class TestLiftReport:
    def test_insufficient_data_reported_not_silently_dropped(self) -> None:
        rng = random.Random(4)
        obs = _signal_cell(
            rng, agent_type_id=AGENT_A, mem_type=MemType.LESSON, p_treatment=0.5, p_control=0.5, n=1
        )
        report = compute_stratified_lift(obs)
        assert report.estimates == {}
        assert report.insufficient_data == ((AGENT_A, MemType.LESSON),)

    def test_treatment_only_cell_is_insufficient_not_estimated(self) -> None:
        """A cell with plenty of treatment runs and no shadow control at all has no comparison
        to make — it must never fall through to an estimate against an empty control."""
        rng = random.Random(6)
        obs = [
            _bernoulli_obs(
                rng,
                agent_type_id=AGENT_A,
                mem_type=MemType.LESSON,
                arm=Arm.MEMORY_ON,
                outcome_code=OutcomeCode.INJECTED,
                p=0.5,
            )
            for _ in range(50)
        ]
        report = compute_stratified_lift(obs)
        assert report.estimates == {}
        assert report.insufficient_data == ((AGENT_A, MemType.LESSON),)


class TestSafetyLift:
    """`workers.safety_lift` — CUTTABLE improvement 2 (PLAN.md section 8 item 2). It shipped
    with no test of any kind and was imported by nothing, so every claim in its docstring was
    unverified; these are the tests for the two things it does that `workers.lift` does not:
    measure a JUDGED fact (epoch-guarded, hard rule 7) and invert the adverse direction.
    """

    def _obs(
        self,
        rng: random.Random,
        *,
        arm: Arm,
        outcome_code: OutcomeCode,
        mem_type: MemType | None,
        violation_r: float,
        epoch: int = 7,
        agent_type_id: AgentTypeId = AGENT_A,
    ) -> SafetyObservation:
        return SafetyObservation(
            run_id=_run_id(rng),
            agent_type_id=agent_type_id,
            arm=arm,
            outcome_code=outcome_code,
            mem_type=mem_type,
            violation_r=violation_r,
            scoring_epoch_id=epoch,
        )

    def _cell(
        self,
        rng: random.Random,
        *,
        p_treatment: float,
        p_control: float,
        n: int,
        epoch: int = 7,
    ) -> list[SafetyObservation]:
        obs = [
            self._obs(
                rng,
                arm=Arm.MEMORY_ON,
                outcome_code=OutcomeCode.INJECTED,
                mem_type=MemType.LESSON,
                violation_r=1.0 if rng.random() < p_treatment else 0.0,
                epoch=epoch,
            )
            for _ in range(n)
        ]
        obs += [
            self._obs(
                rng,
                arm=Arm.HOLDOUT,
                outcome_code=OutcomeCode.HOLDOUT,
                mem_type=MemType.LESSON,
                violation_r=1.0 if rng.random() < p_control else 0.0,
                epoch=epoch,
            )
            for _ in range(n)
        ]
        return obs

    def test_placement_rules_are_the_same_as_lift_observations(self) -> None:
        rng = random.Random(31)
        with pytest.raises(ValueError, match="must not carry a mem_type"):
            self._obs(
                rng,
                arm=Arm.HOLDOUT,
                outcome_code=OutcomeCode.ABSTAINED_RARITY,
                mem_type=MemType.LESSON,
                violation_r=0.0,
            )
        with pytest.raises(ValueError, match="must carry the mem_type"):
            self._obs(
                rng,
                arm=Arm.MEMORY_ON,
                outcome_code=OutcomeCode.INJECTED,
                mem_type=None,
                violation_r=0.0,
            )
        with pytest.raises(ValueError, match=r"outside \[0, 1\]"):
            self._obs(
                rng,
                arm=Arm.MEMORY_ON,
                outcome_code=OutcomeCode.INJECTED,
                mem_type=MemType.LESSON,
                violation_r=1.5,
            )

    def test_would_have_abstained_holdout_runs_are_excluded_here_too(self) -> None:
        rng = random.Random(32)
        obs = self._cell(rng, p_treatment=0.0, p_control=0.0, n=3)
        obs += [
            self._obs(
                rng,
                arm=Arm.HOLDOUT,
                outcome_code=OutcomeCode.ABSTAINED_THRESHOLD,
                mem_type=None,
                violation_r=1.0,
            )
            for _ in range(100)
        ]
        treatment, control = stratify_safety(obs)
        assert control[(AGENT_A, MemType.LESSON)] == [0.0, 0.0, 0.0]
        # No other bucket exists at all -- a widened predicate would have created a
        # `(agent_type, None)` one holding the 100 would-have-abstained runs.
        assert set(control) == set(treatment) == {(AGENT_A, MemType.LESSON)}
        # And the exported predicates, called directly, agree -- in BOTH arms.
        for arm in (Arm.MEMORY_ON, Arm.HOLDOUT):
            non_placing = self._obs(
                rng,
                arm=arm,
                outcome_code=OutcomeCode.ABSTAINED_THRESHOLD,
                mem_type=None,
                violation_r=1.0,
            )
            assert safety_is_treatment(non_placing) is False
            assert safety_is_shadow_control(non_placing) is False

    def test_positive_estimate_means_memory_made_violations_more_likely(self) -> None:
        rng = random.Random(33)
        report = compute_stratified_safety_lift(
            self._cell(rng, p_treatment=0.45, p_control=0.10, n=400)
        )
        estimate = report.estimates[(AGENT_A, MemType.LESSON)]
        assert estimate.point_estimate > 0.0
        assert is_adverse(estimate, AdverseDirection.HIGHER) is True
        assert is_adverse(estimate, AdverseDirection.LOWER) is False
        assert report.scoring_epoch_id == 7

    def test_memory_that_reduces_violations_is_not_adverse(self) -> None:
        rng = random.Random(34)
        report = compute_stratified_safety_lift(
            self._cell(rng, p_treatment=0.10, p_control=0.45, n=400)
        )
        estimate = report.estimates[(AGENT_A, MemType.LESSON)]
        assert is_adverse(estimate, AdverseDirection.HIGHER) is False

    def test_cross_epoch_observations_are_refused_not_pooled(self) -> None:
        """Hard rule 7 / D-008: a judge swap redefines "violation". Averaging judgments from
        two epochs and calling the difference a safety trend is the silent comparison
        `CrossEpochComparison` exists to prevent."""
        rng = random.Random(35)
        obs = self._cell(rng, p_treatment=0.5, p_control=0.5, n=5, epoch=7)
        obs += self._cell(rng, p_treatment=0.5, p_control=0.5, n=5, epoch=8)
        with pytest.raises(CrossEpochComparison, match="scoring epochs"):
            compute_stratified_safety_lift(obs)
        with pytest.raises(CrossEpochComparison):
            stratify_safety(obs)

    def test_single_epoch_is_reported_and_empty_input_has_none(self) -> None:
        rng = random.Random(36)
        assert assert_single_epoch(self._cell(rng, p_treatment=0.5, p_control=0.5, n=2)) == 7
        assert assert_single_epoch([]) is None
        assert compute_stratified_safety_lift([]).scoring_epoch_id is None
