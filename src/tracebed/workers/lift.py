"""Stratified kill-switch lift (PLAN.md section 2 invariant "memory must pay for its context";
section 7 Phase 3; D-027).

THE CORRECTION THIS MODULE EXISTS TO MAKE: lift must never be computed by comparing every
`memory_on` run against every `holdout` run. `abstention.target_abstention_pct` is >= 50 by
design (PLAN.md section 6) -- most calls in EITHER arm abstain, retrieve nothing relevant, or
degrade, and none of that has anything to do with whether memory helps. Averaging those runs
into the same two buckets as the runs that actually exercised memory computes the difference
between two clouds of noise and calls it "lift". `naive_aggregate_lift` below exists to make
that failure reproducible and visible in a test, not to be used anywhere real.

The corrected comparison (D-027): runs where SOMETHING WAS ACTUALLY INJECTED (`arm=memory_on`,
a memory placed) against SHADOW-RETRIEVED HOLDOUT runs -- holdout-arm runs where retrieval ran
and WOULD have placed a memory -- stratified per `(agent_type_id, mem_type)` cell, because a
memory type that helps one agent type and hurts another averages out to "no effect" in a pooled
estimate, which is the same failure as the abstention one at a different grain. Every cell
reports a LOWER CONFIDENCE BOUND, never a point estimate -- a point estimate of -0.01 and one of
-0.01 with a [-0.30, +0.28] interval around it are not the same evidence, and
`workers.killswitch` acts on the bound, not the centre.

WHAT MAKES A HOLDOUT RUN A SHADOW CONTROL, CONCRETELY. This is the one place the "injected vs
all-holdout" failure can creep back in, so the discriminator is stated once and enforced in
`LiftObservation.__post_init__` rather than assumed:

  * A memory was placed (treatment) or would have been placed (shadow control) **iff the run has
    `injection_log` rows**, i.e. iff `mem_type` is resolvable for it. `hotpath.pipeline.Pipeline`
    calls `_record_injections` unconditionally on arm, and only when the assembly seam actually
    produced slots -- so a holdout run that WOULD have abstained has no `injection_log` row, no
    resolvable `mem_type`, and is excluded from both buckets by construction.
  * `outcome_code` is carried and validated, but it is corroboration, never the discriminator.
    The validation is therefore stated over the codes that *provably* settle the question, and
    only those (`validate_placement`, `_NEVER_PLACING_CODES` / `_ALWAYS_PLACING_CODES`). An
    earlier version of this module asserted that NO abstention/degradation/empty/store-error
    code may accompany a `mem_type`; that is false against the shipped hot path and would have
    made real data unrepresentable. `hotpath.pipeline.Pipeline._run_ladder` overwrites the
    assembly seam's code with `degraded_lexical` whenever the embed sub-budget blew, while still
    passing `assembled.injections` through to `injection_log` -- so a run that DID inject a
    memory, and belongs in the treatment bucket by D-027's own words ("runs where something was
    actually injected"), is recorded `degraded_lexical`. Refusing that pairing would have made
    every lexically-degraded injection either crash the observation source or be silently
    dropped from the treatment group, which biases the very estimate the kill switch fires on.

CONTRACT GAP (reported, not deviated on, matching workers.invalidator's precedent): a real
`LiftObservation` sequence is a join of `trace_index` (agent_type_id, arm), `injection_log`
(which mem_type was actually placed), `retrieval_event` (outcome_code) and `outcome_event` (the
scored outcome polarity `r`). None of `stores/pg/repo.py`, `stores/pg/rows.py` or
`stores/pg/telemetry.py` are in this chunk's file list (hard rule 8), and no query joins those
four tables yet. Two specific store-side gaps block a real source, both reported for whoever
owns `stores/pg` next:

  1. `stores.pg.rows.RetrievalEventInsert`/`InjectionRow` carry no `created_at`, so a
     store-backed observation source cannot bucket runs by calendar day --
     `workers.killswitch`'s "sustained 14 days" needs day buckets.
  2. (CLOSED -- kept because the classification below depends on it.)
     `hotpath.pipeline.Pipeline.retrieve()` now relabels a holdout-arm run's `outcome_code` to
     `OutcomeCode.HOLDOUT` and withholds the rendered block from the caller, so the holdout arm
     is genuinely memory-off while still shadow-retrieving. `holdout` therefore covers
     shadow-injected AND would-have-abstained holdout runs alike -- which is exactly why it is
     classified below as an ambiguous code (either presence or absence of a `mem_type` is legal
     under it) rather than as proof that something was placed. `injected` remains accepted on
     the holdout arm for rows written before the relabelling landed; the arm, not the code, is
     what separates the two groups, and the presence of an `injection_log` row is what makes a
     holdout run a shadow control.
"""

from __future__ import annotations

import math
import statistics
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from tracebed.domain.config import KillswitchConfig
from tracebed.domain.enums import Arm, MemType, OutcomeCode
from tracebed.domain.ids import AgentTypeId, RunId

__all__ = [
    "DEFAULT_BH_ALPHA",
    "DEFAULT_CONFIDENCE",
    "AdverseDirection",
    "LiftEstimate",
    "LiftObservation",
    "LiftReport",
    "StratumKey",
    "compute_stratified_lift",
    "directional_p_value",
    "estimate_lift",
    "is_adverse",
    "is_shadow_control",
    "is_treatment",
    "naive_aggregate_lift",
    "stratify",
    "validate_placement",
]

StratumKey = tuple[AgentTypeId, MemType]

DEFAULT_CONFIDENCE = KillswitchConfig().confidence_level
"""The one-sided confidence level every lower bound in this module is computed at.

READ FROM CONFIG (`domain.config.KillswitchConfig.confidence_level`), not written out here.
It used to be a module constant with a CONTRACT GAP note saying PLAN.md §6 named no field for
it -- which made a governed statistical threshold a magic number in code (hard rule 12) while
`killswitch.correction` told an operator they controlled the method. The field now exists and
this is its single point of truth; both remain overridable at every call site, so wiring a
genuinely per-project value is threading an `EffectiveConfig` to the call, not moving a number.
0.95 is D-027's own "uncorrected 95% CIs ... ~1 cell in 20 per window by chance".
"""

DEFAULT_BH_ALPHA = KillswitchConfig().fdr_alpha
"""The Benjamini-Hochberg false-discovery rate, from
`domain.config.KillswitchConfig.fdr_alpha` -- the level `killswitch.correction` names the
method for. Same history as `DEFAULT_CONFIDENCE` above."""

_MIN_CONFIDENCE = 0.5
_MAX_CONFIDENCE = 1.0

_NEVER_PLACING_CODES = frozenset(
    {
        OutcomeCode.ABSTAINED_THRESHOLD,
        OutcomeCode.ABSTAINED_RARITY,
        OutcomeCode.EMPTY_RESULT,
        OutcomeCode.TIMEOUT_PREFIX_ONLY,
        OutcomeCode.STORE_ERROR,
    }
)
"""Codes that PROVE no `injection_log` row exists for the run, so a `mem_type` alongside one is
a broken join, in either arm.

Traced through the shipped hot path rather than assumed: `hotpath.assembly.CandidateAssembly`
builds its `injections` tuple from the candidates the assembler actually placed and derives its
own code from `bool(assembled.slots)`, so at that seam a non-empty injection list and
`OutcomeCode.INJECTED` are the same fact -- the two abstentions and `empty_result` therefore
carry no rows. `hotpath.pipeline.Pipeline._timeout_prefix_only` and the `store_error` rung both
return a `_LadderResult` whose `injections` field keeps its empty default, so those two carry
none either."""

_ALWAYS_PLACING_CODES = frozenset({OutcomeCode.INJECTED})
"""Codes that PROVE an `injection_log` row exists, so a missing `mem_type` alongside one is the
other half of the same broken join. `injected` is written (in either arm) exactly when the
assembler placed at least one slot -- see `_NEVER_PLACING_CODES`.

Everything not in either set is genuinely ambiguous and constrains nothing:
`degraded_lexical` (the ladder overwrites the assembly seam's code on an embed timeout whether
or not that seam placed anything) and `holdout` (an arm-level label once `hotpath/pipeline.py`
relabels, covering shadow-injected and would-have-abstained runs alike). For those two, the
presence of a `mem_type` -- i.e. of an `injection_log` row -- is the whole discriminator, which
is what the module docstring says it always was."""


class AdverseDirection(StrEnum):
    """Which sign of an effect is the bad one for the kill switch that is reading it.

    This exists because the adverse predicate and the significance test MUST agree on a
    direction, and for one release they did not: `workers.killswitch` combined "lower bound < 0"
    with `LiftEstimate.p_value`, which is TWO-SIDED. A cell with a large positive effect
    (memory helping) and a wide interval satisfies "lower bound < 0" whenever the interval's
    confidence level is stricter than the correction's alpha (e.g. confidence 0.99 with
    alpha 0.05), and its two-sided p-value is tiny precisely BECAUSE the effect is large -- so
    the switch auto-disabled a memory type that was significantly helping. Pairing the two
    through this enum instead of through two independently-supplied callables makes that
    mismatch unrepresentable: `is_adverse` and `directional_p_value` take the same value.
    """

    LOWER = "lower"
    """Adverse when the effect is BELOW zero: task-quality lift (memory made outcomes worse)."""

    HIGHER = "higher"
    """Adverse when the effect is ABOVE zero: safety violation rate (memory made policy
    violations more likely) -- `workers.safety_lift`."""


@dataclass(frozen=True, slots=True)
class LiftObservation:
    """One run's contribution to a lift computation, already resolved from the four tables
    named in the module docstring's contract gap.

    Self-validating on purpose (see the module docstring's "WHAT MAKES A HOLDOUT RUN A SHADOW
    CONTROL" section): `mem_type` is present if and only if `outcome_code` says a memory was or
    would have been placed, and `OutcomeCode.HOLDOUT` may only appear on the holdout arm. A
    caller that got the join wrong fails at construction, not three functions later inside a
    silently-wrong stratum.
    """

    run_id: RunId
    agent_type_id: AgentTypeId
    arm: Arm
    outcome_code: OutcomeCode
    mem_type: MemType | None
    outcome_r: float
    """Outcome polarity in [0, 1] from the run's resolved `outcome_event` (PLAN.md section 2
    invariant 8). This dataclass represents only runs that HAVE a resolved outcome -- a run
    with no scored feedback contributes nothing to lift and is excluded upstream, the same way
    `workers.invalidator`'s repo-side selects are the ones that decide what reaches this module.

    Deliberately NOT epoch-stamped: `r` is the server's mapping of an authenticated adapter's
    positive/negative outcome (PLAN.md section 3's API contract), not a judged artifact -- no
    judge model produces it, so a judge swap does not change what it means. `workers.safety_lift`
    measures a judged fact instead and therefore DOES carry a `scoring_epoch_id` (hard rule 7)."""

    def __post_init__(self) -> None:
        if not 0.0 <= self.outcome_r <= 1.0:
            raise ValueError(f"LiftObservation.outcome_r={self.outcome_r!r} is outside [0, 1]")
        validate_placement(
            kind="LiftObservation",
            arm=self.arm,
            outcome_code=self.outcome_code,
            mem_type=self.mem_type,
        )


def validate_placement(
    *, kind: str, arm: Arm, outcome_code: OutcomeCode, mem_type: MemType | None
) -> None:
    """The shared placement invariant for `LiftObservation` and
    `workers.safety_lift.SafetyObservation` -- one implementation so the two cannot drift into
    disagreeing about what a shadow control is."""
    # The message wording avoids a leading "with ...": `scripts/raw_sql_lint.py` reads a string
    # literal starting that way as a CTE and fails the CI-blocking gate on it.
    if outcome_code in _ALWAYS_PLACING_CODES and mem_type is None:
        raise ValueError(
            f"{kind} carrying outcome_code={outcome_code.value!r} must carry the mem_type that "
            "was (or would have been) injected"
        )
    if outcome_code in _NEVER_PLACING_CODES and mem_type is not None:
        raise ValueError(
            f"{kind} carrying outcome_code={outcome_code.value!r} must not carry a mem_type -- "
            "nothing was, or would have been, injected on this run"
        )
    if outcome_code is OutcomeCode.HOLDOUT and arm is not Arm.HOLDOUT:
        raise ValueError("outcome_code=holdout only occurs on the holdout arm")


def is_treatment(observation: LiftObservation) -> bool:
    """"Something was actually injected" (D-027) -- the treatment group. The arm decides the
    group; `mem_type is not None` decides whether the run exercised memory at all."""
    return observation.arm is Arm.MEMORY_ON and observation.mem_type is not None


def is_shadow_control(observation: LiftObservation) -> bool:
    """The shadow-retrieved holdout control group: retrieval ran on the holdout arm and would
    have injected (`mem_type` resolvable from `injection_log`). A holdout run that would have
    ABSTAINED has no `mem_type` and is excluded -- that exclusion is the whole point of the
    stratification correction."""
    return observation.arm is Arm.HOLDOUT and observation.mem_type is not None


@dataclass(frozen=True, slots=True)
class LiftEstimate:
    """One stratum's (or the naive pool's) lift estimate.

    `lower_bound` is the number `workers.killswitch` acts on -- a one-sided lower confidence
    bound at `confidence` (default 0.95 -> z ~= 1.645). `upper_bound` mirrors the same margin
    for reporting symmetry (a dashboard wants an interval, not a ray) but is not read by the
    kill switch anywhere in this codebase; only `lower_bound` is.
    """

    agent_type_id: AgentTypeId | None
    """`None` only for `naive_aggregate_lift`'s pooled, deliberately-not-stratified estimate."""
    mem_type: MemType | None
    n_treatment: int
    n_control: int
    point_estimate: float
    """mean(treatment) - mean(control). Positive: memory helped. Negative: memory hurt."""
    lower_bound: float
    upper_bound: float
    p_value: float
    """TWO-SIDED Wald z-test p-value for point_estimate != 0. Never fed to a directional
    decision as-is -- `directional_p_value` converts it, and `AdverseDirection` explains why."""
    confidence: float

    def __post_init__(self) -> None:
        """Refuses a non-finite statistic, for the reason `hotpath.abstention` (D-048) and
        `hotpath.assembler.Candidate` (D-056(d)) refuse one: NaN compares `False` against
        everything, so a NaN `lower_bound` makes `is_adverse` return `False` in BOTH directions
        and permanently disarms the kill switch for that cell -- silently, and looking exactly
        like a healthy cell in every report. `estimate_lift` cannot produce one from
        `outcome_r`/`violation_r` values this module already bounds to [0, 1], but a
        store-backed daily-snapshot source (the contract gap in the module docstring) computes
        these same numbers in SQL, where a zero-row denominator is one division away.
        """
        for name, value in (
            ("point_estimate", self.point_estimate),
            ("lower_bound", self.lower_bound),
            ("upper_bound", self.upper_bound),
            ("p_value", self.p_value),
            ("confidence", self.confidence),
        ):
            if not math.isfinite(value):
                raise ValueError(f"LiftEstimate.{name}={value!r} is not a finite number")
        if not 0.0 <= self.p_value <= 1.0:
            raise ValueError(f"LiftEstimate.p_value={self.p_value!r} is outside [0, 1]")
        if self.n_treatment < 0 or self.n_control < 0:
            raise ValueError(
                f"LiftEstimate sample sizes must be non-negative, got "
                f"n_treatment={self.n_treatment}, n_control={self.n_control}"
            )


def directional_p_value(estimate: LiftEstimate, direction: AdverseDirection) -> float:
    """The ONE-SIDED p-value for "the effect is adverse in `direction`", derived from the
    two-sided `p_value` and the sign of `point_estimate`.

    A symmetric null distribution splits the two-sided p evenly between the tails, so the tail
    the observation actually fell in has p/2 and the other has 1 - p/2. A zero point estimate is
    p = 0.5 in both directions: no evidence either way, never significant.

    This is what `workers.killswitch` feeds to Benjamini-Hochberg. Using the two-sided value
    there lets a strongly-HELPING cell clear the significance bar of a switch whose job is to
    catch harm -- see `AdverseDirection`.
    """
    diff = estimate.point_estimate
    if diff == 0.0:
        return 0.5
    observed_below = diff < 0.0
    adverse_below = direction is AdverseDirection.LOWER
    tail = estimate.p_value / 2.0
    return tail if observed_below == adverse_below else 1.0 - tail


def is_adverse(estimate: LiftEstimate, direction: AdverseDirection) -> bool:
    """The conservative-bound half of the trigger (D-027: "lower confidence bound < 0").

    Both directions test the SAME one-sided lower bound, against zero, in the direction that is
    bad for the caller. For `LOWER` (task quality) that is a deliberately permissive screen --
    almost any noisy cell has a lower bound below zero -- and the directional Benjamini-Hochberg
    step is what supplies the evidence. For `HIGHER` (safety violation rate) the same test is
    conservative in its own right: even the pessimistic end of the interval says violations went
    up.
    """
    if direction is AdverseDirection.LOWER:
        return estimate.lower_bound < 0.0
    return estimate.lower_bound > 0.0


def estimate_lift(
    treatment: Sequence[float],
    control: Sequence[float],
    *,
    agent_type_id: AgentTypeId | None,
    mem_type: MemType | None,
    confidence: float = DEFAULT_CONFIDENCE,
) -> LiftEstimate:
    """Welch (unequal-variance) two-sample estimate of `mean(treatment) - mean(control)`,
    using the normal approximation `statistics.NormalDist` provides without a numpy/scipy
    dependency (neither is in `pyproject.toml`'s dependency set, and D-036 wants every
    addition individually reviewed) -- reasonable at the sample sizes this module is built
    for: `killswitch.min_cell_n` is 200 per arm, well past where the normal approximation to
    a t/binomial-difference statistic is a real concern.

    Raises `ValueError` for fewer than two observations in either group (no variance to
    estimate) or a `confidence` outside `(0.5, 1.0)` (a bound at or below 0.5 is not a
    one-sided confidence bound in any useful sense, and one at or above 1.0 has no finite z).
    """
    if not _MIN_CONFIDENCE < confidence < _MAX_CONFIDENCE:
        raise ValueError(f"confidence must be in (0.5, 1.0), got {confidence!r}")
    n1, n2 = len(treatment), len(control)
    if n1 < 2 or n2 < 2:
        raise ValueError(
            f"estimate_lift requires at least 2 observations per group, got "
            f"n_treatment={n1}, n_control={n2}"
        )

    mean1, mean2 = statistics.fmean(treatment), statistics.fmean(control)
    var1 = statistics.variance(treatment, xbar=mean1)
    var2 = statistics.variance(control, xbar=mean2)
    diff = mean1 - mean2
    se = math.sqrt(var1 / n1 + var2 / n2)

    if se == 0.0:
        # Every observation in both groups is identical (the degenerate all-zero or
        # all-one fixture, or a genuinely constant signal) -- there is no sampling
        # variance to build an interval from. The point estimate IS the bound in both
        # directions, and the p-value is exactly 0 or 1: either the (degenerate) groups
        # differ with total certainty, or they are the same constant.
        return LiftEstimate(
            agent_type_id=agent_type_id,
            mem_type=mem_type,
            n_treatment=n1,
            n_control=n2,
            point_estimate=diff,
            lower_bound=diff,
            upper_bound=diff,
            p_value=0.0 if diff != 0.0 else 1.0,
            confidence=confidence,
        )

    dist = statistics.NormalDist()
    z = dist.inv_cdf(confidence)
    margin = z * se
    z_stat = diff / se
    p_value = 2.0 * (1.0 - dist.cdf(abs(z_stat)))

    return LiftEstimate(
        agent_type_id=agent_type_id,
        mem_type=mem_type,
        n_treatment=n1,
        n_control=n2,
        point_estimate=diff,
        lower_bound=diff - margin,
        upper_bound=diff + margin,
        p_value=p_value,
        confidence=confidence,
    )


def stratify(
    observations: Sequence[LiftObservation],
) -> tuple[dict[StratumKey, list[float]], dict[StratumKey, list[float]]]:
    """Splits `observations` into per-`(agent_type_id, mem_type)` treatment/control buckets of
    `outcome_r`. Observations that are neither treatment nor shadow-control (abstained,
    degraded, empty, timeout, store-error runs in EITHER arm) contribute to neither bucket --
    exactly the exclusion `naive_aggregate_lift` deliberately skips, to make the difference
    visible.
    """
    treatment: dict[StratumKey, list[float]] = {}
    control: dict[StratumKey, list[float]] = {}
    for obs in observations:
        mem_type = obs.mem_type
        if mem_type is None:
            # Nothing was placed, and nothing would have been: excluded from BOTH groups.
            # This is the whole correction -- see the module docstring.
            continue
        # `Arm` has exactly two members and `mem_type is not None` already established that
        # this run placed (or would have placed) a memory, so these two predicates are
        # exhaustive here; there is no third bucket to fall through to.
        target = treatment if is_treatment(obs) else control
        target.setdefault((obs.agent_type_id, mem_type), []).append(obs.outcome_r)
    return treatment, control


@dataclass(frozen=True, slots=True)
class LiftReport:
    estimates: dict[StratumKey, LiftEstimate]
    insufficient_data: tuple[StratumKey, ...]
    """Cells with fewer than 2 treatment or 2 control observations -- reported rather than
    silently dropped, so a cell missing from `estimates` is distinguishable from a cell that
    was never observed at all (which is simply absent from both fields)."""


def compute_stratified_lift(
    observations: Sequence[LiftObservation], *, confidence: float = DEFAULT_CONFIDENCE
) -> LiftReport:
    """THE corrected computation (module docstring): one `LiftEstimate` per
    `(agent_type_id, mem_type)` cell, built only from that cell's treatment and shadow-control
    runs -- never pooled across cells, never diluted by abstained/degraded runs.
    """
    treatment, control = stratify(observations)
    keys = sorted(set(treatment) | set(control), key=lambda k: (str(k[0]), k[1].value))
    estimates: dict[StratumKey, LiftEstimate] = {}
    insufficient: list[StratumKey] = []
    for key in keys:
        t_values = treatment.get(key, [])
        c_values = control.get(key, [])
        if len(t_values) < 2 or len(c_values) < 2:
            insufficient.append(key)
            continue
        agent_type_id, mem_type = key
        estimates[key] = estimate_lift(
            t_values,
            c_values,
            agent_type_id=agent_type_id,
            mem_type=mem_type,
            confidence=confidence,
        )
    return LiftReport(estimates=estimates, insufficient_data=tuple(insufficient))


def naive_aggregate_lift(
    observations: Sequence[LiftObservation], *, confidence: float = DEFAULT_CONFIDENCE
) -> LiftEstimate:
    """THE WRONG WAY, on purpose (module docstring): pools every observation by `arm` alone,
    including every abstained/degraded/timed-out/store-error run in both arms -- the
    comparison PLAN.md's Phase 3 gate calls "noise vs noise" at
    `abstention.target_abstention_pct >= 50`.

    This function exists to be called from exactly one place outside its own tests: nowhere.
    `workers.killswitch` never imports it. Its only purpose is
    `tests/phase3/test_lift.py` demonstrating, on one synthetic fleet, that this pooled
    estimate is uninformative (a wide interval straddling zero, or a p-value nowhere near
    significant) while `compute_stratified_lift` on the SAME fleet correctly recovers a
    significant negative lift in the one cell that actually has one -- the evidence for
    stratifying at all.
    """
    treatment = [obs.outcome_r for obs in observations if obs.arm is Arm.MEMORY_ON]
    control = [obs.outcome_r for obs in observations if obs.arm is Arm.HOLDOUT]
    if len(treatment) < 2 or len(control) < 2:
        raise ValueError(
            f"naive_aggregate_lift requires at least 2 observations per arm, got "
            f"memory_on={len(treatment)}, holdout={len(control)}"
        )
    return estimate_lift(
        treatment, control, agent_type_id=None, mem_type=None, confidence=confidence
    )
