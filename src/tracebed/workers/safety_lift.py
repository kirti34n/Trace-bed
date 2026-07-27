"""Safety-aware kill switch (PLAN.md section 8 improvement 2 -- **CUTTABLE**: cutting this
module removes it, `tests/phase3/test_lift.py::TestSafetyLift` and
`tests/phase3/test_killswitch.py::TestSafetyGrid`, and nothing else; `workers.killswitch`'s
task-quality trigger path is unaffected).

THE GAP THIS MODULE CLOSES: `workers.killswitch` (undiminished by this module's absence) only
ever asks "did task-quality outcomes get worse". Benign accumulation -- memory content that is
individually plausible, policy-conformant, and never touched by an attacker -- degrades safety
anyway, at measured violation rates of 0.3-0.5 for broad-retrieval architectures (PLAN.md
section 8 item 2), and the drift is STATISTICAL: no single injected memory looks wrong, so
render-as-data (D-026, itself already reclassified as a governance control, never an
anti-poisoning one) cannot touch it, and neither can a scan suite looking at one memory item at
a time. A kill switch that never asks the safety question will happily keep serving a
configuration that is measurably less safe than not having memory at all, for as long as task
quality alone stays flat or improves.

THE MEASURE: policy-violation RATE, memory-on vs memory-off, using the exact same stratified
machinery `workers.lift` built for task quality -- because the statistical problem is identical
(pooling across abstained/degraded runs, or across agent-type x mem-type cells with opposite
signs, washes out a real effect the same way in both directions). Three differences from
`workers.lift.LiftObservation`, all of them load-bearing:

  - the outcome being measured is `violation_r` (1.0 = a policy violation occurred on this run,
    0.0 = none), not outcome polarity -- a DIFFERENT judged fact about the same run, so it is
    its own dataclass rather than an overload of `LiftObservation` with a confusing field name;
  - the ADVERSE direction is inverted (`workers.lift.AdverseDirection.HIGHER`): for task
    quality, a lower bound BELOW zero is bad; for safety, a lower bound ABOVE zero is bad
    (memory made violations MORE likely, and the effect survives the conservative one-sided
    bound);
  - `violation_r` IS a judged artifact -- an LLM policy-violation judge produces it -- so every
    observation carries `scoring_epoch_id` and this module REFUSES to pool observations from
    two epochs (hard rule 7 / invariant 7 / D-008: "cross-epoch comparison is rejected, not
    silently allowed"). A judge swap mid-window changes what "violation" means; averaging the
    two rulers together and calling the difference a safety trend is exactly the silent
    comparison `domain.errors.CrossEpochComparison` exists to prevent. `LiftObservation` carries
    no epoch because adapter-derived outcome polarity has no judge in its lineage -- the
    asymmetry is deliberate and is stated on that field too.

CONTRACT GAP: this module has the identical join dependency `workers.lift` documents
(trace_index x injection_log x retrieval_event), PLUS a policy-violation judgment per run that
no table in PLAN.md section 5 stores yet -- `outcome_event.payload` is the only jsonb wide
enough to carry one, and no schema pins a key for it, nor for the `scoring_epoch_id` that
judgment must be stamped with. Resolving both is a contract_gap for whoever owns `stores/pg`
and the policy-violation judge next; every test here builds `SafetyObservation`s directly,
exactly like `workers.lift`'s own offline suite.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from tracebed.domain.config import KillswitchConfig
from tracebed.domain.enums import Arm, MemType, OutcomeCode
from tracebed.domain.errors import CrossEpochComparison
from tracebed.domain.ids import AgentTypeId, RunId
from tracebed.workers.killswitch import (
    DailyLiftSnapshot,
    KillswitchGridEvaluator,
    TriggerDecision,
    TriggerReason,
)
from tracebed.workers.lift import (
    DEFAULT_BH_ALPHA,
    DEFAULT_CONFIDENCE,
    AdverseDirection,
    LiftEstimate,
    StratumKey,
    estimate_lift,
    validate_placement,
)

__all__ = [
    "SafetyLiftReport",
    "SafetyObservation",
    "assert_single_epoch",
    "compute_stratified_safety_lift",
    "evaluate_safety_grid",
    "is_shadow_control",
    "is_treatment",
    "stratify_safety",
]


@dataclass(frozen=True, slots=True)
class SafetyObservation:
    """One run's contribution to a safety-lift computation -- structurally parallel to
    `workers.lift.LiftObservation` (see that module for the stratification rationale, and for
    why `mem_type is not None` rather than the outcome code is what identifies a shadow
    control) but measuring a different, judged fact about the run.
    """

    run_id: RunId
    agent_type_id: AgentTypeId
    arm: Arm
    outcome_code: OutcomeCode
    mem_type: MemType | None
    violation_r: float
    """1.0 = a policy violation was judged to have occurred on this run; 0.0 = none. Graded
    values in between are accepted (a partial/ambiguous violation judgment) but everything in
    this module treats it as a plain rate, exactly like `LiftObservation.outcome_r`."""
    scoring_epoch_id: int
    """Which `scoring_epoch` the policy-violation judge ran under (hard rule 7). Required, not
    optional: a judged value with no epoch cannot be compared to anything, and defaulting it
    would let two epochs pool under one placeholder -- the silent comparison the rule forbids."""

    def __post_init__(self) -> None:
        if not 0.0 <= self.violation_r <= 1.0:
            raise ValueError(
                f"SafetyObservation.violation_r={self.violation_r!r} is outside [0, 1]"
            )
        validate_placement(
            kind="SafetyObservation",
            arm=self.arm,
            outcome_code=self.outcome_code,
            mem_type=self.mem_type,
        )


def is_treatment(observation: SafetyObservation) -> bool:
    """"Memory-on" for the safety comparison: something was actually injected."""
    return observation.arm is Arm.MEMORY_ON and observation.mem_type is not None


def is_shadow_control(observation: SafetyObservation) -> bool:
    """"Memory-off" for the safety comparison: the shadow-retrieved holdout counterfactual --
    a holdout-arm run where retrieval WOULD have placed a memory. A holdout run that would have
    abstained carries no `mem_type` and is excluded."""
    return observation.arm is Arm.HOLDOUT and observation.mem_type is not None


def assert_single_epoch(observations: Sequence[SafetyObservation]) -> int | None:
    """The epoch guard (module docstring, hard rule 7). Returns the single `scoring_epoch_id`
    every observation shares, or `None` for an empty sequence.

    Raises `domain.errors.CrossEpochComparison` -- the same typed error `workers.epochs.
    assert_same_epoch` raises -- rather than picking a winner, dropping the minority, or
    averaging across the split. There is no coercion path: the caller either has one epoch's
    worth of judgments or gets an exception.
    """
    epochs = {obs.scoring_epoch_id for obs in observations}
    if not epochs:
        return None
    if len(epochs) > 1:
        raise CrossEpochComparison(
            "cannot compute safety lift across scoring epochs "
            f"{sorted(epochs)}: a judge change redefines what a policy violation is"
        )
    return epochs.pop()


def stratify_safety(
    observations: Sequence[SafetyObservation],
) -> tuple[dict[StratumKey, list[float]], dict[StratumKey, list[float]]]:
    """Per-`(agent_type_id, mem_type)` treatment/control buckets of `violation_r`, with the
    same exclusions `workers.lift.stratify` applies. Epoch-guarded: this is the lowest level at
    which two judgments actually get put in the same bucket."""
    assert_single_epoch(observations)
    treatment: dict[StratumKey, list[float]] = {}
    control: dict[StratumKey, list[float]] = {}
    for obs in observations:
        mem_type = obs.mem_type
        if mem_type is None:
            continue
        target = treatment if is_treatment(obs) else control
        target.setdefault((obs.agent_type_id, mem_type), []).append(obs.violation_r)
    return treatment, control


@dataclass(frozen=True, slots=True)
class SafetyLiftReport:
    estimates: dict[StratumKey, LiftEstimate]
    insufficient_data: tuple[StratumKey, ...]
    scoring_epoch_id: int | None
    """The one epoch every estimate in this report was judged under -- carried so
    `evaluate_safety_grid` can stamp it into `killswitch_state.evidence` and a later reader can
    tell which ruler produced the decision. `None` only when there were no observations."""


def compute_stratified_safety_lift(
    observations: Sequence[SafetyObservation], *, confidence: float = DEFAULT_CONFIDENCE
) -> SafetyLiftReport:
    """`point_estimate = violation_rate(memory-on) - violation_rate(memory-off)` per cell.
    Positive: memory made violations MORE likely, which is the adverse direction here
    (`AdverseDirection.HIGHER`).
    """
    epoch_id = assert_single_epoch(observations)
    treatment, control = stratify_safety(observations)
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
    return SafetyLiftReport(
        estimates=estimates, insufficient_data=tuple(insufficient), scoring_epoch_id=epoch_id
    )


def evaluate_safety_grid(
    evaluator: KillswitchGridEvaluator,
    history_by_cell: Mapping[StratumKey, Sequence[DailyLiftSnapshot]],
    *,
    cfg: KillswitchConfig,
    scoring_epoch_id: int,
    bh_alpha: float = DEFAULT_BH_ALPHA,
) -> dict[StratumKey, TriggerDecision]:
    """Runs the SAME sustained-window / min-N / Benjamini-Hochberg machinery
    `workers.killswitch.KillswitchGridEvaluator.evaluate_grid` uses for task-quality lift,
    tagged `TriggerReason.SAFETY_VIOLATION_RATE` and with the adverse direction inverted to
    `AdverseDirection.HIGHER` -- which flips BOTH the conservative-bound test and the
    directional p-value fed to BH, together, because they come from the same value.

    `evaluator.apply(...)` on the returned decisions writes to the identical `killswitch_state`
    path -- a mem_type disabled for safety reasons is disabled the same way a mem_type disabled
    for task-quality reasons is; only `evidence` tells the two apart.

    `scoring_epoch_id` is REQUIRED here (unlike on `evaluate_grid`, whose input has no judge in
    its lineage): every decision this function produces is derived from judged artifacts, and
    hard rule 7 says every judged artifact records its epoch. Pass the
    `SafetyLiftReport.scoring_epoch_id` the daily snapshots were built from.

    It is also ENFORCED, not merely stamped. `compute_stratified_safety_lift` refuses to pool
    two epochs inside one day's estimate, but the trigger compares `cfg.window_days` of those
    estimates, and a judge swap on day 7 of a 14-day window is the identical silent comparison
    one level up: half the window measures violations with one ruler and half with another,
    while `evidence["scoring_epoch_id"]` claims a single one. `evaluate_grid` therefore checks
    every in-window `DailyLiftSnapshot.scoring_epoch_id` against this argument and raises
    `domain.errors.CrossEpochComparison` on a mismatch -- including the mismatch of an unstamped
    (`None`) snapshot, which is a judged value that cannot be compared to anything.
    """
    return evaluator.evaluate_grid(
        history_by_cell,
        cfg=cfg,
        reason=TriggerReason.SAFETY_VIOLATION_RATE,
        direction=AdverseDirection.HIGHER,
        bh_alpha=bh_alpha,
        scoring_epoch_id=scoring_epoch_id,
    )
