"""The Phase 3 gate's lift simulation (PLAN.md section 7 Phase 3):

    "Lift sim reporting STRATIFIED lift with a confidence interval. READ THIS
    CAREFULLY: PLAN.md says 'operational lane only' IS A DOCUMENTED PASSING
    OUTCOME, and the 2026 evidence says it is the LIKELY one. So the gate must
    not require positive quality-lane lift to pass. It must report what it
    measures honestly and treat 'no measurable quality-lane lift, operational
    lane carries the value' as a PASS with that conclusion stated. Do not
    build a gate that quietly pressures the system toward a flattering
    number."

Driven entirely through the REAL `workers.lift` module -- `compute_stratified_lift`,
`estimate_lift`, and `naive_aggregate_lift` (the module's own "the wrong way,
on purpose" comparison point) -- over a synthetic two-cell fleet:

  * a QUALITY-LANE cell (`MemType.LESSON` -- content-derived, corroborated,
    scored via `workers.scorer`'s Q updates) with NO true effect: treatment
    and control are drawn from the identical distribution, so any measured
    difference is sampling noise;
  * an OPERATIONAL-LANE proxy cell (`MemType.EPISODIC` -- the mem_type
    `workers.extractors` Tier A parsers actually emit, PLAN.md section 7
    Phase 2) with a real, substantial, LLM-free effect baked into the
    simulation.

`workers.lift.LiftObservation` has no `lane` field of its own (`lane` lives on
`memory_item`, one level up from what this module's stratification key
carries) -- the mem_type choice above is this harness's own documented
proxy for "quality lane" vs "operational lane", not a claim that `mem_type`
and `lane` are the same column. See `LiftSimReport`'s docstring for exactly
what "PASS" means here: never the sign of the quality-lane estimate.
"""

from __future__ import annotations

import argparse
import random
from dataclasses import dataclass

from tracebed.domain.enums import Arm, MemType, OutcomeCode
from tracebed.domain.ids import AgentTypeId, RunId
from tracebed.workers.lift import (
    DEFAULT_CONFIDENCE,
    LiftEstimate,
    LiftObservation,
    LiftReport,
    StratumKey,
    compute_stratified_lift,
    naive_aggregate_lift,
)

__all__ = [
    "LiftSimReport",
    "render_text",
    "run_lift_sim",
]

_QUALITY_LANE_MEM_TYPE = MemType.LESSON
_OPERATIONAL_LANE_MEM_TYPE = MemType.EPISODIC

# Simulation parameters. These are THIS HARNESS's own modelling choices (no
# PLAN.md section 6 field describes "how much true lift the operational lane
# has"), documented here rather than presented as measured facts.
_QUALITY_LANE_TREATMENT_P = 0.55
_QUALITY_LANE_CONTROL_P = 0.55
"""Identical probabilities on purpose -- the quality lane has NO true effect
in this simulation, which is the scenario D-027/PLAN.md section 7's 2026
evidence says is the likely real-world one."""

_OPERATIONAL_LANE_TREATMENT_P = 0.75
_OPERATIONAL_LANE_CONTROL_P = 0.55
"""A genuine, substantial (20-point) true effect -- the operational lane
(Tier A, LLM-free) is where this simulation puts the measurable value."""

_N_PER_ARM = 260
"""Comfortably above `killswitch.min_cell_n` (200, PLAN.md section 6) per
arm, so the estimate is the shape a real deployment would actually compute
one on, not a toy sample too small to trust."""

_NAIVE_NOISE_RUNS = 4_000
"""A larger pool for `naive_aggregate_lift`'s pooled comparison -- includes
every abstained/degraded/empty run in BOTH arms (D-027's "noise vs noise"),
which is exactly what makes the naive pooled estimate uninformative even
with many more raw observations than either stratified cell has."""


def _bernoulli_runs(
    rng: random.Random,
    *,
    n: int,
    agent_type_id: AgentTypeId,
    mem_type: MemType,
    treatment_p: float,
    control_p: float,
) -> list[LiftObservation]:
    observations: list[LiftObservation] = []
    for _i in range(n):
        observations.append(
            LiftObservation(
                run_id=_mint_run_id(rng),
                agent_type_id=agent_type_id,
                arm=Arm.MEMORY_ON,
                outcome_code=OutcomeCode.INJECTED,
                mem_type=mem_type,
                outcome_r=1.0 if rng.random() < treatment_p else 0.0,
            )
        )
        observations.append(
            LiftObservation(
                run_id=_mint_run_id(rng),
                agent_type_id=agent_type_id,
                arm=Arm.HOLDOUT,
                outcome_code=OutcomeCode.INJECTED,
                mem_type=mem_type,
                outcome_r=1.0 if rng.random() < control_p else 0.0,
            )
        )
    return observations


def _mint_run_id(rng: random.Random) -> RunId:
    from uuid import UUID

    return RunId(UUID(int=rng.getrandbits(128)))


def _noise_pool(rng: random.Random, *, n: int, agent_type_id: AgentTypeId) -> list[LiftObservation]:
    """Every abstained/degraded/empty/timeout/store-error run in BOTH arms --
    `naive_aggregate_lift`'s pooled estimate treats these identically to the
    genuinely-treated runs above, which is the exact failure D-027 exists to
    correct. A handful of genuinely-placed runs at a near-coinflip rate is
    folded in too, so the pool is not purely codes that resolve to nothing:
    it is dominated by noise, the way a real >=50%-abstention fleet's pooled
    traffic is."""
    codes = (
        OutcomeCode.ABSTAINED_THRESHOLD,
        OutcomeCode.ABSTAINED_RARITY,
        OutcomeCode.EMPTY_RESULT,
        OutcomeCode.TIMEOUT_PREFIX_ONLY,
        OutcomeCode.STORE_ERROR,
    )
    observations: list[LiftObservation] = []
    for i in range(n):
        arm = Arm.MEMORY_ON if rng.random() < 0.5 else Arm.HOLDOUT
        if rng.random() < 0.7:
            # The dominant case: nothing was (or would have been) placed.
            observations.append(
                LiftObservation(
                    run_id=_mint_run_id(rng),
                    agent_type_id=agent_type_id,
                    arm=arm,
                    outcome_code=codes[i % len(codes)],
                    mem_type=None,
                    outcome_r=1.0 if rng.random() < 0.5 else 0.0,
                )
            )
        else:
            p = _QUALITY_LANE_TREATMENT_P if arm is Arm.MEMORY_ON else _QUALITY_LANE_CONTROL_P
            observations.append(
                LiftObservation(
                    run_id=_mint_run_id(rng),
                    agent_type_id=agent_type_id,
                    arm=arm,
                    outcome_code=OutcomeCode.INJECTED,
                    mem_type=_QUALITY_LANE_MEM_TYPE,
                    outcome_r=1.0 if rng.random() < p else 0.0,
                )
            )
    return observations


@dataclass(frozen=True, slots=True)
class LiftSimReport:
    stratified: LiftReport
    naive: LiftEstimate
    quality_lane_cell: StratumKey
    quality_lane_estimate: LiftEstimate | None
    operational_lane_cell: StratumKey
    operational_lane_estimate: LiftEstimate | None
    confidence: float
    conclusion: str

    @property
    def quality_lane_significant_positive(self) -> bool:
        est = self.quality_lane_estimate
        return est is not None and est.lower_bound > 0.0

    @property
    def operational_lane_significant_positive(self) -> bool:
        est = self.operational_lane_estimate
        return est is not None and est.lower_bound > 0.0

    @property
    def ok(self) -> bool:
        """PASS means the simulation ran and produced a real, data-backed
        stratified estimate WITH a confidence interval for both cells --
        never that the quality-lane sign came out positive. Per the module
        docstring, "no measurable quality-lane lift, operational lane
        carries the value" is a documented PASS, not a failure, so the only
        way this reads False is a construction defect: a cell this harness
        expected data for came back with insufficient data to estimate at
        all (`workers.lift.compute_stratified_lift`'s own `insufficient_data`
        list), which would mean the simulation's own sample sizes are too
        small to trust -- never the direction of either cell's effect.
        """
        return (
            self.quality_lane_estimate is not None
            and self.operational_lane_estimate is not None
            and len(self.stratified.insufficient_data) == 0
        )


def run_lift_sim(*, seed: int = 20260726, n_per_arm: int = _N_PER_ARM) -> LiftSimReport:
    rng = random.Random(seed)
    agent_type_id = _agent_type(rng)

    quality_observations = _bernoulli_runs(
        rng,
        n=n_per_arm,
        agent_type_id=agent_type_id,
        mem_type=_QUALITY_LANE_MEM_TYPE,
        treatment_p=_QUALITY_LANE_TREATMENT_P,
        control_p=_QUALITY_LANE_CONTROL_P,
    )
    operational_observations = _bernoulli_runs(
        rng,
        n=n_per_arm,
        agent_type_id=agent_type_id,
        mem_type=_OPERATIONAL_LANE_MEM_TYPE,
        treatment_p=_OPERATIONAL_LANE_TREATMENT_P,
        control_p=_OPERATIONAL_LANE_CONTROL_P,
    )
    all_observations = quality_observations + operational_observations
    stratified = compute_stratified_lift(all_observations, confidence=DEFAULT_CONFIDENCE)

    quality_cell: StratumKey = (agent_type_id, _QUALITY_LANE_MEM_TYPE)
    operational_cell: StratumKey = (agent_type_id, _OPERATIONAL_LANE_MEM_TYPE)
    quality_estimate = stratified.estimates.get(quality_cell)
    operational_estimate = stratified.estimates.get(operational_cell)

    noise_pool = _noise_pool(rng, n=_NAIVE_NOISE_RUNS, agent_type_id=agent_type_id)
    naive = naive_aggregate_lift(all_observations + noise_pool, confidence=DEFAULT_CONFIDENCE)

    conclusion = _conclusion(quality_estimate, operational_estimate, naive)

    return LiftSimReport(
        stratified=stratified,
        naive=naive,
        quality_lane_cell=quality_cell,
        quality_lane_estimate=quality_estimate,
        operational_lane_cell=operational_cell,
        operational_lane_estimate=operational_estimate,
        confidence=DEFAULT_CONFIDENCE,
        conclusion=conclusion,
    )


def _agent_type(rng: random.Random) -> AgentTypeId:
    from uuid import UUID

    return AgentTypeId(UUID(int=rng.getrandbits(128)))


def _conclusion(
    quality: LiftEstimate | None, operational: LiftEstimate | None, naive: LiftEstimate
) -> str:
    quality_sig = quality is not None and quality.lower_bound > 0.0
    operational_sig = operational is not None and operational.lower_bound > 0.0

    if quality is None or operational is None:
        return "INCOMPLETE -- one or both cells had insufficient data to estimate at all."

    quality_line = (
        f"quality lane ({_QUALITY_LANE_MEM_TYPE.value}): point={quality.point_estimate:+.4f}, "
        f"95% one-sided lower bound={quality.lower_bound:+.4f}, p={quality.p_value:.4f} -> "
        f"{'SIGNIFICANT POSITIVE' if quality_sig else 'not significant (CI does not clear zero)'}"
    )
    operational_line = (
        f"operational lane proxy ({_OPERATIONAL_LANE_MEM_TYPE.value}): "
        f"point={operational.point_estimate:+.4f}, lower bound={operational.lower_bound:+.4f}, "
        f"p={operational.p_value:.4f} -> "
        f"{'SIGNIFICANT POSITIVE' if operational_sig else 'not significant'}"
    )
    naive_line = (
        f"naive pooled (arm-only, includes every abstained/degraded run): "
        f"point={naive.point_estimate:+.4f}, lower bound={naive.lower_bound:+.4f}, "
        f"p={naive.p_value:.4f} ({'looks significant' if naive.lower_bound > 0.0 else 'not significant'}) "
        "-- this is D-027's 'noise vs noise' comparison, not read as evidence either way."
    )

    if quality_sig:
        reading = (
            "Reading: this window shows a measurable QUALITY-LANE lift. Not the "
            "documented-likely outcome, but a legitimate PASS on its own terms."
        )
    else:
        reading = (
            "Reading: no measurable quality-lane lift this window; the operational "
            "lane is carrying the measured value. This is a DOCUMENTED PASSING "
            "OUTCOME (PLAN.md section 7 Phase 3), not a failure -- the gate does "
            "not require a positive quality-lane number."
        )

    return "\n".join([quality_line, operational_line, naive_line, reading])


def render_text(report: LiftSimReport) -> str:
    lines = [
        f"confidence level: {report.confidence:.2f} (one-sided lower bound)",
        f"cells with insufficient data: {len(report.stratified.insufficient_data)} "
        f"(must be 0 for this drill to mean anything): {report.stratified.insufficient_data}",
        "",
        report.conclusion,
        "",
        f"overall: {'PASS' if report.ok else 'FAIL'} "
        "(PASS requires only that both cells produced a real CI-backed estimate -- "
        "never that the quality-lane sign was positive)",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=20260726)
    parser.add_argument("--n-per-arm", type=int, default=_N_PER_ARM)
    args = parser.parse_args(argv)
    report = run_lift_sim(seed=args.seed, n_per_arm=args.n_per_arm)
    print(render_text(report))
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
