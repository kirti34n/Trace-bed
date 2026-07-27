"""The kill switch (PLAN.md section 2 invariant "memory must pay for its context"; section 6
`killswitch.*`; section 7 Phase 3; D-027).

Three independently-required conditions, per D-027, and this module enforces all three as
SEPARATE booleans so a caller (and every test) can see which one, if any, is missing -- "needs
all of {LCB<0, sustained 14d, N>=200} and fires on none of them alone":

1. **Lower confidence bound < 0**, from `workers.lift.LiftEstimate.lower_bound` (never the
   point estimate -- see that module).
2. **Sustained for `killswitch.window_days` (14)**: the bound must be adverse on EVERY day of
   an unbroken `window_days`-day trailing window, not merely on the day being evaluated. A
   transient bad day must not disable a memory type any more than a transient good day should
   save one that has been bad for two weeks.
3. **Minimum cell N (`killswitch.min_cell_n`, 200)**, on every one of those days -- a "sustained"
   run of days with too few observations to trust is not evidence, it is thin data that happens
   to agree with itself.

A fourth control, **Benjamini-Hochberg correction across the agent-type x mem-type grid**,
exists for a different reason: even when every cell individually clears the three conditions
above at nominal alpha, testing 20 cells at alpha=0.05 SIMULTANEOUSLY produces roughly one false
positive per window by chance alone (D-027). BH bounds the expected proportion of false
discoveries among triggered cells.

THE STATISTIC BH IS FED IS DIRECTIONAL, AND THAT IS LOAD-BEARING. `LiftEstimate.p_value` is
two-sided. Condition 1 ("lower bound < 0") is a permissive screen that a cell with a large
POSITIVE effect and a wide interval also passes whenever the interval's confidence level is
stricter than the correction's alpha -- and such a cell's two-sided p-value is tiny precisely
BECAUSE its effect is large. Combining the two directly therefore auto-disabled memory types
that were significantly HELPING (demonstrated by
`tests/phase3/test_killswitch.py::TestTriggerDirection`). Both the adverse predicate and the
significance statistic are now derived from one `workers.lift.AdverseDirection` value
(`is_adverse` / `directional_p_value`), so a direction mismatch is unrepresentable rather than
merely discouraged.

ON TRIGGER: exactly the `(agent_type_id, mem_type)` cell that caused it is disabled -- nothing
else. This module writes ONE `killswitch_state` row per triggering cell, keyed on
`(project_id, agent_type_id, mem_type)`; it never disables a cell it did not evaluate as
triggering, and a triggering cell never causes any OTHER cell's row to change (D-027:
"auto-disable the memory type that caused it for that agent-type").

A DEVELOPER OVERRIDE is a separate, explicitly-tagged write (`record_override`) -- an operator
re-enabling or force-disabling a mem_type is recorded with `evidence["source"] ==
"operator_override"` and the acting principal, distinguishable from an automatic trigger's
`evidence["source"] == "auto_killswitch"` on every downstream read (dashboard, audit sink).
There is no automatic re-enable: `apply()` only ever writes `disabled=True`, so recovery is an
operator decision with an operator's name on it. KNOWN LIMITATION, reported rather than
papered over: a standing operator re-enable is not read back before the next `apply()`, so a
cell that still triggers will be disabled again on the next evaluation. Suppressing that needs
a READ of `killswitch_state` scoped to overrides, and `stores/pg/repo.py` (see the contract gap
below) has no such accessor -- inventing an in-memory suppression list here would be a control
that silently evaporates on restart, which is worse than a documented one.

SHARED WITH `workers.safety_lift` (CUTTABLE improvement 2, PLAN.md section 8 item 2): a kill
switch that only ever looks at task-quality lift will happily keep a configuration that is
getting less safe with no attacker present, because render-as-data cannot touch a benign,
statistical safety drift (D-026). `evaluate_grid`/`apply` are therefore generic over WHICH
direction is adverse (`workers.lift.AdverseDirection`) and over the `TriggerReason` recorded --
`workers.safety_lift` calls the exact same sustained-window/min-N/BH/write machinery with
`AdverseDirection.HIGHER` rather than duplicating it.

`bh_alpha` and the confidence level default to `workers.lift.DEFAULT_BH_ALPHA` /
`DEFAULT_CONFIDENCE`, which now READ `domain.config.KillswitchConfig.fdr_alpha` /
`.confidence_level` -- the fields that closed the contract gap this note used to report (a
governed statistical threshold living as a module constant while `killswitch.correction` told
an operator they controlled the method). Still keyword parameters at every call site, so a
caller holding an `EffectiveConfig` can pass a per-project value.

CONTRACT GAP (reported, not deviated on, same shape as `workers.derived_state`'s storage-seam
note): `KillswitchStorePort.write_killswitch_state` has no implementation in `stores/pg/repo.py`
today -- verified by reading that file in full: `Repo.get_killswitch_overlay` (read-only) is the
only method touching `killswitch_state`, and PLAN.md section 5's DDL sketch defines the table
with no corresponding writer anywhere in the codebase. `stores/pg/repo.py` is outside this
chunk's file list (hard rule 8); a real Postgres-backed `KillswitchStorePort` (an upsert on
`(project_id, agent_type_id, mem_type)`, since the table has no separate row per historical
change -- `evidence`/`changed_at` describe the LATEST decision only) is a contract_gap for
whoever owns that file next. Every test in `tests/phase3/test_killswitch.py` substitutes an
in-memory fake, exactly like `workers.invalidator`'s and `workers.derived_state`'s offline
suites do for their own unimplemented store seams.
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from enum import StrEnum
from typing import Protocol, runtime_checkable

from tracebed.domain.clock import Clock
from tracebed.domain.config import KillswitchConfig
from tracebed.domain.enums import MemType
from tracebed.domain.errors import CrossEpochComparison
from tracebed.domain.ids import AgentTypeId, PrincipalId, ProjectId
from tracebed.workers.lift import (
    DEFAULT_BH_ALPHA,
    AdverseDirection,
    LiftEstimate,
    StratumKey,
    directional_p_value,
    is_adverse,
)

# Re-exported, not redefined (D-126). This module carried its own float copy of the
# Benjamini-Hochberg step-up until this pass; a differential run showed the two
# implementations of the one governing correction disagreed on ~2% of randomised inputs,
# all at rank boundaries, with the local copy firing SPURIOUSLY (it rounded the threshold
# up, so a cell whose exact p-value sits fractionally above the boundary was rejected and a
# memory type disabled for an agent type on a floating-point artefact). The name stays
# importable from here because `__all__` and existing callers/tests reference it; what is
# gone is the second author.
from tracebed.workers.statistics import benjamini_hochberg

__all__ = [
    "DailyLiftSnapshot",
    "KillswitchAuditPort",
    "KillswitchGridEvaluator",
    "KillswitchStorePort",
    "SustainedResult",
    "TriggerDecision",
    "TriggerReason",
    "benjamini_hochberg",
    "evaluate_sustained",
]

logger = logging.getLogger(__name__)


class TriggerReason(StrEnum):
    """Which control caused a `killswitch_state` write -- carried into `evidence["reason"]` so
    a dashboard or audit reader never has to guess."""

    TASK_QUALITY_LIFT = "task_quality_lift"
    SAFETY_VIOLATION_RATE = "safety_violation_rate"


@dataclass(frozen=True, slots=True)
class DailyLiftSnapshot:
    """One day's `LiftEstimate` for one `(agent_type_id, mem_type)` cell. `day` is a UTC
    calendar date -- this module derives one from an injected `Clock` through `_utc_day` and
    never reads a wall clock; callers hand in whichever date their own day-bucketed store read
    used, which must be the same UTC convention `workers.spend` documents at length.
    """

    day: date
    estimate: LiftEstimate
    scoring_epoch_id: int | None = None
    """Which `scoring_epoch` produced this day's estimate, when the estimate is derived from a
    judged artifact (hard rule 7 / invariant 7 / D-008).

    `None` for task-quality lift, whose input is adapter-derived outcome polarity with no judge
    in its lineage (`workers.lift.LiftObservation.outcome_r`). REQUIRED for
    `workers.safety_lift`, whose `violation_r` an LLM policy-violation judge produces --
    `workers.safety_lift.compute_stratified_safety_lift` already refuses to pool two epochs
    inside ONE day's estimate, but the trigger compares `window_days` of them, and a judge swap
    on day 7 of a 14-day window is the same silent cross-epoch comparison one level up. Without
    this field the window had no way to notice, and `evidence["scoring_epoch_id"]` would have
    recorded a single epoch the decision was not actually made under."""


def _utc_day(instant: datetime) -> date:
    """The UTC calendar day for a `Clock` instant.

    Rejects a naive instant instead of normalising it, for exactly the reason
    `workers.spend._utc_day` states: `datetime.astimezone`/`.date()` on a naive value silently
    means "host local time", so a 14-day window would start and end at a different instant in
    every deployment timezone and the mis-bucketing would surface months later as a kill switch
    that fired a day early or late, not as an error. `Clock` is a structural Protocol, so any
    object with `now()` satisfies it and this guard is not redundant with `SystemClock`.
    """
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise ValueError(
            "killswitch requires a timezone-aware instant from Clock.now(); a naive datetime "
            "would bucket the sustained window against host-local time, not UTC"
        )
    return instant.astimezone(UTC).date()


@dataclass(frozen=True, slots=True)
class SustainedResult:
    sustained: bool
    """The adverse predicate held on EVERY day of an unbroken `window_days`-day window ending
    at `now`. `False` if the window is not fully covered by snapshots at all -- missing days
    fail closed (not sustained) rather than being skipped, because a gap in reporting is not
    evidence of a healthy cell."""
    min_n_satisfied: bool
    """`n_treatment` and `n_control` both met `min_cell_n` on EVERY day of the same window.
    `False` (not vacuously `True`) when the window is not fully covered, for the same
    fail-closed reason."""
    latest_estimate: LiftEstimate | None
    """The window's last day's estimate, or `None` if `now` itself has no snapshot."""
    days_covered: int
    """How many of the `window_days` trailing calendar days had a snapshot -- diagnostic only,
    never itself a trigger input."""


def evaluate_sustained(
    history: Sequence[DailyLiftSnapshot],
    *,
    window_days: int,
    min_cell_n: int,
    now: date,
    direction: AdverseDirection = AdverseDirection.LOWER,
    expected_epoch: int | None = None,
) -> SustainedResult:
    """Conditions 2 and 3 (module docstring) for ONE cell's daily history.

    Requires a snapshot for every one of the `window_days` calendar days ending at `now`
    (inclusive) -- a cell with only 10 days of history, or one with 14 days but a hole in the
    middle, is not sustained by construction; there is no partial-window average that could
    stand in for "every day looked bad", because that is exactly the claim being tested.

    Two snapshots for the same day are a `ValueError`, not a last-one-wins overwrite: which of
    a good day and a bad day survived would depend on the order the store happened to return
    rows in, which is precisely the kind of silently order-dependent evidence a governance
    control must not act on.

    `expected_epoch`, when supplied, declares that these snapshots are judged artifacts produced
    under that `scoring_epoch` -- every IN-WINDOW snapshot must then carry exactly it, or the
    window raises `domain.errors.CrossEpochComparison` rather than averaging two rulers together
    (hard rule 7 / D-008). Out-of-window snapshots are not checked: they are not compared to
    anything. `None` (the default, and the task-quality path) checks nothing, because
    adapter-derived outcome polarity has no judge whose swap could redefine it.
    """
    if window_days < 1:
        raise ValueError(f"window_days must be at least 1, got {window_days!r}")
    if min_cell_n < 1:
        raise ValueError(f"min_cell_n must be at least 1, got {min_cell_n!r}")

    start = now - timedelta(days=window_days - 1)
    by_day: dict[date, LiftEstimate] = {}
    for snap in history:
        if not start <= snap.day <= now:
            continue
        if snap.day in by_day:
            raise ValueError(
                f"two DailyLiftSnapshots for {snap.day.isoformat()}; a cell's history must have "
                "at most one estimate per day or the window's verdict depends on row order"
            )
        if expected_epoch is not None and snap.scoring_epoch_id != expected_epoch:
            raise CrossEpochComparison(
                f"the day {snap.day.isoformat()} of this {window_days}-day window was judged "
                f"under scoring_epoch {snap.scoring_epoch_id!r}, not {expected_epoch!r}; a judge "
                "change redefines what the measured quantity means, so the window cannot be "
                "compared to itself across it"
            )
        by_day[snap.day] = snap.estimate

    required_days = [start + timedelta(days=i) for i in range(window_days)]
    days_covered = sum(1 for d in required_days if d in by_day)
    fully_covered = days_covered == window_days
    latest = by_day.get(now)

    if not fully_covered:
        return SustainedResult(
            sustained=False,
            min_n_satisfied=False,
            latest_estimate=latest,
            days_covered=days_covered,
        )

    window_estimates = [by_day[d] for d in required_days]
    sustained = all(is_adverse(est, direction) for est in window_estimates)
    min_n_satisfied = all(
        est.n_treatment >= min_cell_n and est.n_control >= min_cell_n for est in window_estimates
    )
    return SustainedResult(
        sustained=sustained,
        min_n_satisfied=min_n_satisfied,
        latest_estimate=latest,
        days_covered=days_covered,
    )


@dataclass(frozen=True, slots=True)
class TriggerDecision:
    """One cell's full trigger evaluation. `should_disable` is the AND of all four conditions
    (module docstring) -- `evidence` is built once, at evaluation time, so `apply()` never has
    to reconstruct it (and risk disagreeing with what was actually evaluated) from the other
    fields."""

    agent_type_id: AgentTypeId
    mem_type: MemType
    reason: TriggerReason
    should_disable: bool
    sustained: bool
    min_n_satisfied: bool
    bh_significant: bool
    latest_estimate: LiftEstimate | None
    evidence: Mapping[str, object]


@runtime_checkable
class KillswitchStorePort(Protocol):
    """What `KillswitchGridEvaluator` needs from a store -- see the module docstring's
    contract gap. `disabled=False` (an operator re-enable) uses the exact same method; there is
    one write path, not two."""

    def write_killswitch_state(
        self,
        project_id: ProjectId,
        agent_type_id: AgentTypeId,
        mem_type: MemType,
        *,
        disabled: bool,
        evidence: Mapping[str, object],
        changed_at: datetime,
    ) -> None: ...


@runtime_checkable
class KillswitchAuditPort(Protocol):
    """Structurally identical to `adapters.ports.AuditSinkPort` -- declared locally so this
    module does not have to import `adapters.ports` (and everything importing that file drags
    in) just to type-hint an optional, best-effort audit emit. Any object with `.emit(...)`,
    including a real `AuditSinkPort` implementation, satisfies this."""

    def emit(self, event: Mapping[str, object]) -> None: ...


def _evidence(
    *,
    reason: TriggerReason,
    source: str,
    sustained: bool | None = None,
    min_n_satisfied: bool | None = None,
    bh_significant: bool | None = None,
    direction: AdverseDirection | None = None,
    estimate: LiftEstimate | None = None,
    scoring_epoch_id: int | None = None,
    principal_id: PrincipalId | None = None,
    override_reason: str | None = None,
    days_covered: int | None = None,
    window_days: int | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {"source": source, "reason": reason.value}
    if direction is not None:
        payload["adverse_direction"] = direction.value
    if sustained is not None:
        payload["sustained"] = sustained
    if min_n_satisfied is not None:
        payload["min_n_satisfied"] = min_n_satisfied
    if bh_significant is not None:
        payload["bh_significant"] = bh_significant
    if days_covered is not None and window_days is not None:
        # Recorded on EVERY decision, triggering or not, because the fail-closed rule in
        # `evaluate_sustained` means a cell with a permanent reporting gap is indistinguishable
        # in `sustained` from a cell that is genuinely healthy: both read `False`. A cell that
        # never reaches full coverage is a cell the kill switch can never fire on, and this pair
        # is what makes that visible to a dashboard or an auditor instead of inferable only by
        # re-reading the store.
        payload["days_covered"] = days_covered
        payload["window_days"] = window_days
    if estimate is not None:
        payload["lower_bound"] = estimate.lower_bound
        payload["point_estimate"] = estimate.point_estimate
        payload["p_value"] = estimate.p_value
        payload["n_treatment"] = estimate.n_treatment
        payload["n_control"] = estimate.n_control
        payload["confidence"] = estimate.confidence
        if direction is not None:
            payload["directional_p_value"] = directional_p_value(estimate, direction)
    if scoring_epoch_id is not None:
        payload["scoring_epoch_id"] = scoring_epoch_id
    if principal_id is not None:
        payload["principal_id"] = str(principal_id)
    if override_reason is not None:
        payload["override_reason"] = override_reason
    return payload


class KillswitchGridEvaluator:
    """Evaluates an agent-type x mem-type grid and, on request, writes the triggering cells to
    `killswitch_state`. One instance per process is fine -- all state needed for one call lives
    in that call's arguments; nothing is cached between `evaluate_grid` calls.
    """

    def __init__(
        self,
        store: KillswitchStorePort,
        clock: Clock,
        *,
        audit: KillswitchAuditPort | None = None,
    ) -> None:
        self._store = store
        self._clock = clock
        self._audit = audit

    def evaluate_grid(
        self,
        history_by_cell: Mapping[StratumKey, Sequence[DailyLiftSnapshot]],
        *,
        cfg: KillswitchConfig,
        reason: TriggerReason = TriggerReason.TASK_QUALITY_LIFT,
        direction: AdverseDirection = AdverseDirection.LOWER,
        bh_alpha: float = DEFAULT_BH_ALPHA,
        scoring_epoch_id: int | None = None,
        now: date | None = None,
    ) -> dict[StratumKey, TriggerDecision]:
        """The full pipeline: per-cell sustained/min-N (conditions 1-3), then BH correction
        (condition 4) across every cell in `history_by_cell` using each cell's most recent
        day's DIRECTIONAL p-value. `should_disable` requires ALL FOUR.

        A cell with no snapshot on `now` (so no p-value to correct) is treated as p=1.0 for the
        BH step -- maximally non-significant, never spuriously rejected -- and its `sustained`/
        `min_n_satisfied` are already `False` from `evaluate_sustained`'s fail-closed rule, so
        `should_disable` is `False` regardless of what BH does with it.

        `scoring_epoch_id` is stamped into every decision's `evidence` when supplied, AND
        ENFORCED against every in-window snapshot of every cell: supplying it asserts that these
        estimates are judged artifacts produced under that epoch, and a window that spans a
        judge change raises `domain.errors.CrossEpochComparison` instead of averaging two
        rulers (hard rule 7). It is optional here because task-quality lift is built from
        adapter-derived outcome polarity, which no judge produces (see
        `workers.lift.LiftObservation.outcome_r`); it is REQUIRED by
        `workers.safety_lift.evaluate_safety_grid`, whose input IS a judged artifact.
        """
        as_of = now if now is not None else _utc_day(self._clock.now())

        keys = list(history_by_cell.keys())
        sustained_results: dict[StratumKey, SustainedResult] = {
            key: evaluate_sustained(
                history_by_cell[key],
                window_days=cfg.window_days,
                min_cell_n=cfg.min_cell_n,
                now=as_of,
                direction=direction,
                expected_epoch=scoring_epoch_id,
            )
            for key in keys
        }

        p_values = [
            directional_p_value(latest, direction)
            if (latest := sustained_results[key].latest_estimate) is not None
            else 1.0
            for key in keys
        ]
        rejected = benjamini_hochberg(p_values, alpha=bh_alpha)
        bh_significant: dict[StratumKey, bool] = dict(zip(keys, rejected, strict=True))

        decisions: dict[StratumKey, TriggerDecision] = {}
        for key in keys:
            agent_type_id, mem_type = key
            result = sustained_results[key]
            should_disable = result.sustained and result.min_n_satisfied and bh_significant[key]
            decisions[key] = TriggerDecision(
                agent_type_id=agent_type_id,
                mem_type=mem_type,
                reason=reason,
                should_disable=should_disable,
                sustained=result.sustained,
                min_n_satisfied=result.min_n_satisfied,
                bh_significant=bh_significant[key],
                latest_estimate=result.latest_estimate,
                evidence=_evidence(
                    reason=reason,
                    source="auto_killswitch",
                    sustained=result.sustained,
                    min_n_satisfied=result.min_n_satisfied,
                    bh_significant=bh_significant[key],
                    direction=direction,
                    estimate=result.latest_estimate,
                    scoring_epoch_id=scoring_epoch_id,
                    days_covered=result.days_covered,
                    window_days=cfg.window_days,
                ),
            )
        return decisions

    def apply(
        self,
        project_id: ProjectId,
        decisions: Mapping[StratumKey, TriggerDecision],
        *,
        now: datetime | None = None,
    ) -> tuple[StratumKey, ...]:
        """Writes `disabled=True` for exactly the cells whose `should_disable` is `True` --
        nothing else. Returns the cells actually disabled, so a caller (or a test) can assert
        "exactly this one, and no other" without re-deriving it from `decisions`.
        """
        moment = self._moment(now)
        applied: list[StratumKey] = []
        for key, decision in decisions.items():
            if not decision.should_disable:
                continue
            agent_type_id, mem_type = key
            self._store.write_killswitch_state(
                project_id,
                agent_type_id,
                mem_type,
                disabled=True,
                evidence=decision.evidence,
                changed_at=moment,
            )
            self._emit_audit(
                project_id=project_id,
                agent_type_id=agent_type_id,
                mem_type=mem_type,
                disabled=True,
                evidence=decision.evidence,
            )
            logger.warning(
                "killswitch: disabling mem_type=%s for agent_type=%s in project=%s (reason=%s)",
                mem_type.value,
                agent_type_id,
                project_id,
                decision.reason.value,
            )
            applied.append(key)
        return tuple(applied)

    def record_override(
        self,
        project_id: ProjectId,
        agent_type_id: AgentTypeId,
        mem_type: MemType,
        *,
        disabled: bool,
        principal_id: PrincipalId,
        justification: str,
        trigger_reason: TriggerReason = TriggerReason.TASK_QUALITY_LIFT,
        now: datetime | None = None,
    ) -> None:
        """A developer override: an operator forcing a mem_type on or off for an agent type,
        independent of (and recorded distinctly from, via `evidence["source"]`) any automatic
        trigger. `justification` is free-text operator reasoning, never parsed.

        `trigger_reason` names WHICH control the operator is overriding, and is a required part
        of the record rather than a constant: an operator re-enabling a mem_type that the
        SAFETY switch disabled, filed under `task_quality_lift`, is an audit trail that says the
        opposite of what happened.
        """
        if not justification.strip():
            raise ValueError("record_override requires a non-empty justification")
        moment = self._moment(now)
        evidence = _evidence(
            reason=trigger_reason,
            source="operator_override",
            principal_id=principal_id,
            override_reason=justification,
        )
        self._store.write_killswitch_state(
            project_id,
            agent_type_id,
            mem_type,
            disabled=disabled,
            evidence=evidence,
            changed_at=moment,
        )
        self._emit_audit(
            project_id=project_id,
            agent_type_id=agent_type_id,
            mem_type=mem_type,
            disabled=disabled,
            evidence=evidence,
        )

    def _moment(self, now: datetime | None) -> datetime:
        """`changed_at` for a `killswitch_state` write, always timezone-aware.

        `killswitch_state.changed_at` is `timestamptz`; Postgres reinterprets a naive value in
        the session TimeZone, which is the same silent-skew hazard D-043 moved to the wire for
        `FeedbackIn.occurred_at`. An injected `Clock` is a structural Protocol, and a
        caller-supplied `now` is not validated anywhere else, so both are checked here.
        """
        instant = now if now is not None else self._clock.now()
        if instant.tzinfo is None or instant.utcoffset() is None:
            raise ValueError(
                "killswitch_state.changed_at must be timezone-aware; a naive datetime is "
                "reinterpreted by Postgres in the session TimeZone"
            )
        return instant

    def _emit_audit(
        self,
        *,
        project_id: ProjectId,
        agent_type_id: AgentTypeId,
        mem_type: MemType,
        disabled: bool,
        evidence: Mapping[str, object],
    ) -> None:
        if self._audit is None:
            return
        # Audit emission is bookkeeping about the decision that already happened -- a failing
        # sink must never make the kill-switch write itself (already committed via
        # `write_killswitch_state` above) appear to have failed.
        with contextlib.suppress(Exception):
            self._audit.emit(
                {
                    "event": "killswitch_state_changed",
                    "project_id": str(project_id),
                    "agent_type_id": str(agent_type_id),
                    "mem_type": mem_type.value,
                    "disabled": disabled,
                    # Nested, never splatted: `evidence` is a Mapping this class does not own
                    # end-to-end (a future store-backed decision could carry extra keys), and a
                    # splat would let one of them overwrite the envelope fields above -- an
                    # audit record that misnames its own project is worse than no record.
                    "evidence": dict(evidence),
                }
            )
