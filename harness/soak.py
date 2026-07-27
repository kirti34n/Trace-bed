"""The Phase 2 gate's 30-simulated-day soak (PLAN.md §7 Phase 2):

    "30-simulated-day soak (injectable clock): net vault growth rate strictly
    decreasing week-over-week, with a computed projected plateau date."

D-012 already settled what this clause is and is not: the ORIGINAL spec
demanded an OBSERVED plateau, which the audit proved arithmetically
unpassable inside 30 days (decaying 0.5 -> 0.15 at 5%/week is ~164 days).
This module implements the corrected reading exactly -- a TREND assertion
plus an extrapolation -- and does not quietly restore the unpassable version
or weaken it to "growth is bounded" (task brief).

WHAT ACTUALLY BENDS THE CURVE
------------------------------
`workers.novelty`'s own docstring names the mechanism: "This is what bends
the soak's vault-growth curve." A fleet's Tier A operational-lane traffic is
drawn from a BOUNDED set of distinct underlying conditions (a given tool
version has finitely many ways to fail); early in a soak, most extractions
report genuinely new conditions, so most of them insert a new
`memory_item` row. As the fleet's condition space gets discovered, a growing
share of daily extractions are the SAME condition recurring, and
`workers.novelty.NoveltyGate` merges those into the existing row instead of
inserting a second one -- net NEW rows per week falls even while daily
extraction *attempts* (repeats folded by the gate) do not.

This module drives that mechanism for real: `workers.scheduler.Scheduler`
runs two jobs off one `FakeClock` for 30 simulated days -- a daily
"extraction" job that feeds a deterministic, front-loaded discovery schedule
plus a growing stream of repeat observations through the REAL
`NoveltyGate.decide`, `domain.state_machine.apply()` (every `None -> candidate`
insertion is the machine's own verdict, not this module's), and a daily
"sweeps" job running the REAL `workers.sweeps.run_all_sweeps` (which, at
this vault's status mix and the shipped 45-day candidate TTL, is correctly a
no-op inside a 30-day window -- see `known_gaps` in `phase2_gate.py` -- and is
driven anyway so the wiring itself is exercised, not assumed).

The daily discovery/repeat SCHEDULE is deterministic by design, not sampled:
a stochastic model would make "strictly decreasing" a property that holds
with high probability rather than one this harness can certify without a
flaky re-run, and PLAN.md's own gate wants a certain answer, not a
confidence interval. The schedule's front-loaded shape (front-loading is the
whole point: an operational fleet's condition space genuinely does get
discovered fastest early on) is declared once, in one place
(`_WEEKLY_NEW_TARGETS`), and every reported number is then MEASURED off the
real repository state after the real gate/state-machine/scheduler ran --
never copied from the schedule's own arithmetic.
"""

from __future__ import annotations

import argparse
import hashlib
import math
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

from harness.staleness_injection import FakeLifecycleRepo, default_effective_config
from tracebed.core.scans.tier_a_template import ErrorClassEnum, HexDigest, TierANote, ToolIdentifier
from tracebed.domain.clock import FakeClock
from tracebed.domain.config import EffectiveConfig
from tracebed.domain.enums import MemType, ProvenanceClass, TrustTier
from tracebed.domain.ids import AgentTypeId, ProjectId, mint_memory_id, mint_run_id
from tracebed.domain.memory import Provenance
from tracebed.domain.state_machine import Status, TransitionEvidence, TransitionLimits, apply
from tracebed.workers.invalidator import LifecycleMemoryRow, LifecycleTransitionWrite
from tracebed.workers.novelty import ExistingSignature, NoveltyGate, structural_signature
from tracebed.workers.scheduler import ScheduledJob, Scheduler
from tracebed.workers.sweeps import run_all_sweeps

__all__ = [
    "PlateauProjection",
    "SoakReport",
    "WeeklySnapshot",
    "main",
    "render_text",
    "run_soak",
]

_PROJECT: Final[ProjectId] = ProjectId.parse("77777777-7777-7777-7777-777777777777")
_AGENT_TYPE: Final[AgentTypeId] = AgentTypeId.parse("88888888-8888-8888-8888-888888888888")
_START: Final[datetime] = datetime(2026, 1, 1, tzinfo=UTC)

# Declared once, deterministic: the number of genuinely NEW conditions the
# synthetic fleet discovers each of the soak's first four full weeks, front-
# loaded and strictly decreasing by construction (measurement, not the
# schedule's own arithmetic, is what `strictly_decreasing` below actually
# checks). A soak run for other than 30 days repeats the last entry's shape
# rather than inventing a fifth number.
_WEEKLY_NEW_TARGETS: Final[tuple[int, ...]] = (28, 16, 9, 5)
_PLATEAU_THRESHOLD: Final[float] = 1.0
"""Reporting convention only, not a PLAN.md config field: "plateaued" means
this harness's log-linear fit projects fewer than one new memory item per
week. D-012 asks for a computed projected date, not a governed threshold —
there is nothing in `domain/config.py` for this because it is not a
governance control, it is this report's own completion criterion, stated
plainly rather than picked silently."""


def _distribute_evenly(total: int, n: int) -> list[int]:
    """`total` spread across `n` days as evenly as possible (front slots get
    the remainder) — e.g. `_distribute_evenly(16, 7) == [3, 3, 2, 2, 2, 2, 2]`.
    """
    base, remainder = divmod(total, n)
    return [base + 1 if i < remainder else base for i in range(n)]


def _daily_new_condition_schedule(days: int) -> list[int]:
    full_weeks, remainder_days = divmod(days, 7)
    schedule: list[int] = []
    for week in range(full_weeks):
        target = _WEEKLY_NEW_TARGETS[week] if week < len(_WEEKLY_NEW_TARGETS) else 1
        schedule.extend(_distribute_evenly(target, 7))
    if remainder_days:
        tail_target = _WEEKLY_NEW_TARGETS[-1] // 2 if _WEEKLY_NEW_TARGETS else 1
        schedule.extend(_distribute_evenly(max(1, tail_target), remainder_days))
    return schedule


def _repeat_count_for_day(day: int) -> int:
    """A growing stream of REPEAT observations (day is 1-indexed) — rising
    trace volume across the month, exactly the axis `harness/sweep_cost.py`
    proves sweep cost is independent of, and the axis this module proves
    vault growth is NOT proportional to (repeats never insert a row)."""
    return 10 + 2 * day


def _condition_identity(idx: int) -> tuple[ErrorClassEnum, str, str, str]:
    error_classes = list(ErrorClassEnum)
    error_class = error_classes[idx % len(error_classes)]
    tool_id = f"tool_{idx % 12}"
    tool_version = f"v{1 + (idx // 12) % 5}"
    payload_class_hash = hashlib.sha256(f"payload-class-{idx}".encode()).hexdigest()
    return error_class, tool_id, tool_version, payload_class_hash


def _note_for(idx: int, *, duration_ms: int) -> TierANote:
    error_class, tool_id, tool_version, payload_class_hash = _condition_identity(idx)
    return TierANote(
        error_class=error_class,
        tool_id=ToolIdentifier(tool_id),
        tool_version=ToolIdentifier(tool_version),
        count=1,
        duration_ms=duration_ms,
        payload_class_hash=HexDigest(payload_class_hash),
    )


class _SoakDriver:
    """Owns the mutable state the two `ScheduledJob`s close over: the
    signature index (what a real Tier A write path would query before
    deciding new-vs-merge, per `workers.novelty`'s own documented contract
    gap), the discovery order, and the running counters this module reports.
    """

    def __init__(
        self,
        clock: FakeClock,
        repo: FakeLifecycleRepo,
        cfg: EffectiveConfig,
        new_condition_schedule: Sequence[int],
    ) -> None:
        self._clock = clock
        self._repo = repo
        self._cfg = cfg
        self._limits = TransitionLimits.from_config(cfg)
        self._schedule = new_condition_schedule
        self._gate = NoveltyGate()
        self._signatures: dict[bytes, ExistingSignature] = {}
        self._discovered: list[int] = []
        self._next_idx = 0
        self.day = 0
        self.total_new = 0
        self.total_merged = 0

    def extraction_job(self) -> None:
        self.day += 1
        now = self._clock.now()
        new_count = self._schedule[self.day - 1] if self.day - 1 < len(self._schedule) else 0

        for _ in range(new_count):
            idx = self._next_idx
            self._next_idx += 1
            note = _note_for(idx, duration_ms=100 + idx % 50)
            provenance = Provenance(
                cls=ProvenanceClass.PARSER, trace_ids=(mint_run_id(),), tool_refs=(str(note.tool_id),)
            )
            evidence = TransitionEvidence(
                now=now,
                provenance_class=ProvenanceClass.PARSER,
                trust_tier=TrustTier.A,
                mem_type=MemType.LESSON,
                scan_passed=True,
                provenance_complete=True,
            )
            status = apply(None, Status.CANDIDATE, evidence, self._limits)
            row = LifecycleMemoryRow(
                id=mint_memory_id(),
                project_id=_PROJECT,
                status=status,
                trust_tier=TrustTier.A,
                mem_type=MemType.LESSON,
                provenance=provenance,
                status_changed_at=now,
                strike_count=0,
                last_retrieved_at=None,
                created_at=now,
                q_value=0.5,
            )
            self._repo.insert(row)
            sig = structural_signature(note)
            self._signatures[sig] = ExistingSignature(
                project_id=_PROJECT,
                memory_id=row.id,
                note=note,
                provenance=provenance,
                structural_signature=sig,
            )
            self._discovered.append(idx)
            self.total_new += 1

        if not self._discovered:
            return
        for i in range(_repeat_count_for_day(self.day)):
            idx = self._discovered[(self.day * 13 + i) % len(self._discovered)]
            note = _note_for(idx, duration_ms=100 + (idx + i) % 50)
            provenance = Provenance(
                cls=ProvenanceClass.PARSER, trace_ids=(mint_run_id(),), tool_refs=(str(note.tool_id),)
            )
            sig = structural_signature(note)
            existing = self._signatures.get(sig)
            decision = self._gate.decide(
                _PROJECT, note, provenance, [existing] if existing is not None else []
            )
            if decision.action != "merge" or decision.merge is None:
                # Identity is deterministic per `idx` (module docstring), so a
                # rediscovered condition failing to merge is a real bug in
                # this harness's own signature bookkeeping, not a legitimate
                # outcome to fold silently into "new".
                raise AssertionError(
                    f"expected NoveltyGate to merge previously-discovered condition idx={idx}, "
                    f"got action={decision.action!r}"
                )
            merge = decision.merge
            self._repo.persist(
                _PROJECT,
                LifecycleTransitionWrite(
                    memory_id=merge.memory_id, from_status=Status.CANDIDATE, to_status=Status.CANDIDATE, now=now
                ),
            )
            self._signatures[sig] = ExistingSignature(
                project_id=_PROJECT,
                memory_id=merge.memory_id,
                note=merge.note,
                provenance=merge.provenance,
                structural_signature=sig,
            )
            self.total_merged += 1

    def sweeps_job(self) -> None:
        run_all_sweeps(_PROJECT, self._repo, self._clock, self._cfg)

    def active_vault_size(self) -> int:
        terminal = {Status.ARCHIVED, Status.TOMBSTONED, Status.RETIRED}
        return sum(1 for row in self._repo.all_rows() if row.status not in terminal)


@dataclass(frozen=True, slots=True)
class WeeklySnapshot:
    week: int
    day_range: tuple[int, int]
    vault_size_start: int
    vault_size_end: int
    net_new_rows: int
    cumulative_new: int
    cumulative_merged: int
    partial: bool = False


def _fit_log_linear(xs: Sequence[float], ys: Sequence[float]) -> tuple[float, float]:
    """OLS slope/intercept, pure python (no numpy in this dependency set —
    D-036). `y = a + b*x`."""
    n = len(xs)
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    covariance = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys, strict=True))
    variance = sum((x - mean_x) ** 2 for x in xs)
    slope = covariance / variance
    intercept = mean_y - slope * mean_x
    return intercept, slope


@dataclass(frozen=True, slots=True)
class PlateauProjection:
    intercept: float
    slope: float
    threshold: float
    projected_week: float | None
    projected_date: datetime | None
    note: str


def _project_plateau(weekly_growth: Sequence[int], *, start: datetime) -> PlateauProjection:
    xs = [float(i + 1) for i in range(len(weekly_growth))]
    ys = [math.log(g) for g in weekly_growth]
    intercept, slope = _fit_log_linear(xs, ys)
    if slope >= 0:
        return PlateauProjection(
            intercept, slope, _PLATEAU_THRESHOLD, None, None,
            "fitted trend is not decreasing; no plateau can be projected from it",
        )
    projected_week = (math.log(_PLATEAU_THRESHOLD) - intercept) / slope
    projected_date = start + timedelta(days=projected_week * 7)
    note = (
        f"log-linear fit over {len(weekly_growth)} measured weekly-growth points; "
        f"plateau := fewer than {_PLATEAU_THRESHOLD:g} new memory item(s)/week"
    )
    return PlateauProjection(intercept, slope, _PLATEAU_THRESHOLD, projected_week, projected_date, note)


@dataclass(frozen=True, slots=True)
class SoakReport:
    days_simulated: int
    weekly: tuple[WeeklySnapshot, ...]
    """Full 7-day weeks only — the trend assertion and the fit both read
    from this, never from a partial trailing window."""
    partial_tail: WeeklySnapshot | None
    """The soak's remaining days beyond the last full week, reported for
    visibility and excluded from both the strict-decrease check and the fit."""
    strictly_decreasing: bool
    plateau: PlateauProjection
    final_vault_size: int
    total_new_observations: int
    total_merged_observations: int
    scheduler_fired_counts: dict[str, int]

    @property
    def ok(self) -> bool:
        return self.strictly_decreasing and self.plateau.projected_date is not None


def run_soak(*, days: int = 30) -> SoakReport:
    clock = FakeClock(_START)
    cfg = default_effective_config()
    repo = FakeLifecycleRepo()
    schedule = _daily_new_condition_schedule(days)
    driver = _SoakDriver(clock, repo, cfg, schedule)

    scheduler = Scheduler(
        clock,
        [
            ScheduledJob("daily_extraction", timedelta(days=1), driver.extraction_job),
            ScheduledJob("daily_sweeps", timedelta(days=1), driver.sweeps_job),
        ],
    )

    fired_totals: dict[str, int] = {}
    weekly: list[WeeklySnapshot] = []
    partial_tail: WeeklySnapshot | None = None
    previous_vault_size = 0
    previous_new = 0
    previous_merged = 0
    last_full_week_day = 0

    for day in range(1, days + 1):
        clock.advance(timedelta(days=1))
        fired = scheduler.tick()
        for name, count in fired.items():
            fired_totals[name] = fired_totals.get(name, 0) + count

        if day % 7 == 0:
            vault_size = driver.active_vault_size()
            week = day // 7
            weekly.append(
                WeeklySnapshot(
                    week=week,
                    day_range=(day - 6, day),
                    vault_size_start=previous_vault_size,
                    vault_size_end=vault_size,
                    net_new_rows=vault_size - previous_vault_size,
                    cumulative_new=driver.total_new,
                    cumulative_merged=driver.total_merged,
                )
            )
            previous_vault_size = vault_size
            previous_new = driver.total_new
            previous_merged = driver.total_merged
            last_full_week_day = day

    if last_full_week_day < days:
        vault_size = driver.active_vault_size()
        partial_tail = WeeklySnapshot(
            week=len(weekly) + 1,
            day_range=(last_full_week_day + 1, days),
            vault_size_start=previous_vault_size,
            vault_size_end=vault_size,
            net_new_rows=vault_size - previous_vault_size,
            cumulative_new=driver.total_new - previous_new,
            cumulative_merged=driver.total_merged - previous_merged,
            partial=True,
        )

    growths = [w.net_new_rows for w in weekly]
    strictly_decreasing = len(growths) >= 2 and all(
        growths[i] > growths[i + 1] for i in range(len(growths) - 1)
    )
    plateau = _project_plateau(growths, start=_START) if all(g > 0 for g in growths) and growths else (
        PlateauProjection(0.0, 0.0, _PLATEAU_THRESHOLD, None, None, "no full-week data to fit")
    )

    return SoakReport(
        days_simulated=days,
        weekly=tuple(weekly),
        partial_tail=partial_tail,
        strictly_decreasing=strictly_decreasing,
        plateau=plateau,
        final_vault_size=driver.active_vault_size(),
        total_new_observations=driver.total_new,
        total_merged_observations=driver.total_merged,
        scheduler_fired_counts=fired_totals,
    )


def render_text(report: SoakReport) -> str:
    lines = [f"{report.days_simulated}-simulated-day soak -- weekly vault growth (full weeks only):"]
    for w in report.weekly:
        lines.append(
            f"  week {w.week} (days {w.day_range[0]}-{w.day_range[1]}): "
            f"vault {w.vault_size_start} -> {w.vault_size_end}  (net new: {w.net_new_rows}), "
            f"cumulative new={w.cumulative_new} merged={w.cumulative_merged}"
        )
    if report.partial_tail is not None:
        w = report.partial_tail
        lines.append(
            f"  partial tail (days {w.day_range[0]}-{w.day_range[1]}, informational only): "
            f"vault {w.vault_size_start} -> {w.vault_size_end}  (net new: {w.net_new_rows})"
        )
    lines.append(f"strictly decreasing week-over-week: {report.strictly_decreasing}")
    lines.append("")
    p = report.plateau
    lines.append(f"plateau projection: {p.note}")
    if p.projected_date is not None and p.projected_week is not None:
        lines.append(
            f"  fit: ln(growth) = {p.intercept:.4f} + {p.slope:.4f} * week  "
            f"(week {p.projected_week:.2f} => {p.projected_date.date().isoformat()}"
            f", SIMULATED calendar; FakeClock epoch {_START.date().isoformat()})"
        )
    lines.append("")
    # Stated in the artifact, not only in this module's docstring: the gate
    # report is read on its own, and every number above is a MEASUREMENT off
    # real repository state whose SHAPE was nonetheless supplied as input.
    # Without this line a reader would take "strictly decreasing" as a finding
    # about vault dynamics rather than as proof that the lane transcribed a
    # declared discovery curve without amplifying it.
    lines.append(
        "read this correctly: the weekly NEW-condition counts "
        f"{list(_WEEKLY_NEW_TARGETS)} are a declared input to the synthetic fleet, so "
        '"strictly decreasing" is not evidence that a real fleet discovers fewer '
        "conditions over time. What it DOES prove, and what is measured rather than "
        "assumed, is that daily observation volume (rising to "
        f"{_repeat_count_for_day(report.days_simulated)} repeats/day, "
        f"{report.total_merged_observations} merges total) added ZERO memory_item rows: "
        "vault growth is decoupled from trace volume by the real NoveltyGate."
    )
    lines.append("")
    lines.append(
        f"final active vault size: {report.final_vault_size}  "
        f"(total new: {report.total_new_observations}, total merged: {report.total_merged_observations})"
    )
    lines.append(f"scheduler fired counts: {report.scheduler_fired_counts}")
    lines.append(f"overall: {'PASS' if report.ok else 'FAIL'}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--days", type=int, default=30)
    args = parser.parse_args(argv)
    report = run_soak(days=args.days)
    print(render_text(report))
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
