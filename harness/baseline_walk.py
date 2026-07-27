"""The Phase 2 gate's baseline-walk drill (PLAN.md §7 Phase 2, D-022):

    "Baseline-walk drill: monotone drift attack trips the clamp alert and
    divergence alarm."

Drives the REAL `workers.derived_state.DerivedStateWriter` (never a
re-implementation of its rate bound / clamp-alert / divergence-alarm logic)
through a sustained +20%/day monotone walk against an in-memory
`DerivedStateStorePort` double, and reports the concrete day each of the two
watchdogs actually tripped -- not merely that they eventually did.

+20%/day is chosen because it is the one number that exercises BOTH watchdogs
in one scenario: it exceeds `derived.baseline_max_delta_pct` (10, PLAN.md §6)
on every single update, so the rate bound clamps every step and the clamp-
binding alert (`derived.clamp_alert_consecutive`, 3) fires within the first
handful of days; the clamped-but-still-monotone +10%/day *applied* result
still diverges from the far-end slow reference fast enough to alarm well
inside a month. This mirrors
`tests/phase2/test_baseline_drift.py::test_monotone_drift_attack_trips_clamp_alert_and_divergence_alarm`
(same scenario, proven there); this module exists to produce the CONCRETE
day-by-day numbers `harness/phase2_gate.py` reports, which a bare pass/fail
test result cannot carry on its own.

`FakeDerivedStateStore` is duplicated from
`tests/phase2/test_derived_state.py` rather than imported from it -- harness
code must not depend on `tests/` (this chunk's own `harness/phase1_gate.py`
docstring already names per-chunk fake/helper duplication as an accepted
convention here).
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

from tracebed.domain.clock import FakeClock
from tracebed.domain.config import DerivedConfig
from tracebed.domain.ids import AgentTypeId, ProjectId
from tracebed.workers.derived_state import (
    DerivedStateStorePort,
    DerivedStateVersion,
    DerivedStateWriter,
)

__all__ = [
    "BaselineWalkReport",
    "FakeDerivedStateStore",
    "main",
    "render_text",
    "run_baseline_walk",
]

_PROJECT: Final[ProjectId] = ProjectId.parse("33333333-3333-3333-3333-333333333333")
_AGENT_TYPE: Final[AgentTypeId] = AgentTypeId.parse("44444444-4444-4444-4444-444444444444")
_KEY: Final[str] = "success_rate"
_START: Final[datetime] = datetime(2026, 1, 1, tzinfo=UTC)


class FakeDerivedStateStore:
    """In-memory `DerivedStateStorePort`: one append-only list per
    `(project_id, agent_type_id, key)`, ordered by version -- the same shape
    `tests/phase2/test_derived_state.py::FakeDerivedStateStore` uses,
    duplicated per this chunk's own documented convention rather than
    imported across the harness/tests boundary."""

    def __init__(self) -> None:
        self._rows: dict[tuple[ProjectId, AgentTypeId, str], list[DerivedStateVersion]] = {}

    def _bucket(
        self, project_id: ProjectId, agent_type_id: AgentTypeId, key: str
    ) -> list[DerivedStateVersion]:
        return self._rows.setdefault((project_id, agent_type_id, key), [])

    def recent_versions(
        self, project_id: ProjectId, agent_type_id: AgentTypeId, key: str
    ) -> list[DerivedStateVersion]:
        return sorted(self._bucket(project_id, agent_type_id, key), key=lambda row: row.version)

    def append_version(self, version: DerivedStateVersion) -> None:
        self._bucket(version.project_id, version.agent_type_id, version.key).append(version)

    def prune_versions(
        self, project_id: ProjectId, agent_type_id: AgentTypeId, key: str, *, keep: int
    ) -> None:
        bucket = self._bucket(project_id, agent_type_id, key)
        bucket.sort(key=lambda row: row.version)
        if len(bucket) > keep:
            del bucket[: len(bucket) - keep]


assert isinstance(FakeDerivedStateStore(), DerivedStateStorePort)  # structural conformance, checked at import time


@dataclass(frozen=True, slots=True)
class BaselineWalkReport:
    per_day_drift_pct: float
    days_driven: int
    any_clamped: bool
    clamp_alert_tripped: bool
    clamp_alert_first_day: int | None
    divergence_alarm_tripped: bool
    divergence_alarm_first_day: int | None
    final_value: float

    @property
    def ok(self) -> bool:
        """PLAN.md §7's literal clause: BOTH watchdogs trip."""
        return self.clamp_alert_tripped and self.divergence_alarm_tripped


def run_baseline_walk(
    *,
    cfg: DerivedConfig | None = None,
    per_day_drift_pct: float = 20.0,
    days: int = 60,
) -> BaselineWalkReport:
    """Drives `DerivedStateWriter` through a constant `per_day_drift_pct`
    monotone walk for `days` simulated days, against the real rate bound /
    clamp alert / divergence alarm, and reports the day each watchdog first
    fired."""
    config = cfg or DerivedConfig()
    clock = FakeClock(_START)
    writer = DerivedStateWriter(FakeDerivedStateStore(), clock, config)

    per_day_multiplier = 1.0 + per_day_drift_pct / 100.0
    value = 100.0
    first = writer.update(_PROJECT, _AGENT_TYPE, _KEY, value)
    assert first.version is not None  # first write always succeeds unclamped

    any_clamped = False
    clamp_alert_day: int | None = None
    divergence_day: int | None = None

    for day in range(1, days + 1):
        clock.advance(timedelta(days=1))
        value *= per_day_multiplier
        result = writer.update(_PROJECT, _AGENT_TYPE, _KEY, value)
        assert result.version is not None
        any_clamped = any_clamped or result.version.clamped
        if clamp_alert_day is None and result.clamp_alert is not None:
            clamp_alert_day = day
        if divergence_day is None and result.divergence_alarm is not None:
            divergence_day = day
        value = result.version.value  # the CLAMPED value compounds forward, not the raw ask

    return BaselineWalkReport(
        per_day_drift_pct=per_day_drift_pct,
        days_driven=days,
        any_clamped=any_clamped,
        clamp_alert_tripped=clamp_alert_day is not None,
        clamp_alert_first_day=clamp_alert_day,
        divergence_alarm_tripped=divergence_day is not None,
        divergence_alarm_first_day=divergence_day,
        final_value=value,
    )


def render_text(report: BaselineWalkReport) -> str:
    lines = [
        f"monotone drift attack: {report.per_day_drift_pct:.1f}%/day for {report.days_driven} "
        f"simulated days (baseline starts at 100.0, ends at {report.final_value:.1f})",
        f"rate bound (clamp) ever bound: {report.any_clamped}",
        f"clamp-binding alert tripped: {report.clamp_alert_tripped}"
        + (f" (day {report.clamp_alert_first_day})" if report.clamp_alert_first_day else ""),
        f"divergence alarm tripped: {report.divergence_alarm_tripped}"
        + (f" (day {report.divergence_alarm_first_day})" if report.divergence_alarm_first_day else ""),
        f"overall (both watchdogs must trip): {'PASS' if report.ok else 'FAIL'}",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--drift-pct-per-day", type=float, default=20.0)
    parser.add_argument("--days", type=int, default=60)
    args = parser.parse_args(argv)
    report = run_baseline_walk(per_day_drift_pct=args.drift_pct_per_day, days=args.days)
    print(render_text(report))
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
