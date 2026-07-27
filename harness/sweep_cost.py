"""The Phase 2 gate's sweep-cost drill (PLAN.md §7 Phase 2):

    "Sweep cost measured to scale with vault size, not trace volume."

`workers.sweeps`'s own docstring already states the invariant this drill
measures rather than assumes: every `SweepResult.rows_examined` is exactly
the size of one indexed `select_by_status` result, and nothing in that module
reads `trace_index` or any trace-store object. That is a claim about the
CODE; this module is the claim measured on the actual code path, twice:

  (a) hold vault size constant, multiply `FakeLifecycleRepo.trace_row_count`
      (an inert label the sweeps never read) across four orders of
      magnitude -- sweep cost (`rows_examined` summed across the three
      sweeps) must stay flat.
  (b) hold `trace_row_count` constant, multiply vault size across the same
      range -- sweep cost must grow (and does so exactly linearly here,
      because `select_by_status` returns every matching row and this
      harness's own vault is split evenly and exactly across the three
      swept statuses).

"A gate clause that says 'scales with X' and is tested at one point is not
tested" (task brief) -- hence two curves, each with more than one point,
reported in full rather than collapsed to a single before/after pair.
"""

from __future__ import annotations

import argparse
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from harness.staleness_injection import FakeLifecycleRepo, default_effective_config
from tracebed.domain.clock import FakeClock
from tracebed.domain.enums import MemType, ProvenanceClass, TrustTier
from tracebed.domain.ids import AgentTypeId, ProjectId, mint_memory_id, mint_run_id
from tracebed.domain.memory import Provenance
from tracebed.domain.state_machine import Status
from tracebed.workers.invalidator import LifecycleMemoryRow
from tracebed.workers.sweeps import run_all_sweeps

__all__ = [
    "SweepCostPoint",
    "SweepCostReport",
    "main",
    "render_text",
    "run_sweep_cost_drill",
]

_PROJECT: Final[ProjectId] = ProjectId.parse("55555555-5555-5555-5555-555555555555")
_AGENT_TYPE: Final[AgentTypeId] = AgentTypeId.parse("66666666-6666-6666-6666-666666666666")
_START: Final[datetime] = datetime(2026, 1, 1, tzinfo=UTC)

# The three statuses `workers.sweeps.run_all_sweeps` examines. A vault of size
# N is split evenly across all three so total `rows_examined` == N exactly,
# making "scales with vault size" checkable to the row, not just "goes up".
_SWEPT_STATUSES: Final[tuple[Status, ...]] = (Status.QUARANTINED, Status.CANDIDATE, Status.VALIDATED)

_TRACE_VOLUMES: Final[tuple[int, ...]] = (1_000, 10_000, 100_000, 1_000_000)
_VAULT_SIZES: Final[tuple[int, ...]] = (300, 3_000, 30_000)


def _make_row(status: Status, now: datetime) -> LifecycleMemoryRow:
    return LifecycleMemoryRow(
        id=mint_memory_id(),
        project_id=_PROJECT,
        status=status,
        trust_tier=TrustTier.A if status is not Status.VALIDATED else TrustTier.B,
        mem_type=MemType.LESSON,
        provenance=Provenance(cls=ProvenanceClass.PARSER, trace_ids=(mint_run_id(),)),
        status_changed_at=now,
        strike_count=0,
        last_retrieved_at=None,
        created_at=now,
        q_value=0.5,
    )


def _repo_of_size(vault_size: int, *, trace_row_count: int, now: datetime) -> FakeLifecycleRepo:
    """A vault of exactly `vault_size` rows, split evenly across the three
    swept statuses (remainder padded onto `CANDIDATE`), so
    `sum(rows_examined)` equals `vault_size` exactly -- proportionality is
    then checkable arithmetically, not just directionally."""
    per_status = vault_size // len(_SWEPT_STATUSES)
    remainder = vault_size - per_status * len(_SWEPT_STATUSES)
    rows: list[LifecycleMemoryRow] = []
    for i, status in enumerate(_SWEPT_STATUSES):
        count = per_status + (remainder if i == 0 else 0)
        rows.extend(_make_row(status, now) for _ in range(count))
    return FakeLifecycleRepo(rows, trace_row_count=trace_row_count)


def _sweep_cost(repo: FakeLifecycleRepo) -> tuple[int, float]:
    """`(rows_examined_total, wall_clock_ms)` for one `run_all_sweeps` call.
    The row count is the real, deterministic metric this drill asserts on;
    wall-clock time is reported alongside for interest only (an in-memory
    dict scan is not a stand-in for Postgres index-scan latency)."""
    clock = FakeClock(_START)
    cfg = default_effective_config()
    start = time.perf_counter()
    report = run_all_sweeps(_PROJECT, repo, clock, cfg)
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    total = (
        report.quarantine.rows_examined + report.candidate.rows_examined + report.decay.rows_examined
    )
    return total, elapsed_ms


@dataclass(frozen=True, slots=True)
class SweepCostPoint:
    varying_label: str
    varying_value: int
    rows_examined: int
    wall_clock_ms: float


@dataclass(frozen=True, slots=True)
class SweepCostReport:
    vault_size_held_at: int
    trace_volume_curve: tuple[SweepCostPoint, ...]
    """Vault size fixed, `trace_row_count` varied -- cost must stay flat."""
    trace_volume_held_at: int
    vault_size_curve: tuple[SweepCostPoint, ...]
    """`trace_row_count` fixed, vault size varied -- cost must grow."""

    @property
    def cost_independent_of_trace_volume(self) -> bool:
        costs = {p.rows_examined for p in self.trace_volume_curve}
        return len(costs) == 1

    @property
    def cost_scales_with_vault_size(self) -> bool:
        costs = [p.rows_examined for p in self.vault_size_curve]
        sizes = [p.varying_value for p in self.vault_size_curve]
        strictly_increasing = all(costs[i] < costs[i + 1] for i in range(len(costs) - 1))
        # Exact linearity, not merely "went up": this drill's own vault is an
        # even split across three statuses, so cost == vault size precisely.
        exact = all(cost == size for cost, size in zip(costs, sizes, strict=True))
        return strictly_increasing and exact

    @property
    def ok(self) -> bool:
        return self.cost_independent_of_trace_volume and self.cost_scales_with_vault_size


def run_sweep_cost_drill() -> SweepCostReport:
    vault_fixed_size = _VAULT_SIZES[0]
    trace_curve: list[SweepCostPoint] = []
    for trace_volume in _TRACE_VOLUMES:
        repo = _repo_of_size(vault_fixed_size, trace_row_count=trace_volume, now=_START)
        rows_examined, elapsed_ms = _sweep_cost(repo)
        trace_curve.append(
            SweepCostPoint(
                varying_label="trace_row_count",
                varying_value=trace_volume,
                rows_examined=rows_examined,
                wall_clock_ms=elapsed_ms,
            )
        )

    trace_fixed_volume = _TRACE_VOLUMES[1]
    vault_curve: list[SweepCostPoint] = []
    for vault_size in _VAULT_SIZES:
        repo = _repo_of_size(vault_size, trace_row_count=trace_fixed_volume, now=_START)
        rows_examined, elapsed_ms = _sweep_cost(repo)
        vault_curve.append(
            SweepCostPoint(
                varying_label="vault_size",
                varying_value=vault_size,
                rows_examined=rows_examined,
                wall_clock_ms=elapsed_ms,
            )
        )

    return SweepCostReport(
        vault_size_held_at=vault_fixed_size,
        trace_volume_curve=tuple(trace_curve),
        trace_volume_held_at=trace_fixed_volume,
        vault_size_curve=tuple(vault_curve),
    )


def render_text(report: SweepCostReport) -> str:
    lines = [
        f"(a) vault size held at {report.vault_size_held_at} rows, trace_row_count varied "
        f"{report.trace_volume_curve[0].varying_value:,} -> "
        f"{report.trace_volume_curve[-1].varying_value:,}:",
    ]
    for p in report.trace_volume_curve:
        lines.append(f"      trace_row_count={p.varying_value:>10,}  rows_examined={p.rows_examined}")
    lines.append(f"    cost independent of trace volume: {report.cost_independent_of_trace_volume}")
    lines.append("")
    lines.append(
        f"(b) trace_row_count held at {report.trace_volume_held_at:,}, vault size varied "
        f"{report.vault_size_curve[0].varying_value:,} -> {report.vault_size_curve[-1].varying_value:,}:"
    )
    for p in report.vault_size_curve:
        lines.append(f"      vault_size={p.varying_value:>7,}  rows_examined={p.rows_examined}")
    lines.append(f"    cost scales with vault size (exactly linear here): {report.cost_scales_with_vault_size}")
    lines.append("")
    lines.append(f"overall: {'PASS' if report.ok else 'FAIL'}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    report = run_sweep_cost_drill()
    print(render_text(report))
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
