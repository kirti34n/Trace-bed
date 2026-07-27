"""TTL sweeps and idle decay (PLAN.md §5 state machine; §6 `lifecycle.*`) — PLAN.md §7 Phase 2.

Three independent sweeps, each driven off an INDEXED `memory_item` status predicate
(`MemoryLifecycleRepoPort.select_by_status`) and never a trace scan — the Phase 2 gate's
explicit clause: "SWEEP COST MUST SCALE WITH VAULT SIZE, NOT TRACE VOLUME." Each
`SweepResult.rows_examined` is exactly the size of one indexed `WHERE project_id = ... AND
status = ...` result; nothing in this module reads `trace_index` or any trace-store object,
so `rows_examined` is provably independent of trace volume by construction.

  1. `quarantine_ttl_sweep`: `quarantined -> archived` at `lifecycle.quarantine_ttl_days` (30).
  2. `candidate_ttl_sweep`: `candidate -> archived` at `lifecycle.candidate_ttl_days` (45).
  3. `decay_sweep`: `validated` rows decay their `q_value` toward `lifecycle.archive_floor`
     (0.15) at `lifecycle.decay_pct_per_idle_week` (5) per idle week; once the decayed value
     reaches the floor, `validated -> archived` (`decay_floor_reached`).

The two TTL sweeps reuse `state_machine.apply()`'s own TTL guards rather than
re-implementing the date math: a sweep calls `apply()` for every candidate row and treats
`GuardNotSatisfied` as "not due yet" (not an error). This keeps the TTL arithmetic in
exactly one place (invariant 7) and makes a sweep re-run at the same simulated instant
produce the identical population every time — a row that already transitioned is no longer
returned by `select_by_status`, and a row not yet due raises the same way on every call.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from tracebed.domain.clock import Clock
from tracebed.domain.config import EffectiveConfig
from tracebed.domain.errors import GuardNotSatisfied, TracebedError
from tracebed.domain.ids import MemoryId, ProjectId
from tracebed.domain.state_machine import Status, TransitionEvidence, TransitionLimits, apply
from tracebed.workers.invalidator import (
    LifecycleMemoryRow,
    LifecycleTransitionWrite,
    MemoryLifecycleRepoPort,
)

__all__ = [
    "SweepReport",
    "SweepResult",
    "candidate_ttl_sweep",
    "decay_sweep",
    "quarantine_ttl_sweep",
    "run_all_sweeps",
]


@dataclass(frozen=True, slots=True)
class SweepResult:
    """`rows_examined` is this sweep's measurable cost (module docstring) — the size of one
    indexed `select_by_status` result, never a trace scan."""

    rows_examined: int
    transitioned: tuple[MemoryId, ...]
    decayed_only: tuple[MemoryId, ...] = ()
    """Rows whose `q_value` moved but had not yet reached the archive floor this run
    (`decay_sweep` only; always empty for the two TTL sweeps)."""
    undatable: tuple[MemoryId, ...] = ()
    """Rows with a NULL `status_changed_at`, whose TTL is therefore uncomputable.

    `memory_item.status_changed_at` is nullable (migrations/0002_partitioned.sql), and the
    shared TTL guard treats a missing one as a deficiency — correctly. But a sweep that
    swallows that as an ordinary `GuardNotSatisfied` makes such a row permanently
    unsweepable AND invisible: D-012 added these TTLs precisely so `quarantined` and
    `candidate` would be bounded populations, and a silently-skipped row is one that grows
    the vault forever while every sweep reports success. Surfacing the count is the
    difference between "nothing was due" and "something can never be due"."""


@dataclass(frozen=True, slots=True)
class SweepReport:
    quarantine: SweepResult
    candidate: SweepResult
    decay: SweepResult


def _sweep_ttl(
    project_id: ProjectId,
    repo: MemoryLifecycleRepoPort,
    clock: Clock,
    cfg: EffectiveConfig,
    *,
    source_status: Status,
    target_status: Status,
) -> SweepResult:
    limits = TransitionLimits.from_config(cfg)
    now = clock.now()
    rows = repo.select_by_status(project_id, [source_status])
    transitioned: list[MemoryId] = []
    undatable: list[MemoryId] = []
    for row in rows:
        _require_returned_row(row, project_id, source_status)
        if row.status_changed_at is None:
            # Reported, not swallowed: this row can never satisfy a TTL guard, so it would
            # otherwise sit in `quarantined`/`candidate` forever while the sweep that exists
            # to bound that population reports a clean run every time (see SweepResult).
            undatable.append(row.id)
            continue
        evidence = TransitionEvidence(
            now=now,
            provenance_class=row.provenance.cls,
            trust_tier=row.trust_tier,
            mem_type=row.mem_type,
            status_changed_at=row.status_changed_at,
        )
        try:
            # `row.status`, not `source_status`: the machine judges the edge the row is
            # actually on. With the literal, a store that returned a `validated` row from a
            # `quarantined` select would have had it archived under the quarantine TTL.
            new_status = apply(row.status, target_status, evidence, limits)
        except GuardNotSatisfied:
            continue  # TTL not reached yet — "not due", not a defect
        repo.persist(
            project_id,
            LifecycleTransitionWrite(
                memory_id=row.id, from_status=row.status, to_status=new_status, now=now
            ),
        )
        transitioned.append(row.id)
    return SweepResult(
        rows_examined=len(rows), transitioned=tuple(transitioned), undatable=tuple(undatable)
    )


def _require_returned_row(
    row: LifecycleMemoryRow, project_id: ProjectId, expected_status: Status
) -> None:
    """Re-assert what `select_by_status` promised, on every row, before acting on it.

    The predicate lives in a store implementation that does not exist yet (contract gap,
    `workers.invalidator`'s module docstring), and every sweep here is a bulk status
    *change*. A select that over-returns is therefore a bulk mis-transition — the same class
    of hazard `workers.invalidator` re-asserts its provenance selector against, and the same
    reason `stores.pg.search` re-asserts retrievability on rows it has already filtered
    (D-057(d) / D-070). Raising costs one sweep, which the next tick redoes; not raising
    costs whatever the sweep archived by mistake, which only an operator restore undoes.
    """
    if row.project_id != project_id:
        raise TracebedError(
            f"select_by_status returned memory {row.id} scoped to project {row.project_id}, "
            f"not the requested {project_id} (invariant 4)"
        )
    if row.status is not expected_status:
        raise TracebedError(
            f"select_by_status({expected_status.value!r}) returned memory {row.id}, whose "
            f"status is {row.status.value!r}; a sweep must not transition a row off an edge "
            f"it is not on"
        )


def quarantine_ttl_sweep(
    project_id: ProjectId, repo: MemoryLifecycleRepoPort, clock: Clock, cfg: EffectiveConfig
) -> SweepResult:
    """PLAN.md §5 row 5: `quarantined -> archived` at `lifecycle.quarantine_ttl_days`."""
    return _sweep_ttl(
        project_id,
        repo,
        clock,
        cfg,
        source_status=Status.QUARANTINED,
        target_status=Status.ARCHIVED,
    )


def candidate_ttl_sweep(
    project_id: ProjectId, repo: MemoryLifecycleRepoPort, clock: Clock, cfg: EffectiveConfig
) -> SweepResult:
    """PLAN.md §5 row 8: `candidate -> archived` at `lifecycle.candidate_ttl_days`."""
    return _sweep_ttl(
        project_id,
        repo,
        clock,
        cfg,
        source_status=Status.CANDIDATE,
        target_status=Status.ARCHIVED,
    )


def _idle_weeks(reference: datetime, now: datetime) -> int:
    if now <= reference:
        return 0
    return (now - reference).days // 7


def _decayed_q_value(
    *, q_start: float, floor: float, pct_per_week: float, idle_weeks: int
) -> float:
    """Pure exponential decay from the CONFIGURED Q SEED (`scoring.q_start`), not the row's
    live `q_value`.

    Deliberate, and idempotent by construction: re-running this sweep at the same simulated
    `now` recomputes the identical value from `(q_start, floor, pct_per_week, idle_weeks)`
    alone, with no dependency on a previously-written, possibly-already-decayed number.
    There is no `last_decayed_at` column (migrations/0002_partitioned.sql has none) to anchor
    an incremental "decay one more week" step against, and adding one is outside this
    chunk's file list. Using the row's own stored `q_value` as the base instead would
    double-decay on a second call within the same idle period.

    CONTRACT GAP for Phase 3: once `workers/scorer.py` exists and updates `q_value` from
    real adapter-derived outcomes (D-011), a memory with a genuinely-earned high Q that
    later goes idle should decay from ITS OWN last-active Q, not from the global seed — that
    needs a column recording "Q at the start of the current idle period", which this schema
    does not have. Reported here rather than silently reusing `q_value` as if it were that
    column (idempotency-breaking, per above) or inventing a new migration (outside this
    chunk's file list).

    `pct_per_week` is clamped into `[0, 100]` — a defensive bound on a caller-supplied
    percentage, not an invented magic number: `DerivedConfig`/`LifecycleConfig` carry no
    `Field` bound on this value in `domain/config.py` (outside this chunk's file list).
    """
    pct = min(100.0, max(0.0, pct_per_week))
    if idle_weeks <= 0:
        return q_start
    factor = (1.0 - pct / 100.0) ** idle_weeks
    return max(floor, floor + (q_start - floor) * factor)


def decay_sweep(
    project_id: ProjectId, repo: MemoryLifecycleRepoPort, clock: Clock, cfg: EffectiveConfig
) -> SweepResult:
    """PLAN.md §5 row 11 (`validated -> archived`, decay floor) / §6
    `lifecycle.decay_pct_per_idle_week`.

    A row not yet at the floor gets its `q_value` updated in place (no status change, so no
    `apply()` call — nothing transitioned); a row whose decayed value has reached
    `lifecycle.archive_floor` is archived through `apply()` with `decay_floor_reached=True`,
    and `q_value` is persisted at exactly the floor (never below it — `_decayed_q_value`
    clamps). Once archived, a row leaves the `validated` population `select_by_status`
    returns, so decay "stops": nothing decays it further, ever again.

    A write happens only when the computed value is strictly BELOW the row's stored
    `q_value`. Decay only ever lowers Q, so "not below" means there is nothing to do — and
    that is what makes a re-run at the same simulated instant write nothing at all rather
    than re-writing the identical number for every idle row in the vault. It is also the
    comparison to make rather than an equality test: `q_value` round-trips through a
    `double precision` column, and a sweep whose no-op test is `==` on a float is one
    representation change away from writing forever.
    """
    limits = TransitionLimits.from_config(cfg)
    now = clock.now()
    rows = repo.select_by_status(project_id, [Status.VALIDATED])
    transitioned: list[MemoryId] = []
    decayed_only: list[MemoryId] = []
    for row in rows:
        _require_returned_row(row, project_id, Status.VALIDATED)
        reference = row.last_retrieved_at if row.last_retrieved_at is not None else row.created_at
        idle_weeks = _idle_weeks(reference, now)
        if idle_weeks <= 0:
            continue  # not idle at all yet — nothing to decay
        new_q = _decayed_q_value(
            q_start=cfg.scoring.q_start,
            floor=limits.archive_floor,
            pct_per_week=cfg.lifecycle.decay_pct_per_idle_week,
            idle_weeks=idle_weeks,
        )
        if new_q > limits.archive_floor:
            if new_q >= row.q_value:
                continue  # already at or below this idle period's decayed value
            repo.persist(
                project_id,
                LifecycleTransitionWrite(
                    memory_id=row.id,
                    from_status=row.status,
                    to_status=row.status,
                    now=now,
                    q_value=new_q,
                ),
            )
            decayed_only.append(row.id)
            continue

        evidence = TransitionEvidence(
            now=now,
            provenance_class=row.provenance.cls,
            trust_tier=row.trust_tier,
            mem_type=row.mem_type,
            status_changed_at=row.status_changed_at,
            decay_floor_reached=True,
        )
        new_status = apply(row.status, Status.ARCHIVED, evidence, limits)
        repo.persist(
            project_id,
            LifecycleTransitionWrite(
                memory_id=row.id,
                from_status=row.status,
                to_status=new_status,
                now=now,
                q_value=limits.archive_floor,
            ),
        )
        transitioned.append(row.id)
    return SweepResult(
        rows_examined=len(rows),
        transitioned=tuple(transitioned),
        decayed_only=tuple(decayed_only),
    )


def run_all_sweeps(
    project_id: ProjectId, repo: MemoryLifecycleRepoPort, clock: Clock, cfg: EffectiveConfig
) -> SweepReport:
    """Convenience entry point: all three sweeps, in a fixed order that carries no meaning —
    each reads and writes a disjoint status population, so ordering has no cross-sweep
    effect."""
    return SweepReport(
        quarantine=quarantine_ttl_sweep(project_id, repo, clock, cfg),
        candidate=candidate_ttl_sweep(project_id, repo, clock, cfg),
        decay=decay_sweep(project_id, repo, clock, cfg),
    )
