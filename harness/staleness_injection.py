"""The Phase 2 gate's staleness-injection drill (PLAN.md §7 Phase 2):

    "Staleness injection green (flip tool def -> dependents stale -> two
    strikes retire)."

Drives the REAL `workers.invalidator.Invalidator` and
`workers.revalidation.RevalidationWorker` (never a re-implementation of their
logic) against an in-memory `FakeLifecycleRepo` satisfying
`workers.invalidator.MemoryLifecycleRepoPort`, so every status change below is
`domain.state_machine.apply()`'s own verdict, not this module's.

The scenario, literally:

  1. A fleet of `validated` memories depends on `tool_refs=("vendor_tool_v1",)`
     (provenance carries the tool it was derived from); an unrelated set of
     `validated` memories depends on a different tool and must never move.
  2. "Flip the tool definition": an `InvalidationEvent` selector names
     `vendor_tool_v1`. `Invalidator.process_event` resolves it against
     provenance (never content) and demotes exactly the dependents to `stale`
     (strike 1) -- PLAN.md §5 row 10.
  3. A later revalidation pass (`RevalidationWorker.run_once`, an
     always-fails `RevalidationCheckPort`) supplies the SECOND strike:
     `stale -> retired` per PLAN.md §5's "stale -> retired: second strike".
     The unrelated set is untouched throughout -- over-invalidation would be
     as real a defect as under-invalidation, so both halves are asserted.

`FakeLifecycleRepo` is also imported by `harness/sweep_cost.py` and
`harness/soak.py` (all three are this chunk's own files) rather than
duplicated three times -- the same in-memory-double convention
`harness/phase1_gate.py`'s own docstring names ("per-chunk fake/helper
duplication is an accepted convention"), applied here as *one* fake shared
within one chunk's file list instead of three copies of it.
"""

from __future__ import annotations

import argparse
import dataclasses
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final
from uuid import uuid4

from tracebed.domain.clock import Clock, FakeClock
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
from tracebed.domain.enums import MemType, ProvenanceClass, TrustTier
from tracebed.domain.ids import AgentTypeId, MemoryId, ProjectId, RunId, mint_memory_id
from tracebed.domain.memory import Provenance
from tracebed.domain.state_machine import Status
from tracebed.workers.invalidator import (
    InvalidationEvent,
    InvalidationSelector,
    Invalidator,
    LifecycleMemoryRow,
    LifecycleTransitionWrite,
    MemoryLifecycleRepoPort,
    selector_matches,
)
from tracebed.workers.revalidation import RevalidationCheckPort, RevalidationWorker

__all__ = [
    "FakeLifecycleRepo",
    "StalenessInjectionReport",
    "default_effective_config",
    "main",
    "render_text",
    "run_staleness_injection",
]

_PROJECT: Final[ProjectId] = ProjectId.parse("11111111-1111-1111-1111-111111111111")
_AGENT_TYPE: Final[AgentTypeId] = AgentTypeId.parse("22222222-2222-2222-2222-222222222222")
_START: Final[datetime] = datetime(2026, 1, 1, tzinfo=UTC)


def default_effective_config(**overrides: object) -> EffectiveConfig:
    """One `EffectiveConfig` built from the real Phase 0 section models --
    same pattern `tests/phase2/test_invalidator.py` and
    `tests/phase2/test_prefix_builder.py` already use, so a field rename in
    `domain/config.py` breaks this harness rather than it staying silently
    stale. Shared by `staleness_injection.py`, `sweep_cost.py`, and
    `soak.py`."""
    sections: dict[str, object] = {
        "retrieval": RetrievalConfig(),
        "abstention": AbstentionConfig(),
        "score": ScoreConfig(),
        "budget": BudgetConfig(),
        "scoring": ScoringConfig(),
        "promotion": PromotionConfig(),
        "retirement": RetirementConfig(),
        "lifecycle": LifecycleConfig(),
        "derived": DerivedConfig(),
        "proposals": ProposalConfig(),
        "tier_a": TierAConfig(),
        "killswitch": KillswitchConfig(),
        "spend": SpendConfig(),
        "cache": CacheConfig(),
        "session": SessionConfig(),
        "queue": QueueConfig(),
    }
    sections.update(overrides)
    return EffectiveConfig(**sections)


# --------------------------------------------------------------------------- #
# The shared in-memory `MemoryLifecycleRepoPort` double.
# --------------------------------------------------------------------------- #


class FakeLifecycleRepo:
    """In-memory `MemoryLifecycleRepoPort`, shared by this chunk's three
    drills (`staleness_injection`, `sweep_cost`, `soak`).

    `select_by_status` and `select_due_for_revalidation` are exactly the two
    indexed-predicate queries the port promises -- a linear scan over an
    in-memory dict here, an indexed `WHERE project_id = ... AND status = ...`
    against real Postgres, but the COST MODEL each stands in for is the same:
    proportional to matching `memory_item` rows, never to `trace_row_count`
    (carried on this fake purely as an inert label -- see `sweep_cost.py`,
    which is the one drill that reads it to prove nothing else does).
    """

    def __init__(
        self, rows: Sequence[LifecycleMemoryRow] = (), *, trace_row_count: int = 0
    ) -> None:
        self._rows: dict[MemoryId, LifecycleMemoryRow] = {r.id: r for r in rows}
        self.trace_row_count = trace_row_count
        """Unrelated, never-consulted by any sweep/invalidator/revalidation
        code path -- `harness/sweep_cost.py` varies this while holding vault
        size fixed to prove sweep cost does not move with it."""
        self.persisted: list[LifecycleTransitionWrite] = []

    def insert(self, row: LifecycleMemoryRow) -> None:
        """Not part of `MemoryLifecycleRepoPort` -- harness-only setup/seed
        helper, the fake's equivalent of `Repo.insert_memory_item`."""
        self._rows[row.id] = row

    def all_rows(self) -> tuple[LifecycleMemoryRow, ...]:
        """Harness-only introspection: every row currently held, for
        reporting (never consulted by the workers under test)."""
        return tuple(self._rows.values())

    def select_by_provenance(
        self,
        project_id: ProjectId,
        *,
        tool_refs: Sequence[str] = (),
        trace_ids: Sequence[RunId] = (),
        input_sig_hashes: Sequence[bytes] = (),
    ) -> Sequence[LifecycleMemoryRow]:
        selector = InvalidationSelector(
            tool_refs=tuple(tool_refs),
            trace_ids=tuple(trace_ids),
            input_sig_hashes=tuple(input_sig_hashes),
        )
        return [
            row
            for row in self._rows.values()
            if row.project_id == project_id and selector_matches(row.provenance, selector)
        ]

    def select_by_status(
        self, project_id: ProjectId, statuses: Sequence[Status], *, limit: int = 10_000
    ) -> Sequence[LifecycleMemoryRow]:
        wanted = set(statuses)
        return [
            row
            for row in self._rows.values()
            if row.project_id == project_id and row.status in wanted
        ][:limit]

    def select_due_for_revalidation(
        self, project_id: ProjectId, *, older_than: datetime, limit: int = 10_000
    ) -> Sequence[LifecycleMemoryRow]:
        due: list[LifecycleMemoryRow] = []
        for row in self._rows.values():
            if row.project_id != project_id or row.status is not Status.VALIDATED:
                continue
            reference = row.last_retrieved_at if row.last_retrieved_at is not None else row.created_at
            if reference <= older_than:
                due.append(row)
        return due[:limit]

    def persist(self, project_id: ProjectId, write: LifecycleTransitionWrite) -> None:
        current = self._rows[write.memory_id]
        status_changed = write.from_status != write.to_status
        self._rows[write.memory_id] = dataclasses.replace(
            current,
            status=write.to_status,
            status_changed_at=write.now if status_changed else current.status_changed_at,
            strike_count=write.strike_count if write.strike_count is not None else current.strike_count,
            q_value=write.q_value if write.q_value is not None else current.q_value,
        )
        self.persisted.append(write)


assert isinstance(FakeLifecycleRepo(), MemoryLifecycleRepoPort)  # structural conformance, checked at import time


@dataclass(frozen=True, slots=True)
class _AlwaysFailVerifier:
    """`RevalidationCheckPort`: every re-verification fails -- this drill's
    stand-in for a tool that genuinely no longer works the way the retired
    memory claimed, supplying the second strike deliberately rather than by
    chance."""

    def reverify(self, row: LifecycleMemoryRow) -> bool:
        return False


def _row(
    tag: int,
    *,
    tool_refs: tuple[str, ...],
    created_at: datetime,
) -> LifecycleMemoryRow:
    return LifecycleMemoryRow(
        id=mint_memory_id(),
        project_id=_PROJECT,
        status=Status.VALIDATED,
        trust_tier=TrustTier.B,
        mem_type=MemType.LESSON,
        provenance=Provenance(
            cls=ProvenanceClass.DISTILLER,
            trace_ids=(RunId(uuid4()),),
            tool_refs=tool_refs,
        ),
        status_changed_at=created_at,
        strike_count=0,
        last_retrieved_at=None,
        created_at=created_at,
        q_value=0.6,
    )


# --------------------------------------------------------------------------- #
# The drill itself.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class StalenessInjectionReport:
    dependent_tool_ref: str
    dependents_seeded: int
    non_dependents_seeded: int
    dependents_gone_stale: tuple[MemoryId, ...]
    non_dependents_disturbed: tuple[MemoryId, ...]
    """Must be empty -- any id here means invalidation reached beyond the
    tool's real dependents (over-invalidation)."""
    dependents_retired_after_second_strike: tuple[MemoryId, ...]
    non_dependents_final_status_all_validated: bool

    @property
    def flip_stage_ok(self) -> bool:
        return (
            len(self.dependents_gone_stale) == self.dependents_seeded
            and not self.non_dependents_disturbed
        )

    @property
    def two_strike_stage_ok(self) -> bool:
        return (
            len(self.dependents_retired_after_second_strike) == self.dependents_seeded
            and self.non_dependents_final_status_all_validated
        )

    @property
    def ok(self) -> bool:
        return self.flip_stage_ok and self.two_strike_stage_ok


def run_staleness_injection(
    *,
    dependents: int = 5,
    non_dependents: int = 3,
    clock: Clock | None = None,
) -> StalenessInjectionReport:
    """Runs the full flip -> stale -> second-strike -> retired sequence once
    and reports what actually happened, measured off the fake repo's state --
    never assumed from the scenario's own setup."""
    fake_clock = clock if isinstance(clock, FakeClock) else FakeClock(_START)
    tool_ref = "vendor_tool_v1"
    cfg = default_effective_config()

    dependent_rows = [_row(i, tool_refs=(tool_ref,), created_at=fake_clock.now()) for i in range(dependents)]
    non_dependent_rows = [
        _row(100 + i, tool_refs=("unrelated_tool_v9",), created_at=fake_clock.now())
        for i in range(non_dependents)
    ]
    repo = FakeLifecycleRepo([*dependent_rows, *non_dependent_rows])

    # Stage 1: "flip the tool definition" -- an invalidation event naming the
    # changed tool's ref, resolved through the REAL Invalidator against
    # provenance, never against content.
    invalidator = Invalidator(repo, fake_clock)
    event = InvalidationEvent(
        event_type="tool_definition_changed", selector=InvalidationSelector(tool_refs=(tool_ref,))
    )
    result = invalidator.process_event(_PROJECT, event, cfg)

    dependent_ids = {row.id for row in dependent_rows}
    non_dependent_ids = {row.id for row in non_dependent_rows}
    gone_stale = tuple(mid for mid in result.transitioned_to_stale if mid in dependent_ids)
    disturbed = tuple(mid for mid in result.considered if mid in non_dependent_ids)

    # Stage 2: the second strike. Advance the clock so the now-`stale` rows
    # are due again (`is_due_for_revalidation`: any later instant than the one
    # they entered `stale` on), then run a REAL `RevalidationWorker.run_once`
    # with a verifier that always fails.
    fake_clock.advance(timedelta(days=1))
    revalidator = RevalidationWorker(repo, fake_clock)
    verifier: RevalidationCheckPort = _AlwaysFailVerifier()
    revalidator.run_once(_PROJECT, verifier=verifier, cfg=cfg)

    retired = tuple(
        row.id
        for row in repo.all_rows()
        if row.id in dependent_ids and row.status is Status.RETIRED
    )
    non_dependents_all_validated = all(
        row.status is Status.VALIDATED for row in repo.all_rows() if row.id in non_dependent_ids
    )

    return StalenessInjectionReport(
        dependent_tool_ref=tool_ref,
        dependents_seeded=dependents,
        non_dependents_seeded=non_dependents,
        dependents_gone_stale=gone_stale,
        non_dependents_disturbed=disturbed,
        dependents_retired_after_second_strike=retired,
        non_dependents_final_status_all_validated=non_dependents_all_validated,
    )


def render_text(report: StalenessInjectionReport) -> str:
    lines = [
        f"tool flipped: {report.dependent_tool_ref!r}",
        f"dependents seeded: {report.dependents_seeded}, went stale on the flip: "
        f"{len(report.dependents_gone_stale)}",
        f"non-dependents seeded: {report.non_dependents_seeded}, disturbed by the flip: "
        f"{len(report.non_dependents_disturbed)} (must be 0)",
        f"dependents retired after the second strike: "
        f"{len(report.dependents_retired_after_second_strike)}/{report.dependents_seeded}",
        f"non-dependents still validated at the end: {report.non_dependents_final_status_all_validated}",
        f"flip stage ok: {report.flip_stage_ok}; two-strike stage ok: {report.two_strike_stage_ok}",
        f"overall: {'PASS' if report.ok else 'FAIL'}",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dependents", type=int, default=5)
    parser.add_argument("--non-dependents", type=int, default=3)
    args = parser.parse_args(argv)
    report = run_staleness_injection(dependents=args.dependents, non_dependents=args.non_dependents)
    print(render_text(report))
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
