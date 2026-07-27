"""Recall & Rollback — memory forensics (PLAN.md §8 improvement 1; CUTTABLE).

Answers "now what" after a poisoned memory reached `validated`:

  1. quarantine the memory,
  2. enumerate EVERY run it touched via `injection_log`,
  3. flag derived descendants transitively via `memory_link`,
  4. re-open affected outcomes,
  5. emit a BLAST-RADIUS REPORT.

CUTTABLE per PLAN.md §8: this module and its tests are the bounded unit; cutting it
removes `workers/forensics.py` + `tests/phase3/test_forensics.py` and nothing else --
nothing outside this chunk imports it.

Step 1, "quarantine the memory", literally:

CONTRACT GAP (reported, not deviated from). `domain.state_machine.TRANSITIONS` (frozen;
owned by chunk `domain-state-machine`, outside this chunk's file list) has no
`validated -> quarantined` edge at all -- PLAN.md §5's table only reaches `quarantined`
from `None` (creation) or from `candidate` (row 7, weaker-provenance contradiction). A
poisoned memory discovered at `validated` therefore cannot be moved to the literal status
named "quarantined" without a new `TRANSITIONS` entry this chunk may not add. `_contain`
below uses the nearest LEGAL edge that removes the row from
`state_machine.RETRIEVABLE_STATUSES` for each status that can hold one:

  * `candidate -> quarantined` (row 7) -- the one case that IS the literal word, used
    when the poisoned row has not been promoted yet. A poisoning finding is exactly a
    weaker-provenance contradiction of whatever got it to `candidate` in the first place.
  * `validated -> stale` (row 10, `invalidation_event=True`) -- `stale` is excluded from
    `RETRIEVABLE_STATUSES` exactly like `quarantined` is; a poisoning finding IS new
    information that invalidates the row, so this is treated as a real invalidation
    event, not a synonym invented for convenience.

    This substitution is NOT equivalent to the quarantine PLAN.md §8 asks for, and the
    difference is a live hole rather than a naming quibble: `stale -> validated` is a
    legal edge that `workers.revalidation.check_stale` takes UNATTENDED whenever its
    verifier re-verifies. A locally-correct poisoned memory (the OEP shape) is exactly
    the kind that re-verifies, so a contained memory can walk back into retrievability
    with no second human decision -- and NOT after a delay: `revalidation
    .is_due_for_revalidation` makes a `stale` row due on "any LATER instant than the one
    it entered `stale` on", so the very next `revalidation.run_once` tick is enough. The
    R-day idle window applies to `validated` rows only. Nothing in this chunk's file list
    can close that -- the real fix is a `validated -> quarantined` edge in
    `domain/state_machine.py`, or a revalidation worker that refuses a row with an open
    review item, and both files belong to other chunks.

    What IS done here, so the hole is loud rather than silent while it stands:

      * `BlastRadiusReport.containment_reversible_by` carries the unattended routes back
        into `RETRIEVABLE_STATUSES` as DATA -- an empty tuple means the containment holds,
        a non-empty one names every status a background worker can walk the row back to.
        A caller (an API route, a dashboard, a gate assertion) can branch on it. Prose in
        a `review_queue.reason` column cannot be branched on, and this fact is too load-
        bearing to exist only as English inside a text column nothing reads back.
      * every containment additionally opens a `ReviewQueue.flag_contained_memory` row
        stating the same thing for the human, with the reachable statuses probed through
        `apply()` at the time of writing rather than hardcoded.
  * `pinned -> tombstoned` -- pinned participates in exactly `None->pinned` and
    `pinned->tombstoned` (state_machine.py's own docstring); there is no intermediate
    contained state for a preference at all, so a poisoned preference is tombstoned
    outright rather than left retrievable through the forensics pass.

Step 4, "re-open affected outcomes", literally: `outcome_event` (migrations
/0002_partitioned.sql) is a replay-safe append log keyed on `(project_id, event_id)` with
no mutable "reopened" column, and adding one is a schema change outside this chunk's file
list. Reopening is therefore implemented as a `workers.review_queue.ReviewQueue` entry
naming the affected outcome (composes with this chunk's own sibling module, not a new
contract gap) -- reported in `BlastRadiusReport.reopened_outcomes` either way, whether or
not a `ReviewQueue` was supplied to flag it.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Final, Protocol, runtime_checkable
from uuid import UUID

from tracebed.domain.clock import Clock
from tracebed.domain.config import EffectiveConfig
from tracebed.domain.errors import TracebedError
from tracebed.domain.ids import MemoryId, ProjectId, RunId
from tracebed.domain.state_machine import (
    RETRIEVABLE_STATUSES,
    Status,
    TransitionEvidence,
    TransitionLimits,
    apply,
)
from tracebed.workers.edit_ops import EditableMemory, MemoryStatusWrite
from tracebed.workers.review_queue import ReviewQueue, reversible_containment_targets

__all__ = [
    "BlastRadiusReport",
    "Forensics",
    "ForensicsRepoPort",
    "OutcomeEventRef",
]

# Bounds on the descendant walk (`memory_link` `derived_from` edges), mirroring
# `state_machine.independent_confirmations`'s own reasoning: the graph is built from
# rows a store returns, its size is not under this module's control, and a malformed or
# adversarial link graph (a cycle, or a very wide fan-out) must degrade this into a
# bounded-but-possibly-incomplete report rather than hang or crash. Both bounds can only
# make the reported descendant set SMALLER than the true one, never larger, which is the
# safe direction for a forensics report to err in -- an incomplete blast radius still
# names real descendants; a report that never returns names none.
#
# Erring smaller is only safe if the consumer is TOLD. A truncated blast radius that
# reads as a complete one is worse than no report at all, because it will be trusted:
# every id it lists is real, so nothing about it looks wrong. Hitting either bound
# therefore sets `BlastRadiusReport.descendants_truncated`, and the review row
# `ReviewQueue.flag_contained_memory` writes says "at least N" instead of "N".
MAX_DESCENDANTS_CONSIDERED: Final = 10_000
MAX_GENERATIONS_CONSIDERED: Final = 256


@dataclass(frozen=True, slots=True)
class OutcomeEventRef:
    """One `outcome_event` row identified by its replay-safe key, scored while the
    forensically-examined memory was injected into `run_id`."""

    event_id: UUID
    run_id: RunId


@runtime_checkable
class ForensicsRepoPort(Protocol):
    """What `Forensics` needs from a store. `get_memory_by_id`/`persist_status` are
    `workers.edit_ops.MemoryEditRepoPort`'s own pair (reused, not redefined -- both
    chunks act on the same `EditableMemory`/`MemoryStatusWrite` shapes); the other three
    are new reads this chunk needs and `Repo` does not implement yet (contract gap,
    same class as `workers.edit_ops`'s: `injection_log`/`memory_link`/`outcome_event`
    have no query method on `Repo` today, though the DDL PLAN.md §5 sketch already
    defines every column this module reads)."""

    def get_memory_by_id(self, project_id: ProjectId, memory_id: MemoryId) -> EditableMemory: ...

    def persist_status(self, project_id: ProjectId, write: MemoryStatusWrite) -> None: ...

    def list_runs_injected_with(
        self, project_id: ProjectId, memory_id: MemoryId
    ) -> Sequence[RunId]:
        """Every DISTINCT `run_id` from `injection_log` whose `memory_id` matches --
        step 2 of Recall & Rollback."""
        ...

    def list_direct_derived_descendants(
        self, project_id: ProjectId, memory_id: MemoryId
    ) -> Sequence[MemoryId]:
        """Every `memory_link.src_id` where `dst_id = memory_id AND relation =
        'derived_from'` -- i.e. every memory ONE HOP derived from `memory_id`. Step 3's
        transitive closure is this chunk's own BFS over repeated calls to this method
        (`_transitive_descendants`), not a recursive query -- a naive one-hop
        implementation is exactly what the gate test's third-generation assertion is
        designed to catch."""
        ...

    def list_outcome_events_for_runs(
        self, project_id: ProjectId, run_ids: Sequence[RunId]
    ) -> Sequence[OutcomeEventRef]:
        """Every `outcome_event` row (as an `(event_id, run_id)` reference) whose
        `run_id` is one of `run_ids` -- step 4's re-open candidates."""
        ...


@dataclass(frozen=True, slots=True)
class BlastRadiusReport:
    """The one artifact Recall & Rollback exists to produce."""

    memory_id: MemoryId
    from_status: Status
    """The memory's status when this pass started -- before any containment action."""
    contained_status: Status
    """The memory's status after containment: unchanged from `from_status` when it was
    already outside `RETRIEVABLE_STATUSES` (`already_contained=True`), otherwise whatever
    `apply()` returned for the edge `_contain` chose (see module docstring)."""
    already_contained: bool
    containment_reversible_by: tuple[Status, ...]
    """Every retrievable status `contained_status` still reaches in ONE legal transition,
    probed through `apply()` (`review_queue.reversible_containment_targets`).

    Empty means the containment holds. Non-empty means a BACKGROUND WORKER can walk this
    memory back into retrievability with no second human decision -- `stale` keeps
    `stale -> validated`, which `workers.revalidation.check_stale` takes on the next tick
    (see the module docstring). This is a field rather than only a sentence inside the
    `review_queue.reason` text: a caller that must not act on an incomplete containment
    has to be able to TEST for it, and no one can branch on prose."""
    affected_run_ids: tuple[RunId, ...]
    """Every run `injection_log` ties to this memory -- empty, not an error, for a memory
    that was never injected anywhere."""
    descendant_memory_ids: tuple[MemoryId, ...]
    """Every transitive descendant found via `memory_link` `derived_from` edges,
    breadth-first, deduplicated, in discovery order -- INCLUDING descendants found only
    through a chain of two or more `derived_from` hops (the transitive third generation
    the gate test names explicitly)."""
    descendants_truncated: bool
    """True iff the walk stopped at `MAX_DESCENDANTS_CONSIDERED` or
    `MAX_GENERATIONS_CONSIDERED` with link edges still unexplored -- i.e. iff
    `descendant_memory_ids` is a LOWER BOUND on the real descendant set rather than the
    whole of it. Never inferred from `len(descendant_memory_ids)`: a walk that ends
    exactly on the bound with nothing left to explore is complete, and a consumer
    guessing from the length alone would get that case wrong in the unsafe direction."""
    reopened_outcomes: tuple[OutcomeEventRef, ...]
    generated_at: datetime


def _require_project(row: EditableMemory, project_id: ProjectId, *, source: str) -> None:
    """Re-assert project scope before acting on a row a store returned -- the same
    defensive re-check every sibling worker in this package performs (invariant 4)."""
    if row.project_id != project_id:
        raise TracebedError(
            f"{source} returned memory {row.id} scoped to project {row.project_id}, not "
            f"the requested {project_id} (invariant 4)"
        )


class Forensics:
    """Recall & Rollback. `review_queue`, when supplied, is used to flag reopened
    outcomes and derived descendants for a human (composing with this chunk's own
    `workers.review_queue.ReviewQueue`); when omitted, the same information is still
    returned in the `BlastRadiusReport` -- this module never REQUIRES a review queue to
    produce a complete report, only to additionally record one."""

    def __init__(
        self, repo: ForensicsRepoPort, clock: Clock, *, review_queue: ReviewQueue | None = None
    ) -> None:
        self._repo = repo
        self._clock = clock
        self._review_queue = review_queue

    def recall_and_rollback(
        self, project_id: ProjectId, memory_id: MemoryId, *, cfg: EffectiveConfig
    ) -> BlastRadiusReport:
        # One clock read for the whole pass: the containment transition, the review rows
        # it produces and the report itself all describe a single forensic event, and
        # under `SystemClock` a second read makes `generated_at` disagree with the
        # transition it reports (hard rule 3 -- the clock is injected precisely so that
        # "when did this happen" has one answer).
        now = self._clock.now()

        limits = TransitionLimits.from_config(cfg)

        row = self._repo.get_memory_by_id(project_id, memory_id)
        _require_project(row, project_id, source="get_memory_by_id")
        from_status = row.status

        already_contained, contained_status = self._contain(project_id, row, limits, now)
        reversible_by = reversible_containment_targets(contained_status, limits=limits, now=now)

        # De-duplicated defensively: `list_runs_injected_with` is contractually DISTINCT
        # (injection_log's PK is `(project_id, run_id, memory_id)`), but a duplicate
        # arriving anyway would double every re-opened outcome and every review row --
        # inflating a blast radius is the same class of lie as truncating one.
        affected_runs = tuple(dict.fromkeys(self._repo.list_runs_injected_with(project_id, memory_id)))
        descendants, descendants_truncated = self._transitive_descendants(project_id, memory_id)

        outcome_refs: tuple[OutcomeEventRef, ...] = ()
        if affected_runs:
            outcome_refs = tuple(
                dict.fromkeys(self._repo.list_outcome_events_for_runs(project_id, affected_runs))
            )
            # Same discipline as `_require_project` and `edit_ops`'s subject-tag re-check:
            # a row a store hands back is checked against what was ASKED for. An outcome
            # attached to a run this memory was never injected into is not part of this
            # blast radius, and admitting one puts a review row naming an unrelated run on
            # a human's desk -- inflating a blast radius is the same class of lie as
            # truncating one, and it is the class that survives review, because every id
            # in the report is a real id.
            in_radius = set(affected_runs)
            for ref in outcome_refs:
                if ref.run_id not in in_radius:
                    raise TracebedError(
                        f"list_outcome_events_for_runs returned outcome {ref.event_id} for "
                        f"run {ref.run_id}, which memory {memory_id} was never injected into"
                    )

        if self._review_queue is not None:
            # The memory the pass was ABOUT comes first: it is the row a human acts on,
            # and it is the only place the truncation and reversible-containment warnings
            # reach anyone who never sees the returned report.
            self._review_queue.flag_contained_memory(
                project_id,
                memory_id=memory_id,
                from_status=from_status,
                contained_status=contained_status,
                already_contained=already_contained,
                affected_run_count=len(affected_runs),
                descendant_count=len(descendants),
                descendants_truncated=descendants_truncated,
                cfg=cfg,
            )
            for ref in outcome_refs:
                self._review_queue.flag_reopened_outcome(
                    project_id, memory_id=memory_id, run_id=ref.run_id, event_id=ref.event_id
                )
            for descendant_id in descendants:
                self._review_queue.flag_descendant_of_quarantined(
                    project_id,
                    descendant_memory_id=descendant_id,
                    source_memory_id=memory_id,
                )

        return BlastRadiusReport(
            memory_id=memory_id,
            from_status=from_status,
            contained_status=contained_status,
            already_contained=already_contained,
            containment_reversible_by=reversible_by,
            affected_run_ids=affected_runs,
            descendant_memory_ids=descendants,
            descendants_truncated=descendants_truncated,
            reopened_outcomes=outcome_refs,
            generated_at=now,
        )

    # -- step 1: containment ---------------------------------------------------------

    def _contain(
        self, project_id: ProjectId, row: EditableMemory, limits: TransitionLimits, now: datetime
    ) -> tuple[bool, Status]:
        """Removes `row` from `RETRIEVABLE_STATUSES` via the nearest legal edge for its
        current status (see module docstring), or reports it as already contained.
        Returns `(already_contained, resulting_status)`.
        """
        if row.status not in RETRIEVABLE_STATUSES:
            return True, row.status

        if row.status is Status.CANDIDATE:
            target = Status.QUARANTINED
            evidence = TransitionEvidence(
                now=now,
                provenance_class=row.provenance.cls,
                trust_tier=row.trust_tier,
                mem_type=row.mem_type,
                status_changed_at=row.status_changed_at,
                contradiction_weaker_provenance=True,
            )
        elif row.status is Status.VALIDATED:
            target = Status.STALE
            evidence = TransitionEvidence(
                now=now,
                provenance_class=row.provenance.cls,
                trust_tier=row.trust_tier,
                mem_type=row.mem_type,
                status_changed_at=row.status_changed_at,
                invalidation_event=True,
            )
        elif row.status is Status.PINNED:
            target = Status.TOMBSTONED
            evidence = TransitionEvidence(
                now=now,
                provenance_class=row.provenance.cls,
                trust_tier=row.trust_tier,
                mem_type=row.mem_type,
                status_changed_at=row.status_changed_at,
                erasure_or_approved_delete=True,
            )
        else:  # pragma: no cover - RETRIEVABLE_STATUSES is exactly {CANDIDATE, VALIDATED, PINNED}
            raise TracebedError(f"unexpected retrievable status {row.status!r}")

        new_status = apply(row.status, target, evidence, limits)
        self._repo.persist_status(
            project_id,
            MemoryStatusWrite(
                memory_id=row.id, from_status=row.status, to_status=new_status, now=now
            ),
        )
        return False, new_status

    # -- step 3: transitive descendants -----------------------------------------------

    def _transitive_descendants(
        self, project_id: ProjectId, memory_id: MemoryId
    ) -> tuple[tuple[MemoryId, ...], bool]:
        """Breadth-first closure over `list_direct_derived_descendants`, one generation
        at a time -- this is the difference between this implementation and "a naive
        one-hop implementation" (module docstring): the frontier is re-expanded from
        EVERY newly-found descendant, not just the memory the caller originally asked
        about, so a third-generation descendant (derived from a descendant of a
        descendant) is found exactly as reliably as a first-generation one.

        `visited` (seeded with `memory_id` itself) makes a cycle in the link graph a
        no-op rather than an infinite loop; the two `MAX_*` bounds (module-level) cap the
        work against a store returning an unexpectedly large or adversarial graph.

        Returns `(descendants, truncated)`. `truncated` is True iff a bound stopped the
        walk with link edges still unexplored, and it is tracked explicitly rather than
        inferred from `len(descendants)`: a walk that exhausts the graph at exactly
        `MAX_DESCENDANTS_CONSIDERED` ids is COMPLETE, and a length comparison would call
        that one truncated while calling a generation-bounded walk of three ids complete
        -- wrong in both directions, and wrong in the unsafe direction in the second.
        """
        visited = {memory_id}
        frontier = [memory_id]
        order: list[MemoryId] = []
        generations = 0
        truncated = False

        while frontier:
            if generations >= MAX_GENERATIONS_CONSIDERED:
                truncated = True
                break
            generations += 1
            next_frontier: list[MemoryId] = []
            for parent in frontier:
                for child in self._repo.list_direct_derived_descendants(project_id, parent):
                    if child in visited:
                        continue
                    if len(order) >= MAX_DESCENDANTS_CONSIDERED:
                        truncated = True
                        break
                    visited.add(child)
                    order.append(child)
                    next_frontier.append(child)
                if truncated:
                    break
            if truncated:
                break
            frontier = next_frontier

        return tuple(order), truncated
