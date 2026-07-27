"""The review queue: everything the automated lanes refuse to resolve on their own
(PLAN.md §7 Phase 3; DDL `review_queue` table, migrations/0002_partitioned.sql).

PLAN.md's own comment on the table names the two shapes of row that land here: "scan
rejections and anything the state machine refuses to auto-resolve (e.g.
validated->retired below the K-distinct-principals floor, DECISIONS D-021)". This
chunk's task widens that to five reason kinds a human can act on:

  1. scan rejections            -- `core.scans.ScanResult` refused content outright.
  2. open contradictions        -- `candidate -> validated`'s `open_contradiction` guard
                                    is blocking promotion and neither the weaker- nor the
                                    equal/stronger-provenance edge applies, so nothing in
                                    the machine will ever resolve it automatically.
  3. K-1 retirement candidates  -- PLAN.md §5 row 12 / D-021: `validated -> retired`'s
                                    guard is satisfied on Q and scored-use-count but
                                    refuses on distinct-principal count below K; the
                                    guard's own reason names this exact branch as
                                    "route to review_queue instead of auto-retiring".
  4. clamp-binding alerts       -- `workers.derived_state.ClampAlert` (D-022).
  5. divergence alarms          -- `workers.derived_state.DivergenceAlarm` (D-022).

plus the three Recall & Rollback rows `workers.forensics` composes with (PLAN.md §8
improvement 1): the contained memory itself, each re-opened outcome, and each derived
descendant.

Every reason string built here names the memory (or key), the numbers involved, and the
threshold that was not met -- "a reason a human can act on, not an error code" (this
chunk's task description). `review_queue.reason` (migrations/0002_partitioned.sql) is a
free `text` column; there is no enum to satisfy and no reason to invent one only this
module would read -- the human is the only consumer of this string.

`ReviewQueueRepoPort` is exactly `stores.pg.repo.Repo.insert_review_item`'s real
signature (contract §5.1), so the production `Repo` satisfies it with zero adapter code
-- unlike the sibling Phase 2/3 workers in this package, this module has NO contract gap
against `Repo` for its write side. Reading the queue back for a dashboard view is out of
scope for this chunk (no `Repo.list_review_items` exists either) and is not needed by
anything below: every method here only ever writes.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Final, Protocol, runtime_checkable
from uuid import UUID

from tracebed.domain.clock import Clock
from tracebed.domain.config import EffectiveConfig
from tracebed.domain.enums import MemType, ProvenanceClass, TrustTier
from tracebed.domain.errors import GuardNotSatisfied, IllegalTransition
from tracebed.domain.ids import MemoryId, ProjectId, RunId
from tracebed.domain.state_machine import (
    RETRIEVABLE_STATUSES,
    Status,
    TransitionEvidence,
    TransitionLimits,
    apply,
)
from tracebed.workers.derived_state import ClampAlert, DivergenceAlarm

__all__ = [
    "MAX_REASON_CHARS",
    "RetirementCandidate",
    "ReviewQueue",
    "ReviewQueueRepoPort",
    "reversible_containment_targets",
]

# `review_queue.reason` is an unbounded `text` column and several of the reason
# builders below splice in caller-supplied strings (`flag_scan_rejection`'s `reasons`,
# `flag_open_contradiction`'s `note`). `core.scans._dedupe`'s own docstring makes the
# argument this constant enforces: a `reasons` tuple whose length scales with
# attacker-shaped input lands verbatim in this exact column. `scan()` bounds its own
# side by de-duplicating; this module bounds every OTHER caller's side, because a
# review row a human cannot read is a review row that does not get actioned.
MAX_REASON_CHARS: Final = 4_000
_TRUNCATION_MARKER: Final = " [truncated]"

# The exact substring `state_machine._guard_validated_to_retired` puts in
# `GuardNotSatisfied.reason` for precisely the D-021 branch (distinct-principal count
# below K, every other condition already satisfied). `state_machine.py`'s own
# `GuardOutcome` docstring names this as the sanctioned mechanism: "a caller that wants
# to distinguish 'route to review' from 'just illegal/deficient' has only
# `GuardNotSatisfied.reason` (a string) to key off of in Phase 0/3." Matched as a
# substring, not equality, because the reason also embeds the row's live numbers and
# therefore differs on every call.
_ROUTE_TO_REVIEW_MARKER = "route to review_queue instead of auto-retiring"


def _bounded(reason: str) -> str:
    """Every reason this module writes passes through here (see `MAX_REASON_CHARS`)."""
    if len(reason) <= MAX_REASON_CHARS:
        return reason
    return reason[: MAX_REASON_CHARS - len(_TRUNCATION_MARKER)] + _TRUNCATION_MARKER


def reversible_containment_targets(
    status: Status, *, limits: TransitionLimits, now: datetime
) -> tuple[Status, ...]:
    """Retrievable statuses reachable from `status` in ONE legal transition.

    Answers "can an automated worker undo this containment without a second human
    decision?" -- `stale` keeps `stale -> validated` (re-verification, which
    `workers.revalidation.check_stale` performs unattended), so containing a poisoned
    memory there is REVERSIBLE and the review row has to say so.

    Asked through `apply()` rather than by reading `TRANSITIONS`: workers may not import
    that table (`tests/phase2/test_write_path_seams.py` -- the chokepoint stays exactly
    one function wide, hard rule 5), and reading it here would also mean this module
    re-deciding something the machine decides. `apply()` already distinguishes the two
    answers this needs, with a distinct exception type each: `IllegalTransition` is
    raised BEFORE any guard runs and means the edge does not exist at all;
    `GuardNotSatisfied` means the edge exists and merely was not earned by the evidence
    supplied. So a deliberately empty probe -- one that no guard in the table passes --
    separates "no such route" from "a route that a worker with real evidence could take".

    The probe's `provenance_class`/`trust_tier`/`mem_type` cannot change the answer:
    table membership is keyed on `(from, to)` alone and is checked before any guard sees
    a field. They are populated only because `TransitionEvidence` requires them.
    """
    probe = TransitionEvidence(
        now=now,
        provenance_class=ProvenanceClass.DISTILLER,
        trust_tier=TrustTier.B,
        mem_type=MemType.LESSON,
    )
    reachable: list[Status] = []
    for target in sorted(RETRIEVABLE_STATUSES):
        try:
            apply(status, target, probe, limits)
        except IllegalTransition:
            continue  # no such edge -- this containment cannot be undone this way
        except GuardNotSatisfied:
            reachable.append(target)  # the edge is real; only the evidence was missing
        else:  # pragma: no cover - no guard into a retrievable status passes empty evidence
            reachable.append(target)
    return tuple(reachable)


@runtime_checkable
class ReviewQueueRepoPort(Protocol):
    """`Repo.insert_review_item`'s real signature (contract §5.1) -- satisfied
    structurally by the production `Repo` with no adapter."""

    def insert_review_item(
        self, project_id: ProjectId, reason: str, memory_id: MemoryId | None = None
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class RetirementCandidate:
    """Exactly the fields `state_machine._guard_validated_to_retired` inspects, plus the
    memory's own id for the reason string. Assembled by the caller (the scorer chunk owns
    `q_value`/`scored_use_count`/`distinct_scoring_principals`'s real source; this module
    does not read a store at all -- see the module docstring).

    `status` carries the row's OWN live status rather than this module assuming
    `Status.VALIDATED` as a literal: `tests/phase2/test_write_path_seams.py` enforces,
    package-wide, that every `state_machine.apply()` call in `workers/` judges the row's
    own status (an attribute read or a bound name), never a hardcoded `Status.X` --
    exactly the class of defect that test exists to catch mechanically. Passing anything
    other than `Status.VALIDATED` here simply means `apply()` refuses with
    `IllegalTransition`, which is correct: only a `validated` row is ever a retirement
    candidate (PLAN.md §5 row 12)."""

    memory_id: MemoryId
    status: Status
    provenance_class: ProvenanceClass
    trust_tier: TrustTier
    mem_type: MemType
    status_changed_at: datetime | None
    q_value: float
    scored_use_count: int
    distinct_scoring_principals: int


class ReviewQueue:
    """Every `review_queue` write this chunk owns. `repo` is the only I/O seam; every
    method computes its own `reason` string and forwards it unchanged."""

    def __init__(self, repo: ReviewQueueRepoPort, clock: Clock) -> None:
        self._repo = repo
        self._clock = clock

    # -- 1. scan rejections --------------------------------------------------------

    def flag_scan_rejection(
        self,
        project_id: ProjectId,
        *,
        reasons: Sequence[str],
        memory_id: MemoryId | None = None,
        mem_type: MemType | None = None,
    ) -> None:
        """`reasons` is `core.scans.ScanResult.reasons` (or a `ScanRejected.reasons`) --
        never re-derived here, since `core.scans` is the one place that scan logic lives.

        Refuses an empty `reasons`, AND a `reasons` whose every entry is blank: a rejection
        with no reason is not a rejection a human can act on, and `("",)` produced exactly
        that row -- the literal text "scan rejection: " -- while satisfying a `if not
        reasons` check that the error message already claimed meant "non-empty". Blank
        entries mixed in with real ones are dropped rather than rejected, so one empty
        string from a sub-scan cannot suppress the real reasons beside it.
        """
        kept = tuple(r for r in reasons if r.strip())
        if not kept:
            raise ValueError("flag_scan_rejection requires at least one non-empty reason")
        label = f"scan rejection ({mem_type.value})" if mem_type is not None else "scan rejection"
        reason = f"{label}: " + "; ".join(kept)
        self._repo.insert_review_item(project_id, _bounded(reason), memory_id)

    # -- 2. open contradictions ----------------------------------------------------

    def flag_open_contradiction(
        self,
        project_id: ProjectId,
        memory_id: MemoryId,
        *,
        contradicting_memory_id: MemoryId,
        note: str = "",
    ) -> None:
        """PLAN.md §5 row 6: `candidate -> validated`'s `open_contradiction` guard has no
        edge that resolves it automatically -- it is neither "weaker provenance"
        (`candidate -> quarantined`) nor "equal/stronger provenance"
        (`validated -> superseded`, and this row is not even validated yet). Promotion
        stays blocked until a human looks at the pair."""
        reason = (
            f"open contradiction: memory {memory_id} conflicts with memory "
            f"{contradicting_memory_id}; neither provenance class dominates the other, so "
            f"promotion stays blocked (PLAN.md §5 row 6, open_contradiction) pending "
            f"human review."
        )
        if note:
            reason += f" {note}"
        self._repo.insert_review_item(project_id, _bounded(reason), memory_id)

    # -- 3. K-1 retirement candidates ------------------------------------------------

    def flag_retirement_candidate(
        self, project_id: ProjectId, candidate: RetirementCandidate, *, cfg: EffectiveConfig
    ) -> bool:
        """Attempts `validated -> retired` through `state_machine.apply` (invariant 7 --
        this is the ONLY legal way to learn whether a row is a retirement candidate; this
        method never re-derives the guard's arithmetic itself).

        Returns `True` and opens a review item iff the guard refused specifically for
        insufficient distinct scoring principals (PLAN.md §5 row 12 / D-021's "otherwise
        -> review_queue" branch: Q and scored-use-count both already clear their
        thresholds). Returns `False` when `apply()` succeeds outright (auto-retirement is
        the caller's concern elsewhere, not this queue) or when it refuses for any OTHER
        reason (Q has not dropped far enough yet, or not enough scored uses -- not a
        retirement candidate at all, K-deficient or otherwise).
        """
        limits = TransitionLimits.from_config(cfg)
        now = self._clock.now()
        evidence = TransitionEvidence(
            now=now,
            provenance_class=candidate.provenance_class,
            trust_tier=candidate.trust_tier,
            mem_type=candidate.mem_type,
            status_changed_at=candidate.status_changed_at,
            q_value=candidate.q_value,
            scored_use_count=candidate.scored_use_count,
            distinct_scoring_principals=candidate.distinct_scoring_principals,
        )
        try:
            apply(candidate.status, Status.RETIRED, evidence, limits)
        except GuardNotSatisfied as exc:
            if _ROUTE_TO_REVIEW_MARKER not in exc.reason:
                return False
            reason = (
                f"retirement candidate: memory {candidate.memory_id} has q_value="
                f"{candidate.q_value:.3f} (below {limits.retire_q_threshold}) after "
                f"{candidate.scored_use_count} scored uses (>= "
                f"{limits.retire_min_scored_uses} required), but only "
                f"{candidate.distinct_scoring_principals} distinct scoring principal(s) "
                f"contributed (K={limits.retire_min_distinct_principals} required); {exc.reason}"
            )
            self._repo.insert_review_item(project_id, _bounded(reason), candidate.memory_id)
            return True
        else:
            # The transition actually succeeded: this is a real auto-retirement, not a
            # review-queue case at all. Nothing to flag.
            return False

    # -- 4/5. derived-state watchdogs (D-022) ---------------------------------------

    def flag_clamp_binding(self, project_id: ProjectId, alert: ClampAlert) -> None:
        reason = (
            f"derived-state clamp binding: key {alert.key!r} (agent_type "
            f"{alert.agent_type_id}) has clamped {alert.consecutive_clamps} consecutive "
            f"updates at the configured rate bound (derived.baseline_max_delta_pct); "
            f"verify the underlying signal before it reaches the divergence alarm (D-022)."
        )
        self._repo.insert_review_item(project_id, _bounded(reason))

    def flag_divergence_alarm(self, project_id: ProjectId, alarm: DivergenceAlarm) -> None:
        reason = (
            f"derived-state divergence alarm: key {alarm.key!r} (agent_type "
            f"{alarm.agent_type_id}) has moved {alarm.divergence_pct:.1f}% from its "
            f"{alarm.slow_age} reference ({alarm.slow_reference!r} -> "
            f"{alarm.current_value!r}, fast reference {alarm.fast_reference!r}); possible "
            f"baseline-walk poisoning (D-022) -- verify before trusting this baseline."
        )
        self._repo.insert_review_item(project_id, _bounded(reason))

    # -- Recall & Rollback support (workers.forensics composes with these) ----------

    def flag_reopened_outcome(
        self, project_id: ProjectId, *, memory_id: MemoryId, run_id: RunId, event_id: UUID
    ) -> None:
        """One outcome that needs re-evaluation because the memory injected into its run
        has since been quarantined/contained (PLAN.md §8 improvement 1, step 4:
        "re-open affected outcomes"). `outcome_event` has no mutable "reopened" column
        (migrations/0002_partitioned.sql: it is a replay-safe append log keyed on
        `(project_id, event_id)`) -- reopening is therefore implemented as a
        `review_queue` entry naming the affected outcome, not a write to `outcome_event`
        itself."""
        reason = (
            f"reopened outcome: run {run_id} (outcome {event_id}) was scored while memory "
            f"{memory_id} was injected; {memory_id} has since been quarantined/contained "
            f"(Recall & Rollback) and this outcome needs re-evaluation."
        )
        self._repo.insert_review_item(project_id, _bounded(reason), memory_id)

    def flag_descendant_of_quarantined(
        self, project_id: ProjectId, *, descendant_memory_id: MemoryId, source_memory_id: MemoryId
    ) -> None:
        """One memory derived (directly or transitively, via `memory_link`
        `derived_from`) from a memory that has since been quarantined/contained."""
        reason = (
            f"derived descendant: memory {descendant_memory_id} was derived (directly or "
            f"transitively) from memory {source_memory_id}, which has been "
            f"quarantined/contained (Recall & Rollback); review before trusting this "
            f"descendant further."
        )
        self._repo.insert_review_item(project_id, _bounded(reason), descendant_memory_id)

    def flag_contained_memory(
        self,
        project_id: ProjectId,
        *,
        memory_id: MemoryId,
        from_status: Status,
        contained_status: Status,
        already_contained: bool,
        affected_run_count: int,
        descendant_count: int,
        descendants_truncated: bool,
        cfg: EffectiveConfig,
    ) -> None:
        """The memory a Recall & Rollback pass was ABOUT -- not one of its descendants.

        Without this, `workers.forensics` opened a review item for every descendant and
        every re-opened outcome and none at all for the poisoned memory itself: the one
        row a human most needs to see was the only one that existed nowhere but in the
        caller's returned `BlastRadiusReport`, which a caller is free to drop.

        Two facts this row exists to make un-missable, both of which a
        `BlastRadiusReport` field alone cannot carry to a human:

        * `descendants_truncated` -- an under-reported blast radius that LOOKS complete
          is worse than no report, because it will be trusted. The count is stated with
          "at least" whenever the walk hit its bound.
        * a REVERSIBLE containment -- `domain.state_machine.TRANSITIONS` has no
          `validated -> quarantined` edge, so `workers.forensics` contains a validated
          row at `stale`, and `stale -> validated` is an edge an unattended worker
          (`workers.revalidation.check_stale`) takes on its own. Probed through `apply()`
          by `reversible_containment_targets`, never hardcoded.
        """
        if already_contained:
            head = (
                f"contained memory (Recall & Rollback): memory {memory_id} was already "
                f"outside the retrievable statuses at status {from_status.value!r}; no "
                f"transition was applied"
            )
        else:
            head = (
                f"contained memory (Recall & Rollback): memory {memory_id} moved "
                f"{from_status.value!r} -> {contained_status.value!r}"
            )
        radius = (
            f"; blast radius: {'at least ' if descendants_truncated else ''}"
            f"{descendant_count} derived descendant(s) across {affected_run_count} "
            f"affected run(s)"
        )
        if descendants_truncated:
            radius += (
                " -- THE DESCENDANT WALK HIT ITS BOUND, so this radius is INCOMPLETE and "
                "the true descendant set is larger"
            )
        reversible = reversible_containment_targets(
            contained_status,
            limits=TransitionLimits.from_config(cfg),
            now=self._clock.now(),
        )
        tail = "."
        if reversible:
            names = ", ".join(s.value for s in reversible)
            tail = (
                f". WARNING: status {contained_status.value!r} still has a legal "
                f"transition back into retrievable status(es) [{names}], which a "
                f"background worker can take unattended -- this containment is "
                f"reversible; confirm or erase the memory rather than leaving it here."
            )
        self._repo.insert_review_item(project_id, _bounded(head + radius + tail), memory_id)
