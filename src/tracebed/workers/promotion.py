"""Promotion (`candidate -> validated`) and retirement (`validated -> retired`) — PLAN.md §5
rows 6 and 12, §6 `promotion.*`/`retirement.*`, §7 Phase 3. D-021 (retirement's principal
threshold K) is the correction this worker's retirement half exists to enforce: automatic
retirement below K distinct scoring principals is a memory-destruction primitive one
attacker-controlled feedback source can trigger in four calendar days (D-021's own
arithmetic), so this worker routes that case to `review_queue` instead of retiring.

Same discipline as `workers.shadow_validator`: every governance decision is
`domain.state_machine.apply()`'s, never re-derived here. What this module owns is the
promotion/retirement predicates' *evidence assembly* (reading a row's pre-aggregated
outcome/principal counts) and the review-queue routing `apply()` itself cannot perform
(PLAN.md §5 row 12: "the machine only refuses" — routing on refusal is the caller's job).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable

from tracebed.domain.clock import Clock
from tracebed.domain.config import EffectiveConfig
from tracebed.domain.enums import MemType, TrustTier
from tracebed.domain.errors import GuardNotSatisfied, TracebedError
from tracebed.domain.ids import MemoryId, ProjectId
from tracebed.domain.memory import Provenance
from tracebed.domain.state_machine import Status, TransitionEvidence, TransitionLimits, apply

__all__ = [
    "CandidateMemoryRow",
    "PromotionBatchResult",
    "PromotionOutcome",
    "PromotionRepoPort",
    "PromotionTransitionWrite",
    "PromotionWorker",
    "RetirementBatchResult",
    "RetirementOutcome",
    "ValidatedMemoryRow",
]


@dataclass(frozen=True, slots=True)
class CandidateMemoryRow:
    """The projection of a `candidate` `memory_item` row this worker needs to evaluate
    promotion (PLAN.md §5 row 6).

    The four promotion fields below are pre-aggregated by the store from `outcome_event`
    rows joined through `injection_log` (which run this candidate was actually injected
    into) and from any open `memory_link(relation='contradicts')` — neither join lives in
    this chunk's file list, so this row is the same kind of thin projection
    `workers.invalidator.LifecycleMemoryRow` already is for the Phase 2 lifecycle workers:
    this worker only ever consumes it.
    """

    id: MemoryId
    project_id: ProjectId
    status: Status
    trust_tier: TrustTier
    mem_type: MemType
    provenance: Provenance
    status_changed_at: datetime | None
    promotion_outcomes: int
    """Count of outcome-consistent, scored observations tied to a run where this candidate
    was injected — the raw count PLAN.md §5 row 6 compares against
    `promotion.min_outcomes`/`promotion.failure_lesson_outcomes`."""
    promotion_distinct_principals: int
    """Distinct authenticated `outcome_event.principal_id` values among those observations."""
    outcome_consistent: bool
    """Whether the observations agree (no recorded outcome contradicts the memory's claim).
    A single negative-polarity outcome among otherwise-positive ones makes this False —
    computing what "agree" means for a given `mem_type` is the store's aggregation, not this
    worker's; this worker only reads the pre-computed verdict."""
    scan_repass: bool
    open_contradiction: bool


@dataclass(frozen=True, slots=True)
class ValidatedMemoryRow:
    """The projection of a `validated` `memory_item` row this worker needs to evaluate
    retirement (PLAN.md §5 row 12 / D-021)."""

    id: MemoryId
    project_id: ProjectId
    status: Status
    trust_tier: TrustTier
    mem_type: MemType
    provenance: Provenance
    status_changed_at: datetime | None
    q_value: float
    scored_use_count: int
    distinct_scoring_principals: int
    """Distinct authenticated principals across every scored Q update this memory has
    received — the count D-021 requires to be `>= retirement.min_distinct_principals` (K)
    before an automatic retirement is even considered."""


@dataclass(frozen=True, slots=True)
class PromotionTransitionWrite:
    """One committed status write for either edge this worker authorises — always
    `to_status == apply()`'s return value."""

    memory_id: MemoryId
    from_status: Status
    to_status: Status
    now: datetime


@runtime_checkable
class PromotionRepoPort(Protocol):
    def select_candidates_for_promotion(
        self, project_id: ProjectId
    ) -> Sequence[CandidateMemoryRow]:
        """Indexed `(project_id, status='candidate')` — never a trace scan."""
        ...

    def select_validated_for_retirement(
        self, project_id: ProjectId
    ) -> Sequence[ValidatedMemoryRow]:
        """Indexed `(project_id, status='validated')` — never a trace scan."""
        ...

    def persist(self, project_id: ProjectId, write: PromotionTransitionWrite) -> None: ...

    def insert_review_item(
        self, project_id: ProjectId, reason: str, memory_id: MemoryId | None = None
    ) -> None:
        """D-021's "otherwise -> review_queue" branch — never a status change, never a
        substitute for `apply()`; purely a record that a human should look at this memory.

        This is `stores.pg.repo.Repo.insert_review_item`'s real signature, verbatim, and
        the same one `workers.review_queue.ReviewQueueRepoPort` declares — so the
        production `Repo` satisfies this half of the port structurally, with no adapter and
        no new repository method to write. (The `select_*`/`persist` methods above still
        have no `Repo` backing; that gap is reported, this one no longer needs to be.)
        """
        ...


@dataclass(frozen=True, slots=True)
class PromotionOutcome:
    memory_id: MemoryId
    promoted: bool
    to_status: Status | None
    reason: str
    """Empty iff `promoted`; otherwise the guard's own refusal reason."""


@dataclass(frozen=True, slots=True)
class RetirementOutcome:
    memory_id: MemoryId
    retired: bool
    routed_to_review: bool
    """True iff this row cleared the Q/scored-use preconditions but not the K-distinct-
    principals floor, and was therefore opened in `review_queue` instead of retired
    (D-021). Mutually exclusive with `retired`; both False means "not due yet" (some
    other precondition, e.g. Q still above threshold, was not met) and nothing happened."""
    to_status: Status | None
    reason: str


@dataclass(frozen=True, slots=True)
class PromotionBatchResult:
    rows_examined: int
    outcomes: tuple[PromotionOutcome, ...]


@dataclass(frozen=True, slots=True)
class RetirementBatchResult:
    rows_examined: int
    outcomes: tuple[RetirementOutcome, ...]


class PromotionWorker:
    def __init__(self, repo: PromotionRepoPort, clock: Clock) -> None:
        self._repo = repo
        self._clock = clock

    # ------------------------------------------------------------------ promotion -----------

    def evaluate_candidate(
        self, project_id: ProjectId, row: CandidateMemoryRow, *, cfg: EffectiveConfig
    ) -> PromotionOutcome:
        """`candidate -> validated`: PLAN.md §5 row 6's four conditions, all four required.

        Every condition is read straight off `row` into `TransitionEvidence` and handed to
        `apply()` unmodified — this method makes no promotion decision of its own; a refusal
        on ANY of the four surfaces as the same `GuardNotSatisfied`, and its `reason` names
        exactly which one(s) `apply()`'s guard checked first.
        """
        _require_status(row, project_id, Status.CANDIDATE)
        now = self._clock.now()
        limits = TransitionLimits.from_config(cfg)
        evidence = TransitionEvidence(
            now=now,
            provenance_class=row.provenance.cls,
            trust_tier=row.trust_tier,
            mem_type=row.mem_type,
            status_changed_at=row.status_changed_at,
            promotion_outcomes=row.promotion_outcomes,
            promotion_distinct_principals=row.promotion_distinct_principals,
            outcome_consistent=row.outcome_consistent,
            scan_repass=row.scan_repass,
            open_contradiction=row.open_contradiction,
        )
        try:
            new_status = apply(row.status, Status.VALIDATED, evidence, limits)
        except GuardNotSatisfied as exc:
            return PromotionOutcome(row.id, False, None, exc.reason)

        self._repo.persist(
            project_id, PromotionTransitionWrite(row.id, row.status, new_status, now)
        )
        return PromotionOutcome(row.id, True, new_status, "")

    def run_promotion_once(
        self, project_id: ProjectId, *, cfg: EffectiveConfig
    ) -> PromotionBatchResult:
        rows = self._repo.select_candidates_for_promotion(project_id)
        outcomes = tuple(self.evaluate_candidate(project_id, row, cfg=cfg) for row in rows)
        return PromotionBatchResult(rows_examined=len(rows), outcomes=outcomes)

    # ------------------------------------------------------------------ retirement ----------

    def evaluate_retirement(
        self, project_id: ProjectId, row: ValidatedMemoryRow, *, cfg: EffectiveConfig
    ) -> RetirementOutcome:
        """`validated -> retired`: PLAN.md §5 row 12 / D-021.

        `apply()` is asked for real, exactly once, with the row's actual
        `distinct_scoring_principals` — this method never substitutes a different value to
        make the edge legal, and never retires on its own authority. When the guard refuses
        SPECIFICALLY because the principal floor (K) is unmet, while the Q-value and
        scored-use preconditions both already hold, the row is routed to `review_queue`
        instead (PLAN.md §5 row 12: "otherwise -> review_queue"; the state machine's own
        docstring: "the caller's job"). A row that is not due yet for any other reason (Q
        still at or above threshold, or too few scored uses) is left alone — routing every
        refusal to review would flood the queue with rows nobody needs to look at.

        `workers.review_queue.ReviewQueue.flag_retirement_candidate` is the sibling
        implementation of the same D-021 branch, reaching the same `Repo.insert_review_item`
        with the same reason wording; the difference is only how the branch is recognised
        (that one substring-matches the guard's reason, this one re-derives the three
        thresholds from `limits`). Whoever schedules these must call exactly ONE of them per
        row: `review_queue` has no dedup key and `review_queue.item_id` is a fresh uuid per
        insert, so wiring both — or re-running either on a row a human has not yet resolved
        — appends a duplicate row every tick. Reported as a cross-chunk gap rather than
        resolved here: an `open item for (project, memory, reason kind)` upsert belongs with
        whoever owns the `review_queue` schema.
        """
        _require_status(row, project_id, Status.VALIDATED)
        now = self._clock.now()
        limits = TransitionLimits.from_config(cfg)
        evidence = TransitionEvidence(
            now=now,
            provenance_class=row.provenance.cls,
            trust_tier=row.trust_tier,
            mem_type=row.mem_type,
            status_changed_at=row.status_changed_at,
            q_value=row.q_value,
            scored_use_count=row.scored_use_count,
            distinct_scoring_principals=row.distinct_scoring_principals,
        )
        try:
            new_status = apply(row.status, Status.RETIRED, evidence, limits)
        except GuardNotSatisfied as exc:
            if (
                row.q_value < limits.retire_q_threshold
                and row.scored_use_count >= limits.retire_min_scored_uses
                and row.distinct_scoring_principals < limits.retire_min_distinct_principals
            ):
                self._repo.insert_review_item(
                    project_id,
                    (
                        f"retirement candidate: memory {row.id} has q_value="
                        f"{row.q_value:.3f} (below {limits.retire_q_threshold}) after "
                        f"{row.scored_use_count} scored uses (>= "
                        f"{limits.retire_min_scored_uses} required), but only "
                        f"{row.distinct_scoring_principals} distinct scoring principal(s) "
                        f"contributed (K={limits.retire_min_distinct_principals} required); "
                        f"{exc.reason}"
                    ),
                    row.id,
                )
                return RetirementOutcome(row.id, False, True, None, exc.reason)
            return RetirementOutcome(row.id, False, False, None, exc.reason)

        self._repo.persist(
            project_id, PromotionTransitionWrite(row.id, row.status, new_status, now)
        )
        return RetirementOutcome(row.id, True, False, new_status, "")

    def run_retirement_once(
        self, project_id: ProjectId, *, cfg: EffectiveConfig
    ) -> RetirementBatchResult:
        rows = self._repo.select_validated_for_retirement(project_id)
        outcomes = tuple(self.evaluate_retirement(project_id, row, cfg=cfg) for row in rows)
        return RetirementBatchResult(rows_examined=len(rows), outcomes=outcomes)


def _require_status(
    row: CandidateMemoryRow | ValidatedMemoryRow, project_id: ProjectId, expected: Status
) -> None:
    """Re-assert what the select promised, on every row, before acting on it — the same
    defensive check `workers.invalidator`/`workers.revalidation`/`workers.sweeps` apply to
    their own store results (a select that over-returns is a bulk mis-transition waiting to
    happen, and the predicate that should stop it lives in a store outside this chunk)."""
    if row.project_id != project_id:
        raise TracebedError(
            f"memory {row.id} belongs to project {row.project_id}, not {project_id}; "
            f"the promotion/retirement select returned a row outside the requested project "
            f"(invariant 4)"
        )
    if row.status is not expected:
        raise TracebedError(
            f"memory {row.id} is {row.status.value!r}, not {expected.value!r}; promotion/"
            f"retirement must not ask the state machine to judge an edge this row is not on"
        )
