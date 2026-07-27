"""Shadow validation: `quarantined -> candidate` — PLAN.md §2 invariant 7 (Tier B quarantine),
§5 row 4, §7 Phase 3. D-020 (computable independence) and D-023 (`propose_memory` never
skips) are the two corrections this worker exists to enforce; both are enabled here for the
first time — Phase 0 shipped `submitter_principal`/`input_signature_hash` on `trace_index`
but left the corroboration skip disabled (PHASE0-CONTRACT.md, "ships disabled until both
columns exist and Phase 3 turns it on").

This worker is deliberately thin: every governance decision — is this edge legal, does this
evidence clear its guard, can `proposal` provenance ever skip — lives in
`domain.state_machine.apply()`, which this module calls and never second-guesses. What this
module owns is turning a quarantined row's recorded confirming runs into the
`ShadowConfirmation` tuple `apply()` needs (via `workers.independence`), and reporting the
outcome. It is not the place a new skip route, a new provenance class, or an admin override
gets added — PLAN.md §10: no admin bypass exists in code.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable

from tracebed.domain.clock import Clock
from tracebed.domain.config import EffectiveConfig
from tracebed.domain.enums import MemType, ProvenanceClass, TrustTier
from tracebed.domain.errors import GuardNotSatisfied, TracebedError
from tracebed.domain.ids import MemoryId, ProjectId, RunId
from tracebed.domain.memory import Provenance
from tracebed.domain.state_machine import (
    ShadowConfirmation,
    Status,
    TransitionEvidence,
    TransitionLimits,
    apply,
    independent_confirmations,
)
from tracebed.workers.epochs import ScoringEpoch
from tracebed.workers.independence import (
    TracePrincipalLookupPort,
    build_confirmations,
    independent_of,
)

__all__ = [
    "QuarantinedMemoryRow",
    "ShadowTransitionWrite",
    "ShadowValidationBatchResult",
    "ShadowValidationOutcome",
    "ShadowValidator",
    "ShadowValidatorRepoPort",
    "origin_runs",
]


@dataclass(frozen=True, slots=True)
class QuarantinedMemoryRow:
    """The projection of a `quarantined` `memory_item` row this worker needs.

    `confirming_run_ids` is every run a store currently offers as corroborating evidence —
    `memory_item.shadow_confirm_runs` (migrations/0002: "distinct confirming run_ids"),
    which accumulates AFTER the row was written. A store that also folds the memory's own
    `provenance.trace_ids` in here changes nothing: `origin_runs` is subtracted before any
    of this is resolved, because a memory cannot corroborate itself (see `origin_runs`).
    Reading the store's own row shape is outside this chunk's file list; this worker only
    ever consumes the projection, exactly as `workers.invalidator`/`workers.revalidation`/
    `workers.sweeps` consume `LifecycleMemoryRow` without themselves querying
    `memory_item`.

    `is_failure_lesson` is likewise store-supplied classification data (which quarantined
    lessons record a *failure* rather than, say, a success pattern) — not something this
    worker infers, and not something `mem_type` alone can answer: PLAN.md §5 row 4 relaxes
    the corroboration count for failure lessons specifically, and a lesson that is not about
    a failure must not get that relaxation just for being a `LESSON`.
    """

    id: MemoryId
    project_id: ProjectId
    status: Status
    trust_tier: TrustTier
    mem_type: MemType
    provenance: Provenance
    status_changed_at: datetime | None
    is_failure_lesson: bool
    confirming_run_ids: tuple[RunId, ...]


@dataclass(frozen=True, slots=True)
class ShadowTransitionWrite:
    """One committed status write — always `to_status == apply()`'s return value.

    `epoch_id` is carried on every shadow confirmation for the reason PLAN.md §5 states on
    the `scoring_epoch` table itself: "every Q update **and shadow confirmation** records
    epoch_id; cross-epoch comparison is rejected". It is stamped even though the
    independence computation this worker performs is LLM-free, because D-008 makes the
    shadow validator one of the three judge-pinned workers: the moment the counterfactual
    /judged half of shadow validation lands (PLAN.md §9 backlog), rows confirmed under the
    previous judge pin must already be distinguishable from rows confirmed under the new
    one, and a stamp that starts late cannot retroactively attribute the old rows.
    `workers.scorer.QUpdate` carries it on exactly the same terms — the value is correct
    the moment a repo owner adds the column.
    """

    memory_id: MemoryId
    from_status: Status
    to_status: Status
    now: datetime
    epoch_id: int


@runtime_checkable
class ShadowValidatorRepoPort(Protocol):
    def select_quarantined(self, project_id: ProjectId) -> Sequence[QuarantinedMemoryRow]:
        """Indexed `(project_id, status='quarantined')` — never a trace scan, matching the
        cost discipline `workers.sweeps` already established for the other lifecycle
        sweeps."""
        ...

    def persist(self, project_id: ProjectId, write: ShadowTransitionWrite) -> None: ...


@dataclass(frozen=True, slots=True)
class ShadowValidationOutcome:
    memory_id: MemoryId
    promoted: bool
    to_status: Status | None
    """`None` iff the guard refused (see `reason`); otherwise always `Status.CANDIDATE`,
    because `apply()` never returns anything else for this edge."""
    independent_count: int
    """Diagnostic only — the exact size of the largest independent-confirmation subset,
    computed by the same `domain.state_machine.independent_confirmations` the guard uses.
    Never the value this worker used to decide anything, and deliberately not compared
    against a threshold here: `apply()`'s own guard is the sole decision-maker
    (invariant 7)."""
    reason: str
    """Empty iff `promoted`; otherwise the guard's own refusal reason."""


@dataclass(frozen=True, slots=True)
class ShadowValidationBatchResult:
    rows_examined: int
    outcomes: tuple[ShadowValidationOutcome, ...]


def origin_runs(provenance: Provenance) -> frozenset[RunId]:
    """The runs a quarantined memory was DERIVED FROM — which can never also be the runs
    that CONFIRM it.

    This is the difference between quarantine and a formality. A `distiller` memory's
    provenance always names at least one trace (`REQUIRED_PROVENANCE_FIELDS`, invariant 6),
    and a `proposal` always names its `run_id`. If those same runs are allowed to count as
    shadow confirmations, then:

    - every quarantined FAILURE LESSON exits quarantine on the first sweep after it is
      written, because `promotion.failure_lesson_outcomes` is 1 and its own origin trace
      supplies that 1 — the entire failure-lesson class would never spend a single tick
      actually quarantined;
    - any memory the distiller derived from a batch of >= 2 traces that happen to differ in
      principal and wording exits at creation with ZERO evidence that arrived after the
      content existed.

    Both make invariant 7 vacuous for the classes it exists to hold: "content-derived
    memory is quarantined until confirmed against real outcomes" (PLAN.md §1) means
    confirmed against outcomes OTHER than the ones it was distilled out of. PLAN.md §5
    keeps the two sets in different columns for this reason — `provenance.trace_ids` is
    where it came from, `shadow_confirm_runs` is "distinct confirming run_ids".

    Subtracting here rather than trusting a store to subtract is deliberate: the store that
    assembles `confirming_run_ids` is outside this chunk, and an invariant enforced only by
    a convention in another module's query is not enforced.
    """
    runs = set(provenance.trace_ids)
    if provenance.run_id is not None:
        runs.add(provenance.run_id)
    return frozenset(runs)


class ShadowValidator:
    def __init__(
        self,
        repo: ShadowValidatorRepoPort,
        clock: Clock,
        lookup: TracePrincipalLookupPort,
        epoch: ScoringEpoch,
    ) -> None:
        self._repo = repo
        self._clock = clock
        self._lookup = lookup
        self._epoch = epoch

    def evaluate_one(
        self, project_id: ProjectId, row: QuarantinedMemoryRow, *, cfg: EffectiveConfig
    ) -> ShadowValidationOutcome:
        """Attempt `quarantined -> candidate` for exactly one row.

        Refuses (raises) rather than silently skipping a row that is not actually
        `quarantined` or not scoped to `project_id` — the same defensive re-assertion
        `workers.invalidator`/`workers.revalidation`/`workers.sweeps` already apply to their
        own store results, because a select that over-returns is a bulk mis-transition
        waiting to happen, and the predicate that is supposed to stop it lives in a store
        this chunk does not own.
        """
        _require_row(row, project_id)
        now = self._clock.now()
        limits = TransitionLimits.from_config(cfg)

        confirmations = self._resolve_confirmations(project_id, row)
        # No `at_least` hint. Sizing one means re-deriving "how many does THIS row need" —
        # the failure-lesson relaxation, its `mem_type is LESSON` half, and the fixed count
        # beside it — which is `_guard_quarantined_to_candidate`'s decision and no one
        # else's. A second copy of it here is a copy that can drift silently: it changes
        # only the diagnostic below, so no promotion outcome moves when it is wrong, and a
        # mutation that deletes the `mem_type` half of the relaxation from THIS copy is
        # invisible to every test. `independent_confirmations` is already bounded on its own
        # terms (MAX_CONFIRMATIONS_CONSIDERED nodes, a hard step budget), so the exact
        # count costs a bounded search and carries no policy.
        independent = independent_confirmations(confirmations)

        # "Verified-human-verdict provenance" (PLAN.md §5 row 4's other skip) IS the
        # HUMAN_VERDICT provenance class carrying its verdict record. `verdict_id` is
        # re-checked here rather than assumed from the class: `validate_provenance` runs at
        # INSERT, but this row arrives from a `jsonb` column through `Provenance.from_json`,
        # which rehydrates whatever is on disk without re-validating it. A row whose
        # `verdict_id` went missing (a hand-edited jsonb, a partial migration) would
        # otherwise take a zero-evidence skip on the strength of a class label alone —
        # "verified human verdict" with no verdict to point at. `apply()`'s guard requires
        # BOTH this flag and the class, and reads D-023's proposal short-circuit first,
        # unconditionally.
        has_verified_human_verdict = (
            row.provenance.cls is ProvenanceClass.HUMAN_VERDICT
            and row.provenance.verdict_id is not None
        )

        evidence = TransitionEvidence(
            now=now,
            provenance_class=row.provenance.cls,
            trust_tier=row.trust_tier,
            mem_type=row.mem_type,
            is_failure_lesson=row.is_failure_lesson,
            status_changed_at=row.status_changed_at,
            confirmations=confirmations,
            has_verified_human_verdict=has_verified_human_verdict,
        )
        try:
            new_status = apply(row.status, Status.CANDIDATE, evidence, limits)
        except GuardNotSatisfied as exc:
            return ShadowValidationOutcome(row.id, False, None, independent, exc.reason)

        self._repo.persist(
            project_id,
            ShadowTransitionWrite(
                row.id, row.status, new_status, now, epoch_id=self._epoch.epoch_id
            ),
        )
        return ShadowValidationOutcome(row.id, True, new_status, independent, "")

    def _resolve_confirmations(
        self, project_id: ProjectId, row: QuarantinedMemoryRow
    ) -> tuple[ShadowConfirmation, ...]:
        """Turn the row's offered runs into resolved confirmations, minus its own origins
        and minus anything merely CORRELATED with those origins.

        Excluding the origin `run_id`s (see `origin_runs`) is not sufficient on its own, and
        the failure-lesson class is where that shows. `promotion.failure_lesson_outcomes` is
        1, and pairwise independence over a set of size 1 is vacuous — a single confirmation
        is trivially "independent" of the empty rest of the set. So for the entire
        failure-lesson class, excluding origin run ids leaves exactly one thing standing
        between quarantine and exit: whether that one confirming run is genuinely a second
        observation. Submit the same failing input twice under the same identity and the
        second run is a different `run_id`, so id-exclusion lets it through, and quarantine
        is cleared by a verbatim replay of the run the memory was distilled out of — the
        two-call Sybil bypass D-020 exists to kill, wearing an n=1 hat.

        So a confirming run must be independent of every ORIGIN run by the same D-020
        predicate the guard applies between confirmations: distinct run AND distinct
        authenticated principal AND distinct input-signature cluster. Asked through
        `workers.independence.independent_of`, which delegates to
        `domain.state_machine.independent_confirmations`, so this is the guard's own
        definition applied to one more pair — not a second implementation of it.

        It matters for the >= 2 case too: a set of {replay-of-origin, genuinely-new} scores
        2 on pairwise independence among confirmations alone, while containing exactly one
        observation that arrived after the content existed.

        An origin whose `trace_index` row cannot be resolved (`lookup` -> `None`) is not
        treated as correlated with everything: nothing is known about its principal or its
        wording, and refusing every confirmation on an unresolvable origin would make an
        incomplete trace index a project-wide promotion freeze. Its `run_id` is still
        excluded, which is the check that never needs a lookup.

        Proposals resolve nothing at all. D-023 makes `proposal` a class no amount of
        corroboration can ever help, so every lookup performed for one is work an attacker
        gets to schedule for free: proposals are the only quarantined class a caller
        creates directly (2/run, 50/project/day, held for the full 30-day quarantine TTL),
        and each would otherwise cost up to `MAX_CONFIRMATIONS_CONSIDERED` trace_index
        reads plus a clique search on EVERY sweep for a month, to reach a refusal that was
        already decided by the class alone. `apply()` still makes the decision — it is
        handed an empty confirmation tuple and refuses on the class check it performs
        first, so removing that check from the guard still surfaces as a changed refusal
        reason rather than being masked here.
        """
        if row.provenance.cls is ProvenanceClass.PROPOSAL:
            return ()
        origins = origin_runs(row.provenance)
        offered = tuple(run_id for run_id in row.confirming_run_ids if run_id not in origins)
        if not offered:
            return ()
        confirmations = build_confirmations(project_id, offered, self._lookup)
        # `sorted` because `origin_runs` is a frozenset and `build_confirmations` truncates
        # at MAX_CONFIRMATIONS_CONSIDERED: without a total order, WHICH origins are resolved
        # would vary between processes under hash randomisation, and so would the promotion
        # decision. `RunId` is not orderable, hence the key.
        origin_confirmations = build_confirmations(
            project_id, sorted(origins, key=str), self._lookup
        )
        if not origin_confirmations:
            return confirmations
        return tuple(
            confirmation
            for confirmation in confirmations
            if all(independent_of(confirmation, origin) for origin in origin_confirmations)
        )

    def run_once(
        self, project_id: ProjectId, *, cfg: EffectiveConfig
    ) -> ShadowValidationBatchResult:
        """Batch entry point: every currently-`quarantined` row, one indexed select."""
        rows = self._repo.select_quarantined(project_id)
        outcomes = tuple(self.evaluate_one(project_id, row, cfg=cfg) for row in rows)
        return ShadowValidationBatchResult(rows_examined=len(rows), outcomes=outcomes)


def _require_row(row: QuarantinedMemoryRow, project_id: ProjectId) -> None:
    if row.project_id != project_id:
        raise TracebedError(
            f"memory {row.id} belongs to project {row.project_id}, not {project_id}; "
            f"select_quarantined returned a row outside the requested project (invariant 4)"
        )
    if row.status is not Status.QUARANTINED:
        raise TracebedError(
            f"memory {row.id} is {row.status.value!r}, not 'quarantined'; shadow validation "
            f"must not ask the state machine to judge an edge this row is not on"
        )
